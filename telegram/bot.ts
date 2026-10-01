/**
 * Telegram Bot Controller & Interactive Command Handler
 */
import { TelegramClient } from "@/telegram/client";
import { TelegramUpdate, TelegramInlineKeyboardMarkup, TelegramUser } from "@/telegram/types";
import { CloudflareListsService } from "@/cloudflare/lists";
import { DecisionEngine } from "@/guard/decision-engine";
import { Blocker, PrunedUnbanItem } from "@/guard/blocker";
import { GuardPolicy } from "@/domain/models/policy";
import { GuardDecision } from "@/domain/models/decision";
import { safeValidatePolicy } from "@/config/policy-schema";

export interface TelegramBotOptions {
  client: TelegramClient;
  adminChatIds: string[];
  listsService: CloudflareListsService;
  decisionEngine: DecisionEngine;
  blocker: Blocker;
  listId?: string;
  zoneId?: string;
  getPolicy: () => Promise<GuardPolicy>;
  savePolicy?: (policy: GuardPolicy) => Promise<void>;
}

export class TelegramBotHandler {
  private client: TelegramClient;
  private adminChatIds: Set<string>;
  private listsService: CloudflareListsService;
  private decisionEngine: DecisionEngine;
  private blocker: Blocker;
  private listId?: string;
  private zoneId?: string;
  private getPolicy: () => Promise<GuardPolicy>;
  private savePolicy?: (policy: GuardPolicy) => Promise<void>;

  constructor(options: TelegramBotOptions) {
    this.client = options.client;
    this.adminChatIds = new Set(options.adminChatIds.filter(Boolean));
    this.listsService = options.listsService;
    this.decisionEngine = options.decisionEngine;
    this.blocker = options.blocker;
    this.listId = options.listId;
    this.zoneId = options.zoneId;
    this.getPolicy = options.getPolicy;
    this.savePolicy = options.savePolicy;
  }

  /**
   * Verifies if a Telegram user/chat ID is an authorized administrator.
   * Checks both individual sender ID (from.id) and conversation ID (chat.id).
   */
  private isAuthorized(userId?: number | string, chatId?: number | string): boolean {
    if (this.adminChatIds.size === 0) return false;
    if (userId !== undefined && this.adminChatIds.has(String(userId))) return true;
    if (chatId !== undefined && this.adminChatIds.has(String(chatId))) return true;
    return false;
  }

  /**
   * Safely validates and persists a policy update
   */
  private async savePolicySafely(policy: GuardPolicy): Promise<{ success: boolean; error?: string }> {
    if (!this.savePolicy) {
      return { success: false, error: "Policy persistence is not configured." };
    }
    const validation = safeValidatePolicy(policy);
    if (!validation.success) {
      const errMsg = validation.error?.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ");
      return { success: false, error: errMsg || "Invalid policy schema" };
    }
    await this.savePolicy(validation.data as GuardPolicy);
    return { success: true };
  }

  /**
   * Main entrypoint for processing incoming Telegram Webhook updates
   */
  public async handleUpdate(update: TelegramUpdate): Promise<void> {
    // 1. Handle Inline Button Callback Queries
    if (update.callback_query) {
      await this.handleCallbackQuery(update.callback_query);
      return;
    }

    // 2. Handle Text Commands
    if (update.message && update.message.text) {
      await this.handleMessage(update.message);
    }
  }

  /**
   * Handles text messages & slash commands
   */
  private async handleMessage(message: NonNullable<TelegramUpdate["message"]>): Promise<void> {
    const chatId = message.chat.id;
    const userId = message.from?.id;
    const text = (message.text || "").trim();

    if (!this.isAuthorized(userId, chatId)) {
      await this.client.sendMessage(
        chatId,
        `⛔ <b>Unauthorized Access!</b>\nThis bot is strictly restricted to system administrators.\nYour User ID: <code>${userId || chatId}</code>\nChat ID: <code>${chatId}</code>`
      );
      return;
    }

    const [cmd, ...args] = text.split(/\s+/);
    const commandName = cmd.toLowerCase().split("@")[0]; // Strip bot username if invoked in groups

    switch (commandName) {
      case "/start":
      case "/help":
        await this.sendHelp(chatId);
        break;
      case "/status":
        await this.sendStatus(chatId);
        break;
      case "/list":
        await this.sendList(chatId);
        break;
      case "/evaluate":
        await this.executeEvaluate(chatId);
        break;
      case "/policy":
        await this.sendPolicy(chatId);
        break;
      case "/admins":
        await this.sendAdmins(chatId);
        break;
      case "/flush":
      case "/unban_all":
      case "/clear":
        await this.executeFlushPrompt(chatId);
        break;
      case "/ban":
        await this.executeBan(chatId, args[0], args.slice(1).join(" "));
        break;
      case "/unban":
        await this.executeUnban(chatId, args);
        break;
      case "/set_threshold":
        await this.executeSetThreshold(chatId, args[0]);
        break;
      case "/set_window":
        await this.executeSetWindow(chatId, args[0]);
        break;
      case "/set_topn":
        await this.executeSetTopN(chatId, args[0]);
        break;
      case "/set_country":
        await this.executeSetCountry(chatId, args[0], args[1], args[2]);
        break;
      case "/remove_country":
        await this.executeRemoveCountry(chatId, args[0]);
        break;
      case "/allow":
        await this.executeAllow(chatId, args[0]);
        break;
      case "/disallow":
        await this.executeDisallow(chatId, args[0]);
        break;
      case "/set_ttl":
        await this.executeSetTtl(chatId, args[0]);
        break;
      case "/set_policy":
        await this.executeSetPolicyJson(chatId, text.replace(/^\/set_policy\s*/i, ""));
        break;
      default:
        await this.client.sendMessage(
          chatId,
          "❓ Unknown command: <code>" +
            cmd +
            "</code>\nSend /help to view all available commands."
        );
        break;
    }
  }

  /**
   * /help & /start command: Rich interactive control menu
   */
  private async sendHelp(chatId: number): Promise<void> {
    const text =
      `🛡️ <b>Cloudflare Auto Guard — Control Center</b>\n\n` +
      `Manage, inspect, and update edge security directly from Telegram:\n\n` +
      `<b>⚡ Core Commands:</b>\n` +
      `• /status — Real-time system health and WAF metrics\n` +
      `• /evaluate — Trigger edge GraphQL traffic analysis now\n` +
      `• /list — View currently banned IPs in Cloudflare WAF\n` +
      `• /ban &lt;IP&gt; [reason] — Manually add an IP to the WAF list\n` +
      `• /unban &lt;IP1&gt; [IP2...] — Remove one or multiple IPs at once\n` +
      `• /flush — Wipe and unban all currently blocked IPs\n` +
      `• /policy — View active policy with 1-click preset buttons\n` +
      `• /admins — View authorized administrator accounts\n\n` +
      `<b>⚙️ Policy Update Commands:</b>\n` +
      `• /set_threshold &lt;reqs&gt; — Set default threshold (e.g. <code>/set_threshold 300</code>)\n` +
      `• /set_window &lt;seconds&gt; — Set inspection window (e.g. <code>/set_window 900</code>)\n` +
      `• /set_topn &lt;count&gt; — Set Top-N candidates (e.g. <code>/set_topn 50</code>)\n` +
      `• /set_country &lt;CODE&gt; &lt;reqs&gt; — Country rule (e.g. <code>/set_country RU 100</code>)\n` +
      `• /remove_country &lt;CODE&gt; — Delete country override (e.g. <code>/remove_country RU</code>)\n` +
      `• /allow &lt;IP/CIDR&gt; — Add to allowlist (e.g. <code>/allow 1.1.1.1</code>)\n` +
      `• /disallow &lt;IP/CIDR&gt; — Remove from allowlist\n` +
      `• /set_ttl &lt;hours|seconds&gt; — Set unban TTL (e.g. <code>/set_ttl 24h</code>)\n` +
      `• /set_policy &lt;JSON&gt; — Upload raw policy JSON directly\n\n` +
      `<i>Use the quick action buttons below:</i>`;

    const keyboard: TelegramInlineKeyboardMarkup = {
      inline_keyboard: [
        [
          { text: "📊 System Status", callback_data: "cmd:status" },
          { text: "⚡ Evaluate Now", callback_data: "cmd:evaluate" }
        ],
        [
          { text: "📋 Banned IPs", callback_data: "cmd:list" },
          { text: "📜 Active Policy", callback_data: "cmd:policy" }
        ]
      ]
    };

    await this.client.sendMessage(chatId, text, { reply_markup: keyboard });
  }

  /**
   * /status command: Live health and configuration card
   */
  private async sendStatus(chatId: number): Promise<void> {
    const policy = await this.getPolicy();
    let itemCount = 0;

    if (this.listId) {
      const items = await this.listsService.getListItems(this.listId);
      itemCount = items.length;
    }

    const unbanTtlHours = Math.round((policy.unban?.ttlSeconds ?? 86400) / 3600);
    const maxLimit = policy.unban?.maxListSize ?? 9000;
    const countryCount = Object.keys(policy.countries || {}).length;

    const text =
      `📊 <b>Auto Guard System Status</b>\n` +
      `━━━━━━━━━━━━━━━━━━━━\n` +
      `🟢 <b>Status:</b> Active & Guarding\n` +
      `👥 <b>Authorized Admins:</b> <b>${this.adminChatIds.size}</b>\n` +
      `🌐 <b>Zone ID:</b> <code>${this.zoneId || "Not Configured"}</code>\n` +
      `📋 <b>WAF List ID:</b> <code>${this.listId || "Not Configured"}</code>\n` +
      `🚫 <b>Active Banned IPs:</b> <b>${itemCount}</b> / 10,000\n` +
      `━━━━━━━━━━━━━━━━━━━━\n` +
      `⚙️ <b>Policy Summary:</b>\n` +
      `• Default Threshold: <b>${policy.default.threshold} reqs</b> / ${policy.windowSeconds || 300}s\n` +
      `• Top-N Sampling: <b>${policy.topN || 100} IPs</b>\n` +
      `• Country Overrides: <b>${countryCount} rules</b>\n` +
      `• Automated Unban (TTL): <b>${unbanTtlHours} Hours</b>\n` +
      `• Max List Ceiling: <b>${maxLimit} IPs</b>\n` +
      `• Allowlist Size: <b>${policy.allowlist?.length || 0} CIDRs</b>\n` +
      `━━━━━━━━━━━━━━━━━━━━\n` +
      `⏱️ <i>Inspected: ${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC</i>`;

    const keyboard: TelegramInlineKeyboardMarkup = {
      inline_keyboard: [
        [
          { text: "⚡ Evaluate Now", callback_data: "cmd:evaluate" },
          { text: "📋 Banned IPs", callback_data: "cmd:list" }
        ],
        [
          { text: "📜 View / Edit Policy", callback_data: "cmd:policy" }
        ]
      ]
    };

    await this.client.sendMessage(chatId, text, { reply_markup: keyboard });
  }

  /**
   * /list command: Displays active banned IPs with compact buttons and a Flush All action
   */
  private async sendList(chatId: number): Promise<void> {
    if (!this.listId) {
      await this.client.sendMessage(chatId, "⚠️ CF_LIST_ID is not configured.");
      return;
    }

    const items = await this.listsService.getListItems(this.listId);
    if (items.length === 0) {
      await this.client.sendMessage(
        chatId,
        "✅ <b>Cloudflare WAF IP List is Empty!</b>\nNo IPs are currently blocked."
      );
      return;
    }

    const latestItems = items.slice(-10).reverse();
    let text = `📋 <b>Active Banned IPs (${items.length} total, showing latest ${latestItems.length}):</b>\n\n`;

    for (let i = 0; i < latestItems.length; i++) {
      const it = latestItems[i];
      const dateStr = it.created_on ? it.created_on.slice(0, 16).replace("T", " ") : "-";
      text += `${i + 1}. <code>${it.ip}</code>\n   📝 <i>${it.comment || "Auto Guard"}</i>\n   📅 ${dateStr}\n\n`;
    }

    // Pair buttons 2 per row for a clean, compact view
    const itemButtons: TelegramInlineKeyboardMarkup["inline_keyboard"] = [];
    const maxQuickButtons = Math.min(latestItems.length, 6);
    for (let i = 0; i < maxQuickButtons; i += 2) {
      const row: TelegramInlineKeyboardMarkup["inline_keyboard"][0] = [
        { text: `🔓 ${latestItems[i].ip}`, callback_data: `unban:${latestItems[i].ip}` }
      ];
      if (i + 1 < maxQuickButtons) {
        row.push({ text: `🔓 ${latestItems[i + 1].ip}`, callback_data: `unban:${latestItems[i + 1].ip}` });
      }
      itemButtons.push(row);
    }

    const keyboard: TelegramInlineKeyboardMarkup = {
      inline_keyboard: [
        ...itemButtons,
        [
          { text: `💥 Flush All (${items.length})`, callback_data: "flush:prompt" },
          { text: "🔄 Refresh", callback_data: "cmd:list" }
        ]
      ]
    };

    await this.client.sendMessage(chatId, text, { reply_markup: keyboard });
  }

  /**
   * /evaluate command: Instantly triggers GraphQL analytics traffic inspection
   */
  private async executeEvaluate(chatId: number): Promise<void> {
    if (!this.zoneId) {
      await this.client.sendMessage(chatId, "⚠️ CF_ZONE_ID is not configured.");
      return;
    }

    await this.client.sendMessage(chatId, "🔍 <i>Querying Cloudflare edge analytics, please wait...</i>");

    try {
      const policy = await this.getPolicy();
      const { decisions, unbanned } = await this.decisionEngine.evaluateCandidates(policy, this.zoneId);

      const blocked = decisions.filter((d) => d.action === "BLOCK");
      const ignored = decisions.filter((d) => d.action === "IGNORE");

      let report =
        `⚡ <b>Evaluation Completed!</b>\n\n` +
        `📊 <b>Analyzed Candidates:</b> ${decisions.length}\n` +
        `🚫 <b>Newly Blocked:</b> ${blocked.length}\n` +
        `🔓 <b>Auto-Unbanned:</b> ${unbanned.length}\n` +
        `✅ <b>Clean / Ignored:</b> ${ignored.length}\n\n`;

      if (unbanned.length > 0) {
        report += `<b>Auto-Unbanned IPs (TTL / FIFO):</b>\n`;
        for (const u of unbanned.slice(0, 10)) {
          const reasonLabel = u.reason === "TTL_EXPIRED" ? "TTL Expired" : "FIFO Overflow";
          report += `• <code>${u.ip}</code> <i>(${reasonLabel})</i>\n`;
        }
        if (unbanned.length > 10) {
          report += `<i>...and ${unbanned.length - 10} more</i>\n`;
        }
        report += `\n`;
      }

      if (blocked.length > 0) {
        report += `<b>Blocked Threats:</b>\n`;
        for (const b of blocked) {
          report += `• <code>${b.ip}</code> (${b.country || "??"}) — ${b.requestCount} reqs (Limit: ${b.threshold})\n`;
        }
      } else {
        report += `<i>No threshold violations detected. All systems secure.</i>`;
      }

      await this.client.sendMessage(chatId, report);
    } catch (err) {
      await this.client.sendMessage(
        chatId,
        `❌ <b>Evaluation Failed:</b>\n<code>${(err as Error).message}</code>`
      );
    }
  }

  /**
   * /policy command: Displays current protection rules with quick preset adjustment buttons
   */
  private async sendPolicy(chatId: number, messageId?: number): Promise<void> {
    const policy = await this.getPolicy();
    const formatted = JSON.stringify(policy, null, 2);

    const countryCount = Object.keys(policy.countries || {}).length;
    const allowCount = policy.allowlist?.length || 0;
    const ttlHours = Math.round((policy.unban?.ttlSeconds ?? 86400) / 3600);

    const text =
      `📜 <b>Active Security Policy</b>\n` +
      `━━━━━━━━━━━━━━━━━━━━\n` +
      `🛡️ <b>Default Threshold:</b> <b>${policy.default.threshold} reqs</b> / ${policy.windowSeconds || 300}s\n` +
      `🔍 <b>Top-N Sample Size:</b> <b>${policy.topN || 100} IPs</b>\n` +
      `🏳️ <b>Country Overrides:</b> <b>${countryCount} rules</b>\n` +
      `🛡️ <b>Allowlist Size:</b> <b>${allowCount} CIDRs</b>\n` +
      `🧹 <b>Auto-Unban (TTL):</b> <b>${ttlHours} Hours</b>\n` +
      `━━━━━━━━━━━━━━━━━━━━\n` +
      `<b>JSON Schema:</b>\n` +
      `<pre><code class="language-json">${formatted}</code></pre>\n\n` +
      `<i>Quickly adjust threshold or window using the buttons below, or use /set_threshold, /set_country, etc.</i>`;

    const keyboard: TelegramInlineKeyboardMarkup = {
      inline_keyboard: [
        [
          { text: "⚡ Thresh: 150", callback_data: "set_th:150" },
          { text: "⚡ Thresh: 300", callback_data: "set_th:300" },
          { text: "⚡ Thresh: 500", callback_data: "set_th:500" }
        ],
        [
          { text: "⏳ Win: 5m", callback_data: "set_win:300" },
          { text: "⏳ Win: 15m", callback_data: "set_win:900" },
          { text: "⏳ Win: 1h", callback_data: "set_win:3600" }
        ],
        [
          { text: "🔄 Refresh", callback_data: "cmd:policy" }
        ]
      ]
    };

    if (messageId) {
      await this.client.editMessageText(chatId, messageId, text, { reply_markup: keyboard });
    } else {
      await this.client.sendMessage(chatId, text, { reply_markup: keyboard });
    }
  }

  /**
   * /set_threshold command: Updates default request limit
   */
  private async executeSetThreshold(chatId: number, rawVal?: string): Promise<void> {
    const val = parseInt(rawVal || "", 10);
    if (isNaN(val) || val <= 0) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/set_threshold &lt;number&gt;</code>\nExample: <code>/set_threshold 300</code>"
      );
      return;
    }

    const policy = await this.getPolicy();
    policy.default.threshold = val;
    const res = await this.savePolicySafely(policy);
    if (!res.success) {
      await this.client.sendMessage(chatId, `❌ Failed to update threshold: ${res.error}`);
      return;
    }

    await this.client.sendMessage(
      chatId,
      `✅ <b>Default Threshold Updated!</b>\nNew Threshold: <b>${val} requests</b> / ${policy.windowSeconds || 300}s\nPolicy is now active across all Cloudflare edge nodes.`
    );
  }

  /**
   * /set_window command: Updates analytics inspection timeframe
   */
  private async executeSetWindow(chatId: number, rawVal?: string): Promise<void> {
    const val = parseInt(rawVal || "", 10);
    if (isNaN(val) || val <= 0) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/set_window &lt;seconds&gt;</code>\nExample: <code>/set_window 900</code> (15 mins)"
      );
      return;
    }

    const policy = await this.getPolicy();
    policy.windowSeconds = val;
    const res = await this.savePolicySafely(policy);
    if (!res.success) {
      await this.client.sendMessage(chatId, `❌ Failed to update window: ${res.error}`);
      return;
    }

    const mins = Math.round(val / 60);
    await this.client.sendMessage(
      chatId,
      `✅ <b>Inspection Window Updated!</b>\nNew Window: <b>${val} seconds</b> (${mins} minutes)`
    );
  }

  /**
   * /set_topn command: Updates top candidate sample size
   */
  private async executeSetTopN(chatId: number, rawVal?: string): Promise<void> {
    const val = parseInt(rawVal || "", 10);
    if (isNaN(val) || val <= 0) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/set_topn &lt;number&gt;</code>\nExample: <code>/set_topn 50</code>"
      );
      return;
    }

    const policy = await this.getPolicy();
    policy.topN = val;
    const res = await this.savePolicySafely(policy);
    if (!res.success) {
      await this.client.sendMessage(chatId, `❌ Failed to update Top-N: ${res.error}`);
      return;
    }

    await this.client.sendMessage(
      chatId,
      `✅ <b>Top-N Sample Size Updated!</b>\nNew Top-N: <b>${val} candidates</b> analyzed per evaluation cycle.`
    );
  }

  /**
   * /set_country command: Adds or modifies country policy rule
   */
  private async executeSetCountry(
    chatId: number,
    rawCode?: string,
    rawTh?: string,
    rawAction?: string
  ): Promise<void> {
    if (!rawCode || !rawTh) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/set_country &lt;CODE&gt; &lt;threshold&gt; [block|challenge]</code>\nExample: <code>/set_country RU 100</code>"
      );
      return;
    }

    const code = rawCode.trim().toUpperCase();
    const threshold = parseInt(rawTh, 10);
    if (isNaN(threshold) || threshold <= 0) {
      await this.client.sendMessage(chatId, "⚠️ Threshold must be a positive integer.");
      return;
    }

    const action = rawAction?.toLowerCase() === "challenge" ? "challenge" : "block";
    const policy = await this.getPolicy();
    policy.countries = policy.countries || {};
    policy.countries[code] = {
      ...policy.countries[code],
      enabled: true,
      threshold,
      action
    };

    const res = await this.savePolicySafely(policy);
    if (!res.success) {
      await this.client.sendMessage(chatId, `❌ Failed to update country rule: ${res.error}`);
      return;
    }

    await this.client.sendMessage(
      chatId,
      `✅ <b>Country Policy Updated!</b>\nCountry: <b>${code}</b>\nThreshold: <b>${threshold} requests</b>\nAction: <b>${action.toUpperCase()}</b>`
    );
  }

  /**
   * /remove_country command: Deletes a country override
   */
  private async executeRemoveCountry(chatId: number, rawCode?: string): Promise<void> {
    if (!rawCode) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/remove_country &lt;CODE&gt;</code>\nExample: <code>/remove_country RU</code>"
      );
      return;
    }

    const code = rawCode.trim().toUpperCase();
    const policy = await this.getPolicy();
    if (!policy.countries || !policy.countries[code]) {
      await this.client.sendMessage(chatId, `ℹ️ No custom policy found for country: <b>${code}</b>`);
      return;
    }

    delete policy.countries[code];
    const res = await this.savePolicySafely(policy);
    if (!res.success) {
      await this.client.sendMessage(chatId, `❌ Failed to remove country rule: ${res.error}`);
      return;
    }

    await this.client.sendMessage(
      chatId,
      `✅ <b>Country Policy Removed!</b>\nCountry: <b>${code}</b>\nDefault threshold (${policy.default.threshold}) now applies to ${code}.`
    );
  }

  /**
   * /allow command: Adds an IP or CIDR to the allowlist
   */
  private async executeAllow(chatId: number, rawCidr?: string): Promise<void> {
    if (!rawCidr) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/allow &lt;IP_or_CIDR&gt;</code>\nExample: <code>/allow 1.1.1.1</code> or <code>/allow 192.168.1.0/24</code>"
      );
      return;
    }

    const cidr = rawCidr.trim();
    const policy = await this.getPolicy();
    policy.allowlist = policy.allowlist || [];

    if (policy.allowlist.includes(cidr)) {
      await this.client.sendMessage(chatId, `ℹ️ <code>${cidr}</code> is already in the allowlist.`);
      return;
    }

    policy.allowlist.push(cidr);
    const res = await this.savePolicySafely(policy);
    if (!res.success) {
      await this.client.sendMessage(chatId, `❌ Failed to add to allowlist: ${res.error}`);
      return;
    }

    await this.client.sendMessage(
      chatId,
      `✅ <b>Added to Allowlist!</b>\nEntry: <code>${cidr}</code>\nTotal allowlist entries: <b>${policy.allowlist.length}</b>`
    );
  }

  /**
   * /disallow command: Removes an IP or CIDR from the allowlist
   */
  private async executeDisallow(chatId: number, rawCidr?: string): Promise<void> {
    if (!rawCidr) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/disallow &lt;IP_or_CIDR&gt;</code>\nExample: <code>/disallow 1.1.1.1</code>"
      );
      return;
    }

    const cidr = rawCidr.trim();
    const policy = await this.getPolicy();
    policy.allowlist = policy.allowlist || [];

    const idx = policy.allowlist.indexOf(cidr);
    if (idx === -1) {
      await this.client.sendMessage(chatId, `ℹ️ <code>${cidr}</code> was not found in the allowlist.`);
      return;
    }

    policy.allowlist.splice(idx, 1);
    const res = await this.savePolicySafely(policy);
    if (!res.success) {
      await this.client.sendMessage(chatId, `❌ Failed to remove from allowlist: ${res.error}`);
      return;
    }

    await this.client.sendMessage(
      chatId,
      `✅ <b>Removed from Allowlist!</b>\nEntry: <code>${cidr}</code>\nTotal allowlist entries: <b>${policy.allowlist.length}</b>`
    );
  }

  /**
   * /set_ttl command: Updates automated unban TTL
   */
  private async executeSetTtl(chatId: number, rawTtl?: string): Promise<void> {
    if (!rawTtl) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/set_ttl &lt;hours|seconds&gt;</code>\nExample: <code>/set_ttl 24h</code> or <code>/set_ttl 12</code>"
      );
      return;
    }

    let seconds = 0;
    const trimmed = rawTtl.trim().toLowerCase();
    if (trimmed.endsWith("h")) {
      const h = parseFloat(trimmed.replace("h", ""));
      seconds = Math.round(h * 3600);
    } else if (trimmed.endsWith("d")) {
      const d = parseFloat(trimmed.replace("d", ""));
      seconds = Math.round(d * 86400);
    } else {
      const num = parseInt(trimmed, 10);
      seconds = num <= 72 ? num * 3600 : num;
    }

    if (isNaN(seconds) || seconds <= 0) {
      await this.client.sendMessage(chatId, "⚠️ Invalid TTL value. Provide hours (e.g. 24h) or seconds.");
      return;
    }

    const policy = await this.getPolicy();
    policy.unban = policy.unban || {};
    policy.unban.ttlSeconds = seconds;
    const res = await this.savePolicySafely(policy);
    if (!res.success) {
      await this.client.sendMessage(chatId, `❌ Failed to update TTL: ${res.error}`);
      return;
    }

    const hours = Math.round(seconds / 3600);
    await this.client.sendMessage(
      chatId,
      `✅ <b>Auto-Unban TTL Updated!</b>\nNew TTL: <b>${hours} Hours</b> (${seconds}s)\nBans older than ${hours}h will be pruned automatically.`
    );
  }

  /**
   * /set_policy command: Uploads raw JSON policy
   */
  private async executeSetPolicyJson(chatId: number, rawJson?: string): Promise<void> {
    if (!rawJson || !rawJson.trim()) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/set_policy &lt;JSON&gt;</code>\nSend a valid policy JSON string."
      );
      return;
    }

    try {
      const parsed = JSON.parse(rawJson);
      const res = await this.savePolicySafely(parsed);
      if (!res.success) {
        await this.client.sendMessage(
          chatId,
          `❌ <b>Invalid Policy Schema:</b>\n<code>${res.error}</code>`
        );
        return;
      }

      await this.client.sendMessage(
        chatId,
        `✅ <b>Full Policy Updated!</b>\nNew policy successfully validated and persisted to KV.`
      );
    } catch (err) {
      await this.client.sendMessage(
        chatId,
        `❌ <b>Invalid JSON:</b>\n<code>${(err as Error).message}</code>`
      );
    }
  }

  /**
   * Helper to broadcast an informational message to all admins except optionally the initiator
   */
  private async broadcastToOtherAdmins(text: string, excludeChatId?: number | string): Promise<void> {
    const exclude = excludeChatId !== undefined ? String(excludeChatId) : null;
    for (const adminId of this.adminChatIds) {
      if (exclude && adminId === exclude) continue;
      try {
        await this.client.sendMessage(adminId, text);
      } catch (err) {
        // Suppress broadcast transmission errors
      }
    }
  }

  /**
   * /admins command: Displays authorized administrator accounts
   */
  private async sendAdmins(chatId: number): Promise<void> {
    const list = Array.from(this.adminChatIds);
    const formatted = list.map((id, idx) => `${idx + 1}. <code>${id}</code>`).join("\n");
    await this.client.sendMessage(
      chatId,
      `👥 <b>Authorized Administrators (${list.length} total):</b>\n\n${formatted}\n\n<i>To add more admins, configure TELEGRAM_ADMIN_CHAT_ID (e.g. ID1,ID2,ID3) in wrangler secrets.</i>`
    );
  }

  /**
   * /ban command: Manual block execution
   */
  private async executeBan(chatId: number, ip?: string, reason?: string): Promise<void> {
    if (!ip) {
      await this.client.sendMessage(chatId, "⚠️ Usage: <code>/ban &lt;IP&gt; [reason]</code>\nExample: <code>/ban 1.2.3.4 Malicious scraper</code>");
      return;
    }

    if (!this.listId) {
      await this.client.sendMessage(chatId, "⚠️ CF_LIST_ID is not configured.");
      return;
    }

    const comment = `Telegram Manual: ${reason || "Admin Ban"} | ${new Date().toISOString().slice(0, 16)}`;
    try {
      await this.listsService.addIpToList(this.listId, ip, comment);
      this.blocker.markAsBlockedLocally(ip);

      const text =
        `🚫 <b>IP Successfully Blocked!</b>\n\n` +
        `🌐 <b>IP:</b> <code>${ip}</code>\n` +
        `📝 <b>Comment:</b> ${comment}\n` +
        `🛡️ Added to Cloudflare WAF blocklist.`;

      const keyboard: TelegramInlineKeyboardMarkup = {
        inline_keyboard: [[{ text: `🔓 Unban (${ip})`, callback_data: `unban:${ip}` }]]
      };

      await this.client.sendMessage(chatId, text, { reply_markup: keyboard });

      // Notify other admins about manual ban
      await this.broadcastToOtherAdmins(
        `ℹ️ <b>Admin Action: IP Blocked Manually</b>\n🌐 <b>IP:</b> <code>${ip}</code>\n📝 <b>Comment:</b> ${comment}`,
        chatId
      );
    } catch (err) {
      await this.client.sendMessage(chatId, `❌ Ban Failed:\n<code>${(err as Error).message}</code>`);
    }
  }

  /**
   * /unban command: Supports unbanning single or multiple IPs at once
   */
  private async executeUnban(chatId: number, rawIps?: string[]): Promise<void> {
    const ips = Array.from(
      new Set(
        (rawIps || [])
          .flatMap((r) => r.split(/[,\s;]+/))
          .map((s) => s.trim())
          .filter(Boolean)
      )
    );

    if (ips.length === 0) {
      await this.client.sendMessage(
        chatId,
        "⚠️ Usage: <code>/unban &lt;IP1&gt; [IP2] ...</code>\nExample: <code>/unban 1.2.3.4 5.6.7.8</code>"
      );
      return;
    }

    if (!this.listId) {
      await this.client.sendMessage(chatId, "⚠️ CF_LIST_ID is not configured.");
      return;
    }

    try {
      const items = await this.listsService.getListItems(this.listId);
      const toDelete = items.filter((item) => ips.includes(item.ip));

      if (toDelete.length === 0) {
        await this.client.sendMessage(
          chatId,
          `ℹ️ None of the specified IP(s) were found in the active blocklist:\n<code>${ips.join(", ")}</code>`
        );
        return;
      }

      await this.listsService.deleteIpsBatch(
        this.listId,
        toDelete.map((it) => it.id)
      );

      for (const it of toDelete) {
        this.blocker.markAsUnblockedLocally(it.ip);
      }

      const unbannedList = toDelete.map((it) => `• <code>${it.ip}</code>`).join("\n");
      await this.client.sendMessage(
        chatId,
        `✅ <b>Unbanned ${toDelete.length} IP(s) in 1 Batch!</b>\n\n${unbannedList}\n\n<i>Removed from Cloudflare WAF list.</i>`
      );

      // Notify other admins about manual unban
      await this.broadcastToOtherAdmins(
        `ℹ️ <b>Admin Action: IP Unbanned Manually</b>\n\n${unbannedList}\n\n<i>Removed from Cloudflare WAF list.</i>`,
        chatId
      );
    } catch (err) {
      await this.client.sendMessage(chatId, `❌ Unban Failed:\n<code>${(err as Error).message}</code>`);
    }
  }

  /**
   * Prompts admin with a confirmation dialog before wiping the entire blocklist
   */
  private async executeFlushPrompt(chatId: number, messageId?: number): Promise<void> {
    if (!this.listId) {
      await this.client.sendMessage(chatId, "⚠️ CF_LIST_ID is not configured.");
      return;
    }

    const items = await this.listsService.getListItems(this.listId);
    if (items.length === 0) {
      await this.client.sendMessage(chatId, "ℹ️ Blocklist is already empty. Nothing to flush.");
      return;
    }

    const text =
      `⚠️ <b>CONFIRMATION REQUIRED: Flush Entire Blocklist</b>\n\n` +
      `Are you sure you want to remove all <b>${items.length}</b> IPs from the Cloudflare WAF blocklist?\n\n` +
      `<i>This will immediately restore access for all currently blocked IPs.</i>`;

    const keyboard: TelegramInlineKeyboardMarkup = {
      inline_keyboard: [
        [
          { text: `💥 Yes, Flush All (${items.length})`, callback_data: "flush:confirm" },
          { text: "❌ Cancel", callback_data: "flush:cancel" }
        ]
      ]
    };

    if (messageId) {
      await this.client.editMessageText(chatId, messageId, text, { reply_markup: keyboard });
    } else {
      await this.client.sendMessage(chatId, text, { reply_markup: keyboard });
    }
  }

  /**
   * Executes bulk deletion of all items in the blocklist
   */
  private async executeFlushConfirmed(
    chatId: number,
    messageId?: number,
    user?: TelegramUser
  ): Promise<void> {
    if (!this.listId) return;

    try {
      const items = await this.listsService.getListItems(this.listId);
      if (items.length === 0) {
        const text = "ℹ️ Blocklist is already empty.";
        if (messageId) await this.client.editMessageText(chatId, messageId, text);
        else await this.client.sendMessage(chatId, text);
        return;
      }

      const allIds = items.map((it) => it.id);
      await this.listsService.deleteIpsBatch(this.listId, allIds);
      this.blocker.setBlockedList([]);

      const userTag = user ? ` (@${user.username || user.first_name})` : "";
      const text =
        `🧹 <b>Blocklist Flushed Successfully!</b>\n\n` +
        `All <b>${items.length}</b> IPs have been deleted from Cloudflare WAF in 1 bulk request.\n` +
        `<i>Action executed by${userTag}</i>`;

      if (messageId) {
        await this.client.editMessageText(chatId, messageId, text);
      } else {
        await this.client.sendMessage(chatId, text);
      }

      // Notify other admins about blocklist flush
      await this.broadcastToOtherAdmins(
        `🧹 <b>Admin Action: Blocklist Flushed</b>\nAll <b>${items.length}</b> IPs have been deleted from Cloudflare WAF by${userTag}.`,
        chatId
      );
    } catch (err) {
      const text = `❌ <b>Flush Failed:</b> ${(err as Error).message}`;
      if (messageId) await this.client.editMessageText(chatId, messageId, text);
      else await this.client.sendMessage(chatId, text);
    }
  }

  /**
   * Handles inline button callback queries (e.g. unban click, menu navigation, threshold presets)
   */
  private async handleCallbackQuery(cb: NonNullable<TelegramUpdate["callback_query"]>): Promise<void> {
    const chatId = cb.message?.chat.id || cb.from.id;
    const userId = cb.from.id;
    const data = cb.data || "";

    if (!this.isAuthorized(userId, chatId)) {
      await this.client.answerCallbackQuery(cb.id, "⛔ Unauthorized action.", true);
      return;
    }

    // Quick threshold adjustment presets
    if (data.startsWith("set_th:")) {
      const val = parseInt(data.replace("set_th:", ""), 10);
      if (!isNaN(val) && val > 0) {
        await this.client.answerCallbackQuery(cb.id, `Threshold set to ${val}!`);
        const policy = await this.getPolicy();
        policy.default.threshold = val;
        await this.savePolicySafely(policy);
        await this.sendPolicy(chatId, cb.message?.message_id);
      }
      return;
    }

    // Quick window adjustment presets
    if (data.startsWith("set_win:")) {
      const val = parseInt(data.replace("set_win:", ""), 10);
      if (!isNaN(val) && val > 0) {
        await this.client.answerCallbackQuery(cb.id, `Window set to ${val}s!`);
        const policy = await this.getPolicy();
        policy.windowSeconds = val;
        await this.savePolicySafely(policy);
        await this.sendPolicy(chatId, cb.message?.message_id);
      }
      return;
    }

    if (data === "flush:prompt") {
      await this.executeFlushPrompt(chatId, cb.message?.message_id);
      return;
    }

    if (data === "flush:confirm") {
      await this.executeFlushConfirmed(chatId, cb.message?.message_id, cb.from);
      return;
    }

    if (data === "flush:cancel") {
      await this.client.answerCallbackQuery(cb.id, "Flush operation cancelled.");
      if (cb.message) {
        await this.client.editMessageText(
          chatId,
          cb.message.message_id,
          "❌ <i>Flush operation cancelled. No changes were made.</i>"
        );
      }
      return;
    }

    if (data.startsWith("unban:")) {
      const ip = data.replace("unban:", "");
      await this.client.answerCallbackQuery(cb.id, `Unbanning ${ip}...`);

      if (this.listId) {
        try {
          const items = await this.listsService.getListItems(this.listId);
          const target = items.find((item) => item.ip === ip);
          if (target) {
            await this.listsService.deleteIpsBatch(this.listId, [target.id]);
            this.blocker.markAsUnblockedLocally(ip);
          }

          if (cb.message) {
            await this.client.editMessageText(
              chatId,
              cb.message.message_id,
              `${cb.message.text || ""}\n\n✅ <b>[UNBANNED]</b> <i>(by @${cb.from.username || cb.from.first_name})</i>`
            );
          }

          // Broadcast unban action to other admins
          const adminTag = cb.from.username ? `@${cb.from.username}` : (cb.from.first_name || "Admin");
          await this.broadcastToOtherAdmins(
            `🔓 <b>Admin Action: IP Unbanned via Button</b>\n🌐 <b>IP:</b> <code>${ip}</code>\n👤 <b>By:</b> ${adminTag}`,
            chatId
          );
        } catch (err) {
          await this.client.sendMessage(chatId, `❌ Unban Error: ${(err as Error).message}`);
        }
      }
      return;
    }

    if (data.startsWith("reban:")) {
      const ip = data.replace("reban:", "");
      await this.client.answerCallbackQuery(cb.id, `Re-banning ${ip}...`);

      if (this.listId) {
        try {
          await this.listsService.addIpToList(
            this.listId,
            ip,
            `Manual re-ban via Telegram by @${cb.from.username || cb.from.first_name || cb.from.id}`
          );
          this.blocker.markAsBlockedLocally(ip);

          if (cb.message) {
            await this.client.editMessageText(
              chatId,
              cb.message.message_id,
              `${cb.message.text || ""}\n\n🚫 <b>[RE-BANNED]</b> <i>(by @${cb.from.username || cb.from.first_name})</i>`
            );
          }

          // Broadcast re-ban action to other admins
          const adminTag = cb.from.username ? `@${cb.from.username}` : (cb.from.first_name || "Admin");
          await this.broadcastToOtherAdmins(
            `🚫 <b>Admin Action: IP Re-Banned via Button</b>\n🌐 <b>IP:</b> <code>${ip}</code>\n👤 <b>By:</b> ${adminTag}`,
            chatId
          );
        } catch (err) {
          await this.client.sendMessage(chatId, `❌ Re-ban Error: ${(err as Error).message}`);
        }
      }
      return;
    }

    // Command shortcuts via buttons
    await this.client.answerCallbackQuery(cb.id);
    switch (data) {
      case "cmd:status":
        await this.sendStatus(chatId);
        break;
      case "cmd:evaluate":
        await this.executeEvaluate(chatId);
        break;
      case "cmd:list":
        await this.sendList(chatId);
        break;
      case "cmd:policy":
        await this.sendPolicy(chatId, cb.message?.message_id);
        break;
    }
  }

  /**
   * Broadcasts a real-time attack alert when new high-frequency IPs are blocked by the system
   */
  public async notifyBannedIps(decisions: GuardDecision[]): Promise<void> {
    const newlyBlocked = decisions.filter((d) => d.action === "BLOCK");
    if (newlyBlocked.length === 0 || this.adminChatIds.size === 0) return;

    for (const adminId of this.adminChatIds) {
      for (const d of newlyBlocked) {
        const text =
          `🚨 <b>Auto Guard: Threat Detected & Mitigated!</b>\n` +
          `━━━━━━━━━━━━━━━━━━━━\n` +
          `🌐 <b>IP:</b> <code>${d.ip}</code>\n` +
          `🏳️ <b>Country:</b> ${d.country || "Unknown"}\n` +
          `📊 <b>Traffic:</b> <b>${d.requestCount} requests</b> (Threshold: ${d.threshold})\n` +
          `🏷️ <b>Rank:</b> #${d.rank}\n` +
          `📝 <b>Reason:</b> <i>${d.reason}</i>\n` +
          `━━━━━━━━━━━━━━━━━━━━\n` +
          `⏰ <i>${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC</i>`;

        const keyboard: TelegramInlineKeyboardMarkup = {
          inline_keyboard: [[{ text: `🔓 Unban (${d.ip})`, callback_data: `unban:${d.ip}` }]]
        };

        await this.client.sendMessage(adminId, text, { reply_markup: keyboard });
      }
    }
  }

  /**
   * Broadcasts a real-time notification to all administrators whenever IPs are unbanned
   * (e.g. TTL expired or FIFO list limit pruning)
   */
  public async notifyUnbannedIps(unbanned: PrunedUnbanItem[]): Promise<void> {
    if (!unbanned || unbanned.length === 0 || this.adminChatIds.size === 0) return;

    if (unbanned.length <= 5) {
      for (const adminId of this.adminChatIds) {
        for (const u of unbanned) {
          const reasonLabel =
            u.reason === "TTL_EXPIRED"
              ? "⏳ <b>TTL Expired</b> <i>(Automatic ban expiration)</i>"
              : "🧹 <b>List Limit FIFO</b> <i>(Pruned to preserve list capacity)</i>";

          const text =
            `🔓 <b>Auto Guard: IP Unbanned</b>\n` +
            `━━━━━━━━━━━━━━━━━━━━\n` +
            `🌐 <b>IP:</b> <code>${u.ip}</code>\n` +
            `📋 <b>Reason:</b> ${reasonLabel}\n` +
            (u.comment ? `💬 <b>Original Ban:</b> <i>${u.comment}</i>\n` : "") +
            (u.createdOn ? `📅 <b>Banned At:</b> <i>${u.createdOn}</i>\n` : "") +
            `━━━━━━━━━━━━━━━━━━━━\n` +
            `⏰ <i>${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC</i>`;

          const keyboard: TelegramInlineKeyboardMarkup = {
            inline_keyboard: [[{ text: `🚫 Re-Ban (${u.ip})`, callback_data: `reban:${u.ip}` }]]
          };

          await this.client.sendMessage(adminId, text, { reply_markup: keyboard });
        }
      }
    } else {
      for (const adminId of this.adminChatIds) {
        let text =
          `🔓 <b>Auto Guard: Batch Auto-Unban Executed</b>\n` +
          `━━━━━━━━━━━━━━━━━━━━\n` +
          `<b>Total Unbanned:</b> ${unbanned.length} IPs\n\n`;

        for (const u of unbanned.slice(0, 25)) {
          const tag = u.reason === "TTL_EXPIRED" ? "TTL Expired" : "FIFO Overflow";
          text += `• <code>${u.ip}</code> — <i>${tag}</i>\n`;
        }

        if (unbanned.length > 25) {
          text += `\n<i>...and ${unbanned.length - 25} additional IPs</i>\n`;
        }

        text +=
          `━━━━━━━━━━━━━━━━━━━━\n` +
          `⏰ <i>${new Date().toISOString().replace("T", " ").slice(0, 19)} UTC</i>`;

        await this.client.sendMessage(adminId, text);
      }
    }
  }
}
