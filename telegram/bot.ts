/**
 * Telegram Bot Controller & Interactive Command Handler
 */
import { TelegramClient } from "@/telegram/client";
import { TelegramUpdate, TelegramInlineKeyboardMarkup } from "@/telegram/types";
import { CloudflareListsService } from "@/cloudflare/lists";
import { DecisionEngine } from "@/guard/decision-engine";
import { Blocker } from "@/guard/blocker";
import { GuardPolicy } from "@/domain/models/policy";
import { GuardDecision } from "@/domain/models/decision";

export interface TelegramBotOptions {
  client: TelegramClient;
  adminChatIds: string[];
  listsService: CloudflareListsService;
  decisionEngine: DecisionEngine;
  blocker: Blocker;
  listId?: string;
  zoneId?: string;
  getPolicy: () => Promise<GuardPolicy>;
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

  constructor(options: TelegramBotOptions) {
    this.client = options.client;
    this.adminChatIds = new Set(options.adminChatIds.filter(Boolean));
    this.listsService = options.listsService;
    this.decisionEngine = options.decisionEngine;
    this.blocker = options.blocker;
    this.listId = options.listId;
    this.zoneId = options.zoneId;
    this.getPolicy = options.getPolicy;
  }

  /**
   * Verifies if a Telegram user/chat ID is an authorized administrator
   */
  private isAuthorized(chatId: number | string): boolean {
    if (this.adminChatIds.size === 0) return false;
    return this.adminChatIds.has(String(chatId));
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
    const text = (message.text || "").trim();

    if (!this.isAuthorized(chatId)) {
      await this.client.sendMessage(
        chatId,
        "⛔ <b>Unauthorized Access!</b>\nThis bot is strictly restricted to system administrators. Your Chat ID:\n<code>" +
          chatId +
          "</code>"
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
      case "/ban":
        await this.executeBan(chatId, args[0], args.slice(1).join(" "));
        break;
      case "/unban":
        await this.executeUnban(chatId, args[0]);
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
      `Manage and inspect edge security directly from Telegram:\n\n` +
      `<b>⚡ Available Commands:</b>\n` +
      `• /status — Real-time system health and WAF metrics\n` +
      `• /evaluate — Trigger edge GraphQL traffic analysis now\n` +
      `• /list — View currently banned IPs in Cloudflare WAF\n` +
      `• /ban &lt;IP&gt; [reason] — Manually add an IP to the WAF list\n` +
      `• /unban &lt;IP&gt; — Remove an IP from the WAF blocklist\n` +
      `• /policy — View active threshold and protection policy\n\n` +
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

    const text =
      `📊 <b>Auto Guard System Status</b>\n` +
      `━━━━━━━━━━━━━━━━━━━━\n` +
      `🟢 <b>Status:</b> Active & Guarding\n` +
      `🌐 <b>Zone ID:</b> <code>${this.zoneId || "Not Configured"}</code>\n` +
      `📋 <b>WAF List ID:</b> <code>${this.listId || "Not Configured"}</code>\n` +
      `🚫 <b>Active Banned IPs:</b> <b>${itemCount}</b> / 10,000\n` +
      `━━━━━━━━━━━━━━━━━━━━\n` +
      `⚙️ <b>Policy Summary:</b>\n` +
      `• Default Threshold: <b>${policy.defaultThreshold} reqs</b> / ${policy.windowSeconds}s\n` +
      `• Top-N Sampling: <b>${policy.topN} IPs</b>\n` +
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
        ]
      ]
    };

    await this.client.sendMessage(chatId, text, { reply_markup: keyboard });
  }

  /**
   * /list command: Displays active banned IPs with quick unban buttons
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

    const buttons = latestItems.slice(0, 5).map((item) => [
      { text: `🔓 Unban ${item.ip}`, callback_data: `unban:${item.ip}` }
    ]);

    for (let i = 0; i < latestItems.length; i++) {
      const it = latestItems[i];
      const dateStr = it.created_on ? it.created_on.slice(0, 16).replace("T", " ") : "-";
      text += `${i + 1}. <code>${it.ip}</code>\n   📝 <i>${it.comment || "Auto Guard"}</i>\n   📅 ${dateStr}\n\n`;
    }

    const keyboard: TelegramInlineKeyboardMarkup = {
      inline_keyboard: [
        ...buttons,
        [{ text: "🔄 Refresh", callback_data: "cmd:list" }]
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
      const decisions = await this.decisionEngine.evaluateCandidates(policy, this.zoneId);

      const blocked = decisions.filter((d) => d.action === "BLOCK");
      const ignored = decisions.filter((d) => d.action === "IGNORE");

      let report =
        `⚡ <b>Evaluation Completed!</b>\n\n` +
        `📊 <b>Analyzed Candidates:</b> ${decisions.length}\n` +
        `🚫 <b>Newly Blocked:</b> ${blocked.length}\n` +
        `✅ <b>Clean / Ignored:</b> ${ignored.length}\n\n`;

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
   * /policy command: Displays current protection rules
   */
  private async sendPolicy(chatId: number): Promise<void> {
    const policy = await this.getPolicy();
    const formatted = JSON.stringify(policy, null, 2);

    await this.client.sendMessage(
      chatId,
      `📜 <b>Active Protection Policy:</b>\n<pre><code class="language-json">${formatted}</code></pre>`
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
    } catch (err) {
      await this.client.sendMessage(chatId, `❌ Ban Failed:\n<code>${(err as Error).message}</code>`);
    }
  }

  /**
   * /unban command: Manual unban execution
   */
  private async executeUnban(chatId: number, ip?: string): Promise<void> {
    if (!ip) {
      await this.client.sendMessage(chatId, "⚠️ Usage: <code>/unban &lt;IP&gt;</code>\nExample: <code>/unban 1.2.3.4</code>");
      return;
    }

    if (!this.listId) {
      await this.client.sendMessage(chatId, "⚠️ CF_LIST_ID is not configured.");
      return;
    }

    try {
      const items = await this.listsService.getListItems(this.listId);
      const target = items.find((item) => item.ip === ip);

      if (!target) {
        await this.client.sendMessage(chatId, `ℹ️ <code>${ip}</code> was not found in the active blocklist.`);
        return;
      }

      await this.listsService.deleteIpsBatch(this.listId, [target.id]);
      this.blocker.markAsUnblockedLocally(ip);

      await this.client.sendMessage(
        chatId,
        `✅ <b>IP Successfully Unbanned!</b>\n<code>${ip}</code> has been removed from Cloudflare WAF list.`
      );
    } catch (err) {
      await this.client.sendMessage(chatId, `❌ Unban Failed:\n<code>${(err as Error).message}</code>`);
    }
  }

  /**
   * Handles inline button callback queries (e.g. unban click, menu navigation)
   */
  private async handleCallbackQuery(cb: NonNullable<TelegramUpdate["callback_query"]>): Promise<void> {
    const chatId = cb.message?.chat.id || cb.from.id;
    const data = cb.data || "";

    if (!this.isAuthorized(chatId)) {
      await this.client.answerCallbackQuery(cb.id, "⛔ Unauthorized action.", true);
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
        } catch (err) {
          await this.client.sendMessage(chatId, `❌ Unban Error: ${(err as Error).message}`);
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
        await this.sendPolicy(chatId);
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
}
