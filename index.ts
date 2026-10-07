/**
 * Cloudflare Worker — Production-Grade Country-Based Auto Guard
 *
 * Automatically inspects Cloudflare GraphQL Zone Analytics, identifies high-frequency
 * malicious IPs based on country policies, and mitigates them via Cloudflare Lists API & WAF.
 *
 * Multi-Interface: Headless JSON API via cURL + Complete Two-Way Interactive Telegram Bot.
 */
import { DEFAULT_GUARD_POLICY } from "@/config/defaults";
import { GuardPolicy } from "@/domain/models/policy";
import { safeValidatePolicy } from "@/config/policy-schema";
import { DecisionEngine } from "@/guard/decision-engine";
import { Blocker } from "@/guard/blocker";
import { AllowlistMatcher } from "@/security/allowlist";
import { CloudflareApiClient } from "@/cloudflare/client";
import { CloudflareListsService } from "@/cloudflare/lists";
import { CloudflareAnalyticsService } from "@/cloudflare/analytics";
import { TelegramClient } from "@/telegram/client";
import { TelegramBotHandler } from "@/telegram/bot";
import { TelegramUpdate } from "@/telegram/types";
import { parseZones } from "@/domain/models/zone";
import { logger } from "@/observability/logger";
import { metrics } from "@/observability/metrics";

export interface Env {
  POLICY_KV?: KVNamespace;
  CF_ZONES?: string;
  CF_ACCOUNT_ID?: string;
  CF_API_TOKEN?: string;
  CF_LIST_ID?: string;
  CF_LIST_NAME?: string;
  DRY_RUN?: string;
  GUARD_ADMIN_TOKEN?: string;
  TELEGRAM_BOT_TOKEN?: string;
  TELEGRAM_ADMIN_CHAT_ID?: string;
}

// Runtime in-memory policy state & allowlist
let runtimePolicy: GuardPolicy = DEFAULT_GUARD_POLICY;
const allowlistMatcher = new AllowlistMatcher(DEFAULT_GUARD_POLICY.allowlist || []);

async function getActivePolicy(env: Env): Promise<GuardPolicy> {
  if (env.POLICY_KV) {
    try {
      const raw = await env.POLICY_KV.get("guard:policy", "text");
      if (raw) {
        const parsed = JSON.parse(raw);
        const val = safeValidatePolicy(parsed);
        if (val.success) {
          return val.data as GuardPolicy;
        }
      }
    } catch {
      // Fallback to runtime memory policy
    }
  }
  return runtimePolicy;
}

function createServices(env: Env) {
  const apiToken = env.CF_API_TOKEN || "";
  const accountId = env.CF_ACCOUNT_ID || "";

  const cfClient = new CloudflareApiClient({
    apiToken,
    accountId
  });

  const listsService = new CloudflareListsService(cfClient);
  const analyticsService = new CloudflareAnalyticsService(cfClient);

  const isDryRun = env.DRY_RUN === "true";
  const blocker = new Blocker(listsService, {
    listId: env.CF_LIST_ID,
    dryRun: isDryRun
  });

  const decisionEngine = new DecisionEngine({
    analyticsService,
    blocker,
    allowlistMatcher
  });

  const telegramClient = new TelegramClient(env.TELEGRAM_BOT_TOKEN || "");
  const adminChatIds = (env.TELEGRAM_ADMIN_CHAT_ID || "")
    .split(/[|\r\n,;\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const zones = parseZones(env.CF_ZONES);

  const telegramBot = new TelegramBotHandler({
    client: telegramClient,
    adminChatIds,
    listsService,
    decisionEngine,
    blocker,
    listId: env.CF_LIST_ID,
    zones,
    getPolicy: () => getActivePolicy(env),
    savePolicy: async (newPolicy: GuardPolicy) => {
      if (env.POLICY_KV) {
        await env.POLICY_KV.put("guard:policy", JSON.stringify(newPolicy, null, 2));
      }
      runtimePolicy = newPolicy;
      if (runtimePolicy.allowlist) {
        allowlistMatcher.update(runtimePolicy.allowlist);
      }
    }
  });

  return { decisionEngine, listsService, blocker, telegramClient, telegramBot, zones };
}

export default {
  /**
   * Main request handler: JSON API + Telegram Bot Webhook
   */
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // 0. Public routes: healthchecks, debug, and incoming Telegram webhook
    const isPublicRoute =
      url.pathname === "/health" ||
      url.pathname === "/__guard/health" ||
      url.pathname === "/_debug" ||
      url.pathname === "/__guard/debug" ||
      url.pathname === "/__guard/telegram/webhook" ||
      url.pathname === "/__guard/telegram" ||
      url.pathname === "/telegram";

    // 0.5. Debug endpoint: Diagnostic check of environment variables presence
    if (url.pathname === "/_debug" || url.pathname === "/__guard/debug") {
      const zones = parseZones(env.CF_ZONES);
      return new Response(
        JSON.stringify(
          {
            CF_ACCOUNT_ID: !!env.CF_ACCOUNT_ID,
            CF_API_TOKEN: !!env.CF_API_TOKEN,
            CF_LIST_ID: !!env.CF_LIST_ID,
            CF_ZONES: !!env.CF_ZONES,
            configuredZones: zones.map((z) => ({ name: z.name, id: `${z.id.slice(0, 6)}...` })),
            DRY_RUN: env.DRY_RUN,
            GUARD_ADMIN_TOKEN: !!env.GUARD_ADMIN_TOKEN,
            TELEGRAM_BOT_TOKEN: !!env.TELEGRAM_BOT_TOKEN,
            TELEGRAM_ADMIN_CHAT_ID: !!env.TELEGRAM_ADMIN_CHAT_ID,
            POLICY_KV: !!env.POLICY_KV,
            allEnvKeys: Object.keys(env || {})
          },
          null,
          2
        ),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // 0.8. Telegram Webhook Endpoint (Receives updates from Telegram servers)
    if (
      url.pathname === "/__guard/telegram/webhook" ||
      url.pathname === "/__guard/telegram" ||
      url.pathname === "/telegram"
    ) {
      if (request.method !== "POST") {
        return new Response(
          JSON.stringify({ status: "ok", message: "Telegram webhook endpoint ready. Send POST updates here." }),
          { headers: { "Content-Type": "application/json" } }
        );
      }

      const { telegramBot } = createServices(env);
      try {
        const update = (await request.json()) as TelegramUpdate;
        ctx.waitUntil(telegramBot.handleUpdate(update));
        return new Response(JSON.stringify({ ok: true }), {
          headers: { "Content-Type": "application/json" }
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ ok: false, error: (err as Error).message }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // 0.9. Telegram One-Click Webhook & Commands Registration
    if (url.pathname === "/__guard/telegram/setup") {
      const { telegramClient } = createServices(env);
      const webhookUrl = `${url.origin}/__guard/telegram/webhook`;
      const webhookResult = await telegramClient.setWebhook(webhookUrl);
      const commandsResult = await telegramClient.setMyCommands([
        { command: "status", description: "System health and active banned IP count" },
        { command: "evaluate", description: "Trigger edge traffic evaluation now" },
        { command: "list", description: "View currently banned IPs in Cloudflare WAF" },
        { command: "flush", description: "Flush and unban all currently blocked IPs" },
        { command: "ban", description: "Manually block an IP: /ban <ip> [reason]" },
        { command: "unban", description: "Remove IP(s) from blocklist: /unban <ip1> [ip2]" },
        { command: "policy", description: "View active threshold and protection policy" },
        { command: "admins", description: "List authorized administrator accounts" },
        { command: "help", description: "Show interactive control panel and menu" }
      ]);

      return new Response(
        JSON.stringify(
          {
            status: webhookResult.ok && commandsResult.ok ? "success" : "partial_or_failed",
            webhookUrl,
            webhookResponse: webhookResult,
            commandsResponse: commandsResult
          },
          null,
          2
        ),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // 1. Security Guard for REST API: Protect admin/mutation routes with GUARD_ADMIN_TOKEN
    if (!isPublicRoute) {
      const adminToken = env.GUARD_ADMIN_TOKEN;
      if (adminToken) {
        const providedToken = request.headers.get("X-Guard-Token") || url.searchParams.get("token");
        if (providedToken !== adminToken) {
          return new Response(
            JSON.stringify(
              {
                error: "UNAUTHORIZED",
                message: "Access Denied: Missing or invalid X-Guard-Token header or ?token= param."
              },
              null,
              2
            ),
            { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }
      }
    }

    // 2. Healthcheck endpoint
    if (url.pathname === "/health" || url.pathname === "/__guard/health") {
      return new Response(JSON.stringify({ status: "healthy", timestamp: Date.now() }, null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // 3. Metrics endpoint
    if (url.pathname === "/__guard/metrics") {
      return new Response(JSON.stringify(metrics.getSnapshot(), null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }

    const { decisionEngine, telegramBot } = createServices(env);
    const activePolicy = await getActivePolicy(env);

    if (activePolicy.allowlist && activePolicy.allowlist.length > 0) {
      allowlistMatcher.update(activePolicy.allowlist);
    }

    // 4. Policy View & Upload / Mutation API endpoint (cURL)
    if (url.pathname === "/__guard/policy" || url.pathname === "/policy") {
      if (request.method === "POST" || request.method === "PUT") {
        try {
          const body = await request.json();
          const validation = safeValidatePolicy(body);

          if (!validation.success) {
            return new Response(
              JSON.stringify(
                {
                  error: "INVALID_POLICY_SCHEMA",
                  message: validation.error?.message,
                  issues: validation.error?.issues
                },
                null,
                2
              ),
              { status: 400, headers: { "Content-Type": "application/json" } }
            );
          }

          const validatedPolicy = validation.data as GuardPolicy;

          // Persist to KV if namespace is bound
          if (env.POLICY_KV) {
            await env.POLICY_KV.put("guard:policy", JSON.stringify(validatedPolicy, null, 2));
          }

          // Update runtime memory & allowlist
          runtimePolicy = validatedPolicy;
          if (runtimePolicy.allowlist) {
            allowlistMatcher.update(runtimePolicy.allowlist);
          }

          return new Response(
            JSON.stringify(
              {
                status: "success",
                message: "Policy updated successfully via cURL!",
                persistedToKv: Boolean(env.POLICY_KV),
                policy: validatedPolicy
              },
              null,
              2
            ),
            { headers: { "Content-Type": "application/json" } }
          );
        } catch (err) {
          return new Response(
            JSON.stringify({ error: "INVALID_JSON", message: (err as Error).message }, null, 2),
            { status: 400, headers: { "Content-Type": "application/json" } }
          );
        }
      }

      // GET: Return active policy
      return new Response(JSON.stringify(activePolicy, null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // 5. Manual evaluation endpoint: Fetches edge analytics and evaluates top IPs immediately
    if (url.pathname === "/__guard/evaluate" || url.pathname === "/evaluate") {
      const queryZoneId = url.searchParams.get("zoneId");
      const queryZoneName = url.searchParams.get("zoneName");
      const targetZones = queryZoneId
        ? [{ id: queryZoneId, name: queryZoneName || queryZoneId }]
        : parseZones(env.CF_ZONES);

      if (targetZones.length === 0) {
        return new Response(
          JSON.stringify({
            error: "MISSING_ZONES",
            message: "CF_ZONES is not configured, and no ?zoneId query parameter was provided."
          }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      const { decisions, unbanned, zoneSummaries } = await decisionEngine.evaluateZones(
        activePolicy,
        targetZones
      );

      // Push real-time alert to Telegram admins for blocked threats & unbanned IPs
      ctx.waitUntil(
        Promise.all([
          telegramBot.notifyBannedIps(decisions),
          telegramBot.notifyUnbannedIps(unbanned)
        ])
      );

      return new Response(
        JSON.stringify(
          {
            status: "success",
            zonesEvaluated: targetZones.length,
            zones: targetZones.map((z) => z.name),
            zoneSummaries,
            evaluated: decisions.length,
            unbannedCount: unbanned.length,
            unbanned,
            decisions
          },
          null,
          2
        ),
        {
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    // Default status dashboard response (JSON)
    const configuredZones = parseZones(env.CF_ZONES);
    return new Response(
      JSON.stringify(
        {
          status: "active",
          guard: "Cloudflare Auto Guard (Edge Engine)",
          telegramBot: !!env.TELEGRAM_BOT_TOKEN ? "enabled" : "disabled",
          monitoredZonesCount: configuredZones.length,
          monitoredZones: configuredZones.map((z) => z.name),
          sharedListId: env.CF_LIST_ID ? `${env.CF_LIST_ID.slice(0, 6)}...` : "NOT_CONFIGURED",
          interfaces: {
            telegramWebhook: "/__guard/telegram/webhook",
            telegramSetup: "/__guard/telegram/setup",
            policy: "/__guard/policy",
            evaluate: "/__guard/evaluate",
            health: "/__guard/health"
          }
        },
        null,
        2
      ),
      {
        headers: { "Content-Type": "application/json" }
      }
    );
  },

  /**
   * Scheduled cron event: Periodically inspects Cloudflare Analytics and enforces security policy
   */
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const zones = parseZones(env.CF_ZONES);
    if (zones.length === 0) {
      logger.warn("SCHEDULED_SKIPPED_NO_ZONES", {
        message: "CF_ZONES is not configured. Skipping automated evaluation."
      });
      return;
    }

    const { decisionEngine, telegramBot } = createServices(env);
    const activePolicy = await getActivePolicy(env);

    if (activePolicy.allowlist && activePolicy.allowlist.length > 0) {
      allowlistMatcher.update(activePolicy.allowlist);
    }

    ctx.waitUntil(
      decisionEngine
        .evaluateZones(activePolicy, zones)
        .then(({ decisions, unbanned }) => {
          return Promise.all([
            telegramBot.notifyBannedIps(decisions),
            telegramBot.notifyUnbannedIps(unbanned)
          ]);
        })
        .catch((err) => {
          logger.error("SCHEDULED_EVALUATION_FAILED", {
            message: (err as Error).message
          });
        })
    );
  }
};
