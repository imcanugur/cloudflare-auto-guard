/**
 * Cloudflare Worker — Production-Grade Country-Based Auto Guard
 *
 * Automatically inspects Cloudflare GraphQL Zone Analytics, identifies high-frequency
 * malicious IPs based on runtime country policies in KV, and mitigates them via Cloudflare Lists API & WAF.
 */
import { DEFAULT_GUARD_POLICY } from "@/config/defaults";
import { DecisionEngine } from "@/guard/decision-engine";
import { Blocker } from "@/guard/blocker";
import { AllowlistMatcher } from "@/security/allowlist";
import { CloudflareApiClient } from "@/cloudflare/client";
import { CloudflareListsService } from "@/cloudflare/lists";
import { CloudflareAnalyticsService } from "@/cloudflare/analytics";
import { logger } from "@/observability/logger";
import { metrics } from "@/observability/metrics";

export interface Env {
  CF_ZONE_ID?: string;
  CF_ACCOUNT_ID?: string;
  CF_API_TOKEN?: string;
  CF_LIST_ID?: string;
  CF_LIST_NAME?: string;
  DRY_RUN?: string;
  GUARD_ADMIN_TOKEN?: string;
}

const allowlistMatcher = new AllowlistMatcher();

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

  return { decisionEngine, listsService, blocker };
}

export default {
  /**
   * Main request handler: Exposes health, metrics, and on-demand evaluation endpoints
   */
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // 0. Security Guard: Protect admin/management routes
    const isLocal = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    const isAdminRoute = url.pathname.startsWith("/__guard") || url.pathname === "/policy" || url.pathname === "/evaluate";
    const isPublicHealth = url.pathname === "/health" || url.pathname === "/__guard/health";

    if (isAdminRoute && !isPublicHealth) {
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
      } else if (!isLocal && request.method === "POST") {
        return new Response(
          JSON.stringify(
            {
              error: "GUARD_ADMIN_TOKEN_REQUIRED",
              message: "Security Protection: In production, GUARD_ADMIN_TOKEN secret must be configured to authorize policy updates."
            },
            null,
            2
          ),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // 1. Healthcheck endpoint
    if (url.pathname === "/health" || url.pathname === "/__guard/health") {
      return new Response(JSON.stringify({ status: "healthy", timestamp: Date.now() }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // 2. Metrics endpoint
    if (url.pathname === "/__guard/metrics") {
      return new Response(JSON.stringify(metrics.getSnapshot(), null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }

    const { decisionEngine } = createServices(env);

    // 3. Load static policy directly from policy.json
    const policy = DEFAULT_GUARD_POLICY;

    if (policy.allowlist && policy.allowlist.length > 0) {
      allowlistMatcher.update(policy.allowlist);
    }

    // 3.5. View policy endpoint (returns active policy.json)
    if (url.pathname === "/__guard/policy" || url.pathname === "/policy") {
      return new Response(JSON.stringify(policy, null, 2), {
        headers: { "Content-Type": "application/json" }
      });
    }

    // 4. Manual evaluation endpoint: Fetches edge analytics and evaluates top IPs immediately
    if (url.pathname === "/__guard/evaluate" || url.pathname === "/evaluate") {
      const zoneId = env.CF_ZONE_ID || url.searchParams.get("zoneId") || "";

      if (!zoneId) {
        return new Response(
          JSON.stringify({
            error: "MISSING_ZONE_ID",
            message: "CF_ZONE_ID environment variable or ?zoneId query parameter is required."
          }),
          { status: 400, headers: { "Content-Type": "application/json" } }
        );
      }

      const decisions = await decisionEngine.evaluateCandidates(policy, zoneId);
      return new Response(
        JSON.stringify(
          {
            status: "success",
            zoneId,
            evaluated: decisions.length,
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

    // Default status dashboard response
    return new Response(
      JSON.stringify(
        {
          status: "active",
          guard: "Cloudflare Auto Guard (Analytics-Powered)",
          zoneId: env.CF_ZONE_ID ? `${env.CF_ZONE_ID.slice(0, 6)}...` : "NOT_CONFIGURED",
          endpoints: {
            evaluate: "/__guard/evaluate",
            metrics: "/__guard/metrics",
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
    const zoneId = env.CF_ZONE_ID;
    if (!zoneId) {
      logger.warn("SCHEDULED_SKIPPED_NO_ZONE_ID", {
        message: "CF_ZONE_ID is not configured. Skipping automated evaluation."
      });
      return;
    }

    const { decisionEngine } = createServices(env);
    const policy = DEFAULT_GUARD_POLICY;

    if (policy.allowlist && policy.allowlist.length > 0) {
      allowlistMatcher.update(policy.allowlist);
    }

    ctx.waitUntil(
      decisionEngine.evaluateCandidates(policy, zoneId).catch((err) => {
        logger.error("SCHEDULED_EVALUATION_FAILED", {
          message: (err as Error).message
        });
      })
    );
  }
};
