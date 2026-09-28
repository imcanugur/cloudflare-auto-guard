/**
 * Cloudflare Worker — Production-Grade Country-Based Auto Guard
 *
 * Automatically inspects Cloudflare GraphQL Zone Analytics, identifies high-frequency
 * malicious IPs based on runtime country policies in KV, and mitigates them via Cloudflare Lists API & WAF.
 */
import { PolicyCache } from "@/storage/policy-cache";
import { DecisionEngine } from "@/guard/decision-engine";
import { Blocker } from "@/guard/blocker";
import { AllowlistMatcher } from "@/security/allowlist";
import { CloudflareApiClient } from "@/cloudflare/client";
import { CloudflareListsService } from "@/cloudflare/lists";
import { CloudflareAnalyticsService } from "@/cloudflare/analytics";
import { logger } from "@/observability/logger";
import { metrics } from "@/observability/metrics";

export interface Env {
  POLICY_KV: KVNamespace;
  CF_ZONE_ID?: string;
  CF_ACCOUNT_ID?: string;
  CF_API_TOKEN?: string;
  CF_LIST_ID?: string;
  CF_LIST_NAME?: string;
  POLICY_CACHE_TTL_MS?: string;
  DRY_RUN?: string;
  GUARD_ADMIN_TOKEN?: string;
}

// Module-level in-memory cache
const policyCache = new PolicyCache(30000);
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

    // 0. Security Guard: Protect all /__guard/* endpoints with GUARD_ADMIN_TOKEN
    if (url.pathname.startsWith("/__guard") && url.pathname !== "/__guard/health") {
      const adminToken = env.GUARD_ADMIN_TOKEN;
      if (adminToken) {
        const providedToken = request.headers.get("X-Guard-Token") || url.searchParams.get("token");
        if (providedToken !== adminToken) {
          return new Response(
            JSON.stringify(
              {
                error: "UNAUTHORIZED",
                message: "Access Denied: Missing or invalid X-Guard-Token."
              },
              null,
              2
            ),
            { status: 401, headers: { "Content-Type": "application/json" } }
          );
        }
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

    // 3. Load / refresh cached policy from KV
    if (env.POLICY_CACHE_TTL_MS) {
      policyCache.setTtl(parseInt(env.POLICY_CACHE_TTL_MS, 10));
    }
    const policy = await policyCache.getPolicy(env.POLICY_KV);

    if (policy.allowlist && policy.allowlist.length > 0) {
      allowlistMatcher.update(policy.allowlist);
    }

    // 3.5. View or update KV policy endpoint
    if (url.pathname === "/__guard/policy" || url.pathname === "/policy") {
      if (request.method === "POST") {
        try {
          const body = await request.json();
          await env.POLICY_KV.put("guard:policy", JSON.stringify(body, null, 2));
          policyCache.invalidate();
          return new Response(JSON.stringify({ status: "success", message: "Policy updated in KV successfully", policy: body }, null, 2), {
            headers: { "Content-Type": "application/json" }
          });
        } catch (err) {
          return new Response(JSON.stringify({ error: "INVALID_JSON", message: (err as Error).message }, null, 2), {
            status: 400,
            headers: { "Content-Type": "application/json" }
          });
        }
      }

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
    const policy = await policyCache.getPolicy(env.POLICY_KV);

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
