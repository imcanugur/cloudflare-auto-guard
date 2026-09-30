/**
 * Decision Engine: Main coordinator for the Auto Guard pipeline using Cloudflare Analytics
 */
import { GuardPolicy } from "@/domain/models/policy";
import { GuardDecision } from "@/domain/models/decision";
import { CloudflareAnalyticsService } from "@/cloudflare/analytics";
import { AllowlistMatcher } from "@/security/allowlist";
import { CandidateEvaluator } from "@/guard/evaluator";
import { Blocker } from "@/guard/blocker";
import { metrics } from "@/observability/metrics";

export interface DecisionEngineOptions {
  analyticsService: CloudflareAnalyticsService;
  blocker: Blocker;
  allowlistMatcher: AllowlistMatcher;
}

export class DecisionEngine {
  private analyticsService: CloudflareAnalyticsService;
  private blocker: Blocker;
  private allowlistMatcher: AllowlistMatcher;

  constructor(options: DecisionEngineOptions) {
    this.analyticsService = options.analyticsService;
    this.blocker = options.blocker;
    this.allowlistMatcher = options.allowlistMatcher;
  }

  /**
   * Fetches top traffic candidates from Cloudflare Analytics and evaluates against active policy
   */
  public async evaluateCandidates(policy: GuardPolicy, zoneId: string): Promise<GuardDecision[]> {
    if (!policy.enabled || !zoneId) {
      return [];
    }

    const windowSeconds = policy.windowSeconds ?? 300;
    const topN = policy.topN ?? 100;

    // 1. Sync existing blocked IPs from Cloudflare List for 100% idempotency
    await this.blocker.syncExistingList();

    // 2. Fetch real edge Top-N IP statistics directly from Cloudflare GraphQL Analytics
    const candidates = await this.analyticsService.fetchTopIps(zoneId, windowSeconds, topN);
    metrics.increment("top_n_candidates", candidates.length);

    const decisions: GuardDecision[] = [];
    const toBlock: GuardDecision[] = [];

    // 3. Evaluate each candidate against the resolved country policy
    for (const candidate of candidates) {
      const isAlreadyBlocked = this.blocker.isAlreadyBlocked(candidate.ip);

      const decision = CandidateEvaluator.evaluate({
        ip: candidate.ip,
        country: candidate.country,
        asn: candidate.asn,
        requestCount: candidate.requestCount,
        rank: candidate.rank,
        policy,
        allowlistMatcher: this.allowlistMatcher,
        isAlreadyBlocked
      });

      if (decision.action === "BLOCK") {
        toBlock.push(decision);
      } else {
        metrics.increment("ignored_ips");
        decisions.push(decision);
      }
    }

    // 4. Execute all blocks in a single batch API call (prevents subrequest limit errors)
    if (toBlock.length > 0) {
      const executedBlocks = await this.blocker.executeBlockBatch(toBlock);
      decisions.push(...executedBlocks);
    }

    return decisions;
  }
}
