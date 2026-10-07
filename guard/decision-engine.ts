/**
 * Decision Engine: Main coordinator for the Auto Guard pipeline using Cloudflare Analytics
 */
import { GuardPolicy } from "@/domain/models/policy";
import { GuardDecision } from "@/domain/models/decision";
import { CloudflareAnalyticsService } from "@/cloudflare/analytics";
import { AllowlistMatcher } from "@/security/allowlist";
import { CandidateEvaluator } from "@/guard/evaluator";
import { Blocker, PrunedUnbanItem } from "@/guard/blocker";
import { ZoneConfig } from "@/domain/models/zone";
import { metrics } from "@/observability/metrics";
import { logger } from "@/observability/logger";

export interface DecisionEngineOptions {
  analyticsService: CloudflareAnalyticsService;
  blocker: Blocker;
  allowlistMatcher: AllowlistMatcher;
}

export interface EvaluationResult {
  decisions: GuardDecision[];
  unbanned: PrunedUnbanItem[];
}

export interface ZoneEvaluationSummary {
  zoneId: string;
  zoneName: string;
  evaluated: number;
  blocked: number;
  ignored: number;
}

export interface MultiZoneEvaluationResult {
  decisions: GuardDecision[];
  unbanned: PrunedUnbanItem[];
  zoneSummaries: ZoneEvaluationSummary[];
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
   * Fetches top traffic candidates from Cloudflare Analytics for a single zone
   */
  public async evaluateCandidates(
    policy: GuardPolicy,
    zoneId: string,
    zoneName?: string
  ): Promise<EvaluationResult> {
    const multi = await this.evaluateZones(policy, [{ id: zoneId, name: zoneName || zoneId }]);
    return {
      decisions: multi.decisions,
      unbanned: multi.unbanned
    };
  }

  /**
   * Evaluates multiple zones in parallel/sequence against active policy using a shared blocklist
   */
  public async evaluateZones(
    policy: GuardPolicy,
    zones: ZoneConfig[]
  ): Promise<MultiZoneEvaluationResult> {
    if (!policy.enabled || zones.length === 0) {
      return { decisions: [], unbanned: [], zoneSummaries: [] };
    }

    const windowSeconds = policy.windowSeconds ?? 300;
    const topN = policy.topN ?? 100;

    // 1. Sync existing blocked IPs and prune expired/stale bans on shared list ONCE
    let unbanned: PrunedUnbanItem[] = [];
    const unbanConfig = policy.unban;
    if (unbanConfig?.enabled !== false) {
      const ttl = unbanConfig?.ttlSeconds ?? 86400;
      const maxLimit = unbanConfig?.maxListSize ?? 9000;
      unbanned = await this.blocker.pruneExpiredItems(ttl, maxLimit);
    } else {
      await this.blocker.syncExistingList();
    }

    const allDecisions: GuardDecision[] = [];
    const toBlockGlobal: GuardDecision[] = [];
    const zoneSummaries: ZoneEvaluationSummary[] = [];

    // 2. Query Analytics and evaluate candidates across all configured zones
    for (const zone of zones) {
      try {
        const candidates = await this.analyticsService.fetchTopIps(zone.id, windowSeconds, topN);
        metrics.increment("top_n_candidates", candidates.length);

        let blockedCount = 0;
        let ignoredCount = 0;

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
            isAlreadyBlocked,
            zoneId: zone.id,
            zoneName: zone.name
          });

          if (decision.action === "BLOCK") {
            toBlockGlobal.push(decision);
            blockedCount++;
          } else {
            metrics.increment("ignored_ips");
            allDecisions.push(decision);
            ignoredCount++;
          }
        }

        zoneSummaries.push({
          zoneId: zone.id,
          zoneName: zone.name,
          evaluated: candidates.length,
          blocked: blockedCount,
          ignored: ignoredCount
        });
      } catch (err) {
        logger.error("ZONE_EVALUATION_FAILED", {
          zoneId: zone.id,
          zoneName: zone.name,
          message: (err as Error).message
        });
      }
    }

    // 3. Execute all blocks across all evaluated zones in a single batch mutation
    if (toBlockGlobal.length > 0) {
      const executedBlocks = await this.blocker.executeBlockBatch(toBlockGlobal);
      allDecisions.push(...executedBlocks);
    }

    return {
      decisions: allDecisions,
      unbanned,
      zoneSummaries
    };
  }
}
