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
    const toBlockIpSet = new Set<string>();
    const zoneSummaries: ZoneEvaluationSummary[] = [];

    // 2. Query Analytics and evaluate candidates across all configured zones
    for (const zone of zones) {
      try {
        const candidates = await this.analyticsService.fetchTopIps(zone.id, windowSeconds, topN);
        metrics.increment("top_n_candidates", candidates.length);

        let blockedCount = 0;
        let ignoredCount = 0;

        for (const candidate of candidates) {
          const isAlreadyBlocked =
            this.blocker.isAlreadyBlocked(candidate.ip) ||
            toBlockIpSet.has(candidate.ip);

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
            if (!toBlockIpSet.has(candidate.ip)) {
              toBlockGlobal.push(decision);
              toBlockIpSet.add(candidate.ip);
            }
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
          ignored: ignoredCount,
          scannersBlocked: 0
        });

        // 2.b. Evaluate 404 Error Storm Scanners (Engine 1)
        if (policy.scanner?.enabled !== false) {
          const scannerWindow = policy.scanner?.windowSeconds ?? windowSeconds;
          const scanners404 = await this.analyticsService.fetch404Scanners(zone.id, scannerWindow, 50);
          metrics.increment("scanner_404_candidates", scanners404.length);

          let scannersBlockedForZone = 0;
          for (const candidate of scanners404) {
            const isAlreadyBlocked =
              this.blocker.isAlreadyBlocked(candidate.ip) ||
              toBlockIpSet.has(candidate.ip);

            const decision = CandidateEvaluator.evaluateScanner404({
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
              if (!toBlockIpSet.has(candidate.ip)) {
                toBlockGlobal.push(decision);
                toBlockIpSet.add(candidate.ip);
              }
              scannersBlockedForZone++;
              blockedCount++;
            } else {
              allDecisions.push(decision);
            }
          }

          // 2.c. Evaluate Canary / Sensitive Path Trap Probes (Engine 2)
          const trapPaths = policy.scanner?.trapPaths;
          if (trapPaths && trapPaths.length > 0) {
            const trapProbes = await this.analyticsService.fetchTrapProbes(zone.id, scannerWindow, trapPaths, 50);
            metrics.increment("canary_trap_candidates", trapProbes.length);

            for (const candidate of trapProbes) {
              const isAlreadyBlocked =
                this.blocker.isAlreadyBlocked(candidate.ip) ||
                toBlockIpSet.has(candidate.ip);

              const decision = CandidateEvaluator.evaluateScannerTrap(
                {
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
                },
                candidate.probePath
              );

              if (decision.action === "BLOCK") {
                if (!toBlockIpSet.has(candidate.ip)) {
                  toBlockGlobal.push(decision);
                  toBlockIpSet.add(candidate.ip);
                }
                scannersBlockedForZone++;
                blockedCount++;
              } else {
                allDecisions.push(decision);
              }
            }
          }

          const summary = zoneSummaries[zoneSummaries.length - 1];
          if (summary) {
            summary.scannersBlocked = scannersBlockedForZone;
            summary.blocked = blockedCount;
          }
        }
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
