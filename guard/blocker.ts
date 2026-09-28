/**
 * Blocker: Handles Cloudflare IP List mutation, dry-run, idempotency, and audit logging
 */
import { GuardDecision, DecisionReason } from "@/domain/models/decision";
import { CloudflareListsService } from "@/cloudflare/lists";
import { logger } from "@/observability/logger";
import { metrics } from "@/observability/metrics";

export interface BlockerConfig {
  listId?: string | undefined;
  dryRun?: boolean | undefined;
}

export class Blocker {
  private listsService: CloudflareListsService | undefined;
  private listId: string | undefined;
  private dryRun: boolean;
  private blockedCache: Set<string> = new Set();

  constructor(
    listsService?: CloudflareListsService | undefined,
    config: BlockerConfig = {}
  ) {
    this.listsService = listsService;
    this.listId = config.listId;
    this.dryRun = config.dryRun === true;
  }

  public isAlreadyBlocked(ip: string): boolean {
    return this.blockedCache.has(ip);
  }

  public markBlockedLocal(ip: string): void {
    this.blockedCache.add(ip);
  }

  public setBlockedList(ips: string[]): void {
    this.blockedCache = new Set(ips);
  }

  public async executeBlock(decision: GuardDecision): Promise<GuardDecision> {
    const { ip, country, requestCount, rank, threshold } = decision;

    // Dry-run mode handling
    if (this.dryRun) {
      logger.info("WOULD_BLOCK", {
        ip,
        country,
        requests: requestCount,
        rank,
        threshold,
        action: "BLOCK",
        reason: "DRY_RUN_POLICY_MATCH"
      });
      metrics.increment("blocked_ips");
      this.markBlockedLocal(ip);
      return decision;
    }

    if (!this.listsService || !this.listId) {
      logger.warn("BLOCK_SKIPPED_NO_CLOUDFLARE_CONFIG", {
        ip,
        country,
        message: "Cloudflare Lists API credentials or listId not configured"
      });
      return decision;
    }

    try {
      // Mutate Cloudflare IP list
      await this.listsService.addIpToList(
        this.listId,
        ip,
        `Auto Guard: ${country} | Req: ${requestCount} | Rank: ${rank}`
      );

      this.markBlockedLocal(ip);

      logger.info("GUARD_DECISION", {
        ip,
        country,
        requests: requestCount,
        rank,
        threshold,
        action: "BLOCK",
        reason: DecisionReason.POLICY_MATCH
      });

      metrics.increment("blocked_ips");
      return decision;
    } catch (err) {
      metrics.increment("cloudflare_api_errors");
      logger.error("BLOCK_EXECUTION_FAILED", {
        ip,
        country,
        message: (err as Error).message
      });

      return {
        ...decision,
        reason: DecisionReason.BLOCK_FAILED
      };
    }
  }
}
