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

  /**
   * Warms local cache with existing items from the Cloudflare IP List for 100% idempotency
   */
  public async syncExistingList(): Promise<void> {
    if (!this.listsService || !this.listId) return;
    try {
      const items = await this.listsService.getListItems(this.listId);
      for (const item of items) {
        if (item && item.ip) {
          this.blockedCache.add(item.ip);
        }
      }
    } catch (err) {
      logger.warn("SYNC_EXISTING_LIST_FAILED", {
        message: (err as Error).message
      });
    }
  }

  public async executeBlock(decision: GuardDecision): Promise<GuardDecision> {
    const { ip, country, asn, requestCount, rank, threshold, windowSeconds } = decision;

    const windowMinutes = Math.max(1, Math.round((windowSeconds || 3600) / 60));
    const windowStr = windowMinutes >= 60 ? `${Math.round(windowMinutes / 60)}h` : `${windowMinutes}m`;
    const dateStr = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";
    const asnStr = asn ? ` | ASN: ${asn.slice(0, 24).trim()}` : "";
    const comment = `Auto Guard: ${country}${asnStr} | Req: ${requestCount} (Limit: ${threshold}/${windowStr}) | Rank: #${rank} | ${dateStr}`;

    // Dry-run mode handling
    if (this.dryRun) {
      logger.info("WOULD_BLOCK", {
        ip,
        country,
        asn,
        requests: requestCount,
        rank,
        threshold,
        comment,
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
        comment
      );

      this.markBlockedLocal(ip);

      logger.info("GUARD_DECISION", {
        ip,
        country,
        asn,
        requests: requestCount,
        rank,
        threshold,
        comment,
        action: "BLOCK",
        reason: DecisionReason.POLICY_MATCH
      });

      metrics.increment("blocked_ips");
      return decision;
    } catch (err) {
      const msg = (err as Error).message.toLowerCase();
      if (
        msg.includes("duplicate") ||
        msg.includes("already exists") ||
        msg.includes("10002") ||
        msg.includes("10008")
      ) {
        this.markBlockedLocal(ip);
        logger.info("IP_ALREADY_EXISTS_IN_LIST", { ip, country });
        return {
          ...decision,
          action: "IGNORE",
          reason: DecisionReason.ALREADY_BLOCKED
        };
      }

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
