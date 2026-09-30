/**
 * Blocker: Enforces block decisions via Cloudflare Lists API with batching, deduplication, and failure isolation
 */
import { GuardDecision, DecisionReason } from "@/domain/models/decision";
import { CloudflareListsService } from "@/cloudflare/lists";
import { logger } from "@/observability/logger";
import { metrics } from "@/observability/metrics";

export interface BlockerConfig {
  listId?: string;
  dryRun?: boolean;
}

function formatComment(decision: GuardDecision): string {
  const { country, asn, requestCount, rank, threshold, windowSeconds } = decision;
  const windowMinutes = Math.max(1, Math.round((windowSeconds || 3600) / 60));
  const windowStr = windowMinutes >= 60 ? `${Math.round(windowMinutes / 60)}h` : `${windowMinutes}m`;
  const dateStr = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";
  const asnStr = asn ? ` | ASN: ${asn.slice(0, 24).trim()}` : "";
  return `Auto Guard: ${country}${asnStr} | Req: ${requestCount} (Limit: ${threshold}/${windowStr}) | Rank: #${rank} | ${dateStr}`;
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

  /**
   * Automatically unbans expired IPs and enforces the max list size limit (FIFO pruning)
   */
  public async pruneExpiredItems(ttlSeconds = 86400, maxListSize = 9000): Promise<number> {
    if (!this.listsService || !this.listId) return 0;

    try {
      const items = await this.listsService.getListItems(this.listId);
      const now = Date.now();
      const toDeleteIds: string[] = [];
      const toDeleteIps: string[] = [];
      const activeItems: typeof items = [];

      for (const item of items) {
        if (!item || !item.id || !item.ip) continue;
        this.blockedCache.add(item.ip);

        // Check if item has exceeded TTL
        const createdTime = item.created_on ? new Date(item.created_on).getTime() : 0;
        const isExpired = createdTime > 0 && now - createdTime > ttlSeconds * 1000;

        if (isExpired) {
          toDeleteIds.push(item.id);
          toDeleteIps.push(item.ip);
        } else {
          activeItems.push(item);
        }
      }

      // 10k Limit Safeguard: If remaining active items exceed maxListSize, prune oldest first
      if (activeItems.length > maxListSize) {
        activeItems.sort((a, b) => {
          const tA = a.created_on ? new Date(a.created_on).getTime() : 0;
          const tB = b.created_on ? new Date(b.created_on).getTime() : 0;
          return tA - tB;
        });

        const overflowCount = activeItems.length - maxListSize;
        const overflowItems = activeItems.slice(0, overflowCount);
        for (const item of overflowItems) {
          toDeleteIds.push(item.id);
          toDeleteIps.push(item.ip);
        }
      }

      // Execute bulk deletion in a single API call
      if (toDeleteIds.length > 0) {
        await this.listsService.deleteIpsBatch(this.listId, toDeleteIds);

        // Remove unbanned IPs from in-memory cache
        for (const ip of toDeleteIps) {
          this.blockedCache.delete(ip);
        }

        logger.info("AUTO_UNBAN_PRUNED", {
          expiredCount: toDeleteIds.length,
          remainingCount: items.length - toDeleteIds.length
        });
        metrics.increment("unbanned_ips", toDeleteIds.length);
        return toDeleteIds.length;
      }

      return 0;
    } catch (err) {
      logger.warn("PRUNE_EXPIRED_ITEMS_FAILED", {
        message: (err as Error).message
      });
      return 0;
    }
  }

  /**
   * Executes a single block decision
   */
  public async executeBlock(decision: GuardDecision): Promise<GuardDecision> {
    const results = await this.executeBlockBatch([decision]);
    return results[0] ?? decision;
  }

  /**
   * Executes bulk block decisions in a single API call (Batch) to avoid subrequest limits
   */
  public async executeBlockBatch(decisions: GuardDecision[]): Promise<GuardDecision[]> {
    if (decisions.length === 0) return [];

    // Filter out any that were already marked in cache during the cycle
    const unblockedDecisions = decisions.filter((d) => !this.isAlreadyBlocked(d.ip));
    if (unblockedDecisions.length === 0) {
      return decisions.map((d) => ({
        ...d,
        action: "IGNORE",
        reason: DecisionReason.ALREADY_BLOCKED
      }));
    }

    // 1. Dry-run mode
    if (this.dryRun) {
      for (const d of unblockedDecisions) {
        const comment = formatComment(d);
        logger.info("WOULD_BLOCK", {
          ip: d.ip,
          country: d.country,
          asn: d.asn,
          requests: d.requestCount,
          rank: d.rank,
          threshold: d.threshold,
          comment,
          action: "BLOCK",
          reason: "DRY_RUN_POLICY_MATCH"
        });
        metrics.increment("blocked_ips");
        this.markBlockedLocal(d.ip);
      }
      return decisions;
    }

    if (!this.listsService || !this.listId) {
      logger.warn("BLOCK_SKIPPED_NO_CLOUDFLARE_CONFIG", {
        count: unblockedDecisions.length,
        message: "Cloudflare Lists API credentials or listId not configured"
      });
      return decisions;
    }

    // 2. Prepare bulk payload (up to 1,000 items in ONE HTTP request)
    const payload = unblockedDecisions.map((d) => ({
      ip: d.ip,
      comment: formatComment(d)
    }));

    try {
      if (typeof this.listsService.addIpsBatch === "function") {
        await this.listsService.addIpsBatch(this.listId, payload);
      } else {
        for (const item of payload) {
          await this.listsService.addIpToList(this.listId, item.ip, item.comment);
        }
      }

      for (const d of unblockedDecisions) {
        this.markBlockedLocal(d.ip);
        logger.info("GUARD_DECISION", {
          ip: d.ip,
          country: d.country,
          asn: d.asn,
          requests: d.requestCount,
          rank: d.rank,
          threshold: d.threshold,
          comment: formatComment(d),
          action: "BLOCK",
          reason: DecisionReason.POLICY_MATCH
        });
        metrics.increment("blocked_ips");
      }

      return decisions;
    } catch (err) {
      const msg = (err as Error).message.toLowerCase();

      // Gracefully handle duplicate items error from Cloudflare
      if (
        msg.includes("duplicate") ||
        msg.includes("already exists") ||
        msg.includes("10002") ||
        msg.includes("10008")
      ) {
        for (const d of unblockedDecisions) {
          this.markBlockedLocal(d.ip);
        }
        logger.info("IP_BATCH_CONTAINED_EXISTING_ITEMS", { count: unblockedDecisions.length });
        return decisions;
      }

      metrics.increment("cloudflare_api_errors");
      logger.error("BLOCK_BATCH_EXECUTION_FAILED", {
        count: unblockedDecisions.length,
        message: (err as Error).message
      });

      return decisions.map((d) => ({
        ...d,
        reason: DecisionReason.BLOCK_FAILED
      }));
    }
  }
}
