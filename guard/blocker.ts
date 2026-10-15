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

export interface PrunedUnbanItem {
  ip: string;
  reason: "TTL_EXPIRED" | "LIST_LIMIT_FIFO";
  createdOn?: string;
  comment?: string;
}

function formatComment(decision: GuardDecision): string {
  const { country, asn, requestCount, rank, threshold, windowSeconds, zoneName, zoneId, threatType } = decision;
  const windowMinutes = Math.max(1, Math.round((windowSeconds || 3600) / 60));
  const windowStr = windowMinutes >= 60 ? `${Math.round(windowMinutes / 60)}h` : `${windowMinutes}m`;
  const dateStr = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";
  const asnStr = asn ? ` | ASN: ${asn.slice(0, 24).trim()}` : "";
  const zoneTag = zoneName ? `[${zoneName}] ` : (zoneId ? `[${zoneId.slice(0, 8)}] ` : "");

  if (threatType === "SCANNER_404") {
    return `Auto Guard: ${zoneTag}SCANNER 404 | ${country}${asnStr} | 404s: ${requestCount} (Limit: ${threshold}/${windowStr}) | Rank: #${rank} | ${dateStr}`;
  }

  if (threatType === "SCANNER_TRAP") {
    const probe = decision.probePath ? ` | Probe: ${decision.probePath.slice(0, 32)}` : "";
    return `Auto Guard: ${zoneTag}CANARY TRAP | ${country}${asnStr}${probe} | Rank: #${rank} | ${dateStr}`;
  }

  return `Auto Guard: ${zoneTag}${country}${asnStr} | Req: ${requestCount} (Limit: ${threshold}/${windowStr}) | Rank: #${rank} | ${dateStr}`;
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

  public markUnblockedLocal(ip: string): void {
    this.blockedCache.delete(ip);
  }

  public markAsBlockedLocally(ip: string): void {
    this.markBlockedLocal(ip);
  }

  public markAsUnblockedLocally(ip: string): void {
    this.markUnblockedLocal(ip);
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
  public async pruneExpiredItems(
    ttlSeconds = 86400,
    maxListSize = 9000
  ): Promise<PrunedUnbanItem[]> {
    if (!this.listsService || !this.listId) return [];

    try {
      const items = await this.listsService.getListItems(this.listId);
      const now = Date.now();
      const toDeleteIds: string[] = [];
      const unbannedItems: PrunedUnbanItem[] = [];
      const activeItems: typeof items = [];

      for (const item of items) {
        if (!item || !item.id || !item.ip) continue;
        this.blockedCache.add(item.ip);

        // Check if item has exceeded TTL
        let createdTime = item.created_on ? new Date(item.created_on).getTime() : 0;
        // Fallback: Parse date from comment if created_on is missing or invalid
        if ((!createdTime || isNaN(createdTime)) && item.comment) {
          const match = item.comment.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?)\s*UTC/i);
          if (match && match[1]) {
            createdTime = new Date(match[1].replace(" ", "T") + "Z").getTime();
          }
        }
        const isExpired = createdTime > 0 && now - createdTime > ttlSeconds * 1000;

        if (isExpired) {
          toDeleteIds.push(item.id);
          unbannedItems.push({
            ip: item.ip,
            reason: "TTL_EXPIRED",
            createdOn: item.created_on,
            comment: item.comment
          });
        } else {
          activeItems.push(item);
        }
      }

      // 10k Limit Safeguard: If remaining active items exceed maxListSize, prune oldest first
      if (activeItems.length > maxListSize) {
        const getItemTime = (i: typeof items[0]) => {
          let t = i.created_on ? new Date(i.created_on).getTime() : 0;
          if ((!t || isNaN(t)) && i.comment) {
            const m = i.comment.match(/(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}(?::\d{2})?)\s*UTC/i);
            if (m && m[1]) t = new Date(m[1].replace(" ", "T") + "Z").getTime();
          }
          return t || 0;
        };
        activeItems.sort((a, b) => getItemTime(a) - getItemTime(b));

        const overflowCount = activeItems.length - maxListSize;
        const overflowItems = activeItems.slice(0, overflowCount);
        for (const item of overflowItems) {
          toDeleteIds.push(item.id);
          unbannedItems.push({
            ip: item.ip,
            reason: "LIST_LIMIT_FIFO",
            createdOn: item.created_on,
            comment: item.comment
          });
        }
      }

      // Execute bulk deletion in a single API call
      if (toDeleteIds.length > 0) {
        await this.listsService.deleteIpsBatch(this.listId, toDeleteIds);

        // Remove unbanned IPs from in-memory cache
        for (const unbanned of unbannedItems) {
          this.blockedCache.delete(unbanned.ip);
        }

        logger.info("AUTO_UNBAN_PRUNED", {
          expiredCount: toDeleteIds.length,
          remainingCount: items.length - toDeleteIds.length
        });
        metrics.increment("unbanned_ips", toDeleteIds.length);
        return unbannedItems;
      }

      return [];
    } catch (err) {
      logger.warn("PRUNE_EXPIRED_ITEMS_FAILED", {
        message: (err as Error).message
      });
      return [];
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

    // Strictly deduplicate by IP to eliminate duplicate item values in the batch payload
    const uniqueDecisionsMap = new Map<string, GuardDecision>();
    for (const d of unblockedDecisions) {
      if (!uniqueDecisionsMap.has(d.ip)) {
        uniqueDecisionsMap.set(d.ip, d);
      }
    }
    const dedupedDecisions = Array.from(uniqueDecisionsMap.values());

    // 1. Dry-run mode
    if (this.dryRun) {
      for (const d of dedupedDecisions) {
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
        count: dedupedDecisions.length,
        message: "Cloudflare Lists API credentials or listId not configured"
      });
      return decisions;
    }

    // 2. Prepare bulk payload (strictly unique IPs)
    const payload = dedupedDecisions.map((d) => ({
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

      for (const d of dedupedDecisions) {
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
      const msg = (err as Error).message || "";
      const lowerMsg = msg.toLowerCase();

      // Gracefully handle duplicate items error from Cloudflare:
      // e.g. "Cloudflare API request failed with status 400: invalid value for ip at position 52: filters.api.duplicate_item_value..."
      if (
        lowerMsg.includes("duplicate") ||
        lowerMsg.includes("already exists") ||
        lowerMsg.includes("10002") ||
        lowerMsg.includes("10008")
      ) {
        const duplicatePositions = new Set<number>(
          [...msg.matchAll(/position\s+(\d+)/gi)].map((m) => parseInt(m[1], 10))
        );

        if (duplicatePositions.size > 0 && typeof this.listsService.addIpsBatch === "function") {
          for (const pos of duplicatePositions) {
            if (payload[pos]) {
              this.markBlockedLocal(payload[pos].ip);
            }
          }

          const cleanPayload = payload.filter((_, idx) => !duplicatePositions.has(idx));
          if (cleanPayload.length > 0) {
            try {
              await this.listsService.addIpsBatch(this.listId, cleanPayload);
              logger.info("IP_BATCH_RETRY_WITHOUT_DUPLICATES_SUCCESS", {
                originalCount: payload.length,
                duplicatesRemoved: duplicatePositions.size,
                addedCount: cleanPayload.length
              });
            } catch (retryErr) {
              logger.warn("IP_BATCH_RETRY_FAILED", {
                message: (retryErr as Error).message
              });
            }
          }
        }

        for (const d of dedupedDecisions) {
          this.markBlockedLocal(d.ip);
        }

        logger.info("IP_BATCH_CONTAINED_EXISTING_ITEMS", { count: dedupedDecisions.length });
        return decisions;
      }

      metrics.increment("cloudflare_api_errors");
      logger.error("BLOCK_BATCH_EXECUTION_FAILED", {
        count: dedupedDecisions.length,
        message: (err as Error).message
      });

      return decisions.map((d) => ({
        ...d,
        reason: DecisionReason.BLOCK_FAILED
      }));
    }
  }
}
