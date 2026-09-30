/**
 * Cloudflare IP Lists API service
 */
import { CloudflareApiClient } from "@/cloudflare/client";
import { CloudflareListItem, CloudflareListOperationResult } from "@/cloudflare/types";
import { logger } from "@/observability/logger";

export class CloudflareListsService {
  private client: CloudflareApiClient;

  constructor(client: CloudflareApiClient) {
    this.client = client;
  }

  /**
   * Adds an IP to a Cloudflare IP List for WAF enforcement
   */
  public async addIpToList(
    listId: string,
    ip: string,
    comment = "Auto Guard Block"
  ): Promise<CloudflareListOperationResult | null> {
    return this.addIpsBatch(listId, [{ ip, comment }]);
  }

  /**
   * Adds multiple IPs in bulk (Batch) to a Cloudflare IP List in a single HTTP request
   */
  public async addIpsBatch(
    listId: string,
    items: Array<{ ip: string; comment?: string }>
  ): Promise<CloudflareListOperationResult | null> {
    if (items.length === 0) return null;

    const accountId = this.client.getAccountId();
    const endpoint = `/accounts/${accountId}/rules/lists/${listId}/items`;

    try {
      const result = await this.client.request<CloudflareListOperationResult>(endpoint, {
        method: "POST",
        body: JSON.stringify(items)
      });

      logger.info("CLOUDFLARE_LIST_BATCH_ADDED", {
        count: items.length,
        metadata: { listId, operationId: result?.operation_id }
      });

      return result;
    } catch (err) {
      logger.error("CLOUDFLARE_LIST_BATCH_FAILED", {
        count: items.length,
        message: (err as Error).message,
        metadata: { listId }
      });
      throw err;
    }
  }

  /**
   * Fetches existing items in the Cloudflare IP List (used for initial idempotency cache warming & TTL pruning)
   * Uses Cloudflare cursor-based pagination with valid per_page (max 500) within worker subrequest budget.
   */
  public async getListItems(listId: string, maxItems = 10000): Promise<CloudflareListItem[]> {
    const accountId = this.client.getAccountId();
    const allItems: CloudflareListItem[] = [];
    let cursor: string | undefined = undefined;
    let pageCount = 0;
    const maxPages = 15;

    try {
      while (pageCount < maxPages) {
        let endpoint = `/accounts/${accountId}/rules/lists/${listId}/items?per_page=500`;
        if (cursor) {
          endpoint += `&cursor=${encodeURIComponent(cursor)}`;
        }

        const envelope = await this.client.requestEnvelope<CloudflareListItem[]>(endpoint, {
          method: "GET"
        });

        const items = envelope.result || [];
        allItems.push(...items);
        pageCount++;

        cursor = envelope.result_info?.cursors?.after;
        if (!cursor || items.length === 0 || allItems.length >= maxItems) {
          break;
        }
      }

      return allItems;
    } catch (err) {
      logger.warn("CLOUDFLARE_LIST_FETCH_ITEMS_FAILED", {
        message: (err as Error).message,
        metadata: { listId }
      });
      return allItems;
    }
  }

  /**
   * Deletes multiple items by ID from Cloudflare IP List in a single batch request
   */
  public async deleteIpsBatch(
    listId: string,
    itemIds: string[]
  ): Promise<CloudflareListOperationResult | null> {
    if (itemIds.length === 0) return null;

    const accountId = this.client.getAccountId();
    const endpoint = `/accounts/${accountId}/rules/lists/${listId}/items`;

    const payload = {
      items: itemIds.map((id) => ({ id }))
    };

    try {
      const result = await this.client.request<CloudflareListOperationResult>(endpoint, {
        method: "DELETE",
        body: JSON.stringify(payload)
      });

      logger.info("CLOUDFLARE_LIST_ITEMS_DELETED", {
        count: itemIds.length,
        metadata: { listId, operationId: result?.operation_id }
      });

      return result;
    } catch (err) {
      logger.error("CLOUDFLARE_LIST_DELETE_FAILED", {
        count: itemIds.length,
        message: (err as Error).message,
        metadata: { listId }
      });
      throw err;
    }
  }
}
