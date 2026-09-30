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
   * Fetches existing items in the Cloudflare IP List (used for initial idempotency cache warming)
   */
  public async getListItems(listId: string): Promise<CloudflareListItem[]> {
    const accountId = this.client.getAccountId();
    const endpoint = `/accounts/${accountId}/rules/lists/${listId}/items?per_page=1000`;

    try {
      const items = await this.client.request<CloudflareListItem[]>(endpoint, {
        method: "GET"
      });
      return items || [];
    } catch (err) {
      logger.warn("CLOUDFLARE_LIST_FETCH_ITEMS_FAILED", {
        message: (err as Error).message,
        metadata: { listId }
      });
      return [];
    }
  }
}
