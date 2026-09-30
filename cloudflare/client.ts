/**
 * Resilient Cloudflare API Client with retry and exponential backoff
 */
import { CloudflareApiError } from "@/shared/errors";
import { withRetry } from "@/shared/retry";
import { metrics } from "@/observability/metrics";
import { CloudflareApiResponse } from "@/cloudflare/types";

export interface CloudflareClientConfig {
  apiToken: string;
  accountId: string;
  baseUrl?: string;
  maxRetries?: number;
}

export class CloudflareApiClient {
  private apiToken: string;
  private accountId: string;
  private baseUrl: string;
  private maxRetries: number;

  constructor(config: CloudflareClientConfig) {
    this.apiToken = config.apiToken;
    this.accountId = config.accountId;
    this.baseUrl = config.baseUrl || "https://api.cloudflare.com/client/v4";
    this.maxRetries = config.maxRetries ?? 3;
  }

  public getAccountId(): string {
    return this.accountId;
  }

  /**
   * Executes a Cloudflare API request with exponential backoff for transient errors
   */
  public async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const url = `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${this.apiToken}`);
    headers.set("Content-Type", "application/json");

    return withRetry(
      async () => {
        let response: Response;
        try {
          response = await fetch(url, {
            ...init,
            headers
          });
        } catch (fetchErr) {
          metrics.increment("cloudflare_api_errors");
          throw new CloudflareApiError(
            `Network error contacting Cloudflare API: ${(fetchErr as Error).message}`,
            503
          );
        }

        const data = (await response.json().catch(() => null)) as Record<string, unknown> | null;

        if (!response.ok) {
          metrics.increment("cloudflare_api_errors");
          let errorDetail = "";
          if (data && typeof data === "object" && "errors" in data) {
            const errList = (data as { errors?: Array<{ message?: string }> }).errors;
            if (Array.isArray(errList) && errList.length > 0) {
              errorDetail = ": " + errList.map((e) => e.message || JSON.stringify(e)).join("; ");
            }
          }

          throw new CloudflareApiError(
            `Cloudflare API request failed with status ${response.status}${errorDetail}`,
            response.status,
            data
          );
        }

        if (!data) {
          return null as unknown as T;
        }

        // GraphQL endpoints return { data, errors }
        if (data["data"] !== undefined) {
          if (Array.isArray(data["errors"]) && data["errors"].length > 0 && !data["data"]) {
            metrics.increment("cloudflare_api_errors");
            const errorMsg = (data["errors"][0] as { message: string })?.message || "GraphQL error";
            throw new CloudflareApiError(errorMsg, 400, data);
          }
          return data as T;
        }

        // Standard REST endpoints return { success, result }
        const restData = data as unknown as CloudflareApiResponse<T>;
        if (!restData.success) {
          metrics.increment("cloudflare_api_errors");
          const errorMsg = restData.errors?.[0]?.message || "Unknown Cloudflare API error";
          throw new CloudflareApiError(errorMsg, 400, restData);
        }

        return restData.result;
      },
      {
        maxRetries: this.maxRetries,
        shouldRetry: (error) => {
          if (error instanceof CloudflareApiError) {
            const status = error.statusCode;
            const isTransient = status === 429 || (status >= 500 && status <= 504);
            if (isTransient) {
              metrics.increment("cloudflare_api_retries");
              return true;
            }
          }
          return false;
        }
      }
    );
  }

  /**
   * Executes a Cloudflare API request and returns the full CloudflareApiResponse envelope (including result_info / cursors)
   */
  public async requestEnvelope<T>(
    path: string,
    init: RequestInit = {}
  ): Promise<CloudflareApiResponse<T>> {
    const url = `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    const headers = new Headers(init.headers);
    headers.set("Authorization", `Bearer ${this.apiToken}`);
    headers.set("Content-Type", "application/json");

    return withRetry(
      async () => {
        let response: Response;
        try {
          response = await fetch(url, {
            ...init,
            headers
          });
        } catch (fetchErr) {
          metrics.increment("cloudflare_api_errors");
          throw new CloudflareApiError(
            `Network error contacting Cloudflare API: ${(fetchErr as Error).message}`,
            503
          );
        }

        const data = (await response.json().catch(() => null)) as Record<string, unknown> | null;

        if (!response.ok) {
          metrics.increment("cloudflare_api_errors");
          let errorDetail = "";
          if (data && typeof data === "object" && "errors" in data) {
            const errList = (data as { errors?: Array<{ message?: string }> }).errors;
            if (Array.isArray(errList) && errList.length > 0) {
              errorDetail = ": " + errList.map((e) => e.message || JSON.stringify(e)).join("; ");
            }
          }

          throw new CloudflareApiError(
            `Cloudflare API request failed with status ${response.status}${errorDetail}`,
            response.status,
            data
          );
        }

        const restData = (data || {}) as unknown as CloudflareApiResponse<T>;
        if (!restData.success) {
          metrics.increment("cloudflare_api_errors");
          const errorMsg = restData.errors?.[0]?.message || "Unknown Cloudflare API error";
          throw new CloudflareApiError(errorMsg, 400, restData);
        }

        return restData;
      },
      {
        maxRetries: this.maxRetries,
        shouldRetry: (error) => {
          if (error instanceof CloudflareApiError) {
            const status = error.statusCode;
            const isTransient = status === 429 || (status >= 500 && status <= 504);
            if (isTransient) {
              metrics.increment("cloudflare_api_retries");
              return true;
            }
          }
          return false;
        }
      }
    );
  }
}
