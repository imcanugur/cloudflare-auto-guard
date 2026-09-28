/**
 * Cloudflare GraphQL Analytics service: Fetches edge-level Top IP traffic statistics
 */
import { CloudflareApiClient } from "@/cloudflare/client";
import { TrafficCandidate } from "@/domain/models/traffic";
import { logger } from "@/observability/logger";

interface GraphQLAnalyticsResponse {
  data?: {
    viewer?: {
      zones?: Array<{
        httpRequestsAdaptiveGroups?: Array<{
          count: number;
          dimensions: {
            clientIP: string;
            clientCountryName: string;
          };
        }>;
      }>;
    };
  };
  errors?: Array<{ message: string }>;
}

export class CloudflareAnalyticsService {
  private client: CloudflareApiClient;

  constructor(client: CloudflareApiClient) {
    this.client = client;
  }

  /**
   * Queries Cloudflare GraphQL Analytics to extract top IPs hitting the zone over windowSeconds
   */
  public async fetchTopIps(
    zoneId: string,
    windowSeconds = 300,
    topN = 100
  ): Promise<TrafficCandidate[]> {
    const sinceDate = new Date(Date.now() - windowSeconds * 1000).toISOString();

    const query = `
      query GetTopIps($zoneTag: String!, $since: Time!, $limit: Int!) {
        viewer {
          zones(filter: { zoneTag: $zoneTag }) {
            httpRequestsAdaptiveGroups(
              filter: {
                datetime_geq: $since
              }
              limit: $limit
              orderBy: [count_DESC]
            ) {
              count
              dimensions {
                clientIP
                clientCountryName
              }
            }
          }
        }
      }
    `;

    try {
      const response = await this.client.request<GraphQLAnalyticsResponse>("/graphql", {
        method: "POST",
        body: JSON.stringify({
          query,
          variables: {
            zoneTag: zoneId,
            since: sinceDate,
            limit: topN
          }
        })
      });

      if (response.errors && response.errors.length > 0) {
        throw new Error(response.errors.map((e) => e.message).join(", "));
      }

      const groups = response.data?.viewer?.zones?.[0]?.httpRequestsAdaptiveGroups || [];

      const candidates: TrafficCandidate[] = groups
        .filter((g) => Boolean(g.dimensions.clientIP))
        .map((g, index) => ({
          ip: g.dimensions.clientIP,
          country: (g.dimensions.clientCountryName || "XX").toUpperCase(),
          requestCount: g.count,
          rank: index + 1
        }));

      logger.info("ANALYTICS_TOP_IPS_FETCHED", {
        metadata: {
          zoneId,
          windowSeconds,
          count: candidates.length
        }
      });

      return candidates;
    } catch (err) {
      logger.error("ANALYTICS_FETCH_FAILED", {
        message: (err as Error).message,
        metadata: { zoneId }
      });
      return [];
    }
  }
}
