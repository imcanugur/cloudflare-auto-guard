/**
 * Distributed Top-N Aggregator: Merges local Top-N lists across shards into Global Top-N
 */
import { TrafficCandidate, GlobalTrafficRanking } from "@/domain/models/traffic";

export class TrafficAggregator {
  /**
   * Merges candidate arrays from all shards and returns globally sorted and ranked Top-N
   */
  public static mergeTopN(
    shardCandidates: TrafficCandidate[],
    windowSeconds: number,
    topN: number
  ): GlobalTrafficRanking {
    // Deduplicate or sum up (in case of shard redistribution)
    const map = new Map<string, { country: string; count: number }>();

    for (const c of shardCandidates) {
      const existing = map.get(c.ip);
      if (existing) {
        existing.count += c.requestCount;
        if (c.country && c.country !== "XX") {
          existing.country = c.country;
        }
      } else {
        map.set(c.ip, { country: c.country, count: c.requestCount });
      }
    }

    const sorted = Array.from(map.entries())
      .map(([ip, data]) => ({
        ip,
        country: data.country,
        requestCount: data.count,
        rank: 0
      }))
      .sort((a, b) => b.requestCount - a.requestCount)
      .slice(0, topN);

    const candidates = sorted.map((item, index) => ({
      ...item,
      rank: index + 1
    }));

    return {
      candidates,
      windowSeconds,
      evaluatedAt: Date.now()
    };
  }
}
