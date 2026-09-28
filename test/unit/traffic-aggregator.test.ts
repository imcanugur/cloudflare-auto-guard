import { describe, it, expect } from "vitest";
import { TrafficAggregator } from "@/guard/aggregator";
import { TrafficCandidate } from "@/domain/models/traffic";

describe("Distributed TrafficAggregator", () => {
  it("correctly merges, aggregates, and sorts candidates across shards", () => {
    const shardCandidates: TrafficCandidate[] = [
      { ip: "1.1.1.1", country: "US", requestCount: 1500, rank: 1 },
      { ip: "2.2.2.2", country: "DE", requestCount: 3000, rank: 2 },
      { ip: "3.3.3.3", country: "NL", requestCount: 500, rank: 3 },
      { ip: "4.4.4.4", country: "GB", requestCount: 7000, rank: 1 }
    ];

    const result = TrafficAggregator.mergeTopN(shardCandidates, 300, 3);

    expect(result.candidates.length).toBe(3);
    // Highest rank must be 4.4.4.4 with 7000
    expect(result.candidates[0]?.ip).toBe("4.4.4.4");
    expect(result.candidates[0]?.rank).toBe(1);

    // Rank 2 must be 2.2.2.2 with 3000
    expect(result.candidates[1]?.ip).toBe("2.2.2.2");
    expect(result.candidates[1]?.rank).toBe(2);

    // Rank 3 must be 1.1.1.1 with 1500
    expect(result.candidates[2]?.ip).toBe("1.1.1.1");
    expect(result.candidates[2]?.rank).toBe(3);
  });
});
