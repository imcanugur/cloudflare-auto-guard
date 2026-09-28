/**
 * Traffic statistics and aggregation domain models
 */

export interface TrafficCandidate {
  ip: string;
  country: string;
  requestCount: number;
  rank: number;
}

export interface ShardAggregateResult {
  shardId: number;
  candidates: TrafficCandidate[];
  totalUniqueIps: number;
  totalRequests: number;
  windowSeconds: number;
}

export interface GlobalTrafficRanking {
  candidates: TrafficCandidate[];
  windowSeconds: number;
  evaluatedAt: number;
}
