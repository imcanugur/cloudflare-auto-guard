/**
 * TrafficRepository: Coordinates communication with sharded Durable Objects
 */
import { TrafficCandidate } from "@/domain/models/traffic";
import { getShardIndex } from "@/shared/utils";
import { logger } from "@/observability/logger";

export interface ITrafficRepository {
  record(ip: string, country: string, timestamp?: number): Promise<void>;
  getAllShardsTopN(windowSeconds: number, topN: number): Promise<TrafficCandidate[]>;
  isBlocked(ip: string): Promise<boolean>;
  markBlocked(ip: string): Promise<void>;
}

export class DurableObjectTrafficRepository implements ITrafficRepository {
  private shardNamespace: DurableObjectNamespace;
  private shardCount: number;

  constructor(shardNamespace: DurableObjectNamespace, shardCount = 8) {
    this.shardNamespace = shardNamespace;
    this.shardCount = shardCount;
  }

  private getShardStub(shardIndex: number): DurableObjectStub {
    const id = this.shardNamespace.idFromName(`shard-${shardIndex}`);
    return this.shardNamespace.get(id);
  }

  private getStubForIp(ip: string): DurableObjectStub {
    const shardIndex = getShardIndex(ip, this.shardCount);
    return this.getShardStub(shardIndex);
  }

  public async record(ip: string, country: string, timestamp = Date.now()): Promise<void> {
    const stub = this.getStubForIp(ip);
    try {
      await stub.fetch("http://do/record", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, country, timestamp })
      });
    } catch (err) {
      logger.error("DO_RECORD_TRAFFIC_FAILED", {
        ip,
        country,
        message: (err as Error).message
      });
    }
  }

  public async getAllShardsTopN(
    windowSeconds: number,
    topN: number
  ): Promise<TrafficCandidate[]> {
    const shardPromises: Promise<TrafficCandidate[]>[] = [];

    for (let i = 0; i < this.shardCount; i++) {
      const stub = this.getShardStub(i);
      shardPromises.push(
        stub
          .fetch(`http://do/top-n?windowSeconds=${windowSeconds}&topN=${topN}`, {
            method: "GET"
          })
          .then(async (res) => {
            if (!res.ok) return [];
            const data = (await res.json()) as { candidates: TrafficCandidate[] };
            return data.candidates || [];
          })
          .catch((err) => {
            logger.warn("DO_FETCH_SHARD_TOP_N_FAILED", {
              message: (err as Error).message,
              metadata: { shardId: i }
            });
            return [];
          })
      );
    }

    const results = await Promise.allSettled(shardPromises);
    const combinedCandidates: TrafficCandidate[] = [];

    for (const res of results) {
      if (res.status === "fulfilled") {
        combinedCandidates.push(...res.value);
      }
    }

    return combinedCandidates;
  }

  public async isBlocked(ip: string): Promise<boolean> {
    const stub = this.getStubForIp(ip);
    try {
      const res = await stub.fetch(`http://do/blocked?ip=${encodeURIComponent(ip)}`, {
        method: "GET"
      });
      if (!res.ok) return false;
      const data = (await res.json()) as { blocked: boolean };
      return data.blocked === true;
    } catch (err) {
      logger.warn("DO_CHECK_BLOCKED_FAILED", {
        ip,
        message: (err as Error).message
      });
      return false;
    }
  }

  public async markBlocked(ip: string): Promise<void> {
    const stub = this.getStubForIp(ip);
    try {
      await stub.fetch("http://do/blocked", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip })
      });
    } catch (err) {
      logger.error("DO_MARK_BLOCKED_FAILED", {
        ip,
        message: (err as Error).message
      });
    }
  }
}
