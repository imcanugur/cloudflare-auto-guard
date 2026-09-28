/**
 * In-memory policy cache with configurable TTL to minimize KV reads
 */
import { GuardPolicy } from "@/domain/models/policy";
import { ConfigLoader } from "@/config/config-loader";

export class PolicyCache {
  private cachedPolicy: GuardPolicy | null = null;
  private lastFetchedAt = 0;
  private ttlMs: number;

  constructor(ttlMs = 30000) {
    this.ttlMs = ttlMs;
  }

  public setTtl(ttlMs: number): void {
    this.ttlMs = ttlMs;
  }

  /**
   * Retrieves policy from cache or refreshes from KV if TTL expired
   */
  public async getPolicy(kvNamespace?: KVNamespace): Promise<GuardPolicy> {
    const now = Date.now();
    if (this.cachedPolicy && now - this.lastFetchedAt < this.ttlMs) {
      return this.cachedPolicy;
    }

    const { policy } = await ConfigLoader.loadFromKv(kvNamespace);
    this.cachedPolicy = policy;
    this.lastFetchedAt = now;
    return policy;
  }

  /**
   * Manually invalidates the cached policy
   */
  public invalidate(): void {
    this.cachedPolicy = null;
    this.lastFetchedAt = 0;
  }
}

export const policyCache = new PolicyCache();
