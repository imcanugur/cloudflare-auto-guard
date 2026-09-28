/**
 * Sharded Durable Object for traffic aggregation, sliding window top-N calculation,
 * and block idempotency state.
 */
import { TrafficCandidate } from "@/domain/models/traffic";
import { AuditEvent, AuditRecorder } from "@/observability/audit";

interface BucketIpEntry {
  count: number;
  country: string;
}

export class TrafficShardDO implements DurableObject {
  private state: DurableObjectState;
  // BucketId (ms) -> Map<ip, BucketIpEntry>
  private buckets: Map<number, Map<string, BucketIpEntry>> = new Map();
  private blockedIps: Set<string> = new Set();
  private auditRecorder = new AuditRecorder(1000);
  private bucketIntervalMs = 10000; // 10-second granularity for sliding window

  constructor(state: DurableObjectState, _env?: unknown) {
    this.state = state;
    // Load persisted blocked IPs if any on startup
    this.state.blockConcurrencyWhile(async () => {
      const persistedBlocked = (await this.state.storage.get<string[]>("blocked_ips")) || [];
      for (const ip of persistedBlocked) {
        this.blockedIps.add(ip);
      }
    });
  }

  public async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/record" && request.method === "POST") {
        const body = (await request.json()) as { ip: string; country: string; timestamp?: number };
        const now = body.timestamp || Date.now();
        this.recordTraffic(body.ip, body.country, now);
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.pathname === "/top-n" && request.method === "GET") {
        const windowSeconds = parseInt(url.searchParams.get("windowSeconds") || "300", 10);
        const topN = parseInt(url.searchParams.get("topN") || "100", 10);
        const candidates = this.getTopN(windowSeconds, topN);
        return new Response(JSON.stringify({ candidates }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.pathname === "/blocked" && request.method === "GET") {
        const ip = url.searchParams.get("ip") || "";
        const isBlocked = this.blockedIps.has(ip);
        return new Response(JSON.stringify({ blocked: isBlocked }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.pathname === "/blocked" && request.method === "POST") {
        const body = (await request.json()) as { ip: string };
        await this.markBlocked(body.ip);
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.pathname === "/audit" && request.method === "GET") {
        const limit = parseInt(url.searchParams.get("limit") || "100", 10);
        const events = this.auditRecorder.getRecentEvents(limit);
        return new Response(JSON.stringify({ events }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.pathname === "/audit" && request.method === "POST") {
        const event = (await request.json()) as AuditEvent;
        // Direct audit recording
        this.auditRecorder.recordDecision({
          action: event.action as any,
          reason: event.reason,
          ip: event.ip,
          country: event.country,
          requestCount: event.requests,
          rank: event.rank,
          threshold: event.threshold,
          windowSeconds: 300
        });
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      if (url.pathname === "/health") {
        return new Response(JSON.stringify({ status: "ok" }), {
          headers: { "Content-Type": "application/json" }
        });
      }

      return new Response("Not Found", { status: 404 });
    } catch (err) {
      return new Response(
        JSON.stringify({ error: (err as Error).message }),
        { status: 500, headers: { "Content-Type": "application/json" } }
      );
    }
  }

  private recordTraffic(ip: string, country: string, now: number): void {
    const bucketId = Math.floor(now / this.bucketIntervalMs) * this.bucketIntervalMs;
    let bucket = this.buckets.get(bucketId);
    if (!bucket) {
      bucket = new Map();
      this.buckets.set(bucketId, bucket);
    }

    const entry = bucket.get(ip);
    if (entry) {
      entry.count += 1;
      if (country && country !== "XX") {
        entry.country = country;
      }
    } else {
      bucket.set(ip, { count: 1, country });
    }

    // Clean up older buckets (keep max 15 minutes of history)
    const cutoff = now - 15 * 60 * 1000;
    for (const bId of this.buckets.keys()) {
      if (bId < cutoff) {
        this.buckets.delete(bId);
      }
    }
  }

  private getTopN(windowSeconds: number, topN: number): TrafficCandidate[] {
    const now = Date.now();
    const windowMs = windowSeconds * 1000;
    const windowStart = now - windowMs;

    // Aggregate counts for active buckets
    const aggregated = new Map<string, { count: number; country: string }>();

    for (const [bucketId, bucket] of this.buckets.entries()) {
      if (bucketId >= windowStart && bucketId <= now) {
        for (const [ip, entry] of bucket.entries()) {
          const current = aggregated.get(ip);
          if (current) {
            current.count += entry.count;
            if (entry.country && entry.country !== "XX") {
              current.country = entry.country;
            }
          } else {
            aggregated.set(ip, { count: entry.count, country: entry.country });
          }
        }
      }
    }

    // Sort descending by requestCount
    const sorted = Array.from(aggregated.entries())
      .map(([ip, data]) => ({
        ip,
        country: data.country,
        requestCount: data.count,
        rank: 0
      }))
      .sort((a, b) => b.requestCount - a.requestCount)
      .slice(0, topN);

    // Assign rank
    return sorted.map((item, index) => ({
      ...item,
      rank: index + 1
    }));
  }

  private async markBlocked(ip: string): Promise<void> {
    this.blockedIps.add(ip);
    // Persist to Durable Object storage for durability across restarts
    const list = Array.from(this.blockedIps).slice(-5000); // keep recent 5000 in storage
    await this.state.storage.put("blocked_ips", list);
  }
}
