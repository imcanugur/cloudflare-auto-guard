/**
 * Metrics counter and aggregator for runtime telemetry
 */

export interface MetricSnapshot {
  requests_observed: number;
  unique_ips: number;
  top_n_candidates: number;
  blocked_ips: number;
  ignored_ips: number;
  allowlisted_ips: number;
  country_policy_matches: number;
  cloudflare_api_errors: number;
  cloudflare_api_retries: number;
}

export class MetricsCollector {
  private counters: MetricSnapshot = {
    requests_observed: 0,
    unique_ips: 0,
    top_n_candidates: 0,
    blocked_ips: 0,
    ignored_ips: 0,
    allowlisted_ips: 0,
    country_policy_matches: 0,
    cloudflare_api_errors: 0,
    cloudflare_api_retries: 0
  };

  public increment(key: keyof MetricSnapshot, amount = 1): void {
    this.counters[key] += amount;
  }

  public getSnapshot(): MetricSnapshot {
    return { ...this.counters };
  }

  public reset(): void {
    for (const key of Object.keys(this.counters) as (keyof MetricSnapshot)[]) {
      this.counters[key] = 0;
    }
  }
}

export const metrics = new MetricsCollector();
