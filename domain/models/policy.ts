/**
 * Guard policy models and resolved country policy representation
 */

export interface DefaultPolicyRule {
  enabled: boolean;
  threshold: number;
  action?: "block" | "challenge";
  windowSeconds?: number;
  topN?: number;
}

export interface CountryPolicyRule {
  enabled?: boolean;
  threshold?: number;
  action?: "block" | "challenge";
  windowSeconds?: number;
  topN?: number;
}

export interface UnbanPolicyConfig {
  enabled?: boolean;
  ttlSeconds?: number;
  maxListSize?: number;
}

export interface GuardPolicy {
  enabled: boolean;
  windowSeconds?: number;
  topN?: number;
  default: DefaultPolicyRule;
  countries?: Record<string, CountryPolicyRule>;
  allowlist?: string[];
  unban?: UnbanPolicyConfig;
}

export interface ResolvedPolicy {
  enabled: boolean;
  threshold: number;
  windowSeconds: number;
  topN: number;
  action: "block" | "challenge";
  isCountryOverride: boolean;
}
