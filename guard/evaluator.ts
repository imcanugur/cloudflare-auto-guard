/**
 * Candidate Evaluator: Evaluates an IP against policies with strict precedence
 */
import { GuardPolicy } from "@/domain/models/policy";
import { GuardDecision, DecisionReason } from "@/domain/models/decision";
import { CountryPolicyResolver } from "@/domain/policies/country-policy";
import { TopNPolicy } from "@/domain/policies/top-n-policy";
import { ThresholdPolicy } from "@/domain/policies/threshold-policy";
import { AllowlistMatcher } from "@/security/allowlist";
import { isValidIp } from "@/security/ip-validator";

export interface CandidateEvaluationContext {
  ip: string;
  country: string;
  asn?: string;
  requestCount: number;
  rank: number;
  policy: GuardPolicy;
  allowlistMatcher: AllowlistMatcher;
  isAlreadyBlocked?: boolean;
}

export class CandidateEvaluator {
  public static evaluate(ctx: CandidateEvaluationContext): GuardDecision {
    const { ip, country, asn, requestCount, rank, policy, allowlistMatcher, isAlreadyBlocked } = ctx;

    // 1. Global Guard enabled?
    if (!policy.enabled) {
      return {
        action: "IGNORE",
        reason: DecisionReason.GLOBAL_DISABLED,
        ip,
        country,
        requestCount,
        rank,
        threshold: 0,
        windowSeconds: policy.windowSeconds ?? 300
      };
    }

    // 2. Valid IP?
    if (!isValidIp(ip)) {
      return {
        action: "IGNORE",
        reason: DecisionReason.INVALID_IP,
        ip,
        country,
        requestCount,
        rank,
        threshold: 0,
        windowSeconds: policy.windowSeconds ?? 300
      };
    }

    // 3. Allowlist check
    if (allowlistMatcher.isAllowlisted(ip)) {
      return {
        action: "ALLOW",
        reason: DecisionReason.ALLOWLISTED,
        ip,
        country,
        requestCount,
        rank,
        threshold: 0,
        windowSeconds: policy.windowSeconds ?? 300
      };
    }

    // 4. Resolve country policy (merges with default)
    const resolved = CountryPolicyResolver.resolve(policy, country);

    // 5. Country policy enabled?
    if (!resolved.enabled) {
      return {
        action: "IGNORE",
        reason: DecisionReason.COUNTRY_DISABLED,
        ip,
        country,
        requestCount,
        rank,
        threshold: resolved.threshold,
        windowSeconds: resolved.windowSeconds
      };
    }

    // 6. Top-N check
    if (!TopNPolicy.isWithinTopN(rank, resolved.topN)) {
      return {
        action: "IGNORE",
        reason: DecisionReason.OUTSIDE_TOP_N,
        ip,
        country,
        requestCount,
        rank,
        threshold: resolved.threshold,
        windowSeconds: resolved.windowSeconds
      };
    }

    // 7. Request count threshold check
    if (!ThresholdPolicy.isThresholdExceeded(requestCount, resolved.threshold)) {
      return {
        action: "IGNORE",
        reason: DecisionReason.BELOW_THRESHOLD,
        ip,
        country,
        requestCount,
        rank,
        threshold: resolved.threshold,
        windowSeconds: resolved.windowSeconds
      };
    }

    // 8. Already blocked? (Idempotency)
    if (isAlreadyBlocked) {
      return {
        action: "IGNORE",
        reason: DecisionReason.ALREADY_BLOCKED,
        ip,
        country,
        requestCount,
        rank,
        threshold: resolved.threshold,
        windowSeconds: resolved.windowSeconds
      };
    }

    // 9. Match policy: BLOCK
    return {
      action: "BLOCK",
      reason: DecisionReason.POLICY_MATCH,
      ip,
      country,
      asn,
      requestCount,
      rank,
      threshold: resolved.threshold,
      windowSeconds: resolved.windowSeconds
    };
  }
}
