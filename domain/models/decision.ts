/**
 * Guard Decision and Reason Code models
 */

export type GuardAction = "ALLOW" | "IGNORE" | "BLOCK";

export const DecisionReason = {
  GLOBAL_DISABLED: "GLOBAL_DISABLED",
  INVALID_IP: "INVALID_IP",
  ALLOWLISTED: "ALLOWLISTED",
  COUNTRY_DISABLED: "COUNTRY_DISABLED",
  BELOW_THRESHOLD: "BELOW_THRESHOLD",
  OUTSIDE_TOP_N: "OUTSIDE_TOP_N",
  ALREADY_BLOCKED: "ALREADY_BLOCKED",
  POLICY_MATCH: "POLICY_MATCH",
  BLOCK_FAILED: "BLOCK_FAILED"
} as const;

export type DecisionReasonCode = typeof DecisionReason[keyof typeof DecisionReason];

export interface GuardDecision {
  action: GuardAction;
  reason: DecisionReasonCode | string;
  ip: string;
  country: string;
  requestCount: number;
  rank: number;
  threshold: number;
  windowSeconds: number;
}
