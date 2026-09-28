/**
 * Safe defaults and static configuration loader for Auto Guard
 *
 * Reads and validates policy.json at bundle time.
 */
import { GuardPolicy } from "@/domain/models/policy";
import localPolicy from "@/policy.json";
import { safeValidatePolicy } from "@/config/policy-schema";

const validation = safeValidatePolicy(localPolicy);
if (!validation.success) {
  throw new Error(`Invalid policy.json configuration: ${validation.error?.message}`);
}

export const DEFAULT_GUARD_POLICY: GuardPolicy = validation.data as GuardPolicy;
