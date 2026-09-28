/**
 * Safe defaults and static configuration loader for Auto Guard
 *
 * Reads and validates policy.json at bundle time.
 */
import { GuardPolicy } from "@/domain/models/policy";
import examplePolicy from "@/policy.example.json";
import { safeValidatePolicy } from "@/config/policy-schema";

const validation = safeValidatePolicy(examplePolicy);
if (!validation.success) {
  throw new Error(`Invalid policy.example.json configuration: ${validation.error?.message}`);
}

export const DEFAULT_GUARD_POLICY: GuardPolicy = validation.data as GuardPolicy;
