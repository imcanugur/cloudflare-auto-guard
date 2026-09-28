/**
 * Safe fallback defaults for Auto Guard
 *
 * Principle: Fail-safe. If KV policy is missing, corrupted, or unreachable,
 * conservative settings take effect to prevent accidental false-positive blocking.
 */
import { GuardPolicy } from "@/domain/models/policy";
import localPolicy from "@/policy.json";

export const DEFAULT_GUARD_POLICY: GuardPolicy = localPolicy as unknown as GuardPolicy;
