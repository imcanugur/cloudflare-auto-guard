/**
 * PolicyLoader: Loads and validates runtime policy from Cloudflare KV
 * with fail-safe fallback to conservative default policy.
 */
import { GuardPolicy } from "@/domain/models/policy";
import { DEFAULT_GUARD_POLICY } from "@/config/defaults";
import { safeValidatePolicy } from "@/config/policy-schema";

export const POLICY_KV_KEY = "guard:policy";

export class ConfigLoader {
  /**
   * Reads raw JSON from KV, validates against schema, and returns a verified GuardPolicy.
   * If KV is unavailable, unreadable, or invalid, returns fail-safe DEFAULT_GUARD_POLICY.
   */
  public static async loadFromKv(
    kvNamespace?: KVNamespace,
    key = POLICY_KV_KEY
  ): Promise<{ policy: GuardPolicy; isFallback: boolean; error?: string }> {
    if (!kvNamespace) {
      return { policy: DEFAULT_GUARD_POLICY, isFallback: true, error: "KV namespace not bound" };
    }

    try {
      const raw = await kvNamespace.get(key, "text");
      if (!raw) {
        // Auto-seed KV with default policy.json so user never has to set it manually
        try {
          await kvNamespace.put(key, JSON.stringify(DEFAULT_GUARD_POLICY, null, 2));
        } catch {
          // Ignore write failure in restricted preview environments
        }
        return { policy: DEFAULT_GUARD_POLICY, isFallback: false };
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch (err) {
        return {
          policy: DEFAULT_GUARD_POLICY,
          isFallback: true,
          error: `Malformed JSON in KV key '${key}': ${(err as Error).message}`
        };
      }

      const validation = safeValidatePolicy(parsed);
      if (!validation.success) {
        return {
          policy: DEFAULT_GUARD_POLICY,
          isFallback: true,
          error: `Schema validation failed for KV policy: ${validation.error?.message}`
        };
      }

      return {
        policy: validation.data as GuardPolicy,
        isFallback: false
      };
    } catch (err) {
      return {
        policy: DEFAULT_GUARD_POLICY,
        isFallback: true,
        error: `Unexpected error reading KV: ${(err as Error).message}`
      };
    }
  }
}
