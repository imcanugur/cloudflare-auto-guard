/**
 * Country policy resolution service with controlled typed merge
 */
import { GuardPolicy, ResolvedPolicy } from "@/domain/models/policy";

export class CountryPolicyResolver {
  /**
   * Resolves the effective policy for a given country code by merging
   * country-level overrides with the global default policy.
   */
  public static resolve(policy: GuardPolicy, countryCode: string): ResolvedPolicy {
    const normalizedCountry = (countryCode || "").toUpperCase().trim();
    const defaultRule = policy.default;

    // Fallback baseline values from root or default block
    const baseWindowSeconds = defaultRule.windowSeconds ?? policy.windowSeconds ?? 300;
    const baseTopN = defaultRule.topN ?? policy.topN ?? 100;
    const baseAction = defaultRule.action ?? "block";
    const baseThreshold = defaultRule.threshold;
    const baseEnabled = defaultRule.enabled ?? policy.enabled;

    const countryRule = policy.countries?.[normalizedCountry];

    if (!countryRule) {
      return {
        enabled: baseEnabled,
        threshold: baseThreshold,
        windowSeconds: baseWindowSeconds,
        topN: baseTopN,
        action: baseAction,
        isCountryOverride: false
      };
    }

    // Explicit country override exists
    return {
      enabled: countryRule.enabled !== undefined ? countryRule.enabled : baseEnabled,
      threshold: countryRule.threshold !== undefined ? countryRule.threshold : baseThreshold,
      windowSeconds: countryRule.windowSeconds !== undefined ? countryRule.windowSeconds : baseWindowSeconds,
      topN: countryRule.topN !== undefined ? countryRule.topN : baseTopN,
      action: countryRule.action !== undefined ? countryRule.action : baseAction,
      isCountryOverride: true
    };
  }
}
