import { describe, it, expect } from "vitest";
import { validatePolicy, safeValidatePolicy } from "@/config/policy-schema";
import { ConfigLoader } from "@/config/config-loader";
import { DEFAULT_GUARD_POLICY } from "@/config/defaults";

describe("Policy Schema & Config Loader", () => {
  it("successfully parses valid runtime policy JSON", () => {
    const raw = {
      enabled: true,
      windowSeconds: 300,
      topN: 100,
      default: {
        enabled: true,
        threshold: 10000,
        action: "block"
      },
      countries: {
        TR: { enabled: false },
        US: { threshold: 2000 }
      }
    };

    const validated = validatePolicy(raw);
    expect(validated.enabled).toBe(true);
    expect(validated.countries["US"]?.threshold).toBe(2000);
  });

  it("fails schema validation on missing required threshold", () => {
    const invalid = {
      enabled: true,
      default: {
        enabled: true
        // threshold missing!
      }
    };

    const res = safeValidatePolicy(invalid);
    expect(res.success).toBe(false);
  });

  it("falls back to DEFAULT_GUARD_POLICY when KV has malformed JSON", async () => {
    const mockKv = {
      get: async () => "{ this is not json"
    } as unknown as KVNamespace;

    const res = await ConfigLoader.loadFromKv(mockKv);
    expect(res.isFallback).toBe(true);
    expect(res.policy).toEqual(DEFAULT_GUARD_POLICY);
  });

  it("falls back to DEFAULT_GUARD_POLICY when KV is missing", async () => {
    const res = await ConfigLoader.loadFromKv(undefined);
    expect(res.isFallback).toBe(true);
    expect(res.policy).toEqual(DEFAULT_GUARD_POLICY);
  });
});
