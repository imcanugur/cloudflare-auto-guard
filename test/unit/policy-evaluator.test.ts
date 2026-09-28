import { describe, it, expect } from "vitest";
import { CandidateEvaluator } from "@/guard/evaluator";
import { GuardPolicy } from "@/domain/models/policy";
import { AllowlistMatcher } from "@/security/allowlist";
import { DecisionReason } from "@/domain/models/decision";

describe("CandidateEvaluator — Production Scenarios", () => {
  const policy: GuardPolicy = {
    enabled: true,
    windowSeconds: 300,
    topN: 100,
    default: {
      enabled: true,
      threshold: 10000,
      action: "block"
    },
    countries: {
      TR: {
        enabled: false
      },
      US: {
        enabled: true,
        threshold: 10,
        action: "block"
      },
      DE: {
        enabled: true,
        threshold: 5000,
        action: "block"
      },
      NL: {
        enabled: true,
        threshold: 3000,
        action: "block"
      }
    }
  };

  const allowlistMatcher = new AllowlistMatcher(["198.51.100.1"]);

  it("TR + 50.000 request -> IGNORE (COUNTRY_DISABLED)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "195.175.0.1",
      country: "TR",
      requestCount: 50000,
      rank: 1,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("IGNORE");
    expect(decision.reason).toBe(DecisionReason.COUNTRY_DISABLED);
  });

  it("US + 1.999 request -> IGNORE (BELOW_THRESHOLD)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "203.0.113.1",
      country: "US",
      requestCount: 1999,
      rank: 10,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("IGNORE");
    expect(decision.reason).toBe(DecisionReason.BELOW_THRESHOLD);
    expect(decision.threshold).toBe(2000);
  });

  it("US + 2.000 request -> BLOCK (POLICY_MATCH)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "203.0.113.2",
      country: "US",
      requestCount: 2000,
      rank: 10,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("BLOCK");
    expect(decision.reason).toBe(DecisionReason.POLICY_MATCH);
    expect(decision.threshold).toBe(2000);
  });

  it("US + 10.000 request -> BLOCK (POLICY_MATCH)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "203.0.113.3",
      country: "US",
      requestCount: 10000,
      rank: 5,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("BLOCK");
    expect(decision.reason).toBe(DecisionReason.POLICY_MATCH);
  });

  it("DE + 4.999 request -> IGNORE (BELOW_THRESHOLD)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "194.12.1.1",
      country: "DE",
      requestCount: 4999,
      rank: 20,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("IGNORE");
    expect(decision.reason).toBe(DecisionReason.BELOW_THRESHOLD);
    expect(decision.threshold).toBe(5000);
  });

  it("DE + 5.000 request -> BLOCK (POLICY_MATCH)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "194.12.1.2",
      country: "DE",
      requestCount: 5000,
      rank: 20,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("BLOCK");
    expect(decision.reason).toBe(DecisionReason.POLICY_MATCH);
    expect(decision.threshold).toBe(5000);
  });

  it("NL + 2.999 request -> IGNORE (BELOW_THRESHOLD)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "185.10.1.1",
      country: "NL",
      requestCount: 2999,
      rank: 50,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("IGNORE");
    expect(decision.reason).toBe(DecisionReason.BELOW_THRESHOLD);
    expect(decision.threshold).toBe(3000);
  });

  it("NL + 3.000 request -> BLOCK (POLICY_MATCH)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "185.10.1.2",
      country: "NL",
      requestCount: 3000,
      rank: 50,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("BLOCK");
    expect(decision.reason).toBe(DecisionReason.POLICY_MATCH);
    expect(decision.threshold).toBe(3000);
  });

  it("JP + 9.999 request -> IGNORE (BELOW_THRESHOLD with global default)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "133.1.1.1",
      country: "JP",
      requestCount: 9999,
      rank: 2,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("IGNORE");
    expect(decision.reason).toBe(DecisionReason.BELOW_THRESHOLD);
    expect(decision.threshold).toBe(10000);
  });

  it("JP + 10.000 request -> BLOCK (POLICY_MATCH with global default)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "133.1.1.2",
      country: "JP",
      requestCount: 10000,
      rank: 2,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("BLOCK");
    expect(decision.reason).toBe(DecisionReason.POLICY_MATCH);
    expect(decision.threshold).toBe(10000);
  });

  it("US + 50.000 + rank 101 -> IGNORE (OUTSIDE_TOP_N)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "203.0.113.99",
      country: "US",
      requestCount: 50000,
      rank: 101,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("IGNORE");
    expect(decision.reason).toBe(DecisionReason.OUTSIDE_TOP_N);
  });

  it("Allowlisted US IP -> ALLOW (ALLOWLISTED)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "198.51.100.1",
      country: "US",
      requestCount: 50000,
      rank: 1,
      policy,
      allowlistMatcher
    });

    expect(decision.action).toBe("ALLOW");
    expect(decision.reason).toBe(DecisionReason.ALLOWLISTED);
  });

  it("Already blocked IP -> IGNORE (ALREADY_BLOCKED)", () => {
    const decision = CandidateEvaluator.evaluate({
      ip: "203.0.113.5",
      country: "US",
      requestCount: 8000,
      rank: 3,
      policy,
      allowlistMatcher,
      isAlreadyBlocked: true
    });

    expect(decision.action).toBe("IGNORE");
    expect(decision.reason).toBe(DecisionReason.ALREADY_BLOCKED);
  });
});
