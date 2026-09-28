import { describe, it, expect } from "vitest";
import { isValidIp, isIPv4, isIPv6 } from "@/security/ip-validator";
import { normalizeIp } from "@/security/ip-normalizer";
import { AllowlistMatcher } from "@/security/allowlist";

describe("IP Validator & Normalizer", () => {
  it("validates standard IPv4 addresses", () => {
    expect(isValidIp("192.168.1.1")).toBe(true);
    expect(isIPv4("8.8.8.8")).toBe(true);
    expect(isValidIp("256.0.0.1")).toBe(false);
    expect(isValidIp("1.2.3")).toBe(false);
    expect(isValidIp("not-an-ip")).toBe(false);
  });

  it("validates standard and compressed IPv6 addresses", () => {
    expect(isValidIp("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe(true);
    expect(isValidIp("2001:db8::1")).toBe(true);
    expect(isValidIp("::1")).toBe(true);
    expect(isIPv6("::1")).toBe(true);
    expect(isValidIp("2001:xyz::1")).toBe(false);
  });

  it("normalizes IPv4 and IPv6 addresses correctly", () => {
    expect(normalizeIp(" 192.168.01.1 ")).toBe("192.168.1.1");
    expect(normalizeIp("[2001:db8::1]")).toBe("2001:db8::1");
    expect(normalizeIp("10.0.0.1:8080")).toBe("10.0.0.1");
  });
});

describe("AllowlistMatcher with CIDR Support", () => {
  const matcher = new AllowlistMatcher([
    "1.1.1.1",
    "8.8.8.8",
    "10.0.0.0/8",
    "192.168.1.0/24",
    "2001:db8::/32"
  ]);

  it("matches exact allowlisted IPs", () => {
    expect(matcher.isAllowlisted("1.1.1.1")).toBe(true);
    expect(matcher.isAllowlisted("8.8.8.8")).toBe(true);
    expect(matcher.isAllowlisted("8.8.4.4")).toBe(false);
  });

  it("matches IPv4 CIDR ranges correctly", () => {
    expect(matcher.isAllowlisted("10.5.20.1")).toBe(true);
    expect(matcher.isAllowlisted("10.255.255.254")).toBe(true);
    expect(matcher.isAllowlisted("11.0.0.1")).toBe(false);

    expect(matcher.isAllowlisted("192.168.1.55")).toBe(true);
    expect(matcher.isAllowlisted("192.168.2.1")).toBe(false);
  });

  it("matches IPv6 CIDR ranges correctly", () => {
    expect(matcher.isAllowlisted("2001:db8:0:0:0:0:0:1")).toBe(true);
    expect(matcher.isAllowlisted("2001:db8:ffff::1")).toBe(true);
    expect(matcher.isAllowlisted("2001:dead::1")).toBe(false);
  });
});
