/**
 * High-performance IP and CIDR allowlist matcher
 */
import { isIPv4, isIPv6 } from "@/security/ip-validator";
import { normalizeIp } from "@/security/ip-normalizer";

/**
 * Converts an IPv4 string into a 32-bit unsigned number
 */
function ipv4ToNumber(ip: string): number {
  return (
    ip
      .split(".")
      .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0
  );
}

/**
 * Checks if an IPv4 address is contained within a given IPv4 CIDR range
 */
function isIpv4InCidr(ip: string, cidr: string): boolean {
  const [rangeIp, prefixStr] = cidr.split("/");
  if (!rangeIp || !prefixStr) return false;

  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const ipNum = ipv4ToNumber(ip);
  const rangeNum = ipv4ToNumber(rangeIp);

  if (prefix === 0) return true;

  const mask = ((0xffffffff << (32 - prefix)) & 0xffffffff) >>> 0;
  return (ipNum & mask) === (rangeNum & mask);
}

/**
 * Expands an IPv6 address into 8 groups of 4-character hex strings
 */
function expandIpv6(ip: string): string[] {
  let [left, right] = ip.split("::");
  const leftParts = left ? left.split(":") : [];
  const rightParts = right ? right.split(":") : [];

  if (ip.includes("::")) {
    const missing = 8 - (leftParts.length + rightParts.length);
    const middle = Array(missing).fill("0000");
    return [...leftParts, ...middle, ...rightParts].map((p) => p.padStart(4, "0"));
  }

  return leftParts.map((p) => p.padStart(4, "0"));
}

/**
 * Checks if an IPv6 address is contained within a given IPv6 CIDR range
 */
function isIpv6InCidr(ip: string, cidr: string): boolean {
  const [rangeIp, prefixStr] = cidr.split("/");
  if (!rangeIp || !prefixStr) return false;

  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 128) return false;

  try {
    const ipBits = expandIpv6(ip)
      .map((hex) => parseInt(hex, 16).toString(2).padStart(16, "0"))
      .join("");
    const rangeBits = expandIpv6(rangeIp)
      .map((hex) => parseInt(hex, 16).toString(2).padStart(16, "0"))
      .join("");

    return ipBits.slice(0, prefix) === rangeBits.slice(0, prefix);
  } catch {
    return false;
  }
}

export class AllowlistMatcher {
  private exactIps = new Set<string>();
  private cidrRanges: string[] = [];

  constructor(entries: string[] = []) {
    this.update(entries);
  }

  public update(entries: string[]): void {
    this.exactIps.clear();
    this.cidrRanges = [];

    for (const raw of entries) {
      if (!raw) continue;
      const entry = raw.trim();
      if (entry.includes("/")) {
        this.cidrRanges.push(entry);
      } else {
        this.exactIps.add(normalizeIp(entry));
      }
    }
  }

  public isAllowlisted(rawIp: string): boolean {
    const normalized = normalizeIp(rawIp);
    if (!normalized) return false;

    // Check exact match (O(1))
    if (this.exactIps.has(normalized)) {
      return true;
    }

    // Check CIDR matches
    const isV4 = isIPv4(normalized);
    const isV6 = isIPv6(normalized);

    for (const cidr of this.cidrRanges) {
      if (isV4 && isIpv4InCidr(normalized, cidr)) {
        return true;
      }
      if (isV6 && isIpv6InCidr(normalized, cidr)) {
        return true;
      }
    }

    return false;
  }
}
