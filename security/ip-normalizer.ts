/**
 * IP address normalization utilities
 */
import { isIPv4, isIPv6 } from "@/security/ip-validator";

export function normalizeIp(ip: string): string {
  if (!ip) return "";
  let clean = ip.trim().toLowerCase();

  // Strip enclosing brackets for IPv6 if present (e.g., [2001:db8::1])
  if (clean.startsWith("[") && clean.endsWith("]")) {
    clean = clean.slice(1, -1);
  }

  // Strip port if present in IPv4 (e.g. 1.2.3.4:8080)
  if (clean.includes(".")) {
    const colonIndex = clean.lastIndexOf(":");
    if (colonIndex > 0 && !clean.includes("::")) {
      clean = clean.slice(0, colonIndex);
    }
  }

  if (isIPv4(clean)) {
    // Normalize octets by stripping leading zeros (e.g. 192.168.001.001 -> 192.168.1.1)
    return clean
      .split(".")
      .map((part) => parseInt(part, 10).toString())
      .join(".");
  }

  if (isIPv6(clean)) {
    return clean;
  }

  return clean;
}
