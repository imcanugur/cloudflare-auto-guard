/**
 * IPv4 and IPv6 validation utilities without external dependencies
 */

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

// Standard IPv6 regex matching compressed (::) and full hexadecimal groups
const IPV6_REGEX = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;

export type IpVersion = "IPv4" | "IPv6";

export function isIPv4(ip: string): boolean {
  return IPV4_REGEX.test(ip.trim());
}

export function isIPv6(ip: string): boolean {
  return IPV6_REGEX.test(ip.trim());
}

export function isValidIp(ip: string): boolean {
  if (!ip || typeof ip !== "string") return false;
  const clean = ip.trim();
  return isIPv4(clean) || isIPv6(clean);
}

export function getIpVersion(ip: string): IpVersion | null {
  if (isIPv4(ip)) return "IPv4";
  if (isIPv6(ip)) return "IPv6";
  return null;
}
