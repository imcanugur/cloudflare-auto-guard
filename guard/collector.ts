/**
 * Traffic Collector: Extracts, validates, and normalizes request metadata
 */
import { RequestIpContext } from "@/domain/models/ip";
import { isValidIp, getIpVersion } from "@/security/ip-validator";
import { normalizeIp } from "@/security/ip-normalizer";

export class TrafficCollector {
  public static extractContext(request: Request): RequestIpContext {
    const rawIp = request.headers.get("CF-Connecting-IP") || "";
    const country = (request.headers.get("CF-IPCountry") || "XX").toUpperCase();
    const timestamp = Date.now();

    const valid = isValidIp(rawIp);
    const normalizedIp = valid ? normalizeIp(rawIp) : "";
    const version = valid ? getIpVersion(rawIp) : null;

    return {
      rawIp,
      normalizedIp,
      version,
      country,
      timestamp
    };
  }
}
