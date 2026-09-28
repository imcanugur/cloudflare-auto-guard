/**
 * IP and Request Metadata domain model
 */
import { IpVersion } from "@/security/ip-validator";

export interface RequestIpContext {
  rawIp: string;
  normalizedIp: string;
  version: IpVersion | null;
  country: string;
  timestamp: number;
}
