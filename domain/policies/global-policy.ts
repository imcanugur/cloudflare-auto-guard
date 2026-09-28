/**
 * Global Guard policy evaluation
 */
import { GuardPolicy } from "@/domain/models/policy";

export class GlobalPolicy {
  public static isGuardEnabled(policy: GuardPolicy): boolean {
    return policy.enabled === true;
  }
}
