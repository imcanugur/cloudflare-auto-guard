/**
 * Strict schema validation for runtime policies using Zod
 */
import { z } from "zod";

export const ActionSchema = z.enum(["block", "challenge"]);

export const DefaultRuleSchema = z.object({
  enabled: z.boolean().default(true),
  threshold: z.number().int().positive(),
  action: ActionSchema.optional().default("block"),
  windowSeconds: z.number().int().positive().optional(),
  topN: z.number().int().positive().optional()
});

export const CountryRuleSchema = z.object({
  enabled: z.boolean().optional(),
  threshold: z.number().int().positive().optional(),
  action: ActionSchema.optional(),
  windowSeconds: z.number().int().positive().optional(),
  topN: z.number().int().positive().optional()
});

export const UnbanPolicySchema = z.object({
  enabled: z.boolean().optional().default(true),
  ttlSeconds: z.number().int().positive().optional().default(86400),
  maxListSize: z.number().int().positive().optional().default(9000)
}).optional();

export const ScannerPolicySchema = z.object({
  enabled: z.boolean().optional().default(true),
  max404Threshold: z.number().int().positive().optional().default(25),
  windowSeconds: z.number().int().positive().optional().default(300),
  trapPaths: z.array(z.string()).optional().default([
    "/.env",
    "/.git",
    "/.git/config",
    "/.aws/credentials",
    "/wp-login.php",
    "/xmlrpc.php",
    "/wp-config.php",
    "/phpmyadmin",
    "/pma",
    "/adminer.php",
    "/actuator",
    "/actuator/health",
    "/shell.php",
    "/backup.sql",
    "/dump.sql"
  ]),
  enableHoneypot: z.boolean().optional().default(true),
  action: z.enum(["block", "log"]).optional().default("block")
}).optional();

export const GuardPolicySchema = z.object({
  enabled: z.boolean().default(true),
  timezone: z.string().optional().default("UTC"),
  windowSeconds: z.number().int().positive().optional().default(300),
  topN: z.number().int().positive().optional().default(100),
  default: DefaultRuleSchema,
  countries: z.record(z.string(), CountryRuleSchema).optional().default({}),
  allowlist: z.array(z.string()).optional().default([]),
  unban: UnbanPolicySchema,
  scanner: ScannerPolicySchema
});

export type ValidatedGuardPolicy = z.infer<typeof GuardPolicySchema>;

/**
 * Validates a policy object or throws a ZodError
 */
export function validatePolicy(data: unknown): ValidatedGuardPolicy {
  return GuardPolicySchema.parse(data);
}

/**
 * Safely parses a policy object without throwing
 */
export function safeValidatePolicy(data: unknown): {
  success: boolean;
  data?: ValidatedGuardPolicy;
  error?: z.ZodError;
} {
  return GuardPolicySchema.safeParse(data);
}
