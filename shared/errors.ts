/**
 * Standardized domain and infrastructure error classes for Auto Guard
 */

export class GuardError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(message: string, code = "GUARD_ERROR", statusCode = 500) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class InvalidIpError extends GuardError {
  constructor(ip: string, message = `Invalid IP address format: ${ip}`) {
    super(message, "INVALID_IP", 400);
  }
}

export class ConfigurationError extends GuardError {
  constructor(message: string) {
    super(message, "CONFIGURATION_ERROR", 500);
  }
}

export class CloudflareApiError extends GuardError {
  public readonly responseBody?: unknown;

  constructor(message: string, statusCode = 502, responseBody?: unknown) {
    super(message, "CLOUDFLARE_API_ERROR", statusCode);
    this.responseBody = responseBody;
  }
}

export class StorageError extends GuardError {
  constructor(message: string) {
    super(message, "STORAGE_ERROR", 500);
  }
}
