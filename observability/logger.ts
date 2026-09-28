/**
 * Production structured JSON logger
 */

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogPayload {
  level: LogLevel;
  event: string;
  message?: string;
  ip?: string;
  country?: string;
  requests?: number;
  rank?: number;
  threshold?: number;
  action?: string;
  reason?: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
}

export class Logger {
  private contextName: string;

  constructor(contextName = "AutoGuard") {
    this.contextName = contextName;
  }

  private log(level: LogLevel, event: string, payload: Partial<LogPayload>): void {
    const entry: LogPayload = {
      level,
      event,
      timestamp: Date.now(),
      ...payload,
      metadata: {
        context: this.contextName,
        ...payload.metadata
      }
    };

    const serialized = JSON.stringify(entry);
    if (level === "error") {
      console.error(serialized);
    } else if (level === "warn") {
      console.warn(serialized);
    } else {
      console.log(serialized);
    }
  }

  public debug(event: string, payload: Partial<LogPayload> = {}): void {
    this.log("debug", event, payload);
  }

  public info(event: string, payload: Partial<LogPayload> = {}): void {
    this.log("info", event, payload);
  }

  public warn(event: string, payload: Partial<LogPayload> = {}): void {
    this.log("warn", event, payload);
  }

  public error(event: string, payload: Partial<LogPayload> = {}): void {
    this.log("error", event, payload);
  }
}

export const logger = new Logger("AutoGuard");
