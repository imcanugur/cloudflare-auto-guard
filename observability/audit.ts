/**
 * Audit event models and retention buffer
 */
import { GuardDecision } from "@/domain/models/decision";

export interface AuditEvent {
  timestamp: number;
  ip: string;
  country: string;
  requests: number;
  rank: number;
  threshold: number;
  action: string;
  reason: string;
}

export class AuditRecorder {
  private events: AuditEvent[] = [];
  private maxRetention: number;

  constructor(maxRetention = 1000) {
    this.maxRetention = maxRetention;
  }

  public recordDecision(decision: GuardDecision): AuditEvent {
    const event: AuditEvent = {
      timestamp: Date.now(),
      ip: decision.ip,
      country: decision.country,
      requests: decision.requestCount,
      rank: decision.rank,
      threshold: decision.threshold,
      action: decision.action,
      reason: decision.reason
    };

    this.events.unshift(event);

    // Apply retention pruning
    if (this.events.length > this.maxRetention) {
      this.events = this.events.slice(0, this.maxRetention);
    }

    return event;
  }

  public getRecentEvents(limit = 100): AuditEvent[] {
    return this.events.slice(0, limit);
  }
}
