import { count, desc, eq } from "drizzle-orm";
import type { CrelunaDb } from "../../db";
import {
  agentAssessments,
  auditLog,
  incidents,
  securityEvents,
} from "../../db/schema";
import {
  createInitialDemoState,
  type AgentId,
  type DashboardState,
  type DefenseCycleResult,
  type PolicyDecision,
  type PolicyOutcome,
  type SafeAction,
} from "./defense-engine";
import type { SecurityStore } from "./security-store";

const MAX_PUBLIC_EVENTS = 12;
const MAX_PUBLIC_AUDIT_ENTRIES = 100;

function clockLabel(iso: string): string {
  return iso.match(/T(\d{2}:\d{2}:\d{2})/)?.[1] ?? "LAB";
}

function isAgentId(value: string): value is AgentId {
  return ["aegis", "argine", "orbit", "decoy", "phoenix"].includes(value);
}

/** D1 adapter. Every value is bound by Drizzle; no interpolated SQL is used. */
export class D1SecurityStore implements SecurityStore {
  constructor(private readonly db: CrelunaDb) {}

  async appendCycle(result: DefenseCycleResult): Promise<void> {
    const assessmentRows = result.assessments.map((assessment) => ({
      id: assessment.id,
      eventId: assessment.eventId,
      agentId: assessment.agentId,
      verdict: assessment.verdict,
      scoreBps: Math.round(assessment.score * 10_000),
      rationale: assessment.rationale,
      createdAt: result.event.occurredAt,
    }));

    if (assessmentRows.length !== 5) {
      throw new Error("A complete lab council assessment must contain five agents.");
    }

    await this.db.batch([
      this.db.insert(securityEvents).values({
        id: result.event.id,
        sequence: result.snapshot.revision,
        scenarioId: result.event.scenarioId,
        title: result.event.title,
        publicSummary: result.event.detail,
        severity: result.event.severity,
        confidenceBps: Math.round(result.event.confidence * 10_000),
        signalCount: result.event.independentSignals,
        assetId: result.event.demoAsset,
        requestedAction: result.event.requestedAction,
        decision: result.decision.outcome,
        isSynthetic: true,
        occurredAt: result.event.occurredAt,
        createdAt: result.event.occurredAt,
      }),
      this.db.insert(agentAssessments).values(assessmentRows),
      this.db.insert(incidents).values({
        id: result.incident.id,
        eventId: result.incident.eventId,
        status: result.incident.status,
        impact: result.incident.impact,
        approvalStatus: result.incident.approvalStatus,
        publicSummary: result.incident.publicSummary,
        openedAt: result.incident.openedAt,
        resolvedAt: result.incident.resolvedAt,
        updatedAt: result.incident.updatedAt,
      }),
      this.db.insert(auditLog).values({
        id: result.audit.id,
        eventId: result.audit.eventId,
        sequence: result.audit.sequence,
        actor: result.audit.actor,
        action: result.audit.action,
        outcome: result.audit.outcome,
        reasonCode: result.audit.reasonCode,
        detail: result.audit.detail,
        createdAt: result.audit.createdAt,
      }),
    ]);
  }

  async readSanitizedSnapshot(): Promise<DashboardState> {
    const base = createInitialDemoState();

    const recentEvents = await this.db
      .select()
      .from(securityEvents)
      .orderBy(desc(securityEvents.occurredAt), desc(securityEvents.sequence))
      .limit(MAX_PUBLIC_EVENTS);

    const recentAssessments = await this.db
      .select({
        agentId: agentAssessments.agentId,
        verdict: agentAssessments.verdict,
        rationale: agentAssessments.rationale,
        eventSequence: securityEvents.sequence,
      })
      .from(agentAssessments)
      .innerJoin(securityEvents, eq(agentAssessments.eventId, securityEvents.id))
      .orderBy(desc(securityEvents.sequence))
      .limit(50);

    const recentAudit = await this.db
      .select({
        eventId: auditLog.eventId,
        action: auditLog.action,
        outcome: auditLog.outcome,
        reasonCode: auditLog.reasonCode,
        createdAt: auditLog.createdAt,
      })
      .from(auditLog)
      .orderBy(desc(auditLog.createdAt))
      .limit(MAX_PUBLIC_AUDIT_ENTRIES);

    const [eventCountRow] = await this.db
      .select({ value: count() })
      .from(securityEvents);
    const [mitigatedCountRow] = await this.db
      .select({ value: count() })
      .from(securityEvents)
      .where(eq(securityEvents.decision, "allow_simulation"));
    const [pendingCountRow] = await this.db
      .select({ value: count() })
      .from(incidents)
      .where(eq(incidents.approvalStatus, "pending"));

    const eventCount = Number(eventCountRow?.value ?? 0);
    const mitigatedCount = Number(mitigatedCountRow?.value ?? 0);
    const pendingApprovalCount = Number(pendingCountRow?.value ?? 0);
    const latestEvent = recentEvents[0];
    const latestByAgent = new Map<
      AgentId,
      { verdict: string; rationale: string }
    >();

    for (const assessment of recentAssessments) {
      if (
        isAgentId(assessment.agentId) &&
        !latestByAgent.has(assessment.agentId)
      ) {
        latestByAgent.set(assessment.agentId, assessment);
      }
    }

    return {
      ...base,
      revision: eventCount,
      status:
        pendingApprovalCount > 0
          ? "review"
          : latestEvent?.decision === "deny" || latestEvent?.severity === "high"
            ? "attention"
            : "protected",
      metrics: {
        detected: eventCount,
        mitigated: mitigatedCount,
        pendingApprovals: pendingApprovalCount,
        criticalBreaches: 0,
      },
      agents: base.agents.map((agent) => {
        const latest = latestByAgent.get(agent.id);
        if (!latest) return agent;
        return {
          ...agent,
          status:
            latest.verdict === "contain_simulation" ||
            latest.verdict === "hold_for_human"
              ? "engaged"
              : "ready",
          lastAction: latest.rationale,
        };
      }),
      timeline:
        recentEvents.length === 0
          ? base.timeline
          : recentEvents.map((event) => ({
              id: event.id,
              time: clockLabel(event.occurredAt),
              title: event.title,
              detail:
                event.decision === "requires_approval"
                  ? `${event.publicSummary} · approval required`
                  : event.publicSummary,
              severity: event.severity,
            })),
      audit: recentAudit
        .map((entry) => ({
          eventId: entry.eventId,
          action: entry.action as SafeAction,
          decision: entry.outcome as PolicyOutcome,
          reasonCode: entry.reasonCode as PolicyDecision["reasonCode"],
        }))
        .reverse(),
    };
  }
}
