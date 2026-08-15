import { and, asc, count, desc, eq } from "drizzle-orm";
import type { CrelunaDb } from "../../db";
import {
  agentAssessments,
  approvalDecisions,
  approvalRequests,
  auditLog,
  councilDecisions,
  idempotencyRecords,
  incidents,
  securityEvents,
} from "../../db/schema.ts";
import {
  autopilotOutcomeFor,
  buildCouncilSummary,
  createAutopilotState,
  createInitialDemoState,
  evaluateDemoAction,
  GUARDED_AUTOPILOT_ALLOWLIST,
  resolveApprovalInState,
  validateCouncilReports,
  type AgentId,
  type ApprovalDecision,
  type ApprovalResolutionResult,
  type CouncilSummary,
  type DashboardState,
  type DefenseCycleResult,
  type PolicyDecision,
  type PolicyOutcome,
  type SafeAction,
  type Severity,
} from "./defense-engine.ts";
import {
  ApprovalAlreadyResolvedError,
  ApprovalNotFoundError,
  IdempotencyConflictError,
  type IdempotencyRecordInput,
  type SecurityStore,
  type StoredReplay,
} from "./security-store.ts";

const MAX_PUBLIC_EVENTS = 12;
const MAX_PUBLIC_AUDIT_ENTRIES = 100;
// Bounded FIFO window: operators always see the oldest work first, so a busy
// lab cannot indefinitely hide an earlier approval behind newer proposals.
const MAX_PUBLIC_PENDING_APPROVALS = 50;
const MIN_AUTOPILOT_COUNCIL_CONFIDENCE = 85;

function decisionRank(outcome: PolicyOutcome): number {
  return outcome === "deny" ? 2 : outcome === "requires_approval" ? 1 : 0;
}

function clockLabel(iso: string): string {
  return iso.match(/T(\d{2}:\d{2}:\d{2})/)?.[1] ?? "LAB";
}

function parseStringArray(value: string, limit = 6): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is string => typeof item === "string").slice(0, limit);
  } catch {
    return [];
  }
}

/** D1 adapter. All values are bound by Drizzle; no SQL text is interpolated. */
export class D1SecurityStore implements SecurityStore {
  private readonly db: CrelunaDb;

  constructor(db: CrelunaDb) {
    this.db = db;
  }

  async findReplay(id: string): Promise<StoredReplay | null> {
    const [row] = await this.db
      .select()
      .from(idempotencyRecords)
      .where(eq(idempotencyRecords.id, id))
      .limit(1);
    return row ?? null;
  }

  async appendCycle(result: DefenseCycleResult, replay?: IdempotencyRecordInput): Promise<void> {
    if (
      result.assessments.length !== 5 ||
      result.council.quorum.received !== 5 ||
      result.council.quorum.required !== 5 ||
      !result.council.quorum.met
    ) {
      throw new Error("A complete validated five-agent council is required.");
    }
    const validatedReports = validateCouncilReports(
      result.event,
      result.assessments,
    );
    if (new Set(validatedReports.map(({ provider }) => provider)).size !== 1) {
      throw new Error("Council reports must come from one declared advisory boundary.");
    }
    const immutablePolicyDecision = evaluateDemoAction(result.event);
    const rebuiltCouncil = buildCouncilSummary(
      result.event,
      immutablePolicyDecision,
      validatedReports,
    );
    if (JSON.stringify(rebuiltCouncil) !== JSON.stringify(result.council)) {
      throw new Error("The persisted council summary must match validated reports and Policy Guard.");
    }
    let expectedOutcome = immutablePolicyDecision.outcome;
    let expectedReasonCode = immutablePolicyDecision.reasonCode;
    let expectedApprovalRequired = immutablePolicyDecision.approvalRequired;
    if (immutablePolicyDecision.outcome === "allow_simulation") {
      const confidenceGateMet = validatedReports.every(
        ({ confidence }) => confidence >= MIN_AUTOPILOT_COUNCIL_CONFIDENCE,
      );
      expectedOutcome = confidenceGateMet && rebuiltCouncil.recommendation === "allow_simulation"
        ? "allow_simulation"
        : "deny";
      if (!confidenceGateMet) {
        expectedReasonCode = "COUNCIL_CONFIDENCE_GATE_FAILED";
      } else if (rebuiltCouncil.recommendation === "deny") {
        expectedReasonCode = "COUNCIL_DENY_RECORDED";
      } else if (rebuiltCouncil.recommendation === "requires_approval") {
        expectedReasonCode = "COUNCIL_SAFETY_HOLD_RECORDED";
      }
      expectedApprovalRequired = false;
    } else if (
      decisionRank(rebuiltCouncil.recommendation) >
      decisionRank(immutablePolicyDecision.outcome)
    ) {
      expectedOutcome = rebuiltCouncil.recommendation;
      expectedReasonCode = "COUNCIL_DENY_RECORDED";
      expectedApprovalRequired = false;
    }
    if (
      result.decision.outcome !== expectedOutcome ||
      result.decision.reasonCode !== expectedReasonCode ||
      result.decision.approvalRequired !== expectedApprovalRequired
    ) {
      throw new Error("The persisted decision cannot weaken Policy Guard or guarded-autopilot gates.");
    }
    if (
      result.execution.externalNetworkAction !== false ||
      result.execution.offensiveAction !== false ||
      result.execution.privilegedAction !== false
    ) {
      throw new Error("External, offensive and privileged execution is forbidden.");
    }
    const isAutopilotAction = (GUARDED_AUTOPILOT_ALLOWLIST as readonly string[])
      .includes(result.event.requestedAction);
    if (
      result.decision.outcome === "allow_simulation" &&
      !isAutopilotAction
    ) {
      throw new Error("Only guarded-autopilot allowlisted actions may be recorded as autonomous.");
    }
    if (
      result.approval !== null &&
      result.event.requestedAction !== "restore_demo_snapshot"
    ) {
      throw new Error("Only manual snapshot restoration may create a blocking approval.");
    }
    if (
      result.event.requestedAction === "restore_demo_snapshot" &&
      (
        result.decision.outcome === "allow_simulation" ||
        (result.decision.outcome === "requires_approval" && result.approval === null) ||
        (result.decision.outcome === "deny" && result.approval !== null)
      )
    ) {
      throw new Error("Snapshot restoration must remain behind a recorded manual approval gate.");
    }
    if (
      result.event.requestedAction !== "restore_demo_snapshot" &&
      result.decision.outcome === "requires_approval"
    ) {
      throw new Error("Guarded-autopilot actions cannot create a new blocking approval.");
    }
    if (
      result.audit.eventId !== result.event.id ||
      result.audit.action !== result.event.requestedAction ||
      result.audit.outcome !== result.decision.outcome ||
      result.audit.reasonCode !== result.decision.reasonCode ||
      result.incident.eventId !== result.event.id
    ) {
      throw new Error("Cycle audit and incident records must match the effective decision.");
    }
    if (replay) {
      const existing = await this.findReplay(replay.id);
      if (existing) {
        if (existing.requestHash !== replay.requestHash) throw new IdempotencyConflictError();
        return;
      }
    }

    const eventInsert = this.db.insert(securityEvents).values({
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
    });
    const assessmentsInsert = this.db.insert(agentAssessments).values(
      result.assessments.map((assessment) => ({
        id: assessment.id,
        eventId: assessment.eventId,
        agentId: assessment.agentId,
        verdict: assessment.verdict,
        vote: assessment.vote,
        risk: assessment.risk,
        scoreBps: Math.round(assessment.score * 10_000),
        confidenceBps: Math.round(assessment.confidence * 100),
        trustBps: Math.round(assessment.trust * 100),
        rationale: assessment.rationale,
        evidenceJson: JSON.stringify(assessment.evidence),
        safeguardsJson: JSON.stringify(assessment.safeguards),
        createdAt: result.event.occurredAt,
      })),
    );
    const councilInsert = this.db.insert(councilDecisions).values({
      id: `${result.event.id}:council`,
      eventId: result.event.id,
      consensus: result.council.consensus,
      recommendation: result.council.recommendation,
      quorumRequired: result.council.quorum.required,
      quorumReceived: result.council.quorum.received,
      agreementBps: Math.round(result.council.agreement * 100),
      risk: result.council.risk,
      confidenceBps: Math.round(result.council.confidence * 100),
      allowVotes: result.council.votes.allowSimulation,
      approvalVotes: result.council.votes.requiresApproval,
      denyVotes: result.council.votes.deny,
      explanationJson: JSON.stringify(result.council.explanation),
      dissentingAgentsJson: JSON.stringify(result.council.dissentingAgents),
      createdAt: result.event.occurredAt,
    });
    const incidentInsert = this.db.insert(incidents).values({
      id: result.incident.id,
      eventId: result.incident.eventId,
      status: result.incident.status,
      impact: result.incident.impact,
      approvalStatus: result.incident.approvalStatus,
      publicSummary: result.incident.publicSummary,
      openedAt: result.incident.openedAt,
      resolvedAt: result.incident.resolvedAt,
      updatedAt: result.incident.updatedAt,
    });
    const auditInsert = this.db.insert(auditLog).values({
      id: result.audit.id,
      eventId: result.audit.eventId,
      sequence: result.audit.sequence,
      actor: result.audit.actor,
      action: result.audit.action,
      outcome: result.audit.outcome,
      reasonCode: result.audit.reasonCode,
      detail: result.audit.detail,
      createdAt: result.audit.createdAt,
    });
    const approvalInsert = result.approval
      ? this.db.insert(approvalRequests).values({
          id: result.approval.id,
          eventId: result.approval.eventId,
          scenarioId: result.approval.scenarioId,
          title: result.approval.title,
          severity: result.approval.severity,
          requestedAction: result.approval.requestedAction,
          status: result.approval.status,
          policyVersion: result.approval.policyVersion,
          councilRecommendation: result.approval.councilRecommendation,
          explanation: result.approval.explanation,
          createdAt: result.approval.createdAt,
          decidedAt: null,
        })
      : null;
    const replayInsert = replay ? this.db.insert(idempotencyRecords).values(replay) : null;

    if (approvalInsert && replayInsert) {
      await this.db.batch([eventInsert, assessmentsInsert, councilInsert, incidentInsert, auditInsert, approvalInsert, replayInsert]);
    } else if (approvalInsert) {
      await this.db.batch([eventInsert, assessmentsInsert, councilInsert, incidentInsert, auditInsert, approvalInsert]);
    } else if (replayInsert) {
      await this.db.batch([eventInsert, assessmentsInsert, councilInsert, incidentInsert, auditInsert, replayInsert]);
    } else {
      await this.db.batch([eventInsert, assessmentsInsert, councilInsert, incidentInsert, auditInsert]);
    }
  }

  async resolveApproval(
    approvalId: string,
    decision: ApprovalDecision,
    now: string,
    replay?: IdempotencyRecordInput,
  ): Promise<ApprovalResolutionResult> {
    if (replay) {
      const existing = await this.findReplay(replay.id);
      if (existing) {
        if (existing.requestHash !== replay.requestHash) throw new IdempotencyConflictError();
        throw new ApprovalAlreadyResolvedError();
      }
    }

    const [request] = await this.db
      .select()
      .from(approvalRequests)
      .where(eq(approvalRequests.id, approvalId))
      .limit(1);
    if (!request) throw new ApprovalNotFoundError();
    if (request.status !== "pending") throw new ApprovalAlreadyResolvedError();

    const before = await this.readSanitizedSnapshot();
    if (!before.pendingApprovalItems.some(({ id }) => id === request.id)) {
      before.pendingApprovalItems = [{
        id: request.id,
        eventId: request.eventId,
        scenarioId: request.scenarioId,
        title: request.title,
        severity: request.severity,
        requestedAction: request.requestedAction,
        status: "pending",
        policyVersion: request.policyVersion,
        createdAt: request.createdAt,
        councilRecommendation: request.councilRecommendation,
        explanation: request.explanation,
        reviewMode: request.requestedAction === "restore_demo_snapshot"
          ? "blocking_manual"
          : "post_event",
      }, ...before.pendingApprovalItems];
    }
    const result = resolveApprovalInState(before, approvalId, decision, now);
    const nextStatus = decision === "approve_simulation" ? "approved_simulation" : "rejected";
    const nextIncidentStatus = decision === "approve_simulation" ? "contained" : "denied";
    const decisionInsert = this.db.insert(approvalDecisions).values({
      id: result.record.id,
      approvalId: result.record.approvalId,
      eventId: result.record.eventId,
      decision: result.record.decision,
      scope: result.record.scope,
      executedExternalAction: false,
      decidedAt: result.record.decidedAt,
    });
    const approvalUpdate = this.db
      .update(approvalRequests)
      .set({ status: nextStatus, decidedAt: now })
      .where(and(eq(approvalRequests.id, approvalId), eq(approvalRequests.status, "pending")));
    const incidentUpdate = this.db
      .update(incidents)
      .set({
        status: nextIncidentStatus,
        impact: "none",
        approvalStatus: nextStatus,
        publicSummary: decision === "approve_simulation"
          ? "State-only simulation authorization recorded; no external action executed"
          : "Proposal rejected by the lab operator; no action executed",
        resolvedAt: now,
        updatedAt: now,
      })
      .where(eq(incidents.eventId, request.eventId));
    const auditInsert = this.db.insert(auditLog).values({
      id: result.audit.id,
      eventId: result.audit.eventId,
      sequence: result.audit.sequence,
      actor: result.audit.actor,
      action: result.audit.action,
      outcome: result.audit.outcome,
      reasonCode: result.audit.reasonCode,
      detail: result.audit.detail,
      createdAt: result.audit.createdAt,
    });
    const replayInsert = replay ? this.db.insert(idempotencyRecords).values(replay) : null;

    try {
      if (replayInsert) {
        await this.db.batch([approvalUpdate, incidentUpdate, decisionInsert, auditInsert, replayInsert]);
      } else {
        await this.db.batch([approvalUpdate, incidentUpdate, decisionInsert, auditInsert]);
      }
    } catch (error) {
      const [latest] = await this.db
        .select({ status: approvalRequests.status })
        .from(approvalRequests)
        .where(eq(approvalRequests.id, approvalId))
        .limit(1);
      if (latest && latest.status !== "pending") throw new ApprovalAlreadyResolvedError();
      throw error;
    }

    return { ...result, snapshot: await this.readSanitizedSnapshot() };
  }

  async readSanitizedSnapshot(): Promise<DashboardState> {
    const base = createInitialDemoState();
    // `sequence` remains revision metadata, not a cross-request coordinator.
    // Stable ID tie-breakers and event-scoped assessments keep the public view
    // deterministic even if concurrent cycles happen to receive the same value.
    // A strict point-in-time snapshot across every counter/list still requires
    // a future single-batch/session read architecture rather than a fake lock.
    const recentEvents = await this.db
      .select()
      .from(securityEvents)
      .orderBy(
        desc(securityEvents.occurredAt),
        desc(securityEvents.sequence),
        desc(securityEvents.id),
      )
      .limit(MAX_PUBLIC_EVENTS);
    const assessmentCounts = await this.db
      .select({ agentId: agentAssessments.agentId, value: count() })
      .from(agentAssessments)
      .groupBy(agentAssessments.agentId);
    const [latestCouncil] = await this.db
      .select()
      .from(councilDecisions)
      .orderBy(desc(councilDecisions.createdAt), desc(councilDecisions.eventId))
      .limit(1);
    const latestCouncilAssessments = latestCouncil
      ? await this.db
          .select({
            agentId: agentAssessments.agentId,
            verdict: agentAssessments.verdict,
            vote: agentAssessments.vote,
            risk: agentAssessments.risk,
            confidenceBps: agentAssessments.confidenceBps,
            trustBps: agentAssessments.trustBps,
            rationale: agentAssessments.rationale,
            evidenceJson: agentAssessments.evidenceJson,
            safeguardsJson: agentAssessments.safeguardsJson,
          })
          .from(agentAssessments)
          .where(eq(agentAssessments.eventId, latestCouncil.eventId))
          .orderBy(asc(agentAssessments.agentId))
          .limit(5)
      : [];
    const pendingRows = await this.db
      .select()
      .from(approvalRequests)
      .where(eq(approvalRequests.status, "pending"))
      .orderBy(asc(approvalRequests.createdAt), asc(approvalRequests.id))
      .limit(MAX_PUBLIC_PENDING_APPROVALS);
    const decisionRows = await this.db
      .select({
        id: approvalDecisions.id,
        approvalId: approvalDecisions.approvalId,
        eventId: approvalDecisions.eventId,
        decision: approvalDecisions.decision,
        scope: approvalDecisions.scope,
        executedExternalAction: approvalDecisions.executedExternalAction,
        decidedAt: approvalDecisions.decidedAt,
        title: approvalRequests.title,
      })
      .from(approvalDecisions)
      .innerJoin(approvalRequests, eq(approvalDecisions.approvalId, approvalRequests.id))
      .orderBy(desc(approvalDecisions.decidedAt), desc(approvalDecisions.id))
      .limit(20);
    const [latestCouncilResolution] = latestCouncil
      ? await this.db
          .select({ decision: approvalDecisions.decision })
          .from(approvalDecisions)
          .where(eq(approvalDecisions.eventId, latestCouncil.eventId))
          .orderBy(desc(approvalDecisions.decidedAt))
          .limit(1)
      : [];
    const recentAudit = await this.db
      .select({
        eventId: auditLog.eventId,
        action: auditLog.action,
        outcome: auditLog.outcome,
        reasonCode: auditLog.reasonCode,
      })
      .from(auditLog)
      .orderBy(desc(auditLog.createdAt), desc(auditLog.id))
      .limit(MAX_PUBLIC_AUDIT_ENTRIES);
    const [eventCountRow] = await this.db.select({ value: count() }).from(securityEvents);
    const [allowedCountRow] = await this.db
      .select({ value: count() })
      .from(securityEvents)
      .where(eq(securityEvents.decision, "allow_simulation"));
    const [approvedCountRow] = await this.db
      .select({ value: count() })
      .from(approvalDecisions)
      .where(eq(approvalDecisions.decision, "approve_simulation"));
    const [decisionCountRow] = await this.db
      .select({ value: count() })
      .from(approvalDecisions);
    const [pendingCountRow] = await this.db
      .select({ value: count() })
      .from(approvalRequests)
      .where(eq(approvalRequests.status, "pending"));
    const [blockingManualCountRow] = await this.db
      .select({ value: count() })
      .from(approvalRequests)
      .where(and(
        eq(approvalRequests.status, "pending"),
        eq(approvalRequests.requestedAction, "restore_demo_snapshot"),
      ));

    const latestByAgent = new Map<AgentId, (typeof latestCouncilAssessments)[number]>();
    for (const assessment of latestCouncilAssessments) {
      latestByAgent.set(assessment.agentId, assessment);
    }
    const countsByAgent = new Map<AgentId, number>(
      assessmentCounts.map((entry) => [entry.agentId, Number(entry.value)]),
    );
    const council: CouncilSummary | null = latestCouncil
      ? {
          eventId: latestCouncil.eventId,
          consensus: latestCouncil.consensus,
          recommendation: latestCouncil.recommendation,
          quorum: {
            required: latestCouncil.quorumRequired,
            received: latestCouncil.quorumReceived,
            met: latestCouncil.quorumReceived >= latestCouncil.quorumRequired,
          },
          agreement: latestCouncil.agreementBps / 100,
          risk: latestCouncil.risk,
          confidence: latestCouncil.confidenceBps / 100,
          votes: {
            allowSimulation: latestCouncil.allowVotes,
            requiresApproval: latestCouncil.approvalVotes,
            deny: latestCouncil.denyVotes,
          },
          explanation: parseStringArray(latestCouncil.explanationJson, 5),
          dissentingAgents: parseStringArray(latestCouncil.dissentingAgentsJson, 5)
            .filter((id): id is AgentId => ["aegis", "argine", "orbit", "decoy", "phoenix"].includes(id)),
        }
      : null;
    const eventCount = Number(eventCountRow?.value ?? 0);
    const approvedSimulationCount = Number(allowedCountRow?.value ?? 0) + Number(approvedCountRow?.value ?? 0);
    const pendingApprovalCount = Number(pendingCountRow?.value ?? 0);
    const blockingManualApprovalCount = Number(blockingManualCountRow?.value ?? 0);
    const latestEvent = recentEvents[0];
    const pendingApprovalItems = pendingRows.map((item) => {
      const reviewMode = item.requestedAction === "restore_demo_snapshot"
        ? "blocking_manual" as const
        : "post_event" as const;
      return {
        id: item.id,
        eventId: item.eventId,
        scenarioId: item.scenarioId,
        title: item.title,
        severity: item.severity,
        requestedAction: item.requestedAction,
        status: "pending" as const,
        policyVersion: item.policyVersion,
        createdAt: item.createdAt,
        councilRecommendation: item.councilRecommendation,
        explanation: reviewMode === "post_event"
          ? "Legacy proposal retained for post-event review; guarded protection remains active."
          : "Snapshot restoration remains blocked until one explicit human decision is recorded.",
        reviewMode,
      };
    });
    const latestCouncilLegacyPostReview = latestCouncil
      ? pendingRows.some((item) =>
          item.eventId === latestCouncil.eventId &&
          item.requestedAction !== "restore_demo_snapshot"
        )
      : false;
    const decisionTimeline = decisionRows.map((record) => {
      const severity: Severity = record.decision === "approve_simulation" ? "low" : "info";
      return {
        id: record.id,
        time: clockLabel(record.decidedAt),
        sortAt: record.decidedAt,
        title: record.decision === "approve_simulation" ? "State-only simulation approved" : "Simulation proposal rejected",
        detail: record.decision === "approve_simulation"
          ? `${record.title} · authorization recorded; no external action executed`
          : `${record.title} · rejected; no action executed`,
        severity,
      };
    });
    const eventTimeline = recentEvents.map((event) => ({
      id: event.id,
      time: clockLabel(event.occurredAt),
      sortAt: event.occurredAt,
      title: event.title,
      detail: event.decision === "requires_approval"
        ? event.requestedAction === "restore_demo_snapshot"
          ? `${event.publicSummary} · manual restore approval required`
          : `${event.publicSummary} · legacy post-event review · guarded protection active`
        : event.publicSummary,
      severity: event.severity,
    }));

    return {
      ...base,
      revision: eventCount + Number(decisionCountRow?.value ?? 0),
      status: blockingManualApprovalCount > 0
        ? "review"
        : latestEvent?.decision === "deny" ? "attention" : "protected",
      metrics: {
        detected: eventCount,
        mitigated: approvedSimulationCount,
        pendingApprovals: pendingApprovalCount,
        criticalBreaches: 0,
      },
      autopilot: {
        ...createAutopilotState(latestEvent
          ? {
              outcome: autopilotOutcomeFor(
                latestEvent.requestedAction,
                latestEvent.decision,
              ),
              cycleId: latestEvent.id,
              scenario: latestEvent.scenarioId,
              action: latestEvent.requestedAction,
              decidedAt: latestEvent.occurredAt,
            }
          : null, pendingApprovalItems),
        // The public queue is intentionally bounded, so derive this flag from
        // the unbounded count rather than only the first visible 50 records.
        postReviewOnly: blockingManualApprovalCount === 0,
      },
      council,
      agents: base.agents.map((agent) => {
        const latest = latestByAgent.get(agent.id);
        if (!latest) return agent;
        const assessment = {
          verdict: latest.verdict,
          vote: latest.vote,
          risk: latest.risk,
          confidence: latest.confidenceBps / 100,
          trust: latest.trustBps / 100,
          rationale: latest.rationale,
          evidence: parseStringArray(latest.evidenceJson),
          safeguards: parseStringArray(latest.safeguardsJson),
        };
        return {
          ...agent,
          status: latestCouncilResolution || latestCouncilLegacyPostReview
            ? "ready"
            : assessment.verdict === "contain_simulation" || assessment.verdict === "hold_for_human"
              ? "engaged"
              : "ready",
          lastAction: latestCouncilResolution
            ? latestCouncilResolution.decision === "approve_simulation"
              ? "Human state-only authorization recorded; no external action executed"
              : "Human rejection recorded; no action executed"
            : latestCouncilLegacyPostReview
              ? "Legacy hold retained for post-event review; guarded autopilot remains active"
            : assessment.rationale,
          stats: {
            assessments: countsByAgent.get(agent.id) ?? 0,
            consensusAlignment: council && assessment.vote === council.recommendation ? 100 : 80,
            trust: assessment.trust,
          },
          assessment,
        };
      }),
      pendingApprovalItems,
      recentApprovalDecisions: decisionRows.map((record) => ({
        id: record.id,
        approvalId: record.approvalId,
        eventId: record.eventId,
        decision: record.decision,
        scope: record.scope,
        executedExternalAction: record.executedExternalAction,
        decidedAt: record.decidedAt,
      })),
      timeline: [...decisionTimeline, ...eventTimeline]
        .sort((a, b) => b.sortAt.localeCompare(a.sortAt))
        .slice(0, MAX_PUBLIC_EVENTS)
        .map((entry) => ({
          id: entry.id,
          time: entry.time,
          title: entry.title,
          detail: entry.detail,
          severity: entry.severity,
        })),
      audit: recentAudit.map((entry) => ({
        eventId: entry.eventId,
        action: entry.action as SafeAction,
        decision: entry.outcome as PolicyOutcome,
        reasonCode: entry.reasonCode as PolicyDecision["reasonCode"],
      })).reverse(),
    };
  }
}
