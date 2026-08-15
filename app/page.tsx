"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";
import {
  createInitialDemoState,
  type AgentState,
  type DashboardState,
  type Severity,
} from "../lib/creluna/defense-engine";

const severityLabels: Record<Severity, string> = {
  info: "INFO",
  low: "LOW",
  medium: "MEDIUM",
  high: "HIGH",
  critical: "CRITICAL",
};

const agentIcons: Record<AgentState["id"], string> = {
  aegis: "A",
  argine: "AR",
  orbit: "O",
  decoy: "D",
  phoenix: "P",
};

const agentBriefs: Record<
  AgentState["id"],
  { phase: string; description: string; boundary: string }
> = {
  aegis: {
    phase: "RILEVA",
    description:
      "Correla telemetria sanitizzata e costruisce una prova verificabile prima di proporre qualsiasi risposta.",
    boundary: "Sola lettura · nessun dato grezzo pubblico",
  },
  argine: {
    phase: "CONTIENE",
    description:
      "Applica limiti reversibili a sessioni e richieste esclusivamente dentro il laboratorio autorizzato.",
    boundary: "Azioni circoscritte · rollback immediato",
  },
  orbit: {
    phase: "PROTEGGE",
    description:
      "Verifica identità, sessioni e privilegi per fermare movimenti anomali senza inseguire l'attaccante.",
    boundary: "Identità del lab · credenziali protette",
  },
  decoy: {
    phase: "DEVIA",
    description:
      "Instrada verso un'esca interna isolata quando evidenze, quorum e allowlist soddisfano la policy.",
    boundary: "Honeypot interno · routing reversibile",
  },
  phoenix: {
    phase: "RIPRISTINA",
    description:
      "Convalida copie pulite e orchestra il recupero controllato del servizio dopo il contenimento.",
    boundary: "Snapshot firmati · recupero auditabile",
  },
};

const safeScenarios = [
  {
    id: "authentication-burst",
    label: "Authentication burst",
  },
  {
    id: "api-input-anomaly",
    label: "API input anomaly",
  },
  {
    id: "integrity-drift",
    label: "Integrity drift",
  },
  {
    id: "recovery-check",
    label: "Recovery check",
  },
] as const;

type ConnectionState =
  | "connecting"
  | "d1"
  | "memory_fallback"
  | "unavailable";

type ApprovalResolution = "approve_simulation" | "reject";

interface ApprovalOperation {
  decision: ApprovalResolution;
  idempotencyKey: string;
}

interface ApprovalBusyState {
  approvalId: string;
  decision: ApprovalResolution;
}

type PipelineTone = "complete" | "active" | "waiting";

interface PipelineStage {
  id: "detect" | "correlate" | "decide" | "approve" | "audit";
  label: string;
  detail: string;
  tone: PipelineTone;
}

interface AgentIntelligenceShape {
  level?: number;
  mission?: string;
  capabilities?: string[];
  stats?: {
    assessments?: number;
    consensusAlignment?: number;
    trust?: number;
  };
  assessment?: {
    verdict?: string;
    vote?: string;
    risk?: string;
    confidence?: number;
    trust?: number;
    rationale?: string;
    evidence?: string[];
    safeguards?: string[];
  } | null;
}

type IntelligenceAgent = AgentState & AgentIntelligenceShape;

interface CouncilShape {
  eventId?: string;
  consensus?: string;
  recommendation?: string;
  quorum?: { required?: number; received?: number; met?: boolean };
  agreement?: number;
  risk?: string;
  confidence?: number;
  votes?: {
    allowSimulation?: number;
    requiresApproval?: number;
    deny?: number;
  };
  explanation?: string[];
  dissentingAgents?: string[];
}

interface PendingApprovalShape {
  id: string;
  eventId?: string;
  scenarioId?: string;
  title?: string;
  severity?: string;
  requestedAction?: string;
  status?: string;
  policyVersion?: string;
  createdAt?: string;
  councilRecommendation?: string;
  explanation?: string;
  reviewMode?: "post_event" | "blocking_manual";
}

interface PolicyShape {
  id?: string;
  version?: string;
  fingerprint?: string;
  mode?: string;
  externalNetworkActions?: boolean;
  offensiveActions?: boolean;
  humanApprovalForHighImpact?: boolean;
  humanApprovalForRestore?: boolean;
}

type AutopilotOutcome =
  | "auto-contained"
  | "observed"
  | "denied"
  | "manual_review";

interface AutopilotShape {
  enabled: boolean;
  mode: "guarded_autopilot";
  availability: "event_driven";
  lastCycle: {
    outcome: AutopilotOutcome;
    cycleId: string;
    scenario: string;
    action: string;
    decidedAt: string;
  } | null;
  allowlist: string[];
  hardLimits: {
    stateOnly: true;
    labOnly: true;
    reversibleOnly: true;
    externalActions: false;
    offensiveActions: false;
    privilegedActions: false;
    networkExecution: false;
  };
  postReviewOnly: boolean;
}

interface ApprovalDecisionShape extends Record<string, unknown> {
  id: string;
  approvalId: string;
  eventId: string;
  decision: ApprovalResolution;
  scope: "state_only_lab_simulation";
  executedExternalAction: false;
  decidedAt: string;
}

type IntelligenceDashboard = DashboardState & {
  policy?: PolicyShape;
  council?: CouncilShape | null;
  pendingApprovalItems?: PendingApprovalShape[];
  recentApprovalDecisions?: ApprovalDecisionShape[];
  autopilot?: AutopilotShape;
};

const verdictLabels: Record<string, string> = {
  clear: "CLEAR",
  monitor: "MONITOR",
  contain_simulation: "CONTAIN LAB",
  hold_for_human: "SAFE HOLD",
  allow_simulation: "ALLOW LAB",
  requires_approval: "REVIEW",
  deny: "DENY",
};

const voteLabels: Record<string, string> = {
  allow_simulation: "ALLOW",
  requires_approval: "REVIEW",
  deny: "DENY",
};

const autopilotAllowlist = [
  "observe",
  "rate_limit_demo_session",
  "route_to_internal_decoy",
  "quarantine_demo_asset",
] as const;

const failClosedAutopilot: AutopilotShape = {
  enabled: false,
  mode: "guarded_autopilot",
  availability: "event_driven",
  lastCycle: null,
  allowlist: [],
  hardLimits: {
    stateOnly: true,
    labOnly: true,
    reversibleOnly: true,
    externalActions: false,
    offensiveActions: false,
    privilegedActions: false,
    networkExecution: false,
  },
  postReviewOnly: true,
};

const auditActions = [
  "observe",
  "tag_demo_session",
  "notify_operator",
  "rate_limit_demo_session",
  "route_to_internal_decoy",
  "quarantine_demo_asset",
  "restore_demo_snapshot",
] as const;

const auditDecisions = ["allow_simulation", "requires_approval", "deny"] as const;

const auditReasonCodes = [
  "LAB_OBSERVATION_ALLOWED",
  "SCOPED_REVERSIBLE_SIMULATION",
  "HUMAN_APPROVAL_REQUIRED",
  "HUMAN_APPROVAL_RECORDED",
  "HUMAN_REJECTION_RECORDED",
  "OUTSIDE_LAB_BOUNDARY",
  "ACTION_NOT_ALLOWLISTED",
  "INVALID_EVIDENCE",
  "COUNCIL_DENY_RECORDED",
  "COUNCIL_SAFETY_HOLD_RECORDED",
  "COUNCIL_CONFIDENCE_GATE_FAILED",
  "COUNCIL_HUMAN_APPROVAL_REQUIRED",
] as const;

function percentLabel(value: number) {
  return `${Math.round(Math.max(0, Math.min(100, value)))}%`;
}

function normalizeScore(value: unknown, fallback: number) {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const normalized = value <= 1 ? value * 100 : value;
  return Math.round(Math.max(0, Math.min(100, normalized)));
}

function safeScoreValue(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.min(100, value)
    : fallback;
}

function normalizeStringList(value: unknown, limit: number, itemLimit = 100) {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .slice(0, limit)
    .map((item) => sanitizePublicText(item, "Policy detail withheld", itemLimit));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAuditAction(
  value: unknown,
): value is DashboardState["audit"][number]["action"] {
  return (
    typeof value === "string" &&
    (auditActions as readonly string[]).includes(value)
  );
}

function isAuditDecision(
  value: unknown,
): value is DashboardState["audit"][number]["decision"] {
  return (
    typeof value === "string" &&
    (auditDecisions as readonly string[]).includes(value)
  );
}

function isAuditReasonCode(
  value: unknown,
): value is DashboardState["audit"][number]["reasonCode"] {
  return (
    typeof value === "string" &&
    (auditReasonCodes as readonly string[]).includes(value)
  );
}

function connectionFromPayload(payload: unknown): ConnectionState {
  if (!isRecord(payload)) return "unavailable";
  if (payload.persistence === "d1") return "d1";
  if (payload.persistence === "memory_fallback") return "memory_fallback";
  return "unavailable";
}

function sanitizePublicText(value: unknown, fallback: string, limit = 160) {
  if (typeof value !== "string") return fallback;

  return value
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[redacted]")
    .replace(
      /\b(token|password|secret|api[_-]?key)\b\s*[:=]\s*\S+/gi,
      "$1=[redacted]",
    )
    .replace(/[\r\n\t]+/g, " ")
    .trim()
    .slice(0, limit) || fallback;
}

function sanitizeAutonomyText(
  value: unknown,
  fallback: string,
  limit = 160,
) {
  const sanitized = sanitizePublicText(value, fallback, limit);
  const describesBlockingForAPerson =
    /(?:wait|await|pending|blocked|held|sospes|attend|fermat).{0,48}(?:human|operator|approval|operatore|approvazione)/i.test(
      sanitized,
    ) ||
    /(?:human|operator|approval|operatore|approvazione).{0,48}(?:required|pending|wait|necessari|attesa)/i.test(
      sanitized,
    );

  return describesBlockingForAPerson ? fallback : sanitized;
}

function normalizeAutopilot(value: unknown): AutopilotShape {
  if (!isRecord(value)) return failClosedAutopilot;

  const hardLimits = isRecord(value.hardLimits) ? value.hardLimits : {};
  const safeLimits =
    hardLimits.stateOnly === true &&
    hardLimits.labOnly === true &&
    hardLimits.reversibleOnly === true &&
    hardLimits.externalActions === false &&
    hardLimits.offensiveActions === false &&
    hardLimits.privilegedActions === false &&
    hardLimits.networkExecution === false;
  const suppliedAllowlist = Array.isArray(value.allowlist)
    ? value.allowlist.filter((item): item is string => typeof item === "string")
    : [];
  const suppliedAllowlistSet = new Set(suppliedAllowlist);
  const allowlistIsSafe =
    suppliedAllowlist.length === autopilotAllowlist.length &&
    suppliedAllowlistSet.size === autopilotAllowlist.length &&
    autopilotAllowlist.every((item) => suppliedAllowlistSet.has(item));
  const modeIsSafe =
    value.mode === "guarded_autopilot" &&
    value.availability === "event_driven";
  const enabled =
    value.enabled === true && safeLimits && allowlistIsSafe && modeIsSafe;
  const lastCycle = isRecord(value.lastCycle) ? value.lastCycle : null;
  const outcome = lastCycle?.outcome;
  const validOutcome =
    outcome === "auto-contained" ||
    outcome === "observed" ||
    outcome === "denied" ||
    outcome === "manual_review";

  return {
    enabled,
    mode: "guarded_autopilot",
    availability: "event_driven",
    lastCycle:
      enabled && lastCycle && validOutcome
        ? {
            outcome,
            cycleId: sanitizePublicText(lastCycle.cycleId, "cycle-withheld", 100),
            scenario: sanitizePublicText(lastCycle.scenario, "safe-lab", 48),
            action: sanitizePublicText(lastCycle.action, "observe", 48),
            decidedAt: sanitizePublicText(lastCycle.decidedAt, "—", 36),
          }
        : null,
    allowlist: enabled
      ? suppliedAllowlist.filter((item) =>
          (autopilotAllowlist as readonly string[]).includes(item),
        )
      : [],
    hardLimits: failClosedAutopilot.hardLimits,
    postReviewOnly: value.postReviewOnly === true,
  };
}

function normalizePolicy(
  value: unknown,
  fallback: PolicyShape | undefined,
): PolicyShape {
  const candidate = isRecord(value) ? value : {};
  return {
    id: sanitizePublicText(candidate.id, fallback?.id ?? "policy-guard", 42),
    version: sanitizePublicText(candidate.version, fallback?.version ?? "—", 18),
    fingerprint: sanitizePublicText(
      candidate.fingerprint,
      fallback?.fingerprint ?? "not-published",
      40,
    ),
    mode: sanitizePublicText(
      candidate.mode,
      fallback?.mode ?? "deterministic_policy_bound",
      44,
    ),
    externalNetworkActions:
      typeof candidate.externalNetworkActions === "boolean"
        ? candidate.externalNetworkActions
        : (fallback?.externalNetworkActions ?? false),
    offensiveActions:
      typeof candidate.offensiveActions === "boolean"
        ? candidate.offensiveActions
        : (fallback?.offensiveActions ?? false),
    humanApprovalForHighImpact:
      typeof candidate.humanApprovalForHighImpact === "boolean"
        ? candidate.humanApprovalForHighImpact
        : (fallback?.humanApprovalForHighImpact ?? false),
    humanApprovalForRestore:
      typeof candidate.humanApprovalForRestore === "boolean"
        ? candidate.humanApprovalForRestore
        : (fallback?.humanApprovalForRestore ?? true),
  };
}

function normalizeCouncil(value: unknown): CouncilShape | null {
  if (!isRecord(value)) return null;
  const quorum = isRecord(value.quorum) ? value.quorum : {};
  const votes = isRecord(value.votes) ? value.votes : {};
  const count = (candidate: unknown) =>
    typeof candidate === "number" && Number.isFinite(candidate)
      ? Math.max(0, Math.floor(candidate))
      : 0;

  return {
    eventId: sanitizePublicText(value.eventId, "cycle-unavailable", 80),
    consensus: sanitizePublicText(value.consensus, "standby", 32),
    recommendation: sanitizePublicText(
      value.recommendation,
      "observe",
      48,
    ),
    quorum: {
      required: count(quorum.required),
      received: count(quorum.received),
      met: quorum.met === true,
    },
    agreement: safeScoreValue(value.agreement, 0),
    risk: sanitizePublicText(value.risk, "none", 16).toLowerCase(),
    confidence: safeScoreValue(value.confidence, 0),
    votes: {
      allowSimulation: count(votes.allowSimulation),
      requiresApproval: count(votes.requiresApproval),
      deny: count(votes.deny),
    },
    explanation: normalizeStringList(value.explanation, 5, 150).map((item) =>
      sanitizeAutonomyText(
        item,
        "Il Policy Guard mantiene il safe hold mentre l'autopilot continua a proteggere il laboratorio.",
        150,
      ),
    ),
    dissentingAgents: normalizeStringList(value.dissentingAgents, 5, 34),
  };
}

function normalizePendingApprovals(value: unknown): PendingApprovalShape[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter(isRecord)
    .slice(0, 6)
    .map((item, index) => ({
      id: sanitizePublicText(item.id, `approval-${index}`, 80),
      eventId: sanitizePublicText(item.eventId, "event-withheld", 80),
      scenarioId: sanitizePublicText(item.scenarioId, "safe-lab", 48),
      title: sanitizePublicText(item.title, "Human review required", 100),
      severity: sanitizePublicText(item.severity, "high", 16).toLowerCase(),
      requestedAction: sanitizePublicText(
        item.requestedAction,
        "state_only_review",
        48,
      ),
      status: item.status === "pending" ? "pending" : "pending",
      policyVersion: sanitizePublicText(item.policyVersion, "—", 18),
      createdAt: sanitizePublicText(item.createdAt, "—", 36),
      councilRecommendation: sanitizePublicText(
        item.councilRecommendation,
        "requires_approval",
        48,
      ),
      explanation: sanitizeAutonomyText(
        item.explanation,
        "Safe hold state-only registrato. L'autopilot resta attivo; questa revisione può essere completata in seguito.",
        180,
      ),
      reviewMode:
        item.reviewMode === "blocking_manual" ||
        item.requestedAction === "restore_demo_snapshot"
          ? "blocking_manual"
          : "post_event",
    }));
}

function normalizeApprovalDecisions(value: unknown): ApprovalDecisionShape[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter(isRecord)
    .slice(0, 20)
    .flatMap((item, index) => {
      if (
        item.decision !== "approve_simulation" &&
        item.decision !== "reject"
      ) {
        return [];
      }
      if (
        item.scope !== "state_only_lab_simulation" ||
        item.executedExternalAction !== false
      ) {
        return [];
      }

      return [
        {
          id: sanitizePublicText(item.id, `decision-${index}`, 120),
          approvalId: sanitizePublicText(
            item.approvalId,
            `approval-${index}`,
            120,
          ),
          eventId: sanitizePublicText(item.eventId, "event-withheld", 120),
          decision: item.decision,
          scope: "state_only_lab_simulation" as const,
          executedExternalAction: false as const,
          decidedAt: sanitizePublicText(item.decidedAt, "—", 36),
        },
      ];
    });
}

function normalizeAudit(value: unknown): DashboardState["audit"] {
  if (!Array.isArray(value)) return [];
  return value
    .filter(isRecord)
    .slice(0, 100)
    .flatMap((item, index) => {
      if (
        !isAuditAction(item.action) ||
        !isAuditDecision(item.decision) ||
        !isAuditReasonCode(item.reasonCode)
      ) {
        return [];
      }
      return [
        {
          eventId: sanitizePublicText(
            item.eventId,
            `audit-event-${index}`,
            120,
          ),
          action: item.action,
          decision: item.decision,
          reasonCode: item.reasonCode,
        },
      ];
    });
}

function normalizePublicSnapshot(
  payload: unknown,
  fallback: DashboardState,
): DashboardState | null {
  let candidate: unknown = payload;

  for (let depth = 0; depth < 3 && isRecord(candidate); depth += 1) {
    if (isRecord(candidate.metrics)) break;
    candidate =
      candidate.snapshot ??
      candidate.state ??
      candidate.dashboard ??
      candidate.data;
  }

  if (!isRecord(candidate) || !isRecord(candidate.metrics)) return null;
  const snapshot = candidate;
  const metrics = candidate.metrics;

  const metricValue = (key: string, defaultValue: number) => {
    const value = metrics[key];
    return typeof value === "number" && Number.isFinite(value) && value >= 0
      ? Math.floor(value)
      : defaultValue;
  };

  const status =
    snapshot.status === "protected" ||
    snapshot.status === "attention" ||
    snapshot.status === "review"
      ? snapshot.status
      : fallback.status;

  const incomingAgents = Array.isArray(snapshot.agents)
    ? snapshot.agents.filter(isRecord)
    : [];
  const incomingTimeline = Array.isArray(snapshot.timeline)
    ? snapshot.timeline.filter(isRecord)
    : [];
  const incomingResearchers = Array.isArray(snapshot.researchers)
    ? snapshot.researchers.filter(isRecord)
    : [];
  const fallbackIntelligence = fallback as IntelligenceDashboard;

  return {
    ...fallback,
    revision:
      typeof snapshot.revision === "number" &&
      Number.isFinite(snapshot.revision) &&
      snapshot.revision >= 0
        ? Math.floor(snapshot.revision)
        : fallback.revision,
    status,
    metrics: {
      detected: metricValue("detected", fallback.metrics.detected),
      mitigated: metricValue("mitigated", fallback.metrics.mitigated),
      criticalBreaches: metricValue(
        "criticalBreaches",
        fallback.metrics.criticalBreaches,
      ),
      pendingApprovals: metricValue(
        "pendingApprovals",
        fallback.metrics.pendingApprovals,
      ),
    },
    agents: (Array.isArray(snapshot.agents)
      ? fallback.agents.filter((agent) =>
          incomingAgents.some((item) => item.id === agent.id),
        )
      : fallback.agents
    ).map((agent) => {
      const incoming = incomingAgents.find((item) => item.id === agent.id);
      const fallbackAgent = agent as IntelligenceAgent;
      const incomingStats = isRecord(incoming?.stats) ? incoming.stats : {};
      const incomingAssessment = isRecord(incoming?.assessment)
        ? incoming.assessment
        : null;
      const vote =
        incomingAssessment?.vote === "allow_simulation" ||
        incomingAssessment?.vote === "requires_approval" ||
        incomingAssessment?.vote === "deny"
          ? incomingAssessment.vote
          : "requires_approval";
      const verdict =
        incomingAssessment?.verdict === "clear" ||
        incomingAssessment?.verdict === "monitor" ||
        incomingAssessment?.verdict === "contain_simulation" ||
        incomingAssessment?.verdict === "hold_for_human"
          ? incomingAssessment.verdict
          : "hold_for_human";
      const risk =
        incomingAssessment?.risk === "low" ||
        incomingAssessment?.risk === "medium" ||
        incomingAssessment?.risk === "high" ||
        incomingAssessment?.risk === "critical"
          ? incomingAssessment.risk
          : "low";
      return {
        ...agent,
        status:
          incoming?.status === "engaged" || incoming?.status === "ready"
            ? incoming.status
            : agent.status,
        lastAction: sanitizeAutonomyText(
          incoming?.lastAction,
          agent.lastAction,
          110,
        ),
        level:
          typeof incoming?.level === "number" && Number.isFinite(incoming.level)
            ? Math.max(1, Math.floor(incoming.level))
            : (fallbackAgent.level ?? 1),
        mission: sanitizePublicText(
          incoming?.mission,
          fallbackAgent.mission ?? agent.role,
          110,
        ),
        capabilities: Array.isArray(incoming?.capabilities)
          ? normalizeStringList(incoming.capabilities, 6, 48)
          : (fallbackAgent.capabilities ?? []),
        stats: {
          assessments:
            typeof incomingStats.assessments === "number" &&
            Number.isFinite(incomingStats.assessments)
              ? Math.max(0, Math.floor(incomingStats.assessments))
              : (fallbackAgent.stats?.assessments ?? 0),
          consensusAlignment: safeScoreValue(
            incomingStats.consensusAlignment,
            fallbackAgent.stats?.consensusAlignment ?? 0,
          ),
          trust: safeScoreValue(
            incomingStats.trust,
            fallbackAgent.stats?.trust ?? 0,
          ),
        },
        assessment: incomingAssessment
          ? {
              verdict,
              vote,
              risk,
              confidence: safeScoreValue(incomingAssessment.confidence, 0),
              trust: safeScoreValue(incomingAssessment.trust, 0),
              rationale: sanitizeAutonomyText(
                incomingAssessment.rationale,
                "Safe hold applicato; l'autopilot continua entro i limiti della policy.",
                170,
              ),
              evidence: normalizeStringList(
                incomingAssessment.evidence,
                6,
                110,
              ),
              safeguards: normalizeStringList(
                incomingAssessment.safeguards,
                6,
                110,
              ),
            }
          : (fallbackAgent.assessment ?? null),
      } as AgentState;
    }),
    timeline: Array.isArray(snapshot.timeline)
      ? incomingTimeline.slice(0, 4).map((event, index) => {
            const severity: Severity =
              event.severity === "info" ||
              event.severity === "low" ||
              event.severity === "medium" ||
              event.severity === "high" ||
              event.severity === "critical"
                ? event.severity
                : "info";
            return {
              id: sanitizePublicText(event.id, `public-event-${index}`, 80),
              time: sanitizePublicText(event.time, "--:--:--", 12),
              title: sanitizePublicText(
                event.title,
                "Sanitized security event",
                90,
              ),
              detail: sanitizeAutonomyText(
                event.detail,
                "Safe hold registrato; la protezione autonoma resta attiva entro la policy.",
                170,
              ),
              severity,
            };
          })
      : fallback.timeline,
    researchers: Array.isArray(snapshot.researchers)
      ? incomingResearchers.slice(0, 8).map((researcher, index) => ({
            alias: sanitizePublicText(
              researcher.alias,
              `Researcher ${index + 1}`,
              32,
            ),
            country: sanitizePublicText(researcher.country, "--", 3),
            findings:
              typeof researcher.findings === "number" &&
              Number.isFinite(researcher.findings) &&
              researcher.findings >= 0
                ? Math.floor(researcher.findings)
                : 0,
          }))
      : fallback.researchers,
    audit: Array.isArray(snapshot.audit)
      ? normalizeAudit(snapshot.audit)
      : fallback.audit,
    policy: normalizePolicy(snapshot.policy, fallbackIntelligence.policy),
    council: normalizeCouncil(snapshot.council),
    pendingApprovalItems: normalizePendingApprovals(
      snapshot.pendingApprovalItems,
    ),
    recentApprovalDecisions: Array.isArray(snapshot.recentApprovalDecisions)
      ? normalizeApprovalDecisions(snapshot.recentApprovalDecisions)
      : normalizeApprovalDecisions(
          fallbackIntelligence.recentApprovalDecisions ?? [],
        ),
    autopilot: normalizeAutopilot(snapshot.autopilot),
  } as DashboardState;
}

const mapPoints = [
  { left: "17%", top: "35%", delay: "0s" },
  { left: "29%", top: "62%", delay: ".7s" },
  { left: "46%", top: "29%", delay: "1.3s" },
  { left: "57%", top: "53%", delay: ".2s" },
  { left: "72%", top: "38%", delay: "1.7s" },
  { left: "82%", top: "65%", delay: ".9s" },
];

function MetricCard({
  eyebrow,
  value,
  note,
  tone = "blue",
}: {
  eyebrow: string;
  value: string;
  note: string;
  tone?: "blue" | "green" | "violet" | "amber" | "red";
}) {
  return (
    <article className={`metric-card metric-${tone}`}>
      <div className="metric-topline">
        <span>{eyebrow}</span>
        <span className="metric-spark" aria-hidden="true">
          <i />
          <i />
          <i />
          <i />
          <i />
        </span>
      </div>
      <strong>{value}</strong>
      <small>{note}</small>
    </article>
  );
}

function AgentRow({
  agent,
  verified,
}: {
  agent: AgentState;
  verified: boolean;
}) {
  const brief = agentBriefs[agent.id];
  const intelligence = agent as IntelligenceAgent;
  const assessment = intelligence.assessment;
  const trust = normalizeScore(
    assessment?.trust,
    normalizeScore(intelligence.stats?.trust, 0),
  );
  const confidence = assessment
    ? normalizeScore(assessment.confidence, 0)
    : null;
  const vote = assessment?.vote ?? "standby";
  const verdict = assessment?.verdict ?? "standby";
  const risk = assessment?.risk ?? "none";

  return (
    <article
      className={`agent-row agent-${verified ? agent.status : "verifying"}`}
      aria-label={`${agent.name}, ${verified ? agent.status : "in verifica"}`}
    >
      <div className="agent-mark" aria-hidden="true">
        {agentIcons[agent.id]}
      </div>
      <div className="agent-copy">
        <div className="agent-title-line">
          <strong>
            {agent.name}
            <small className="agent-level">
              L{intelligence.level ?? 1}
            </small>
          </strong>
          <span>
            {verified
              ? agent.status === "engaged"
                ? "ANALYZING"
                : "READY"
              : "VERIFYING"}
          </span>
        </div>
        <p>
          {brief.phase} · {agent.role}
        </p>
        <div className="agent-intelligence-line">
          <span className={`agent-vote vote-${vote}`}>
            {vote === "standby" ? "NO VOTE" : voteLabels[vote] ?? vote}
          </span>
          <span className="agent-verdict">
            {verdict === "standby"
              ? "STANDBY"
              : verdictLabels[verdict] ?? verdict}
          </span>
          <span className={`risk-label risk-${risk}`}>RISK {risk.toUpperCase()}</span>
          <span>TRUST {verified ? `${trust}%` : "—"}</span>
          <span>
            CONF {verified && confidence !== null ? `${confidence}%` : "—"}
          </span>
        </div>
        <div className="confidence-track" aria-hidden="true">
          <i style={{ width: verified ? `${confidence ?? trust}%` : "0%" }} />
        </div>
        <small className="agent-rationale">
          {verified
            ? sanitizeAutonomyText(
                assessment?.rationale,
                agent.lastAction,
                135,
              )
            : "Verifica dello snapshot operativo in corso"}
        </small>
      </div>
    </article>
  );
}

function buildPipeline(
  state: DashboardState,
  autopilot: AutopilotShape,
): PipelineStage[] {
  const hasCycle = state.revision > 0;
  const lastOutcome = autopilot.lastCycle?.outcome;
  const autoContained = lastOutcome === "auto-contained";
  const safelyDenied = lastOutcome === "denied" || lastOutcome === "manual_review";

  return [
    {
      id: "detect",
      label: "RILEVA",
      detail: hasCycle ? "Evento acquisito" : "Ingresso eventi pronto",
      tone: hasCycle ? "complete" : "active",
    },
    {
      id: "correlate",
      label: "CORRELA",
      detail: hasCycle ? "Evidenze incrociate" : "In attesa di evento",
      tone: hasCycle ? "complete" : "waiting",
    },
    {
      id: "decide",
      label: "DECIDE",
      detail: hasCycle ? "Consiglio registrato" : "Nessuna decisione",
      tone: hasCycle ? "complete" : "waiting",
    },
    {
      id: "approve",
      label: "APPLICA",
      detail: autoContained
        ? "Contenimento automatico"
        : safelyDenied
          ? "Safe hold applicato"
          : hasCycle
            ? "Policy applicata"
            : "Guardrail pronto",
      tone: hasCycle ? "complete" : "waiting",
    },
    {
      id: "audit",
      label: "REVISIONA",
      detail: hasCycle ? "Post-action, non bloccante" : "Registro pronto",
      tone: hasCycle ? "complete" : "waiting",
    },
  ];
}

function memoryLabel(connection: ConnectionState) {
  if (connection === "d1") return "DURABLE / CONNECTED";
  if (connection === "memory_fallback") return "EPHEMERAL / SAFE";
  if (connection === "connecting") return "VERIFYING";
  return "UNAVAILABLE / FAILED CLOSED";
}

export default function Home() {
  const [state, setState] = useState<DashboardState>(() =>
    createInitialDemoState(),
  );
  const stateRef = useRef(state);
  const mutationInFlightRef = useRef(false);
  const hydrationInFlightRef = useRef(false);
  const hydrationControllerRef = useRef<AbortController | null>(null);
  const scenarioIdempotencyKeysRef = useRef(new Map<string, string>());
  const [isLive, setIsLive] = useState(true);
  const [hasVerifiedSnapshot, setHasVerifiedSnapshot] = useState(false);
  const [connection, setConnection] =
    useState<ConnectionState>("connecting");
  const [selectedScenario, setSelectedScenario] = useState<string>(
    safeScenarios[0].id,
  );
  const [isSimulating, setIsSimulating] = useState(false);
  const [approvalBusy, setApprovalBusy] =
    useState<ApprovalBusyState | null>(null);
  const [approvalOperations, setApprovalOperations] = useState<
    Record<string, ApprovalOperation>
  >({});
  const [operatorNotice, setOperatorNotice] = useState(
    "Autopilot attivo: la revisione umana è post-azione e non blocca la protezione.",
  );
  const [secondsRemaining, setSecondsRemaining] = useState(
    3 * 24 * 60 * 60 + 14 * 60 * 60 + 22 * 60 + 8,
  );

  const clearApprovalOperation = useCallback((approvalId: string) => {
    setApprovalOperations((previous) => {
      if (!(approvalId in previous)) return previous;
      const next = { ...previous };
      delete next[approvalId];
      return next;
    });
  }, []);

  const applySnapshot = useCallback((snapshot: DashboardState) => {
    if (snapshot.revision < stateRef.current.revision) return false;

    stateRef.current = snapshot;
    setState(snapshot);
    const pendingIds = new Set(
      ((snapshot as IntelligenceDashboard).pendingApprovalItems ?? []).map(
        ({ id }) => id,
      ),
    );
    setApprovalOperations((previous) => {
      const entries = Object.entries(previous).filter(([id]) =>
        pendingIds.has(id),
      );
      return entries.length === Object.keys(previous).length
        ? previous
        : Object.fromEntries(entries);
    });
    return true;
  }, []);

  const hydrateFromApi = useCallback(async () => {
    if (hydrationInFlightRef.current) {
      return { ok: false as const, snapshot: null };
    }

    hydrationInFlightRef.current = true;
    const controller = new AbortController();
    hydrationControllerRef.current = controller;
    let timedOut = false;
    const timeout = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 4500);

    try {
      const response = await fetch("/api/security", {
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error("Public snapshot unavailable");

      const payload: unknown = await response.json();
      const normalized = normalizePublicSnapshot(
        payload,
        stateRef.current,
      );
      if (!normalized) throw new Error("Invalid public snapshot");

      applySnapshot(normalized);
      setConnection(connectionFromPayload(payload));
      setHasVerifiedSnapshot(true);
      return { ok: true as const, snapshot: stateRef.current };
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        if (timedOut) setConnection("unavailable");
        return { ok: false as const, snapshot: null };
      }
      setConnection("unavailable");
      return { ok: false as const, snapshot: null };
    } finally {
      window.clearTimeout(timeout);
      if (hydrationControllerRef.current === controller) {
        hydrationControllerRef.current = null;
      }
      hydrationInFlightRef.current = false;
    }
  }, [applySnapshot]);

  useEffect(() => {
    const kickoff = window.setTimeout(() => {
      void hydrateFromApi();
    }, 0);
    return () => {
      window.clearTimeout(kickoff);
      hydrationControllerRef.current?.abort();
    };
  }, [hydrateFromApi]);

  useEffect(() => {
    if (!isLive) return;

    const timer = window.setInterval(async () => {
      if (mutationInFlightRef.current) return;
      await hydrateFromApi();
    }, 6000);

    return () => window.clearInterval(timer);
  }, [hydrateFromApi, isLive]);

  useEffect(() => {
    if (!isLive) return;
    const timer = window.setInterval(() => {
      setSecondsRemaining((value) => Math.max(0, value - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [isLive]);

  const simulateSafeEvent = useCallback(async () => {
    if (isSimulating || approvalBusy || mutationInFlightRef.current) return;
    const scenario = selectedScenario;
    let idempotencyKey = scenarioIdempotencyKeysRef.current.get(scenario);
    if (!idempotencyKey) {
      idempotencyKey = `scenario:${crypto.randomUUID()}`;
      scenarioIdempotencyKeysRef.current.set(scenario, idempotencyKey);
    }

    mutationInFlightRef.current = true;
    setIsSimulating(true);
    setOperatorNotice("Registrazione idempotente dello scenario sicuro in corso…");

    try {
      const response = await fetch("/api/security", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
        },
        body: JSON.stringify({ scenario }),
      });
      if (!response.ok) {
        if (response.status === 409 || response.status >= 500) {
          await hydrateFromApi();
        }
        if (response.status === 409 || response.status < 500) {
          scenarioIdempotencyKeysRef.current.delete(scenario);
        }
        setOperatorNotice(
          response.status >= 500
            ? "Esito non confermato: lo snapshot è stato riletto. Ripeti lo stesso scenario per un retry idempotente; nessuna azione esterna è stata eseguita."
            : response.status === 409
              ? "Conflitto idempotente verificato: lo snapshot è stato riletto e nessuna nuova azione è stata eseguita."
              : "Scenario rifiutato dall'API: lo stato resta invariato e nessuna azione è stata eseguita.",
        );
        return;
      }

      const payload: unknown = await response.json();
      const normalized = normalizePublicSnapshot(payload, stateRef.current);
      if (!normalized) throw new Error("Invalid public simulation response");

      applySnapshot(normalized);
      setConnection(connectionFromPayload(payload));
      scenarioIdempotencyKeysRef.current.delete(scenario);
      setOperatorNotice(
        connectionFromPayload(payload) === "d1"
          ? "Scenario registrato nella memoria durevole del laboratorio."
          : "Scenario registrato nella memoria temporanea del laboratorio; non è persistente.",
      );
      const scenarioIndex = safeScenarios.findIndex(
        (candidate) => candidate.id === scenario,
      );
      setSelectedScenario(
        safeScenarios[(scenarioIndex + 1) % safeScenarios.length].id,
      );
    } catch {
      await hydrateFromApi();
      setOperatorNotice(
        "Esito non confermato: lo snapshot è stato riletto. Ripeti lo stesso scenario per un retry idempotente; nessuna azione esterna è stata eseguita.",
      );
    } finally {
      setIsSimulating(false);
      mutationInFlightRef.current = false;
    }
  }, [applySnapshot, approvalBusy, hydrateFromApi, isSimulating, selectedScenario]);

  const resolveApproval = useCallback(
    async (approvalId: string, decision: ApprovalResolution) => {
      if (approvalBusy || isSimulating || mutationInFlightRef.current) return;
      const existingOperation = approvalOperations[approvalId];
      if (existingOperation && existingOperation.decision !== decision) {
        setOperatorNotice(
          "Esiste già un tentativo con esito non confermato: ripeti prima la stessa decisione per una verifica idempotente.",
        );
        return;
      }
      const operation =
        existingOperation ??
        ({
          decision,
          idempotencyKey: `approval:${crypto.randomUUID()}`,
        } satisfies ApprovalOperation);
      if (!existingOperation) {
        setApprovalOperations((previous) => ({
          ...previous,
          [approvalId]: operation,
        }));
      }

      mutationInFlightRef.current = true;
      setApprovalBusy({ approvalId, decision });
      setOperatorNotice("Registrazione della decisione state-only in corso…");

      try {
        const response = await fetch("/api/security/approvals", {
          method: "POST",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            "Idempotency-Key": operation.idempotencyKey,
          },
          body: JSON.stringify({
            approvalId,
            decision,
            confirmation: "STATE_ONLY_LAB",
          }),
        });
        if (!response.ok) {
          const needsReconciliation =
            response.status === 404 ||
            response.status === 409 ||
            response.status >= 500;
          const reconciliation = needsReconciliation
            ? await hydrateFromApi()
            : { ok: false as const, snapshot: null };
          const reconciledSnapshot = reconciliation.snapshot;
          const stillPending = reconciledSnapshot
            ? ((reconciledSnapshot as IntelligenceDashboard)
                .pendingApprovalItems ?? []
              ).some((item) => item.id === approvalId)
            : true;
          const recordedDecision = reconciledSnapshot
            ? ((reconciledSnapshot as IntelligenceDashboard)
                .recentApprovalDecisions ?? []
              ).find((item) => item.approvalId === approvalId)
            : undefined;

          if (!stillPending) {
            clearApprovalOperation(approvalId);
            setOperatorNotice(
              recordedDecision?.decision === "approve_simulation"
                ? "Decisione riconciliata: la simulazione state-only risulta approvata; nessuna azione esterna è stata eseguita."
                : recordedDecision?.decision === "reject"
                  ? "Decisione riconciliata: la proposta risulta rifiutata; nessuna azione è stata eseguita."
                  : "La proposta non è più in coda; lo snapshot corrente è stato riletto e nessuna azione esterna è stata eseguita.",
            );
          } else if (response.status === 409 || response.status < 500) {
            clearApprovalOperation(approvalId);
            setOperatorNotice(
              response.status === 409
                ? "Conflitto idempotente verificato: la coda è stata riletta e nessuna nuova decisione è stata registrata."
                : "Decisione rifiutata dall'API: la coda resta invariata e nessuna azione è stata eseguita.",
            );
          } else {
            setOperatorNotice(
              "Esito non confermato: la coda è stata riletta. Ripeti la stessa decisione per un retry idempotente; nessuna azione esterna è stata eseguita.",
            );
          }
          return;
        }

        const payload: unknown = await response.json();
        const normalized = normalizePublicSnapshot(payload, stateRef.current);
        if (!normalized) throw new Error("Invalid approval response");

        applySnapshot(normalized);
        setConnection(connectionFromPayload(payload));
        clearApprovalOperation(approvalId);
        setOperatorNotice(
          decision === "approve_simulation"
            ? "Simulazione state-only approvata e registrata. Nessuna azione esterna eseguita."
            : "Proposta rifiutata e registrata. Nessuna azione è stata eseguita.",
        );
      } catch {
        const reconciliation = await hydrateFromApi();
        const reconciledSnapshot = reconciliation.snapshot;
        const stillPending = reconciledSnapshot
          ? ((reconciledSnapshot as IntelligenceDashboard)
              .pendingApprovalItems ?? []
            ).some((item) => item.id === approvalId)
          : true;
        const recordedDecision = reconciledSnapshot
          ? ((reconciledSnapshot as IntelligenceDashboard)
              .recentApprovalDecisions ?? []
            ).find((item) => item.approvalId === approvalId)
          : undefined;
        if (!stillPending) {
          clearApprovalOperation(approvalId);
        }
        setOperatorNotice(
          !stillPending && recordedDecision?.decision === "approve_simulation"
            ? "Decisione riconciliata: la simulazione state-only risulta approvata; nessuna azione esterna è stata eseguita."
            : !stillPending && recordedDecision?.decision === "reject"
              ? "Decisione riconciliata: la proposta risulta rifiutata; nessuna azione è stata eseguita."
              : "Esito non confermato: la coda è stata riletta. Ripeti la stessa decisione per un retry idempotente; nessuna azione esterna è stata eseguita.",
        );
      } finally {
        setApprovalBusy(null);
        mutationInFlightRef.current = false;
      }
    },
    [
      applySnapshot,
      approvalBusy,
      approvalOperations,
      clearApprovalOperation,
      hydrateFromApi,
      isSimulating,
    ],
  );

  const countdown = useMemo(() => {
    const days = Math.floor(secondsRemaining / 86400);
    const hours = Math.floor((secondsRemaining % 86400) / 3600);
    const minutes = Math.floor((secondsRemaining % 3600) / 60);
    const seconds = secondsRemaining % 60;
    return `${String(days).padStart(2, "0")}D · ${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  }, [secondsRemaining]);

  const intelligenceDashboard = state as IntelligenceDashboard;
  const council = intelligenceDashboard.council ?? null;
  const policy = intelligenceDashboard.policy;
  const approvalItems = intelligenceDashboard.pendingApprovalItems ?? [];
  const pendingApprovalTotal = state.metrics.pendingApprovals;
  const blockingManualTotal = approvalItems.filter(
    (item) => item.reviewMode === "blocking_manual",
  ).length;
  const approvalDecisions =
    intelligenceDashboard.recentApprovalDecisions ?? [];
  const autopilot = intelligenceDashboard.autopilot ?? failClosedAutopilot;
  const autopilotActive =
    hasVerifiedSnapshot &&
    connection === "d1" &&
    autopilot.enabled &&
    state.agents.length === 5;
  const autopilotStatus = !hasVerifiedSnapshot && connection !== "unavailable"
    ? "VERIFYING"
    : !autopilotActive
      ? "DENIED"
    : autopilot.lastCycle?.outcome === "auto-contained"
      ? "AUTO-CONTAINED"
      : autopilot.lastCycle?.outcome === "denied"
        ? "DENIED"
        : autopilot.lastCycle?.outcome === "manual_review"
          ? "SAFE-HOLD"
          : "OBSERVING";
  const pipeline = useMemo(
    () => buildPipeline(state, autopilot),
    [autopilot, state],
  );
  const evidence = useMemo(() => {
    const items = state.agents.flatMap((agent) => {
      const assessment = (agent as IntelligenceAgent).assessment;
      return assessment?.evidence ?? [];
    });
    return [...new Set(items)].slice(0, 4);
  }, [state.agents]);
  const safeguards = useMemo(() => {
    const items = state.agents.flatMap((agent) => {
      const assessment = (agent as IntelligenceAgent).assessment;
      return assessment?.safeguards ?? [];
    });
    return [...new Set(items)].slice(0, 4);
  }, [state.agents]);
  const agreement = council ? normalizeScore(council.agreement, 0) : null;
  const councilConfidence = council
    ? normalizeScore(council.confidence, 0)
    : null;
  const quorumRequired = council?.quorum?.required ?? 0;
  const quorumReceived = council?.quorum?.received ?? 0;
  const councilRisk = council?.risk ?? "none";
  const councilApproval = council?.eventId
    ? approvalItems.find((item) => item.eventId === council.eventId)
    : undefined;
  const councilDecision = council?.eventId
    ? approvalDecisions.find((item) => item.eventId === council.eventId)
    : undefined;
  const councilAudit = council?.eventId
    ? state.audit.find((item) => item.eventId === council.eventId)
    : undefined;
  const proposal =
    councilApproval?.requestedAction ??
    councilAudit?.action ??
    autopilot.lastCycle?.action ??
    council?.recommendation;
  const executionLabel = !hasVerifiedSnapshot
    ? "NOT VERIFIED"
    : !autopilotActive
      ? "DENIED / FAIL-CLOSED"
      : autopilot.lastCycle?.outcome === "auto-contained"
        ? autopilot.lastCycle.action.toUpperCase()
        : autopilot.lastCycle?.outcome === "observed"
          ? "OBSERVE / READ-ONLY"
          : autopilot.lastCycle?.outcome === "denied"
            ? "DENIED / NO ACTION"
            : autopilot.lastCycle?.outcome === "manual_review"
              ? "SAFE HOLD / NO REQUESTED ACTION"
              : councilDecision?.decision === "approve_simulation"
                ? "STATE-ONLY LAB"
                : "OBSERVE / ARMED";

  const statusLabel =
    connection === "unavailable"
      ? "AUTOPILOT FAILED CLOSED"
      : connection === "connecting"
        ? "VERIFYING GUARDED AUTOPILOT"
        : autopilotStatus === "AUTO-CONTAINED"
          ? "THREAT AUTO-CONTAINED"
          : autopilotStatus === "DENIED"
            ? "UNSAFE ACTION DENIED"
            : autopilotStatus === "SAFE-HOLD"
              ? "SAFE HOLD ACTIVE"
              : "AUTOPILOT ARMED";

  return (
    <main
      className={`command-center status-${state.status} connection-${connection} autopilot-${autopilotStatus.toLowerCase()}`}
      aria-busy={!hasVerifiedSnapshot || connection === "connecting"}
    >
      <div className="ambient-grid" aria-hidden="true" />

      <header className="command-header">
        <div className="brand-lockup">
          <span className="brand-glyph" aria-hidden="true">
            K
          </span>
          <div>
            <p>KRELUNA CYBER</p>
            <h1>THE VAULT CHALLENGE</h1>
          </div>
        </div>

        <div className="challenge-clock" aria-label="Tempo restante nella demo">
          <span>CHALLENGE REMAINING</span>
          <strong>{countdown}</strong>
        </div>

        <button
          className={`live-toggle ${isLive ? "is-live" : ""}`}
          type="button"
          onClick={() => setIsLive((value) => !value)}
          aria-pressed={isLive}
          aria-label={`${isLive ? "Sospendi" : "Riprendi"} soltanto l'aggiornamento visivo della dashboard; l'autopilot resta operativo`}
        >
          <span aria-hidden="true" />
          {isLive
            ? connection === "unavailable"
              ? "RETRYING"
              : "AUTO REFRESH"
            : "VIEW PAUSED"}
        </button>
      </header>

      <section className="demo-notice" aria-label="Avviso modalità dimostrativa">
        <span>SIMULATION MODE · STATE-ONLY LAB</span>
        <p>
          5 moduli deterministici · consensus policy-bound · dati pubblici
          sanitizzati
        </p>
        <strong>NO OFFENSIVE OR EXTERNAL ACTIONS · NO NETWORK EXECUTION</strong>
      </section>

      <section
        className="autopilot-banner glass-panel"
        aria-labelledby="autopilot-title"
      >
        <div className="autopilot-identity">
          <span className="autopilot-pulse" aria-hidden="true" />
          <div>
            <span>GUARDED AUTONOMY / V0.4</span>
            <h2 id="autopilot-title">AUTOPILOT 24/7 · LAB PROTOTYPE</h2>
            <p>
              Quando riceve un evento di laboratorio, decide senza attendere un
              operatore. Il collegamento ai sensori live è la fase successiva.
            </p>
          </div>
        </div>

        <dl className="autopilot-facts">
          <div>
            <dt>RUNTIME</dt>
            <dd>EVENT-DRIVEN LAB</dd>
          </div>
          <div>
            <dt>COUNCIL</dt>
            <dd>{hasVerifiedSnapshot ? `${state.agents.length}/5 AGENTI` : "VERIFYING"}</dd>
          </div>
          <div>
            <dt>BOUNDARY</dt>
            <dd>POLICY-BOUND</dd>
          </div>
          <div>
            <dt>HUMAN ROLE</dt>
            <dd>
              {blockingManualTotal > 0
                ? "RESTORE APPROVAL ONLY"
                : "POST-ACTION REVIEW"}
            </dd>
          </div>
        </dl>

        <div
          className={`autopilot-outcome outcome-${autopilotStatus.toLowerCase()}`}
          role="status"
          aria-live="polite"
        >
          <span>CURRENT STATE</span>
          <strong>{autopilotStatus}</strong>
          <small>
            {autopilotActive
                ? autopilot.lastCycle
                  ? `ULTIMA AZIONE · ${executionLabel}`
                : "ARMED · IN ATTESA DI EVENTI LAB"
              : hasVerifiedSnapshot
                ? "SAFE DENY · LIMITI NON VERIFICATI"
                : "SNAPSHOT IN VERIFICA"}
          </small>
        </div>
      </section>

      <section className="operations-grid">
        <aside className="surface-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>01 / SYNTHETIC TELEMETRY</span>
              <h2>LAB SIGNAL MAP</h2>
            </div>
            <i
              className={`status-light ${
                connection === "unavailable"
                  ? "is-error"
                  : connection === "connecting"
                    ? "is-pending"
                    : ""
              }`}
              role="status"
              aria-label={
                connection === "unavailable"
                  ? "API della telemetria non disponibile"
                  : connection === "connecting"
                    ? "Verifica della telemetria in corso"
                    : "Ingresso eventi sintetici verificato"
              }
            />
          </div>

          <div
            className="radar-map"
            role="img"
            aria-label="Distribuzione sintetica degli eventi demo"
          >
            <div className="radar-sweep" aria-hidden="true" />
            <div className="radar-axis radar-axis-x" aria-hidden="true" />
            <div className="radar-axis radar-axis-y" aria-hidden="true" />
            {mapPoints.map((point, index) => (
              <span
                key={`${point.left}-${point.top}`}
                className={`map-point point-${(index % 3) + 1}`}
                style={{
                  left: point.left,
                  top: point.top,
                  animationDelay: point.delay,
                }}
                aria-hidden="true"
              />
            ))}
            <div className="radar-center" aria-hidden="true">
              <span>K</span>
            </div>
          </div>

          <div
            className="signal-bars"
            role="img"
            aria-label="Volume sintetico delle finestre demo"
          >
            {[31, 56, 42, 78, 63, 91, 67, 84, 52, 73, 95, 62].map(
              (height, index) => (
                <i
                  key={`${height}-${index}`}
                  style={{ height: `${height}%` }}
                  aria-hidden="true"
                />
              ),
            )}
          </div>

          <dl className="surface-stats">
            <div>
              <dt>Safe scenarios</dt>
              <dd>{safeScenarios.length}</dd>
            </div>
            <div>
              <dt>Defensive agents</dt>
              <dd>{state.agents.length}</dd>
            </div>
            <div>
              <dt>Dashboard refresh</dt>
              <dd>{isLive ? "6 sec" : "VIEW PAUSED"}</dd>
            </div>
          </dl>
        </aside>

        <section className="vault-panel glass-panel" aria-labelledby="vault-title">
          <div className="vault-header">
            <span>CORE ASSET / TV-01</span>
            <span>SAFE BOUNDARY ON</span>
          </div>

          <div className="vault-stage">
            <div className="vault-floor-shadow" aria-hidden="true" />
            <div
              className="bank-vault"
              role="img"
              aria-label="THE VAULT, server della challenge isolato TV-01"
            >
              <div className="vault-hinge vault-hinge-top" aria-hidden="true">
                <i />
                <span />
              </div>
              <div className="vault-hinge vault-hinge-bottom" aria-hidden="true">
                <i />
                <span />
              </div>
              <div className="vault-outer-rim">
                <div className="vault-bolts" aria-hidden="true">
                  {Array.from({ length: 12 }, (_, index) => (
                    <i key={index} />
                  ))}
                </div>
                <div className="vault-door">
                  <div className="vault-door-groove" aria-hidden="true" />
                  <div className="vault-plaque">
                    <small>KRELUNA SECURE CORE</small>
                    <strong>THE VAULT</strong>
                    <span>ISOLATED CHALLENGE SERVER</span>
                  </div>
                  <div className="locking-wheel" aria-hidden="true">
                    {Array.from({ length: 6 }, (_, index) => (
                      <i className={`wheel-spoke spoke-${index + 1}`} key={index} />
                    ))}
                    <span className="wheel-hub"><i /></span>
                  </div>
                  <div className="vault-serial">
                    <span>ASSET</span>
                    <strong>TV-01</strong>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="vault-status-copy">
            <span className="status-kicker">POLICY-BOUND DEFENSE MESH</span>
            <h2 id="vault-title">{statusLabel}</h2>
            <p>
              {connection === "unavailable"
                ? "La console pubblica non è verificabile: il motore nega ogni nuova azione e conserva l'ultimo snapshot noto."
                : connection === "connecting"
                  ? "Verifica dei limiti e della memoria privata prima di mostrare uno stato operativo."
                  : autopilotStatus === "AUTO-CONTAINED"
                    ? "Il consiglio 5/5 ha applicato un contenimento state-only reversibile. La traccia è disponibile per la revisione successiva."
                    : autopilotStatus === "DENIED"
                      ? "Il Policy Guard ha negato l'azione non conforme. I vincoli restano pronti per il prossimo evento di laboratorio."
                      : autopilotStatus === "SAFE-HOLD"
                        ? "Il Policy Guard mantiene il laboratorio in safe hold. Le decisioni allowlisted restano autonome quando arrivano nuovi eventi; nessuna azione richiesta è stata eseguita."
                        : "Autopilot armato: quando l'API riceve un evento lab autenticato, decide senza attendere un operatore."}
            </p>
          </div>

          <div className="vault-actions">
            <label className="scenario-picker">
              <span>SAFE SCENARIO</span>
              <select
                value={selectedScenario}
                onChange={(event) => setSelectedScenario(event.target.value)}
                disabled={isSimulating || approvalBusy !== null}
              >
                {safeScenarios.map((scenario) => (
                  <option value={scenario.id} key={scenario.id}>
                    {scenario.label}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              onClick={() => void simulateSafeEvent()}
              disabled={
                isSimulating || approvalBusy !== null || connection !== "d1"
              }
            >
              <span aria-hidden="true">＋</span>
              {isSimulating
                ? "RUNNING SAFE TEST"
                : connection === "d1"
                  ? "SIMULATE SAFE EVENT"
                  : "DURABLE MEMORY REQUIRED"}
            </button>
            <div className="policy-state">
              <span>
                {connection === "d1"
                  ? "DURABLE SECURITY API"
                  : connection === "memory_fallback"
                    ? "TEMPORARY MEMORY"
                    : connection === "connecting"
                      ? "SECURITY API"
                      : "SECURITY API UNAVAILABLE"}
              </span>
              <strong>
                {connection === "connecting"
                  ? "CONNECTING"
                  : state.metrics.pendingApprovals > 0
                    ? `${state.metrics.pendingApprovals} POST-REVIEW OPEN`
                    : connection === "memory_fallback"
                      ? "NOT PERSISTED"
                      : connection === "unavailable"
                        ? "FAILED CLOSED"
                        : "POLICY ENFORCED"}
              </strong>
            </div>
          </div>
        </section>

        <section className="metrics-grid" aria-label="Metriche principali">
          <MetricCard
            eyebrow="LAB SECURITY EVENTS"
            value={hasVerifiedSnapshot ? state.metrics.detected.toLocaleString("en-US") : "—"}
            note="sanitized synthetic events"
          />
          <MetricCard
            eyebrow="AUTHORIZED LAB CYCLES"
            value={hasVerifiedSnapshot ? state.metrics.mitigated.toLocaleString("en-US") : "—"}
            note="state-only policy decisions"
            tone="violet"
          />
          <MetricCard
            eyebrow="POST-ACTION REVIEW"
            value={hasVerifiedSnapshot ? String(state.metrics.pendingApprovals) : "—"}
            note="non-blocking review records"
            tone={state.metrics.pendingApprovals > 0 ? "amber" : "green"}
          />
          <MetricCard
            eyebrow="EVENT MEMORY"
            value={
              connection === "d1"
                ? "DURABLE"
                : connection === "memory_fallback"
                  ? "TEMP"
                  : connection === "connecting"
                    ? "CHECK"
                    : "ERROR"
            }
            note={
              connection === "d1"
                ? "saved to private event memory"
                : connection === "memory_fallback"
                  ? "ephemeral failsafe, not persisted"
                  : connection === "connecting"
                    ? "verifying event storage"
                    : "API unavailable; no state applied"
            }
            tone={
              connection === "d1"
                ? "green"
                : connection === "unavailable"
                  ? "red"
                  : "amber"
            }
          />
        </section>

        <aside className="agents-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>02 / DETERMINISTIC AGENTS</span>
              <h2>AGENT COUNCIL</h2>
            </div>
            <span className="agent-count">
              {state.agents.length}{" "}
              {connection === "unavailable"
                ? "MODULI IN STANDBY"
                : connection === "connecting"
                  ? "MODULI IN VERIFICA"
                  : "MODULI ATTIVI"}
            </span>
          </div>

          <div className="agent-list">
            {state.agents.map((agent) => (
              <AgentRow
                key={agent.id}
                agent={agent}
                verified={hasVerifiedSnapshot}
              />
            ))}
          </div>

          <div className="guardrail-card">
            <span>EXECUTION BOUNDARY</span>
            <strong>Agents assess. Policy authorizes or denies.</strong>
            <p>
              Guarded autonomy state-only · reversible allowlist · human review
              after the event, without pausing protection.
            </p>
          </div>
        </aside>
      </section>

      <section
        className="command-deck glass-panel"
        aria-labelledby="command-deck-title"
      >
        <div className="panel-heading command-deck-heading">
          <div>
            <span>03 / GUARDED AUTOPILOT</span>
            <h2 id="command-deck-title">COMMAND DECK</h2>
          </div>
          <div className="engine-badges" aria-label="Modalità del motore">
            <span>POLICY-BOUND</span>
            <span>EVENT-DRIVEN LAB</span>
            <span>HYBRID-READY</span>
            <span>STATE-ONLY</span>
          </div>
        </div>

        <div className="council-grid">
          <article className="council-card" aria-labelledby="consensus-title">
            <div className="subpanel-heading">
              <span>COUNCIL CONSENSUS</span>
              <i className={council?.quorum?.met ? "is-good" : "is-idle"}>
                {council?.quorum?.met ? "QUORUM MET" : "STANDBY"}
              </i>
            </div>

            <div
              className={`consensus-orb risk-${councilRisk}`}
              style={
                {
                  "--agreement": `${agreement ?? 0}%`,
                } as CSSProperties
              }
              role="progressbar"
              aria-labelledby="consensus-title"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={agreement ?? 0}
            >
              <span id="consensus-title">AGREEMENT</span>
              <strong>{agreement === null ? "—" : `${agreement}%`}</strong>
              <small>
                {council?.consensus?.toUpperCase() ?? "NO CYCLE YET"}
              </small>
            </div>

            <dl className="council-stats">
              <div>
                <dt>Quorum</dt>
                <dd>
                  {council ? `${quorumReceived} / ${quorumRequired}` : "—"}
                </dd>
              </div>
              <div>
                <dt>Bounded confidence</dt>
                <dd>
                  {councilConfidence === null
                    ? "—"
                    : percentLabel(councilConfidence)}
                </dd>
              </div>
              <div>
                <dt>Risk</dt>
                <dd className={`risk-text risk-${councilRisk}`}>
                  {councilRisk.toUpperCase()}
                </dd>
              </div>
              <div>
                <dt>Rule</dt>
                <dd>{quorumRequired > 0 ? `${quorumRequired}-of-5` : "ARMED"}</dd>
              </div>
            </dl>

            <div
              className="vote-tally"
              role="group"
              aria-label="Distribuzione dei voti"
            >
              <span>
                ALLOW <strong>{council?.votes?.allowSimulation ?? 0}</strong>
              </span>
              <span>
                HOLD <strong>{council?.votes?.requiresApproval ?? 0}</strong>
              </span>
              <span>
                DENY <strong>{council?.votes?.deny ?? 0}</strong>
              </span>
            </div>
          </article>

          <article className="decision-card" aria-labelledby="decision-title">
            <div className="subpanel-heading">
              <span id="decision-title">EXPLAINED DECISION</span>
              <i>{council ? "RECORDED CYCLE" : "WAITING"}</i>
            </div>

            <div className="proposal-execution">
              <div>
                <span>PROPOSAL</span>
                <strong>{proposal?.toUpperCase() ?? "NONE"}</strong>
              </div>
              <span className="decision-arrow" aria-hidden="true">
                →
              </span>
              <div>
                <span>EXECUTED</span>
                <strong>{executionLabel}</strong>
              </div>
            </div>

            <ul className="explanation-list">
              {(council?.explanation?.length
                ? council.explanation
                : [
                    "Esegui uno scenario sicuro per ottenere una decisione spiegata e verificabile.",
                  ]
              ).map((reason, index) => (
                <li key={`${reason}-${index}`}>{reason}</li>
              ))}
            </ul>

            <div className="evidence-grid">
              <section>
                <span>EVIDENCE</span>
                {evidence.length > 0 ? (
                  <ul>
                    {evidence.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                ) : (
                  <p>No evidence in the current cycle.</p>
                )}
              </section>
              <section>
                <span>COUNTEREVIDENCE / SAFEGUARDS</span>
                {safeguards.length > 0 ? (
                  <ul>
                    {safeguards.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                ) : (
                  <p>No dissent or safeguard signal recorded.</p>
                )}
              </section>
            </div>
          </article>

          <aside className="memory-card" aria-labelledby="memory-title">
            <div className="subpanel-heading">
              <span id="memory-title">MEMORY HEALTH</span>
              <i className={connection === "d1" ? "is-good" : "is-idle"}>
                {connection === "d1"
                  ? "HEALTHY"
                  : connection === "unavailable"
                    ? "FAILED CLOSED"
                    : connection === "connecting"
                      ? "VERIFYING"
                      : "EPHEMERAL"}
              </i>
            </div>
            <strong>{memoryLabel(connection)}</strong>
            <p>
              {connection === "d1"
                ? "Eventi, valutazioni e decisioni operatore sono conservati nella memoria privata."
                : connection === "memory_fallback"
                  ? "Snapshot temporaneo disponibile, ma le mutazioni restano disabilitate finché manca una memoria durevole."
                  : connection === "connecting"
                    ? "Verifica della memoria privata in corso; nessuna nuova mutazione viene accettata."
                    : "Memoria di sicurezza non disponibile: nessun nuovo evento o decisione viene applicato."}
            </p>
            <dl>
              <div>
                <dt>Revision</dt>
                <dd>#{state.revision}</dd>
              </div>
              <div>
                <dt>Policy</dt>
                <dd>{policy?.version ?? "—"}</dd>
              </div>
              <div>
                <dt>Fingerprint</dt>
                <dd>{policy?.fingerprint?.slice(0, 12) ?? "—"}</dd>
              </div>
              <div>
                <dt>External actions</dt>
                <dd
                  className={
                    policy?.externalNetworkActions === true
                      ? "violation-value"
                      : "blocked-value"
                  }
                >
                  {policy?.externalNetworkActions === true
                    ? "POLICY VIOLATION"
                    : "BLOCKED"}
                </dd>
              </div>
              <div>
                <dt>Offensive actions</dt>
                <dd
                  className={
                    policy?.offensiveActions === true
                      ? "violation-value"
                      : "blocked-value"
                  }
                >
                  {policy?.offensiveActions === true
                    ? "POLICY VIOLATION"
                    : "BLOCKED"}
                </dd>
              </div>
              <div>
                <dt>Network execution</dt>
                <dd className="blocked-value">
                  {autopilot.hardLimits.networkExecution ? "VIOLATION" : "BLOCKED"}
                </dd>
              </div>
              <div>
                <dt>Restore snapshot</dt>
                <dd className="review-value">
                  {policy?.humanApprovalForRestore === false
                    ? "POLICY VIOLATION"
                    : "MANUAL ONLY"}
                </dd>
              </div>
            </dl>
          </aside>
        </div>

        <div className="decision-pipeline" aria-label="Pipeline di decisione">
          {pipeline.map((stage, index) => (
            <article
              className={`pipeline-stage pipeline-${stage.tone}`}
              key={stage.id}
              aria-current={stage.tone === "active" ? "step" : undefined}
            >
              <span>{String(index + 1).padStart(2, "0")}</span>
              <div>
                <strong>{stage.label}</strong>
                <small>{stage.detail}</small>
              </div>
              <i aria-hidden="true" />
            </article>
          ))}
        </div>

        <section
          className="approval-console"
          aria-labelledby="approval-title"
          aria-busy={approvalBusy !== null}
        >
          <div className="approval-console-heading">
            <div>
              <span>POST-ACTION REVIEW · NON-BLOCKING</span>
              <h3 id="approval-title">
                {pendingApprovalTotal > 0
                  ? `${pendingApprovalTotal} REVIEW OPEN · AUTOPILOT ACTIVE${blockingManualTotal > 0 ? ` · ${blockingManualTotal} MANUAL EXCEPTION` : ""}${pendingApprovalTotal > approvalItems.length ? ` · VISIBILI ${approvalItems.length}` : ""}`
                  : "REVIEW LOG CLEAR · AUTOPILOT ACTIVE"}
              </h3>
            </div>
            <p>
              La protezione continua in autonomia. Qui puoi rivedere gli esiti
              in seguito; soltanto il ripristino snapshot resta un&apos;eccezione
              manuale separata, sempre state-only.
            </p>
          </div>

          {approvalItems.length > 0 ? (
            <div className="approval-list">
              {approvalItems.map((item) => {
                const isBlockingManual = item.reviewMode === "blocking_manual";
                const pendingOperation = approvalOperations[item.id];
                const approvingThisItem =
                  approvalBusy?.approvalId === item.id &&
                  approvalBusy.decision === "approve_simulation";
                const rejectingThisItem =
                  approvalBusy?.approvalId === item.id &&
                  approvalBusy.decision === "reject";

                return (
                  <article className="approval-item" key={item.id}>
                    <div className="approval-item-copy">
                      <span>
                        {isBlockingManual ? "MANUAL EXCEPTION" : "POST-EVENT"} ·{" "}
                        {item.severity?.toUpperCase()} · {item.scenarioId}
                      </span>
                      <strong>{item.title}</strong>
                      <p>{item.explanation}</p>
                      <small>
                        SAFE HOLD: {item.requestedAction} · POLICY{" "}
                        {item.policyVersion}
                      </small>
                    </div>
                    <div className="approval-controls">
                      <button
                        type="button"
                        className="approve-button"
                        onClick={() =>
                          void resolveApproval(item.id, "approve_simulation")
                        }
                        disabled={
                          approvalBusy !== null ||
                          isSimulating ||
                          connection !== "d1" ||
                          (pendingOperation !== undefined &&
                            pendingOperation.decision !== "approve_simulation")
                        }
                        aria-label={`${isBlockingManual ? "Autorizza l'eccezione manuale" : "Conferma la revisione post-evento"} ${item.title}`}
                      >
                        {approvingThisItem
                          ? "RECORDING…"
                          : pendingOperation?.decision === "approve_simulation"
                            ? "RETRY REVIEW"
                            : isBlockingManual
                              ? "AUTORIZZA RESTORE LAB"
                              : "CONFERMA REVIEW"}
                      </button>
                      <button
                        type="button"
                        className="reject-button"
                        onClick={() => void resolveApproval(item.id, "reject")}
                        disabled={
                          approvalBusy !== null ||
                          isSimulating ||
                          connection !== "d1" ||
                          (pendingOperation !== undefined &&
                            pendingOperation.decision !== "reject")
                        }
                        aria-label={`${isBlockingManual ? "Nega l'eccezione manuale" : "Archivia con rifiuto la revisione"} ${item.title}`}
                      >
                        {rejectingThisItem
                          ? "RECORDING…"
                          : pendingOperation?.decision === "reject"
                            ? "RETRY REJECT"
                            : isBlockingManual
                              ? "NEGA ECCEZIONE"
                              : "ARCHIVIA / RIFIUTA"}
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="approval-empty">
              <span aria-hidden="true">✓</span>
              <div>
                <strong>Nessuna revisione aperta</strong>
                <p>
                  L&apos;autopilot event-driven applica automaticamente allowlist,
                  quorum e Policy Guard.
                </p>
              </div>
            </div>
          )}

          <p className="operator-notice" role="status" aria-live="polite">
            {operatorNotice}
          </p>
        </section>
      </section>

      <section className="operator-overview glass-panel" aria-labelledby="operator-title">
        <div className="panel-heading operator-heading">
          <div>
            <span>04 / AUTONOMY PLAYBOOK</span>
            <h2 id="operator-title">COME DECIDONO SENZA ATTESA</h2>
          </div>
          <p>
            Cinque moduli deterministici separano rilevazione, contenimento,
            identità, deviazione e recupero. Il Policy Guard può soltanto
            restringere l&apos;azione; la revisione umana avviene dopo l&apos;evento.
          </p>
        </div>

        <div className="agent-overview-grid">
          {state.agents.map((agent, index) => {
            const brief = agentBriefs[agent.id];
            return (
              <article
                className={`agent-brief agent-${agent.status}`}
                key={`brief-${agent.id}`}
              >
                <div className="agent-brief-topline">
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <i aria-hidden="true">{agentIcons[agent.id]}</i>
                </div>
                <small>{brief.phase}</small>
                <h3>{agent.name}</h3>
                <p>{brief.description}</p>
                <strong>{brief.boundary}</strong>
              </article>
            );
          })}
        </div>
      </section>

      <section className="lower-grid">
        <section className="timeline-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>05 / VERIFIED STREAM</span>
              <h2 id="timeline-title">
                {connection === "unavailable"
                  ? "LAST KNOWN EVENT TIMELINE"
                  : connection === "connecting"
                    ? "VERIFYING EVENT TIMELINE"
                    : "VERIFIED EVENT TIMELINE"}
              </h2>
            </div>
            <span className="feed-state">
              {connection === "unavailable"
                ? "STALE / SANITIZED"
                : connection === "connecting"
                  ? "VERIFYING"
                  : "SANITIZED"}
            </span>
          </div>

          <div
            className="timeline-list"
            role="log"
            aria-labelledby="timeline-title"
            aria-live="polite"
            aria-relevant="additions"
          >
            {hasVerifiedSnapshot ? (
              state.timeline.length > 0 ? (
                state.timeline.map((event) => (
                  <article key={event.id} className={`event event-${event.severity}`}>
                    <time>{event.time}</time>
                    <span className="event-pip" aria-hidden="true" />
                    <div>
                      <strong>{event.title}</strong>
                      <p>{event.detail}</p>
                    </div>
                    <span className="severity-pill">
                      {severityLabels[event.severity]}
                    </span>
                  </article>
                ))
              ) : (
                <div className="verified-empty-state">
                  Nessun evento sanitizzato nello snapshot verificato.
                </div>
              )
            ) : (
              <div className="verified-empty-state" role="status">
                Verifica dello stream pubblico in corso…
              </div>
            )}
          </div>
        </section>

        <section className="leaderboard-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>06 / SEASON 01</span>
              <h2>RESEARCHER BOARD</h2>
            </div>
            <span className="feed-state">DEMO</span>
          </div>

          {hasVerifiedSnapshot && state.researchers.length > 0 ? (
            <ol className="leaderboard-list">
              {state.researchers.map((researcher, index) => (
                <li key={researcher.alias}>
                  <span className="rank">{String(index + 1).padStart(2, "0")}</span>
                  <span className="researcher-avatar" aria-hidden="true">
                    {researcher.alias.slice(0, 2).toUpperCase()}
                  </span>
                  <div>
                    <strong>{researcher.alias}</strong>
                    <small>{researcher.country} · VERIFIED</small>
                  </div>
                  <span className="finding-count">
                    {researcher.findings} <small>FINDINGS</small>
                  </span>
                </li>
              ))}
            </ol>
          ) : (
            <div className="verified-empty-state" role="status">
              {hasVerifiedSnapshot
                ? "Nessun ricercatore nello snapshot verificato."
                : "Verifica della classifica pubblica in corso…"}
            </div>
          )}
        </section>
      </section>

      <footer className="command-footer">
        <p>
          PUBLIC PROJECTION <span>•</span> NO RAW IP <span>•</span> NO PAYLOADS{" "}
          <span>•</span> NO SECRETS
        </p>
        <p>
          KRELUNA DEFENSE ENGINE · GUARDED AUTOPILOT / POLICY-BOUND · SAFE LAB v0.4
        </p>
      </footer>
    </main>
  );
}
