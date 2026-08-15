export const SAFE_SCENARIO_IDS = [
  "authentication-burst",
  "api-input-anomaly",
  "integrity-drift",
  "recovery-check",
] as const;

export type SafeScenarioId = (typeof SAFE_SCENARIO_IDS)[number];
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type SystemStatus = "protected" | "attention" | "review";
export type PolicyOutcome =
  | "allow_simulation"
  | "requires_approval"
  | "deny";

export type SafeAction =
  | "observe"
  | "tag_demo_session"
  | "notify_operator"
  | "rate_limit_demo_session"
  | "route_to_internal_decoy"
  | "quarantine_demo_asset"
  | "restore_demo_snapshot";

export type AuthorizedDemoAsset =
  | "vault-web-01"
  | "vault-api-01"
  | "identity-lab-01";

export type AgentId = "aegis" | "argine" | "orbit" | "decoy" | "phoenix";

export interface SyntheticSecurityEvent {
  id: string;
  scenarioId: SafeScenarioId;
  title: string;
  detail: string;
  severity: Severity;
  confidence: number;
  independentSignals: number;
  demoAsset: AuthorizedDemoAsset;
  requestedAction: SafeAction;
  labOnly: true;
  occurredAt: string;
}

export interface PolicyDecision {
  outcome: PolicyOutcome;
  explanation: string;
  reasonCode:
    | "LAB_OBSERVATION_ALLOWED"
    | "SCOPED_REVERSIBLE_SIMULATION"
    | "HUMAN_APPROVAL_REQUIRED"
    | "OUTSIDE_LAB_BOUNDARY"
    | "ACTION_NOT_ALLOWLISTED"
    | "INVALID_EVIDENCE";
  approvalRequired: boolean;
}

export interface AgentState {
  id: AgentId;
  name: string;
  role: string;
  status: "ready" | "engaged";
  lastAction: string;
}

export interface AgentAssessment {
  id: string;
  eventId: string;
  agentId: AgentId;
  agentName: string;
  provider: "deterministic_lab" | "advisory_model";
  verdict: "clear" | "monitor" | "contain_simulation" | "hold_for_human";
  score: number;
  rationale: string;
}

/**
 * Replaceable analysis boundary. A future model can advise here, but its output
 * never enters Policy Guard's allow/deny decision and can never execute actions.
 */
export interface AgentCouncil {
  readonly provider: "deterministic_lab" | "advisory_model";
  assess(
    event: Readonly<SyntheticSecurityEvent>,
    immutablePolicyDecision: Readonly<PolicyDecision>,
  ): readonly AgentAssessment[] | Promise<readonly AgentAssessment[]>;
}

export interface TimelineEvent {
  id: string;
  time: string;
  title: string;
  detail: string;
  severity: Severity;
}

export interface DashboardState {
  revision: number;
  status: SystemStatus;
  metrics: {
    detected: number;
    mitigated: number;
    pendingApprovals: number;
    criticalBreaches: number;
  };
  agents: AgentState[];
  timeline: TimelineEvent[];
  researchers: Array<{
    alias: string;
    country: string;
    findings: number;
  }>;
  audit: Array<{
    eventId: string;
    action: SafeAction;
    decision: PolicyOutcome;
    reasonCode: PolicyDecision["reasonCode"];
  }>;
}

export interface LabIncident {
  id: string;
  eventId: string;
  status: "observed" | "contained" | "pending_approval" | "denied";
  impact: "none" | "unconfirmed";
  approvalStatus: "not_required" | "pending";
  publicSummary: string;
  openedAt: string;
  resolvedAt: string | null;
  updatedAt: string;
}

export interface AuditEntry {
  id: string;
  eventId: string;
  sequence: number;
  actor: "policy-guard";
  action: SafeAction;
  outcome: PolicyOutcome;
  reasonCode: PolicyDecision["reasonCode"];
  detail: string;
  createdAt: string;
}

export interface DefenseCycleResult {
  event: SyntheticSecurityEvent;
  decision: PolicyDecision;
  assessments: readonly AgentAssessment[];
  incident: LabIncident;
  audit: AuditEntry;
  snapshot: DashboardState;
  execution: {
    scope: "state_only_lab_simulation";
    externalNetworkAction: false;
    offensiveAction: false;
  };
}

export interface DefenseCycleContext {
  eventId: string;
  now: string;
  sequence: number;
}

export interface SafeScenarioSummary {
  id: SafeScenarioId;
  label: string;
  severity: Severity;
  requiresApproval: boolean;
}

type ScenarioDefinition = Omit<
  SyntheticSecurityEvent,
  "id" | "occurredAt"
> & { label: string };

const AUTHORIZED_DEMO_ASSETS: ReadonlySet<string> = new Set([
  "vault-web-01",
  "vault-api-01",
  "identity-lab-01",
]);

const ALLOWLISTED_ACTIONS: ReadonlySet<string> = new Set<SafeAction>([
  "observe",
  "tag_demo_session",
  "notify_operator",
  "rate_limit_demo_session",
  "route_to_internal_decoy",
  "quarantine_demo_asset",
  "restore_demo_snapshot",
]);

const HIGH_IMPACT_ACTIONS: ReadonlySet<SafeAction> = new Set([
  "route_to_internal_decoy",
  "quarantine_demo_asset",
  "restore_demo_snapshot",
]);

const SCENARIOS: Readonly<Record<SafeScenarioId, ScenarioDefinition>> = {
  "authentication-burst": {
    scenarioId: "authentication-burst",
    label: "Authentication burst",
    title: "Suspicious authentication burst",
    detail: "Synthetic demo session scoped for a reversible rate-limit simulation",
    severity: "medium",
    confidence: 0.91,
    independentSignals: 3,
    demoAsset: "identity-lab-01",
    requestedAction: "rate_limit_demo_session",
    labOnly: true,
  },
  "api-input-anomaly": {
    scenarioId: "api-input-anomaly",
    label: "API input anomaly",
    title: "Abnormal API input isolated",
    detail: "Sanitized signature retained; internal decoy proposal held for approval",
    severity: "high",
    confidence: 0.94,
    independentSignals: 2,
    demoAsset: "vault-api-01",
    requestedAction: "route_to_internal_decoy",
    labOnly: true,
  },
  "integrity-drift": {
    scenarioId: "integrity-drift",
    label: "Integrity drift",
    title: "Integrity signal requires review",
    detail: "Quarantine remains a proposal until an authorized human reviews it",
    severity: "high",
    confidence: 0.97,
    independentSignals: 3,
    demoAsset: "vault-web-01",
    requestedAction: "quarantine_demo_asset",
    labOnly: true,
  },
  "recovery-check": {
    scenarioId: "recovery-check",
    label: "Recovery readiness check",
    title: "Defense mesh synchronized",
    detail: "Policy, recovery and audit planes report healthy in the lab",
    severity: "low",
    confidence: 1,
    independentSignals: 4,
    demoAsset: "vault-web-01",
    requestedAction: "observe",
    labOnly: true,
  },
};

const AGENT_DEFINITIONS: ReadonlyArray<
  Pick<AgentState, "id" | "name" | "role">
> = [
  { id: "aegis", name: "AEGIS", role: "Evidence correlation" },
  { id: "argine", name: "ARGINE", role: "Policy-bound containment" },
  { id: "orbit", name: "ORBIT", role: "Identity protection" },
  { id: "decoy", name: "DECOY", role: "Internal lab deception" },
  { id: "phoenix", name: "PHOENIX", role: "Recovery readiness" },
];

function isSafeScenarioId(value: unknown): value is SafeScenarioId {
  return (
    typeof value === "string" &&
    (SAFE_SCENARIO_IDS as readonly string[]).includes(value)
  );
}

export function parseLabScenarioRequest(input: unknown):
  | { ok: true; scenario: SafeScenarioId }
  | {
      ok: false;
      code: "INVALID_BODY" | "UNKNOWN_SCENARIO";
      message: string;
    } {
  if (
    typeof input !== "object" ||
    input === null ||
    Array.isArray(input) ||
    Object.getPrototypeOf(input) !== Object.prototype
  ) {
    return {
      ok: false,
      code: "INVALID_BODY",
      message: "The request body must be a JSON object containing only `scenario`.",
    };
  }

  const keys = Object.keys(input);
  if (keys.length !== 1 || keys[0] !== "scenario") {
    return {
      ok: false,
      code: "INVALID_BODY",
      message: "Only the `scenario` field is accepted.",
    };
  }

  const scenario = (input as { scenario?: unknown }).scenario;
  if (!isSafeScenarioId(scenario)) {
    return {
      ok: false,
      code: "UNKNOWN_SCENARIO",
      message: "Choose one of the published safe laboratory scenarios.",
    };
  }

  return { ok: true, scenario };
}

export function listSafeLabScenarios(): SafeScenarioSummary[] {
  return SAFE_SCENARIO_IDS.map((id) => {
    const scenario = SCENARIOS[id];
    return {
      id,
      label: scenario.label,
      severity: scenario.severity,
      requiresApproval: HIGH_IMPACT_ACTIONS.has(scenario.requestedAction),
    };
  });
}

export function evaluateDemoAction(
  event: Readonly<SyntheticSecurityEvent>,
): PolicyDecision {
  if (event.labOnly !== true || !AUTHORIZED_DEMO_ASSETS.has(event.demoAsset)) {
    return {
      outcome: "deny",
      explanation: "The target is outside the authorized Creluna laboratory boundary.",
      reasonCode: "OUTSIDE_LAB_BOUNDARY",
      approvalRequired: false,
    };
  }

  if (!ALLOWLISTED_ACTIONS.has(event.requestedAction)) {
    return {
      outcome: "deny",
      explanation: "Policy Guard rejected an action that is not on the lab allowlist.",
      reasonCode: "ACTION_NOT_ALLOWLISTED",
      approvalRequired: false,
    };
  }

  if (
    !Number.isFinite(event.confidence) ||
    event.confidence < 0 ||
    event.confidence > 1 ||
    !Number.isInteger(event.independentSignals) ||
    event.independentSignals < 1
  ) {
    return {
      outcome: "deny",
      explanation: "The evidence envelope is invalid.",
      reasonCode: "INVALID_EVIDENCE",
      approvalRequired: false,
    };
  }

  if (HIGH_IMPACT_ACTIONS.has(event.requestedAction)) {
    return {
      outcome: "requires_approval",
      explanation: "The proposal is recorded, but a human must authorize any high-impact lab action.",
      reasonCode: "HUMAN_APPROVAL_REQUIRED",
      approvalRequired: true,
    };
  }

  if (event.requestedAction === "rate_limit_demo_session") {
    if (event.confidence >= 0.85 && event.independentSignals >= 2) {
      return {
        outcome: "allow_simulation",
        explanation: "Policy Guard allowed a scoped, reversible state-only simulation.",
        reasonCode: "SCOPED_REVERSIBLE_SIMULATION",
        approvalRequired: false,
      };
    }

    return {
      outcome: "deny",
      explanation: "The evidence threshold for the rate-limit simulation was not met.",
      reasonCode: "INVALID_EVIDENCE",
      approvalRequired: false,
    };
  }

  return {
    outcome: "allow_simulation",
    explanation: "Policy Guard allowed a low-impact observational lab update.",
    reasonCode: "LAB_OBSERVATION_ALLOWED",
    approvalRequired: false,
  };
}

function assessmentVerdict(
  agentId: AgentId,
  event: SyntheticSecurityEvent,
  decision: PolicyDecision,
): AgentAssessment["verdict"] {
  if (decision.outcome === "requires_approval") return "hold_for_human";
  if (decision.outcome === "deny") return "monitor";
  if (agentId === "argine" && event.requestedAction !== "observe") {
    return "contain_simulation";
  }
  if (agentId === "orbit" && event.scenarioId === "authentication-burst") {
    return "monitor";
  }
  return "clear";
}

function assessmentRationale(
  agentId: AgentId,
  event: SyntheticSecurityEvent,
  decision: PolicyDecision,
): string {
  const rationales: Record<AgentId, string> = {
    aegis: `${event.independentSignals} sanitized signals correlated at ${Math.round(event.confidence * 100)}% confidence`,
    argine: decision.explanation,
    orbit:
      event.scenarioId === "authentication-burst"
        ? "Synthetic identity session isolated from all production identities"
        : "No production identity action requested",
    decoy:
      event.requestedAction === "route_to_internal_decoy"
        ? "Internal decoy routing held for explicit human approval"
        : "No deception route activated",
    phoenix:
      event.scenarioId === "recovery-check"
        ? "Clean lab checkpoint verified; no restoration executed"
        : "Recovery plan remains read-only",
  };
  return rationales[agentId];
}

export const deterministicLabAgentCouncil: AgentCouncil = {
  provider: "deterministic_lab",
  assess(event, decision) {
    return AGENT_DEFINITIONS.map((agent, index) => ({
      id: `${event.id}:assessment:${agent.id}`,
      eventId: event.id,
      agentId: agent.id,
      agentName: agent.name,
      provider: "deterministic_lab" as const,
      verdict: assessmentVerdict(agent.id, event, decision),
      score: Math.min(1, Math.max(0, event.confidence - index * 0.015)),
      rationale: assessmentRationale(agent.id, event, decision),
    }));
  },
};

export function createInitialDemoState(): DashboardState {
  return {
    revision: 0,
    status: "protected",
    metrics: {
      detected: 0,
      mitigated: 0,
      pendingApprovals: 0,
      criticalBreaches: 0,
    },
    agents: AGENT_DEFINITIONS.map((agent) => ({
      ...agent,
      status: "ready",
      lastAction: "Deterministic lab policy loaded",
    })),
    timeline: [
      {
        id: "lab-ready",
        time: "READY",
        title: "Creluna safe laboratory online",
        detail: "No external targets · no raw payloads · no autonomous counterattack",
        severity: "info",
      },
    ],
    researchers: [
      { alias: "CipherNorth", country: "SE", findings: 7 },
      { alias: "Nexa", country: "IT", findings: 5 },
      { alias: "ZeroMistral", country: "FR", findings: 4 },
      { alias: "ByteHarbor", country: "NL", findings: 3 },
    ],
    audit: [],
  };
}

function safeClockLabel(iso: string): string {
  const match = iso.match(/T(\d{2}:\d{2}:\d{2})/);
  return match?.[1] ?? "LAB";
}

function createIncident(
  event: SyntheticSecurityEvent,
  decision: PolicyDecision,
): LabIncident {
  const status: LabIncident["status"] =
    decision.outcome === "requires_approval"
      ? "pending_approval"
      : decision.outcome === "allow_simulation"
        ? event.requestedAction === "observe"
          ? "observed"
          : "contained"
        : "denied";

  return {
    id: `${event.id}:incident`,
    eventId: event.id,
    status,
    impact: status === "pending_approval" ? "unconfirmed" : "none",
    approvalStatus:
      status === "pending_approval" ? "pending" : "not_required",
    publicSummary:
      status === "pending_approval"
        ? "Proposal recorded for an authorized human; no action executed"
        : status === "contained"
          ? "State-only defensive simulation recorded inside the lab"
          : status === "denied"
            ? "Policy Guard denied the proposal; no action executed"
            : "Read-only laboratory observation recorded",
    openedAt: event.occurredAt,
    resolvedAt:
      status === "contained" || status === "observed" || status === "denied"
        ? event.occurredAt
        : null,
    updatedAt: event.occurredAt,
  };
}

function finalizeDefenseCycle(
  previous: DashboardState,
  event: SyntheticSecurityEvent,
  decision: PolicyDecision,
  assessments: readonly AgentAssessment[],
  sequence: number,
): DefenseCycleResult {
  const incident = createIncident(event, decision);
  const pendingApprovals =
    previous.metrics.pendingApprovals +
    (decision.outcome === "requires_approval" ? 1 : 0);
  const audit: AuditEntry = {
    id: `${event.id}:audit:1`,
    eventId: event.id,
    sequence: 1,
    actor: "policy-guard",
    action: event.requestedAction,
    outcome: decision.outcome,
    reasonCode: decision.reasonCode,
    detail: decision.explanation,
    createdAt: event.occurredAt,
  };
  const latestAssessment = new Map(
    assessments.map((assessment) => [assessment.agentId, assessment]),
  );

  const snapshot: DashboardState = {
    ...previous,
    revision: Math.max(previous.revision + 1, sequence),
    status:
      pendingApprovals > 0
        ? "review"
        : decision.outcome === "deny" || event.severity === "high"
          ? "attention"
          : "protected",
    metrics: {
      detected: previous.metrics.detected + 1,
      mitigated:
        previous.metrics.mitigated +
        (decision.outcome === "allow_simulation" ? 1 : 0),
      pendingApprovals,
      criticalBreaches: previous.metrics.criticalBreaches,
    },
    agents: previous.agents.map((agent) => {
      const assessment = latestAssessment.get(agent.id);
      if (!assessment) return agent;
      return {
        ...agent,
        status:
          assessment.verdict === "contain_simulation" ||
          assessment.verdict === "hold_for_human"
            ? "engaged"
            : "ready",
        lastAction: assessment.rationale,
      };
    }),
    timeline: [
      {
        id: event.id,
        time: safeClockLabel(event.occurredAt),
        title: event.title,
        detail:
          decision.outcome === "requires_approval"
            ? `${event.detail} · approval required`
            : event.detail,
        severity: event.severity,
      },
      ...previous.timeline.filter((item) => item.id !== "lab-ready"),
    ].slice(0, 12),
    audit: [
      ...previous.audit,
      {
        eventId: event.id,
        action: event.requestedAction,
        decision: decision.outcome,
        reasonCode: decision.reasonCode,
      },
    ].slice(-100),
  };

  return {
    event,
    decision,
    assessments,
    incident,
    audit,
    snapshot,
    execution: {
      scope: "state_only_lab_simulation",
      externalNetworkAction: false,
      offensiveAction: false,
    },
  };
}

function createScenarioEvent(
  scenarioId: SafeScenarioId,
  context: DefenseCycleContext,
): SyntheticSecurityEvent {
  const definition = SCENARIOS[scenarioId];
  return {
    id: context.eventId,
    scenarioId,
    title: definition.title,
    detail: definition.detail,
    severity: definition.severity,
    confidence: definition.confidence,
    independentSignals: definition.independentSignals,
    demoAsset: definition.demoAsset,
    requestedAction: definition.requestedAction,
    labOnly: true,
    occurredAt: context.now,
  };
}

/** Pure, synchronous production path used by the current lab API. */
export function runNamedLabScenario(
  previous: DashboardState,
  scenarioId: SafeScenarioId,
  context: DefenseCycleContext,
): DefenseCycleResult {
  const event = createScenarioEvent(scenarioId, context);
  const decision = evaluateDemoAction(event);
  const assessments = deterministicLabAgentCouncil.assess(event, decision);

  if (assessments instanceof Promise) {
    throw new Error("The deterministic lab council must be synchronous.");
  }

  return finalizeDefenseCycle(
    previous,
    event,
    decision,
    assessments,
    context.sequence,
  );
}

/**
 * Future provider path. Agent advice is collected only after Policy Guard has
 * made the immutable decision, so a model cannot expand execution privileges.
 */
export async function runNamedLabScenarioWithCouncil(
  previous: DashboardState,
  scenarioId: SafeScenarioId,
  context: DefenseCycleContext,
  council: AgentCouncil,
): Promise<DefenseCycleResult> {
  const event = createScenarioEvent(scenarioId, context);
  const decision = Object.freeze(evaluateDemoAction(event));
  const assessments = await council.assess(Object.freeze(event), decision);
  return finalizeDefenseCycle(
    previous,
    event,
    decision,
    assessments,
    context.sequence,
  );
}

/** Compatibility helper for the original client-only demo. */
export function runDemoDefenseCycle(
  previous: DashboardState,
  cycle: number,
): DashboardState {
  const normalizedCycle = Number.isInteger(cycle) && cycle > 0 ? cycle : 1;
  const scenarioId = SAFE_SCENARIO_IDS[(normalizedCycle - 1) % SAFE_SCENARIO_IDS.length];
  const second = normalizedCycle % 60;
  return runNamedLabScenario(previous, scenarioId, {
    eventId: `client-demo-${normalizedCycle}`,
    sequence: normalizedCycle,
    now: `2026-08-15T14:22:${String(second).padStart(2, "0")}Z`,
  }).snapshot;
}
