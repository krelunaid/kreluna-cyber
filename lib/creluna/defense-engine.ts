export const SAFE_SCENARIO_IDS = [
  "authentication-burst",
  "api-input-anomaly",
  "integrity-drift",
  "recovery-check",
] as const;

export type SafeScenarioId = (typeof SAFE_SCENARIO_IDS)[number];
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type SystemStatus = "protected" | "attention" | "review";
export type PolicyOutcome =
  | "allow_simulation"
  | "requires_approval"
  | "deny";
export type CouncilVote = PolicyOutcome;

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

export interface PolicyProfile {
  id: string;
  version: string;
  fingerprint: string;
  mode: string;
  externalNetworkActions: boolean;
  offensiveActions: boolean;
  humanApprovalForHighImpact: boolean;
}

export const POLICY_PROFILE: Readonly<PolicyProfile> = Object.freeze({
  id: "creluna-policy-guard",
  version: "3.0.0",
  fingerprint: "CPG-STATE-ONLY-5A-2026",
  mode: "deterministic_policy_bound",
  externalNetworkActions: false as const,
  offensiveActions: false as const,
  humanApprovalForHighImpact: true as const,
});

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
    | "COUNCIL_HUMAN_APPROVAL_REQUIRED"
    | "COUNCIL_DENY_RECORDED"
    | "HUMAN_APPROVAL_RECORDED"
    | "HUMAN_REJECTION_RECORDED"
    | "OUTSIDE_LAB_BOUNDARY"
    | "ACTION_NOT_ALLOWLISTED"
    | "INVALID_EVIDENCE";
  approvalRequired: boolean;
}

export interface AgentAssessment {
  id: string;
  eventId: string;
  agentId: AgentId;
  agentName: string;
  provider: "deterministic_lab" | "advisory_model";
  verdict: "clear" | "monitor" | "contain_simulation" | "hold_for_human";
  vote: CouncilVote;
  risk: RiskLevel;
  confidence: number;
  trust: number;
  score: number;
  rationale: string;
  evidence: string[];
  safeguards: string[];
}

export type AgentAssessmentSnapshot = Pick<
  AgentAssessment,
  | "verdict"
  | "vote"
  | "risk"
  | "confidence"
  | "trust"
  | "rationale"
  | "evidence"
  | "safeguards"
>;

export interface AgentState {
  id: AgentId;
  name: string;
  role: string;
  level: number;
  mission: string;
  capabilities: string[];
  status: "ready" | "engaged";
  lastAction: string;
  stats: {
    assessments: number;
    consensusAlignment: number;
    trust: number;
  };
  assessment: AgentAssessmentSnapshot | null;
}

export interface CouncilSummary {
  eventId: string;
  consensus:
    | "unanimous"
    | "qualified_majority"
    | "policy_veto"
    | "no_quorum";
  recommendation: PolicyOutcome;
  quorum: { required: number; received: number; met: boolean };
  agreement: number;
  risk: RiskLevel;
  confidence: number;
  votes: {
    allowSimulation: number;
    requiresApproval: number;
    deny: number;
  };
  explanation: string[];
  dissentingAgents: AgentId[];
}

/**
 * Replaceable analysis boundary. Model output remains advisory and is validated
 * before use; Policy Guard is evaluated first and cannot be weakened by votes.
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

export interface PendingApprovalItem {
  id: string;
  eventId: string;
  scenarioId: SafeScenarioId;
  title: string;
  severity: Severity;
  requestedAction: SafeAction;
  status: "pending";
  policyVersion: string;
  createdAt: string;
  councilRecommendation: PolicyOutcome;
  explanation: string;
}

export type ApprovalDecision = "approve_simulation" | "reject";

export interface ApprovalDecisionRecord extends Record<string, unknown> {
  id: string;
  approvalId: string;
  eventId: string;
  decision: ApprovalDecision;
  scope: "state_only_lab_simulation";
  executedExternalAction: false;
  decidedAt: string;
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
  policy: Readonly<PolicyProfile>;
  council: CouncilSummary | null;
  agents: AgentState[];
  pendingApprovalItems: PendingApprovalItem[];
  recentApprovalDecisions: Array<Record<string, unknown>>;
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
  approvalStatus:
    | "not_required"
    | "pending"
    | "approved_simulation"
    | "rejected";
  publicSummary: string;
  openedAt: string;
  resolvedAt: string | null;
  updatedAt: string;
}

export interface AuditEntry {
  id: string;
  eventId: string;
  sequence: number;
  actor: "policy-guard" | "human-operator";
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
  council: CouncilSummary;
  incident: LabIncident;
  approval: PendingApprovalItem | null;
  audit: AuditEntry;
  snapshot: DashboardState;
  execution: {
    scope: "state_only_lab_simulation";
    externalNetworkAction: false;
    offensiveAction: false;
    privilegedAction: false;
  };
}

export interface ApprovalResolutionResult {
  record: ApprovalDecisionRecord;
  audit: AuditEntry;
  snapshot: DashboardState;
  execution: DefenseCycleResult["execution"];
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

type ScenarioDefinition = Omit<SyntheticSecurityEvent, "id" | "occurredAt"> & {
  label: string;
};

type AgentDefinition = Pick<
  AgentState,
  "id" | "name" | "role" | "level" | "mission" | "capabilities"
> & { baselineTrust: number };

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

export const AGENT_DEFINITIONS: readonly AgentDefinition[] = [
  {
    id: "aegis",
    name: "AEGIS",
    role: "Evidence correlation",
    level: 99,
    mission: "Correlate multiple sanitized signals into a verifiable evidence envelope.",
    capabilities: ["multi-signal correlation", "bounded confidence scoring", "evidence integrity"],
    baselineTrust: 99,
  },
  {
    id: "argine",
    name: "ARGINE",
    role: "Policy-bound containment",
    level: 99,
    mission: "Evaluate reversible containment proposals without crossing the lab boundary.",
    capabilities: ["policy evaluation", "reversible containment", "scope verification"],
    baselineTrust: 99,
  },
  {
    id: "orbit",
    name: "ORBIT",
    role: "Identity protection",
    level: 98,
    mission: "Protect synthetic identities, sessions and privilege boundaries.",
    capabilities: ["identity anomaly review", "session risk", "privilege boundary checks"],
    baselineTrust: 98,
  },
  {
    id: "decoy",
    name: "DECOY",
    role: "Internal lab deception",
    level: 98,
    mission: "Assess isolated decoy proposals while preserving strict human control.",
    capabilities: ["internal decoy planning", "isolation validation", "proposal-only routing"],
    baselineTrust: 98,
  },
  {
    id: "phoenix",
    name: "PHOENIX",
    role: "Recovery readiness",
    level: 99,
    mission: "Verify clean checkpoints and recovery readiness without executing restoration.",
    capabilities: ["checkpoint verification", "recovery scoring", "rollback readiness"],
    baselineTrust: 99,
  },
] as const;

const EXPECTED_AGENT_IDS = new Set<AgentId>(AGENT_DEFINITIONS.map(({ id }) => id));

function isSafeScenarioId(value: unknown): value is SafeScenarioId {
  return typeof value === "string" && (SAFE_SCENARIO_IDS as readonly string[]).includes(value);
}

export function parseLabScenarioRequest(input: unknown):
  | { ok: true; scenario: SafeScenarioId }
  | { ok: false; code: "INVALID_BODY" | "UNKNOWN_SCENARIO"; message: string } {
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
    return { ok: false, code: "INVALID_BODY", message: "Only the `scenario` field is accepted." };
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

export function parseApprovalRequest(input: unknown):
  | { ok: true; approvalId: string; decision: ApprovalDecision }
  | { ok: false; code: "INVALID_BODY" | "INVALID_APPROVAL_ID"; message: string } {
  if (
    typeof input !== "object" ||
    input === null ||
    Array.isArray(input) ||
    Object.getPrototypeOf(input) !== Object.prototype
  ) {
    return { ok: false, code: "INVALID_BODY", message: "A strict approval object is required." };
  }

  const record = input as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (
    keys.length !== 3 ||
    keys[0] !== "approvalId" ||
    keys[1] !== "confirmation" ||
    keys[2] !== "decision" ||
    record.confirmation !== "STATE_ONLY_LAB" ||
    (record.decision !== "approve_simulation" && record.decision !== "reject")
  ) {
    return {
      ok: false,
      code: "INVALID_BODY",
      message: "Use only approvalId, a supported decision and confirmation `STATE_ONLY_LAB`.",
    };
  }

  if (
    typeof record.approvalId !== "string" ||
    !/^[a-zA-Z0-9][a-zA-Z0-9:._-]{5,119}$/.test(record.approvalId)
  ) {
    return { ok: false, code: "INVALID_APPROVAL_ID", message: "The approval identifier is invalid." };
  }

  return { ok: true, approvalId: record.approvalId, decision: record.decision };
}

export function listSafeLabScenarios(): SafeScenarioSummary[] {
  return SAFE_SCENARIO_IDS.map((id) => ({
    id,
    label: SCENARIOS[id].label,
    severity: SCENARIOS[id].severity,
    requiresApproval: HIGH_IMPACT_ACTIONS.has(SCENARIOS[id].requestedAction),
  }));
}

export function evaluateDemoAction(event: Readonly<SyntheticSecurityEvent>): PolicyDecision {
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
      explanation: "Policy Guard recorded the proposal; a human must authorize the state-only simulation.",
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

function agentVote(agentId: AgentId, event: SyntheticSecurityEvent, decision: PolicyDecision): CouncilVote {
  if (decision.outcome === "deny") return "deny";
  if (decision.outcome === "requires_approval") {
    if (agentId === "orbit" && event.scenarioId !== "authentication-burst") return "allow_simulation";
    if (agentId === "phoenix" && event.scenarioId === "integrity-drift") return "deny";
    return "requires_approval";
  }
  if (agentId === "orbit" && event.scenarioId === "authentication-burst") return "requires_approval";
  return "allow_simulation";
}

function agentVerdict(agentId: AgentId, event: SyntheticSecurityEvent, vote: CouncilVote): AgentAssessment["verdict"] {
  if (vote === "deny") return "monitor";
  if (vote === "requires_approval") return "hold_for_human";
  if (agentId === "argine" && event.requestedAction !== "observe") return "contain_simulation";
  if (agentId === "orbit" && event.scenarioId === "authentication-burst") return "monitor";
  return "clear";
}

function riskFromSeverity(severity: Severity): RiskLevel {
  return severity === "critical" ? "critical" : severity === "high" ? "high" : severity === "medium" ? "medium" : "low";
}

function specializedReport(
  definition: AgentDefinition,
  event: SyntheticSecurityEvent,
  decision: PolicyDecision,
  index: number,
): AgentAssessment {
  const vote = agentVote(definition.id, event, decision);
  const confidence = Math.max(0, Math.min(100, Math.round(event.confidence * 100 - index)));
  const reportByAgent: Record<AgentId, Pick<AgentAssessment, "rationale" | "evidence" | "safeguards">> = {
    aegis: {
      rationale: `${event.independentSignals} sanitized lab signals correlated at ${Math.round(event.confidence * 100)}% confidence.`,
      evidence: [`Signal quorum ${event.independentSignals}/2`, `Scenario signature ${event.scenarioId}`, `Asset scope ${event.demoAsset}`],
      safeguards: ["Sanitized evidence only", "No raw-content retention", "Read-only correlation"],
    },
    argine: {
      rationale: `Policy ${POLICY_PROFILE.version} maps ${event.requestedAction} to ${decision.outcome}.`,
      evidence: [`Action allowlist checked`, `Lab-only flag confirmed`, `Policy reason ${decision.reasonCode}`],
      safeguards: ["Policy Guard cannot be overridden", "Reversible state only", "No privileged action"],
    },
    orbit: {
      rationale: event.scenarioId === "authentication-burst"
        ? "Synthetic identity sessions show elevated risk; production identities remain untouched."
        : "No production identity or credential operation is present in this scenario.",
      evidence: [`Identity plane ${event.scenarioId === "authentication-burst" ? "relevant" : "clear"}`, "Synthetic session boundary", "Privilege escalation absent"],
      safeguards: ["No credentials exposed", "No account mutation", "Session scope isolated"],
    },
    decoy: {
      rationale: event.requestedAction === "route_to_internal_decoy"
        ? "Internal decoy routing is a proposal only and remains blocked pending human authorization."
        : "No decoy route is required; deception controls stay inactive.",
      evidence: [`Decoy requirement ${event.requestedAction === "route_to_internal_decoy" ? "proposed" : "none"}`, "Isolation boundary verified", "External routing absent"],
      safeguards: ["Internal lab destination only", "Human approval gate", "No interaction with external actors"],
    },
    phoenix: {
      rationale: event.scenarioId === "recovery-check"
        ? "Clean checkpoint metadata is coherent; no restore operation has been executed."
        : "Recovery readiness remains verified and read-only while the event is assessed.",
      evidence: ["Checkpoint metadata verified", "Recovery plan available", "Execution state unchanged"],
      safeguards: ["No automatic restore", "Signed checkpoint policy", "Operator-controlled recovery"],
    },
  };
  const report = reportByAgent[definition.id];
  return {
    id: `${event.id}:assessment:${definition.id}`,
    eventId: event.id,
    agentId: definition.id,
    agentName: definition.name,
    provider: "deterministic_lab",
    verdict: agentVerdict(definition.id, event, vote),
    vote,
    risk: riskFromSeverity(event.severity),
    confidence,
    trust: definition.baselineTrust,
    score: confidence / 100,
    rationale: report.rationale,
    evidence: report.evidence,
    safeguards: report.safeguards,
  };
}

export const deterministicLabAgentCouncil: AgentCouncil = {
  provider: "deterministic_lab",
  assess(event, decision) {
    return AGENT_DEFINITIONS.map((agent, index) => specializedReport(agent, event, decision, index));
  },
};

function isPercentage(value: number): boolean {
  return Number.isFinite(value) && value >= 0 && value <= 100;
}

export function validateCouncilReports(
  event: Readonly<SyntheticSecurityEvent>,
  reports: readonly AgentAssessment[],
  expectedProvider?: AgentCouncil["provider"],
): readonly AgentAssessment[] {
  if (reports.length !== AGENT_DEFINITIONS.length) {
    throw new Error("INVALID_COUNCIL_REPORTS: exactly five reports are required.");
  }
  const observedIds = new Set<AgentId>();
  const observedReportIds = new Set<string>();
  for (const report of reports) {
    const definition = AGENT_DEFINITIONS.find(({ id }) => id === report.agentId);
    const validTextList = (items: unknown) => Array.isArray(items) && items.length >= 1 && items.length <= 6 && items.every(
      (item) => typeof item === "string" && item.length >= 1 && item.length <= 120,
    );
    if (
      !EXPECTED_AGENT_IDS.has(report.agentId) ||
      observedIds.has(report.agentId) ||
      typeof report.id !== "string" ||
      report.id.length < 8 ||
      report.id.length > 160 ||
      observedReportIds.has(report.id) ||
      report.eventId !== event.id ||
      !definition ||
      report.agentName !== definition.name ||
      !["deterministic_lab", "advisory_model"].includes(report.provider) ||
      (expectedProvider !== undefined && report.provider !== expectedProvider) ||
      !["clear", "monitor", "contain_simulation", "hold_for_human"].includes(report.verdict) ||
      !["allow_simulation", "requires_approval", "deny"].includes(report.vote) ||
      !["low", "medium", "high", "critical"].includes(report.risk) ||
      !isPercentage(report.confidence) ||
      !isPercentage(report.trust) ||
      !Number.isFinite(report.score) ||
      report.score < 0 ||
      report.score > 1 ||
      typeof report.rationale !== "string" ||
      report.rationale.length < 12 ||
      report.rationale.length > 220 ||
      !validTextList(report.evidence) ||
      !validTextList(report.safeguards)
    ) {
      throw new Error("INVALID_COUNCIL_REPORTS: a report failed schema or trust validation.");
    }
    observedIds.add(report.agentId);
    observedReportIds.add(report.id);
  }
  return reports.map((report) => Object.freeze({
    ...report,
    evidence: Object.freeze([...report.evidence]) as unknown as string[],
    safeguards: Object.freeze([...report.safeguards]) as unknown as string[],
  }));
}

function policyRank(outcome: PolicyOutcome): number {
  return outcome === "deny" ? 2 : outcome === "requires_approval" ? 1 : 0;
}

export function buildCouncilSummary(
  event: Readonly<SyntheticSecurityEvent>,
  policyDecision: Readonly<PolicyDecision>,
  reports: readonly AgentAssessment[],
): CouncilSummary {
  const validated = validateCouncilReports(event, reports);
  const voteCounts = {
    allowSimulation: validated.filter(({ vote }) => vote === "allow_simulation").length,
    requiresApproval: validated.filter(({ vote }) => vote === "requires_approval").length,
    deny: validated.filter(({ vote }) => vote === "deny").length,
  };
  const quorum = { required: 5, received: validated.length, met: validated.length === 5 };
  let advisory: PolicyOutcome = "requires_approval";
  if (!quorum.met) advisory = "deny";
  else if (voteCounts.deny >= 3) advisory = "deny";
  else if (voteCounts.requiresApproval + voteCounts.deny >= 3) advisory = "requires_approval";
  else advisory = "allow_simulation";

  const recommendation = policyRank(policyDecision.outcome) > policyRank(advisory)
    ? policyDecision.outcome
    : advisory;
  const policyVeto = recommendation !== advisory;
  const matching = validated.filter(({ vote }) => vote === recommendation);
  const consensus: CouncilSummary["consensus"] = !quorum.met
    ? "no_quorum"
    : policyVeto
      ? "policy_veto"
      : matching.length === validated.length
        ? "unanimous"
        : "qualified_majority";

  return {
    eventId: event.id,
    consensus,
    recommendation,
    quorum,
    agreement: Math.round((matching.length / validated.length) * 100),
    risk: riskFromSeverity(event.severity),
    confidence: Math.round(validated.reduce((sum, report) => sum + report.confidence, 0) / validated.length),
    votes: voteCounts,
    explanation: [
      `${validated.length}/5 unique agent reports passed council validation.`,
      `Vote tally: ${voteCounts.allowSimulation} allow, ${voteCounts.requiresApproval} hold, ${voteCounts.deny} deny.`,
      policyDecision.explanation,
      ...(policyVeto ? ["Policy Guard applied the stricter decision and vetoed broader agent advice."] : []),
      ...(!policyVeto && recommendation !== policyDecision.outcome
        ? ["The validated council applied a stricter safety recommendation than the initial policy result."]
        : []),
    ],
    dissentingAgents: validated.filter(({ vote }) => vote !== recommendation).map(({ agentId }) => agentId),
  };
}

function effectiveDecisionFromCouncil(
  policyDecision: Readonly<PolicyDecision>,
  council: Readonly<CouncilSummary>,
): PolicyDecision {
  if (policyRank(council.recommendation) <= policyRank(policyDecision.outcome)) {
    return { ...policyDecision };
  }

  if (council.recommendation === "deny") {
    return {
      outcome: "deny",
      explanation: "The validated council issued a stricter denial; Policy Guard kept the cycle fail-closed.",
      reasonCode: "COUNCIL_DENY_RECORDED",
      approvalRequired: false,
    };
  }

  return {
    outcome: "requires_approval",
    explanation: "The validated council requested human review; the state-only simulation remains blocked.",
    reasonCode: "COUNCIL_HUMAN_APPROVAL_REQUIRED",
    approvalRequired: true,
  };
}

export function createInitialDemoState(): DashboardState {
  return {
    revision: 0,
    status: "protected",
    metrics: { detected: 0, mitigated: 0, pendingApprovals: 0, criticalBreaches: 0 },
    policy: POLICY_PROFILE,
    council: null,
    agents: AGENT_DEFINITIONS.map((agent) => ({
      id: agent.id,
      name: agent.name,
      role: agent.role,
      level: agent.level,
      mission: agent.mission,
      capabilities: [...agent.capabilities],
      status: "ready",
      lastAction: "Advanced deterministic policy loaded",
      stats: { assessments: 0, consensusAlignment: 100, trust: agent.baselineTrust },
      assessment: null,
    })),
    pendingApprovalItems: [],
    recentApprovalDecisions: [],
    timeline: [{
      id: "lab-ready",
      time: "READY",
      title: "Creluna safe laboratory online",
      detail: "Five-agent council · policy veto · no external or offensive actions",
      severity: "info",
    }],
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
  return iso.match(/T(\d{2}:\d{2}:\d{2})/)?.[1] ?? "LAB";
}

function createIncident(event: SyntheticSecurityEvent, decision: PolicyDecision): LabIncident {
  const status: LabIncident["status"] = decision.outcome === "requires_approval"
    ? "pending_approval"
    : decision.outcome === "allow_simulation"
      ? event.requestedAction === "observe" ? "observed" : "contained"
      : "denied";
  return {
    id: `${event.id}:incident`,
    eventId: event.id,
    status,
    impact: status === "pending_approval" ? "unconfirmed" : "none",
    approvalStatus: status === "pending_approval" ? "pending" : "not_required",
    publicSummary: status === "pending_approval"
      ? "Proposal recorded for an authorized human; no action executed"
      : status === "contained"
        ? "State-only defensive simulation recorded inside the lab"
        : status === "denied"
          ? "Policy Guard denied the proposal; no action executed"
          : "Read-only laboratory observation recorded",
    openedAt: event.occurredAt,
    resolvedAt: status === "pending_approval" ? null : event.occurredAt,
    updatedAt: event.occurredAt,
  };
}

function createPendingApproval(
  event: SyntheticSecurityEvent,
  decision: PolicyDecision,
  council: CouncilSummary,
): PendingApprovalItem | null {
  if (decision.outcome !== "requires_approval") return null;
  return {
    id: `${event.id}:approval`,
    eventId: event.id,
    scenarioId: event.scenarioId,
    title: event.title,
    severity: event.severity,
    requestedAction: event.requestedAction,
    status: "pending",
    policyVersion: POLICY_PROFILE.version,
    createdAt: event.occurredAt,
    councilRecommendation: council.recommendation,
    explanation: "This state-only simulation is blocked until one explicit human decision is recorded.",
  };
}

function finalizeDefenseCycle(
  previous: DashboardState,
  event: SyntheticSecurityEvent,
  decision: PolicyDecision,
  assessments: readonly AgentAssessment[],
  council: CouncilSummary,
  sequence: number,
): DefenseCycleResult {
  const incident = createIncident(event, decision);
  const approval = createPendingApproval(event, decision, council);
  const pendingApprovalItems = approval
    ? [approval, ...previous.pendingApprovalItems]
    : previous.pendingApprovalItems;
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
  const latestAssessment = new Map(assessments.map((assessment) => [assessment.agentId, assessment]));
  const snapshot: DashboardState = {
    ...previous,
    revision: Math.max(previous.revision + 1, sequence),
    status: pendingApprovalItems.length > 0
      ? "review"
      : decision.outcome === "deny" || event.severity === "high" ? "attention" : "protected",
    metrics: {
      detected: previous.metrics.detected + 1,
      mitigated: previous.metrics.mitigated + (decision.outcome === "allow_simulation" ? 1 : 0),
      pendingApprovals: pendingApprovalItems.length,
      criticalBreaches: previous.metrics.criticalBreaches,
    },
    policy: POLICY_PROFILE,
    council,
    agents: previous.agents.map((agent) => {
      const assessment = latestAssessment.get(agent.id);
      if (!assessment) return agent;
      const nextCount = agent.stats.assessments + 1;
      const aligned = assessment.vote === council.recommendation ? 100 : 0;
      return {
        ...agent,
        status: assessment.verdict === "contain_simulation" || assessment.verdict === "hold_for_human" ? "engaged" : "ready",
        lastAction: assessment.rationale,
        stats: {
          assessments: nextCount,
          consensusAlignment: Math.round(((agent.stats.consensusAlignment * agent.stats.assessments) + aligned) / nextCount),
          trust: assessment.trust,
        },
        assessment: {
          verdict: assessment.verdict,
          vote: assessment.vote,
          risk: assessment.risk,
          confidence: assessment.confidence,
          trust: assessment.trust,
          rationale: assessment.rationale,
          evidence: [...assessment.evidence],
          safeguards: [...assessment.safeguards],
        },
      };
    }),
    pendingApprovalItems,
    timeline: [{
      id: event.id,
      time: safeClockLabel(event.occurredAt),
      title: event.title,
      detail: decision.outcome === "requires_approval"
        ? `${event.detail} · blocked for human approval`
        : `${event.detail} · council ${council.consensus}`,
      severity: event.severity,
    }, ...previous.timeline.filter((item) => item.id !== "lab-ready")].slice(0, 12),
    audit: [...previous.audit, {
      eventId: event.id,
      action: event.requestedAction,
      decision: decision.outcome,
      reasonCode: decision.reasonCode,
    }].slice(-100),
  };
  return {
    event,
    decision,
    assessments,
    council,
    incident,
    approval,
    audit,
    snapshot,
    execution: {
      scope: "state_only_lab_simulation",
      externalNetworkAction: false,
      offensiveAction: false,
      privilegedAction: false,
    },
  };
}

function createScenarioEvent(scenarioId: SafeScenarioId, context: DefenseCycleContext): SyntheticSecurityEvent {
  const definition = SCENARIOS[scenarioId];
  return { ...definition, id: context.eventId, occurredAt: context.now };
}

export function runNamedLabScenario(
  previous: DashboardState,
  scenarioId: SafeScenarioId,
  context: DefenseCycleContext,
): DefenseCycleResult {
  const event = createScenarioEvent(scenarioId, context);
  const decision = Object.freeze(evaluateDemoAction(event));
  const assessments = deterministicLabAgentCouncil.assess(Object.freeze(event), decision);
  if (assessments instanceof Promise) throw new Error("The deterministic lab council must be synchronous.");
  const validated = validateCouncilReports(event, assessments, deterministicLabAgentCouncil.provider);
  const council = buildCouncilSummary(event, decision, validated);
  const effectiveDecision = effectiveDecisionFromCouncil(decision, council);
  return finalizeDefenseCycle(previous, event, effectiveDecision, validated, council, context.sequence);
}

export async function runNamedLabScenarioWithCouncil(
  previous: DashboardState,
  scenarioId: SafeScenarioId,
  context: DefenseCycleContext,
  councilProvider: AgentCouncil,
): Promise<DefenseCycleResult> {
  const event = createScenarioEvent(scenarioId, context);
  const decision = Object.freeze(evaluateDemoAction(event));
  const reports = await councilProvider.assess(Object.freeze(event), decision);
  const validated = validateCouncilReports(event, reports, councilProvider.provider);
  const council = buildCouncilSummary(event, decision, validated);
  const effectiveDecision = effectiveDecisionFromCouncil(decision, council);
  return finalizeDefenseCycle(previous, event, effectiveDecision, validated, council, context.sequence);
}

export function resolveApprovalInState(
  previous: DashboardState,
  approvalId: string,
  decision: ApprovalDecision,
  now: string,
): ApprovalResolutionResult {
  const approval = previous.pendingApprovalItems.find((item) => item.id === approvalId);
  if (!approval) throw new Error("APPROVAL_NOT_PENDING");
  const record: ApprovalDecisionRecord = {
    id: `${approval.id}:decision`,
    approvalId: approval.id,
    eventId: approval.eventId,
    decision,
    scope: "state_only_lab_simulation",
    executedExternalAction: false,
    decidedAt: now,
  };
  const outcome: PolicyOutcome = decision === "approve_simulation" ? "allow_simulation" : "deny";
  const reasonCode: PolicyDecision["reasonCode"] = decision === "approve_simulation"
    ? "HUMAN_APPROVAL_RECORDED"
    : "HUMAN_REJECTION_RECORDED";
  const detail = decision === "approve_simulation"
    ? "Human authorized a state-only lab simulation; no external or privileged action was executed."
    : "Human rejected the proposal; no action was executed.";
  const audit: AuditEntry = {
    id: `${approval.eventId}:audit:2`,
    eventId: approval.eventId,
    sequence: 2,
    actor: "human-operator",
    action: approval.requestedAction,
    outcome,
    reasonCode,
    detail,
    createdAt: now,
  };
  const remaining = previous.pendingApprovalItems.filter((item) => item.id !== approvalId);
  const resolutionSeverity: Severity = decision === "approve_simulation" ? "low" : "info";
  const snapshot: DashboardState = {
    ...previous,
    revision: previous.revision + 1,
    status: remaining.length > 0 ? "review" : "protected",
    metrics: {
      ...previous.metrics,
      mitigated: previous.metrics.mitigated + (decision === "approve_simulation" ? 1 : 0),
      pendingApprovals: remaining.length,
    },
    agents: previous.agents.map((agent) => ({ ...agent, status: "ready" as const })),
    pendingApprovalItems: remaining,
    recentApprovalDecisions: [record, ...previous.recentApprovalDecisions].slice(0, 20),
    timeline: [{
      id: record.id,
      time: safeClockLabel(now),
      title: decision === "approve_simulation" ? "State-only simulation approved" : "Simulation proposal rejected",
      detail,
      severity: resolutionSeverity,
    }, ...previous.timeline].slice(0, 12),
    audit: [...previous.audit, {
      eventId: approval.eventId,
      action: approval.requestedAction,
      decision: outcome,
      reasonCode,
    }].slice(-100),
  };
  return {
    record,
    audit,
    snapshot,
    execution: {
      scope: "state_only_lab_simulation",
      externalNetworkAction: false,
      offensiveAction: false,
      privilegedAction: false,
    },
  };
}

export function runDemoDefenseCycle(previous: DashboardState, cycle: number): DashboardState {
  const normalizedCycle = Number.isInteger(cycle) && cycle > 0 ? cycle : 1;
  const scenarioId = SAFE_SCENARIO_IDS[(normalizedCycle - 1) % SAFE_SCENARIO_IDS.length];
  const second = normalizedCycle % 60;
  return runNamedLabScenario(previous, scenarioId, {
    eventId: `client-demo-${normalizedCycle}`,
    sequence: normalizedCycle,
    now: `2026-08-15T14:22:${String(second).padStart(2, "0")}Z`,
  }).snapshot;
}
