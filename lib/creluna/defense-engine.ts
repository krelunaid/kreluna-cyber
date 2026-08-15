export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type SystemStatus = "protected" | "attention" | "review";

export type SafeAction =
  | "observe"
  | "tag_demo_session"
  | "notify_operator"
  | "rate_limit_demo_session"
  | "route_to_internal_decoy"
  | "quarantine_demo_asset"
  | "restore_demo_snapshot";

export interface SyntheticSecurityEvent {
  id: string;
  title: string;
  detail: string;
  severity: Severity;
  confidence: number;
  independentSignals: number;
  demoAsset: "vault-web-01" | "vault-api-01" | "identity-lab-01";
  requestedAction: SafeAction;
}

export interface PolicyDecision {
  outcome: "allow_simulation" | "requires_approval" | "deny";
  explanation: string;
}

export interface AgentState {
  id: "aegis" | "argine" | "orbit" | "decoy" | "phoenix";
  name: string;
  role: string;
  status: "ready" | "engaged";
  lastAction: string;
}

export interface TimelineEvent {
  id: string;
  time: string;
  title: string;
  detail: string;
  severity: Severity;
}

export interface DashboardState {
  status: SystemStatus;
  metrics: {
    detected: number;
    mitigated: number;
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
    decision: PolicyDecision["outcome"];
  }>;
}

const AUTHORIZED_DEMO_ASSETS = new Set([
  "vault-web-01",
  "vault-api-01",
  "identity-lab-01",
]);

const scenarios: SyntheticSecurityEvent[] = [
  {
    id: "scenario-auth-burst",
    title: "Suspicious authentication burst",
    detail: "Synthetic session scoped and rate-limited for 300 seconds",
    severity: "medium",
    confidence: 0.91,
    independentSignals: 3,
    demoAsset: "identity-lab-01",
    requestedAction: "rate_limit_demo_session",
  },
  {
    id: "scenario-api-input",
    title: "Abnormal API input contained",
    detail: "Request signature preserved; sensitive fields were redacted",
    severity: "high",
    confidence: 0.94,
    independentSignals: 2,
    demoAsset: "vault-api-01",
    requestedAction: "route_to_internal_decoy",
  },
  {
    id: "scenario-integrity",
    title: "Integrity signal requires review",
    detail: "Quarantine proposal held for human authorization",
    severity: "high",
    confidence: 0.97,
    independentSignals: 3,
    demoAsset: "vault-web-01",
    requestedAction: "quarantine_demo_asset",
  },
  {
    id: "scenario-health",
    title: "Defense mesh synchronized",
    detail: "Policy, recovery and audit planes report healthy",
    severity: "info",
    confidence: 1,
    independentSignals: 4,
    demoAsset: "vault-web-01",
    requestedAction: "observe",
  },
];

export function evaluateDemoAction(
  event: SyntheticSecurityEvent,
): PolicyDecision {
  if (!AUTHORIZED_DEMO_ASSETS.has(event.demoAsset)) {
    return {
      outcome: "deny",
      explanation: "Target is outside the authorized demo boundary.",
    };
  }

  if (event.confidence < 0 || event.confidence > 1) {
    return {
      outcome: "deny",
      explanation: "Confidence must be between zero and one.",
    };
  }

  if (
    event.requestedAction === "quarantine_demo_asset" ||
    event.requestedAction === "restore_demo_snapshot"
  ) {
    return {
      outcome: "requires_approval",
      explanation: "High-impact demo actions always require a human.",
    };
  }

  if (event.requestedAction === "route_to_internal_decoy") {
    return {
      outcome: "requires_approval",
      explanation: "Internal deception requires explicit authorization.",
    };
  }

  if (event.requestedAction === "rate_limit_demo_session") {
    if (event.confidence >= 0.85 && event.independentSignals >= 2) {
      return {
        outcome: "allow_simulation",
        explanation: "Scoped and reversible demo rate limit allowed.",
      };
    }

    return {
      outcome: "deny",
      explanation: "Rate limit evidence threshold was not met.",
    };
  }

  return {
    outcome: "allow_simulation",
    explanation: "Low-impact observational action allowed.",
  };
}

export function createInitialDemoState(): DashboardState {
  return {
    status: "protected",
    metrics: {
      detected: 128_421,
      mitigated: 127_984,
      criticalBreaches: 0,
    },
    agents: [
      {
        id: "aegis",
        name: "AEGIS",
        role: "Correlation & evidence",
        status: "ready",
        lastAction: "4,208 signals correlated",
      },
      {
        id: "argine",
        name: "ARGINE",
        role: "Scoped containment",
        status: "ready",
        lastAction: "Policy boundary enforced",
      },
      {
        id: "orbit",
        name: "ORBIT",
        role: "Identity protection",
        status: "ready",
        lastAction: "Session graph verified",
      },
      {
        id: "decoy",
        name: "DECOY",
        role: "Internal deception",
        status: "ready",
        lastAction: "Lab route isolated",
      },
      {
        id: "phoenix",
        name: "PHOENIX",
        role: "Recovery orchestration",
        status: "ready",
        lastAction: "Clean snapshot verified",
      },
    ],
    timeline: [
      {
        id: "initial-01",
        time: "14:21:46",
        title: "Threat detected → blocked",
        detail: "Synthetic request · no raw payload retained",
        severity: "medium",
      },
      {
        id: "initial-02",
        time: "14:20:19",
        title: "Authentication anomaly → contained",
        detail: "Demo session isolated by deterministic policy",
        severity: "high",
      },
      {
        id: "initial-03",
        time: "14:18:05",
        title: "Public projection synchronized",
        detail: "Sanitized aggregate snapshot published",
        severity: "info",
      },
      {
        id: "initial-04",
        time: "14:15:32",
        title: "Recovery checkpoint verified",
        detail: "PHOENIX validated clean demo state",
        severity: "low",
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

export function runDemoDefenseCycle(
  previous: DashboardState,
  cycle: number,
): DashboardState {
  const scenario = scenarios[cycle % scenarios.length];
  const decision = evaluateDemoAction(scenario);
  const isMitigated = decision.outcome === "allow_simulation";
  const activeAgentIndex = cycle % previous.agents.length;
  const seconds = 8 + cycle * 3;
  const minuteOffset = Math.floor(seconds / 60);
  const secondValue = seconds % 60;
  const time = `14:${String(22 + minuteOffset).padStart(2, "0")}:${String(secondValue).padStart(2, "0")}`;

  return {
    ...previous,
    status:
      decision.outcome === "requires_approval"
        ? "review"
        : scenario.severity === "medium" || scenario.severity === "high"
          ? "attention"
          : "protected",
    metrics: {
      ...previous.metrics,
      detected: previous.metrics.detected + scenario.independentSignals,
      mitigated: previous.metrics.mitigated + (isMitigated ? 1 : 0),
    },
    agents: previous.agents.map((agent, index) => ({
      ...agent,
      status: index === activeAgentIndex ? "engaged" : "ready",
      lastAction:
        index === activeAgentIndex
          ? decision.explanation
          : agent.lastAction,
    })),
    timeline: [
      {
        id: `${scenario.id}-${cycle}`,
        time,
        title: scenario.title,
        detail:
          decision.outcome === "requires_approval"
            ? `${scenario.detail} · approval required`
            : scenario.detail,
        severity: scenario.severity,
      },
      ...previous.timeline,
    ].slice(0, 4),
    audit: [
      ...previous.audit,
      {
        eventId: `${scenario.id}-${cycle}`,
        action: scenario.requestedAction,
        decision: decision.outcome,
      },
    ].slice(-40),
  };
}
