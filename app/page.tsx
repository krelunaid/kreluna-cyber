"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createInitialDemoState,
  runDemoDefenseCycle,
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
      "Propone l'instradamento verso un'esca interna isolata, soltanto dopo l'autorizzazione prevista.",
    boundary: "Honeypot interno · approvazione umana",
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
  | "local_fallback";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function connectionFromPayload(payload: unknown): ConnectionState {
  if (!isRecord(payload)) return "local_fallback";
  if (payload.persistence === "d1") return "d1";
  if (payload.persistence === "memory_fallback") return "memory_fallback";
  return "local_fallback";
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

  return {
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
    agents: fallback.agents.map((agent) => {
      const incoming = incomingAgents.find((item) => item.id === agent.id);
      return {
        ...agent,
        status:
          incoming?.status === "engaged" || incoming?.status === "ready"
            ? incoming.status
            : agent.status,
        lastAction: sanitizePublicText(
          incoming?.lastAction,
          agent.lastAction,
          110,
        ),
      };
    }),
    timeline:
      incomingTimeline.length > 0
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
              detail: sanitizePublicText(
                event.detail,
                "Public detail withheld by policy",
                170,
              ),
              severity,
            };
          })
        : fallback.timeline,
    researchers:
      incomingResearchers.length > 0
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
    audit: [],
  };
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
  tone?: "blue" | "green" | "violet";
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

function AgentRow({ agent }: { agent: AgentState }) {
  const brief = agentBriefs[agent.id];

  return (
    <article className={`agent-row agent-${agent.status}`}>
      <div className="agent-mark" aria-hidden="true">
        {agentIcons[agent.id]}
      </div>
      <div className="agent-copy">
        <div className="agent-title-line">
          <strong>{agent.name}</strong>
          <span>{agent.status === "engaged" ? "ENGAGED" : "READY"}</span>
        </div>
        <p>
          {brief.phase} · {agent.role}
        </p>
        <small>{agent.lastAction}</small>
      </div>
    </article>
  );
}

export default function Home() {
  const [state, setState] = useState<DashboardState>(() =>
    createInitialDemoState(),
  );
  const [isLive, setIsLive] = useState(true);
  const localCycle = useRef(0);
  const [connection, setConnection] =
    useState<ConnectionState>("connecting");
  const [selectedScenario, setSelectedScenario] = useState<string>(
    safeScenarios[0].id,
  );
  const [isSimulating, setIsSimulating] = useState(false);
  const [secondsRemaining, setSecondsRemaining] = useState(
    3 * 24 * 60 * 60 + 14 * 60 * 60 + 22 * 60 + 8,
  );

  const runLocalCycle = useCallback(() => {
    localCycle.current += 1;
    setState((previous) =>
      runDemoDefenseCycle(previous, localCycle.current),
    );
  }, []);

  const hydrateFromApi = useCallback(async (signal?: AbortSignal) => {
    try {
      const response = await fetch("/api/security", {
        cache: "no-store",
        headers: { Accept: "application/json" },
        signal,
      });
      if (!response.ok) throw new Error("Public snapshot unavailable");

      const payload: unknown = await response.json();
      const normalized = normalizePublicSnapshot(
        payload,
        createInitialDemoState(),
      );
      if (!normalized) throw new Error("Invalid public snapshot");

      setState(normalized);
      setConnection(connectionFromPayload(payload));
      return true;
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        return false;
      }
      setConnection("local_fallback");
      return false;
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    const kickoff = window.setTimeout(() => {
      void hydrateFromApi(controller.signal);
    }, 0);
    return () => {
      window.clearTimeout(kickoff);
      controller.abort();
    };
  }, [hydrateFromApi]);

  useEffect(() => {
    if (!isLive) return;

    const timer = window.setInterval(async () => {
      const hydrated = await hydrateFromApi();
      if (!hydrated) runLocalCycle();
    }, 6000);

    return () => window.clearInterval(timer);
  }, [hydrateFromApi, isLive, runLocalCycle]);

  useEffect(() => {
    if (!isLive) return;
    const timer = window.setInterval(() => {
      setSecondsRemaining((value) => Math.max(0, value - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [isLive]);

  const simulateSafeEvent = useCallback(async () => {
    if (isSimulating) return;
    setIsSimulating(true);

    try {
      const response = await fetch("/api/security", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ scenario: selectedScenario }),
      });
      if (!response.ok) throw new Error("Safe simulation unavailable");

      const payload: unknown = await response.json();
      const normalized = normalizePublicSnapshot(payload, state);
      if (!normalized) throw new Error("Invalid public simulation response");

      setState(normalized);
      setConnection(connectionFromPayload(payload));
    } catch {
      runLocalCycle();
      setConnection("local_fallback");
    } finally {
      const scenarioIndex = safeScenarios.findIndex(
        (scenario) => scenario.id === selectedScenario,
      );
      setSelectedScenario(
        safeScenarios[(scenarioIndex + 1) % safeScenarios.length].id,
      );
      setIsSimulating(false);
    }
  }, [isSimulating, runLocalCycle, selectedScenario, state]);

  const countdown = useMemo(() => {
    const days = Math.floor(secondsRemaining / 86400);
    const hours = Math.floor((secondsRemaining % 86400) / 3600);
    const minutes = Math.floor((secondsRemaining % 3600) / 60);
    const seconds = secondsRemaining % 60;
    return `${String(days).padStart(2, "0")}D · ${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  }, [secondsRemaining]);

  const statusLabel =
    state.status === "protected"
      ? "VAULT PROTECTED"
      : state.status === "attention"
        ? "THREAT CONTAINED"
        : "OPERATOR REVIEW";

  return (
    <main className={`command-center status-${state.status}`}>
      <div className="ambient-grid" aria-hidden="true" />

      <header className="command-header">
        <div className="brand-lockup">
          <span className="brand-glyph" aria-hidden="true">
            C
          </span>
          <div>
            <p>CRELUNA CYBER</p>
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
        >
          <span aria-hidden="true" />
          {isLive ? "LIVE LAB" : "PAUSED"}
        </button>
      </header>

      <section className="demo-notice" aria-label="Avviso modalità dimostrativa">
        <span>SIMULATION MODE</span>
        <p>
          Eventi sintetici · azioni difensive limitate al laboratorio · dati
          pubblici sanitizzati
        </p>
        <strong>NO EXTERNAL COUNTERATTACK</strong>
      </section>

      <section className="metrics-grid" aria-label="Metriche principali">
        <MetricCard
          eyebrow="LAB SECURITY EVENTS"
          value={state.metrics.detected.toLocaleString("en-US")}
          note="sanitized synthetic events"
        />
        <MetricCard
          eyebrow="ALLOWED SIMULATIONS"
          value={state.metrics.mitigated.toLocaleString("en-US")}
          note="policy-approved state updates"
          tone="violet"
        />
        <MetricCard
          eyebrow="REVIEW QUEUE"
          value={String(state.metrics.pendingApprovals)}
          note="human approvals pending"
          tone="green"
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
                  : "LOCAL"
          }
          note={
            connection === "d1"
              ? "saved to private event memory"
              : connection === "memory_fallback"
                ? "ephemeral failsafe, not persisted"
                : connection === "connecting"
                  ? "verifying event storage"
                  : "browser-only simulation"
          }
          tone="green"
        />
      </section>

      <section className="operations-grid">
        <aside className="surface-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>01 / SYNTHETIC TELEMETRY</span>
              <h2>LAB SIGNAL MAP</h2>
            </div>
            <i className="status-light" aria-label="Telemetria sintetica attiva" />
          </div>

          <div className="radar-map" aria-label="Distribuzione sintetica degli eventi demo">
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
              <span>C</span>
            </div>
          </div>

          <div className="signal-bars" aria-label="Volume sintetico delle finestre demo">
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
              <dd>{isLive ? "6 sec" : "PAUSED"}</dd>
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
                    <small>CRELUNA SECURE CORE</small>
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
              {state.status === "protected"
                ? "All defensive layers are synchronized. No confirmed breach."
                : state.status === "attention"
                  ? "A synthetic threat was scoped, rate-limited and preserved for audit."
                  : "High-impact containment is waiting for human authorization."}
            </p>
          </div>

          <div className="vault-actions">
            <label className="scenario-picker">
              <span>SAFE SCENARIO</span>
              <select
                value={selectedScenario}
                onChange={(event) => setSelectedScenario(event.target.value)}
                disabled={isSimulating}
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
              disabled={isSimulating}
            >
              <span aria-hidden="true">＋</span>
              {isSimulating ? "RUNNING SAFE TEST" : "SIMULATE SAFE EVENT"}
            </button>
            <div className="policy-state">
              <span>
                {connection === "d1"
                  ? "DURABLE SECURITY API"
                  : connection === "memory_fallback"
                    ? "TEMPORARY MEMORY"
                    : connection === "connecting"
                      ? "SECURITY API"
                      : "LOCAL FAILSAFE"}
              </span>
              <strong>
                {connection === "connecting"
                  ? "CONNECTING"
                  : state.metrics.pendingApprovals > 0
                    ? `${state.metrics.pendingApprovals} APPROVAL PENDING`
                    : connection === "memory_fallback"
                      ? "NOT PERSISTED"
                      : connection === "local_fallback"
                        ? "OFFLINE DEMO"
                        : "POLICY ENFORCED"}
              </strong>
            </div>
          </div>
        </section>

        <aside className="agents-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>02 / AI COUNCIL</span>
              <h2>SUPER AGENTS</h2>
            </div>
            <span className="agent-count">5 ONLINE</span>
          </div>

          <div className="agent-list">
            {state.agents.map((agent) => (
              <AgentRow key={agent.id} agent={agent} />
            ))}
          </div>

          <div className="guardrail-card">
            <span>EXECUTION BOUNDARY</span>
            <strong>AI proposes. Policy decides.</strong>
            <p>Reversible, internal and fully audited actions only.</p>
          </div>
        </aside>
      </section>

      <section className="operator-overview glass-panel" aria-labelledby="operator-title">
        <div className="panel-heading operator-heading">
          <div>
            <span>03 / OPERATOR PLAYBOOK</span>
            <h2 id="operator-title">COME LAVORANO I 5 SUPER AGENTI</h2>
          </div>
          <p>
            Ogni agente ha un compito separato. Le proposte ad alto impatto si
            fermano davanti al Policy Guard e attendono un operatore umano.
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
              <span>04 / VERIFIED STREAM</span>
              <h2>LIVE EVENT TIMELINE</h2>
            </div>
            <span className="feed-state">SANITIZED</span>
          </div>

          <div className="timeline-list" aria-live="polite">
            {state.timeline.map((event) => (
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
            ))}
          </div>
        </section>

        <section className="leaderboard-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>05 / SEASON 01</span>
              <h2>RESEARCHER BOARD</h2>
            </div>
            <span className="feed-state">DEMO</span>
          </div>

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
        </section>
      </section>

      <footer className="command-footer">
        <p>
          PUBLIC PROJECTION <span>•</span> NO RAW IP <span>•</span> NO PAYLOADS{" "}
          <span>•</span> NO SECRETS
        </p>
        <p>CRELUNA DEFENSE ENGINE · SAFE LAB v0.2</p>
      </footer>
    </main>
  );
}
