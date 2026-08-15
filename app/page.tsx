"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
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
        <p>{agent.role}</p>
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
  const [cycle, setCycle] = useState(0);
  const [secondsRemaining, setSecondsRemaining] = useState(
    3 * 24 * 60 * 60 + 14 * 60 * 60 + 22 * 60 + 8,
  );

  const runCycle = useCallback(() => {
    setCycle((current) => {
      const next = current + 1;
      setState((previous) => runDemoDefenseCycle(previous, next));
      return next;
    });
  }, []);

  useEffect(() => {
    if (!isLive) return;

    const timer = window.setInterval(() => {
      runCycle();
      setSecondsRemaining((value) => Math.max(0, value - 3));
    }, 3000);

    return () => window.clearInterval(timer);
  }, [isLive, runCycle]);

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
          eyebrow="SECURITY EVENTS"
          value={state.metrics.detected.toLocaleString("en-US")}
          note="deduplicated signals"
        />
        <MetricCard
          eyebrow="MITIGATED REQUESTS"
          value={state.metrics.mitigated.toLocaleString("en-US")}
          note="verified demo actions"
          tone="violet"
        />
        <MetricCard
          eyebrow="CRITICAL BREACHES"
          value={String(state.metrics.criticalBreaches)}
          note="confirmed impact"
          tone="green"
        />
        <MetricCard
          eyebrow="SYSTEM UPTIME"
          value="99.999%"
          note="control plane online"
          tone="green"
        />
      </section>

      <section className="operations-grid">
        <aside className="surface-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>01 / TELEMETRY</span>
              <h2>THREAT SURFACE</h2>
            </div>
            <i className="status-light" aria-label="Telemetria attiva" />
          </div>

          <div className="radar-map" aria-label="Distribuzione aggregata degli eventi demo">
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

          <div className="signal-bars" aria-label="Volume segnali delle ultime finestre">
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
              <dt>Active sessions</dt>
              <dd>2,418</dd>
            </div>
            <div>
              <dt>Authorized regions</dt>
              <dd>42</dd>
            </div>
            <div>
              <dt>Public data delay</dt>
              <dd>60 sec</dd>
            </div>
          </dl>
        </aside>

        <section className="vault-panel glass-panel" aria-labelledby="vault-title">
          <div className="vault-header">
            <span>CORE ASSET / TV-01</span>
            <span>INTEGRITY 100%</span>
          </div>

          <div className="vault-stage">
            <div className="vault-orbit orbit-one" aria-hidden="true" />
            <div className="vault-orbit orbit-two" aria-hidden="true" />
            <div className="vault-orbit orbit-three" aria-hidden="true" />
            <div className="vault-scanline" aria-hidden="true" />
            <div className="vault-core" aria-hidden="true">
              <div className="vault-door">
                <div className="vault-bolts">
                  <i />
                  <i />
                  <i />
                  <i />
                </div>
                <span>C</span>
                <small>TV-01</small>
              </div>
            </div>
          </div>

          <div className="vault-status-copy">
            <span className="status-kicker">AUTONOMOUS DEFENSE MESH</span>
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
            <button type="button" onClick={runCycle}>
              <span aria-hidden="true">＋</span>
              SIMULATE SAFE EVENT
            </button>
            <div>
              <span>POLICY GUARD</span>
              <strong>ENFORCED</strong>
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

      <section className="lower-grid">
        <section className="timeline-panel glass-panel">
          <div className="panel-heading">
            <div>
              <span>03 / VERIFIED STREAM</span>
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
              <span>04 / SEASON 01</span>
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
        <p>CRELUNA DEFENSE ENGINE · LAB FOUNDATION v0.1</p>
      </footer>
    </main>
  );
}
