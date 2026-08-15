import assert from "node:assert/strict";
import test from "node:test";

import {
  createInitialDemoState,
  evaluateDemoAction,
  listSafeLabScenarios,
  parseLabScenarioRequest,
  runDemoDefenseCycle,
  runNamedLabScenario,
  runNamedLabScenarioWithCouncil,
  SAFE_SCENARIO_IDS,
} from "../lib/creluna/defense-engine.ts";

const baseEvent = {
  id: "event-1",
  scenarioId: "authentication-burst",
  title: "Synthetic test",
  detail: "Test-only event",
  severity: "medium",
  confidence: 0.92,
  independentSignals: 2,
  demoAsset: "identity-lab-01",
  requestedAction: "rate_limit_demo_session",
  labOnly: true,
  occurredAt: "2026-08-15T12:00:00.000Z",
};

const context = {
  eventId: "cycle-1",
  now: "2026-08-15T12:00:00.000Z",
  sequence: 1,
};

test("publishes exactly four named, safe laboratory scenarios", () => {
  assert.deepEqual(
    listSafeLabScenarios().map(({ id }) => id),
    [...SAFE_SCENARIO_IDS],
  );
  assert.equal(new Set(SAFE_SCENARIO_IDS).size, 4);
});

test("API parser accepts only the exact {scenario} envelope", () => {
  assert.deepEqual(parseLabScenarioRequest({ scenario: "recovery-check" }), {
    ok: true,
    scenario: "recovery-check",
  });

  for (const unsafePayload of [
    { scenarioId: "recovery-check" },
    { scenario: "recovery-check", target: "example.com" },
    { scenario: "custom", action: "counterattack" },
    ["recovery-check"],
    null,
    "recovery-check",
  ]) {
    assert.equal(parseLabScenarioRequest(unsafePayload).ok, false);
  }
});

test("allows only an evidenced, scoped demo rate-limit simulation", () => {
  assert.equal(evaluateDemoAction(baseEvent).outcome, "allow_simulation");
  assert.equal(
    evaluateDemoAction({ ...baseEvent, confidence: 0.5 }).outcome,
    "deny",
  );
  assert.equal(
    evaluateDemoAction({ ...baseEvent, independentSignals: 1 }).outcome,
    "deny",
  );
});

test("requires human approval for every high-impact lab action", () => {
  for (const requestedAction of [
    "route_to_internal_decoy",
    "quarantine_demo_asset",
    "restore_demo_snapshot",
  ]) {
    const decision = evaluateDemoAction({ ...baseEvent, requestedAction });
    assert.equal(decision.outcome, "requires_approval");
    assert.equal(decision.approvalRequired, true);
  }
});

test("rejects non-lab assets, non-lab events and non-allowlisted actions", () => {
  assert.equal(
    evaluateDemoAction({
      ...baseEvent,
      demoAsset: "external-production-server",
    }).reasonCode,
    "OUTSIDE_LAB_BOUNDARY",
  );
  assert.equal(
    evaluateDemoAction({ ...baseEvent, labOnly: false }).outcome,
    "deny",
  );
  assert.equal(
    evaluateDemoAction({ ...baseEvent, requestedAction: "counterattack" })
      .reasonCode,
    "ACTION_NOT_ALLOWLISTED",
  );
});

test("named pipeline is deterministic, immutable and state-only", () => {
  const initial = createInitialDemoState();
  const untouched = structuredClone(initial);
  const first = runNamedLabScenario(
    initial,
    "authentication-burst",
    context,
  );
  const second = runNamedLabScenario(
    initial,
    "authentication-burst",
    context,
  );

  assert.deepEqual(first, second);
  assert.deepEqual(initial, untouched);
  assert.equal(first.execution.externalNetworkAction, false);
  assert.equal(first.execution.offensiveAction, false);
  assert.equal(first.assessments.length, 5);
  assert.ok(first.assessments.every(({ provider }) => provider === "deterministic_lab"));
});

test("a model-style council cannot override Policy Guard", async () => {
  const advisoryCouncil = {
    provider: "advisory_model",
    async assess(event) {
      return ["aegis", "argine", "orbit", "decoy", "phoenix"].map(
        (agentId) => ({
          id: `${event.id}:${agentId}`,
          eventId: event.id,
          agentId,
          agentName: agentId.toUpperCase(),
          provider: "advisory_model",
          verdict: "clear",
          score: 1,
          rationale: "Advisory output only",
        }),
      );
    },
  };
  const result = await runNamedLabScenarioWithCouncil(
    createInitialDemoState(),
    "integrity-drift",
    context,
    advisoryCouncil,
  );

  assert.equal(result.decision.outcome, "requires_approval");
  assert.equal(result.incident.status, "pending_approval");
  assert.equal(result.execution.externalNetworkAction, false);
});

test("records every simulated policy decision in the audit trail", () => {
  const initial = createInitialDemoState();
  const next = runDemoDefenseCycle(initial, 1);

  assert.equal(next.audit.length, 1);
  assert.equal(next.metrics.detected, 1);
  assert.equal(next.metrics.criticalBreaches, 0);
  assert.equal(next.revision, 1);
});

test("keeps the vault in review while an earlier approval is still pending", () => {
  const pending = runNamedLabScenario(
    createInitialDemoState(),
    "api-input-anomaly",
    {
      eventId: "pending-approval",
      now: "2026-08-15T12:00:00.000Z",
      sequence: 1,
    },
  ).snapshot;

  const afterRecoveryCheck = runNamedLabScenario(
    pending,
    "recovery-check",
    {
      eventId: "recovery-after-pending",
      now: "2026-08-15T12:01:00.000Z",
      sequence: 2,
    },
  ).snapshot;

  assert.equal(afterRecoveryCheck.metrics.pendingApprovals, 1);
  assert.equal(afterRecoveryCheck.status, "review");
});
