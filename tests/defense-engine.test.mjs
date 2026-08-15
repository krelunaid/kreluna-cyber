import assert from "node:assert/strict";
import test from "node:test";

import {
  createInitialDemoState,
  evaluateDemoAction,
  listSafeLabScenarios,
  parseLabScenarioRequest,
  parseApprovalRequest,
  resolveApprovalInState,
  runDemoDefenseCycle,
  runNamedLabScenario,
  runNamedLabScenarioWithCouncil,
  SAFE_SCENARIO_IDS,
  validateCouncilReports,
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

test("a model-style council cannot weaken Policy Guard", async () => {
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
          vote: "allow_simulation",
          risk: "low",
          confidence: 100,
          trust: 100,
          score: 1,
          rationale: "Advisory output only",
          evidence: ["Validated synthetic evidence"],
          safeguards: ["Advisory only; no execution"],
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
  assert.equal(result.council.recommendation, "requires_approval");
  assert.equal(result.council.consensus, "policy_veto");
  assert.equal(result.incident.status, "pending_approval");
  assert.equal(result.execution.externalNetworkAction, false);
});

test("a stricter advisory denial becomes the effective fail-closed decision", async () => {
  const baseline = runNamedLabScenario(
    createInitialDemoState(),
    "recovery-check",
    context,
  );
  const denyCouncil = {
    provider: "advisory_model",
    async assess() {
      return baseline.assessments.map((report) => ({
        ...report,
        provider: "advisory_model",
        verdict: "monitor",
        vote: "deny",
        rationale: "Validated advisory denial for the state-only laboratory cycle.",
      }));
    },
  };

  const result = await runNamedLabScenarioWithCouncil(
    createInitialDemoState(),
    "recovery-check",
    context,
    denyCouncil,
  );

  assert.equal(result.council.recommendation, "deny");
  assert.equal(result.decision.outcome, "deny");
  assert.equal(result.decision.reasonCode, "COUNCIL_DENY_RECORDED");
  assert.equal(result.incident.status, "denied");
  assert.equal(result.snapshot.status, "attention");
  assert.equal(result.snapshot.metrics.mitigated, 0);
  assert.equal(result.audit.outcome, "deny");
  assert.equal(result.approval, null);
  assert.equal(result.execution.externalNetworkAction, false);
  assert.equal(result.execution.offensiveAction, false);
  assert.equal(result.execution.privilegedAction, false);
});

test("a stricter advisory hold creates a state-only human approval gate", async () => {
  const baseline = runNamedLabScenario(
    createInitialDemoState(),
    "recovery-check",
    context,
  );
  const holdCouncil = {
    provider: "advisory_model",
    async assess() {
      return baseline.assessments.map((report) => ({
        ...report,
        provider: "advisory_model",
        verdict: "hold_for_human",
        vote: "requires_approval",
        rationale: "Validated advisory hold for explicit human review.",
      }));
    },
  };

  const result = await runNamedLabScenarioWithCouncil(
    createInitialDemoState(),
    "recovery-check",
    context,
    holdCouncil,
  );

  assert.equal(result.council.recommendation, "requires_approval");
  assert.equal(result.decision.outcome, "requires_approval");
  assert.equal(
    result.decision.reasonCode,
    "COUNCIL_HUMAN_APPROVAL_REQUIRED",
  );
  assert.equal(result.incident.status, "pending_approval");
  assert.equal(result.snapshot.status, "review");
  assert.equal(result.snapshot.metrics.mitigated, 0);
  assert.equal(result.snapshot.metrics.pendingApprovals, 1);
  assert.equal(result.audit.outcome, "requires_approval");
  assert.equal(result.approval?.status, "pending");
  assert.equal(result.execution.scope, "state_only_lab_simulation");
  assert.equal(result.execution.externalNetworkAction, false);
  assert.equal(result.execution.offensiveAction, false);
  assert.equal(result.execution.privilegedAction, false);
});

test("publishes five specialized level-98+ agents and a validated 5-of-5 council", () => {
  const result = runNamedLabScenario(
    createInitialDemoState(),
    "authentication-burst",
    context,
  );

  assert.equal(result.council.quorum.required, 5);
  assert.equal(result.council.quorum.received, 5);
  assert.equal(result.council.quorum.met, true);
  assert.equal(new Set(result.assessments.map(({ agentId }) => agentId)).size, 5);
  assert.ok(result.snapshot.agents.every(({ level }) => level >= 98));
  assert.ok(result.snapshot.agents.every(({ mission, capabilities }) => mission.length > 20 && capabilities.length >= 3));
  assert.ok(result.snapshot.agents.every(({ assessment }) => assessment?.evidence.length >= 1));
});

test("rejects duplicate, missing or malformed council reports", () => {
  const result = runNamedLabScenario(
    createInitialDemoState(),
    "recovery-check",
    context,
  );
  assert.throws(
    () => validateCouncilReports(result.event, result.assessments.slice(0, 4)),
    /exactly five reports/,
  );
  const duplicate = [...result.assessments.slice(0, 4), result.assessments[0]];
  assert.throws(
    () => validateCouncilReports(result.event, duplicate),
    /schema or trust validation/,
  );
  const malformed = result.assessments.map((report, index) =>
    index === 0 ? { ...report, evidence: [123] } : report,
  );
  assert.throws(
    () => validateCouncilReports(result.event, malformed),
    /schema or trust validation/,
  );
});

test("approval parser is exact and resolution is one-shot state-only", () => {
  const valid = {
    approvalId: "event-approval:approval",
    decision: "approve_simulation",
    confirmation: "STATE_ONLY_LAB",
  };
  assert.deepEqual(parseApprovalRequest(valid), {
    ok: true,
    approvalId: valid.approvalId,
    decision: valid.decision,
  });
  assert.equal(parseApprovalRequest({ ...valid, target: "external" }).ok, false);
  assert.equal(parseApprovalRequest({ ...valid, confirmation: "YES" }).ok, false);

  const pending = runNamedLabScenario(
    createInitialDemoState(),
    "integrity-drift",
    { ...context, eventId: "event-approval" },
  ).snapshot;
  const approvalId = pending.pendingApprovalItems[0].id;
  const resolved = resolveApprovalInState(
    pending,
    approvalId,
    "approve_simulation",
    "2026-08-15T12:01:00.000Z",
  );
  assert.equal(resolved.snapshot.metrics.pendingApprovals, 0);
  assert.equal(resolved.snapshot.metrics.mitigated, 1);
  assert.equal(resolved.execution.externalNetworkAction, false);
  assert.equal(resolved.execution.offensiveAction, false);
  assert.equal(resolved.execution.privilegedAction, false);
  assert.throws(
    () => resolveApprovalInState(resolved.snapshot, approvalId, "reject", "2026-08-15T12:02:00.000Z"),
    /APPROVAL_NOT_PENDING/,
  );
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
