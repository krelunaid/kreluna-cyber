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
  runGuardedLabEvent,
  runGuardedLabEventWithCouncil,
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
  assert.ok(listSafeLabScenarios().every(({ requiresApproval }) => !requiresApproval));
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

test("allows only the four evidenced, reversible guarded-autopilot actions", () => {
  for (const requestedAction of [
    "observe",
    "rate_limit_demo_session",
    "route_to_internal_decoy",
    "quarantine_demo_asset",
  ]) {
    const decision = evaluateDemoAction({
      ...baseEvent,
      confidence: 0.97,
      independentSignals: 3,
      requestedAction,
    });
    assert.equal(decision.outcome, "allow_simulation");
    assert.equal(decision.approvalRequired, false);
  }

  assert.equal(evaluateDemoAction({ ...baseEvent, confidence: 0.5 }).outcome, "deny");
  assert.equal(evaluateDemoAction({ ...baseEvent, independentSignals: 1 }).outcome, "deny");
  assert.equal(evaluateDemoAction({ ...baseEvent, confidence: Number.NaN }).reasonCode, "INVALID_EVIDENCE");
  assert.equal(evaluateDemoAction({
    ...baseEvent,
    requestedAction: "observe",
    confidence: 0.84,
  }).outcome, "deny");
});

test("keeps restore manual-only and rejects every non-autopilot action", () => {
  const restore = evaluateDemoAction({
    ...baseEvent,
    requestedAction: "restore_demo_snapshot",
  });
  assert.equal(restore.outcome, "requires_approval");
  assert.equal(restore.approvalRequired, true);

  for (const requestedAction of ["tag_demo_session", "notify_operator", "counterattack"]) {
    const decision = evaluateDemoAction({ ...baseEvent, requestedAction });
    assert.equal(decision.outcome, "deny");
    assert.equal(decision.reasonCode, "ACTION_NOT_ALLOWLISTED");
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

test("all four named scenarios autonomously protect in event-driven, state-only mode", () => {
  const initial = createInitialDemoState();
  const untouched = structuredClone(initial);
  const expectedOutcomes = [
    "auto-contained",
    "auto-contained",
    "auto-contained",
    "observed",
  ];

  for (const [index, scenarioId] of SAFE_SCENARIO_IDS.entries()) {
    const scenarioContext = {
      ...context,
      eventId: `cycle-${index + 1}`,
      sequence: index + 1,
    };
    const first = runNamedLabScenario(initial, scenarioId, scenarioContext);
    const second = runNamedLabScenario(initial, scenarioId, scenarioContext);
    assert.deepEqual(first, second);
    assert.equal(first.decision.outcome, "allow_simulation");
    assert.equal(first.approval, null);
    assert.equal(first.snapshot.pendingApprovalItems.length, 0);
    assert.equal(first.snapshot.metrics.pendingApprovals, 0);
    assert.equal(first.snapshot.status, "protected");
    assert.equal(first.snapshot.autopilot.enabled, true);
    assert.equal(first.snapshot.autopilot.mode, "guarded_autopilot");
    assert.equal(first.snapshot.autopilot.availability, "event_driven");
    assert.equal(first.snapshot.autopilot.lastCycle?.outcome, expectedOutcomes[index]);
    assert.equal(first.snapshot.autopilot.postReviewOnly, true);
    assert.equal(first.council.quorum.required, 5);
    assert.equal(first.council.quorum.received, 5);
    assert.equal(first.council.quorum.met, true);
    assert.equal(first.execution.externalNetworkAction, false);
    assert.equal(first.execution.offensiveAction, false);
    assert.equal(first.execution.privilegedAction, false);
    assert.equal(first.assessments.length, 5);
    assert.ok(first.assessments.every(({ provider }) => provider === "deterministic_lab"));
  }

  assert.deepEqual(initial, untouched);
  assert.deepEqual(initial.autopilot.allowlist, [
    "observe",
    "rate_limit_demo_session",
    "route_to_internal_decoy",
    "quarantine_demo_asset",
  ]);
  assert.deepEqual(initial.autopilot.hardLimits, {
    stateOnly: true,
    labOnly: true,
    reversibleOnly: true,
    externalActions: false,
    offensiveActions: false,
    privilegedActions: false,
    networkExecution: false,
  });
});

test("a model-style council cannot weaken a Policy Guard deny", async () => {
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
  const deniedEvent = {
    ...baseEvent,
    id: "policy-deny-event",
    requestedAction: "counterattack",
  };
  const result = await runGuardedLabEventWithCouncil(
    createInitialDemoState(),
    deniedEvent,
    1,
    advisoryCouncil,
  );

  assert.equal(result.decision.outcome, "deny");
  assert.equal(result.council.recommendation, "deny");
  assert.equal(result.council.consensus, "policy_veto");
  assert.equal(result.incident.status, "denied");
  assert.equal(result.approval, null);
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

test("a stricter advisory hold fails closed without creating an autonomous approval", async () => {
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
  assert.equal(result.decision.outcome, "deny");
  assert.equal(
    result.decision.reasonCode,
    "COUNCIL_SAFETY_HOLD_RECORDED",
  );
  assert.equal(result.incident.status, "denied");
  assert.equal(result.snapshot.status, "attention");
  assert.equal(result.snapshot.metrics.mitigated, 0);
  assert.equal(result.snapshot.metrics.pendingApprovals, 0);
  assert.equal(result.snapshot.autopilot.lastCycle?.outcome, "denied");
  assert.equal(result.audit.outcome, "deny");
  assert.equal(result.approval, null);
  assert.equal(result.execution.scope, "state_only_lab_simulation");
  assert.equal(result.execution.externalNetworkAction, false);
  assert.equal(result.execution.offensiveAction, false);
  assert.equal(result.execution.privilegedAction, false);
});

test("autopilot confidence floor fails closed even when all advisory votes allow", async () => {
  const baseline = runNamedLabScenario(
    createInitialDemoState(),
    "recovery-check",
    context,
  );
  const lowConfidenceCouncil = {
    provider: "advisory_model",
    async assess() {
      return baseline.assessments.map((report, index) => ({
        ...report,
        provider: "advisory_model",
        vote: "allow_simulation",
        confidence: index === 0 ? 84 : 100,
        rationale: "Schema-valid advisory report with insufficient autonomous confidence.",
      }));
    },
  };

  const result = await runNamedLabScenarioWithCouncil(
    createInitialDemoState(),
    "recovery-check",
    context,
    lowConfidenceCouncil,
  );

  assert.equal(result.council.recommendation, "allow_simulation");
  assert.equal(result.decision.outcome, "deny");
  assert.equal(result.decision.reasonCode, "COUNCIL_CONFIDENCE_GATE_FAILED");
  assert.equal(result.approval, null);
  assert.equal(result.snapshot.metrics.pendingApprovals, 0);
  assert.equal(result.snapshot.autopilot.lastCycle?.outcome, "denied");
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

  const pendingCycle = runGuardedLabEvent(
    createInitialDemoState(),
    {
      ...baseEvent,
      id: "event-approval",
      requestedAction: "restore_demo_snapshot",
    },
    1,
  );
  const pending = pendingCycle.snapshot;
  assert.equal(pendingCycle.decision.outcome, "requires_approval");
  assert.equal(pendingCycle.approval?.reviewMode, "blocking_manual");
  assert.equal(pending.autopilot.lastCycle?.outcome, "manual_review");
  assert.equal(pending.autopilot.postReviewOnly, false);
  assert.equal(pending.status, "review");
  const approvalId = pending.pendingApprovalItems[0].id;
  const resolved = resolveApprovalInState(
    pending,
    approvalId,
    "approve_simulation",
    "2026-08-15T12:01:00.000Z",
  );
  assert.equal(resolved.snapshot.metrics.pendingApprovals, 0);
  assert.equal(resolved.snapshot.metrics.mitigated, 1);
  assert.equal(resolved.snapshot.autopilot.postReviewOnly, true);
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

test("legacy non-restore pending is post-review and never makes protection look blocked", () => {
  const pending = createInitialDemoState();
  pending.status = "review";
  pending.metrics.pendingApprovals = 1;
  pending.pendingApprovalItems = [{
    id: "pending-approval:approval",
    eventId: "pending-approval",
    scenarioId: "api-input-anomaly",
    title: "Legacy API review",
    severity: "high",
    requestedAction: "route_to_internal_decoy",
    status: "pending",
    policyVersion: "3.0.0",
    createdAt: "2026-08-15T12:00:00.000Z",
    councilRecommendation: "requires_approval",
    explanation: "Legacy review retained.",
    reviewMode: "post_event",
  }];

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
  assert.equal(afterRecoveryCheck.pendingApprovalItems[0].reviewMode, "post_event");
  assert.equal(afterRecoveryCheck.autopilot.postReviewOnly, true);
  assert.equal(afterRecoveryCheck.status, "protected");
});
