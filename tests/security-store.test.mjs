import assert from "node:assert/strict";
import test from "node:test";

import {
  createInitialDemoState,
  runGuardedLabEvent,
  runNamedLabScenario,
} from "../lib/creluna/defense-engine.ts";
import { InMemorySecurityStore } from "../lib/creluna/security-store.ts";

test("fallback store retains sanitized lab state and ignores duplicate event IDs", async () => {
  const store = new InMemorySecurityStore();
  const result = runNamedLabScenario(
    createInitialDemoState(),
    "api-input-anomaly",
    {
      eventId: "store-event-1",
      now: "2026-08-15T12:00:00.000Z",
      sequence: 1,
    },
  );

  await store.appendCycle(result);
  await store.appendCycle(result);
  const snapshot = await store.readSanitizedSnapshot();

  assert.equal(snapshot.metrics.detected, 1);
  assert.equal(snapshot.metrics.pendingApprovals, 0);
  assert.equal(snapshot.status, "protected");
  assert.equal(snapshot.autopilot.lastCycle?.outcome, "auto-contained");
  assert.equal(snapshot.autopilot.availability, "event_driven");
  assert.equal(snapshot.timeline[0].id, "store-event-1");
  assert.equal(JSON.stringify(snapshot).includes("payload"), false);
});

test("fallback reads return defensive copies", async () => {
  const store = new InMemorySecurityStore();
  const first = await store.readSanitizedSnapshot();
  first.metrics.detected = 99;
  first.agents[0].lastAction = "tampered";
  first.agents[0].capabilities[0] = "tampered nested capability";
  first.policy.id = "tampered-policy";

  const second = await store.readSanitizedSnapshot();
  assert.equal(second.metrics.detected, 0);
  assert.notEqual(second.agents[0].lastAction, "tampered");
  assert.notEqual(second.agents[0].capabilities[0], "tampered nested capability");
  assert.notEqual(second.policy.id, "tampered-policy");
});

test("fallback approval decision is atomic, one-shot and state-only", async () => {
  const store = new InMemorySecurityStore();
  const cycle = runGuardedLabEvent(
    createInitialDemoState(),
    {
      id: "approval-store-event",
      scenarioId: "recovery-check",
      title: "Manual recovery proposal",
      detail: "State-only restore remains operator-controlled",
      severity: "high",
      confidence: 1,
      independentSignals: 4,
      demoAsset: "vault-web-01",
      requestedAction: "restore_demo_snapshot",
      labOnly: true,
      occurredAt: "2026-08-15T12:00:00.000Z",
    },
    1,
  );
  await store.appendCycle(cycle);
  const approvalId = cycle.snapshot.pendingApprovalItems[0].id;
  const first = await store.resolveApproval(
    approvalId,
    "reject",
    "2026-08-15T12:01:00.000Z",
  );
  assert.equal(first.snapshot.metrics.pendingApprovals, 0);
  assert.equal(first.record.executedExternalAction, false);
  await assert.rejects(
    store.resolveApproval(approvalId, "approve_simulation", "2026-08-15T12:02:00.000Z"),
    /APPROVAL_ALREADY_RESOLVED/,
  );
});

test("fallback scenario idempotency replays without changing state", async () => {
  const store = new InMemorySecurityStore();
  const cycle = runNamedLabScenario(
    createInitialDemoState(),
    "recovery-check",
    {
      eventId: "idempotent-event",
      now: "2026-08-15T12:00:00.000Z",
      sequence: 1,
    },
  );
  const replay = {
    id: `scenario:${"a".repeat(64)}`,
    operation: "scenario",
    requestHash: "b".repeat(64),
    resourceId: cycle.event.id,
    createdAt: cycle.event.occurredAt,
  };
  await store.appendCycle(cycle, replay);
  await store.appendCycle(cycle, replay);
  assert.equal((await store.readSanitizedSnapshot()).metrics.detected, 1);
  assert.equal((await store.findReplay(replay.id)).resourceId, cycle.event.id);
});
