import assert from "node:assert/strict";
import test from "node:test";

import {
  createInitialDemoState,
  evaluateDemoAction,
  runDemoDefenseCycle,
} from "../lib/creluna/defense-engine.ts";

const baseEvent = {
  id: "event-1",
  title: "Synthetic test",
  detail: "Test-only event",
  severity: "medium",
  confidence: 0.92,
  independentSignals: 2,
  demoAsset: "identity-lab-01",
  requestedAction: "rate_limit_demo_session",
};

test("allows only an evidenced, scoped demo rate limit", () => {
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

test("requires human approval for high-impact demo actions", () => {
  assert.equal(
    evaluateDemoAction({
      ...baseEvent,
      requestedAction: "quarantine_demo_asset",
    }).outcome,
    "requires_approval",
  );
  assert.equal(
    evaluateDemoAction({
      ...baseEvent,
      requestedAction: "restore_demo_snapshot",
    }).outcome,
    "requires_approval",
  );
});

test("rejects assets outside the authorized laboratory boundary", () => {
  assert.equal(
    evaluateDemoAction({
      ...baseEvent,
      demoAsset: "external-production-server",
    }).outcome,
    "deny",
  );
});

test("records every simulated policy decision in the audit trail", () => {
  const initial = createInitialDemoState();
  const next = runDemoDefenseCycle(initial, 1);

  assert.equal(next.audit.length, 1);
  assert.equal(next.metrics.criticalBreaches, 0);
  assert.ok(next.metrics.detected > initial.metrics.detected);
});
