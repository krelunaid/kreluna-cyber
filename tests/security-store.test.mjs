import assert from "node:assert/strict";
import test from "node:test";

import {
  createInitialDemoState,
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
  assert.equal(snapshot.metrics.pendingApprovals, 1);
  assert.equal(snapshot.status, "review");
  assert.equal(snapshot.timeline[0].id, "store-event-1");
  assert.equal(JSON.stringify(snapshot).includes("payload"), false);
});

test("fallback reads return defensive copies", async () => {
  const store = new InMemorySecurityStore();
  const first = await store.readSanitizedSnapshot();
  first.metrics.detected = 99;
  first.agents[0].lastAction = "tampered";

  const second = await store.readSanitizedSnapshot();
  assert.equal(second.metrics.detected, 0);
  assert.notEqual(second.agents[0].lastAction, "tampered");
});
