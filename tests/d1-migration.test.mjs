import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { drizzle } from "drizzle-orm/sqlite-proxy";

import * as schema from "../db/schema.ts";
import { D1SecurityStore } from "../lib/creluna/d1-security-store.ts";
import {
  createInitialDemoState,
  runNamedLabScenario,
} from "../lib/creluna/defense-engine.ts";

const migration0 = readFileSync(
  new URL("../drizzle/0000_new_whirlwind.sql", import.meta.url),
  "utf8",
);
const migration1 = readFileSync(
  new URL("../drizzle/0001_orange_tomorrow_man.sql", import.meta.url),
  "utf8",
);

function openMigratedDatabase(seedLegacy = () => {}) {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  sqlite.exec(migration0);
  seedLegacy(sqlite);
  sqlite.exec(migration1);
  return sqlite;
}

function createProxyDatabase(sqlite) {
  const callback = async (sql, params, method) => {
    const statement = sqlite.prepare(sql);
    statement.setReturnArrays(true);
    if (method === "run") {
      statement.run(...params);
      return { rows: [] };
    }
    if (method === "get") return { rows: statement.get(...params) };
    return { rows: statement.all(...params) };
  };
  return drizzle(callback, { schema });
}

function insertEvent(sqlite, {
  id,
  sequence,
  occurredAt,
  decision = "requires_approval",
  title = id,
}) {
  sqlite.prepare(`
    INSERT INTO security_events (
      id, sequence, scenario_id, title, public_summary, severity,
      confidence_bps, signal_count, asset_id, requested_action, decision,
      is_synthetic, occurred_at, created_at
    ) VALUES (?, ?, 'api-input-anomaly', ?, 'Sanitized test event', 'high',
      9300, 3, 'vault-api-01', 'quarantine_demo_asset', ?, 1, ?, ?)
  `).run(id, sequence, title, decision, occurredAt, occurredAt);
}

test("D1 append guard rejects unsafe execution flags and autonomous approval dependencies", async () => {
  const store = new D1SecurityStore({});
  const safe = runNamedLabScenario(
    createInitialDemoState(),
    "api-input-anomaly",
    {
      eventId: "append-guard",
      now: "2026-08-15T12:00:00.000Z",
      sequence: 1,
    },
  );

  await assert.rejects(
    store.appendCycle({
      ...safe,
      execution: { ...safe.execution, externalNetworkAction: true },
    }),
    /execution is forbidden/i,
  );
  await assert.rejects(
    store.appendCycle({
      ...safe,
      decision: {
        outcome: "requires_approval",
        explanation: "Fabricated blocking hold",
        reasonCode: "COUNCIL_HUMAN_APPROVAL_REQUIRED",
        approvalRequired: true,
      },
    }),
    /decision cannot weaken|cannot create a new blocking approval/i,
  );
  await assert.rejects(
    store.appendCycle({
      ...safe,
      event: { ...safe.event, labOnly: false },
    }),
    /council summary must match|decision cannot weaken/i,
  );
  await assert.rejects(
    store.appendCycle({
      ...safe,
      assessments: [...safe.assessments.slice(0, 4), safe.assessments[0]],
    }),
    /schema or trust validation/i,
  );
});

test("D1 migration backfills legacy approvals and rejects invalid enum state", () => {
  const sqlite = openMigratedDatabase((legacy) => {
    insertEvent(legacy, {
      id: "legacy-event",
      sequence: 1,
      occurredAt: "2026-08-15T12:00:00.000Z",
      title: "Legacy pending proposal",
    });
    legacy.exec(`
      INSERT INTO incidents (
        id, event_id, status, impact, approval_status, public_summary,
        opened_at, resolved_at, updated_at
      ) VALUES (
        'legacy-incident', 'legacy-event', 'pending_approval', 'unconfirmed',
        'pending', 'Legacy proposal awaiting a human',
        '2026-08-15T12:00:00.000Z', NULL, '2026-08-15T12:00:00.000Z'
      );
      INSERT INTO agent_assessments (
        id, event_id, agent_id, verdict, score_bps, rationale, created_at
      ) VALUES (
        'legacy-assessment', 'legacy-event', 'aegis', 'monitor', 7300,
        'Legacy sanitized rationale', '2026-08-15T12:00:00.000Z'
      );
      INSERT INTO audit_log (
        id, event_id, sequence, actor, action, outcome, reason_code, detail, created_at
      ) VALUES (
        'legacy-audit', 'legacy-event', 1, 'policy-guard',
        'quarantine_demo_asset', 'requires_approval', 'HUMAN_APPROVAL_REQUIRED',
        'Legacy proposal remained blocked', '2026-08-15T12:00:00.000Z'
      );
    `);
  });

  try {
    const approval = sqlite.prepare(`
      SELECT id, event_id, status, policy_version, council_recommendation, decided_at
      FROM approval_requests WHERE event_id = 'legacy-event'
    `).get();
    assert.deepEqual(
      { ...approval },
      {
        id: "legacy-event:approval",
        event_id: "legacy-event",
        status: "pending",
        policy_version: "2.0.0-legacy",
        council_recommendation: "requires_approval",
        decided_at: null,
      },
    );

    assert.throws(
      () => sqlite.exec("UPDATE approval_requests SET status = 'corrupt' WHERE event_id = 'legacy-event'"),
      /constraint/i,
    );
    assert.throws(
      () => sqlite.exec("UPDATE approval_requests SET requested_action = 'external_action' WHERE event_id = 'legacy-event'"),
      /constraint/i,
    );
    assert.throws(
      () => sqlite.exec("UPDATE security_events SET requested_action = 'external_action' WHERE id = 'legacy-event'"),
      /enum constraint/i,
    );
    assert.throws(
      () => sqlite.exec("UPDATE incidents SET approval_status = 'bypassed' WHERE id = 'legacy-incident'"),
      /enum constraint/i,
    );
    assert.throws(
      () => sqlite.exec("UPDATE audit_log SET actor = 'unknown-agent' WHERE id = 'legacy-audit'"),
      /enum constraint/i,
    );
    assert.throws(
      () => sqlite.exec(`
        INSERT INTO approval_decisions (
          id, approval_id, event_id, decision, scope, executed_external_action, decided_at
        ) VALUES (
          'bad-decision', 'legacy-event:approval', 'legacy-event', 'accept',
          'state_only_lab_simulation', 0, '2026-08-15T12:01:00.000Z'
        )
      `),
      /constraint/i,
    );
    assert.throws(
      () => sqlite.exec(`
        INSERT INTO idempotency_records (id, operation, request_hash, resource_id, created_at)
        VALUES ('other:key', 'other', '${"a".repeat(64)}', 'legacy-event', '2026-08-15T12:00:00.000Z')
      `),
      /constraint/i,
    );
    assert.deepEqual(sqlite.prepare("PRAGMA foreign_key_check").all(), []);
  } finally {
    sqlite.close();
  }
});

test("D1 snapshot scopes agent cards to the deterministic latest council and serves FIFO approvals", async () => {
  const sqlite = openMigratedDatabase();
  try {
    const agentIds = ["aegis", "argine", "orbit", "decoy", "phoenix"];
    for (const [eventIndex, eventId] of ["event-a", "event-b"].entries()) {
      insertEvent(sqlite, {
        id: eventId,
        sequence: 10,
        occurredAt: "2026-08-15T14:00:00.000Z",
        decision: "allow_simulation",
      });
      sqlite.prepare(`
        INSERT INTO council_decisions (
          id, event_id, consensus, recommendation, quorum_required, quorum_received,
          agreement_bps, risk, confidence_bps, allow_votes, approval_votes, deny_votes,
          explanation_json, dissenting_agents_json, created_at
        ) VALUES (?, ?, 'unanimous', 'allow_simulation', 5, 5, 10000, 'low',
          9500, 5, 0, 0, '["Validated council"]', '[]', '2026-08-15T14:00:00.000Z')
      `).run(`${eventId}:council`, eventId);
      for (const agentId of agentIds) {
        sqlite.prepare(`
          INSERT INTO agent_assessments (
            id, event_id, agent_id, verdict, vote, risk, score_bps,
            confidence_bps, trust_bps, rationale, evidence_json,
            safeguards_json, created_at
          ) VALUES (?, ?, ?, 'clear', 'allow_simulation', 'low', 9500,
            9500, 9900, ?, '["Evidence"]', '["Safeguard"]',
            '2026-08-15T14:00:00.000Z')
        `).run(
          `${eventId}:assessment:${agentId}`,
          eventId,
          agentId,
          `Council ${eventIndex === 0 ? "A" : "B"} assessment for ${agentId}`,
        );
      }
    }

    for (let index = 0; index < 60; index += 1) {
      const suffix = String(index).padStart(2, "0");
      const eventId = `pending-${suffix}`;
      const createdAt = `2026-08-16T00:${suffix}:00.000Z`;
      insertEvent(sqlite, { id: eventId, sequence: 20 + index, occurredAt: createdAt });
      sqlite.prepare(`
        INSERT INTO approval_requests (
          id, event_id, scenario_id, title, severity, requested_action, status,
          policy_version, council_recommendation, explanation, created_at, decided_at
        ) VALUES (?, ?, 'api-input-anomaly', ?, 'high', 'quarantine_demo_asset',
          'pending', '3.0.0', 'requires_approval',
          'State-only proposal awaiting human approval.', ?, NULL)
      `).run(`${eventId}:approval`, eventId, `Pending ${suffix}`, createdAt);
    }

    const store = new D1SecurityStore(createProxyDatabase(sqlite));
    const snapshot = await store.readSanitizedSnapshot();

    assert.equal(snapshot.council?.eventId, "event-b");
    assert.equal(snapshot.agents.length, 5);
    for (const agent of snapshot.agents) {
      assert.match(agent.assessment?.rationale ?? "", /^Council B assessment/);
      assert.equal(agent.stats.assessments, 2);
    }
    assert.equal(snapshot.metrics.pendingApprovals, 60);
    assert.equal(snapshot.pendingApprovalItems.length, 50);
    assert.equal(snapshot.pendingApprovalItems[0].id, "pending-00:approval");
    assert.equal(snapshot.pendingApprovalItems.at(-1)?.id, "pending-49:approval");
    assert.ok(snapshot.pendingApprovalItems.every(({ reviewMode }) => reviewMode === "post_event"));
    assert.equal(snapshot.status, "protected");
    assert.equal(snapshot.autopilot.enabled, true);
    assert.equal(snapshot.autopilot.mode, "guarded_autopilot");
    assert.equal(snapshot.autopilot.availability, "event_driven");
    assert.equal(snapshot.autopilot.postReviewOnly, true);
    assert.equal(snapshot.autopilot.lastCycle?.outcome, "manual_review");
    assert.deepEqual(snapshot.autopilot.allowlist, [
      "observe",
      "rate_limit_demo_session",
      "route_to_internal_decoy",
      "quarantine_demo_asset",
    ]);

    insertEvent(sqlite, {
      id: "pending-restore-outside-public-window",
      sequence: 100,
      occurredAt: "2026-08-17T12:00:00.000Z",
      title: "Manual restore outside bounded FIFO window",
    });
    sqlite.exec(`
      UPDATE security_events
      SET requested_action = 'restore_demo_snapshot'
      WHERE id = 'pending-restore-outside-public-window';
      INSERT INTO approval_requests (
        id, event_id, scenario_id, title, severity, requested_action, status,
        policy_version, council_recommendation, explanation, created_at, decided_at
      ) VALUES (
        'pending-restore-outside-public-window:approval',
        'pending-restore-outside-public-window', 'recovery-check',
        'Manual restore outside bounded FIFO window', 'high',
        'restore_demo_snapshot', 'pending', '4.0.0', 'requires_approval',
        'Manual restore requires an explicit operator decision.',
        '2026-08-17T12:00:00.000Z', NULL
      );
    `);
    const snapshotWithHiddenRestore = await store.readSanitizedSnapshot();
    assert.equal(snapshotWithHiddenRestore.pendingApprovalItems.length, 50);
    assert.ok(snapshotWithHiddenRestore.pendingApprovalItems.every(
      ({ requestedAction }) => requestedAction !== "restore_demo_snapshot",
    ));
    assert.equal(snapshotWithHiddenRestore.status, "review");
    assert.equal(snapshotWithHiddenRestore.autopilot.postReviewOnly, false);
    assert.deepEqual(sqlite.prepare("PRAGMA foreign_key_check").all(), []);
  } finally {
    sqlite.close();
  }
});
