import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  createIdempotencyRecord,
  parseIdempotencyKey,
  readSmallJsonBody,
  requireSameOrigin,
} from "../lib/creluna/api-guards.ts";

test("mutation guard accepts only the exact request origin", () => {
  const sameOrigin = new Request("https://vault.test/api/security", {
    method: "POST",
    headers: { Origin: "https://vault.test", "Sec-Fetch-Site": "same-origin" },
  });
  assert.equal(requireSameOrigin(sameOrigin), null);

  for (const headers of [
    {},
    { Origin: "null" },
    { Origin: "https://attacker.test" },
    { Origin: "https://vault.test", "Sec-Fetch-Site": "cross-site" },
  ]) {
    const request = new Request("https://vault.test/api/security", { method: "POST", headers });
    assert.equal(requireSameOrigin(request)?.status, 403);
  }
});

test("idempotency keys are mandatory, validated and hashed before storage", async () => {
  const missing = parseIdempotencyKey(new Request("https://vault.test/api/security"));
  assert.equal(missing.ok, false);
  assert.equal(missing.response.status, 400);
  assert.equal((await missing.response.json()).error.code, "IDEMPOTENCY_KEY_REQUIRED");
  const invalid = parseIdempotencyKey(new Request("https://vault.test/api/security", {
    headers: { "Idempotency-Key": "short" },
  }));
  assert.equal(invalid.ok, false);

  const record = await createIdempotencyRecord(
    "safe-test-key-001",
    "scenario",
    '{"scenario":"recovery-check"}',
    "event-1",
    "2026-08-15T12:00:00.000Z",
  );
  assert.equal(record.requestHash.length, 64);
  assert.equal(record.id.startsWith("scenario:"), true);
  assert.equal(record.id.includes("safe-test-key-001"), false);
});

test("small JSON reader rejects wrong media type and oversized input", async () => {
  const wrongType = await readSmallJsonBody(new Request("https://vault.test/api/security", {
    method: "POST",
    body: "{}",
  }));
  assert.equal(wrongType.ok, false);
  assert.equal(wrongType.response.status, 415);

  const oversized = await readSmallJsonBody(new Request("https://vault.test/api/security", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: "x".repeat(600) }),
  }));
  assert.equal(oversized.ok, false);
  assert.equal(oversized.response.status, 413);
});

test("both mutation routes require durable D1 and the client never fabricates a fallback cycle", () => {
  for (const relativePath of [
    "../app/api/security/route.ts",
    "../app/api/security/approvals/route.ts",
  ]) {
    const source = readFileSync(new URL(relativePath, import.meta.url), "utf8");
    assert.match(source, /resolved\.persistence !== "d1"/);
    assert.match(source, /return persistenceFailure\(\)/);
    assert.match(source, /requireAuthenticatedOperator/);
  }

  const operatorGuardSource = readFileSync(
    new URL("../app/api/security/operator-auth.ts", import.meta.url),
    "utf8",
  );
  assert.match(operatorGuardSource, /getChatGPTUser\(\)/);
  assert.match(operatorGuardSource, /AUTHENTICATED_OPERATOR_REQUIRED/);

  const clientSource = readFileSync(
    new URL("../app/page.tsx", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(clientSource, /runLocalCycle|runDemoDefenseCycle/);
  assert.match(clientSource, /FAILED CLOSED/);
});
