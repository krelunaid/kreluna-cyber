import { getOptionalDb } from "../../../db";
import {
  listSafeLabScenarios,
  parseLabScenarioRequest,
  runNamedLabScenario,
  SAFE_SCENARIO_IDS,
  type DashboardState,
  type SafeScenarioId,
} from "../../../lib/creluna/defense-engine";
import { D1SecurityStore } from "../../../lib/creluna/d1-security-store";
import {
  memoryFallbackSecurityStore,
  type SecurityStore,
} from "../../../lib/creluna/security-store";

const MAX_BODY_CHARACTERS = 512;
const responseHeaders = {
  "Cache-Control": "no-store, max-age=0",
  "X-Content-Type-Options": "nosniff",
};

type PersistenceMode = "d1" | "memory_fallback";

async function resolveReadableStore(): Promise<{
  store: SecurityStore;
  snapshot: DashboardState;
  persistence: PersistenceMode;
}> {
  const db = getOptionalDb();
  if (db) {
    try {
      const store = new D1SecurityStore(db);
      return {
        store,
        snapshot: await store.readSanitizedSnapshot(),
        persistence: "d1",
      };
    } catch {
      // Local previews and first deployments can start before D1 migrations.
      // The response labels this non-durable fallback explicitly.
    }
  }

  return {
    store: memoryFallbackSecurityStore,
    snapshot: await memoryFallbackSecurityStore.readSanitizedSnapshot(),
    persistence: "memory_fallback",
  };
}

function successEnvelope(
  snapshot: DashboardState,
  persistence: PersistenceMode,
) {
  return {
    ok: true as const,
    mode: "safe_lab" as const,
    persistence,
    allowedScenarios: listSafeLabScenarios(),
    snapshot,
  };
}

function errorResponse(
  status: number,
  code: string,
  message: string,
  includeScenarioIds = false,
) {
  return Response.json(
    {
      ok: false,
      error: { code, message },
      ...(includeScenarioIds
        ? { allowedScenarioIds: [...SAFE_SCENARIO_IDS] }
        : {}),
    },
    { status, headers: responseHeaders },
  );
}

export async function GET() {
  const { snapshot, persistence } = await resolveReadableStore();
  return Response.json(successEnvelope(snapshot, persistence), {
    headers: responseHeaders,
  });
}

async function parseRequestBody(request: Request): Promise<
  | { ok: true; scenario: SafeScenarioId }
  | { ok: false; response: Response }
> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) {
    return {
      ok: false,
      response: errorResponse(
        415,
        "JSON_REQUIRED",
        "Send a small application/json body containing one named lab scenario.",
      ),
    };
  }

  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_CHARACTERS) {
    return {
      ok: false,
      response: errorResponse(413, "BODY_TOO_LARGE", "The request body is too large."),
    };
  }

  const rawBody = await request.text();
  if (rawBody.length === 0 || rawBody.length > MAX_BODY_CHARACTERS) {
    return {
      ok: false,
      response: errorResponse(
        rawBody.length > MAX_BODY_CHARACTERS ? 413 : 400,
        rawBody.length > MAX_BODY_CHARACTERS ? "BODY_TOO_LARGE" : "INVALID_JSON",
        rawBody.length > MAX_BODY_CHARACTERS
          ? "The request body is too large."
          : "A JSON request body is required.",
      ),
    };
  }

  let payload: unknown;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return {
      ok: false,
      response: errorResponse(400, "INVALID_JSON", "The request body is not valid JSON."),
    };
  }

  const parsed = parseLabScenarioRequest(payload);
  if (!parsed.ok) {
    return {
      ok: false,
      response: errorResponse(400, parsed.code, parsed.message, true),
    };
  }

  return parsed;
}

export async function POST(request: Request) {
  const parsed = await parseRequestBody(request);
  if (!parsed.ok) return parsed.response;

  const context = {
    eventId: crypto.randomUUID(),
    now: new Date().toISOString(),
  };
  let { store, snapshot, persistence } = await resolveReadableStore();
  let result = runNamedLabScenario(snapshot, parsed.scenario, {
    ...context,
    sequence: snapshot.revision + 1,
  });

  try {
    await store.appendCycle(result);
  } catch {
    // D1 batch writes are atomic. If persistence is temporarily unavailable,
    // preserve a functional local lab while clearly labelling it ephemeral.
    store = memoryFallbackSecurityStore;
    persistence = "memory_fallback";
    snapshot = await store.readSanitizedSnapshot();
    result = runNamedLabScenario(snapshot, parsed.scenario, {
      ...context,
      sequence: snapshot.revision + 1,
    });
    await store.appendCycle(result);
  }

  return Response.json(
    {
      ...successEnvelope(result.snapshot, persistence),
      scenario: parsed.scenario,
      decision: result.decision,
      execution: result.execution,
    },
    { status: 201, headers: responseHeaders },
  );
}
