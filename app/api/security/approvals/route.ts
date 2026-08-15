import {
  parseApprovalRequest,
  type DashboardState,
} from "../../../../lib/creluna/defense-engine";
import {
  createIdempotencyRecord,
  parseIdempotencyKey,
  readSmallJsonBody,
  requireSameOrigin,
  SECURITY_RESPONSE_HEADERS,
  securityError,
} from "../../../../lib/creluna/api-guards";
import {
  ApprovalAlreadyResolvedError,
  ApprovalNotFoundError,
  IdempotencyConflictError,
  type SecurityStore,
} from "../../../../lib/creluna/security-store";
import {
  resolveSecurityStore,
  type PersistenceMode,
} from "../../../../lib/creluna/store-runtime";
import { requireAuthenticatedOperator } from "../operator-auth";

function successEnvelope(snapshot: DashboardState, persistence: PersistenceMode) {
  return {
    ok: true as const,
    mode: "safe_lab" as const,
    persistence,
    snapshot,
  };
}

function persistenceFailure() {
  return securityError(
    503,
    "SECURITY_MEMORY_UNAVAILABLE",
    "Durable security memory is temporarily unavailable; the lab failed closed.",
  );
}

async function replayResponse(
  store: SecurityStore,
  persistence: PersistenceMode,
  approvalId: string,
) {
  return Response.json(
    {
      ...successEnvelope(await store.readSanitizedSnapshot(), persistence),
      approvalId,
      replayed: true,
      execution: {
        scope: "state_only_lab_simulation",
        externalNetworkAction: false,
        offensiveAction: false,
        privilegedAction: false,
      },
    },
    { status: 200, headers: SECURITY_RESPONSE_HEADERS },
  );
}

export async function POST(request: Request) {
  const originFailure = requireSameOrigin(request);
  if (originFailure) return originFailure;
  const operatorFailure = await requireAuthenticatedOperator(request);
  if (operatorFailure) return operatorFailure;

  const keyResult = parseIdempotencyKey(request);
  if (!keyResult.ok) return keyResult.response;
  const body = await readSmallJsonBody(request);
  if (!body.ok) return body.response;
  const parsed = parseApprovalRequest(body.payload);
  if (!parsed.ok) return securityError(400, parsed.code, parsed.message);

  let resolved: ReturnType<typeof resolveSecurityStore>;
  try {
    resolved = resolveSecurityStore();
    if (resolved.persistence !== "d1") return persistenceFailure();
    await resolved.store.readSanitizedSnapshot();
  } catch {
    return persistenceFailure();
  }

  const now = new Date().toISOString();
  const replay = await createIdempotencyRecord(
    keyResult.key,
    "approval",
    body.rawBody,
    parsed.approvalId,
    now,
  );

  try {
    if (replay) {
      const existing = await resolved.store.findReplay(replay.id);
      if (existing) {
        if (existing.requestHash !== replay.requestHash) {
          return securityError(409, "IDEMPOTENCY_CONFLICT", "This key was already used for a different request.");
        }
        return await replayResponse(resolved.store, resolved.persistence, parsed.approvalId);
      }
    }

    const result = await resolved.store.resolveApproval(
      parsed.approvalId,
      parsed.decision,
      now,
      replay,
    );
    return Response.json(
      {
        ...successEnvelope(result.snapshot, resolved.persistence),
        approvalId: parsed.approvalId,
        resolution: result.record,
        execution: result.execution,
        replayed: false,
      },
      { status: 200, headers: SECURITY_RESPONSE_HEADERS },
    );
  } catch (error) {
    if (error instanceof IdempotencyConflictError) {
      return securityError(409, "IDEMPOTENCY_CONFLICT", "This key was already used for a different request.");
    }
    if (replay) {
      try {
        const existing = await resolved.store.findReplay(replay.id);
        if (existing?.requestHash === replay.requestHash) {
          return await replayResponse(resolved.store, resolved.persistence, parsed.approvalId);
        }
        if (existing) {
          return securityError(409, "IDEMPOTENCY_CONFLICT", "This key was already used for a different request.");
        }
      } catch {
        return persistenceFailure();
      }
    }
    if (error instanceof ApprovalNotFoundError) {
      return securityError(404, "APPROVAL_NOT_FOUND", "The approval request does not exist or is not pending.");
    }
    if (error instanceof ApprovalAlreadyResolvedError) {
      return securityError(409, "APPROVAL_ALREADY_RESOLVED", "This approval has already received its one allowed decision.");
    }
    return resolved.persistence === "d1"
      ? persistenceFailure()
      : securityError(500, "APPROVAL_FAILED", "The decision was not recorded and no action was executed.");
  }
}
