import type { IdempotencyRecordInput, ReplayOperation } from "./security-store";

export const SECURITY_RESPONSE_HEADERS = {
  "Cache-Control": "no-store, max-age=0",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
} as const;

export function securityError(
  status: number,
  code: string,
  message: string,
  extras: Record<string, unknown> = {},
): Response {
  return Response.json(
    { ok: false, error: { code, message }, ...extras },
    { status, headers: SECURITY_RESPONSE_HEADERS },
  );
}

/** Mutation endpoints accept browser requests only from their exact own origin. */
export function requireSameOrigin(request: Request): Response | null {
  const fetchSite = request.headers.get("sec-fetch-site")?.toLowerCase();
  if (fetchSite && fetchSite !== "same-origin") {
    return securityError(403, "SAME_ORIGIN_REQUIRED", "This mutation is available only to the same-origin lab console.");
  }

  const origin = request.headers.get("origin");
  if (!origin || origin === "null") {
    return securityError(403, "SAME_ORIGIN_REQUIRED", "A valid same-origin request is required.");
  }

  try {
    const parsedOrigin = new URL(origin);
    if (origin !== `${parsedOrigin.protocol}//${parsedOrigin.host}`) {
      return securityError(403, "SAME_ORIGIN_REQUIRED", "The request origin is invalid.");
    }
    if (parsedOrigin.origin !== new URL(request.url).origin) {
      return securityError(403, "SAME_ORIGIN_REQUIRED", "Cross-origin mutations are blocked.");
    }
  } catch {
    return securityError(403, "SAME_ORIGIN_REQUIRED", "The request origin is invalid.");
  }
  return null;
}

export function parseIdempotencyKey(request: Request):
  | { ok: true; key: string }
  | { ok: false; response: Response } {
  const raw = request.headers.get("idempotency-key");
  if (raw === null) {
    return {
      ok: false,
      response: securityError(
        400,
        "IDEMPOTENCY_KEY_REQUIRED",
        "Idempotency-Key is required for every state-changing lab request.",
      ),
    };
  }
  const key = raw.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(key)) {
    return {
      ok: false,
      response: securityError(
        400,
        "INVALID_IDEMPOTENCY_KEY",
        "Idempotency-Key must contain 8-128 safe ASCII characters.",
      ),
    };
  }
  return { ok: true, key };
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function createIdempotencyRecord(
  key: string,
  operation: ReplayOperation,
  rawBody: string,
  resourceId: string,
  now: string,
): Promise<IdempotencyRecordInput> {
  const [keyHash, requestHash] = await Promise.all([sha256(key), sha256(rawBody)]);
  return {
    id: `${operation}:${keyHash}`,
    operation,
    requestHash,
    resourceId,
    createdAt: now,
  };
}

export async function readSmallJsonBody(
  request: Request,
  maxCharacters = 512,
): Promise<
  | { ok: true; rawBody: string; payload: unknown }
  | { ok: false; response: Response }
> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) {
    return {
      ok: false,
      response: securityError(415, "JSON_REQUIRED", "Send a small application/json request body."),
    };
  }
  const declaredLength = Number(request.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > maxCharacters) {
    return { ok: false, response: securityError(413, "BODY_TOO_LARGE", "The request body is too large.") };
  }
  const rawBody = await request.text();
  if (rawBody.length === 0 || rawBody.length > maxCharacters) {
    return {
      ok: false,
      response: securityError(
        rawBody.length > maxCharacters ? 413 : 400,
        rawBody.length > maxCharacters ? "BODY_TOO_LARGE" : "INVALID_JSON",
        rawBody.length > maxCharacters ? "The request body is too large." : "A JSON request body is required.",
      ),
    };
  }
  try {
    return { ok: true, rawBody, payload: JSON.parse(rawBody) as unknown };
  } catch {
    return { ok: false, response: securityError(400, "INVALID_JSON", "The request body is not valid JSON.") };
  }
}
