import { getChatGPTUser } from "../../chatgpt-auth";
import { securityError } from "../../../lib/creluna/api-guards";

const LOCAL_PREVIEW_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Private Sites inject stable authenticated-user headers. Mutations require
 * that identity at the edge; the exact localhost exception exists only for
 * the developer preview and never grants access on a deployed hostname.
 */
export async function requireAuthenticatedOperator(
  request: Request,
): Promise<Response | null> {
  const hostname = new URL(request.url).hostname.toLowerCase();
  if (
    process.env.NODE_ENV !== "production" &&
    LOCAL_PREVIEW_HOSTS.has(hostname)
  ) {
    return null;
  }

  const operator = await getChatGPTUser();
  if (operator) return null;

  return securityError(
    401,
    "AUTHENTICATED_OPERATOR_REQUIRED",
    "A signed-in private-site operator is required for state-changing lab requests.",
  );
}
