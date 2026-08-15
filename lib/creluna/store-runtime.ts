import { getOptionalDb } from "../../db";
import { D1SecurityStore } from "./d1-security-store";
import { memoryFallbackSecurityStore, type SecurityStore } from "./security-store";

export type PersistenceMode = "d1" | "memory_fallback";

/** Memory is selected only when no D1 binding exists; D1 failures propagate. */
export function resolveSecurityStore(): {
  store: SecurityStore;
  persistence: PersistenceMode;
} {
  const db = getOptionalDb();
  if (db) return { store: new D1SecurityStore(db), persistence: "d1" };
  return { store: memoryFallbackSecurityStore, persistence: "memory_fallback" };
}
