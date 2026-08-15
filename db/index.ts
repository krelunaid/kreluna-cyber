import { env } from "cloudflare:workers";
import { drizzle } from "drizzle-orm/d1";
import * as schema from "./schema";

type CrelunaWorkerEnv = {
  DB?: D1Database;
};

/** Returns the D1-backed Drizzle client, or null in a local/no-binding preview. */
export function getOptionalDb() {
  const binding = (env as CrelunaWorkerEnv).DB;
  if (!binding) return null;

  return drizzle(binding, { schema });
}

export function getDb() {
  const db = getOptionalDb();
  if (!db) {
    throw new Error(
      "Cloudflare D1 binding `DB` is unavailable. Set the `d1` field in .openai/hosting.json to `DB` or let your control plane inject the real binding values before using the database."
    );
  }

  return db;
}

export type CrelunaDb = ReturnType<typeof getDb>;
