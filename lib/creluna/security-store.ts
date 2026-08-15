import {
  createInitialDemoState,
  type DashboardState,
  type DefenseCycleResult,
} from "./defense-engine.ts";

export interface SecurityStore {
  readSanitizedSnapshot(): Promise<DashboardState>;
  appendCycle(result: DefenseCycleResult): Promise<void>;
}

function cloneSnapshot(snapshot: DashboardState): DashboardState {
  return {
    ...snapshot,
    metrics: { ...snapshot.metrics },
    agents: snapshot.agents.map((agent) => ({ ...agent })),
    timeline: snapshot.timeline.map((event) => ({ ...event })),
    researchers: snapshot.researchers.map((researcher) => ({ ...researcher })),
    audit: snapshot.audit.map((entry) => ({ ...entry })),
  };
}

/**
 * Best-effort local preview fallback. D1 remains the durable store in deployed
 * environments; this store is intentionally labelled as ephemeral by the API.
 */
export class InMemorySecurityStore implements SecurityStore {
  private snapshot = createInitialDemoState();
  private readonly eventIds = new Set<string>();

  async readSanitizedSnapshot(): Promise<DashboardState> {
    return cloneSnapshot(this.snapshot);
  }

  async appendCycle(result: DefenseCycleResult): Promise<void> {
    if (this.eventIds.has(result.event.id)) return;
    this.eventIds.add(result.event.id);
    this.snapshot = cloneSnapshot(result.snapshot);
  }
}

export const memoryFallbackSecurityStore = new InMemorySecurityStore();
