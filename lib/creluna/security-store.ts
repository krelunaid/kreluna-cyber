import {
  createInitialDemoState,
  resolveApprovalInState,
  type ApprovalDecision,
  type ApprovalResolutionResult,
  type DashboardState,
  type DefenseCycleResult,
} from "./defense-engine.ts";

export type ReplayOperation = "scenario" | "approval";

export interface IdempotencyRecordInput {
  id: string;
  operation: ReplayOperation;
  requestHash: string;
  resourceId: string;
  createdAt: string;
}

export type StoredReplay = IdempotencyRecordInput;

export interface SecurityStore {
  readSanitizedSnapshot(): Promise<DashboardState>;
  findReplay(id: string): Promise<StoredReplay | null>;
  appendCycle(result: DefenseCycleResult, replay?: IdempotencyRecordInput): Promise<void>;
  resolveApproval(
    approvalId: string,
    decision: ApprovalDecision,
    now: string,
    replay?: IdempotencyRecordInput,
  ): Promise<ApprovalResolutionResult>;
}

export class ApprovalNotFoundError extends Error {
  constructor() {
    super("APPROVAL_NOT_FOUND");
    this.name = "ApprovalNotFoundError";
  }
}

export class ApprovalAlreadyResolvedError extends Error {
  constructor() {
    super("APPROVAL_ALREADY_RESOLVED");
    this.name = "ApprovalAlreadyResolvedError";
  }
}

export class IdempotencyConflictError extends Error {
  constructor() {
    super("IDEMPOTENCY_CONFLICT");
    this.name = "IdempotencyConflictError";
  }
}

function deepClone<T>(value: T): T {
  return structuredClone(value);
}

/** Ephemeral store used only when the DB binding is absent (local preview). */
export class InMemorySecurityStore implements SecurityStore {
  private snapshot = createInitialDemoState();
  private readonly eventIds = new Set<string>();
  private readonly replays = new Map<string, StoredReplay>();
  private readonly resolvedApprovals = new Set<string>();

  async readSanitizedSnapshot(): Promise<DashboardState> {
    return deepClone(this.snapshot);
  }

  async findReplay(id: string): Promise<StoredReplay | null> {
    const replay = this.replays.get(id);
    return replay ? deepClone(replay) : null;
  }

  async appendCycle(result: DefenseCycleResult, replay?: IdempotencyRecordInput): Promise<void> {
    if (replay) {
      const existing = this.replays.get(replay.id);
      if (existing) {
        if (existing.requestHash !== replay.requestHash) throw new IdempotencyConflictError();
        return;
      }
    }
    if (this.eventIds.has(result.event.id)) return;
    this.eventIds.add(result.event.id);
    this.snapshot = deepClone(result.snapshot);
    if (replay) this.replays.set(replay.id, deepClone(replay));
  }

  async resolveApproval(
    approvalId: string,
    decision: ApprovalDecision,
    now: string,
    replay?: IdempotencyRecordInput,
  ): Promise<ApprovalResolutionResult> {
    if (replay) {
      const existing = this.replays.get(replay.id);
      if (existing && existing.requestHash !== replay.requestHash) throw new IdempotencyConflictError();
      if (existing || this.resolvedApprovals.has(approvalId)) throw new ApprovalAlreadyResolvedError();
    } else if (this.resolvedApprovals.has(approvalId)) {
      throw new ApprovalAlreadyResolvedError();
    }
    if (!this.snapshot.pendingApprovalItems.some(({ id }) => id === approvalId)) {
      throw new ApprovalNotFoundError();
    }

    let result: ApprovalResolutionResult;
    try {
      result = resolveApprovalInState(this.snapshot, approvalId, decision, now);
    } catch {
      throw new ApprovalNotFoundError();
    }
    this.snapshot = deepClone(result.snapshot);
    this.resolvedApprovals.add(approvalId);
    if (replay) this.replays.set(replay.id, deepClone(replay));
    return deepClone(result);
  }
}

export const memoryFallbackSecurityStore = new InMemorySecurityStore();
