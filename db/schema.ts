import { sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

/**
 * D1/SQLite schema for the defensive laboratory.
 *
 * Deliberately absent: raw IP addresses, request bodies, credentials, secrets,
 * exploit payloads and any other field that should never reach the public
 * dashboard database.
 */
export const securityEvents = sqliteTable(
  "security_events",
  {
    id: text("id").primaryKey(),
    sequence: integer("sequence").notNull(),
    scenarioId: text("scenario_id", {
      enum: [
        "authentication-burst",
        "api-input-anomaly",
        "integrity-drift",
        "recovery-check",
      ],
    }).notNull(),
    title: text("title").notNull(),
    publicSummary: text("public_summary").notNull(),
    severity: text("severity", {
      enum: ["info", "low", "medium", "high", "critical"],
    }).notNull(),
    confidenceBps: integer("confidence_bps").notNull(),
    signalCount: integer("signal_count").notNull(),
    assetId: text("asset_id", {
      enum: ["vault-web-01", "vault-api-01", "identity-lab-01"],
    }).notNull(),
    requestedAction: text("requested_action", {
      enum: [
        "observe",
        "tag_demo_session",
        "notify_operator",
        "rate_limit_demo_session",
        "route_to_internal_decoy",
        "quarantine_demo_asset",
        "restore_demo_snapshot",
      ],
    }).notNull(),
    decision: text("decision", {
      enum: ["allow_simulation", "requires_approval", "deny"],
    }).notNull(),
    isSynthetic: integer("is_synthetic", { mode: "boolean" })
      .notNull()
      .default(true),
    occurredAt: text("occurred_at").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("security_events_sequence_idx").on(table.sequence),
    index("security_events_occurred_at_idx").on(table.occurredAt),
    index("security_events_scenario_idx").on(table.scenarioId),
    index("security_events_decision_idx").on(table.decision),
    check(
      "security_events_confidence_range",
      sql`${table.confidenceBps} BETWEEN 0 AND 10000`,
    ),
    check("security_events_signal_count_positive", sql`${table.signalCount} > 0`),
    check("security_events_synthetic_only", sql`${table.isSynthetic} = 1`),
    check("security_events_title_length", sql`length(${table.title}) BETWEEN 1 AND 120`),
    check(
      "security_events_summary_length",
      sql`length(${table.publicSummary}) BETWEEN 1 AND 280`,
    ),
    // Migration 0001 adds INSERT/UPDATE enum guards to the already-deployed
    // V0.2 table without rebuilding this parent table.
  ],
);

export const agentAssessments = sqliteTable(
  "agent_assessments",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => securityEvents.id, { onDelete: "cascade" }),
    agentId: text("agent_id", {
      enum: ["aegis", "argine", "orbit", "decoy", "phoenix"],
    }).notNull(),
    verdict: text("verdict", {
      enum: ["clear", "monitor", "contain_simulation", "hold_for_human"],
    }).notNull(),
    vote: text("vote", {
      enum: ["allow_simulation", "requires_approval", "deny"],
    }).notNull(),
    risk: text("risk", {
      enum: ["low", "medium", "high", "critical"],
    }).notNull(),
    scoreBps: integer("score_bps").notNull(),
    confidenceBps: integer("confidence_bps").notNull(),
    trustBps: integer("trust_bps").notNull(),
    rationale: text("rationale").notNull(),
    evidenceJson: text("evidence_json").notNull(),
    safeguardsJson: text("safeguards_json").notNull(),
    createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    uniqueIndex("agent_assessments_event_agent_uq").on(
      table.eventId,
      table.agentId,
    ),
    index("agent_assessments_event_idx").on(table.eventId),
    index("agent_assessments_agent_idx").on(table.agentId),
    check(
      "agent_assessments_score_range",
      sql`${table.scoreBps} BETWEEN 0 AND 10000`,
    ),
    check(
      "agent_assessments_confidence_range",
      sql`${table.confidenceBps} BETWEEN 0 AND 10000`,
    ),
    check(
      "agent_assessments_trust_range",
      sql`${table.trustBps} BETWEEN 0 AND 10000`,
    ),
    check(
      "agent_assessments_rationale_length",
      sql`length(${table.rationale}) BETWEEN 1 AND 220`,
    ),
    check(
      "agent_assessments_agent_allowed",
      sql`${table.agentId} IN ('aegis', 'argine', 'orbit', 'decoy', 'phoenix')`,
    ),
    check(
      "agent_assessments_verdict_allowed",
      sql`${table.verdict} IN ('clear', 'monitor', 'contain_simulation', 'hold_for_human')`,
    ),
    check(
      "agent_assessments_vote_allowed",
      sql`${table.vote} IN ('allow_simulation', 'requires_approval', 'deny')`,
    ),
    check(
      "agent_assessments_risk_allowed",
      sql`${table.risk} IN ('low', 'medium', 'high', 'critical')`,
    ),
  ],
);

export const incidents = sqliteTable(
  "incidents",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => securityEvents.id, { onDelete: "cascade" }),
    status: text("status", {
      enum: ["observed", "contained", "pending_approval", "denied"],
    }).notNull(),
    impact: text("impact", { enum: ["none", "unconfirmed"] }).notNull(),
    approvalStatus: text("approval_status", {
      enum: ["not_required", "pending", "approved_simulation", "rejected"],
    }).notNull(),
    publicSummary: text("public_summary").notNull(),
    openedAt: text("opened_at").notNull(),
    resolvedAt: text("resolved_at"),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    uniqueIndex("incidents_event_uq").on(table.eventId),
    index("incidents_status_idx").on(table.status),
    index("incidents_opened_at_idx").on(table.openedAt),
    check(
      "incidents_summary_length",
      sql`length(${table.publicSummary}) BETWEEN 1 AND 280`,
    ),
    // Migration 0001 enforces the deployed V0.2 table's enum invariants with
    // equivalent INSERT/UPDATE triggers, avoiding a risky parent-table rebuild.
  ],
);

export const auditLog = sqliteTable(
  "audit_log",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => securityEvents.id, { onDelete: "cascade" }),
    sequence: integer("sequence").notNull(),
    actor: text("actor", {
      enum: [
        "aegis",
        "argine",
        "orbit",
        "decoy",
        "phoenix",
        "policy-guard",
        "human-operator",
      ],
    }).notNull(),
    action: text("action", {
      enum: [
        "observe",
        "tag_demo_session",
        "notify_operator",
        "rate_limit_demo_session",
        "route_to_internal_decoy",
        "quarantine_demo_asset",
        "restore_demo_snapshot",
      ],
    }).notNull(),
    outcome: text("outcome", {
      enum: ["allow_simulation", "requires_approval", "deny"],
    }).notNull(),
    reasonCode: text("reason_code").notNull(),
    detail: text("detail").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("audit_log_event_sequence_uq").on(table.eventId, table.sequence),
    index("audit_log_created_at_idx").on(table.createdAt),
    index("audit_log_outcome_idx").on(table.outcome),
    check("audit_log_sequence_positive", sql`${table.sequence} > 0`),
    check(
      "audit_log_detail_length",
      sql`length(${table.detail}) BETWEEN 1 AND 280`,
    ),
    // Migration 0001 adds equivalent enum-validation triggers to the existing
    // table because this table predates the advanced council schema.
  ],
);

export const councilDecisions = sqliteTable(
  "council_decisions",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => securityEvents.id, { onDelete: "cascade" }),
    consensus: text("consensus", {
      enum: ["unanimous", "qualified_majority", "policy_veto", "no_quorum"],
    }).notNull(),
    recommendation: text("recommendation", {
      enum: ["allow_simulation", "requires_approval", "deny"],
    }).notNull(),
    quorumRequired: integer("quorum_required").notNull(),
    quorumReceived: integer("quorum_received").notNull(),
    agreementBps: integer("agreement_bps").notNull(),
    risk: text("risk", { enum: ["low", "medium", "high", "critical"] }).notNull(),
    confidenceBps: integer("confidence_bps").notNull(),
    allowVotes: integer("allow_votes").notNull(),
    approvalVotes: integer("approval_votes").notNull(),
    denyVotes: integer("deny_votes").notNull(),
    explanationJson: text("explanation_json").notNull(),
    dissentingAgentsJson: text("dissenting_agents_json").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    uniqueIndex("council_decisions_event_uq").on(table.eventId),
    index("council_decisions_created_at_idx").on(table.createdAt),
    check("council_decisions_quorum_range", sql`${table.quorumRequired} = 5 AND ${table.quorumReceived} = 5`),
    check("council_decisions_agreement_range", sql`${table.agreementBps} BETWEEN 0 AND 10000`),
    check("council_decisions_confidence_range", sql`${table.confidenceBps} BETWEEN 0 AND 10000`),
    check("council_decisions_vote_total", sql`${table.allowVotes} + ${table.approvalVotes} + ${table.denyVotes} = 5`),
    check("council_decisions_vote_ranges", sql`${table.allowVotes} BETWEEN 0 AND 5 AND ${table.approvalVotes} BETWEEN 0 AND 5 AND ${table.denyVotes} BETWEEN 0 AND 5`),
    check("council_decisions_consensus_allowed", sql`${table.consensus} IN ('unanimous', 'qualified_majority', 'policy_veto', 'no_quorum')`),
    check("council_decisions_recommendation_allowed", sql`${table.recommendation} IN ('allow_simulation', 'requires_approval', 'deny')`),
    check("council_decisions_risk_allowed", sql`${table.risk} IN ('low', 'medium', 'high', 'critical')`),
  ],
);

export const approvalRequests = sqliteTable(
  "approval_requests",
  {
    id: text("id").primaryKey(),
    eventId: text("event_id")
      .notNull()
      .references(() => securityEvents.id, { onDelete: "cascade" }),
    scenarioId: text("scenario_id", {
      enum: ["authentication-burst", "api-input-anomaly", "integrity-drift", "recovery-check"],
    }).notNull(),
    title: text("title").notNull(),
    severity: text("severity", { enum: ["info", "low", "medium", "high", "critical"] }).notNull(),
    requestedAction: text("requested_action", {
      enum: [
        "observe",
        "tag_demo_session",
        "notify_operator",
        "rate_limit_demo_session",
        "route_to_internal_decoy",
        "quarantine_demo_asset",
        "restore_demo_snapshot",
      ],
    }).notNull(),
    status: text("status", {
      enum: ["pending", "approved_simulation", "rejected"],
    }).notNull(),
    policyVersion: text("policy_version").notNull(),
    councilRecommendation: text("council_recommendation", {
      enum: ["allow_simulation", "requires_approval", "deny"],
    }).notNull(),
    explanation: text("explanation").notNull(),
    createdAt: text("created_at").notNull(),
    decidedAt: text("decided_at"),
  },
  (table) => [
    uniqueIndex("approval_requests_event_uq").on(table.eventId),
    index("approval_requests_pending_idx").on(table.status, table.createdAt),
    check("approval_requests_title_length", sql`length(${table.title}) BETWEEN 1 AND 120`),
    check("approval_requests_explanation_length", sql`length(${table.explanation}) BETWEEN 1 AND 280`),
    check("approval_requests_scenario_allowed", sql`${table.scenarioId} IN ('authentication-burst', 'api-input-anomaly', 'integrity-drift', 'recovery-check')`),
    check("approval_requests_severity_allowed", sql`${table.severity} IN ('info', 'low', 'medium', 'high', 'critical')`),
    check("approval_requests_action_allowed", sql`${table.requestedAction} IN ('observe', 'tag_demo_session', 'notify_operator', 'rate_limit_demo_session', 'route_to_internal_decoy', 'quarantine_demo_asset', 'restore_demo_snapshot')`),
    check("approval_requests_status_allowed", sql`${table.status} IN ('pending', 'approved_simulation', 'rejected')`),
    check("approval_requests_recommendation_allowed", sql`${table.councilRecommendation} IN ('allow_simulation', 'requires_approval', 'deny')`),
    check(
      "approval_requests_lifecycle_consistent",
      sql`(${table.status} = 'pending' AND ${table.decidedAt} IS NULL) OR (${table.status} IN ('approved_simulation', 'rejected') AND ${table.decidedAt} IS NOT NULL)`,
    ),
  ],
);

export const approvalDecisions = sqliteTable(
  "approval_decisions",
  {
    id: text("id").primaryKey(),
    approvalId: text("approval_id")
      .notNull()
      .references(() => approvalRequests.id, { onDelete: "cascade" }),
    eventId: text("event_id")
      .notNull()
      .references(() => securityEvents.id, { onDelete: "cascade" }),
    decision: text("decision", { enum: ["approve_simulation", "reject"] }).notNull(),
    scope: text("scope", { enum: ["state_only_lab_simulation"] }).notNull(),
    executedExternalAction: integer("executed_external_action", { mode: "boolean" }).notNull().default(false),
    decidedAt: text("decided_at").notNull(),
  },
  (table) => [
    uniqueIndex("approval_decisions_approval_uq").on(table.approvalId),
    index("approval_decisions_decided_at_idx").on(table.decidedAt),
    check("approval_decisions_state_only", sql`${table.scope} = 'state_only_lab_simulation'`),
    check("approval_decisions_no_external_action", sql`${table.executedExternalAction} = 0`),
    check("approval_decisions_decision_allowed", sql`${table.decision} IN ('approve_simulation', 'reject')`),
  ],
);

export const idempotencyRecords = sqliteTable(
  "idempotency_records",
  {
    id: text("id").primaryKey(),
    operation: text("operation", { enum: ["scenario", "approval"] }).notNull(),
    requestHash: text("request_hash").notNull(),
    resourceId: text("resource_id").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    index("idempotency_records_created_at_idx").on(table.createdAt),
    check("idempotency_records_hash_length", sql`length(${table.requestHash}) = 64`),
    check("idempotency_records_operation_allowed", sql`${table.operation} IN ('scenario', 'approval')`),
    check(
      "idempotency_records_id_scope",
      sql`(${table.operation} = 'scenario' AND ${table.id} LIKE 'scenario:%') OR (${table.operation} = 'approval' AND ${table.id} LIKE 'approval:%')`,
    ),
  ],
);

export type SecurityEventRow = typeof securityEvents.$inferSelect;
export type NewSecurityEventRow = typeof securityEvents.$inferInsert;
export type AgentAssessmentRow = typeof agentAssessments.$inferSelect;
export type NewAgentAssessmentRow = typeof agentAssessments.$inferInsert;
export type IncidentRow = typeof incidents.$inferSelect;
export type NewIncidentRow = typeof incidents.$inferInsert;
export type AuditLogRow = typeof auditLog.$inferSelect;
export type NewAuditLogRow = typeof auditLog.$inferInsert;
export type CouncilDecisionRow = typeof councilDecisions.$inferSelect;
export type NewCouncilDecisionRow = typeof councilDecisions.$inferInsert;
export type ApprovalRequestRow = typeof approvalRequests.$inferSelect;
export type NewApprovalRequestRow = typeof approvalRequests.$inferInsert;
export type ApprovalDecisionRow = typeof approvalDecisions.$inferSelect;
export type NewApprovalDecisionRow = typeof approvalDecisions.$inferInsert;
export type IdempotencyRecordRow = typeof idempotencyRecords.$inferSelect;
export type NewIdempotencyRecordRow = typeof idempotencyRecords.$inferInsert;
