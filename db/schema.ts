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
    scoreBps: integer("score_bps").notNull(),
    rationale: text("rationale").notNull(),
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
      "agent_assessments_rationale_length",
      sql`length(${table.rationale}) BETWEEN 1 AND 220`,
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
      enum: ["not_required", "pending"],
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
      enum: ["aegis", "argine", "orbit", "decoy", "phoenix", "policy-guard"],
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
