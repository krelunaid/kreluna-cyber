CREATE TABLE `approval_decisions` (
	`id` text PRIMARY KEY NOT NULL,
	`approval_id` text NOT NULL,
	`event_id` text NOT NULL,
	`decision` text NOT NULL,
	`scope` text NOT NULL,
	`executed_external_action` integer DEFAULT false NOT NULL,
	`decided_at` text NOT NULL,
	FOREIGN KEY (`approval_id`) REFERENCES `approval_requests`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`event_id`) REFERENCES `security_events`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "approval_decisions_decision_allowed" CHECK("approval_decisions"."decision" IN ('approve_simulation', 'reject')),
	CONSTRAINT "approval_decisions_state_only" CHECK("approval_decisions"."scope" = 'state_only_lab_simulation'),
	CONSTRAINT "approval_decisions_no_external_action" CHECK("approval_decisions"."executed_external_action" = 0)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `approval_decisions_approval_uq` ON `approval_decisions` (`approval_id`);--> statement-breakpoint
CREATE INDEX `approval_decisions_decided_at_idx` ON `approval_decisions` (`decided_at`);--> statement-breakpoint
CREATE TABLE `approval_requests` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`scenario_id` text NOT NULL,
	`title` text NOT NULL,
	`severity` text NOT NULL,
	`requested_action` text NOT NULL,
	`status` text NOT NULL,
	`policy_version` text NOT NULL,
	`council_recommendation` text NOT NULL,
	`explanation` text NOT NULL,
	`created_at` text NOT NULL,
	`decided_at` text,
	FOREIGN KEY (`event_id`) REFERENCES `security_events`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "approval_requests_title_length" CHECK(length("approval_requests"."title") BETWEEN 1 AND 120),
	CONSTRAINT "approval_requests_explanation_length" CHECK(length("approval_requests"."explanation") BETWEEN 1 AND 280),
	CONSTRAINT "approval_requests_scenario_allowed" CHECK("approval_requests"."scenario_id" IN ('authentication-burst', 'api-input-anomaly', 'integrity-drift', 'recovery-check')),
	CONSTRAINT "approval_requests_severity_allowed" CHECK("approval_requests"."severity" IN ('info', 'low', 'medium', 'high', 'critical')),
	CONSTRAINT "approval_requests_action_allowed" CHECK("approval_requests"."requested_action" IN ('observe', 'tag_demo_session', 'notify_operator', 'rate_limit_demo_session', 'route_to_internal_decoy', 'quarantine_demo_asset', 'restore_demo_snapshot')),
	CONSTRAINT "approval_requests_status_allowed" CHECK("approval_requests"."status" IN ('pending', 'approved_simulation', 'rejected')),
	CONSTRAINT "approval_requests_recommendation_allowed" CHECK("approval_requests"."council_recommendation" IN ('allow_simulation', 'requires_approval', 'deny')),
	CONSTRAINT "approval_requests_lifecycle_consistent" CHECK(("approval_requests"."status" = 'pending' AND "approval_requests"."decided_at" IS NULL) OR ("approval_requests"."status" IN ('approved_simulation', 'rejected') AND "approval_requests"."decided_at" IS NOT NULL))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `approval_requests_event_uq` ON `approval_requests` (`event_id`);--> statement-breakpoint
CREATE INDEX `approval_requests_pending_idx` ON `approval_requests` (`status`,`created_at`);--> statement-breakpoint
INSERT INTO `approval_requests` (
	`id`, `event_id`, `scenario_id`, `title`, `severity`, `requested_action`,
	`status`, `policy_version`, `council_recommendation`, `explanation`,
	`created_at`, `decided_at`
)
SELECT
	`security_events`.`id` || ':approval',
	`security_events`.`id`,
	`security_events`.`scenario_id`,
	`security_events`.`title`,
	`security_events`.`severity`,
	`security_events`.`requested_action`,
	'pending',
	'2.0.0-legacy',
	'requires_approval',
	'Migrated pending V0.2 proposal; no action has been executed.',
	`incidents`.`opened_at`,
	NULL
FROM `incidents`
INNER JOIN `security_events` ON `security_events`.`id` = `incidents`.`event_id`
WHERE `incidents`.`approval_status` = 'pending' OR `incidents`.`status` = 'pending_approval';--> statement-breakpoint
CREATE TABLE `council_decisions` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`consensus` text NOT NULL,
	`recommendation` text NOT NULL,
	`quorum_required` integer NOT NULL,
	`quorum_received` integer NOT NULL,
	`agreement_bps` integer NOT NULL,
	`risk` text NOT NULL,
	`confidence_bps` integer NOT NULL,
	`allow_votes` integer NOT NULL,
	`approval_votes` integer NOT NULL,
	`deny_votes` integer NOT NULL,
	`explanation_json` text NOT NULL,
	`dissenting_agents_json` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `security_events`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "council_decisions_quorum_range" CHECK("council_decisions"."quorum_required" = 5 AND "council_decisions"."quorum_received" = 5),
	CONSTRAINT "council_decisions_agreement_range" CHECK("council_decisions"."agreement_bps" BETWEEN 0 AND 10000),
	CONSTRAINT "council_decisions_confidence_range" CHECK("council_decisions"."confidence_bps" BETWEEN 0 AND 10000),
	CONSTRAINT "council_decisions_vote_total" CHECK("council_decisions"."allow_votes" + "council_decisions"."approval_votes" + "council_decisions"."deny_votes" = 5),
	CONSTRAINT "council_decisions_vote_ranges" CHECK("council_decisions"."allow_votes" BETWEEN 0 AND 5 AND "council_decisions"."approval_votes" BETWEEN 0 AND 5 AND "council_decisions"."deny_votes" BETWEEN 0 AND 5),
	CONSTRAINT "council_decisions_consensus_allowed" CHECK("council_decisions"."consensus" IN ('unanimous', 'qualified_majority', 'policy_veto', 'no_quorum')),
	CONSTRAINT "council_decisions_recommendation_allowed" CHECK("council_decisions"."recommendation" IN ('allow_simulation', 'requires_approval', 'deny')),
	CONSTRAINT "council_decisions_risk_allowed" CHECK("council_decisions"."risk" IN ('low', 'medium', 'high', 'critical'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `council_decisions_event_uq` ON `council_decisions` (`event_id`);--> statement-breakpoint
CREATE INDEX `council_decisions_created_at_idx` ON `council_decisions` (`created_at`);--> statement-breakpoint
CREATE TABLE `idempotency_records` (
	`id` text PRIMARY KEY NOT NULL,
	`operation` text NOT NULL,
	`request_hash` text NOT NULL,
	`resource_id` text NOT NULL,
	`created_at` text NOT NULL,
	CONSTRAINT "idempotency_records_hash_length" CHECK(length("idempotency_records"."request_hash") = 64),
	CONSTRAINT "idempotency_records_operation_allowed" CHECK("idempotency_records"."operation" IN ('scenario', 'approval')),
	CONSTRAINT "idempotency_records_id_scope" CHECK(("idempotency_records"."operation" = 'scenario' AND "idempotency_records"."id" LIKE 'scenario:%') OR ("idempotency_records"."operation" = 'approval' AND "idempotency_records"."id" LIKE 'approval:%'))
);
--> statement-breakpoint
CREATE INDEX `idempotency_records_created_at_idx` ON `idempotency_records` (`created_at`);--> statement-breakpoint
CREATE TABLE `__new_agent_assessments` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`agent_id` text NOT NULL,
	`verdict` text NOT NULL,
	`vote` text NOT NULL,
	`risk` text NOT NULL,
	`score_bps` integer NOT NULL,
	`confidence_bps` integer NOT NULL,
	`trust_bps` integer NOT NULL,
	`rationale` text NOT NULL,
	`evidence_json` text NOT NULL,
	`safeguards_json` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `security_events`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "agent_assessments_score_range" CHECK("score_bps" BETWEEN 0 AND 10000),
	CONSTRAINT "agent_assessments_confidence_range" CHECK("confidence_bps" BETWEEN 0 AND 10000),
	CONSTRAINT "agent_assessments_trust_range" CHECK("trust_bps" BETWEEN 0 AND 10000),
	CONSTRAINT "agent_assessments_rationale_length" CHECK(length("rationale") BETWEEN 1 AND 220),
	CONSTRAINT "agent_assessments_agent_allowed" CHECK("agent_id" IN ('aegis', 'argine', 'orbit', 'decoy', 'phoenix')),
	CONSTRAINT "agent_assessments_verdict_allowed" CHECK("verdict" IN ('clear', 'monitor', 'contain_simulation', 'hold_for_human')),
	CONSTRAINT "agent_assessments_vote_allowed" CHECK("vote" IN ('allow_simulation', 'requires_approval', 'deny')),
	CONSTRAINT "agent_assessments_risk_allowed" CHECK("risk" IN ('low', 'medium', 'high', 'critical'))
);
--> statement-breakpoint
INSERT INTO `__new_agent_assessments`("id", "event_id", "agent_id", "verdict", "vote", "risk", "score_bps", "confidence_bps", "trust_bps", "rationale", "evidence_json", "safeguards_json", "created_at") SELECT "id", "event_id", "agent_id", "verdict", 'requires_approval', 'medium', "score_bps", "score_bps", 9800, "rationale", '["Legacy sanitized assessment"]', '["Policy Guard enforced"]', "created_at" FROM `agent_assessments`;--> statement-breakpoint
DROP TABLE `agent_assessments`;--> statement-breakpoint
ALTER TABLE `__new_agent_assessments` RENAME TO `agent_assessments`;--> statement-breakpoint
CREATE UNIQUE INDEX `agent_assessments_event_agent_uq` ON `agent_assessments` (`event_id`,`agent_id`);--> statement-breakpoint
CREATE INDEX `agent_assessments_event_idx` ON `agent_assessments` (`event_id`);--> statement-breakpoint
CREATE INDEX `agent_assessments_agent_idx` ON `agent_assessments` (`agent_id`);
--> statement-breakpoint
CREATE TRIGGER `security_events_enum_insert_guard`
BEFORE INSERT ON `security_events`
WHEN NEW.`scenario_id` NOT IN ('authentication-burst', 'api-input-anomaly', 'integrity-drift', 'recovery-check')
	OR NEW.`severity` NOT IN ('info', 'low', 'medium', 'high', 'critical')
	OR NEW.`asset_id` NOT IN ('vault-web-01', 'vault-api-01', 'identity-lab-01')
	OR NEW.`requested_action` NOT IN ('observe', 'tag_demo_session', 'notify_operator', 'rate_limit_demo_session', 'route_to_internal_decoy', 'quarantine_demo_asset', 'restore_demo_snapshot')
	OR NEW.`decision` NOT IN ('allow_simulation', 'requires_approval', 'deny')
BEGIN
	SELECT RAISE(ABORT, 'security_events enum constraint failed');
END;--> statement-breakpoint
CREATE TRIGGER `security_events_enum_update_guard`
BEFORE UPDATE OF `scenario_id`, `severity`, `asset_id`, `requested_action`, `decision` ON `security_events`
WHEN NEW.`scenario_id` NOT IN ('authentication-burst', 'api-input-anomaly', 'integrity-drift', 'recovery-check')
	OR NEW.`severity` NOT IN ('info', 'low', 'medium', 'high', 'critical')
	OR NEW.`asset_id` NOT IN ('vault-web-01', 'vault-api-01', 'identity-lab-01')
	OR NEW.`requested_action` NOT IN ('observe', 'tag_demo_session', 'notify_operator', 'rate_limit_demo_session', 'route_to_internal_decoy', 'quarantine_demo_asset', 'restore_demo_snapshot')
	OR NEW.`decision` NOT IN ('allow_simulation', 'requires_approval', 'deny')
BEGIN
	SELECT RAISE(ABORT, 'security_events enum constraint failed');
END;--> statement-breakpoint
CREATE TRIGGER `incidents_enum_insert_guard`
BEFORE INSERT ON `incidents`
WHEN NEW.`status` NOT IN ('observed', 'contained', 'pending_approval', 'denied')
	OR NEW.`impact` NOT IN ('none', 'unconfirmed')
	OR NEW.`approval_status` NOT IN ('not_required', 'pending', 'approved_simulation', 'rejected')
BEGIN
	SELECT RAISE(ABORT, 'incidents enum constraint failed');
END;--> statement-breakpoint
CREATE TRIGGER `incidents_enum_update_guard`
BEFORE UPDATE OF `status`, `impact`, `approval_status` ON `incidents`
WHEN NEW.`status` NOT IN ('observed', 'contained', 'pending_approval', 'denied')
	OR NEW.`impact` NOT IN ('none', 'unconfirmed')
	OR NEW.`approval_status` NOT IN ('not_required', 'pending', 'approved_simulation', 'rejected')
BEGIN
	SELECT RAISE(ABORT, 'incidents enum constraint failed');
END;--> statement-breakpoint
CREATE TRIGGER `audit_log_enum_insert_guard`
BEFORE INSERT ON `audit_log`
WHEN NEW.`actor` NOT IN ('aegis', 'argine', 'orbit', 'decoy', 'phoenix', 'policy-guard', 'human-operator')
	OR NEW.`action` NOT IN ('observe', 'tag_demo_session', 'notify_operator', 'rate_limit_demo_session', 'route_to_internal_decoy', 'quarantine_demo_asset', 'restore_demo_snapshot')
	OR NEW.`outcome` NOT IN ('allow_simulation', 'requires_approval', 'deny')
BEGIN
	SELECT RAISE(ABORT, 'audit_log enum constraint failed');
END;--> statement-breakpoint
CREATE TRIGGER `audit_log_enum_update_guard`
BEFORE UPDATE OF `actor`, `action`, `outcome` ON `audit_log`
WHEN NEW.`actor` NOT IN ('aegis', 'argine', 'orbit', 'decoy', 'phoenix', 'policy-guard', 'human-operator')
	OR NEW.`action` NOT IN ('observe', 'tag_demo_session', 'notify_operator', 'rate_limit_demo_session', 'route_to_internal_decoy', 'quarantine_demo_asset', 'restore_demo_snapshot')
	OR NEW.`outcome` NOT IN ('allow_simulation', 'requires_approval', 'deny')
BEGIN
	SELECT RAISE(ABORT, 'audit_log enum constraint failed');
END;
--> statement-breakpoint
PRAGMA foreign_key_check;
--> statement-breakpoint
PRAGMA optimize;
