CREATE TABLE `agent_assessments` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`agent_id` text NOT NULL,
	`verdict` text NOT NULL,
	`score_bps` integer NOT NULL,
	`rationale` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `security_events`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "agent_assessments_score_range" CHECK("agent_assessments"."score_bps" BETWEEN 0 AND 10000),
	CONSTRAINT "agent_assessments_rationale_length" CHECK(length("agent_assessments"."rationale") BETWEEN 1 AND 220)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `agent_assessments_event_agent_uq` ON `agent_assessments` (`event_id`,`agent_id`);--> statement-breakpoint
CREATE INDEX `agent_assessments_event_idx` ON `agent_assessments` (`event_id`);--> statement-breakpoint
CREATE INDEX `agent_assessments_agent_idx` ON `agent_assessments` (`agent_id`);--> statement-breakpoint
CREATE TABLE `audit_log` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`sequence` integer NOT NULL,
	`actor` text NOT NULL,
	`action` text NOT NULL,
	`outcome` text NOT NULL,
	`reason_code` text NOT NULL,
	`detail` text NOT NULL,
	`created_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `security_events`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "audit_log_sequence_positive" CHECK("audit_log"."sequence" > 0),
	CONSTRAINT "audit_log_detail_length" CHECK(length("audit_log"."detail") BETWEEN 1 AND 280)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `audit_log_event_sequence_uq` ON `audit_log` (`event_id`,`sequence`);--> statement-breakpoint
CREATE INDEX `audit_log_created_at_idx` ON `audit_log` (`created_at`);--> statement-breakpoint
CREATE INDEX `audit_log_outcome_idx` ON `audit_log` (`outcome`);--> statement-breakpoint
CREATE TABLE `incidents` (
	`id` text PRIMARY KEY NOT NULL,
	`event_id` text NOT NULL,
	`status` text NOT NULL,
	`impact` text NOT NULL,
	`approval_status` text NOT NULL,
	`public_summary` text NOT NULL,
	`opened_at` text NOT NULL,
	`resolved_at` text,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`event_id`) REFERENCES `security_events`(`id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT "incidents_summary_length" CHECK(length("incidents"."public_summary") BETWEEN 1 AND 280)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `incidents_event_uq` ON `incidents` (`event_id`);--> statement-breakpoint
CREATE INDEX `incidents_status_idx` ON `incidents` (`status`);--> statement-breakpoint
CREATE INDEX `incidents_opened_at_idx` ON `incidents` (`opened_at`);--> statement-breakpoint
CREATE TABLE `security_events` (
	`id` text PRIMARY KEY NOT NULL,
	`sequence` integer NOT NULL,
	`scenario_id` text NOT NULL,
	`title` text NOT NULL,
	`public_summary` text NOT NULL,
	`severity` text NOT NULL,
	`confidence_bps` integer NOT NULL,
	`signal_count` integer NOT NULL,
	`asset_id` text NOT NULL,
	`requested_action` text NOT NULL,
	`decision` text NOT NULL,
	`is_synthetic` integer DEFAULT true NOT NULL,
	`occurred_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "security_events_confidence_range" CHECK("security_events"."confidence_bps" BETWEEN 0 AND 10000),
	CONSTRAINT "security_events_signal_count_positive" CHECK("security_events"."signal_count" > 0),
	CONSTRAINT "security_events_synthetic_only" CHECK("security_events"."is_synthetic" = 1),
	CONSTRAINT "security_events_title_length" CHECK(length("security_events"."title") BETWEEN 1 AND 120),
	CONSTRAINT "security_events_summary_length" CHECK(length("security_events"."public_summary") BETWEEN 1 AND 280)
);
--> statement-breakpoint
CREATE INDEX `security_events_sequence_idx` ON `security_events` (`sequence`);--> statement-breakpoint
CREATE INDEX `security_events_occurred_at_idx` ON `security_events` (`occurred_at`);--> statement-breakpoint
CREATE INDEX `security_events_scenario_idx` ON `security_events` (`scenario_id`);--> statement-breakpoint
CREATE INDEX `security_events_decision_idx` ON `security_events` (`decision`);--> statement-breakpoint
PRAGMA optimize;
