CREATE TABLE "control"."configuration_work" (
	"configuration_work_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"operation_id" uuid NOT NULL,
	"work_kind" text NOT NULL,
	"resource_id" uuid NOT NULL,
	"input_digest" text NOT NULL,
	"configuration_digest" text NOT NULL,
	"runtime_configuration_generation_id" uuid,
	"runtime_target_id" uuid,
	"generation_digest" text,
	"predecessor_digest" text,
	"policy_generation_digest" text NOT NULL,
	"xds_version_digest" text,
	"state" text DEFAULT 'PENDING' NOT NULL,
	"attempt_count" bigint DEFAULT 0 NOT NULL,
	"lease_owner" text,
	"lease_until" timestamp(6) with time zone,
	"result_receipt" jsonb,
	"result_receipt_digest" text,
	"result_event_id" uuid,
	"last_error_code" text,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"completed_at" timestamp(6) with time zone,
	CONSTRAINT "configuration_work_operation_uq" UNIQUE("participant_id","operation_id"),
	CONSTRAINT "configuration_work_runtime_generation_uq" UNIQUE("runtime_configuration_generation_id"),
	CONSTRAINT "configuration_work_kind_ck" CHECK ("control"."configuration_work"."work_kind" in ('PROVIDER_QUALIFICATION','INDEXER_ADMISSION','PROJECTION_VALIDATION','RUNTIME_ACTIVATION')),
	CONSTRAINT "configuration_work_state_ck" CHECK ("control"."configuration_work"."state" in ('PENDING','LEASED','COMPLETED','FAILED')),
	CONSTRAINT "configuration_work_attempt_count_ck" CHECK ("control"."configuration_work"."attempt_count" >= 0),
	CONSTRAINT "configuration_work_lease_ck" CHECK (("control"."configuration_work"."state"='LEASED') = ("control"."configuration_work"."lease_owner" is not null and "control"."configuration_work"."lease_until" is not null)),
	CONSTRAINT "configuration_work_receipt_ck" CHECK (("control"."configuration_work"."state" in ('COMPLETED','FAILED')) = ("control"."configuration_work"."result_receipt" is not null and "control"."configuration_work"."result_receipt_digest" is not null and "control"."configuration_work"."result_event_id" is not null and "control"."configuration_work"."completed_at" is not null)),
	CONSTRAINT "configuration_work_runtime_binding_ck" CHECK (("control"."configuration_work"."work_kind"='RUNTIME_ACTIVATION') = ("control"."configuration_work"."runtime_configuration_generation_id" is not null and "control"."configuration_work"."runtime_target_id" is not null and "control"."configuration_work"."generation_digest" is not null and "control"."configuration_work"."policy_generation_digest" is not null and "control"."configuration_work"."xds_version_digest" is not null)),
	CONSTRAINT "configuration_work_input_digest_ck" CHECK ("control"."configuration_work"."input_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "configuration_work_configuration_digest_ck" CHECK ("control"."configuration_work"."configuration_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "configuration_work_generation_digest_ck" CHECK ("control"."configuration_work"."generation_digest" is null or "control"."configuration_work"."generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "configuration_work_predecessor_digest_ck" CHECK ("control"."configuration_work"."predecessor_digest" is null or "control"."configuration_work"."predecessor_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "configuration_work_policy_digest_ck" CHECK ("control"."configuration_work"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "configuration_work_xds_digest_ck" CHECK ("control"."configuration_work"."xds_version_digest" is null or "control"."configuration_work"."xds_version_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "configuration_work_receipt_digest_ck" CHECK ("control"."configuration_work"."result_receipt_digest" is null or "control"."configuration_work"."result_receipt_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "configuration_work_error_ck" CHECK ("control"."configuration_work"."last_error_code" is null or "control"."configuration_work"."last_error_code" ~ '^PC-[A-Z]+-[0-9]{4}$')
);
--> statement-breakpoint
ALTER TABLE "control"."configuration_work" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."abi_artifact" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."argument_rule_named_set_binding" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."typed_argument_rule_version" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."contract_method_policy" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."logical_contract_asset" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."contract_runtime_binding" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."runtime_configuration_work" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."typed_argument_rule" DISABLE ROW LEVEL SECURITY;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."abi_artifact" CASCADE;--> statement-breakpoint
DROP POLICY "privacy_domain_isolation" ON "control"."abi_artifact" CASCADE;--> statement-breakpoint
DROP TABLE "control"."abi_artifact" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."argument_rule_named_set_binding" CASCADE;--> statement-breakpoint
DROP POLICY "privacy_domain_isolation" ON "control"."argument_rule_named_set_binding" CASCADE;--> statement-breakpoint
DROP TABLE "control"."argument_rule_named_set_binding" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."typed_argument_rule_version" CASCADE;--> statement-breakpoint
DROP POLICY "privacy_domain_isolation" ON "control"."typed_argument_rule_version" CASCADE;--> statement-breakpoint
DROP TABLE "control"."typed_argument_rule_version" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."contract_method_policy" CASCADE;--> statement-breakpoint
DROP POLICY "privacy_domain_isolation" ON "control"."contract_method_policy" CASCADE;--> statement-breakpoint
DROP TABLE "control"."contract_method_policy" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."logical_contract_asset" CASCADE;--> statement-breakpoint
DROP POLICY "privacy_domain_isolation" ON "control"."logical_contract_asset" CASCADE;--> statement-breakpoint
DROP TABLE "control"."logical_contract_asset" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."contract_runtime_binding" CASCADE;--> statement-breakpoint
DROP POLICY "privacy_domain_isolation" ON "control"."contract_runtime_binding" CASCADE;--> statement-breakpoint
DROP TABLE "control"."contract_runtime_binding" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."runtime_configuration_work" CASCADE;--> statement-breakpoint
DROP POLICY "privacy_domain_isolation" ON "control"."runtime_configuration_work" CASCADE;--> statement-breakpoint
DROP TABLE "control"."runtime_configuration_work" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."typed_argument_rule" CASCADE;--> statement-breakpoint
DROP POLICY "privacy_domain_isolation" ON "control"."typed_argument_rule" CASCADE;--> statement-breakpoint
DROP TABLE "control"."typed_argument_rule" CASCADE;--> statement-breakpoint
ALTER TABLE "control"."provider_profile" DROP CONSTRAINT "provider_profile_endpoint_secret_ref_ck";--> statement-breakpoint
ALTER TABLE "control"."configuration_work" ADD CONSTRAINT "configuration_work_generation_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","runtime_configuration_generation_id") REFERENCES "control"."runtime_configuration_generation"("participant_id","privacy_domain_id","runtime_configuration_generation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."configuration_work" ADD CONSTRAINT "configuration_work_target_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","runtime_target_id") REFERENCES "control"."runtime_target"("participant_id","privacy_domain_id","runtime_target_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."provider_profile" ADD CONSTRAINT "provider_profile_endpoint_secret_ref_ck" CHECK ("control"."provider_profile"."endpoint_secret_ref" ~ '^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$');--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."configuration_work" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."configuration_work"."participant_id")) WITH CHECK (openpc.matches_participant("control"."configuration_work"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."configuration_work" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."configuration_work"."participant_id") and openpc.matches_privacy("control"."configuration_work"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."configuration_work"."participant_id") and openpc.matches_privacy("control"."configuration_work"."privacy_domain_id"));
-- OPENPC CONTROL-API SECURITY TAIL
REVOKE ALL ON "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" FROM PUBLIC;
REVOKE ALL ON "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_runtime";
GRANT SELECT ON "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_worker";
GRANT UPDATE ON "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_worker";
GRANT SELECT ON "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_reader";
