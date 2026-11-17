CREATE TABLE "control"."runtime_configuration_work" (
	"runtime_configuration_work_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"runtime_configuration_generation_id" uuid NOT NULL,
	"runtime_target_id" uuid NOT NULL,
	"generation_digest" text NOT NULL,
	"predecessor_digest" text,
	"policy_generation_digest" text NOT NULL,
	"xds_version_digest" text NOT NULL,
	"state" text DEFAULT 'PENDING' NOT NULL,
	"attempt_count" bigint DEFAULT 0 NOT NULL,
	"lease_owner" text,
	"lease_until" timestamp(6) with time zone,
	"activation_receipt" jsonb,
	"activation_receipt_digest" text,
	"last_error_code" text,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"completed_at" timestamp(6) with time zone,
	CONSTRAINT "runtime_configuration_work_generation_uq" UNIQUE("runtime_configuration_generation_id"),
	CONSTRAINT "runtime_configuration_work_state_ck" CHECK ("control"."runtime_configuration_work"."state" in ('PENDING','LEASED','COMPLETED','FAILED')),
	CONSTRAINT "runtime_configuration_work_attempt_count_ck" CHECK ("control"."runtime_configuration_work"."attempt_count" >= 0),
	CONSTRAINT "runtime_configuration_work_lease_ck" CHECK (("control"."runtime_configuration_work"."state"='LEASED') = ("control"."runtime_configuration_work"."lease_owner" is not null and "control"."runtime_configuration_work"."lease_until" is not null)),
	CONSTRAINT "runtime_configuration_work_receipt_ck" CHECK (("control"."runtime_configuration_work"."state"='COMPLETED') = ("control"."runtime_configuration_work"."activation_receipt" is not null and "control"."runtime_configuration_work"."activation_receipt_digest" is not null and "control"."runtime_configuration_work"."completed_at" is not null)),
	CONSTRAINT "runtime_configuration_work_generation_digest_ck" CHECK ("control"."runtime_configuration_work"."generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_configuration_work_predecessor_digest_ck" CHECK ("control"."runtime_configuration_work"."predecessor_digest" is null or "control"."runtime_configuration_work"."predecessor_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_configuration_work_policy_digest_ck" CHECK ("control"."runtime_configuration_work"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_configuration_work_xds_digest_ck" CHECK ("control"."runtime_configuration_work"."xds_version_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_configuration_work_receipt_digest_ck" CHECK ("control"."runtime_configuration_work"."activation_receipt_digest" is null or "control"."runtime_configuration_work"."activation_receipt_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_configuration_work_error_ck" CHECK ("control"."runtime_configuration_work"."last_error_code" is null or "control"."runtime_configuration_work"."last_error_code" ~ '^PC-[A-Z]+-[0-9]{4}$')
);
--> statement-breakpoint
ALTER TABLE "control"."runtime_configuration_work" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."runtime_configuration_work" ADD CONSTRAINT "runtime_configuration_work_generation_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","runtime_configuration_generation_id") REFERENCES "control"."runtime_configuration_generation"("participant_id","privacy_domain_id","runtime_configuration_generation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_configuration_work" ADD CONSTRAINT "runtime_configuration_work_target_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","runtime_target_id") REFERENCES "control"."runtime_target"("participant_id","privacy_domain_id","runtime_target_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_configuration_generation" ADD CONSTRAINT "runtime_configuration_generation_predecessor_digest_ck" CHECK ("control"."runtime_configuration_generation"."predecessor_digest" is null or "control"."runtime_configuration_generation"."predecessor_digest" ~ '^sha256:[0-9a-f]{64}$');--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."runtime_configuration_work" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_configuration_work"."participant_id")) WITH CHECK (openpc.matches_participant("control"."runtime_configuration_work"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."runtime_configuration_work" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_configuration_work"."participant_id") and openpc.matches_privacy("control"."runtime_configuration_work"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."runtime_configuration_work"."participant_id") and openpc.matches_privacy("control"."runtime_configuration_work"."privacy_domain_id"));
-- OPENPC CONTROL-API SECURITY TAIL
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."runtime_configuration_work" FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."runtime_configuration_work" TO "openpc_control_runtime";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."runtime_configuration_work" TO "openpc_control_worker";
GRANT UPDATE ON "control"."runtime_configuration_work", "control"."runtime_configuration_generation", "control"."runtime_target" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."runtime_configuration_work" TO "openpc_control_reader";
