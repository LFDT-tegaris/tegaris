CREATE TABLE "control"."runtime_activation_observation" (
	"runtime_activation_observation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"configuration_work_id" uuid NOT NULL,
	"operation_id" uuid NOT NULL,
	"execution_attempt_id" uuid NOT NULL,
	"runtime_configuration_generation_id" uuid NOT NULL,
	"runtime_target_id" uuid NOT NULL,
	"generation_digest" text NOT NULL,
	"capsule_digest" text NOT NULL,
	"xds_version_digest" text NOT NULL,
	"activation_receipt" jsonb NOT NULL,
	"activation_receipt_digest" text NOT NULL,
	"observed_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "runtime_activation_observation_work_uq" UNIQUE("configuration_work_id"),
	CONSTRAINT "runtime_activation_observation_attempt_uq" UNIQUE("execution_attempt_id"),
	CONSTRAINT "runtime_activation_observation_generation_uq" UNIQUE("runtime_target_id","runtime_configuration_generation_id"),
	CONSTRAINT "runtime_activation_observation_generation_digest_ck" CHECK ("control"."runtime_activation_observation"."generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_activation_observation_capsule_digest_ck" CHECK ("control"."runtime_activation_observation"."capsule_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_activation_observation_xds_digest_ck" CHECK ("control"."runtime_activation_observation"."xds_version_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_activation_observation_receipt_digest_ck" CHECK ("control"."runtime_activation_observation"."activation_receipt_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."runtime_activation_observation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."configuration_work" DROP CONSTRAINT "configuration_work_state_ck";--> statement-breakpoint
ALTER TABLE "control"."configuration_work" ADD COLUMN "execution_attempt_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."configuration_work" ADD COLUMN "execution_started_at" timestamp(6) with time zone;--> statement-breakpoint
ALTER TABLE "control"."configuration_work" ADD COLUMN "reconcile_after" timestamp(6) with time zone;--> statement-breakpoint
ALTER TABLE "control"."runtime_activation_observation" ADD CONSTRAINT "runtime_activation_observation_configuration_work_id_configuration_work_configuration_work_id_fk" FOREIGN KEY ("configuration_work_id") REFERENCES "control"."configuration_work"("configuration_work_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_activation_observation" ADD CONSTRAINT "runtime_activation_observation_runtime_configuration_generation_id_runtime_configuration_generation_runtime_configuration_generation_id_fk" FOREIGN KEY ("runtime_configuration_generation_id") REFERENCES "control"."runtime_configuration_generation"("runtime_configuration_generation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_activation_observation" ADD CONSTRAINT "runtime_activation_observation_runtime_target_id_runtime_target_runtime_target_id_fk" FOREIGN KEY ("runtime_target_id") REFERENCES "control"."runtime_target"("runtime_target_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."configuration_work" ADD CONSTRAINT "configuration_work_execution_ck" CHECK (("control"."configuration_work"."execution_started_at" is null) = ("control"."configuration_work"."execution_attempt_id" is null) and ("control"."configuration_work"."state"<>'RECONCILING' or ("control"."configuration_work"."execution_attempt_id" is not null and "control"."configuration_work"."execution_started_at" is not null and "control"."configuration_work"."reconcile_after" is not null)));--> statement-breakpoint
ALTER TABLE "control"."configuration_work" ADD CONSTRAINT "configuration_work_state_ck" CHECK ("control"."configuration_work"."state" in ('PENDING','LEASED','RECONCILING','COMPLETED','FAILED'));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."runtime_activation_observation" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_activation_observation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."runtime_activation_observation"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."runtime_activation_observation" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_activation_observation"."participant_id") and openpc.matches_privacy("control"."runtime_activation_observation"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."runtime_activation_observation"."participant_id") and openpc.matches_privacy("control"."runtime_activation_observation"."privacy_domain_id"));
-- OPENPC CONTROL-API SECURITY TAIL
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation" FROM PUBLIC;
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation" TO "openpc_control_reader";
CREATE OR REPLACE FUNCTION openpc.reject_runtime_activation_observation_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
DROP TRIGGER IF EXISTS runtime_activation_observation_immutable ON "control"."runtime_activation_observation";
CREATE TRIGGER runtime_activation_observation_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_activation_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
