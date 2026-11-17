CREATE TABLE "control"."provider_probe_observation" (
	"observation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"provider_profile_id" uuid NOT NULL,
	"source_revision" bigint NOT NULL,
	"observed_revision" bigint,
	"input_digest" text NOT NULL,
	"configuration_digest" text NOT NULL,
	"state" text DEFAULT 'RUNNING' NOT NULL,
	"lease_token" uuid NOT NULL,
	"lease_until" timestamp(6) with time zone NOT NULL,
	"observation" jsonb,
	"observation_digest" text,
	"valid_until" timestamp(6) with time zone,
	"last_error_code" text,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"completed_at" timestamp(6) with time zone,
	CONSTRAINT "provider_probe_revision_configuration_uq" UNIQUE("provider_profile_id","source_revision","configuration_digest"),
	CONSTRAINT "provider_probe_source_revision_ck" CHECK ("control"."provider_probe_observation"."source_revision" > 0),
	CONSTRAINT "provider_probe_state_ck" CHECK ("control"."provider_probe_observation"."state" in ('RUNNING','OBSERVED','FAILED')),
	CONSTRAINT "provider_probe_completion_ck" CHECK (("control"."provider_probe_observation"."state"<>'RUNNING') = ("control"."provider_probe_observation"."completed_at" is not null)),
	CONSTRAINT "provider_probe_observation_ck" CHECK (("control"."provider_probe_observation"."state"='OBSERVED' and "control"."provider_probe_observation"."observation" is not null and "control"."provider_probe_observation"."observation_digest" is not null and "control"."provider_probe_observation"."observed_revision" is not null and "control"."provider_probe_observation"."observed_revision"="control"."provider_probe_observation"."source_revision"+1 and "control"."provider_probe_observation"."valid_until" is not null and "control"."provider_probe_observation"."valid_until">"control"."provider_probe_observation"."completed_at") or ("control"."provider_probe_observation"."state"<>'OBSERVED' and "control"."provider_probe_observation"."observation" is null and "control"."provider_probe_observation"."observation_digest" is null and "control"."provider_probe_observation"."observed_revision" is null and "control"."provider_probe_observation"."valid_until" is null)),
	CONSTRAINT "provider_probe_failure_ck" CHECK (("control"."provider_probe_observation"."state"='FAILED') = ("control"."provider_probe_observation"."last_error_code" is not null)),
	CONSTRAINT "provider_probe_input_digest_ck" CHECK ("control"."provider_probe_observation"."input_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "provider_probe_configuration_digest_ck" CHECK ("control"."provider_probe_observation"."configuration_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "provider_probe_observation_digest_ck" CHECK ("control"."provider_probe_observation"."observation_digest" is null or "control"."provider_probe_observation"."observation_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."provider_probe_observation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."provider_profile" ADD COLUMN "qualification_observation_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."provider_probe_observation" ADD CONSTRAINT "provider_probe_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","provider_profile_id") REFERENCES "control"."provider_profile"("participant_id","privacy_domain_id","provider_profile_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."provider_probe_observation" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."provider_probe_observation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."provider_probe_observation"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."provider_probe_observation" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."provider_probe_observation"."participant_id") and openpc.matches_privacy("control"."provider_probe_observation"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."provider_probe_observation"."participant_id") and openpc.matches_privacy("control"."provider_probe_observation"."privacy_domain_id"));
-- OPENPC CONTROL-API SECURITY TAIL
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation" FROM PUBLIC;
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."provider_probe_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."provider_probe_observation" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation" TO "openpc_control_reader";
CREATE OR REPLACE FUNCTION openpc.reject_runtime_activation_observation_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
DROP TRIGGER IF EXISTS runtime_activation_observation_immutable ON "control"."runtime_activation_observation";
CREATE TRIGGER runtime_activation_observation_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_activation_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
CREATE OR REPLACE FUNCTION openpc.guard_provider_probe_observation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  IF TG_OP='DELETE' OR OLD.state<>'RUNNING' OR
    ROW(NEW.observation_id,NEW.participant_id,NEW.privacy_domain_id,NEW.provider_profile_id,
        NEW.source_revision,NEW.input_digest,NEW.configuration_digest,NEW.created_at)
    IS DISTINCT FROM
    ROW(OLD.observation_id,OLD.participant_id,OLD.privacy_domain_id,OLD.provider_profile_id,
        OLD.source_revision,OLD.input_digest,OLD.configuration_digest,OLD.created_at) THEN
    RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='DATA-6020-IMMUTABLE-ROW';
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS provider_probe_observation_guard ON "control"."provider_probe_observation";
CREATE TRIGGER provider_probe_observation_guard BEFORE UPDATE OR DELETE ON "control"."provider_probe_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.guard_provider_probe_observation();
