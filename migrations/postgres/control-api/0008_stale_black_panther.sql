CREATE TABLE "control"."runtime_route_publication" (
	"runtime_route_publication_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"configuration_work_id" uuid NOT NULL,
	"runtime_configuration_generation_id" uuid NOT NULL,
	"runtime_target_id" uuid NOT NULL,
	"provider_profile_id" uuid NOT NULL,
	"qualification_observation_id" uuid NOT NULL,
	"generation_digest" text NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"provider_revision" bigint NOT NULL,
	"qualification_observation_digest" text NOT NULL,
	"routing_source_cbor" "bytea" NOT NULL,
	"routing_source_digest" text NOT NULL,
	"routing_authority_cose" "bytea" NOT NULL,
	"routing_authority_content_digest" text NOT NULL,
	"routing_authority_digest" text NOT NULL,
	"certification_source_cbor" "bytea" NOT NULL,
	"certification_source_digest" text NOT NULL,
	"certification_authority_cose" "bytea" NOT NULL,
	"certification_authority_content_digest" text NOT NULL,
	"certification_authority_digest" text NOT NULL,
	"valid_until" timestamp(6) with time zone NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "runtime_route_publication_generation_uq" UNIQUE("runtime_configuration_generation_id"),
	CONSTRAINT "runtime_route_publication_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","runtime_route_publication_id"),
	CONSTRAINT "runtime_route_publication_generation_digest_ck" CHECK ("control"."runtime_route_publication"."generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_policy_digest_ck" CHECK ("control"."runtime_route_publication"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_observation_digest_ck" CHECK ("control"."runtime_route_publication"."qualification_observation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_routing_source_digest_ck" CHECK ("control"."runtime_route_publication"."routing_source_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_routing_authority_content_digest_ck" CHECK ("control"."runtime_route_publication"."routing_authority_content_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_routing_authority_digest_ck" CHECK ("control"."runtime_route_publication"."routing_authority_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_certification_source_digest_ck" CHECK ("control"."runtime_route_publication"."certification_source_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_certification_authority_content_digest_ck" CHECK ("control"."runtime_route_publication"."certification_authority_content_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_certification_authority_digest_ck" CHECK ("control"."runtime_route_publication"."certification_authority_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_route_publication_provider_revision_ck" CHECK ("control"."runtime_route_publication"."provider_revision" > 0),
	CONSTRAINT "runtime_route_publication_source_content_ck" CHECK ("control"."runtime_route_publication"."routing_source_digest"='sha256:'||encode(sha256("control"."runtime_route_publication"."routing_source_cbor"),'hex') and "control"."runtime_route_publication"."routing_authority_content_digest"='sha256:'||encode(sha256("control"."runtime_route_publication"."routing_authority_cose"),'hex') and "control"."runtime_route_publication"."certification_source_digest"='sha256:'||encode(sha256("control"."runtime_route_publication"."certification_source_cbor"),'hex') and "control"."runtime_route_publication"."certification_authority_content_digest"='sha256:'||encode(sha256("control"."runtime_route_publication"."certification_authority_cose"),'hex')),
	CONSTRAINT "runtime_route_publication_validity_ck" CHECK ("control"."runtime_route_publication"."valid_until">"control"."runtime_route_publication"."created_at")
);
--> statement-breakpoint
ALTER TABLE "control"."runtime_route_publication" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."runtime_route_publication" ADD CONSTRAINT "runtime_route_publication_configuration_work_id_configuration_work_configuration_work_id_fk" FOREIGN KEY ("configuration_work_id") REFERENCES "control"."configuration_work"("configuration_work_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_route_publication" ADD CONSTRAINT "runtime_route_publication_runtime_configuration_generation_id_runtime_configuration_generation_runtime_configuration_generation_id_fk" FOREIGN KEY ("runtime_configuration_generation_id") REFERENCES "control"."runtime_configuration_generation"("runtime_configuration_generation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_route_publication" ADD CONSTRAINT "runtime_route_publication_runtime_target_id_runtime_target_runtime_target_id_fk" FOREIGN KEY ("runtime_target_id") REFERENCES "control"."runtime_target"("runtime_target_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_route_publication" ADD CONSTRAINT "runtime_route_publication_provider_profile_id_provider_profile_provider_profile_id_fk" FOREIGN KEY ("provider_profile_id") REFERENCES "control"."provider_profile"("provider_profile_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_route_publication" ADD CONSTRAINT "runtime_route_publication_qualification_observation_id_provider_probe_observation_observation_id_fk" FOREIGN KEY ("qualification_observation_id") REFERENCES "control"."provider_probe_observation"("observation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."runtime_route_publication" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_route_publication"."participant_id")) WITH CHECK (openpc.matches_participant("control"."runtime_route_publication"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."runtime_route_publication" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_route_publication"."participant_id") and openpc.matches_privacy("control"."runtime_route_publication"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."runtime_route_publication"."participant_id") and openpc.matches_privacy("control"."runtime_route_publication"."privacy_domain_id"));
-- OPENPC CONTROL-API SECURITY TAIL
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication" FROM PUBLIC;
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_activation_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."provider_probe_observation" TO "openpc_control_runtime";
GRANT SELECT ON "control"."runtime_route_publication" TO "openpc_control_runtime";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_activation_observation" TO "openpc_control_worker";
GRANT INSERT ON "control"."runtime_route_publication" TO "openpc_control_worker";
GRANT INSERT, UPDATE ON "control"."provider_probe_observation" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."provider_probe_observation", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work", "control"."runtime_activation_observation", "control"."runtime_route_publication" TO "openpc_control_reader";
CREATE OR REPLACE FUNCTION openpc.reject_runtime_activation_observation_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
DROP TRIGGER IF EXISTS runtime_activation_observation_immutable ON "control"."runtime_activation_observation";
CREATE TRIGGER runtime_activation_observation_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_activation_observation"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_runtime_activation_observation_mutation();
DROP TRIGGER IF EXISTS runtime_route_publication_immutable ON "control"."runtime_route_publication";
CREATE TRIGGER runtime_route_publication_immutable BEFORE UPDATE OR DELETE ON "control"."runtime_route_publication"
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
