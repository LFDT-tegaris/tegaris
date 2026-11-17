CREATE TABLE "control"."policy_artifact" (
	"policy_artifact_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"policy_id" uuid NOT NULL,
	"semantic_version" varchar(64) NOT NULL,
	"policy_schema_digest" "bytea" NOT NULL,
	"semantic_cbor" "bytea" NOT NULL,
	"semantic_digest" "bytea" NOT NULL,
	"semantic_bytes_digest" "bytea" NOT NULL,
	"dependency_closure_digest" "bytea" NOT NULL,
	"payload_cbor" "bytea" NOT NULL,
	"payload_digest" "bytea" NOT NULL,
	"cose_sign1" "bytea" NOT NULL,
	"signer_key_digest" "bytea" NOT NULL,
	"admitted_by_principal_id" uuid NOT NULL,
	"admitted_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "policy_artifact_semantic_digest_uq" UNIQUE("participant_id","privacy_domain_id","semantic_digest"),
	CONSTRAINT "policy_artifact_version_uq" UNIQUE("participant_id","privacy_domain_id","policy_id","semantic_version","policy_schema_digest"),
	CONSTRAINT "policy_artifact_participant_id_uq" UNIQUE("participant_id","policy_artifact_id"),
	CONSTRAINT "policy_artifact_tenant_id_uq" UNIQUE("participant_id","privacy_domain_id","policy_artifact_id"),
	CONSTRAINT "policy_artifact_digests_ck" CHECK (octet_length("control"."policy_artifact"."policy_schema_digest")=32 and octet_length("control"."policy_artifact"."semantic_digest")=32 and octet_length("control"."policy_artifact"."semantic_bytes_digest")=32 and octet_length("control"."policy_artifact"."dependency_closure_digest")=32 and octet_length("control"."policy_artifact"."payload_digest")=32 and octet_length("control"."policy_artifact"."signer_key_digest")=32 and "control"."policy_artifact"."semantic_digest"="control"."policy_artifact"."semantic_bytes_digest" and "control"."policy_artifact"."semantic_version" ~ '^[0-9]+.[0-9]+.[0-9]+$')
);
--> statement-breakpoint
ALTER TABLE "control"."policy_artifact" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."policy_artifact" ADD CONSTRAINT "policy_artifact_policy_fk" FOREIGN KEY ("participant_id","privacy_domain_id","policy_id") REFERENCES "control"."policy"("participant_id","privacy_domain_id","policy_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_artifact" ADD CONSTRAINT "policy_artifact_admitter_fk" FOREIGN KEY ("participant_id","admitted_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_artifact" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_artifact"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_artifact"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_artifact" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_artifact"."participant_id") and openpc.matches_privacy("control"."policy_artifact"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_artifact"."participant_id") and openpc.matches_privacy("control"."policy_artifact"."privacy_domain_id"));
-- OPENPC GENERATED POLICY SECURITY TAIL; DO NOT EDIT
ALTER TABLE "control"."module_configuration_generation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."module_installation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_activation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_activation_prerequisite" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_artifact" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_generation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_simulation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_version" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."module_capability" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."module_configuration_generation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."module_conflict" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."module_dependency" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."module_installation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."module_registration" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."module_version" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."policy" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."policy_activation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."policy_activation_prerequisite" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."policy_artifact" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."policy_generation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."policy_simulation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."policy_version" OWNER TO "openpc_control_owner";
CREATE OR REPLACE FUNCTION openpc.reject_policy_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
DROP TRIGGER IF EXISTS policy_artifact_immutable ON "control"."policy_artifact";
CREATE TRIGGER policy_artifact_immutable BEFORE UPDATE OR DELETE ON "control"."policy_artifact"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_policy_immutable_mutation();
DROP TRIGGER IF EXISTS policy_simulation_immutable ON "control"."policy_simulation";
CREATE TRIGGER policy_simulation_immutable BEFORE UPDATE OR DELETE ON "control"."policy_simulation"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_policy_immutable_mutation();
DROP TRIGGER IF EXISTS policy_version_immutable ON "control"."policy_version";
CREATE TRIGGER policy_version_immutable BEFORE UPDATE OR DELETE ON "control"."policy_version"
FOR EACH ROW EXECUTE FUNCTION openpc.reject_policy_immutable_mutation();
REVOKE ALL ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_simulation", "control"."policy_version" FROM PUBLIC;
REVOKE ALL ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_simulation", "control"."policy_version" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT SELECT ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_worker";
GRANT INSERT ON "control"."policy", "control"."policy_artifact", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE ON "control"."policy" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE ON "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_generation" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_maintenance";
GRANT SELECT ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_simulation", "control"."policy_version" TO "openpc_backup_operator";
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
