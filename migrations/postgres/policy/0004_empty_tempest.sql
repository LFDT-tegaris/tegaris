CREATE TABLE "control"."policy_release_bundle" (
	"release_bundle_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"policy_version_id" uuid NOT NULL,
	"approval_request_id" uuid,
	"created_by_principal_id" uuid NOT NULL,
	"manifest_digest" "bytea" NOT NULL,
	"dependency_closure_digest" "bytea" NOT NULL,
	"state" text DEFAULT 'DRAFT' NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"published_at" timestamp(6) with time zone,
	CONSTRAINT "policy_release_bundle_digest_uq" UNIQUE("participant_id","privacy_domain_id","manifest_digest","dependency_closure_digest"),
	CONSTRAINT "policy_release_bundle_tenant_id_uq" UNIQUE("participant_id","privacy_domain_id","release_bundle_id"),
	CONSTRAINT "policy_release_bundle_state_ck" CHECK ("control"."policy_release_bundle"."state" in ('DRAFT','APPROVAL_PENDING','APPROVED','PUBLISHED','STAGED','ACTIVE','ROLLED_BACK','RETIRED')),
	CONSTRAINT "policy_release_bundle_digest_ck" CHECK (octet_length("control"."policy_release_bundle"."manifest_digest")=32 and octet_length("control"."policy_release_bundle"."dependency_closure_digest")=32),
	CONSTRAINT "policy_release_bundle_revision_ck" CHECK ("control"."policy_release_bundle"."revision">0),
	CONSTRAINT "policy_release_bundle_approval_ck" CHECK ("control"."policy_release_bundle"."state" not in ('APPROVED','PUBLISHED','STAGED','ACTIVE','ROLLED_BACK','RETIRED') or "control"."policy_release_bundle"."approval_request_id" is not null),
	CONSTRAINT "policy_release_bundle_published_ck" CHECK (("control"."policy_release_bundle"."state" in ('PUBLISHED','STAGED','ACTIVE','ROLLED_BACK','RETIRED'))=("control"."policy_release_bundle"."published_at" is not null))
);
--> statement-breakpoint
ALTER TABLE "control"."policy_release_bundle" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."policy_release_bundle" ADD CONSTRAINT "policy_release_bundle_version_fk" FOREIGN KEY ("participant_id","privacy_domain_id","policy_version_id") REFERENCES "control"."policy_version"("participant_id","privacy_domain_id","policy_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_release_bundle" ADD CONSTRAINT "policy_release_bundle_approval_fk" FOREIGN KEY ("participant_id","approval_request_id") REFERENCES "control"."approval_request"("participant_id","approval_request_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_release_bundle" ADD CONSTRAINT "policy_release_bundle_creator_fk" FOREIGN KEY ("participant_id","created_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_release_bundle" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_release_bundle"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_release_bundle"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_release_bundle" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_release_bundle"."participant_id") and openpc.matches_privacy("control"."policy_release_bundle"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_release_bundle"."participant_id") and openpc.matches_privacy("control"."policy_release_bundle"."privacy_domain_id"));
-- OPENPC GENERATED POLICY SECURITY TAIL; DO NOT EDIT
ALTER TABLE "control"."module_configuration_generation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."module_installation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_activation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_activation_prerequisite" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_artifact" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_generation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_release_bundle" FORCE ROW LEVEL SECURITY;
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
ALTER TABLE "control"."policy_release_bundle" OWNER TO "openpc_control_owner";
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
REVOKE ALL ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" FROM PUBLIC;
REVOKE ALL ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT SELECT ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_worker";
GRANT INSERT ON "control"."policy", "control"."policy_artifact", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE ON "control"."policy" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE ON "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_generation", "control"."policy_release_bundle" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_maintenance";
GRANT SELECT ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" TO "openpc_backup_operator";
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
