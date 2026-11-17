CREATE TABLE "control"."policy_activation_occurrence_target" (
	"activation_occurrence_id" uuid NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"runtime_target_id" uuid NOT NULL,
	"phase" text DEFAULT 'FORWARD' NOT NULL,
	"expected_target_revision" bigint NOT NULL,
	"expected_predecessor_digest" text,
	"runtime_configuration_generation_id" uuid,
	"configuration_work_id" uuid,
	"command_operation_id" uuid,
	"state" text DEFAULT 'REQUESTED' NOT NULL,
	"observed_generation_digest" text,
	"activation_receipt_digest" text,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "policy_activation_occurrence_target_pk" PRIMARY KEY("activation_occurrence_id","runtime_target_id","phase"),
	CONSTRAINT "policy_activation_occurrence_target_phase_ck" CHECK ("control"."policy_activation_occurrence_target"."phase" in ('FORWARD','ROLLBACK')),
	CONSTRAINT "policy_activation_occurrence_target_state_ck" CHECK ("control"."policy_activation_occurrence_target"."state" in ('REQUESTED','STAGING','ACTIVE_MATCHED','FAILED','WRITE_AMBIGUITY','ROLLED_BACK')),
	CONSTRAINT "policy_activation_occurrence_target_predecessor_ck" CHECK ("control"."policy_activation_occurrence_target"."expected_predecessor_digest" is null or "control"."policy_activation_occurrence_target"."expected_predecessor_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "policy_activation_occurrence_target_observed_ck" CHECK ("control"."policy_activation_occurrence_target"."observed_generation_digest" is null or "control"."policy_activation_occurrence_target"."observed_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "policy_activation_occurrence_target_receipt_ck" CHECK ("control"."policy_activation_occurrence_target"."activation_receipt_digest" is null or "control"."policy_activation_occurrence_target"."activation_receipt_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."policy_activation_occurrence_target" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."policy_activation_occurrence" (
	"activation_occurrence_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"release_bundle_id" uuid NOT NULL,
	"policy_generation_id" uuid NOT NULL,
	"created_by_principal_id" uuid NOT NULL,
	"target_generation_digest" "bytea" NOT NULL,
	"exact_cohort_digest" "bytea" NOT NULL,
	"state" text DEFAULT 'REQUESTED' NOT NULL,
	"matched_target_count" bigint DEFAULT 0 NOT NULL,
	"total_target_count" bigint NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"activated_at" timestamp(6) with time zone,
	"rollback_started_at" timestamp(6) with time zone,
	"rolled_back_at" timestamp(6) with time zone,
	CONSTRAINT "policy_activation_occurrence_generation_uq" UNIQUE("participant_id","privacy_domain_id","policy_generation_id"),
	CONSTRAINT "policy_activation_occurrence_tenant_id_uq" UNIQUE("participant_id","privacy_domain_id","activation_occurrence_id"),
	CONSTRAINT "policy_activation_occurrence_state_ck" CHECK ("control"."policy_activation_occurrence"."state" in ('REQUESTED','STAGING','PARTIAL','ACTIVE_MATCHED','FAILED','ROLLING_BACK','ROLLED_BACK')),
	CONSTRAINT "policy_activation_occurrence_digest_ck" CHECK (octet_length("control"."policy_activation_occurrence"."target_generation_digest")=32 and octet_length("control"."policy_activation_occurrence"."exact_cohort_digest")=32),
	CONSTRAINT "policy_activation_occurrence_count_ck" CHECK ("control"."policy_activation_occurrence"."total_target_count">0 and "control"."policy_activation_occurrence"."matched_target_count">=0 and "control"."policy_activation_occurrence"."matched_target_count"<="control"."policy_activation_occurrence"."total_target_count"),
	CONSTRAINT "policy_activation_occurrence_revision_ck" CHECK ("control"."policy_activation_occurrence"."revision">0)
);
--> statement-breakpoint
ALTER TABLE "control"."policy_activation_occurrence" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."policy_activation_occurrence_target" ADD CONSTRAINT "policy_activation_occurrence_target_occurrence_fk" FOREIGN KEY ("participant_id","privacy_domain_id","activation_occurrence_id") REFERENCES "control"."policy_activation_occurrence"("participant_id","privacy_domain_id","activation_occurrence_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_activation_occurrence" ADD CONSTRAINT "policy_activation_occurrence_release_fk" FOREIGN KEY ("participant_id","privacy_domain_id","release_bundle_id") REFERENCES "control"."policy_release_bundle"("participant_id","privacy_domain_id","release_bundle_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_activation_occurrence" ADD CONSTRAINT "policy_activation_occurrence_generation_fk" FOREIGN KEY ("participant_id","privacy_domain_id","policy_generation_id") REFERENCES "control"."policy_generation"("participant_id","privacy_domain_id","policy_generation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_activation_occurrence" ADD CONSTRAINT "policy_activation_occurrence_creator_fk" FOREIGN KEY ("participant_id","created_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "policy_activation_occurrence_target_state_idx" ON "control"."policy_activation_occurrence_target" USING btree ("participant_id","privacy_domain_id","activation_occurrence_id","phase","state");--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_activation_occurrence_target" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_activation_occurrence_target"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_activation_occurrence_target"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_activation_occurrence_target" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_activation_occurrence_target"."participant_id") and openpc.matches_privacy("control"."policy_activation_occurrence_target"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_activation_occurrence_target"."participant_id") and openpc.matches_privacy("control"."policy_activation_occurrence_target"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_activation_occurrence" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_activation_occurrence"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_activation_occurrence"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_activation_occurrence" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_activation_occurrence"."participant_id") and openpc.matches_privacy("control"."policy_activation_occurrence"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_activation_occurrence"."participant_id") and openpc.matches_privacy("control"."policy_activation_occurrence"."privacy_domain_id"));
-- OPENPC GENERATED POLICY SECURITY TAIL; DO NOT EDIT
ALTER TABLE "control"."module_configuration_generation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."module_installation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_activation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_activation_occurrence" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."policy_activation_occurrence_target" FORCE ROW LEVEL SECURITY;
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
ALTER TABLE "control"."policy_activation_occurrence" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."policy_activation_occurrence_target" OWNER TO "openpc_control_owner";
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
REVOKE ALL ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" FROM PUBLIC;
REVOKE ALL ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT SELECT ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_worker";
GRANT INSERT ON "control"."policy", "control"."policy_artifact", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE ON "control"."policy" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE ON "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_activation_prerequisite", "control"."policy_generation", "control"."policy_release_bundle" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT DELETE ON "control"."policy_activation_occurrence_target" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE ON "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_generation", "control"."policy_release_bundle" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" TO "openpc_control_maintenance";
GRANT SELECT ON "control"."module_capability", "control"."module_configuration_generation", "control"."module_conflict", "control"."module_dependency", "control"."module_installation", "control"."module_registration", "control"."module_version", "control"."policy", "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_activation_prerequisite", "control"."policy_artifact", "control"."policy_generation", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version" TO "openpc_backup_operator";
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
