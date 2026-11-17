CREATE SCHEMA "control";
--> statement-breakpoint
CREATE TYPE "control"."module_lifecycle_state" AS ENUM('ABSENT', 'ADMITTED', 'INSTALLED_DISABLED', 'ENABLING', 'ENABLED', 'DISABLING', 'UPGRADING', 'DOWNGRADING', 'ROLLING_BACK', 'UNINSTALLING', 'REMOVED', 'FAILED_FENCED');--> statement-breakpoint
CREATE TYPE "control"."policy_lifecycle_state" AS ENUM('EDITABLE_DRAFT', 'IMMUTABLE_VERSION', 'PENDING_APPROVAL', 'APPROVED', 'IMMUTABLE_RELEASE', 'DESIRED', 'PREPARED', 'ACTIVE', 'RETIRED', 'FAILED_FENCED');--> statement-breakpoint
CREATE TYPE "control"."policy_truth_state" AS ENUM('SUCCESS', 'AUTHORIZED_EMPTY', 'DENIED', 'LOADING', 'UNKNOWN', 'UNAVAILABLE', 'STALE', 'REORG', 'PARTIAL', 'CONFLICTING', 'DEGRADED', 'FAILED', 'RETRY_ELIGIBLE', 'FAILOVER_ELIGIBLE', 'WRITE_AMBIGUITY', 'RECOVERY', 'ROLLBACK', 'RETIREMENT', 'UNINSTALL', 'DECOMMISSION');--> statement-breakpoint
CREATE TYPE "control"."policy_prerequisite_state" AS ENUM('PENDING', 'READY', 'FAILED', 'STALE');--> statement-breakpoint
CREATE TYPE "control"."policy_prerequisite_type" AS ENUM('SIMULATION', 'APPROVAL', 'FACT_READINESS', 'FLEET_READY', 'DEPENDENCY_CLOSURE', 'CONFLICT_CLOSURE');--> statement-breakpoint
CREATE TABLE "control"."module_capability" (
	"module_version_id" uuid NOT NULL,
	"capability_id" text NOT NULL,
	"contract_digest" "bytea" NOT NULL,
	CONSTRAINT "module_capability_pk" PRIMARY KEY("module_version_id","capability_id"),
	CONSTRAINT "module_capability_digest_ck" CHECK (octet_length("control"."module_capability"."contract_digest")=32)
);
--> statement-breakpoint
CREATE TABLE "control"."module_configuration_generation" (
	"generation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"module_installation_id" uuid NOT NULL,
	"generation" bigint NOT NULL,
	"configuration_cbor" "bytea" NOT NULL,
	"configuration_digest" "bytea" NOT NULL,
	"active" boolean DEFAULT false NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "module_configuration_generation_uq" UNIQUE("module_installation_id","generation")
);
--> statement-breakpoint
ALTER TABLE "control"."module_configuration_generation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."module_conflict" (
	"conflict_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"module_version_id" uuid NOT NULL,
	"conflicting_module_version_id" uuid NOT NULL,
	"conflict_type" text NOT NULL,
	"resolution_digest" "bytea",
	CONSTRAINT "module_conflict_pair_uq" UNIQUE("module_version_id","conflicting_module_version_id","conflict_type")
);
--> statement-breakpoint
CREATE TABLE "control"."module_dependency" (
	"consumer_module_version_id" uuid NOT NULL,
	"edge_id" text NOT NULL,
	"provider_module_id" varchar(160) NOT NULL,
	"capability_id" text NOT NULL,
	"semantic_version" varchar(64) NOT NULL,
	"provider_manifest_digest" "bytea" NOT NULL,
	CONSTRAINT "module_dependency_pk" PRIMARY KEY("consumer_module_version_id","edge_id"),
	CONSTRAINT "module_dependency_provider_uq" UNIQUE("consumer_module_version_id","capability_id"),
	CONSTRAINT "module_dependency_digest_ck" CHECK (octet_length("control"."module_dependency"."provider_manifest_digest")=32)
);
--> statement-breakpoint
CREATE TABLE "control"."module_installation" (
	"module_installation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"module_version_id" uuid NOT NULL,
	"state" "control"."module_lifecycle_state" DEFAULT 'INSTALLED_DISABLED' NOT NULL,
	"authority_epoch" bigint NOT NULL,
	"delegation_epoch" bigint NOT NULL,
	"aggregate_version" bigint DEFAULT 1 NOT NULL,
	"desired_manifest_digest" "bytea" NOT NULL,
	"active_manifest_digest" "bytea",
	"idempotency_key" varchar(256) NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "module_installation_scope_uq" UNIQUE("participant_id","privacy_domain_id","module_version_id"),
	CONSTRAINT "module_installation_idempotency_uq" UNIQUE("participant_id","idempotency_key"),
	CONSTRAINT "module_installation_epoch_ck" CHECK ("control"."module_installation"."authority_epoch">0 and "control"."module_installation"."delegation_epoch">0 and "control"."module_installation"."aggregate_version">0)
);
--> statement-breakpoint
ALTER TABLE "control"."module_installation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."module_registration" (
	"module_id" varchar(160) PRIMARY KEY NOT NULL,
	"display_name" text NOT NULL,
	"owner" text NOT NULL,
	"state" "control"."module_lifecycle_state" DEFAULT 'ADMITTED' NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "module_registration_id_ck" CHECK ("control"."module_registration"."module_id" ~ '^pc\.[a-z0-9.-]+$')
);
--> statement-breakpoint
CREATE TABLE "control"."module_version" (
	"module_version_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"module_id" varchar(160) NOT NULL,
	"semantic_version" varchar(64) NOT NULL,
	"manifest_cbor" "bytea" NOT NULL,
	"manifest_digest" "bytea" NOT NULL,
	"cose_sign1" "bytea" NOT NULL,
	"sbom_digest" "bytea" NOT NULL,
	"provenance_digest" "bytea" NOT NULL,
	"build_receipt_digest" "bytea" NOT NULL,
	"admitted_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "module_version_identity_uq" UNIQUE("module_id","semantic_version","manifest_digest"),
	CONSTRAINT "module_version_digests_ck" CHECK (octet_length("control"."module_version"."manifest_digest")=32 and octet_length("control"."module_version"."sbom_digest")=32 and octet_length("control"."module_version"."provenance_digest")=32 and octet_length("control"."module_version"."build_receipt_digest")=32)
);
--> statement-breakpoint
CREATE TABLE "control"."policy" (
	"policy_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"policy_name" text NOT NULL,
	"state" "control"."policy_lifecycle_state" DEFAULT 'EDITABLE_DRAFT' NOT NULL,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "policy_scope_name_uq" UNIQUE("participant_id","privacy_domain_id","policy_name"),
	CONSTRAINT "policy_participant_id_uq" UNIQUE("participant_id","policy_id"),
	CONSTRAINT "policy_tenant_id_uq" UNIQUE("participant_id","privacy_domain_id","policy_id")
);
--> statement-breakpoint
ALTER TABLE "control"."policy" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."policy_activation_prerequisite" (
	"policy_activation_id" uuid NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"prerequisite_type" "control"."policy_prerequisite_type" NOT NULL,
	"prerequisite_subject_digest" "bytea" NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"ready" boolean NOT NULL,
	"observed_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "policy_activation_prerequisite_pk" PRIMARY KEY("policy_activation_id","prerequisite_type"),
	CONSTRAINT "policy_activation_prerequisite_receipt_uq" UNIQUE("participant_id","privacy_domain_id","prerequisite_type","receipt_digest"),
	CONSTRAINT "policy_activation_prerequisite_digest_ck" CHECK (octet_length("control"."policy_activation_prerequisite"."prerequisite_subject_digest")=32 and octet_length("control"."policy_activation_prerequisite"."receipt_digest")=32)
);
--> statement-breakpoint
ALTER TABLE "control"."policy_activation_prerequisite" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."policy_activation" (
	"policy_activation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"policy_generation_id" uuid NOT NULL,
	"exact_cohort_digest" "bytea" NOT NULL,
	"prior_generation_digest" "bytea",
	"receipt_digest" "bytea",
	"state" "control"."policy_lifecycle_state" DEFAULT 'PREPARED' NOT NULL,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"prepared_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"activated_at" timestamp(6) with time zone,
	"fenced_at" timestamp(6) with time zone,
	"retired_at" timestamp(6) with time zone,
	CONSTRAINT "policy_activation_generation_uq" UNIQUE("participant_id","policy_generation_id"),
	CONSTRAINT "policy_activation_participant_id_uq" UNIQUE("participant_id","policy_activation_id"),
	CONSTRAINT "policy_activation_tenant_id_uq" UNIQUE("participant_id","privacy_domain_id","policy_activation_id"),
	CONSTRAINT "policy_activation_digests_ck" CHECK (octet_length("control"."policy_activation"."exact_cohort_digest")=32 and ("control"."policy_activation"."prior_generation_digest" is null or octet_length("control"."policy_activation"."prior_generation_digest")=32) and ("control"."policy_activation"."receipt_digest" is null or octet_length("control"."policy_activation"."receipt_digest")=32))
);
--> statement-breakpoint
ALTER TABLE "control"."policy_activation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."policy_generation" (
	"policy_generation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"policy_version_id" uuid NOT NULL,
	"simulation_id" uuid NOT NULL,
	"approval_request_id" uuid NOT NULL,
	"generation" bigint NOT NULL,
	"scope_digest" "bytea" NOT NULL,
	"generation_digest" "bytea" NOT NULL,
	"fact_generation_digest" "bytea" NOT NULL,
	"artifact_digest" "bytea" NOT NULL,
	"compiler_manifest_digest" "bytea" NOT NULL,
	"dependency_closure_digest" "bytea" NOT NULL,
	"state" "control"."policy_lifecycle_state" DEFAULT 'DESIRED' NOT NULL,
	"active" boolean DEFAULT false NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "policy_generation_number_uq" UNIQUE("participant_id","privacy_domain_id","policy_version_id","generation"),
	CONSTRAINT "policy_generation_digest_uq" UNIQUE("participant_id","generation_digest"),
	CONSTRAINT "policy_generation_participant_id_uq" UNIQUE("participant_id","policy_generation_id"),
	CONSTRAINT "policy_generation_tenant_id_uq" UNIQUE("participant_id","privacy_domain_id","policy_generation_id"),
	CONSTRAINT "policy_generation_digests_ck" CHECK (octet_length("control"."policy_generation"."scope_digest")=32 and octet_length("control"."policy_generation"."generation_digest")=32 and octet_length("control"."policy_generation"."fact_generation_digest")=32 and octet_length("control"."policy_generation"."artifact_digest")=32 and octet_length("control"."policy_generation"."compiler_manifest_digest")=32 and octet_length("control"."policy_generation"."dependency_closure_digest")=32)
);
--> statement-breakpoint
ALTER TABLE "control"."policy_generation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."policy_simulation" (
	"simulation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"policy_version_id" uuid NOT NULL,
	"input_digest" "bytea" NOT NULL,
	"result_digest" "bytea" NOT NULL,
	"fact_generation_digest" "bytea" NOT NULL,
	"dependency_closure_digest" "bytea" NOT NULL,
	"truth_state" "control"."policy_truth_state" NOT NULL,
	"authority_label" text DEFAULT 'SIMULATION_ONLY' NOT NULL,
	"result_document" jsonb NOT NULL,
	"completed_at" timestamp(6) with time zone NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "policy_simulation_input_uq" UNIQUE("participant_id","policy_version_id","input_digest","fact_generation_digest"),
	CONSTRAINT "policy_simulation_participant_id_uq" UNIQUE("participant_id","simulation_id"),
	CONSTRAINT "policy_simulation_tenant_id_uq" UNIQUE("participant_id","privacy_domain_id","simulation_id"),
	CONSTRAINT "policy_simulation_digests_ck" CHECK (octet_length("control"."policy_simulation"."input_digest")=32 and octet_length("control"."policy_simulation"."result_digest")=32 and octet_length("control"."policy_simulation"."fact_generation_digest")=32 and octet_length("control"."policy_simulation"."dependency_closure_digest")=32),
	CONSTRAINT "policy_simulation_authority_ck" CHECK ("control"."policy_simulation"."authority_label"='SIMULATION_ONLY')
);
--> statement-breakpoint
ALTER TABLE "control"."policy_simulation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."policy_version" (
	"policy_version_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"policy_id" uuid NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"version" varchar(64) NOT NULL,
	"schema_digest" "bytea" NOT NULL,
	"semantic_cbor" "bytea" NOT NULL,
	"semantic_digest" "bytea" NOT NULL,
	"cose_sign1" "bytea" NOT NULL,
	"state" "control"."policy_lifecycle_state" DEFAULT 'IMMUTABLE_VERSION' NOT NULL,
	"created_by_principal_id" uuid NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "policy_version_number_uq" UNIQUE("participant_id","policy_id","version","schema_digest"),
	CONSTRAINT "policy_version_digest_uq" UNIQUE("participant_id","privacy_domain_id","semantic_digest"),
	CONSTRAINT "policy_version_participant_id_uq" UNIQUE("participant_id","policy_version_id"),
	CONSTRAINT "policy_version_tenant_id_uq" UNIQUE("participant_id","privacy_domain_id","policy_version_id"),
	CONSTRAINT "policy_version_digest_ck" CHECK (octet_length("control"."policy_version"."schema_digest")=32 and octet_length("control"."policy_version"."semantic_digest")=32 and "control"."policy_version"."version" ~ '^[0-9]+.[0-9]+.[0-9]+$')
);
--> statement-breakpoint
ALTER TABLE "control"."policy_version" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."module_capability" ADD CONSTRAINT "module_capability_module_version_id_module_version_module_version_id_fk" FOREIGN KEY ("module_version_id") REFERENCES "control"."module_version"("module_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."module_configuration_generation" ADD CONSTRAINT "module_configuration_generation_module_installation_id_module_installation_module_installation_id_fk" FOREIGN KEY ("module_installation_id") REFERENCES "control"."module_installation"("module_installation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."module_conflict" ADD CONSTRAINT "module_conflict_module_version_id_module_version_module_version_id_fk" FOREIGN KEY ("module_version_id") REFERENCES "control"."module_version"("module_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."module_conflict" ADD CONSTRAINT "module_conflict_conflicting_module_version_id_module_version_module_version_id_fk" FOREIGN KEY ("conflicting_module_version_id") REFERENCES "control"."module_version"("module_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."module_dependency" ADD CONSTRAINT "module_dependency_consumer_module_version_id_module_version_module_version_id_fk" FOREIGN KEY ("consumer_module_version_id") REFERENCES "control"."module_version"("module_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."module_installation" ADD CONSTRAINT "module_installation_module_version_id_module_version_module_version_id_fk" FOREIGN KEY ("module_version_id") REFERENCES "control"."module_version"("module_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."module_version" ADD CONSTRAINT "module_version_module_id_module_registration_module_id_fk" FOREIGN KEY ("module_id") REFERENCES "control"."module_registration"("module_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy" ADD CONSTRAINT "policy_participant_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy" ADD CONSTRAINT "policy_privacy_fk" FOREIGN KEY ("participant_id","privacy_domain_id") REFERENCES "control"."privacy_domain"("participant_id","privacy_domain_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_activation_prerequisite" ADD CONSTRAINT "policy_activation_prerequisite_activation_fk" FOREIGN KEY ("participant_id","privacy_domain_id","policy_activation_id") REFERENCES "control"."policy_activation"("participant_id","privacy_domain_id","policy_activation_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_activation" ADD CONSTRAINT "policy_activation_generation_fk" FOREIGN KEY ("participant_id","privacy_domain_id","policy_generation_id") REFERENCES "control"."policy_generation"("participant_id","privacy_domain_id","policy_generation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_generation" ADD CONSTRAINT "policy_generation_version_fk" FOREIGN KEY ("participant_id","privacy_domain_id","policy_version_id") REFERENCES "control"."policy_version"("participant_id","privacy_domain_id","policy_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_generation" ADD CONSTRAINT "policy_generation_simulation_fk" FOREIGN KEY ("participant_id","privacy_domain_id","simulation_id") REFERENCES "control"."policy_simulation"("participant_id","privacy_domain_id","simulation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_generation" ADD CONSTRAINT "policy_generation_approval_fk" FOREIGN KEY ("participant_id","approval_request_id") REFERENCES "control"."approval_request"("participant_id","approval_request_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_simulation" ADD CONSTRAINT "policy_simulation_version_fk" FOREIGN KEY ("participant_id","privacy_domain_id","policy_version_id") REFERENCES "control"."policy_version"("participant_id","privacy_domain_id","policy_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_version" ADD CONSTRAINT "policy_version_policy_fk" FOREIGN KEY ("participant_id","privacy_domain_id","policy_id") REFERENCES "control"."policy"("participant_id","privacy_domain_id","policy_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."policy_version" ADD CONSTRAINT "policy_version_creator_fk" FOREIGN KEY ("participant_id","created_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "module_configuration_one_active_uq" ON "control"."module_configuration_generation" USING btree ("module_installation_id") WHERE "control"."module_configuration_generation"."active";--> statement-breakpoint
CREATE INDEX "policy_activation_prerequisite_ready_idx" ON "control"."policy_activation_prerequisite" USING btree ("participant_id","privacy_domain_id","ready");--> statement-breakpoint
CREATE UNIQUE INDEX "policy_generation_one_active_uq" ON "control"."policy_generation" USING btree ("participant_id","privacy_domain_id","scope_digest") WHERE "control"."policy_generation"."active";--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."module_configuration_generation" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."module_configuration_generation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."module_configuration_generation"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."module_configuration_generation" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."module_configuration_generation"."participant_id") and openpc.matches_privacy("control"."module_configuration_generation"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."module_configuration_generation"."participant_id") and openpc.matches_privacy("control"."module_configuration_generation"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."module_installation" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."module_installation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."module_installation"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."module_installation" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."module_installation"."participant_id") and openpc.matches_privacy("control"."module_installation"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."module_installation"."participant_id") and openpc.matches_privacy("control"."module_installation"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy"."participant_id") and openpc.matches_privacy("control"."policy"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy"."participant_id") and openpc.matches_privacy("control"."policy"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_activation_prerequisite" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_activation_prerequisite"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_activation_prerequisite"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_activation_prerequisite" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_activation_prerequisite"."participant_id") and openpc.matches_privacy("control"."policy_activation_prerequisite"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_activation_prerequisite"."participant_id") and openpc.matches_privacy("control"."policy_activation_prerequisite"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_activation" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_activation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_activation"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_activation" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_activation"."participant_id") and openpc.matches_privacy("control"."policy_activation"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_activation"."participant_id") and openpc.matches_privacy("control"."policy_activation"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_generation" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_generation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_generation"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_generation" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_generation"."participant_id") and openpc.matches_privacy("control"."policy_generation"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_generation"."participant_id") and openpc.matches_privacy("control"."policy_generation"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_simulation" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_simulation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_simulation"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_simulation" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_simulation"."participant_id") and openpc.matches_privacy("control"."policy_simulation"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_simulation"."participant_id") and openpc.matches_privacy("control"."policy_simulation"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."policy_version" AS PERMISSIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_version"."participant_id")) WITH CHECK (openpc.matches_participant("control"."policy_version"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."policy_version" AS RESTRICTIVE FOR ALL TO "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."policy_version"."participant_id") and openpc.matches_privacy("control"."policy_version"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."policy_version"."participant_id") and openpc.matches_privacy("control"."policy_version"."privacy_domain_id"));