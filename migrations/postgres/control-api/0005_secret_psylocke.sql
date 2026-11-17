CREATE TABLE "control"."abi_artifact" (
	"abi_artifact_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"provenance_source" text NOT NULL,
	"provenance_locator" text NOT NULL,
	"provenance_retrieved_at" timestamp(6) with time zone NOT NULL,
	"provenance_source_digest" text NOT NULL,
	"canonical_abi_bytes" "bytea" NOT NULL,
	"canonical_abi" jsonb NOT NULL,
	"abi_digest" text NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "abi_artifact_digest_uq" UNIQUE("participant_id","privacy_domain_id","abi_digest"),
	CONSTRAINT "abi_artifact_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","abi_artifact_id"),
	CONSTRAINT "abi_artifact_provenance_source_ck" CHECK ("control"."abi_artifact"."provenance_source" in ('AUTHENTICATED_REGISTRY','SOURCE_REPOSITORY','LOCAL_FIXTURE')),
	CONSTRAINT "abi_artifact_provenance_digest_ck" CHECK ("control"."abi_artifact"."provenance_source_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "abi_artifact_digest_ck" CHECK ("control"."abi_artifact"."abi_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "abi_artifact_policy_generation_digest_ck" CHECK ("control"."abi_artifact"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "abi_artifact_revision_ck" CHECK ("control"."abi_artifact"."revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."abi_artifact" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."argument_rule_named_set_binding" (
	"argument_rule_named_set_binding_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"argument_rule_version_id" uuid NOT NULL,
	"owner_id" uuid NOT NULL,
	"set_id" text NOT NULL,
	"version" text NOT NULL,
	"version_digest" text NOT NULL,
	CONSTRAINT "argument_rule_named_set_identity_uq" UNIQUE("argument_rule_version_id","owner_id","set_id","version"),
	CONSTRAINT "argument_rule_named_set_digest_ck" CHECK ("control"."argument_rule_named_set_binding"."version_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "argument_rule_named_set_version_ck" CHECK ("control"."argument_rule_named_set_binding"."version" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
);
--> statement-breakpoint
ALTER TABLE "control"."argument_rule_named_set_binding" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."typed_argument_rule_version" (
	"argument_rule_version_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"runtime_binding_id" uuid NOT NULL,
	"abi_artifact_id" uuid NOT NULL,
	"canonical_signature" text NOT NULL,
	"version" text NOT NULL,
	"rule_digest" text NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"state" text DEFAULT 'PREPARED' NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "argument_rule_version_uq" UNIQUE("runtime_binding_id","version"),
	CONSTRAINT "argument_rule_version_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","argument_rule_version_id"),
	CONSTRAINT "argument_rule_version_state_ck" CHECK ("control"."typed_argument_rule_version"."state" in ('PREPARED','ACTIVE','RETIRED')),
	CONSTRAINT "argument_rule_version_digest_ck" CHECK ("control"."typed_argument_rule_version"."rule_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "argument_rule_version_policy_generation_digest_ck" CHECK ("control"."typed_argument_rule_version"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "argument_rule_version_version_ck" CHECK ("control"."typed_argument_rule_version"."version" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
	CONSTRAINT "argument_rule_version_revision_ck" CHECK ("control"."typed_argument_rule_version"."revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."typed_argument_rule_version" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."contract_method_policy" (
	"contract_method_policy_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"runtime_binding_id" uuid NOT NULL,
	"abi_artifact_id" uuid NOT NULL,
	"canonical_signature" text NOT NULL,
	"selector" text NOT NULL,
	"effect" text NOT NULL,
	"required_roles" text[] NOT NULL,
	"approval_requirement" text NOT NULL,
	"mfa_requirement" text NOT NULL,
	"environments" text[] NOT NULL,
	"argument_rule_version_id" uuid,
	"rpc_method_policy_digest" text NOT NULL,
	"nested_call_set_digest" text NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"state" text DEFAULT 'PREPARED' NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "contract_method_policy_selector_uq" UNIQUE("runtime_binding_id","selector"),
	CONSTRAINT "contract_method_policy_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","contract_method_policy_id"),
	CONSTRAINT "contract_method_policy_selector_ck" CHECK ("control"."contract_method_policy"."selector" ~ '^0x[0-9a-f]{8}$'),
	CONSTRAINT "contract_method_policy_effect_ck" CHECK ("control"."contract_method_policy"."effect" in ('READ','WRITE')),
	CONSTRAINT "contract_method_policy_approval_ck" CHECK ("control"."contract_method_policy"."approval_requirement" in ('NONE','SINGLE','MAKER_CHECKER')),
	CONSTRAINT "contract_method_policy_mfa_ck" CHECK ("control"."contract_method_policy"."mfa_requirement" in ('NONE','WEBAUTHN')),
	CONSTRAINT "contract_method_policy_state_ck" CHECK ("control"."contract_method_policy"."state" in ('PREPARED','ACTIVE','RETIRED','QUARANTINED')),
	CONSTRAINT "contract_method_policy_rpc_method_digest_ck" CHECK ("control"."contract_method_policy"."rpc_method_policy_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "contract_method_policy_nested_call_digest_ck" CHECK ("control"."contract_method_policy"."nested_call_set_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "contract_method_policy_generation_digest_ck" CHECK ("control"."contract_method_policy"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "contract_method_policy_revision_ck" CHECK ("control"."contract_method_policy"."revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."contract_method_policy" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."logical_contract_asset" (
	"logical_contract_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"logical_name" text NOT NULL,
	"display_name" text NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "logical_contract_scope_name_uq" UNIQUE("participant_id","privacy_domain_id","logical_name"),
	CONSTRAINT "logical_contract_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","logical_contract_id"),
	CONSTRAINT "logical_contract_policy_generation_digest_ck" CHECK ("control"."logical_contract_asset"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "logical_contract_revision_ck" CHECK ("control"."logical_contract_asset"."revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."logical_contract_asset" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."contract_runtime_binding" (
	"runtime_binding_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"logical_contract_id" uuid NOT NULL,
	"chain_id" text NOT NULL,
	"network_id" text NOT NULL,
	"genesis_digest" text NOT NULL,
	"contract_address" text NOT NULL,
	"code_digest" text NOT NULL,
	"proxy_address" text,
	"implementation_address" text,
	"implementation_code_digest" text,
	"abi_artifact_id" uuid NOT NULL,
	"abi_version" text NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"state" text DEFAULT 'BOUND' NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"quarantined_at" timestamp(6) with time zone,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "runtime_binding_identity_uq" UNIQUE("participant_id","chain_id","network_id","contract_address"),
	CONSTRAINT "runtime_binding_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","runtime_binding_id"),
	CONSTRAINT "runtime_binding_chain_id_ck" CHECK ("control"."contract_runtime_binding"."chain_id" ~ '^[0-9]{1,20}$'),
	CONSTRAINT "runtime_binding_address_ck" CHECK ("control"."contract_runtime_binding"."contract_address" ~ '^0x[0-9a-fA-F]{40}$'),
	CONSTRAINT "runtime_binding_proxy_pair_ck" CHECK (("control"."contract_runtime_binding"."proxy_address" is null) = ("control"."contract_runtime_binding"."implementation_address" is null) and ("control"."contract_runtime_binding"."proxy_address" is null) = ("control"."contract_runtime_binding"."implementation_code_digest" is null)),
	CONSTRAINT "runtime_binding_state_ck" CHECK ("control"."contract_runtime_binding"."state" in ('BOUND','QUARANTINED','RETIRED')),
	CONSTRAINT "runtime_binding_genesis_digest_ck" CHECK ("control"."contract_runtime_binding"."genesis_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_binding_code_digest_ck" CHECK ("control"."contract_runtime_binding"."code_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_binding_implementation_code_digest_ck" CHECK ("control"."contract_runtime_binding"."implementation_code_digest" is null or "control"."contract_runtime_binding"."implementation_code_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_binding_policy_generation_digest_ck" CHECK ("control"."contract_runtime_binding"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_binding_abi_version_ck" CHECK ("control"."contract_runtime_binding"."abi_version" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
	CONSTRAINT "runtime_binding_revision_ck" CHECK ("control"."contract_runtime_binding"."revision" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."contract_runtime_binding" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."typed_argument_rule" (
	"typed_argument_rule_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"argument_rule_version_id" uuid NOT NULL,
	"ordinal" text NOT NULL,
	"parameter_path" text NOT NULL,
	"operand_type" text NOT NULL,
	"operator" text NOT NULL,
	"scalar_values" text[] NOT NULL,
	CONSTRAINT "typed_argument_rule_ordinal_uq" UNIQUE("argument_rule_version_id","ordinal"),
	CONSTRAINT "typed_argument_rule_ordinal_ck" CHECK ("control"."typed_argument_rule"."ordinal" ~ '^[0-9]{1,4}$'),
	CONSTRAINT "typed_argument_rule_path_ck" CHECK ("control"."typed_argument_rule"."parameter_path" ~ '^inputs\[[0-9]+\](\.([[0-9]+]|[A-Za-z_][A-Za-z0-9_]*))*$'),
	CONSTRAINT "typed_argument_rule_operand_ck" CHECK ("control"."typed_argument_rule"."operand_type" in ('ADDRESS','BOOLEAN','BYTES32','INTEGER','STRING')),
	CONSTRAINT "typed_argument_rule_operator_ck" CHECK ("control"."typed_argument_rule"."operator" in ('EQ','IN','LT','LTE','GT','GTE'))
);
--> statement-breakpoint
ALTER TABLE "control"."typed_argument_rule" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."argument_rule_named_set_binding" ADD CONSTRAINT "argument_rule_named_set_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","argument_rule_version_id") REFERENCES "control"."typed_argument_rule_version"("participant_id","privacy_domain_id","argument_rule_version_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."typed_argument_rule_version" ADD CONSTRAINT "argument_rule_version_binding_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","runtime_binding_id") REFERENCES "control"."contract_runtime_binding"("participant_id","privacy_domain_id","runtime_binding_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."typed_argument_rule_version" ADD CONSTRAINT "argument_rule_version_abi_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","abi_artifact_id") REFERENCES "control"."abi_artifact"("participant_id","privacy_domain_id","abi_artifact_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."contract_method_policy" ADD CONSTRAINT "contract_method_policy_binding_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","runtime_binding_id") REFERENCES "control"."contract_runtime_binding"("participant_id","privacy_domain_id","runtime_binding_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."contract_method_policy" ADD CONSTRAINT "contract_method_policy_abi_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","abi_artifact_id") REFERENCES "control"."abi_artifact"("participant_id","privacy_domain_id","abi_artifact_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."contract_method_policy" ADD CONSTRAINT "contract_method_policy_rule_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","argument_rule_version_id") REFERENCES "control"."typed_argument_rule_version"("participant_id","privacy_domain_id","argument_rule_version_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."contract_runtime_binding" ADD CONSTRAINT "runtime_binding_contract_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","logical_contract_id") REFERENCES "control"."logical_contract_asset"("participant_id","privacy_domain_id","logical_contract_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."contract_runtime_binding" ADD CONSTRAINT "runtime_binding_abi_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","abi_artifact_id") REFERENCES "control"."abi_artifact"("participant_id","privacy_domain_id","abi_artifact_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."typed_argument_rule" ADD CONSTRAINT "typed_argument_rule_version_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","argument_rule_version_id") REFERENCES "control"."typed_argument_rule_version"("participant_id","privacy_domain_id","argument_rule_version_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."abi_artifact" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."abi_artifact"."participant_id")) WITH CHECK (openpc.matches_participant("control"."abi_artifact"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."abi_artifact" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."abi_artifact"."participant_id") and openpc.matches_privacy("control"."abi_artifact"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."abi_artifact"."participant_id") and openpc.matches_privacy("control"."abi_artifact"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."argument_rule_named_set_binding" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."argument_rule_named_set_binding"."participant_id")) WITH CHECK (openpc.matches_participant("control"."argument_rule_named_set_binding"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."argument_rule_named_set_binding" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."argument_rule_named_set_binding"."participant_id") and openpc.matches_privacy("control"."argument_rule_named_set_binding"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."argument_rule_named_set_binding"."participant_id") and openpc.matches_privacy("control"."argument_rule_named_set_binding"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."typed_argument_rule_version" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."typed_argument_rule_version"."participant_id")) WITH CHECK (openpc.matches_participant("control"."typed_argument_rule_version"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."typed_argument_rule_version" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."typed_argument_rule_version"."participant_id") and openpc.matches_privacy("control"."typed_argument_rule_version"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."typed_argument_rule_version"."participant_id") and openpc.matches_privacy("control"."typed_argument_rule_version"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."contract_method_policy" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."contract_method_policy"."participant_id")) WITH CHECK (openpc.matches_participant("control"."contract_method_policy"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."contract_method_policy" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."contract_method_policy"."participant_id") and openpc.matches_privacy("control"."contract_method_policy"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."contract_method_policy"."participant_id") and openpc.matches_privacy("control"."contract_method_policy"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."logical_contract_asset" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."logical_contract_asset"."participant_id")) WITH CHECK (openpc.matches_participant("control"."logical_contract_asset"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."logical_contract_asset" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."logical_contract_asset"."participant_id") and openpc.matches_privacy("control"."logical_contract_asset"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."logical_contract_asset"."participant_id") and openpc.matches_privacy("control"."logical_contract_asset"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."contract_runtime_binding" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."contract_runtime_binding"."participant_id")) WITH CHECK (openpc.matches_participant("control"."contract_runtime_binding"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."contract_runtime_binding" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."contract_runtime_binding"."participant_id") and openpc.matches_privacy("control"."contract_runtime_binding"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."contract_runtime_binding"."participant_id") and openpc.matches_privacy("control"."contract_runtime_binding"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."typed_argument_rule" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."typed_argument_rule"."participant_id")) WITH CHECK (openpc.matches_participant("control"."typed_argument_rule"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."typed_argument_rule" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."typed_argument_rule"."participant_id") and openpc.matches_privacy("control"."typed_argument_rule"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."typed_argument_rule"."participant_id") and openpc.matches_privacy("control"."typed_argument_rule"."privacy_domain_id"));
-- OPENPC CONTROL-API SECURITY TAIL
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" FROM PUBLIC;
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_runtime";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_worker";
GRANT UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation", "control"."configuration_work" TO "openpc_control_reader";
