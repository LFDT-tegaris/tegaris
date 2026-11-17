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
	CONSTRAINT "abi_artifact_policy_generation_digest_ck" CHECK ("control"."abi_artifact"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$')
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
	CONSTRAINT "argument_rule_version_version_ck" CHECK ("control"."typed_argument_rule_version"."version" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
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
	CONSTRAINT "contract_method_policy_generation_digest_ck" CHECK ("control"."contract_method_policy"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."contract_method_policy" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."indexer_profile" (
	"indexer_profile_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"engine" text NOT NULL,
	"engine_version" text NOT NULL,
	"method_profile_digest" text NOT NULL,
	"state" text DEFAULT 'REGISTERED' NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "indexer_profile_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","indexer_profile_id"),
	CONSTRAINT "indexer_profile_engine_ck" CHECK ("control"."indexer_profile"."engine" in ('CLIENT_INDEXER','EXTERNAL_ENGINE_ADAPTER')),
	CONSTRAINT "indexer_profile_engine_version_ck" CHECK ("control"."indexer_profile"."engine_version" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
	CONSTRAINT "indexer_profile_state_ck" CHECK ("control"."indexer_profile"."state" in ('REGISTERED','SHADOW','QUALIFIED','ACTIVE','QUARANTINED','RETIRED')),
	CONSTRAINT "indexer_profile_method_profile_digest_ck" CHECK ("control"."indexer_profile"."method_profile_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "indexer_profile_policy_generation_digest_ck" CHECK ("control"."indexer_profile"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."indexer_profile" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
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
	CONSTRAINT "logical_contract_policy_generation_digest_ck" CHECK ("control"."logical_contract_asset"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."logical_contract_asset" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."projection_plan" (
	"projection_plan_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"indexer_profile_id" uuid NOT NULL,
	"plan_digest" text NOT NULL,
	"readiness" text NOT NULL,
	"state" text DEFAULT 'DRAFT' NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "projection_plan_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","projection_plan_id"),
	CONSTRAINT "projection_plan_digest_ck" CHECK ("control"."projection_plan"."plan_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "projection_plan_readiness_ck" CHECK ("control"."projection_plan"."readiness" in ('UNKNOWN','NOT_READY','READY','STALE','REORG')),
	CONSTRAINT "projection_plan_state_ck" CHECK ("control"."projection_plan"."state" in ('DRAFT','VALIDATED','RUNNING','DEGRADED','QUARANTINED','RETIRED')),
	CONSTRAINT "projection_plan_policy_generation_digest_ck" CHECK ("control"."projection_plan"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."projection_plan" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."provider_profile" (
	"provider_profile_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"chain_id" text NOT NULL,
	"endpoint_secret_ref" text NOT NULL,
	"behavior_fingerprint" text NOT NULL,
	"state" text DEFAULT 'REGISTERED' NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "provider_profile_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","provider_profile_id"),
	CONSTRAINT "provider_profile_chain_id_ck" CHECK ("control"."provider_profile"."chain_id" ~ '^[0-9]{1,20}$'),
	CONSTRAINT "provider_profile_endpoint_secret_ref_ck" CHECK ("control"."provider_profile"."endpoint_secret_ref" ~ '^urn:openpc:secret:[A-Za-z0-9._:-]+$'),
	CONSTRAINT "provider_profile_state_ck" CHECK ("control"."provider_profile"."state" in ('REGISTERED','SHADOW','QUALIFIED','ACTIVE','QUARANTINED','RETIRED')),
	CONSTRAINT "provider_profile_behavior_fingerprint_ck" CHECK ("control"."provider_profile"."behavior_fingerprint" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "provider_profile_policy_generation_digest_ck" CHECK ("control"."provider_profile"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."provider_profile" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
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
	CONSTRAINT "runtime_binding_abi_version_ck" CHECK ("control"."contract_runtime_binding"."abi_version" ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
);
--> statement-breakpoint
ALTER TABLE "control"."contract_runtime_binding" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."runtime_configuration_generation" (
	"runtime_configuration_generation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"runtime_target_id" uuid NOT NULL,
	"projection_plan_id" uuid NOT NULL,
	"predecessor_digest" text,
	"generation_digest" text NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"state" text DEFAULT 'STAGED' NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"activated_at" timestamp(6) with time zone,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "runtime_configuration_generation_uq" UNIQUE("runtime_target_id","generation_digest"),
	CONSTRAINT "runtime_configuration_generation_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","runtime_configuration_generation_id"),
	CONSTRAINT "runtime_configuration_generation_state_ck" CHECK ("control"."runtime_configuration_generation"."state" in ('STAGED','ACTIVATING','ACTIVE','QUARANTINED','FAILED')),
	CONSTRAINT "runtime_configuration_generation_digest_ck" CHECK ("control"."runtime_configuration_generation"."generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_configuration_generation_policy_digest_ck" CHECK ("control"."runtime_configuration_generation"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."runtime_configuration_generation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."runtime_target" (
	"runtime_target_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"desired_generation_digest" text,
	"active_generation_digest" text,
	"xds_version_digest" text,
	"state" text DEFAULT 'OFFLINE' NOT NULL,
	"observed_at" timestamp(6) with time zone NOT NULL,
	"policy_generation_digest" text NOT NULL,
	"revision" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "runtime_target_scope_id_uq" UNIQUE("participant_id","privacy_domain_id","runtime_target_id"),
	CONSTRAINT "runtime_target_state_ck" CHECK ("control"."runtime_target"."state" in ('OFFLINE','DISCOVERED','STAGING','PREPARED','XDS_PENDING','XDS_ACKED_NOT_ACTIVE','ACTIVATING','ACTIVE_MATCHED','ACTIVE_MISMATCH','NACKED','FAILED','ROLLING_BACK','ROLLED_BACK','QUARANTINED','INCOMPATIBLE')),
	CONSTRAINT "runtime_target_desired_digest_ck" CHECK ("control"."runtime_target"."desired_generation_digest" is null or "control"."runtime_target"."desired_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_target_active_digest_ck" CHECK ("control"."runtime_target"."active_generation_digest" is null or "control"."runtime_target"."active_generation_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_target_xds_digest_ck" CHECK ("control"."runtime_target"."xds_version_digest" is null or "control"."runtime_target"."xds_version_digest" ~ '^sha256:[0-9a-f]{64}$'),
	CONSTRAINT "runtime_target_policy_generation_digest_ck" CHECK ("control"."runtime_target"."policy_generation_digest" ~ '^sha256:[0-9a-f]{64}$')
);
--> statement-breakpoint
ALTER TABLE "control"."runtime_target" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
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
ALTER TABLE "control"."projection_plan" ADD CONSTRAINT "projection_plan_indexer_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","indexer_profile_id") REFERENCES "control"."indexer_profile"("participant_id","privacy_domain_id","indexer_profile_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."contract_runtime_binding" ADD CONSTRAINT "runtime_binding_contract_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","logical_contract_id") REFERENCES "control"."logical_contract_asset"("participant_id","privacy_domain_id","logical_contract_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."contract_runtime_binding" ADD CONSTRAINT "runtime_binding_abi_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","abi_artifact_id") REFERENCES "control"."abi_artifact"("participant_id","privacy_domain_id","abi_artifact_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_configuration_generation" ADD CONSTRAINT "runtime_configuration_generation_target_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","runtime_target_id") REFERENCES "control"."runtime_target"("participant_id","privacy_domain_id","runtime_target_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."runtime_configuration_generation" ADD CONSTRAINT "runtime_configuration_generation_plan_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","projection_plan_id") REFERENCES "control"."projection_plan"("participant_id","privacy_domain_id","projection_plan_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."typed_argument_rule" ADD CONSTRAINT "typed_argument_rule_version_scope_fk" FOREIGN KEY ("participant_id","privacy_domain_id","argument_rule_version_id") REFERENCES "control"."typed_argument_rule_version"("participant_id","privacy_domain_id","argument_rule_version_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."abi_artifact" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."abi_artifact"."participant_id")) WITH CHECK (openpc.matches_participant("control"."abi_artifact"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."abi_artifact" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."abi_artifact"."participant_id") and openpc.matches_privacy("control"."abi_artifact"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."abi_artifact"."participant_id") and openpc.matches_privacy("control"."abi_artifact"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."argument_rule_named_set_binding" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."argument_rule_named_set_binding"."participant_id")) WITH CHECK (openpc.matches_participant("control"."argument_rule_named_set_binding"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."argument_rule_named_set_binding" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."argument_rule_named_set_binding"."participant_id") and openpc.matches_privacy("control"."argument_rule_named_set_binding"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."argument_rule_named_set_binding"."participant_id") and openpc.matches_privacy("control"."argument_rule_named_set_binding"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."typed_argument_rule_version" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."typed_argument_rule_version"."participant_id")) WITH CHECK (openpc.matches_participant("control"."typed_argument_rule_version"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."typed_argument_rule_version" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."typed_argument_rule_version"."participant_id") and openpc.matches_privacy("control"."typed_argument_rule_version"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."typed_argument_rule_version"."participant_id") and openpc.matches_privacy("control"."typed_argument_rule_version"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."contract_method_policy" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."contract_method_policy"."participant_id")) WITH CHECK (openpc.matches_participant("control"."contract_method_policy"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."contract_method_policy" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."contract_method_policy"."participant_id") and openpc.matches_privacy("control"."contract_method_policy"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."contract_method_policy"."participant_id") and openpc.matches_privacy("control"."contract_method_policy"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."indexer_profile" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."indexer_profile"."participant_id")) WITH CHECK (openpc.matches_participant("control"."indexer_profile"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."indexer_profile" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."indexer_profile"."participant_id") and openpc.matches_privacy("control"."indexer_profile"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."indexer_profile"."participant_id") and openpc.matches_privacy("control"."indexer_profile"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."logical_contract_asset" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."logical_contract_asset"."participant_id")) WITH CHECK (openpc.matches_participant("control"."logical_contract_asset"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."logical_contract_asset" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."logical_contract_asset"."participant_id") and openpc.matches_privacy("control"."logical_contract_asset"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."logical_contract_asset"."participant_id") and openpc.matches_privacy("control"."logical_contract_asset"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."projection_plan" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."projection_plan"."participant_id")) WITH CHECK (openpc.matches_participant("control"."projection_plan"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."projection_plan" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."projection_plan"."participant_id") and openpc.matches_privacy("control"."projection_plan"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."projection_plan"."participant_id") and openpc.matches_privacy("control"."projection_plan"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."provider_profile" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."provider_profile"."participant_id")) WITH CHECK (openpc.matches_participant("control"."provider_profile"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."provider_profile" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."provider_profile"."participant_id") and openpc.matches_privacy("control"."provider_profile"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."provider_profile"."participant_id") and openpc.matches_privacy("control"."provider_profile"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."contract_runtime_binding" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."contract_runtime_binding"."participant_id")) WITH CHECK (openpc.matches_participant("control"."contract_runtime_binding"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."contract_runtime_binding" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."contract_runtime_binding"."participant_id") and openpc.matches_privacy("control"."contract_runtime_binding"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."contract_runtime_binding"."participant_id") and openpc.matches_privacy("control"."contract_runtime_binding"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."runtime_configuration_generation" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_configuration_generation"."participant_id")) WITH CHECK (openpc.matches_participant("control"."runtime_configuration_generation"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."runtime_configuration_generation" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_configuration_generation"."participant_id") and openpc.matches_privacy("control"."runtime_configuration_generation"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."runtime_configuration_generation"."participant_id") and openpc.matches_privacy("control"."runtime_configuration_generation"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."runtime_target" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_target"."participant_id")) WITH CHECK (openpc.matches_participant("control"."runtime_target"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."runtime_target" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."runtime_target"."participant_id") and openpc.matches_privacy("control"."runtime_target"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."runtime_target"."participant_id") and openpc.matches_privacy("control"."runtime_target"."privacy_domain_id"));--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."typed_argument_rule" AS PERMISSIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."typed_argument_rule"."participant_id")) WITH CHECK (openpc.matches_participant("control"."typed_argument_rule"."participant_id"));--> statement-breakpoint
CREATE POLICY "privacy_domain_isolation" ON "control"."typed_argument_rule" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (openpc.matches_participant("control"."typed_argument_rule"."participant_id") and openpc.matches_privacy("control"."typed_argument_rule"."privacy_domain_id")) WITH CHECK (openpc.matches_participant("control"."typed_argument_rule"."participant_id") and openpc.matches_privacy("control"."typed_argument_rule"."privacy_domain_id"));
-- OPENPC CONTROL-API SECURITY TAIL
REVOKE ALL ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation" FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation" TO "openpc_control_runtime", "openpc_control_worker";
GRANT SELECT ON "control"."abi_artifact", "control"."logical_contract_asset", "control"."contract_runtime_binding", "control"."typed_argument_rule_version", "control"."argument_rule_named_set_binding", "control"."typed_argument_rule", "control"."contract_method_policy", "control"."provider_profile", "control"."indexer_profile", "control"."runtime_target", "control"."projection_plan", "control"."runtime_configuration_generation" TO "openpc_control_reader";
