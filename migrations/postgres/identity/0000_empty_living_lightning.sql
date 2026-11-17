CREATE SCHEMA "control";
--> statement-breakpoint
CREATE TYPE "control"."approval_decision" AS ENUM('APPROVE', 'REJECT');--> statement-breakpoint
CREATE TYPE "control"."approval_state" AS ENUM('OPEN', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED');--> statement-breakpoint
CREATE TYPE "control"."authority_state" AS ENUM('DRAFT', 'PENDING_APPROVAL', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED', 'RETIRED');--> statement-breakpoint
CREATE TYPE "control"."credential_kind" AS ENUM('OIDC_SUBJECT', 'WEBAUTHN', 'WALLET_PROOF', 'WORKLOAD_OIDC', 'WORKLOAD_MTLS');--> statement-breakpoint
CREATE TYPE "control"."credential_state" AS ENUM('PENDING', 'ACTIVE', 'ROTATING', 'REVOKED', 'EXPIRED');--> statement-breakpoint
CREATE TYPE "control"."participant_state" AS ENUM('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'RETIRING', 'RETIRED');--> statement-breakpoint
CREATE TYPE "control"."principal_kind" AS ENUM('USER', 'WALLET', 'WORKLOAD', 'PLATFORM_OPERATOR');--> statement-breakpoint
CREATE TYPE "control"."principal_state" AS ENUM('PENDING', 'ACTIVE', 'DISABLED', 'LOCKED', 'RETIRED');--> statement-breakpoint
CREATE TYPE "control"."privacy_domain_state" AS ENUM('PROVISIONING', 'ACTIVE', 'FENCED', 'RETIRING', 'RETIRED');--> statement-breakpoint
CREATE TYPE "control"."session_state" AS ENUM('ACTIVE', 'IDLE_EXPIRED', 'ABSOLUTE_EXPIRED', 'REVOKED', 'TERMINATED');--> statement-breakpoint
CREATE TABLE "control"."action_intent" (
	"action_intent_id" varchar(160) PRIMARY KEY NOT NULL,
	"resource_type" text NOT NULL,
	"operation_class" varchar(32) NOT NULL,
	"risk_class" varchar(32) NOT NULL,
	"maker_checker_required" boolean NOT NULL,
	"step_up_required" boolean NOT NULL,
	"idempotency_required" boolean NOT NULL,
	"existence_disclosure" text NOT NULL,
	"payload_disclosure" text NOT NULL,
	"evidence_class" text NOT NULL,
	"registered_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "action_intent_id_ck" CHECK ("control"."action_intent"."action_intent_id" ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'),
	CONSTRAINT "action_intent_resource_ck" CHECK ("control"."action_intent"."resource_type" ~ '^[a-z][a-z0-9-]{0,62}$'),
	CONSTRAINT "action_intent_operation_ck" CHECK ("control"."action_intent"."operation_class" in ('READ','CREATE','UPDATE','DELETE','APPROVE','ACTIVATE','ROLLBACK','EXPORT','RECOVER','UNINSTALL')),
	CONSTRAINT "action_intent_risk_ck" CHECK ("control"."action_intent"."risk_class" in ('LOW','STANDARD','HIGH','BREAK_GLASS')),
	CONSTRAINT "action_intent_existence_ck" CHECK ("control"."action_intent"."existence_disclosure" in ('NONE','AUTHORIZED_ONLY','FULL')),
	CONSTRAINT "action_intent_payload_ck" CHECK ("control"."action_intent"."payload_disclosure" in ('NONE','REDACTED','AUTHORIZED_FULL')),
	CONSTRAINT "action_intent_evidence_ck" CHECK (length("control"."action_intent"."evidence_class") between 1 and 96)
);
--> statement-breakpoint
CREATE TABLE "control"."assignment" (
	"assignment_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"authority_group_id" uuid,
	"authority_envelope_id" uuid NOT NULL,
	"delegation_epoch" numeric(20, 0) NOT NULL,
	"scope_digest" "bytea" NOT NULL,
	"valid_during" "tstzrange" NOT NULL,
	"state" "control"."authority_state" DEFAULT 'DRAFT' NOT NULL,
	"created_by_principal_id" uuid NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "assignment_participant_id_uq" UNIQUE("participant_id","assignment_id")
);
--> statement-breakpoint
ALTER TABLE "control"."assignment" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."authority_envelope" (
	"authority_envelope_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"authority_epoch" numeric(20, 0) NOT NULL,
	"delegation_epoch" numeric(20, 0) NOT NULL,
	"state" "control"."authority_state" NOT NULL,
	"valid_from" timestamp(6) with time zone NOT NULL,
	"valid_until" timestamp(6) with time zone,
	"semantic_cbor" "bytea" NOT NULL,
	"semantic_digest" "bytea" NOT NULL,
	"cose_sign1" "bytea" NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "authority_envelope_semantic_digest_unique" UNIQUE("semantic_digest"),
	CONSTRAINT "authority_envelope_participant_id_uq" UNIQUE("participant_id","authority_envelope_id"),
	CONSTRAINT "authority_envelope_validity_ck" CHECK ("control"."authority_envelope"."valid_until" is null or "control"."authority_envelope"."valid_until" > "control"."authority_envelope"."valid_from")
);
--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."authority_group_member" (
	"authority_group_member_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"authority_group_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"valid_during" "tstzrange" NOT NULL,
	"state" "control"."authority_state" DEFAULT 'ACTIVE' NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "control"."authority_group_member" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."authority_group" (
	"authority_group_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"group_name" text NOT NULL,
	"state" "control"."authority_state" DEFAULT 'DRAFT' NOT NULL,
	"row_version" numeric(20, 0) DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "authority_group_participant_id_uq" UNIQUE("participant_id","authority_group_id")
);
--> statement-breakpoint
ALTER TABLE "control"."authority_group" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."delegation" (
	"delegation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"parent_assignment_id" uuid NOT NULL,
	"delegate_principal_id" uuid NOT NULL,
	"delegation_epoch" numeric(20, 0) NOT NULL,
	"scope_digest" "bytea" NOT NULL,
	"valid_during" "tstzrange" NOT NULL,
	"state" "control"."authority_state" DEFAULT 'DRAFT' NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "control"."delegation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."revocation" (
	"revocation_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"target_type" text NOT NULL,
	"target_id" uuid NOT NULL,
	"effective_at" timestamp(6) with time zone NOT NULL,
	"reason_code" text NOT NULL,
	"authority_epoch" numeric(20, 0) NOT NULL,
	"receipt_digest" "bytea" NOT NULL,
	"created_by_principal_id" uuid NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "revocation_receipt_digest_unique" UNIQUE("receipt_digest")
);
--> statement-breakpoint
ALTER TABLE "control"."revocation" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."credential" (
	"credential_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"kind" "control"."credential_kind" NOT NULL,
	"issuer" text,
	"subject" text,
	"audience" text,
	"wallet_chain_namespace" text,
	"wallet_address" "bytea",
	"public_key_digest" "bytea",
	"secret_fingerprint" "bytea",
	"allowed_cidrs" "cidr"[] DEFAULT ARRAY[]::cidr[] NOT NULL,
	"state" "control"."credential_state" DEFAULT 'PENDING' NOT NULL,
	"valid_from" timestamp(6) with time zone NOT NULL,
	"valid_until" timestamp(6) with time zone,
	"rotated_from_credential_id" uuid,
	"last_used_at" timestamp(6) with time zone,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "credential_validity_ck" CHECK ("control"."credential"."valid_until" is null or "control"."credential"."valid_until" > "control"."credential"."valid_from"),
	CONSTRAINT "credential_wallet_ck" CHECK (("control"."credential"."kind" = 'WALLET_PROOF') = ("control"."credential"."wallet_address" is not null)),
	CONSTRAINT "credential_wallet_namespace_ck" CHECK ("control"."credential"."kind" <> 'WALLET_PROOF' or "control"."credential"."wallet_chain_namespace" is not null),
	CONSTRAINT "credential_public_key_ck" CHECK ("control"."credential"."kind" not in ('WEBAUTHN', 'WORKLOAD_MTLS') or "control"."credential"."public_key_digest" is not null),
	CONSTRAINT "credential_oidc_ck" CHECK ("control"."credential"."kind" not in ('OIDC_SUBJECT', 'WORKLOAD_OIDC') or ("control"."credential"."issuer" is not null and "control"."credential"."subject" is not null)),
	CONSTRAINT "credential_row_version_ck" CHECK ("control"."credential"."row_version" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."credential" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."participant" (
	"participant_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"display_name" text NOT NULL,
	"state" "control"."participant_state" DEFAULT 'PROVISIONING' NOT NULL,
	"authority_epoch" numeric(20, 0) DEFAULT 0 NOT NULL,
	"root_privacy_domain_id" uuid,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"retired_at" timestamp(6) with time zone,
	CONSTRAINT "participant_display_name_ck" CHECK (length("control"."participant"."display_name") between 1 and 160),
	CONSTRAINT "participant_row_version_ck" CHECK ("control"."participant"."row_version" > 0),
	CONSTRAINT "participant_retired_state_ck" CHECK (("control"."participant"."state" = 'RETIRED') = ("control"."participant"."retired_at" is not null))
);
--> statement-breakpoint
ALTER TABLE "control"."participant" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."principal" (
	"principal_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"kind" "control"."principal_kind" NOT NULL,
	"display_label" text NOT NULL,
	"state" "control"."principal_state" DEFAULT 'PENDING' NOT NULL,
	"authority_epoch" numeric(20, 0) DEFAULT 0 NOT NULL,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "principal_participant_id_uq" UNIQUE("participant_id","principal_id"),
	CONSTRAINT "principal_display_label_ck" CHECK (length("control"."principal"."display_label") between 1 and 160),
	CONSTRAINT "principal_row_version_ck" CHECK ("control"."principal"."row_version" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."principal" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."privacy_domain" (
	"privacy_domain_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"domain_name" text NOT NULL,
	"placement_profile" text NOT NULL,
	"residency_profile" text NOT NULL,
	"state" "control"."privacy_domain_state" DEFAULT 'PROVISIONING' NOT NULL,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "privacy_domain_participant_id_uq" UNIQUE("participant_id","privacy_domain_id"),
	CONSTRAINT "privacy_domain_name_ck" CHECK (length("control"."privacy_domain"."domain_name") between 1 and 160),
	CONSTRAINT "privacy_domain_placement_ck" CHECK ("control"."privacy_domain"."placement_profile" in ('PRIVACY_GROUP_SHARED', 'PARTICIPANT_LOCAL', 'NETWORK_SHARED_APPROVED_EXCEPTION')),
	CONSTRAINT "privacy_domain_residency_ck" CHECK (length("control"."privacy_domain"."residency_profile") between 1 and 128),
	CONSTRAINT "privacy_domain_row_version_ck" CHECK ("control"."privacy_domain"."row_version" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."privacy_domain" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."recovery_challenge" (
	"recovery_challenge_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"challenge_digest" "bytea" NOT NULL,
	"custodian_one_principal_id" uuid,
	"custodian_two_principal_id" uuid,
	"issued_at" timestamp(6) with time zone NOT NULL,
	"expires_at" timestamp(6) with time zone NOT NULL,
	"consumed_at" timestamp(6) with time zone,
	"outcome" text DEFAULT 'LOADING' NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "recovery_challenge_challenge_digest_unique" UNIQUE("challenge_digest"),
	CONSTRAINT "recovery_lease_ck" CHECK ("control"."recovery_challenge"."expires_at" = "control"."recovery_challenge"."issued_at" + interval '15 minutes'),
	CONSTRAINT "recovery_distinct_custodians_ck" CHECK ("control"."recovery_challenge"."custodian_one_principal_id" is null or "control"."recovery_challenge"."custodian_two_principal_id" is null or "control"."recovery_challenge"."custodian_one_principal_id" <> "control"."recovery_challenge"."custodian_two_principal_id"),
	CONSTRAINT "recovery_consumed_ck" CHECK ("control"."recovery_challenge"."consumed_at" is null or "control"."recovery_challenge"."consumed_at" between "control"."recovery_challenge"."issued_at" and "control"."recovery_challenge"."expires_at")
);
--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."session" (
	"session_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"opaque_token_digest" "bytea" NOT NULL,
	"state" "control"."session_state" DEFAULT 'ACTIVE' NOT NULL,
	"authority_epoch" numeric(20, 0) NOT NULL,
	"delegation_epoch" numeric(20, 0) NOT NULL,
	"issued_at" timestamp(6) with time zone NOT NULL,
	"last_seen_at" timestamp(6) with time zone NOT NULL,
	"idle_expires_at" timestamp(6) with time zone NOT NULL,
	"absolute_expires_at" timestamp(6) with time zone NOT NULL,
	"step_up_verified_at" timestamp(6) with time zone,
	"revoked_at" timestamp(6) with time zone,
	"client_fingerprint_digest" "bytea" NOT NULL,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "session_opaque_token_digest_unique" UNIQUE("opaque_token_digest"),
	CONSTRAINT "session_seen_ck" CHECK ("control"."session"."last_seen_at" >= "control"."session"."issued_at"),
	CONSTRAINT "session_idle_ck" CHECK ("control"."session"."idle_expires_at" = "control"."session"."last_seen_at" + interval '30 minutes'),
	CONSTRAINT "session_absolute_ck" CHECK ("control"."session"."absolute_expires_at" = "control"."session"."issued_at" + interval '12 hours'),
	CONSTRAINT "session_expiry_order_ck" CHECK ("control"."session"."idle_expires_at" <= "control"."session"."absolute_expires_at"),
	CONSTRAINT "session_step_up_ck" CHECK ("control"."session"."step_up_verified_at" is null or "control"."session"."step_up_verified_at" between "control"."session"."issued_at" and "control"."session"."absolute_expires_at"),
	CONSTRAINT "session_revoked_ck" CHECK (("control"."session"."state" = 'REVOKED') = ("control"."session"."revoked_at" is not null)),
	CONSTRAINT "session_row_version_ck" CHECK ("control"."session"."row_version" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."session" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."approval_decision_record" (
	"approval_decision_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"approval_request_id" uuid NOT NULL,
	"approver_principal_id" uuid NOT NULL,
	"decision" "control"."approval_decision" NOT NULL,
	"decision_digest" "bytea" NOT NULL,
	"cose_sign1" "bytea" NOT NULL,
	"decided_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "approval_decision_record_decision_digest_unique" UNIQUE("decision_digest")
);
--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."approval_request" (
	"approval_request_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"privacy_domain_id" uuid NOT NULL,
	"action_intent_id" varchar(160) NOT NULL,
	"subject_type" text NOT NULL,
	"subject_id" uuid NOT NULL,
	"subject_digest" "bytea" NOT NULL,
	"maker_principal_id" uuid NOT NULL,
	"required_approvals" smallint NOT NULL,
	"state" "control"."approval_state" DEFAULT 'OPEN' NOT NULL,
	"expires_at" timestamp(6) with time zone NOT NULL,
	"row_version" bigint DEFAULT 1 NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"updated_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "approval_request_participant_id_uq" UNIQUE("participant_id","approval_request_id"),
	CONSTRAINT "approval_request_required_ck" CHECK ("control"."approval_request"."required_approvals" between 1 and 8),
	CONSTRAINT "approval_request_row_version_ck" CHECK ("control"."approval_request"."row_version" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."approval_request" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."idempotency_record" (
	"participant_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"action_intent_id" varchar(160) NOT NULL,
	"idempotency_key" varchar(256) NOT NULL,
	"operation_id" uuid NOT NULL,
	"input_digest" "bytea" NOT NULL,
	"result_digest" "bytea",
	"terminal_state" text,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	"expires_at" timestamp(6) with time zone NOT NULL,
	CONSTRAINT "idempotency_record_pk" PRIMARY KEY("participant_id","principal_id","action_intent_id","idempotency_key")
);
--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."outbox_event" (
	"outbox_event_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"event_type" text NOT NULL,
	"aggregate_type" text NOT NULL,
	"aggregate_id" uuid NOT NULL,
	"aggregate_sequence" bigint NOT NULL,
	"payload_cbor" "bytea" NOT NULL,
	"payload_digest" "bytea" NOT NULL,
	"cose_sign1" "bytea" NOT NULL,
	"occurred_at" timestamp(6) with time zone NOT NULL,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "outbox_sequence_ck" CHECK ("control"."outbox_event"."aggregate_sequence" > 0)
);
--> statement-breakpoint
ALTER TABLE "control"."outbox_event" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD CONSTRAINT "assignment_principal_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD CONSTRAINT "assignment_envelope_fk" FOREIGN KEY ("participant_id","authority_envelope_id") REFERENCES "control"."authority_envelope"("participant_id","authority_envelope_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD CONSTRAINT "assignment_creator_fk" FOREIGN KEY ("participant_id","created_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD CONSTRAINT "authority_envelope_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD CONSTRAINT "authority_envelope_principal_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."authority_group_member" ADD CONSTRAINT "authority_group_member_group_fk" FOREIGN KEY ("participant_id","authority_group_id") REFERENCES "control"."authority_group"("participant_id","authority_group_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."authority_group_member" ADD CONSTRAINT "authority_group_member_principal_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."authority_group" ADD CONSTRAINT "authority_group_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD CONSTRAINT "delegation_assignment_fk" FOREIGN KEY ("participant_id","parent_assignment_id") REFERENCES "control"."assignment"("participant_id","assignment_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD CONSTRAINT "delegation_principal_fk" FOREIGN KEY ("participant_id","delegate_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."revocation" ADD CONSTRAINT "revocation_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."revocation" ADD CONSTRAINT "revocation_creator_fk" FOREIGN KEY ("participant_id","created_by_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."credential" ADD CONSTRAINT "credential_principal_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."credential" ADD CONSTRAINT "credential_rotated_from_fk" FOREIGN KEY ("rotated_from_credential_id") REFERENCES "control"."credential"("credential_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."principal" ADD CONSTRAINT "principal_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."privacy_domain" ADD CONSTRAINT "privacy_domain_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD CONSTRAINT "recovery_subject_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD CONSTRAINT "recovery_custodian_one_fk" FOREIGN KEY ("participant_id","custodian_one_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD CONSTRAINT "recovery_custodian_two_fk" FOREIGN KEY ("participant_id","custodian_two_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."session" ADD CONSTRAINT "session_principal_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD CONSTRAINT "approval_decision_request_fk" FOREIGN KEY ("participant_id","approval_request_id") REFERENCES "control"."approval_request"("participant_id","approval_request_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD CONSTRAINT "approval_decision_principal_fk" FOREIGN KEY ("participant_id","approver_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_decision_record" ADD CONSTRAINT "approval_decision_privacy_domain_fk" FOREIGN KEY ("participant_id","privacy_domain_id") REFERENCES "control"."privacy_domain"("participant_id","privacy_domain_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_request" ADD CONSTRAINT "approval_request_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_request" ADD CONSTRAINT "approval_request_action_intent_id_action_intent_action_intent_id_fk" FOREIGN KEY ("action_intent_id") REFERENCES "control"."action_intent"("action_intent_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_request" ADD CONSTRAINT "approval_request_maker_fk" FOREIGN KEY ("participant_id","maker_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."approval_request" ADD CONSTRAINT "approval_request_privacy_domain_fk" FOREIGN KEY ("participant_id","privacy_domain_id") REFERENCES "control"."privacy_domain"("participant_id","privacy_domain_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ADD CONSTRAINT "idempotency_principal_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."outbox_event" ADD CONSTRAINT "outbox_event_participant_id_participant_participant_id_fk" FOREIGN KEY ("participant_id") REFERENCES "control"."participant"("participant_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "authority_group_name_uq" ON "control"."authority_group" USING btree ("participant_id","group_name");--> statement-breakpoint
CREATE UNIQUE INDEX "delegation_participant_id_uq" ON "control"."delegation" USING btree ("participant_id","delegation_id");--> statement-breakpoint
CREATE UNIQUE INDEX "delegation_epoch_uq" ON "control"."delegation" USING btree ("participant_id","parent_assignment_id","delegation_epoch");--> statement-breakpoint
CREATE UNIQUE INDEX "revocation_target_epoch_uq" ON "control"."revocation" USING btree ("participant_id","target_type","target_id","authority_epoch");--> statement-breakpoint
CREATE UNIQUE INDEX "credential_identity_uq" ON "control"."credential" USING btree ("participant_id","kind","issuer","subject","audience","wallet_chain_namespace","wallet_address","public_key_digest");--> statement-breakpoint
CREATE UNIQUE INDEX "participant_epoch_uq" ON "control"."participant" USING btree ("participant_id","authority_epoch");--> statement-breakpoint
CREATE UNIQUE INDEX "principal_kind_label_uq" ON "control"."principal" USING btree ("participant_id","kind","display_label");--> statement-breakpoint
CREATE UNIQUE INDEX "privacy_domain_name_uq" ON "control"."privacy_domain" USING btree ("participant_id","domain_name");--> statement-breakpoint
CREATE UNIQUE INDEX "session_participant_id_uq" ON "control"."session" USING btree ("participant_id","session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "approval_decision_approver_uq" ON "control"."approval_decision_record" USING btree ("approval_request_id","approver_principal_id");--> statement-breakpoint
CREATE UNIQUE INDEX "approval_request_subject_uq" ON "control"."approval_request" USING btree ("participant_id","subject_type","subject_id","subject_digest","state");--> statement-breakpoint
CREATE UNIQUE INDEX "idempotency_operation_uq" ON "control"."idempotency_record" USING btree ("participant_id","operation_id");--> statement-breakpoint
CREATE UNIQUE INDEX "outbox_aggregate_sequence_uq" ON "control"."outbox_event" USING btree ("participant_id","aggregate_type","aggregate_id","aggregate_sequence");--> statement-breakpoint
CREATE UNIQUE INDEX "outbox_event_participant_uq" ON "control"."outbox_event" USING btree ("participant_id","event_id");--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."assignment" AS PERMISSIVE FOR ALL TO public USING ("control"."assignment"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."assignment"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."authority_envelope" AS PERMISSIVE FOR ALL TO public USING ("control"."authority_envelope"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."authority_envelope"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."authority_group_member" AS PERMISSIVE FOR ALL TO public USING ("control"."authority_group_member"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."authority_group_member"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."authority_group" AS PERMISSIVE FOR ALL TO public USING ("control"."authority_group"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."authority_group"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."delegation" AS PERMISSIVE FOR ALL TO public USING ("control"."delegation"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."delegation"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."revocation" AS PERMISSIVE FOR ALL TO public USING ("control"."revocation"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."revocation"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."credential" AS PERMISSIVE FOR ALL TO public USING ("control"."credential"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."credential"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."participant" AS PERMISSIVE FOR ALL TO public USING ("control"."participant"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."participant"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."principal" AS PERMISSIVE FOR ALL TO public USING ("control"."principal"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."principal"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."privacy_domain" AS PERMISSIVE FOR ALL TO public USING ("control"."privacy_domain"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."privacy_domain"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."recovery_challenge" AS PERMISSIVE FOR ALL TO public USING ("control"."recovery_challenge"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."recovery_challenge"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."session" AS PERMISSIVE FOR ALL TO public USING ("control"."session"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."session"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."approval_decision_record" AS PERMISSIVE FOR ALL TO public USING ("control"."approval_decision_record"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."approval_decision_record"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."approval_request" AS PERMISSIVE FOR ALL TO public USING ("control"."approval_request"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."approval_request"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."idempotency_record" AS PERMISSIVE FOR ALL TO public USING ("control"."idempotency_record"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."idempotency_record"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."outbox_event" AS PERMISSIVE FOR ALL TO public USING ("control"."outbox_event"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid) WITH CHECK ("control"."outbox_event"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid);