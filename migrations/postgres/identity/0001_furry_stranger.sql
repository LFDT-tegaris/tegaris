ALTER TYPE "control"."authority_state" ADD VALUE 'SUBMITTED' BEFORE 'PENDING_APPROVAL';--> statement-breakpoint
ALTER TYPE "control"."authority_state" ADD VALUE 'APPROVED' BEFORE 'ACTIVE';--> statement-breakpoint
ALTER TYPE "control"."authority_state" ADD VALUE 'PROPOSED' BEFORE 'SUSPENDED';--> statement-breakpoint
ALTER TYPE "control"."authority_state" ADD VALUE 'SUPERSEDED' BEFORE 'REVOKED';--> statement-breakpoint
ALTER TYPE "control"."credential_state" ADD VALUE 'ISSUED' BEFORE 'ACTIVE';--> statement-breakpoint
ALTER TYPE "control"."principal_state" ADD VALUE 'PROVISIONED' BEFORE 'ACTIVE';--> statement-breakpoint
ALTER TYPE "control"."principal_state" ADD VALUE 'SUSPENDED' BEFORE 'DISABLED';--> statement-breakpoint
ALTER TYPE "control"."principal_state" ADD VALUE 'REVOKED' BEFORE 'DISABLED';--> statement-breakpoint
ALTER TYPE "control"."principal_state" ADD VALUE 'OFFBOARDED' BEFORE 'DISABLED';--> statement-breakpoint
ALTER TYPE "control"."session_state" ADD VALUE 'AUTHENTICATING' BEFORE 'ACTIVE';--> statement-breakpoint
ALTER TYPE "control"."session_state" ADD VALUE 'STEP_UP_REQUIRED' BEFORE 'IDLE_EXPIRED';--> statement-breakpoint
ALTER TYPE "control"."session_state" ADD VALUE 'EXPIRED' BEFORE 'REVOKED';--> statement-breakpoint
ALTER TYPE "control"."session_state" ADD VALUE 'COMPROMISED' BEFORE 'TERMINATED';--> statement-breakpoint
CREATE ROLE "openpc_control_owner" WITH NOINHERIT;--> statement-breakpoint
CREATE ROLE "openpc_control_platform_runtime" WITH NOINHERIT;--> statement-breakpoint
CREATE ROLE "openpc_control_reader" WITH NOINHERIT;--> statement-breakpoint
CREATE ROLE "openpc_control_runtime" WITH NOINHERIT;--> statement-breakpoint
CREATE ROLE "openpc_control_worker" WITH NOINHERIT;--> statement-breakpoint
CREATE TABLE "control"."mfa_challenge" (
	"mfa_challenge_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"participant_id" uuid NOT NULL,
	"session_id" uuid NOT NULL,
	"principal_id" uuid NOT NULL,
	"action_intent_id" text NOT NULL,
	"resource_digest" "bytea" NOT NULL,
	"challenge_digest" "bytea" NOT NULL,
	"rp_id_hash" "bytea" NOT NULL,
	"expires_at" timestamp(6) with time zone NOT NULL,
	"consumed_at" timestamp(6) with time zone,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "mfa_challenge_challenge_digest_unique" UNIQUE("challenge_digest")
);
--> statement-breakpoint
ALTER TABLE "control"."mfa_challenge" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "control"."oidc_transaction" (
	"transaction_id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"state_digest" "bytea" NOT NULL,
	"nonce_digest" "bytea" NOT NULL,
	"code_verifier" "bytea" NOT NULL,
	"code_challenge" text NOT NULL,
	"issuer" text NOT NULL,
	"client_id" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"expires_at" timestamp(6) with time zone NOT NULL,
	"consumed_at" timestamp(6) with time zone,
	"created_at" timestamp(6) with time zone DEFAULT clock_timestamp() NOT NULL,
	CONSTRAINT "oidc_transaction_state_digest_unique" UNIQUE("state_digest"),
	CONSTRAINT "oidc_transaction_nonce_digest_unique" UNIQUE("nonce_digest"),
	CONSTRAINT "oidc_transaction_challenge_ck" CHECK (length("control"."oidc_transaction"."code_challenge") between 43 and 128),
	CONSTRAINT "oidc_transaction_expiry_ck" CHECK ("control"."oidc_transaction"."expires_at" > "control"."oidc_transaction"."created_at")
);
--> statement-breakpoint
ALTER TABLE "control"."session" DROP CONSTRAINT "session_idle_ck";--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" DROP CONSTRAINT "idempotency_principal_fk";
--> statement-breakpoint
ALTER TABLE "control"."delegation" ALTER COLUMN "parent_assignment_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "privacy_domain_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "action_intent_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "resource_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "risk_classes" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "maker_checker_required" boolean NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "step_up_required" boolean NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."assignment" ADD COLUMN "onward_delegation_depth" smallint NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "maker_principal_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "checker_principal_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "privacy_domain_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "action_intent_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "resource_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "risk_classes" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "maker_checker_required" boolean NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "step_up_required" boolean NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD COLUMN "onward_delegation_depth" smallint NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "parent_delegation_id" uuid;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "grantor_principal_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "privacy_domain_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "action_intent_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "resource_ids" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "risk_classes" text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "maker_checker_required" boolean NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "step_up_required" boolean NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD COLUMN "onward_delegation_depth" smallint NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD COLUMN "recovery_principal_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD COLUMN "purpose_digest" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD COLUMN "action_intent_id" text NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD COLUMN "current_epoch" numeric(20, 0) NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD COLUMN "custodian_one_approved_at" timestamp(6) with time zone;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD COLUMN "custodian_two_approved_at" timestamp(6) with time zone;--> statement-breakpoint
ALTER TABLE "control"."session" ADD COLUMN "participant_epoch" numeric(20, 0) NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."session" ADD COLUMN "session_epoch" numeric(20, 0) DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."session" ADD COLUMN "refresh_family_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."session" ADD COLUMN "refresh_token_digest" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."session" ADD COLUMN "refresh_used" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."session" ADD COLUMN "csrf_secret" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "control"."session" ADD COLUMN "revoked_reason" text;--> statement-breakpoint
ALTER TABLE "control"."idempotency_record" ADD COLUMN "result_payload" jsonb;--> statement-breakpoint
ALTER TABLE "control"."mfa_challenge" ADD CONSTRAINT "mfa_challenge_session_fk" FOREIGN KEY ("participant_id","session_id") REFERENCES "control"."session"("participant_id","session_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."mfa_challenge" ADD CONSTRAINT "mfa_challenge_principal_fk" FOREIGN KEY ("participant_id","principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD CONSTRAINT "authority_envelope_maker_fk" FOREIGN KEY ("participant_id","maker_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD CONSTRAINT "authority_envelope_checker_fk" FOREIGN KEY ("participant_id","checker_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD CONSTRAINT "delegation_parent_fk" FOREIGN KEY ("participant_id","parent_delegation_id") REFERENCES "control"."delegation"("participant_id","delegation_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD CONSTRAINT "delegation_grantor_fk" FOREIGN KEY ("participant_id","grantor_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD CONSTRAINT "recovery_principal_fk" FOREIGN KEY ("participant_id","recovery_principal_id") REFERENCES "control"."principal"("participant_id","principal_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "session_refresh_digest_uq" ON "control"."session" USING btree ("refresh_token_digest");--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD CONSTRAINT "authority_envelope_maker_checker_ck" CHECK ("control"."authority_envelope"."checker_principal_id" is null or "control"."authority_envelope"."checker_principal_id" <> "control"."authority_envelope"."maker_principal_id");--> statement-breakpoint
ALTER TABLE "control"."authority_envelope" ADD CONSTRAINT "authority_envelope_depth_ck" CHECK ("control"."authority_envelope"."onward_delegation_depth" between 0 and 32);--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD CONSTRAINT "delegation_parent_ck" CHECK (num_nonnulls("control"."delegation"."parent_assignment_id", "control"."delegation"."parent_delegation_id") = 1);--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD CONSTRAINT "delegation_principal_ck" CHECK ("control"."delegation"."grantor_principal_id" <> "control"."delegation"."delegate_principal_id");--> statement-breakpoint
ALTER TABLE "control"."delegation" ADD CONSTRAINT "delegation_depth_ck" CHECK ("control"."delegation"."onward_delegation_depth" between 0 and 32);--> statement-breakpoint
ALTER TABLE "control"."recovery_challenge" ADD CONSTRAINT "recovery_principal_distinct_ck" CHECK ("control"."recovery_challenge"."recovery_principal_id" <> "control"."recovery_challenge"."principal_id");--> statement-breakpoint
ALTER TABLE "control"."session" ADD CONSTRAINT "session_idle_ck" CHECK ("control"."session"."idle_expires_at" = least("control"."session"."last_seen_at" + interval '30 minutes', "control"."session"."absolute_expires_at"));--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."assignment" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."authority_envelope" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."authority_group_member" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."authority_group" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."delegation" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."revocation" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."credential" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."participant" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."principal" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."privacy_domain" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."recovery_challenge" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."session" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."approval_decision_record" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."approval_request" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."idempotency_record" CASCADE;--> statement-breakpoint
DROP POLICY "participant_isolation" ON "control"."outbox_event" CASCADE;--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."assignment" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."assignment"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."assignment"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."authority_envelope" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."authority_envelope"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."authority_envelope"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."authority_group_member" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."authority_group_member"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."authority_group_member"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."authority_group" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."authority_group"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."authority_group"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."delegation" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."delegation"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."delegation"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."revocation" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."revocation"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."revocation"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."credential" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."credential"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."credential"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."participant" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."participant"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."participant"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."principal" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."principal"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."principal"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."privacy_domain" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."privacy_domain"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."privacy_domain"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."recovery_challenge" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."recovery_challenge"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."recovery_challenge"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."session" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."session"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."session"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."approval_decision_record" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."approval_decision_record"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."approval_decision_record"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."approval_request" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."approval_request"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."approval_request"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."idempotency_record" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."idempotency_record"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."idempotency_record"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."outbox_event" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."outbox_event"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."outbox_event"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );--> statement-breakpoint
CREATE POLICY "participant_isolation" ON "control"."mfa_challenge" AS RESTRICTIVE FOR ALL TO "openpc_control_reader", "openpc_control_runtime", "openpc_control_worker" USING (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."mfa_challenge"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    ) WITH CHECK (
      current_setting('openpc.context_mode', true) = 'PARTICIPANT'
      and current_setting('openpc.operation_id', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      and current_setting('openpc.action_intent_id', true) ~ '^ACT-[A-Z0-9_]+-V[1-9][0-9]*$'
      and "control"."mfa_challenge"."participant_id" = nullif(current_setting('openpc.participant_id', true), '')::uuid
    );

-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT
ALTER ROLE "openpc_control_owner" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_runtime" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_worker" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_platform_runtime" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE "openpc_control_reader" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA control FROM PUBLIC;
GRANT USAGE ON SCHEMA control TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
ALTER TABLE "control"."approval_decision_record" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."approval_request" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."assignment" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_envelope" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_group" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."authority_group_member" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."credential" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."delegation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."idempotency_record" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."mfa_challenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."outbox_event" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."participant" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."principal" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."privacy_domain" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."recovery_challenge" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."revocation" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."session" FORCE ROW LEVEL SECURITY;
ALTER TABLE "control"."approval_decision_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."approval_request" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."assignment" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_envelope" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_group" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."authority_group_member" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."credential" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."delegation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."idempotency_record" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."mfa_challenge" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."outbox_event" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."participant" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."principal" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."privacy_domain" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."recovery_challenge" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."revocation" OWNER TO "openpc_control_owner";
ALTER TABLE "control"."session" OWNER TO "openpc_control_owner";
REVOKE ALL ON "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_runtime";
GRANT SELECT, UPDATE ON "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_worker";
GRANT SELECT ON "control"."approval_decision_record", "control"."approval_request", "control"."assignment", "control"."authority_envelope", "control"."authority_group", "control"."authority_group_member", "control"."credential", "control"."delegation", "control"."idempotency_record", "control"."mfa_challenge", "control"."outbox_event", "control"."participant", "control"."principal", "control"."privacy_domain", "control"."recovery_challenge", "control"."revocation", "control"."session" TO "openpc_control_reader";
REVOKE ALL ON "control"."oidc_transaction", "control"."action_intent" FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON "control"."oidc_transaction" TO "openpc_control_runtime";
GRANT SELECT ON "control"."action_intent" TO "openpc_control_runtime", "openpc_control_worker", "openpc_control_reader";
