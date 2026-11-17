import { createHash, createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';

import { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import { encodeIdentityCredentialPayload } from '../../../packages/security-kernel/src/index.js';

import { buildIdentityService } from '../../../services/identity-service/src/app.js';
import { canonicalAuthorizationDigest } from '../../../services/identity-service/src/contracts/authorization.js';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import { createLocalIdentityAuthorizationAdapter } from '../../../services/identity-service/src/domain/local-identity-authorization.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';

const runtimeDatabaseUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const adminDatabaseUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const integration = runtimeDatabaseUrl === undefined ? it.skip : it;
const mutationIntegration =
  runtimeDatabaseUrl === undefined || adminDatabaseUrl === undefined ? it.skip : it;

function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(',')}}`;
}

function sha256(value: string | Buffer): Buffer {
  return createHash('sha256').update(value).digest();
}

function canonicalEvidence(participantId: string, principalId: string, epoch: string): Buffer {
  return encodeIdentityCredentialPayload({
    participantId: `urn:openpc:participant:${participantId}`,
    principalId: `urn:openpc:principal:${principalId}`,
    authorityEpoch: epoch,
    issuedAt: '2026-08-24T00:00:00.000000Z',
    expiresAt: '2026-08-24T00:05:00.000000Z',
  });
}

function cborByteString(value: Buffer): Buffer {
  if (value.length < 24) return Buffer.concat([Buffer.from([0x40 | value.length]), value]);
  if (value.length <= 0xff) return Buffer.concat([Buffer.from([0x58, value.length]), value]);
  const length = Buffer.alloc(3);
  length[0] = 0x59;
  length.writeUInt16BE(value.length, 1);
  return Buffer.concat([length, value]);
}

function signedTestEvidence(evidenceCbor: Buffer): {
  readonly coseSign1: Buffer;
  readonly digest: Buffer;
} {
  const protectedHeader = Buffer.from(
    'a5012603776170706c69636174696f6e2f6f70656e70632b63626f720458205cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd31903e91957e51903ea781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631',
    'hex',
  );
  const signatureStructure = Buffer.concat([
    Buffer.from([0x84, 0x6a]),
    Buffer.from('Signature1'),
    cborByteString(protectedHeader),
    Buffer.from([0x40]),
    cborByteString(evidenceCbor),
  ]);
  const privateKey = createPrivateKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.from(
        '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
        'hex',
      ).toString('base64url'),
      y: Buffer.from(
        '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
        'hex',
      ).toString('base64url'),
      d: Buffer.from(
        '0000000000000000000000000000000000000000000000000000000000000001',
        'hex',
      ).toString('base64url'),
    },
  });
  const signature = sign('sha256', signatureStructure, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return {
    coseSign1: Buffer.concat([
      Buffer.from([0xd2, 0x84]),
      cborByteString(protectedHeader),
      Buffer.from([0xa0]),
      cborByteString(evidenceCbor),
      cborByteString(signature),
    ]),
    digest: sha256(evidenceCbor),
  };
}

describe('authoritative PostgreSQL identity runtime', () => {
  integration(
    'persists server-generated OIDC state under a non-bypass, reset pool context',
    async () => {
      const pool = new Pool({ connectionString: runtimeDatabaseUrl, max: 1 });
      let transactionId: string | undefined;
      try {
        const role = await pool.query<{
          bypass: boolean;
          superuser: boolean;
        }>(
          `select rolbypassrls as bypass, rolsuper as superuser
         from pg_roles where rolname = current_user`,
        );
        expect(role.rows).toEqual([{ bypass: false, superuser: false }]);

        const repository = new PostgresIdentityRepository(pool);
        const started = await repository.beginOidc({
          issuer: 'https://issuer.openpc.example',
          clientId: 'openpc-control',
          redirectUri: 'https://control.openpc.example/callback',
        });
        transactionId = started.authorization.transactionId;
        expect(started.authorization.transactionId).toMatch(
          /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
        );
        expect(started.authorization.state).toHaveLength(43);
        expect(started.authorization.nonce).toHaveLength(43);
        expect(started.authorization.codeChallenge).toHaveLength(43);

        expect(
          await repository.oidcExchangeContext(started.authorization.transactionId, {
            browserSession: started.custody.browserSession,
            codeVerifier: `${started.custody.codeVerifier}x`,
          }),
        ).toBeUndefined();

        const exchange = await repository.oidcExchangeContext(
          started.authorization.transactionId,
          started.custody,
        );
        expect(exchange).toMatchObject({
          issuer: 'https://issuer.openpc.example',
          clientId: 'openpc-control',
          redirectUri: 'https://control.openpc.example/callback',
        });
        expect(exchange?.codeVerifier).toHaveLength(43);

        const oidcStorage = await pool.query<{
          browserDigest: Buffer;
          plaintextVerifierAbsent: boolean;
          stateDigest: Buffer;
          verifierDigest: Buffer;
        }>(
          `select not exists(
                    select 1 from information_schema.columns
                     where table_schema='control' and table_name='oidc_transaction'
                       and column_name='code_verifier'
                  ) "plaintextVerifierAbsent",
                  state_digest "stateDigest",code_verifier_digest "verifierDigest",
                  browser_session_digest "browserDigest"
             from control.oidc_transaction where transaction_id=$1`,
          [started.authorization.transactionId],
        );
        expect(oidcStorage.rows[0]?.plaintextVerifierAbsent).toBe(true);
        expect(oidcStorage.rows[0]?.stateDigest).not.toEqual(
          Buffer.from(started.authorization.state),
        );
        expect(oidcStorage.rows[0]?.verifierDigest).not.toEqual(
          Buffer.from(started.custody.codeVerifier),
        );
        expect(oidcStorage.rows[0]?.browserDigest).not.toEqual(
          Buffer.from(started.custody.browserSession),
        );

        const rls = await pool.query<{
          forced: boolean;
          permissive: boolean;
        }>(
          `select bool_and(c.relforcerowsecurity) as forced,
                bool_and(p.polpermissive) as permissive
           from pg_class c
           join pg_namespace n on n.oid = c.relnamespace
           join pg_policy p on p.polrelid = c.oid
          where n.nspname = 'control' and c.relname in ('participant', 'session', 'assignment')`,
        );
        expect(rls.rows).toEqual([{ forced: true, permissive: true }]);

        const securityCatalog = await pool.query<{
          allRoleFlagsExact: boolean;
          allFunctionsOwned: boolean;
          databaseOwned: boolean;
          immutableTriggerCount: number;
          privacyPolicyCount: number;
          publicCanConnect: boolean;
          runtimeCanDelete: boolean;
          runtimeCanUpdateApproval: boolean;
          typedGuardCount: number;
        }>(
          `select
             (select bool_and(not rolcanlogin and not rolsuper and not rolcreatedb
                              and not rolcreaterole and not rolreplication and not rolinherit
                              and rolbypassrls=(rolname in ('openpc_control_migrator','openpc_control_maintenance','openpc_backup_operator')))
                from pg_roles where rolname = any(array[
                  'openpc_control_owner','openpc_control_migrator','openpc_control_runtime',
                  'openpc_control_worker','openpc_control_platform_runtime','openpc_control_reader',
                  'openpc_control_maintenance','openpc_backup_operator'])) "allRoleFlagsExact",
             (select pg_get_userbyid(datdba)='openpc_control_owner' from pg_database
               where datname=current_database()) "databaseOwned",
             (select bool_and(pg_get_userbyid(p.proowner)=case
                       when p.oid='openpc.signing_attempt_authority_status(uuid)'::regprocedure
                         then 'openpc_signing_authority_locker'
                       else 'openpc_control_owner'
                     end)
                from pg_proc p join pg_namespace n on n.oid=p.pronamespace
               where n.nspname in ('openpc','control')) "allFunctionsOwned",
             has_database_privilege('public',current_database(),'connect') "publicCanConnect",
             has_table_privilege('openpc_control_runtime','control.participant','delete') "runtimeCanDelete",
             has_table_privilege('openpc_control_runtime','control.approval_decision_record','update') "runtimeCanUpdateApproval",
             (select count(*)::int from pg_trigger t join pg_class c on c.oid=t.tgrelid
               join pg_namespace n on n.oid=c.relnamespace where not t.tgisinternal
                 and n.nspname='control' and t.tgname in
                   ('approval_decision_immutable','mutation_evidence_immutable')) "immutableTriggerCount",
             (select count(*)::int from pg_proc p join pg_namespace n on n.oid=p.pronamespace
               where n.nspname='openpc' and p.proname in ('set_request_context','assert_request_context')
                 and not p.prosecdef) "typedGuardCount",
             (select count(*)::int from pg_policy p join pg_class c on c.oid=p.polrelid
               join pg_namespace n on n.oid=c.relnamespace
               where n.nspname='control' and p.polname='privacy_domain_isolation'
                 and c.relname in ('approval_request','approval_decision_record','mutation_evidence','outbox_event'))
               "privacyPolicyCount"`,
        );
        expect(securityCatalog.rows).toEqual([
          {
            allRoleFlagsExact: true,
            allFunctionsOwned: true,
            databaseOwned: true,
            immutableTriggerCount: 2,
            privacyPolicyCount: 4,
            publicCanConnect: false,
            runtimeCanDelete: false,
            runtimeCanUpdateApproval: false,
            typedGuardCount: 2,
          },
        ]);

        const contextClient = await pool.connect();
        try {
          await contextClient.query('begin');
          await contextClient.query(
            `select openpc.set_request_context(
               'PARTICIPANT','018f0000-0000-7000-8000-000000000001',
               '018f0000-0000-7000-8000-000000000002',
               '018f0000-0000-7000-8000-000000000003','ACT-IDENTITY_CREATE_SESSION-V1',true
             ),openpc.assert_request_context(true)`,
          );
          const typed = await contextClient.query<{ operationId: string; privacyDomainId: string }>(
            `select openpc.current_operation_id()::text "operationId",
                    openpc.current_privacy_domain_id()::text "privacyDomainId"`,
          );
          expect(typed.rows).toEqual([
            {
              operationId: '018f0000-0000-7000-8000-000000000003',
              privacyDomainId: '018f0000-0000-7000-8000-000000000002',
            },
          ]);
          await contextClient.query('rollback');
          await contextClient.query('begin');
          await expect(
            contextClient.query(
              `select openpc.set_request_context(
                'PLATFORM','018f0000-0000-7000-8000-000000000001',null,
                '018f0000-0000-7000-8000-000000000003','ACT-IDENTITY_CREATE_SESSION-V1',false)`,
            ),
          ).rejects.toThrow(/DATA-6002-PLATFORM-CONTEXT-FORBIDDEN/u);
          await contextClient.query('rollback');
        } finally {
          contextClient.release();
        }

        const reset = await pool.query<{ contextCleared: boolean }>(
          `select nullif(current_setting('openpc.participant_id', true), '') is null
                  and nullif(current_setting('openpc.operation_id', true), '') is null
                  as "contextCleared"`,
        );
        expect(reset.rows).toEqual([{ contextCleared: true }]);
      } finally {
        await pool.end();
        if (transactionId !== undefined && adminDatabaseUrl !== undefined) {
          const admin = new Pool({ connectionString: adminDatabaseUrl, max: 1 });
          try {
            await admin.query(`delete from control.oidc_transaction where transaction_id=$1`, [
              transactionId,
            ]);
          } finally {
            await admin.end();
          }
        }
      }
    },
  );

  mutationIntegration(
    'commits authorization, fresh WebAuthn, idempotency, evidence, and outbox atomically',
    async () => {
      const runtimePool = new Pool({ connectionString: runtimeDatabaseUrl, max: 1 });
      const adminPool = new Pool({ connectionString: adminDatabaseUrl, max: 1 });
      const participantId = '018f0000-0000-7001-8000-000000000101';
      const privacyDomainId = '018f0000-0000-7001-8000-000000000102';
      const makerId = '018f0000-0000-7001-8000-000000000103';
      const checkerId = '018f0000-0000-7001-8000-000000000104';
      const targetId = '018f0000-0000-7001-8000-000000000105';
      const sessionId = '018f0000-0000-7001-8000-000000000106';
      const approvalId = '018f0000-0000-7001-8000-000000000107';
      const mfaId = '018f0000-0000-7001-8000-000000000108';
      const makerEnvelopeId = '018f0000-0000-7001-8000-000000000111';
      const checkerEnvelopeId = '018f0000-0000-7001-8000-000000000112';
      const makerAssignmentId = '018f0000-0000-7001-8000-000000000113';
      const checkerAssignmentId = '018f0000-0000-7001-8000-000000000114';
      const checkerCredentialId = '018f0000-0000-7001-8000-000000000115';
      const makerCredentialId = '018f0000-0000-7001-8000-000000000116';
      const registrationApprovalId = '018f0000-0000-7001-8000-000000000117';
      const registrationMfaId = '018f0000-0000-7001-8000-000000000118';
      const checkerSessionId = '018f0000-0000-7001-8000-000000000119';
      const provisionCandidateId = '018f0000-0000-7001-8000-000000000120';
      const registrationCandidateId = '018f0000-0000-7001-8000-000000000121';
      const provisionVerificationOperationId = '018f0000-0000-7001-8000-000000000122';
      const registrationVerificationOperationId = '018f0000-0000-7001-8000-000000000123';
      const provisionVerificationEventId = '018f0000-0000-7001-8000-000000000124';
      const registrationVerificationEventId = '018f0000-0000-7001-8000-000000000125';
      const actionIntentId = 'ACT-PARTICIPANT_CREATE_MEMBER-V1';
      const principal = {
        principalId: targetId,
        participantId,
        displayLabel: 'I02 atomic mutation target',
        kind: 'USER' as const,
        state: 'PROVISIONED' as const,
        identityEpoch: '0',
      };
      const candidateDigest = sha256(stableJson(principal));
      const evidenceCbor = Buffer.from(
        'a901781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631021957e50365312e302e300458202bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b111105783b75726e3a6f70656e70633a7061727469636970616e743a30313866316532642d336334622d376136392d386162632d30313233343536373839616206783975726e3a6f70656e70633a7072696e636970616c3a30313866316532642d336334622d376136392d386162632d31313233343536373839616207613708781b323032362d30382d32345430303a30303a30302e3030303030305a09781b323032362d30382d32345430303a30353a30302e3030303030305a',
        'hex',
      );
      const evidenceDigest = sha256(evidenceCbor);
      const registrationRequest = {
        actionIntentId,
        resourceDigest: `sha256:${sha256('i02-registration-resource').toString('hex')}`,
        rpIdHash: `sha256:${sha256('openpc.example').toString('hex')}`,
      };
      const registrationCandidateDigest = sha256(stableJson(registrationRequest));
      const registrationEvidenceCbor = canonicalEvidence(participantId, checkerId, '101');
      const registrationEvidence = signedTestEvidence(registrationEvidenceCbor);
      const signerSpki = Buffer.from(
        '3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
        'hex',
      );
      const coseSign1 = Buffer.from(
        'd2845867a5012603776170706c69636174696f6e2f6f70656e70632b63626f720458205cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd31903e91957e51903ea781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631a0590108a901781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631021957e50365312e302e300458202bcee470e17149e2d5cc67bbc2e5f14b368723181b47d7ebd3f4535e294b111105783b75726e3a6f70656e70633a7061727469636970616e743a30313866316532642d336334622d376136392d386162632d30313233343536373839616206783975726e3a6f70656e70633a7072696e636970616c3a30313866316532642d336334622d376136392d386162632d31313233343536373839616207613708781b323032362d30382d32345430303a30303a30302e3030303030305a09781b323032362d30382d32345430303a30353a30302e3030303030305a5840c0283047c7739a45f0600ea88a379d7d0f20b76da383eb11173620b6c9befe4e3969529b1dba1b493fc93bf204a437a92f71e8b17447d7631a4663290eef19bf',
        'hex',
      );
      const provisionStepUpEvidenceCbor = canonicalEvidence(participantId, makerId, '102');
      const provisionStepUpEvidence = signedTestEvidence(provisionStepUpEvidenceCbor);
      const provisionStepUpBinding = sha256('i02-provision-webauthn-binding');
      const provisionVerificationCandidateDigest = sha256('i02-provision-webauthn-verification');
      const registrationStepUpEvidenceCbor = canonicalEvidence(participantId, makerId, '103');
      const registrationStepUpEvidence = signedTestEvidence(registrationStepUpEvidenceCbor);
      const registrationStepUpBinding = sha256('i02-registration-webauthn-binding');
      const registrationVerificationCandidateDigest = sha256(
        'i02-registration-webauthn-verification',
      );
      const createdActionIds: string[] = [];
      const runtimeKeyPair = generateKeyPairSync('ed25519');
      const runtimePrivateKey = runtimeKeyPair.privateKey.export({
        format: 'der',
        type: 'pkcs8',
      });
      const runtimePublicKey = runtimeKeyPair.publicKey.export({ format: 'der', type: 'spki' });
      const runtimeCrypto = createLocalIdentityRuntimeCryptoAdapter({
        activePrivateKeyPkcs8Der: runtimePrivateKey,
        activePublicKeySpkiDer: runtimePublicKey,
        trustedPublicKeysSpkiDer: [runtimePublicKey],
      });

      try {
        const admin = await adminPool.connect();
        try {
          await admin.query('begin');
          const actions = await admin.query<{ action_intent_id: string }>(
            `insert into control.action_intent
              (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
               step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
             values
              ($1,'principal','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION'),
              ('ACT-IDENTITY_CREATE_SESSION-V1','session','CREATE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','SESSION_MUTATION'),
              ('ACT-IDENTITY_DELETE_SESSION-V1','session','DELETE','STANDARD',false,false,true,'AUTHORIZED_ONLY','REDACTED','SESSION_MUTATION'),
              ('ACT-IDENTITY_UPDATE_STEP_UP-V1','mfa-evidence','UPDATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','MFA_MUTATION')
             on conflict do nothing returning action_intent_id`,
            [actionIntentId],
          );
          createdActionIds.push(...actions.rows.map((row) => row.action_intent_id));
          await admin.query(
            `insert into control.participant
              (participant_id,display_name,state,authority_epoch,root_privacy_domain_id)
             values ($1,'I02 atomic mutation fixture','ACTIVE',7,$2)`,
            [participantId, privacyDomainId],
          );
          await admin.query(
            `insert into control.privacy_domain
              (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
             values ($1,$2,'I02 private','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE')`,
            [privacyDomainId, participantId],
          );
          await admin.query(
            `insert into control.principal
              (principal_id,participant_id,kind,display_label,state,authority_epoch)
             values ($1,$3,'USER','I02 maker','ACTIVE',11),($2,$3,'USER','I02 checker','ACTIVE',13)`,
            [makerId, checkerId, participantId],
          );
          await admin.query(
            `insert into control.credential
              (credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,
               state,credential_epoch,valid_from,valid_until)
             values
              ($1,$3,$4,'WEBAUTHN',$6,$7,'ACTIVE',3,
               clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour'),
              ($2,$3,$5,'WEBAUTHN',$6,$7,'ACTIVE',5,
               clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour')`,
            [
              checkerCredentialId,
              makerCredentialId,
              participantId,
              checkerId,
              makerId,
              sha256(signerSpki),
              signerSpki,
            ],
          );
          await admin.query(
            `insert into control.authority_envelope
              (authority_envelope_id,participant_id,principal_id,maker_principal_id,
               checker_principal_id,authority_epoch,delegation_epoch,state,valid_from,valid_until,
               semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,
               resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
             values
              ($1,$3,$4,$4,$5,17,9,'ACTIVE',clock_timestamp()-interval '1 hour',null,
               $6,$7,$8,array[$9::text],array[$10::text,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1'],array['*'],array['HIGH'],true,true,0),
              ($2,$3,$5,$4,$5,19,9,'ACTIVE',clock_timestamp()-interval '1 hour',null,
               $6,$11,$8,array[$9::text],array[$10::text,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1'],array['*'],array['HIGH'],true,true,0)`,
            [
              makerEnvelopeId,
              checkerEnvelopeId,
              participantId,
              makerId,
              checkerId,
              evidenceCbor,
              sha256('i02-maker-envelope'),
              coseSign1,
              privacyDomainId,
              actionIntentId,
              sha256('i02-checker-envelope'),
            ],
          );
          await admin.query(
            `insert into control.assignment
              (assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
               scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
               maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state,
               created_by_principal_id)
             values
              ($1,$3,$4,$6,9,$8,array[$9::text],array[$10::text,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1'],array['*'],array['HIGH'],
               true,true,0,tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),'ACTIVE',$5),
              ($2,$3,$5,$7,9,$11,array[$9::text],array[$10::text,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ACT-POLICY_APPROVE_REQUEST-V1','ACT-IDENTITY_CREATE_SESSION-V1','ACT-IDENTITY_DELETE_SESSION-V1','ACT-IDENTITY_UPDATE_STEP_UP-V1'],array['*'],array['HIGH'],
               true,true,0,tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),'ACTIVE',$4)`,
            [
              makerAssignmentId,
              checkerAssignmentId,
              participantId,
              makerId,
              checkerId,
              makerEnvelopeId,
              checkerEnvelopeId,
              sha256('i02-maker-assignment'),
              privacyDomainId,
              actionIntentId,
              sha256('i02-checker-assignment'),
            ],
          );
          const issuedAt = new Date(Date.now() - 60_000);
          const makerAuthority = {
            principalId: makerId,
            sessionId,
            sessionEpoch: '1',
            participantEpoch: '7',
            principalEpoch: '11',
            assignmentId: makerAssignmentId,
            assignmentRowVersion: '1',
            authorityEnvelopeId: makerEnvelopeId,
            authorityEpoch: '17',
            delegationEpoch: '9',
            privacyDomainId,
            actionIntentId,
            resourceId: targetId,
          };
          const registrationMakerAuthority = {
            ...makerAuthority,
            actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            resourceId: sessionId,
          };
          await admin.query(
            `insert into control.session
              (session_id,participant_id,principal_id,context_mode,privacy_domain_id,
               opaque_token_digest,state,authority_epoch,
               delegation_epoch,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,
               step_up_verified_at,client_fingerprint_digest,participant_epoch,session_epoch,
               refresh_family_id,refresh_token_digest,refresh_used,csrf_secret)
             values ($1,$2,$3,'PARTICIPANT',$4,$5,'ACTIVE',11,9,$6,$6,$7,$8,$6,$9,7,1,
               $10,$11,false,$12)`,
            [
              sessionId,
              participantId,
              makerId,
              privacyDomainId,
              sha256(`${participantId}.${sessionId}`),
              issuedAt,
              new Date(issuedAt.getTime() + 30 * 60_000),
              new Date(issuedAt.getTime() + 12 * 60 * 60_000),
              sha256('i02-client-fingerprint'),
              '018f0000-0000-7000-8000-000000000109',
              sha256('i02-refresh-token'),
              sha256('i02-csrf-secret'),
            ],
          );
          await admin.query(
            `insert into control.session
              (session_id,participant_id,principal_id,context_mode,privacy_domain_id,
               opaque_token_digest,state,authority_epoch,delegation_epoch,issued_at,last_seen_at,
               idle_expires_at,absolute_expires_at,step_up_verified_at,client_fingerprint_digest,
               participant_epoch,session_epoch,refresh_family_id,refresh_token_digest,refresh_used,
               csrf_secret)
             values ($1,$2,$3,'PARTICIPANT',$4,$5,'ACTIVE',13,9,$6,$6,$7,$8,$6,$9,7,1,
               $10,$11,false,$12)`,
            [
              checkerSessionId,
              participantId,
              checkerId,
              privacyDomainId,
              sha256(`${participantId}.${checkerSessionId}`),
              issuedAt,
              new Date(issuedAt.getTime() + 30 * 60_000),
              new Date(issuedAt.getTime() + 12 * 60 * 60_000),
              sha256('i02-checker-client-fingerprint'),
              '018f0000-0000-7001-8000-000000000126',
              sha256('i02-checker-refresh-token'),
              sha256('i02-checker-csrf-secret'),
            ],
          );
          await admin.query(
            `insert into control.mutation_candidate
              (mutation_candidate_id,participant_id,privacy_domain_id,action_intent_id,
               catalog_operation_id,resource_type,operation_class,resource_id,candidate_digest,
               candidate_document,expected_revision,idempotency_key,maker_principal_id,
               maker_session_id,maker_session_epoch,maker_participant_epoch,maker_principal_epoch,
               maker_assignment_id,maker_assignment_row_version,maker_authority_envelope_id,
               maker_authority_epoch,maker_delegation_epoch,state,expires_at)
             values
              ($1,$3,$4,$5,'ID-OP-PRINCIPAL-PROVISION','principal','CREATE',$6,$7,$8,0,
               'i02-atomic-mutation-1',$9,$10,1,7,11,$11,1,$12,17,9,'PROPOSED',
               clock_timestamp()+interval '10 minutes'),
              ($2,$3,$4,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','ID-OP-WEBAUTHN-REGISTER',
               'participant','UPDATE',$10,$13,$14,1,'i02-webauthn-registration-1',$9,$10,1,7,11,
               $11,1,$12,17,9,'PROPOSED',clock_timestamp()+interval '10 minutes')`,
            [
              provisionCandidateId,
              registrationCandidateId,
              participantId,
              privacyDomainId,
              actionIntentId,
              targetId,
              candidateDigest,
              principal,
              makerId,
              sessionId,
              makerAssignmentId,
              makerEnvelopeId,
              registrationCandidateDigest,
              registrationRequest,
            ],
          );
          await admin.query(
            `update control.mutation_candidate set state='APPROVAL_REQUESTED',
               updated_at=clock_timestamp()
             where participant_id=$1 and mutation_candidate_id=any($2::uuid[])`,
            [participantId, [provisionCandidateId, registrationCandidateId]],
          );
          await admin.query(
            `insert into control.approval_request
              (approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
               subject_id,subject_digest,subject_version,maker_principal_id,maker_authority,
               required_approvals,state,expires_at)
             values ($1,$2,$3,$4,'CONFIGURATION_CANDIDATE',$5,$6,0,$7,$8,1,'APPROVED',
               clock_timestamp()+interval '10 minutes')`,
            [
              approvalId,
              participantId,
              privacyDomainId,
              actionIntentId,
              provisionCandidateId,
              candidateDigest,
              makerId,
              makerAuthority,
            ],
          );
          await admin.query(
            `update control.mutation_candidate set state='APPROVED',updated_at=clock_timestamp()
              where participant_id=$1 and mutation_candidate_id=$2`,
            [participantId, provisionCandidateId],
          );
          await admin.query(
            `insert into control.approval_decision_record
              (participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
               approver_session_id,approver_session_epoch,approver_participant_epoch,
               approver_principal_epoch,approver_authority_envelope_id,approver_envelope_epoch,
               approver_assignment_id,approver_assignment_row_version,approver_delegation_epoch,
               signer_credential_id,signer_credential_epoch,aggregate_version,candidate_digest,
               decision,decision_digest,evidence_cbor,cose_sign1)
             values ($1,$2,$3,$4,$5,1,7,13,$6,19,$7,1,9,$8,3,0,$9,'APPROVE',$10,$11,$12)`,
            [
              participantId,
              privacyDomainId,
              approvalId,
              checkerId,
              checkerSessionId,
              checkerEnvelopeId,
              checkerAssignmentId,
              checkerCredentialId,
              candidateDigest,
              sha256('i02-approval'),
              evidenceCbor,
              coseSign1,
            ],
          );
          await admin.query(
            `insert into control.approval_request
              (approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
               subject_id,subject_digest,subject_version,maker_principal_id,maker_authority,
               required_approvals,state,expires_at)
             values ($1,$2,$3,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1','CONFIGURATION_CANDIDATE',
               $4,$5,1,$6,$7,1,'APPROVED',clock_timestamp()+interval '10 minutes')`,
            [
              registrationApprovalId,
              participantId,
              privacyDomainId,
              registrationCandidateId,
              registrationCandidateDigest,
              makerId,
              registrationMakerAuthority,
            ],
          );
          await admin.query(
            `update control.mutation_candidate set state='APPROVED',updated_at=clock_timestamp()
              where participant_id=$1 and mutation_candidate_id=$2`,
            [participantId, registrationCandidateId],
          );
          await admin.query(
            `insert into control.approval_decision_record
              (participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
               approver_session_id,approver_session_epoch,approver_participant_epoch,
               approver_principal_epoch,approver_authority_envelope_id,approver_envelope_epoch,
               approver_assignment_id,approver_assignment_row_version,approver_delegation_epoch,
               signer_credential_id,signer_credential_epoch,aggregate_version,candidate_digest,
               decision,decision_digest,evidence_cbor,cose_sign1)
             values ($1,$2,$3,$4,$5,1,7,13,$6,19,$7,1,9,$8,3,1,$9,'APPROVE',$10,$11,$12)`,
            [
              participantId,
              privacyDomainId,
              registrationApprovalId,
              checkerId,
              checkerSessionId,
              checkerEnvelopeId,
              checkerAssignmentId,
              checkerCredentialId,
              registrationCandidateDigest,
              sha256('i02-registration-approval'),
              registrationEvidenceCbor,
              registrationEvidence.coseSign1,
            ],
          );
          await admin.query(
            `insert into control.mfa_challenge
              (mfa_challenge_id,participant_id,session_id,principal_id,action_intent_id,
               resource_digest,challenge_digest,rp_id_hash,expires_at,consumed_at)
             values ($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+interval '5 minutes',clock_timestamp())`,
            [
              mfaId,
              participantId,
              sessionId,
              makerId,
              actionIntentId,
              candidateDigest,
              sha256('i02-webauthn-challenge'),
              sha256('i02-rp-id'),
            ],
          );
          await admin.query(
            `insert into control.mfa_challenge
             (mfa_challenge_id,participant_id,session_id,principal_id,action_intent_id,
               resource_digest,challenge_digest,rp_id_hash,expires_at,consumed_at)
             values ($1,$2,$3,$4,'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',$5,$6,$7,
               clock_timestamp()+interval '5 minutes',clock_timestamp())`,
            [
              registrationMfaId,
              participantId,
              sessionId,
              makerId,
              registrationCandidateDigest,
              sha256('i02-registration-step-up'),
              sha256('openpc.example'),
            ],
          );
          await admin.query(
            `insert into control.idempotency_record
              (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,
               idempotency_key,operation_id,input_digest,webauthn_assertion_binding_digest,
               expected_aggregate_version,result_aggregate_version,result_digest,result_payload,
               terminal_state,expires_at)
             values
              ($1,$2,$3,'ACT-IDENTITY_UPDATE_STEP_UP-V1','ID-OP-WEBAUTHN-VERIFY',
               'i02-provision-step-up-verification',$4,$5,$6,1,1,$7,'{}','COMMITTED',
               clock_timestamp()+interval '10 minutes'),
              ($1,$2,$3,'ACT-IDENTITY_UPDATE_STEP_UP-V1','ID-OP-WEBAUTHN-VERIFY',
               'i02-registration-step-up-verification',$8,$9,$10,1,1,$11,'{}','COMMITTED',
               clock_timestamp()+interval '10 minutes')`,
            [
              participantId,
              privacyDomainId,
              makerId,
              provisionVerificationOperationId,
              provisionVerificationCandidateDigest,
              provisionStepUpBinding,
              sha256('i02-provision-step-up-result'),
              registrationVerificationOperationId,
              registrationVerificationCandidateDigest,
              registrationStepUpBinding,
              sha256('i02-registration-step-up-result'),
            ],
          );
          await admin.query(
            `insert into control.mutation_evidence
              (participant_id,privacy_domain_id,operation_id,principal_id,action_intent_id,
               catalog_operation_id,aggregate_type,aggregate_id,aggregate_version,candidate_digest,
               mfa_challenge_id,bound_participant_epoch,bound_principal_epoch,
               bound_authority_envelope_id,bound_envelope_epoch,bound_assignment_id,
               signer_credential_id,webauthn_assertion_binding_digest,evidence_cbor,
               evidence_digest,cose_sign1)
             values
              ($1,$2,$3,$4,'ACT-IDENTITY_UPDATE_STEP_UP-V1','ID-OP-WEBAUTHN-VERIFY',
               'webauthn-verification',$5,1,$6,$7,7,11,$8,17,$9,$10,$11,$12,$13,$14),
              ($1,$2,$15,$4,'ACT-IDENTITY_UPDATE_STEP_UP-V1','ID-OP-WEBAUTHN-VERIFY',
               'webauthn-verification',$5,1,$16,$17,7,11,$8,17,$9,$10,$18,$19,$20,$21)`,
            [
              participantId,
              privacyDomainId,
              provisionVerificationOperationId,
              makerId,
              sessionId,
              provisionVerificationCandidateDigest,
              mfaId,
              makerEnvelopeId,
              makerAssignmentId,
              makerCredentialId,
              provisionStepUpBinding,
              provisionStepUpEvidenceCbor,
              provisionStepUpEvidence.digest,
              provisionStepUpEvidence.coseSign1,
              registrationVerificationOperationId,
              registrationVerificationCandidateDigest,
              registrationMfaId,
              registrationStepUpBinding,
              registrationStepUpEvidenceCbor,
              registrationStepUpEvidence.digest,
              registrationStepUpEvidence.coseSign1,
            ],
          );
          await admin.query(
            `insert into control.outbox_aggregate_head
              (participant_id,aggregate_type,aggregate_id,last_sequence)
             values ($1,'webauthn-verification',$2,2)`,
            [participantId, sessionId],
          );
          await admin.query(
            `insert into control.outbox_event
              (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
               aggregate_sequence,payload_cbor,payload_digest,cose_sign1,
               webauthn_assertion_binding_digest,occurred_at)
             values
              ($1,$2,$3,'openpc.identity.webauthn-verification.mutation.committed.v1',
               'webauthn-verification',$5,1,$6,$7,$8,$9,clock_timestamp()),
              ($1,$2,$4,'openpc.identity.webauthn-verification.mutation.committed.v1',
               'webauthn-verification',$5,2,$10,$11,$12,$13,clock_timestamp())`,
            [
              participantId,
              privacyDomainId,
              provisionVerificationEventId,
              registrationVerificationEventId,
              sessionId,
              provisionStepUpEvidenceCbor,
              provisionStepUpEvidence.digest,
              provisionStepUpEvidence.coseSign1,
              provisionStepUpBinding,
              registrationStepUpEvidenceCbor,
              registrationStepUpEvidence.digest,
              registrationStepUpEvidence.coseSign1,
              registrationStepUpBinding,
            ],
          );
          await admin.query('commit');
        } catch (error) {
          await admin.query('rollback');
          throw error;
        } finally {
          admin.release();
        }

        const repository = new PostgresIdentityRepository(runtimePool, systemClock, runtimeCrypto);
        const scoped = await runtimePool.connect();
        try {
          await scoped.query('begin');
          await scoped.query(
            `select openpc.set_request_context('PARTICIPANT',$1,$2,
              '018f0000-0000-7000-8000-000000000110',$3,true)`,
            [participantId, privacyDomainId, actionIntentId],
          );
          const visible = await scoped.query<{
            inherited: boolean;
            matches: boolean;
            participant: string;
            sessions: number;
          }>(
            `select (select count(*)::int from control.session where session_id=$1) sessions,
                    pg_has_role(current_user,'openpc_control_runtime','MEMBER') inherited,
                    openpc.current_participant_id()::text participant,
                    openpc.matches_participant($2::uuid) matches`,
            [sessionId, participantId],
          );
          expect(visible.rows).toEqual([
            { inherited: true, matches: true, participant: participantId, sessions: 1 },
          ]);
          await scoped.query('rollback');
        } finally {
          scoped.release();
        }
        const actor = {
          principalId: makerId,
          participantId,
          sessionToken: `${participantId}.${sessionId}`,
          platform: false,
          mutationAuthorization: {
            authorized: true as const,
            evidenceKind: 'USER_WEBAUTHN' as const,
            idempotencyKey: 'i02-atomic-mutation-1',
            candidateDigest: `sha256:${candidateDigest.toString('hex')}`,
            privacyDomainId,
            approvalRequestId: approvalId,
            checkerPrincipalId: checkerId,
            aggregateVersion: '0',
            signerCredentialId: checkerCredentialId,
            mfaChallengeId: mfaId,
            webauthnSessionId: sessionId,
            webauthnSignerCredentialId: makerCredentialId,
            webauthnAssertionBindingDigest: provisionStepUpBinding,
            webauthnEvidenceCbor: provisionStepUpEvidenceCbor,
            webauthnEvidenceDigest: provisionStepUpEvidence.digest,
            webauthnCoseSign1: provisionStepUpEvidence.coseSign1,
            evidenceCbor,
            evidenceDigest,
            coseSign1,
          },
        };
        await adminPool.query(
          `update control.principal set authority_epoch=14 where participant_id=$1 and principal_id=$2`,
          [participantId, checkerId],
        );
        await expect(repository.provisionPrincipal(actor, principal)).rejects.toMatchObject({
          code: 'PC-IDENTITY-1001',
        });
        await adminPool.query(
          `update control.principal set authority_epoch=13 where participant_id=$1 and principal_id=$2`,
          [participantId, checkerId],
        );
        const alteredCose = Buffer.from(coseSign1);
        alteredCose[alteredCose.length - 1] = alteredCose[alteredCose.length - 1]! ^ 1;
        await expect(
          repository.provisionPrincipal(
            {
              ...actor,
              mutationAuthorization: { ...actor.mutationAuthorization, coseSign1: alteredCose },
            },
            principal,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' });
        const committed = await repository.provisionPrincipal(actor, principal);
        expect(committed).toEqual(principal);
        expect(await repository.provisionPrincipal(actor, principal)).toEqual(principal);

        const registration = await repository.issueStepUpChallenge(
          {
            ...actor,
            mutationAuthorization: {
              authorized: true,
              evidenceKind: 'USER_WEBAUTHN',
              idempotencyKey: 'i02-webauthn-registration-1',
              candidateDigest: `sha256:${registrationCandidateDigest.toString('hex')}`,
              privacyDomainId,
              approvalRequestId: registrationApprovalId,
              checkerPrincipalId: checkerId,
              aggregateVersion: '1',
              signerCredentialId: checkerCredentialId,
              mfaChallengeId: registrationMfaId,
              webauthnSessionId: sessionId,
              webauthnSignerCredentialId: makerCredentialId,
              webauthnAssertionBindingDigest: registrationStepUpBinding,
              webauthnEvidenceCbor: registrationStepUpEvidenceCbor,
              webauthnEvidenceDigest: registrationStepUpEvidence.digest,
              webauthnCoseSign1: registrationStepUpEvidence.coseSign1,
              evidenceCbor: registrationEvidenceCbor,
              evidenceDigest: registrationEvidence.digest,
              coseSign1: registrationEvidence.coseSign1,
            },
          },
          registrationRequest.actionIntentId,
          registrationRequest.resourceDigest,
          registrationRequest.rpIdHash,
        );
        expect(registration.challenge).toHaveLength(43);

        const kernel = new IdentityKernel(repository);
        const identityApp = buildIdentityService(
          kernel,
          undefined,
          undefined,
          createLocalIdentityAuthorizationAdapter(
            runtimePool,
            kernel,
            privacyDomainId,
            runtimeCrypto,
          ),
        );
        const callSessionMutation = async (input: {
          readonly actionIntentId: string;
          readonly catalogOperation: 'refresh' | 'logout';
          readonly idempotencyKey: string;
          readonly reason: string;
          readonly requestId: string;
          readonly sessionToken: string;
          readonly actionIntentDigest?: string;
          readonly csrfToken?: string;
          readonly expectedRevision?: string;
          readonly privacyDomainId?: string;
        }) => {
          const targetSessionId = input.sessionToken.split('.')[1]!;
          const revision =
            input.expectedRevision ??
            (
              await adminPool.query<{ revision: string }>(
                `select row_version::text revision from control.session
                  where participant_id=$1 and session_id=$2`,
                [participantId, targetSessionId],
              )
            ).rows[0]!.revision;
          const actionIntentDigest =
            input.actionIntentDigest ??
            (await repository.actionIntentSemanticDigest(input.sessionToken, input.actionIntentId));
          const candidate =
            input.catalogOperation === 'refresh'
              ? { sessionId: targetSessionId, operation: 'REFRESH', reason: input.reason }
              : { sessionId: targetSessionId, reason: input.reason };
          const csrf =
            input.csrfToken ??
            (await repository.csrfToken(
              input.sessionToken,
              input.actionIntentId,
              'https://control.openpc.example',
              'control.openpc.example',
            ));
          return identityApp.inject({
            method: 'POST',
            url: `/api/v1/session/${input.catalogOperation}`,
            headers: {
              'cookie': `__Host-openpc_session=${input.sessionToken}`,
              'origin': 'https://control.openpc.example',
              'host': 'control.openpc.example',
              'x-csrf-token': csrf,
              'x-request-id': input.requestId,
              'x-correlation-id': '018f0000-0000-7000-8000-00000000012f',
              'openpc-api-version': '1',
              'openpc-participant-id': `urn:openpc:participant:${participantId}`,
              'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${input.privacyDomainId ?? privacyDomainId}`,
              'openpc-action-intent-digest': actionIntentDigest,
              'if-match': `"${canonicalAuthorizationDigest({
                resourceType: 'session',
                revision,
                sessionId: targetSessionId,
              })}"`,
              'idempotency-key': input.idempotencyKey,
            },
            payload: {
              targetRef: `urn:openpc:resource:${targetSessionId}`,
              actionIntentId: input.actionIntentId,
              actionIntentDigest,
              inputDigest: canonicalAuthorizationDigest(candidate),
              expectedRevision: revision,
              reason: input.reason,
            },
          });
        };
        const originalSessionToken = `${participantId}.${sessionId}`;
        const originalRevision = (
          await adminPool.query<{ revision: string }>(
            `select row_version::text revision from control.session
              where participant_id=$1 and session_id=$2`,
            [participantId, sessionId],
          )
        ).rows[0]!.revision;
        const sessionCreateDigest = await repository.actionIntentSemanticDigest(
          originalSessionToken,
          'ACT-IDENTITY_CREATE_SESSION-V1',
        );
        const refreshCsrf = await repository.csrfToken(
          originalSessionToken,
          'ACT-IDENTITY_CREATE_SESSION-V1',
          'https://control.openpc.example',
          'control.openpc.example',
        );
        const refreshedResponse = await callSessionMutation({
          actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
          catalogOperation: 'refresh',
          idempotencyKey: 'i02-session-refresh-1',
          reason: 'integration-refresh',
          requestId: '018f0000-0000-7000-8000-00000000012d',
          sessionToken: originalSessionToken,
          actionIntentDigest: sessionCreateDigest,
          csrfToken: refreshCsrf,
          expectedRevision: originalRevision,
        });
        expect(refreshedResponse.statusCode, refreshedResponse.body).toBe(202);
        expect(refreshedResponse.body).not.toContain(participantId);
        const refreshedSessionToken = /__Host-openpc_session=([^;]+)/u.exec(
          String(refreshedResponse.headers['set-cookie']),
        )?.[1];
        expect(refreshedSessionToken).toMatch(new RegExp(`^${participantId}\\.`));
        await expect(repository.sessionSnapshot(originalSessionToken)).rejects.toMatchObject({
          code: 'PC-AUTH-0003',
        });
        const replayedRefresh = await callSessionMutation({
          actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
          catalogOperation: 'refresh',
          idempotencyKey: 'i02-session-refresh-1',
          reason: 'integration-refresh',
          requestId: '018f0000-0000-7000-8000-00000000012c',
          sessionToken: originalSessionToken,
          actionIntentDigest: sessionCreateDigest,
          csrfToken: refreshCsrf,
          expectedRevision: originalRevision,
        });
        expect(replayedRefresh.statusCode, replayedRefresh.body).toBe(202);
        expect(replayedRefresh.body).toBe(refreshedResponse.body);
        expect(replayedRefresh.headers['set-cookie']).toBe(refreshedResponse.headers['set-cookie']);
        const refreshEvidence = await adminPool.query<{ count: number }>(
          `select count(*)::int count from control.mutation_evidence
            where participant_id=$1 and principal_id=$2
              and catalog_operation_id='ID-OP-SESSION-REFRESH'`,
          [participantId, makerId],
        );
        expect(refreshEvidence.rows).toEqual([{ count: 1 }]);
        const wrongPrivacyReplay = await callSessionMutation({
          actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
          catalogOperation: 'refresh',
          idempotencyKey: 'i02-session-refresh-1',
          reason: 'integration-refresh',
          requestId: '018f0000-0000-7000-8000-00000000012a',
          sessionToken: originalSessionToken,
          actionIntentDigest: sessionCreateDigest,
          csrfToken: refreshCsrf,
          expectedRevision: originalRevision,
          privacyDomainId: '018f0000-0000-7000-8000-000000000999',
        });
        expect(wrongPrivacyReplay.statusCode).toBe(401);
        const mismatchedReplay = await callSessionMutation({
          actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
          catalogOperation: 'refresh',
          idempotencyKey: 'i02-session-refresh-other',
          reason: 'integration-refresh',
          requestId: '018f0000-0000-7000-8000-00000000012b',
          sessionToken: originalSessionToken,
          actionIntentDigest: sessionCreateDigest,
          csrfToken: refreshCsrf,
          expectedRevision: originalRevision,
        });
        expect(mismatchedReplay.statusCode).toBe(401);
        await adminPool.query(
          `update control.session set revoked_at=clock_timestamp()-interval '2 minutes'
            where participant_id=$1 and session_id=$2`,
          [participantId, sessionId],
        );
        const expiredReplay = await callSessionMutation({
          actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
          catalogOperation: 'refresh',
          idempotencyKey: 'i02-session-refresh-1',
          reason: 'integration-refresh',
          requestId: '018f0000-0000-7000-8000-00000000012a',
          sessionToken: originalSessionToken,
          actionIntentDigest: sessionCreateDigest,
          csrfToken: refreshCsrf,
          expectedRevision: originalRevision,
        });
        expect(expiredReplay.statusCode, expiredReplay.body).toBe(202);
        expect(expiredReplay.body).toBe(refreshedResponse.body);
        expect(expiredReplay.headers['set-cookie']).toBeUndefined();

        const refreshedSessionId = refreshedSessionToken!.split('.')[1]!;
        const logoutRevision = (
          await adminPool.query<{ revision: string }>(
            `select row_version::text revision from control.session
              where participant_id=$1 and session_id=$2`,
            [participantId, refreshedSessionId],
          )
        ).rows[0]!.revision;
        const sessionDeleteDigest = await repository.actionIntentSemanticDigest(
          refreshedSessionToken!,
          'ACT-IDENTITY_DELETE_SESSION-V1',
        );
        const logoutCsrf = await repository.csrfToken(
          refreshedSessionToken!,
          'ACT-IDENTITY_DELETE_SESSION-V1',
          'https://control.openpc.example',
          'control.openpc.example',
        );
        const revokedResponse = await callSessionMutation({
          actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
          catalogOperation: 'logout',
          idempotencyKey: 'i02-session-revoke-1',
          reason: 'explicit-revoke',
          requestId: '018f0000-0000-7000-8000-00000000012e',
          sessionToken: refreshedSessionToken!,
          actionIntentDigest: sessionDeleteDigest,
          csrfToken: logoutCsrf,
          expectedRevision: logoutRevision,
        });
        expect(revokedResponse.statusCode, revokedResponse.body).toBe(202);
        expect(revokedResponse.headers['set-cookie']).toContain('Max-Age=0');
        const replayedLogout = await callSessionMutation({
          actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
          catalogOperation: 'logout',
          idempotencyKey: 'i02-session-revoke-1',
          reason: 'explicit-revoke',
          requestId: '018f0000-0000-7000-8000-000000000129',
          sessionToken: refreshedSessionToken!,
          actionIntentDigest: sessionDeleteDigest,
          csrfToken: logoutCsrf,
          expectedRevision: logoutRevision,
        });
        expect(replayedLogout.statusCode, replayedLogout.body).toBe(202);
        expect(replayedLogout.body).toBe(revokedResponse.body);
        expect(replayedLogout.headers['set-cookie']).toContain('Max-Age=0');
        await identityApp.close();

        const atomic = await adminPool.query<{
          evidence: number;
          idempotency: number;
          mfaUses: number;
          outbox: number;
          principals: number;
          runtimeSessionEvidence: number;
          sessionOutbox: number;
          webauthnEvidence: number;
          webauthnOutbox: number;
        }>(
          `select
             (select count(*)::int from control.principal where principal_id=$1) principals,
             (select count(*)::int from control.mutation_evidence where aggregate_id=$1) evidence,
             (select count(*)::int from control.outbox_event where aggregate_id=$1) outbox,
             (select count(*)::int from control.mutation_evidence
               where participant_id=$2 and aggregate_type='session'
                 and signer_credential_id is null) "runtimeSessionEvidence",
             (select count(*)::int from control.outbox_event
               where participant_id=$2 and aggregate_type='session') "sessionOutbox",
             (select count(*)::int from control.mutation_evidence
               where participant_id=$2 and aggregate_type='webauthn-registration') "webauthnEvidence",
             (select count(*)::int from control.outbox_event
               where participant_id=$2 and aggregate_type='webauthn-registration') "webauthnOutbox",
             (select count(*)::int from control.idempotency_record
               where participant_id=$2 and idempotency_key='i02-atomic-mutation-1'
                 and terminal_state='COMMITTED') idempotency,
             (select count(*)::int from control.mfa_challenge
               where mfa_challenge_id=$3 and used_at is not null and used_operation_id is not null) "mfaUses"`,
          [targetId, participantId, mfaId],
        );
        expect(atomic.rows).toEqual([
          {
            evidence: 1,
            idempotency: 1,
            mfaUses: 1,
            outbox: 1,
            principals: 1,
            runtimeSessionEvidence: 2,
            sessionOutbox: 2,
            webauthnEvidence: 1,
            webauthnOutbox: 1,
          },
        ]);
        await expect(
          adminPool.query(
            `update control.approval_decision_record set decision='REJECT'
              where participant_id=$1 and approval_request_id=$2`,
            [participantId, approvalId],
          ),
        ).rejects.toThrow(/DATA-6020-IMMUTABLE-ROW/u);
        await expect(
          adminPool.query(
            `delete from control.mutation_evidence where participant_id=$1 and aggregate_id=$2`,
            [participantId, targetId],
          ),
        ).rejects.toThrow(/DATA-6020-IMMUTABLE-ROW/u);
      } finally {
        await runtimePool.end();
        await adminPool.query('begin');
        try {
          await adminPool.query(
            `alter table control.mutation_evidence disable trigger mutation_evidence_immutable`,
          );
          await adminPool.query(
            `alter table control.approval_decision_record disable trigger approval_decision_immutable`,
          );
          await adminPool.query(
            `alter table control.mutation_candidate disable trigger mutation_candidate_lifecycle`,
          );
          await adminPool.query(`delete from control.outbox_event where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.mutation_evidence where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(
            `delete from control.outbox_aggregate_head where participant_id=$1`,
            [participantId],
          );
          await adminPool.query(`delete from control.idempotency_record where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.mfa_challenge where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(
            `delete from control.approval_decision_record where participant_id=$1`,
            [participantId],
          );
          await adminPool.query(
            `alter table control.approval_decision_record enable trigger approval_decision_immutable`,
          );
          await adminPool.query(
            `alter table control.mutation_evidence enable trigger mutation_evidence_immutable`,
          );
          await adminPool.query(`delete from control.approval_request where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.mutation_candidate where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(
            `alter table control.mutation_candidate enable trigger mutation_candidate_lifecycle`,
          );
          await adminPool.query(`delete from control.session where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.assignment where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.authority_envelope where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.credential where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.principal where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.privacy_domain where participant_id=$1`, [
            participantId,
          ]);
          await adminPool.query(`delete from control.participant where participant_id=$1`, [
            participantId,
          ]);
          if (createdActionIds.length > 0) {
            await adminPool.query(
              `delete from control.action_intent where action_intent_id=any($1::text[])`,
              [createdActionIds],
            );
          }
          await adminPool.query('commit');
        } catch (error) {
          await adminPool.query('rollback');
          expect(error).toBeUndefined();
        } finally {
          await adminPool.end();
        }
      }
    },
  );
});
