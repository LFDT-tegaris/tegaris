import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';

import { Pool } from 'pg';
import { describe, expect, it } from 'vitest';

import {
  controlMutationForAction,
  encodeIdentityCredentialPayload,
} from '../../../packages/security-kernel/src/index.js';

import {
  type AuthenticatedIdentityActor,
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.js';
import {
  buildIdentityService,
  type IdentityAuthorizationAdapter,
} from '../../../services/identity-service/src/app.js';
import { canonicalAuthorizationDigest } from '../../../services/identity-service/src/contracts/authorization.js';
import { stepUpAuthorizationCandidate } from '../../../services/identity-service/src/domain/step-up-authorization.js';
import { authorizeLocalPolicyAction } from '../../../services/identity-service/src/domain/policy-authorization.js';
import {
  createVerifiedWebAuthnAssertion,
  type IdentityTrustAdapter,
  type VerifiedWebAuthnAssertion,
} from '../../../services/identity-service/src/domain/trust-adapter.js';
import type {
  Assignment,
  AuthorityEnvelope,
  Delegation,
} from '../../../services/participant-service/src/domain/authority-kernel.js';
import {
  type AuthenticatedActor,
  PostgresParticipantRepository,
} from '../../../services/participant-service/src/domain/participant-kernel.js';
import { participantReadbackRuntime } from './participant-readback-runtime.js';

const runtimeDatabaseUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const platformRuntimeDatabaseUrl = process.env.OPENPC_I02_PLATFORM_RUNTIME_DATABASE_URL;
const adminDatabaseUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const integration =
  runtimeDatabaseUrl === undefined ||
  platformRuntimeDatabaseUrl === undefined ||
  adminDatabaseUrl === undefined
    ? it.skip
    : it;

function stableJson(value: unknown): string {
  if (value === undefined || value === null || typeof value !== 'object') {
    return value === undefined ? 'null' : JSON.stringify(value);
  }
  if (value instanceof Date) return JSON.stringify(value.toISOString());
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

const signerSpki = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  'hex',
);
const signerPrivateKey = createPrivateKey({
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

function signedEvidence(payload: Buffer): { readonly coseSign1: Buffer; readonly digest: Buffer } {
  const protectedHeader = Buffer.from(
    'a5012603776170706c69636174696f6e2f6f70656e70632b63626f720458205cd252fb0ce8932436faf8ccd1040981b89ee4ad6b9fe9e2a2b7e71aacb27cd31903e91957e51903ea781d6f70656e70633a6964656e746974792d63726564656e7469616c3a7631',
    'hex',
  );
  const structure = Buffer.concat([
    Buffer.from([0x84, 0x6a]),
    Buffer.from('Signature1'),
    cborByteString(protectedHeader),
    Buffer.from([0x40]),
    cborByteString(payload),
  ]);
  const signature = sign('sha256', structure, {
    key: signerPrivateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return {
    coseSign1: Buffer.concat([
      Buffer.from([0xd2, 0x84]),
      cborByteString(protectedHeader),
      Buffer.from([0xa0]),
      cborByteString(payload),
      cborByteString(signature),
    ]),
    digest: sha256(payload),
  };
}

function signedWebAuthnAssertion(
  credentialId: string,
  challenge: string,
  origin: string,
  rpIdHash: Buffer,
  signCount: number,
  alterSignature = false,
): string {
  const clientDataJson = Buffer.from(
    JSON.stringify({ type: 'webauthn.get', challenge, origin }),
    'utf8',
  );
  const authenticatorData = Buffer.alloc(37);
  rpIdHash.copy(authenticatorData, 0);
  authenticatorData[32] = 0x05;
  authenticatorData.writeUInt32BE(signCount, 33);
  const signedBytes = Buffer.concat([authenticatorData, sha256(clientDataJson)]);
  const signature = sign('sha256', signedBytes, signerPrivateKey);
  if (alterSignature)
    signature.writeUInt8(signature.readUInt8(signature.length - 1) ^ 1, signature.length - 1);
  return JSON.stringify({
    credentialId,
    authenticatorData: authenticatorData.toString('base64url'),
    clientDataJson: clientDataJson.toString('base64url'),
    signature: signature.toString('base64url'),
  });
}

function cryptographicWebAuthnAdapter(
  expectedCredentialId: string,
  onVerified?: (assertion: VerifiedWebAuthnAssertion) => void,
): IdentityTrustAdapter {
  const verifiedAt = new Date().toISOString();
  return {
    async exchangeAuthorizationCode() {
      return undefined;
    },
    async verifyWebAuthnAssertion(input) {
      try {
        const encoded = JSON.parse(input.assertion) as Record<string, unknown>;
        if (
          encoded.credentialId !== expectedCredentialId ||
          typeof encoded.authenticatorData !== 'string' ||
          typeof encoded.clientDataJson !== 'string' ||
          typeof encoded.signature !== 'string'
        ) {
          return undefined;
        }
        const authenticatorData = Buffer.from(encoded.authenticatorData, 'base64url');
        const clientDataJson = Buffer.from(encoded.clientDataJson, 'base64url');
        const signature = Buffer.from(encoded.signature, 'base64url');
        const clientData = JSON.parse(clientDataJson.toString('utf8')) as Record<string, unknown>;
        const expectedRpIdHash = Buffer.from(input.rpIdHash.slice(7), 'hex');
        if (
          authenticatorData.length !== 37 ||
          !authenticatorData.subarray(0, 32).equals(expectedRpIdHash) ||
          (authenticatorData[32]! & 0x05) !== 0x05 ||
          clientData.type !== 'webauthn.get' ||
          clientData.challenge !== input.challenge ||
          clientData.origin !== input.allowedOrigin ||
          !verify(
            'sha256',
            Buffer.concat([authenticatorData, sha256(clientDataJson)]),
            createPublicKey({ key: signerSpki, format: 'der', type: 'spki' }),
            signature,
          )
        ) {
          return undefined;
        }
        const verifiedAssertion = createVerifiedWebAuthnAssertion({
          credentialId: expectedCredentialId,
          credentialPublicKeyDigest: `sha256:${sha256(signerSpki).toString('hex')}`,
          principalId: input.principalId,
          sessionId: input.sessionId,
          actionIntentId: input.actionIntentId,
          resourceDigest: input.resourceDigest,
          challengeDigest: `sha256:${sha256(input.challenge).toString('hex')}`,
          rpIdHash: input.rpIdHash,
          origin: input.allowedOrigin,
          authenticatorDataDigest: `sha256:${sha256(authenticatorData).toString('hex')}`,
          clientDataJsonDigest: `sha256:${sha256(clientDataJson).toString('hex')}`,
          signatureDigest: `sha256:${sha256(signature).toString('hex')}`,
          signCount: String(authenticatorData.readUInt32BE(33)),
          verifiedAt,
        });
        onVerified?.(verifiedAssertion);
        return verifiedAssertion;
      } catch {
        return undefined;
      }
    },
  };
}

describe('I02 catalog mutation PostgreSQL controls', () => {
  integration(
    'executes frozen high-risk operations and role lifecycle with atomic WebAuthn verification',
    async () => {
      const runtime = new Pool({ connectionString: platformRuntimeDatabaseUrl, max: 1 });
      const admin = new Pool({ connectionString: adminDatabaseUrl, max: 1 });
      let serial = 300;
      const id = () => `018f0000-0000-7000-8000-${String(serial++).padStart(12, '0')}`;
      const participantId = id();
      const privacyDomainId = id();
      const makerId = id();
      const checkerId = id();
      const subjectId = id();
      const suspendId = id();
      const workloadPrincipalId = id();
      const custodianOneId = id();
      const custodianTwoId = id();
      const recoveryPrincipalId = id();
      const granteeId = id();
      const makerCredentialId = id();
      const checkerCredentialId = id();
      const actors = [makerId, custodianOneId, custodianTwoId, recoveryPrincipalId] as const;
      const actorSessions = new Map<string, string>();
      const actorEnvelopes = new Map<string, string>();
      const actorAssignments = new Map<string, string>();
      const actorCredentials = new Map<string, string>([
        [makerId, makerCredentialId],
        [checkerId, checkerCredentialId],
      ]);
      for (const principalId of actors) {
        if (!actorCredentials.has(principalId)) actorCredentials.set(principalId, id());
      }
      const actorEpochs = new Map<string, string>([
        [makerId, '11'],
        [checkerId, '13'],
        [custodianOneId, '21'],
        [custodianTwoId, '22'],
        [recoveryPrincipalId, '23'],
      ]);
      const actorEnvelopeEpochs = new Map(actorEpochs);
      actorEnvelopeEpochs.set(makerId, '17');
      const createdParticipantId = id();
      const intents = [
        'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
        'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        'ACT-POLICY_APPROVE_REQUEST-V1',
      ];
      const highRisk = new Set([
        'ID-OP-PRINCIPAL-PROVISION',
        'ID-OP-PRINCIPAL-SUSPEND',
        'ID-OP-WEBAUTHN-REGISTER',
        'ID-OP-WORKLOAD-ISSUE',
        'ID-OP-WORKLOAD-ROTATE',
        'ID-OP-WORKLOAD-REVOKE',
        'ID-OP-RECOVERY-PRINCIPAL-QUALIFY',
        'ID-OP-RECOVERY-PRINCIPAL-REVOKE',
        'ID-OP-RECOVERY-POST-REVIEW',
        'ID-OP-RECOVERY-BEGIN',
        'ID-OP-RECOVERY-APPROVE',
        'ID-OP-RECOVERY-COMPLETE',
        // Public creation is owned by postgres-first-administrator.test.ts.
        'ID-OP-PARTICIPANT-ACTIVATE',
        'ID-OP-ENVELOPE-CREATE',
        'ID-OP-ENVELOPE-ACTIVATE',
        'ID-OP-ASSIGNMENT-CREATE',
        'ID-OP-ASSIGNMENT-REVOKE',
        'ID-OP-DELEGATION-ISSUE',
        'ID-OP-DELEGATION-REVOKE',
        'ID-OP-ROLE-CREATE',
        'ID-OP-ROLE-ARCHIVE',
      ]);
      const permission = {
        participantId,
        privacyDomainIds: [privacyDomainId],
        actionIntentIds: intents,
        resourceIds: ['*'],
        riskClasses: ['LOW', 'HIGH'],
        validFrom: new Date(Date.now() - 60 * 60_000),
        validUntil: new Date(Date.now() + 60 * 60_000),
        makerCheckerRequired: true,
        stepUpRequired: true,
        onwardDelegationDepth: 4,
      } as const;

      const identityActor = (principalId: string): AuthenticatedIdentityActor => ({
        principalId,
        participantId,
        sessionToken: `${participantId}.${actorSessions.get(principalId) ?? ''}`,
        platform: principalId === makerId,
      });
      const participantActor = (
        principalId: string,
        participantEpoch = '7',
      ): AuthenticatedActor => ({
        principalId,
        participantId,
        sessionId: actorSessions.get(principalId),
        boundParticipantEpoch: participantEpoch,
        boundPrincipalEpoch: actorEpochs.get(principalId) ?? '0',
        boundEnvelopeEpoch: principalId === makerId ? '17' : (actorEpochs.get(principalId) ?? '0'),
        platform: principalId === makerId,
      });

      const authorize = async <T extends AuthenticatedIdentityActor | AuthenticatedActor>(
        actor: T,
        operationId: string,
        actionIntentId: string,
        aggregateId: string,
        aggregateVersion: string,
        candidate: unknown,
        seedStepUp = true,
      ): Promise<T> => {
        const approvalRequestId = id();
        const mfaChallengeId = id();
        const candidateHash = sha256(stableJson(candidate));
        const evidenceCbor = canonicalEvidence(participantId, checkerId, String(serial++));
        const evidence = signedEvidence(evidenceCbor);
        const idempotencyKey = `i02-${operationId.toLowerCase()}-${approvalRequestId}`;
        const operation = controlMutationForAction(actionIntentId, operationId);
        const participantEpoch = (
          await admin.query<{ authority_epoch: string }>(
            `select authority_epoch::text from control.participant where participant_id=$1`,
            [participantId],
          )
        ).rows[0]?.authority_epoch;
        if (participantEpoch === undefined) throw new Error('missing fixture participant epoch');
        await admin.query(`update control.session set participant_epoch=$2 where session_id=$1`, [
          actorSessions.get(checkerId),
          participantEpoch,
        ]);
        const makerAuthority = {
          catalogOperationId: operationId,
          principalId: actor.principalId,
          sessionId: actorSessions.get(actor.principalId)!,
          sessionEpoch: '1',
          participantEpoch,
          principalEpoch: actorEpochs.get(actor.principalId)!,
          assignmentId: actorAssignments.get(actor.principalId)!,
          assignmentRowVersion: '1',
          authorityEnvelopeId: actorEnvelopes.get(actor.principalId)!,
          authorityEpoch: actorEnvelopeEpochs.get(actor.principalId)!,
          delegationEpoch: '0',
          privacyDomainId,
          actionIntentId,
          resourceId: aggregateId,
        };
        let mutationCandidateId = aggregateId;
        if (
          operation !== undefined &&
          operation.catalogOperationId === operationId &&
          operation.actionIntentId === actionIntentId
        ) {
          mutationCandidateId = id();
          await admin.query(
            `insert into control.mutation_candidate
              (mutation_candidate_id,participant_id,privacy_domain_id,action_intent_id,
               catalog_operation_id,resource_type,operation_class,resource_id,candidate_digest,
               candidate_document,expected_revision,idempotency_key,maker_principal_id,
               maker_session_id,maker_session_epoch,maker_participant_epoch,maker_principal_epoch,
               maker_assignment_id,maker_assignment_row_version,maker_authority_envelope_id,
               maker_authority_epoch,maker_delegation_epoch,state,expires_at)
             values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1,$15,$16,$17,1,$18,$19,0,
                     'PROPOSED',clock_timestamp()+interval '10 minutes')`,
            [
              mutationCandidateId,
              participantId,
              privacyDomainId,
              actionIntentId,
              operationId,
              operation.resourceType,
              operation.operationClass,
              aggregateId,
              candidateHash,
              candidate,
              aggregateVersion,
              idempotencyKey,
              actor.principalId,
              actorSessions.get(actor.principalId),
              participantEpoch,
              actorEpochs.get(actor.principalId),
              actorAssignments.get(actor.principalId),
              actorEnvelopes.get(actor.principalId),
              actorEnvelopeEpochs.get(actor.principalId),
            ],
          );
          await admin.query(
            `update control.mutation_candidate
                set state='APPROVAL_REQUESTED',updated_at=clock_timestamp()
              where participant_id=$1 and mutation_candidate_id=$2`,
            [participantId, mutationCandidateId],
          );
        }
        await admin.query(
          `insert into control.approval_request
          (approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
           subject_id,subject_digest,subject_version,maker_principal_id,maker_authority,
           required_approvals,state,expires_at)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,'APPROVED',clock_timestamp()+interval '10 minutes')`,
          [
            approvalRequestId,
            participantId,
            privacyDomainId,
            actionIntentId,
            operation?.catalogOperationId === operationId
              ? 'CONFIGURATION_CANDIDATE'
              : `${operationId}:${approvalRequestId}`,
            mutationCandidateId,
            candidateHash,
            aggregateVersion,
            actor.principalId,
            makerAuthority,
          ],
        );
        if (mutationCandidateId !== aggregateId) {
          await admin.query(
            `update control.mutation_candidate set state='APPROVED',updated_at=clock_timestamp()
              where participant_id=$1 and mutation_candidate_id=$2`,
            [participantId, mutationCandidateId],
          );
        }
        await admin.query(
          `insert into control.approval_decision_record
          (participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
           approver_session_id,approver_session_epoch,approver_participant_epoch,
           approver_principal_epoch,approver_authority_envelope_id,approver_envelope_epoch,
           approver_assignment_id,approver_assignment_row_version,approver_delegation_epoch,
           signer_credential_id,signer_credential_epoch,aggregate_version,candidate_digest,
           decision,decision_digest,evidence_cbor,cose_sign1)
         values ($1,$2,$3,$4,$5,1,$6,13,$7,19,$8,1,0,$9,1,$10,$11,'APPROVE',$12,$13,$14)`,
          [
            participantId,
            privacyDomainId,
            approvalRequestId,
            checkerId,
            actorSessions.get(checkerId),
            participantEpoch,
            actorEnvelopes.get(checkerId),
            actorAssignments.get(checkerId),
            checkerCredentialId,
            aggregateVersion,
            candidateHash,
            sha256(`${operationId}:${approvalRequestId}`),
            evidenceCbor,
            evidence.coseSign1,
          ],
        );
        let stepUp:
          | {
              readonly binding: Buffer;
              readonly challengeId: string;
              readonly evidenceCbor: Buffer;
              readonly evidenceDigest: Buffer;
              readonly coseSign1: Buffer;
              readonly signerCredentialId: string;
            }
          | undefined;
        if (seedStepUp) {
          const stepUpEvidenceCbor = canonicalEvidence(
            participantId,
            actor.principalId,
            String(serial++),
          );
          const stepUpEvidence = signedEvidence(stepUpEvidenceCbor);
          const binding = sha256(`assertion:${operationId}:${mfaChallengeId}`);
          const verificationOperationId = id();
          const verificationCandidateDigest = sha256(
            `verification:${operationId}:${mfaChallengeId}`,
          );
          const stepUpSignerCredentialId = actorCredentials.get(actor.principalId);
          if (stepUpSignerCredentialId === undefined) {
            throw new Error(`missing WebAuthn credential for ${actor.principalId}`);
          }
          await admin.query(
            `insert into control.mfa_challenge
            (mfa_challenge_id,participant_id,session_id,principal_id,action_intent_id,
             resource_digest,challenge_digest,rp_id_hash,expires_at,consumed_at)
           values ($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+interval '5 minutes',clock_timestamp())`,
            [
              mfaChallengeId,
              participantId,
              actorSessions.get(actor.principalId),
              actor.principalId,
              actionIntentId,
              candidateHash,
              sha256(`challenge:${operationId}:${mfaChallengeId}`),
              sha256('openpc.example'),
            ],
          );
          await admin.query(
            `insert into control.idempotency_record
              (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,
               idempotency_key,operation_id,input_digest,webauthn_assertion_binding_digest,
               expected_aggregate_version,result_aggregate_version,result_digest,result_payload,
               terminal_state,expires_at)
             values ($1,$2,$3,'ACT-IDENTITY_UPDATE_STEP_UP-V1','ID-OP-WEBAUTHN-VERIFY',
                     $4,$5,$6,$7,1,1,$8,'{}','COMMITTED',clock_timestamp()+interval '10 minutes')`,
            [
              participantId,
              privacyDomainId,
              actor.principalId,
              `i02-step-up-${verificationOperationId}`,
              verificationOperationId,
              verificationCandidateDigest,
              binding,
              sha256(`verification-result:${verificationOperationId}`),
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
             values ($1,$2,$3,$4,'ACT-IDENTITY_UPDATE_STEP_UP-V1','ID-OP-WEBAUTHN-VERIFY',
                     'webauthn-verification',$5,1,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
            [
              participantId,
              privacyDomainId,
              verificationOperationId,
              actor.principalId,
              actorSessions.get(actor.principalId),
              verificationCandidateDigest,
              mfaChallengeId,
              participantEpoch,
              actorEpochs.get(actor.principalId),
              actorEnvelopes.get(actor.principalId),
              actorEnvelopeEpochs.get(actor.principalId),
              actorAssignments.get(actor.principalId),
              stepUpSignerCredentialId,
              binding,
              stepUpEvidenceCbor,
              stepUpEvidence.digest,
              stepUpEvidence.coseSign1,
            ],
          );
          const sequence = (
            await admin.query<{ last_sequence: string }>(
              `insert into control.outbox_aggregate_head
                (participant_id,aggregate_type,aggregate_id,last_sequence)
               values ($1,'webauthn-verification',$2,1)
               on conflict (participant_id,aggregate_type,aggregate_id) do update
                 set last_sequence=control.outbox_aggregate_head.last_sequence+1,
                     updated_at=clock_timestamp()
               returning last_sequence::text`,
              [participantId, actorSessions.get(actor.principalId)],
            )
          ).rows[0]?.last_sequence;
          if (sequence === undefined) throw new Error('missing step-up outbox sequence');
          await admin.query(
            `insert into control.outbox_event
              (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
               aggregate_sequence,payload_cbor,payload_digest,cose_sign1,
               webauthn_assertion_binding_digest,occurred_at)
             values ($1,$2,$3,'openpc.identity.webauthn-verification.mutation.committed.v1',
                     'webauthn-verification',$4,$5,$6,$7,$8,$9,clock_timestamp())`,
            [
              participantId,
              privacyDomainId,
              id(),
              actorSessions.get(actor.principalId),
              sequence,
              stepUpEvidenceCbor,
              stepUpEvidence.digest,
              stepUpEvidence.coseSign1,
              binding,
            ],
          );
          stepUp = {
            binding,
            challengeId: mfaChallengeId,
            evidenceCbor: stepUpEvidenceCbor,
            evidenceDigest: stepUpEvidence.digest,
            coseSign1: stepUpEvidence.coseSign1,
            signerCredentialId: stepUpSignerCredentialId,
          };
        } else {
          const prior = (
            await admin.query<{
              binding: Buffer;
              challenge_id: string;
              cose_sign1: Buffer;
              evidence_cbor: Buffer;
              evidence_digest: Buffer;
              signer_credential_id: string;
            }>(
              `select challenge.mfa_challenge_id challenge_id,
                      evidence.webauthn_assertion_binding_digest binding,
                      evidence.signer_credential_id,evidence.evidence_cbor,
                      evidence.evidence_digest,evidence.cose_sign1
                 from control.mfa_challenge challenge
                 join control.mutation_evidence evidence
                   on evidence.participant_id=challenge.participant_id
                  and evidence.mfa_challenge_id=challenge.mfa_challenge_id
                  and evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
                where challenge.participant_id=$1 and challenge.session_id=$2
                  and challenge.principal_id=$3 and challenge.action_intent_id=$4
                  and challenge.resource_digest=$5 and challenge.consumed_at is not null
                order by challenge.consumed_at desc limit 1`,
              [
                participantId,
                actorSessions.get(actor.principalId),
                actor.principalId,
                actionIntentId,
                candidateHash,
              ],
            )
          ).rows[0];
          if (prior !== undefined) {
            stepUp = {
              binding: prior.binding,
              challengeId: prior.challenge_id,
              evidenceCbor: prior.evidence_cbor,
              evidenceDigest: prior.evidence_digest,
              coseSign1: prior.cose_sign1,
              signerCredentialId: prior.signer_credential_id,
            };
          }
        }
        return {
          ...actor,
          mutationAuthorization: {
            authorized: true,
            evidenceKind: 'USER_WEBAUTHN',
            catalogOperationId: operationId,
            actionIntentId,
            idempotencyKey,
            candidateDigest: `sha256:${candidateHash.toString('hex')}`,
            privacyDomainId,
            approvalRequestId,
            checkerPrincipalId: checkerId,
            aggregateVersion,
            signerCredentialId: checkerCredentialId,
            ...(stepUp === undefined
              ? {}
              : {
                  mfaChallengeId: stepUp.challengeId,
                  webauthnSessionId: actorSessions.get(actor.principalId),
                  webauthnSignerCredentialId: stepUp.signerCredentialId,
                  webauthnAssertionBindingDigest: stepUp.binding,
                  webauthnEvidenceCbor: stepUp.evidenceCbor,
                  webauthnEvidenceDigest: stepUp.evidenceDigest,
                  webauthnCoseSign1: stepUp.coseSign1,
                }),
            evidenceCbor,
            evidenceDigest: evidence.digest,
            coseSign1: evidence.coseSign1,
          },
        };
      };

      let operationError: unknown;
      try {
        for (const intent of intents) {
          const operation = controlMutationForAction(intent);
          await admin.query(
            `insert into control.action_intent
            (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
             step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
           values ($1,$2,$3,'HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','IDENTITY_MUTATION')
           on conflict do nothing returning action_intent_id`,
            [intent, operation?.resourceType ?? 'identity', operation?.operationClass ?? 'UPDATE'],
          );
        }
        await admin.query(
          `insert into control.participant
          (participant_id,display_name,state,authority_epoch,root_privacy_domain_id)
         values ($1,'I02 complete catalog fixture','ACTIVE',7,$2)`,
          [participantId, privacyDomainId],
        );
        await admin.query(
          `insert into control.privacy_domain
          (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
         values ($1,$2,'I02 catalog private','PARTICIPANT_LOCAL','LOCAL_TEST','ACTIVE')`,
          [privacyDomainId, participantId],
        );
        // Installation initial trust exercises the separate activation owner.
        // This does not stand in for the public first-administrator journey.
        await admin.query(
          `insert into control.participant(participant_id,display_name,state,authority_epoch)
           values($1,'Installation provisioning fixture','PROVISIONING',0)`,
          [createdParticipantId],
        );
        const principals = [
          [makerId, 'maker', '11', 'USER'],
          [checkerId, 'checker', '13', 'USER'],
          [subjectId, 'recovery subject', '31', 'USER'],
          [suspendId, 'suspend target', '32', 'USER'],
          [workloadPrincipalId, 'workload principal', '33', 'WORKLOAD'],
          [custodianOneId, 'custodian one', '21', 'USER'],
          [custodianTwoId, 'custodian two', '22', 'USER'],
          [recoveryPrincipalId, 'recovery principal', '23', 'USER'],
          [granteeId, 'delegation grantee', '34', 'USER'],
        ] as const;
        for (const [principalId, label, epoch, kind] of principals) {
          await admin.query(
            `insert into control.principal
            (principal_id,participant_id,kind,display_label,state,authority_epoch)
           values ($1,$2,$3,$4,'ACTIVE',$5)`,
            [principalId, participantId, kind, label, epoch],
          );
        }
        for (const [principalId, credentialId] of actorCredentials) {
          await admin.query(
            `insert into control.credential
            (credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,
             state,credential_epoch,valid_from,valid_until)
           values ($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1,
                   clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour')`,
            [credentialId, participantId, principalId, sha256(signerSpki), signerSpki],
          );
        }
        for (const principalId of [...actors, checkerId]) {
          const envelopeId = id();
          const assignmentId = id();
          const envelopeEpoch =
            principalId === makerId
              ? '17'
              : principalId === checkerId
                ? '19'
                : actorEpochs.get(principalId)!;
          actorEnvelopes.set(principalId, envelopeId);
          actorAssignments.set(principalId, assignmentId);
          await admin.query(
            `insert into control.authority_envelope
            (authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
             authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,
             privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,
             step_up_required,onward_delegation_depth)
           values ($1,$2,$3,$4,$5,$6,0,'ACTIVE',clock_timestamp()-interval '1 hour',$7,$8,$9,$10,$11,array['*'],array['LOW','HIGH'],true,true,4)`,
            [
              envelopeId,
              participantId,
              principalId,
              principalId === checkerId ? makerId : principalId,
              checkerId,
              envelopeEpoch,
              Buffer.from('catalog-envelope'),
              sha256(`envelope:${principalId}`),
              Buffer.alloc(0),
              [privacyDomainId],
              intents,
            ],
          );
          await admin.query(
            `insert into control.assignment
            (assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,
             scope_digest,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
             maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state,
             created_by_principal_id)
           values ($1,$2,$3,$4,0,$5,$6,$7,array['*'],array['LOW','HIGH'],true,true,4,
             tstzrange(clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour','[)'),
             'ACTIVE',$8)`,
            [
              assignmentId,
              participantId,
              principalId,
              envelopeId,
              sha256(`assignment:${principalId}`),
              [privacyDomainId],
              intents,
              makerId,
            ],
          );
        }
        for (const principalId of [...actors, checkerId]) {
          const sessionId = id();
          actorSessions.set(principalId, sessionId);
          const epoch = actorEpochs.get(principalId)!;
          await admin.query(
            `insert into control.session
            (session_id,participant_id,principal_id,context_mode,privacy_domain_id,
             opaque_token_digest,state,authority_epoch,
             delegation_epoch,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,
             step_up_verified_at,client_fingerprint_digest,participant_epoch,session_epoch,
             refresh_family_id,refresh_token_digest,refresh_used,csrf_secret)
           values ($1,$2,$3,'PARTICIPANT',$4,$5,'ACTIVE',$6,0,transaction_timestamp()-interval '10 minutes',transaction_timestamp(),
             transaction_timestamp()+interval '30 minutes',transaction_timestamp()+interval '11 hours 50 minutes',
             transaction_timestamp(),$7,7,1,$8,$9,false,$10)`,
            [
              sessionId,
              participantId,
              principalId,
              privacyDomainId,
              sha256(`${participantId}.${sessionId}`),
              epoch,
              sha256(`fingerprint:${principalId}`),
              id(),
              sha256(`refresh:${principalId}`),
              sha256(`csrf:${principalId}`),
            ],
          );
        }

        const identityRepository = new PostgresIdentityRepository(runtime);
        const participantRepository = new PostgresParticipantRepository(runtime);

        const provisioned = {
          principalId: id(),
          participantId,
          displayLabel: 'catalog provision target',
          kind: 'USER' as const,
          state: 'PROVISIONED' as const,
          identityEpoch: '0',
        };
        const provisionActor = await authorize(
          identityActor(makerId),
          'ID-OP-PRINCIPAL-PROVISION',
          'ACT-PARTICIPANT_CREATE_MEMBER-V1',
          provisioned.principalId,
          '0',
          provisioned,
        );
        const altered = Buffer.from(provisionActor.mutationAuthorization!.coseSign1);
        altered[altered.length - 1] = altered[altered.length - 1]! ^ 1;
        await expect(
          identityRepository.provisionPrincipal(
            {
              ...provisionActor,
              mutationAuthorization: {
                ...provisionActor.mutationAuthorization!,
                coseSign1: altered,
              },
            },
            provisioned,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' });
        expect(await identityRepository.provisionPrincipal(provisionActor, provisioned)).toEqual(
          provisioned,
        );
        expect(await identityRepository.provisionPrincipal(provisionActor, provisioned)).toEqual(
          provisioned,
        );
        await admin.query(`update control.principal set state='SUSPENDED' where principal_id=$1`, [
          checkerId,
        ]);
        await expect(
          identityRepository.provisionPrincipal(provisionActor, provisioned),
        ).rejects.toMatchObject({
          code: 'PC-IDENTITY-1001',
        });
        await admin.query(`update control.principal set state='ACTIVE' where principal_id=$1`, [
          checkerId,
        ]);
        await admin.query(
          `update control.session set state='REVOKED',revoked_at=clock_timestamp(),
             revoked_reason='replay-authorization-regression' where session_id=$1`,
          [actorSessions.get(makerId)],
        );
        await expect(
          identityRepository.provisionPrincipal(provisionActor, provisioned),
        ).rejects.toMatchObject({
          code: 'PC-AUTH-0003',
        });
        await admin.query(
          `update control.session set state='ACTIVE',revoked_at=null,revoked_reason=null where session_id=$1`,
          [actorSessions.get(makerId)],
        );

        const suspendCandidate = { principalId: suspendId, state: 'SUSPENDED' };
        const registrationRequest = {
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          resourceDigest: canonicalAuthorizationDigest(suspendCandidate),
          rpIdHash: `sha256:${sha256('openpc.example').toString('hex')}`,
        };
        const registration = await identityRepository.issueStepUpChallenge(
          await authorize(
            identityActor(makerId),
            'ID-OP-WEBAUTHN-REGISTER',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            actorSessions.get(makerId)!,
            '1',
            registrationRequest,
          ),
          registrationRequest.actionIntentId,
          registrationRequest.resourceDigest,
          registrationRequest.rpIdHash,
        );
        const verification = {
          actionIntentId: registrationRequest.actionIntentId,
          resourceDigest: registrationRequest.resourceDigest,
          challenge: registration.challenge,
          rpIdHash: registrationRequest.rpIdHash,
        };
        const verificationEvidenceCbor = canonicalEvidence(
          participantId,
          makerId,
          String(serial++),
        );
        const verificationEvidence = signedEvidence(verificationEvidenceCbor);
        const verificationAuthorization: IdentityAuthorizationAdapter = {
          async authorize(input) {
            expect(input.actionIntentId).toBe('ACT-IDENTITY_UPDATE_STEP_UP-V1');
            expect(input.makerCheckerRequired).toBe(false);
            expect(input.stepUpRequired).toBe(false);
            return {
              allowed: true,
              signerCredentialId: makerCredentialId,
              privacyDomainId,
              evidenceCbor: verificationEvidenceCbor,
              evidenceDigest: verificationEvidence.digest,
              coseSign1: verificationEvidence.coseSign1,
            };
          },
        };
        let verifiedAssertion: VerifiedWebAuthnAssertion | undefined;
        const identityKernel = new IdentityKernel(identityRepository);
        const identityApp = buildIdentityService(
          identityKernel,
          cryptographicWebAuthnAdapter(makerCredentialId, (assertion) => {
            verifiedAssertion = assertion;
          }),
          undefined,
          verificationAuthorization,
        );
        const sessionToken = `${participantId}.${actorSessions.get(makerId)}`;
        const sessionCookie = `__Host-openpc_session=${sessionToken}`;
        const requestHeaders = async (idempotencyKey: string) => {
          const version = (
            await admin.query<{ row_version: string }>(
              `select row_version::text from control.session where participant_id=$1 and session_id=$2`,
              [participantId, actorSessions.get(makerId)],
            )
          ).rows[0]?.row_version;
          if (version === undefined) throw new Error('missing live WebAuthn session fixture');
          return {
            'cookie': sessionCookie,
            'origin': 'https://control.openpc.example',
            'host': 'control.openpc.example',
            'idempotency-key': idempotencyKey,
            'openpc-action-intent-digest': await identityKernel.actionIntentSemanticDigest(
              sessionToken,
              'ACT-IDENTITY_UPDATE_STEP_UP-V1',
            ),
            'x-csrf-token': await identityKernel.csrfToken(
              sessionToken,
              registrationRequest.actionIntentId,
              'https://control.openpc.example',
              'control.openpc.example',
            ),
            'x-openpc-aggregate-version': version,
          };
        };
        const validIdempotencyKey = `i02-webauthn-http-valid-${id()}`;
        let validAggregateVersion: string | undefined;
        try {
          const rpIdHash = sha256('openpc.example');
          const altered = await identityApp.inject({
            method: 'POST',
            url: '/v1/identity/webauthn/verify',
            headers: await requestHeaders(`i02-webauthn-http-altered-${id()}`),
            payload: {
              ...verification,
              assertion: signedWebAuthnAssertion(
                makerCredentialId,
                registration.challenge,
                'https://control.openpc.example',
                rpIdHash,
                1,
                true,
              ),
            },
          });
          expect(altered.statusCode).toBe(401);
          expect(altered.json()).toMatchObject({ error: { code: 'PC-AUTH-0006' } });

          const validHeaders = await requestHeaders(validIdempotencyKey);
          validAggregateVersion = validHeaders['x-openpc-aggregate-version'];
          const verified = await identityApp.inject({
            method: 'POST',
            url: '/v1/identity/webauthn/verify',
            headers: validHeaders,
            payload: {
              ...verification,
              assertion: signedWebAuthnAssertion(
                makerCredentialId,
                registration.challenge,
                'https://control.openpc.example',
                rpIdHash,
                1,
              ),
            },
          });
          expect(verified.json()).toEqual({ status: 'verified' });
          expect(verified.statusCode).toBe(200);
        } finally {
          await identityApp.close();
        }
        const replayAssertion = verifiedAssertion;
        if (replayAssertion === undefined || validAggregateVersion === undefined) {
          throw new Error('missing verified WebAuthn replay fixture');
        }
        const replayProof = {
          sessionToken: `${participantId}.${actorSessions.get(makerId)}`,
          ...verification,
          verifiedAssertion: replayAssertion,
        };
        const replayActor: AuthenticatedIdentityActor = {
          principalId: makerId,
          participantId,
          sessionToken: replayProof.sessionToken,
          platform: false,
          mutationAuthorization: {
            authorized: true,
            evidenceKind: 'USER_WEBAUTHN',
            idempotencyKey: validIdempotencyKey,
            candidateDigest: canonicalAuthorizationDigest(
              stepUpAuthorizationCandidate(replayProof),
            ),
            privacyDomainId,
            aggregateVersion: validAggregateVersion,
            signerCredentialId: makerCredentialId,
            evidenceCbor: verificationEvidenceCbor,
            evidenceDigest: verificationEvidence.digest,
            coseSign1: verificationEvidence.coseSign1,
          },
        };
        const storedWebAuthnBinding = (
          await admin.query<{ webauthn_assertion_binding_digest: Buffer }>(
            `select webauthn_assertion_binding_digest from control.idempotency_record
             where participant_id=$1 and catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
               and idempotency_key=$2`,
            [participantId, validIdempotencyKey],
          )
        ).rows[0]?.webauthn_assertion_binding_digest;
        if (storedWebAuthnBinding === undefined) {
          throw new Error('missing stored WebAuthn idempotency binding');
        }
        await admin.query(
          `update control.idempotency_record set webauthn_assertion_binding_digest=$2
           where participant_id=$1 and catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
             and idempotency_key=$3`,
          [participantId, Buffer.alloc(32, 0xa5), validIdempotencyKey],
        );
        await expect(
          identityRepository.verifyStepUp(replayActor, replayProof),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1009' });
        await admin.query(
          `update control.idempotency_record set webauthn_assertion_binding_digest=$2
           where participant_id=$1 and catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
             and idempotency_key=$3`,
          [participantId, storedWebAuthnBinding, validIdempotencyKey],
        );
        await expect(
          identityRepository.verifyStepUp(replayActor, replayProof),
        ).resolves.toBeUndefined();

        const stepUpBoundSuspendActor = await authorize(
          identityActor(makerId),
          'ID-OP-PRINCIPAL-SUSPEND',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          suspendId,
          '1',
          suspendCandidate,
          false,
        );
        const suspended = await identityRepository.suspendPrincipal(
          stepUpBoundSuspendActor,
          suspendId,
        );
        expect(suspended).toMatchObject({ principalId: suspendId, state: 'SUSPENDED' });
        await expect(
          identityRepository.suspendPrincipal(stepUpBoundSuspendActor, suspendId),
        ).resolves.toMatchObject({ principalId: suspendId, state: 'SUSPENDED' });
        const currentSuspendVersion = (
          await admin.query<{ row_version: string }>(
            `select row_version::text from control.principal
              where participant_id=$1 and principal_id=$2`,
            [participantId, suspendId],
          )
        ).rows[0]?.row_version;
        if (currentSuspendVersion === undefined) {
          throw new Error('missing suspended principal revision');
        }
        await expect(
          identityRepository.suspendPrincipal(
            {
              ...stepUpBoundSuspendActor,
              mutationAuthorization: {
                ...stepUpBoundSuspendActor.mutationAuthorization!,
                idempotencyKey: `${stepUpBoundSuspendActor.mutationAuthorization!.idempotencyKey}-replay`,
                aggregateVersion: currentSuspendVersion,
              },
            },
            suspendId,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' });

        // An approved workload operation must not mutate a different credential family.
        const unrelatedAuthenticatorId = actorCredentials.get(custodianOneId)!;
        const unrelatedBefore = (
          await admin.query(
            'select state,credential_epoch::text,row_version::text from control.credential where credential_id=$1',
            [unrelatedAuthenticatorId],
          )
        ).rows[0]!;
        for (const mutation of ['ROTATE', 'REVOKE'] as const) {
          const state = mutation === 'ROTATE' ? 'ROTATING' : 'REVOKED';
          const authorized = await authorize(
            identityActor(makerId),
            `ID-OP-WORKLOAD-${mutation}`,
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            unrelatedAuthenticatorId,
            unrelatedBefore.row_version,
            { credentialId: unrelatedAuthenticatorId, state },
          );
          await expect(
            mutation === 'ROTATE'
              ? identityRepository.rotateWorkload(authorized, unrelatedAuthenticatorId)
              : identityRepository.revokeWorkload(authorized, unrelatedAuthenticatorId),
          ).rejects.toMatchObject({ code: 'PC-IDENTITY-1006' });
        }
        expect(
          (
            await admin.query(
              'select state,credential_epoch::text,row_version::text from control.credential where credential_id=$1',
              [unrelatedAuthenticatorId],
            )
          ).rows[0],
        ).toEqual(unrelatedBefore);

        const workloadId = id();
        const now = Date.now();
        const workloadKeyId = `sha256:${sha256(signerSpki).toString('hex')}`;
        const workload = {
          credentialId: workloadId,
          principalId: workloadPrincipalId,
          participantId,
          workloadId: `urn:openpc:workload:${workloadId}`,
          state: 'ISSUED' as const,
          workloadEpoch: '0',
          keyId: workloadKeyId,
          uriSan: `urn:openpc:participant:${participantId}:workload:${workloadId}`,
          notBefore: new Date(now - 13 * 60 * 60_000),
          notAfter: new Date(now + 10 * 60 * 60_000),
          issuer: 'https://workload-issuer.openpc.example',
          certificateFingerprint: sha256('i02-workload-certificate'),
          publicKeySpkiDer: signerSpki,
        };
        const userOwnedWorkload = { ...workload, principalId: makerId };
        await expect(
          identityRepository.issueWorkload(
            await authorize(
              identityActor(makerId),
              'ID-OP-WORKLOAD-ISSUE',
              'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
              workloadId,
              '0',
              userOwnedWorkload,
            ),
            userOwnedWorkload,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1002' });
        await identityRepository.issueWorkload(
          await authorize(
            identityActor(makerId),
            'ID-OP-WORKLOAD-ISSUE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            workloadId,
            '0',
            workload,
          ),
          workload,
        );
        const currentParticipantEpoch = (
          await admin.query<{ authority_epoch: string }>(
            `select authority_epoch::text from control.participant where participant_id=$1`,
            [participantId],
          )
        ).rows[0]?.authority_epoch;
        if (currentParticipantEpoch === undefined) {
          throw new Error('missing current participant epoch for workload authentication');
        }
        const workloadAuthentication = {
          participantId,
          workloadId: workload.workloadId,
          participantEpoch: currentParticipantEpoch,
          workloadEpoch: '0',
          keyId: workloadKeyId,
          uriSan: workload.uriSan,
          certificateFingerprint: workload.certificateFingerprint,
          tlsVersion: 'TLS1.3' as const,
          notBefore: workload.notBefore,
          notAfter: workload.notAfter,
          issuerTrusted: true,
          keyTrusted: true,
          revoked: false,
        };
        const authenticatedWorkload =
          await identityRepository.authenticateWorkload(workloadAuthentication);
        expect(authenticatedWorkload).toMatchObject({
          credentialId: workloadId,
          principalId: workloadPrincipalId,
          participantId,
          workloadId: workload.workloadId,
          participantEpoch: currentParticipantEpoch,
          workloadEpoch: '0',
          keyId: workloadKeyId,
          uriSan: workload.uriSan,
        });
        await expect(
          identityRepository.authenticateWorkload({
            participantId,
            workloadId: workload.workloadId,
            participantEpoch: currentParticipantEpoch,
            workloadEpoch: '0',
            keyId: `sha256:${'0'.repeat(64)}`,
            uriSan: workload.uriSan,
            certificateFingerprint: workload.certificateFingerprint,
            tlsVersion: 'TLS1.3',
            notBefore: workload.notBefore,
            notAfter: workload.notAfter,
            issuerTrusted: true,
            keyTrusted: true,
            revoked: false,
          }),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1006' });
        const lastUsedBeforeMismatch = (
          await admin.query<{ last_used_at: Date }>(
            'select last_used_at from control.credential where credential_id=$1',
            [workloadId],
          )
        ).rows[0]!.last_used_at;
        await expect(
          identityRepository.authenticateWorkload({
            participantId,
            workloadId: workload.workloadId,
            participantEpoch: currentParticipantEpoch,
            workloadEpoch: '0',
            keyId: workloadKeyId,
            uriSan: workload.uriSan,
            certificateFingerprint: sha256('different-certificate-with-the-same-public-key'),
            tlsVersion: 'TLS1.3',
            notBefore: workload.notBefore,
            notAfter: workload.notAfter,
            issuerTrusted: true,
            keyTrusted: true,
            revoked: false,
          }),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1006' });
        expect(
          (
            await admin.query<{ last_used_at: Date }>(
              'select last_used_at from control.credential where credential_id=$1',
              [workloadId],
            )
          ).rows[0]!.last_used_at,
        ).toEqual(lastUsedBeforeMismatch);
        // Race the exact database boundary after an earlier transport lookup.
        // This adversarial store mutation deliberately keeps the public key and
        // epochs unchanged; the full certificate must still be rechecked.
        const replacement = await admin.connect();
        try {
          await replacement.query('begin');
          await replacement.query(
            'update control.credential set secret_fingerprint=$2 where credential_id=$1',
            [workloadId, sha256('concurrent-certificate-replacement')],
          );
          const pendingAuthentication =
            identityRepository.authenticateWorkload(workloadAuthentication);
          // Attach the rejection handler before committing the concurrent writer.
          const authenticationOutcome = pendingAuthentication.then(
            (value) => ({ value, error: undefined }),
            (error: unknown) => ({ value: undefined, error }),
          );
          await expect
            .poll(async () => {
              const blocked = await replacement.query<{ blocked: boolean }>(
                `select exists(select 1 from pg_stat_activity
                 where pid<>pg_backend_pid()
                   and pg_backend_pid()=any(pg_blocking_pids(pid))) as blocked`,
              );
              return blocked.rows[0]?.blocked;
            })
            .toBe(true);
          await replacement.query('commit');
          expect(await authenticationOutcome).toMatchObject({
            value: undefined,
            error: { code: 'PC-IDENTITY-1006' },
          });
        } finally {
          await replacement.query('rollback');
          await replacement.query(
            'update control.credential set secret_fingerprint=$2 where credential_id=$1',
            [workloadId, workload.certificateFingerprint],
          );
          replacement.release();
        }
        await identityRepository.rotateWorkload(
          await authorize(
            identityActor(makerId),
            'ID-OP-WORKLOAD-ROTATE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            workloadId,
            '1',
            { credentialId: workloadId, state: 'ROTATING' },
          ),
          workloadId,
        );
        await expect(
          identityRepository.authenticateWorkload({
            participantId,
            workloadId: workload.workloadId,
            participantEpoch: currentParticipantEpoch,
            workloadEpoch: '0',
            keyId: workloadKeyId,
            uriSan: workload.uriSan,
            certificateFingerprint: workload.certificateFingerprint,
            tlsVersion: 'TLS1.3',
            notBefore: workload.notBefore,
            notAfter: workload.notAfter,
            issuerTrusted: true,
            keyTrusted: true,
            revoked: false,
          }),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1006' });
        await identityRepository.revokeWorkload(
          await authorize(
            identityActor(makerId),
            'ID-OP-WORKLOAD-REVOKE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            workloadId,
            '2',
            { credentialId: workloadId, state: 'REVOKED' },
          ),
          workloadId,
        );

        // External attestation provenance is a component fixture; approval decisions below
        // are signed fixture state. This does not establish the public/browser journey.
        const qualification = {
          principalId: recoveryPrincipalId,
          credentialId: actorCredentials.get(recoveryPrincipalId)!,
          principalEpoch: '23',
          credentialEpoch: '1',
        };
        const qualificationActor = await authorize(
          identityActor(makerId),
          'ID-OP-RECOVERY-PRINCIPAL-QUALIFY',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          recoveryPrincipalId,
          '0',
          qualification,
        );
        await expect(
          identityRepository.qualifyRecoveryPrincipal(qualificationActor, qualification),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1007' });
        await admin.query(
          `insert into control.hardware_authenticator(credential_id,participant_id,principal_id,profile_id,profile_digest,aaguid,attestation_digest)
          values ($1,$2,$3,'component-fixture',$4,$3,$4)`,
          [
            actorCredentials.get(recoveryPrincipalId),
            participantId,
            recoveryPrincipalId,
            `sha256:${sha256('component-fixture').toString('hex')}`,
          ],
        );
        await expect(
          identityRepository.qualifyRecoveryPrincipal(
            await authorize(
              identityActor(recoveryPrincipalId),
              'ID-OP-RECOVERY-PRINCIPAL-QUALIFY',
              'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
              recoveryPrincipalId,
              '0',
              qualification,
            ),
            qualification,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1007' });
        await expect(
          identityRepository.qualifyRecoveryPrincipal(qualificationActor, qualification),
        ).resolves.toMatchObject({
          state: 'ACTIVE',
          assurance: 'RECOVERY_PRINCIPAL',
          revision: '1',
        });
        expect(
          (
            await admin.query(
              `select state,revoked_reason from control.session where session_id=$1`,
              [actorSessions.get(recoveryPrincipalId)],
            )
          ).rows[0],
        ).toEqual({ state: 'REVOKED', revoked_reason: 'recovery-principal-qualified' });
        const revocation = { principalId: recoveryPrincipalId, state: 'REVOKED' };
        await expect(
          identityRepository.revokeRecoveryPrincipal(
            await authorize(
              identityActor(makerId),
              'ID-OP-RECOVERY-PRINCIPAL-REVOKE',
              'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
              recoveryPrincipalId,
              '1',
              revocation,
            ),
            recoveryPrincipalId,
          ),
        ).resolves.toMatchObject({ state: 'REVOKED', revision: '2' });
        const renewedQualification = { ...qualification, principalEpoch: '25' };
        await expect(
          identityRepository.qualifyRecoveryPrincipal(
            await authorize(
              identityActor(makerId),
              'ID-OP-RECOVERY-PRINCIPAL-QUALIFY',
              'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
              recoveryPrincipalId,
              '2',
              renewedQualification,
            ),
            renewedQualification,
          ),
        ).resolves.toMatchObject({ state: 'ACTIVE', revision: '3' });
        actorEpochs.set(recoveryPrincipalId, '26');
        const executorSession = await identityRepository.issueLocalDevelopmentSession(
          participantId,
          recoveryPrincipalId,
          false,
        );
        actorSessions.set(recoveryPrincipalId, executorSession.sessionId);
        const recoveryId = id();
        const recoveryRequest = {
          recoveryId,
          subjectId,
          recoveryPrincipalId,
          participantId,
          custodianPrincipalIds: [custodianOneId, custodianTwoId] as const,
          purposeDigest: `sha256:${sha256('catalog recovery').toString('hex')}`,
          actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        };
        // Component regressions for recovery and custodian separation. This fixture
        // supplies signed approval state and does not qualify the public journey.
        for (const custodians of [
          [subjectId, custodianTwoId],
          [recoveryPrincipalId, custodianTwoId],
          [custodianOneId, subjectId],
          [custodianOneId, recoveryPrincipalId],
          [custodianOneId, custodianOneId],
        ] as const) {
          const invalid = {
            ...recoveryRequest,
            recoveryId: id(),
            custodianPrincipalIds: custodians,
          };
          await expect(
            identityRepository.beginRecovery(
              await authorize(
                identityActor(makerId),
                'ID-OP-RECOVERY-BEGIN',
                invalid.actionIntentId,
                invalid.recoveryId,
                '0',
                invalid,
              ),
              invalid,
            ),
          ).rejects.toMatchObject({ code: 'PC-IDENTITY-1007' });
          expect(
            (
              await admin.query(
                'select 1 from control.recovery_challenge where recovery_challenge_id=$1',
                [invalid.recoveryId],
              )
            ).rowCount,
          ).toBe(0);
        }
        await identityRepository.beginRecovery(
          await authorize(
            identityActor(makerId),
            'ID-OP-RECOVERY-BEGIN',
            recoveryRequest.actionIntentId,
            recoveryId,
            '0',
            recoveryRequest,
          ),
          recoveryRequest,
        );
        const completionCandidate = { recoveryId, state: 'COMPLETED' };
        const approvalCandidate = {
          recoveryId,
          purposeDigest: recoveryRequest.purposeDigest,
        };
        const initialRecoveryAuthority = (
          await admin.query(
            `select recovery_principal_epoch::text,custodian_one_epoch::text,custodian_two_epoch::text
             from control.recovery_challenge where recovery_challenge_id=$1`,
            [recoveryId],
          )
        ).rows[0];
        expect(initialRecoveryAuthority).toEqual({
          recovery_principal_epoch: '26',
          custodian_one_epoch: '21',
          custodian_two_epoch: '22',
        });
        await expect(
          identityRepository.approveRecovery(
            await authorize(
              identityActor(custodianTwoId),
              'ID-OP-RECOVERY-APPROVE',
              'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
              recoveryId,
              '1',
              approvalCandidate,
            ),
            recoveryId,
            recoveryRequest.purposeDigest,
          ),
        ).resolves.toMatchObject({ state: 'CUSTODIAN_ONE_APPROVED' });
        await admin.query(
          `update control.recovery_challenge set outcome='REQUESTED'
           where participant_id=$1 and recovery_challenge_id=$2`,
          [participantId, recoveryId],
        );
        const custodianOneRecoveryActor = await authorize(
          identityActor(custodianOneId),
          'ID-OP-RECOVERY-APPROVE',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          recoveryId,
          '2',
          approvalCandidate,
        );
        await expect(
          identityRepository.approveRecovery(
            custodianOneRecoveryActor,
            recoveryId,
            recoveryRequest.purposeDigest,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1007' });
        await admin.query(
          `update control.recovery_challenge set outcome='CUSTODIAN_ONE_APPROVED'
           where participant_id=$1 and recovery_challenge_id=$2`,
          [participantId, recoveryId],
        );
        await expect(
          identityRepository.approveRecovery(
            custodianOneRecoveryActor,
            recoveryId,
            recoveryRequest.purposeDigest,
          ),
        ).resolves.toMatchObject({ state: 'CUSTODIAN_TWO_APPROVED' });
        await admin.query(
          `update control.recovery_challenge set outcome='CUSTODIAN_ONE_APPROVED'
           where participant_id=$1 and recovery_challenge_id=$2`,
          [participantId, recoveryId],
        );
        const recoveryCompletionActor = await authorize(
          identityActor(recoveryPrincipalId),
          'ID-OP-RECOVERY-COMPLETE',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          recoveryId,
          '3',
          completionCandidate,
        );
        const assertRecoveryDenied = async () => {
          // Either the ordered authority fence or the scoped recovery owner may fail first.
          await expect(
            identityRepository.completeRecovery(recoveryCompletionActor, recoveryId),
          ).rejects.toMatchObject({ code: expect.stringMatching(/^PC-IDENTITY-100[17]$/u) });
          expect(
            (
              await admin.query(
                `select principal.authority_epoch::text,recovery.consumed_at from control.recovery_challenge recovery join control.principal principal on principal.principal_id=recovery.principal_id and principal.participant_id=recovery.participant_id where recovery.recovery_challenge_id=$1`,
                [recoveryId],
              )
            ).rows[0],
          ).toEqual({ authority_epoch: '31', consumed_at: null });
        };
        await assertRecoveryDenied();
        await admin.query(
          `update control.recovery_challenge set outcome='CUSTODIAN_TWO_APPROVED'
           where participant_id=$1 and recovery_challenge_id=$2`,
          [participantId, recoveryId],
        );
        // Changing a non-executing custodian must invalidate the accumulated approvals.
        const retainedCustody = (
          await admin.query(
            `select custodian_one_authority from control.recovery_challenge where recovery_challenge_id=$1`,
            [recoveryId],
          )
        ).rows[0].custodian_one_authority;
        expect(retainedCustody.checkerAuthority).toMatchObject({
          principalId: checkerId,
          signerCredentialId: checkerCredentialId,
          signerCredentialEpoch: '1',
        });
        for (const checkerAuthority of [
          undefined,
          { ...retainedCustody.checkerAuthority, principalEpoch: '999' },
          { ...retainedCustody.checkerAuthority, signerCredentialEpoch: '999' },
          { ...retainedCustody.checkerAuthority, principalId: subjectId },
        ]) {
          await admin.query(
            `update control.recovery_challenge set custodian_one_authority=$2 where recovery_challenge_id=$1`,
            [recoveryId, { ...retainedCustody, checkerAuthority }],
          );
          await assertRecoveryDenied();
        }
        await admin.query(
          `update control.recovery_challenge set custodian_one_authority=$2 where recovery_challenge_id=$1`,
          [recoveryId, retainedCustody],
        );
        for (const custodian of [custodianOneId, custodianTwoId]) {
          await admin.query(
            `update control.principal set state='SUSPENDED' where principal_id=$1`,
            [custodian],
          );
          await assertRecoveryDenied();
          await admin.query(
            `update control.principal set state='ACTIVE',authority_epoch=authority_epoch+1 where principal_id=$1`,
            [custodian],
          );
          await assertRecoveryDenied();
          // Restore only this adversarial fixture so the original valid path can finish.
          await admin.query(
            `update control.principal set authority_epoch=authority_epoch-1 where principal_id=$1`,
            [custodian],
          );
        }
        for (const custodian of [custodianOneId, custodianTwoId]) {
          await admin.query(
            `update control.credential set state='REVOKED' where credential_id=$1`,
            [actorCredentials.get(custodian)],
          );
          await assertRecoveryDenied();
          await admin.query(`update control.credential set state='ACTIVE' where credential_id=$1`, [
            actorCredentials.get(custodian),
          ]);
          await admin.query(
            `update control.assignment set state='REVOKED' where assignment_id=$1`,
            [actorAssignments.get(custodian)],
          );
          await assertRecoveryDenied();
          await admin.query(`update control.assignment set state='ACTIVE' where assignment_id=$1`, [
            actorAssignments.get(custodian),
          ]);
        }
        await admin.query(
          `update control.credential set credential_epoch=credential_epoch+1 where credential_id=$1`,
          [actorCredentials.get(recoveryPrincipalId)],
        );
        await assertRecoveryDenied();
        await admin.query(
          `update control.credential set credential_epoch=credential_epoch-1 where credential_id=$1`,
          [actorCredentials.get(recoveryPrincipalId)],
        );
        expect(
          (
            await admin.query(
              `select current_epoch::text,outcome,consumed_at from control.recovery_challenge where recovery_challenge_id=$1`,
              [recoveryId],
            )
          ).rows[0],
        ).toMatchObject({
          current_epoch: '31',
          outcome: 'CUSTODIAN_TWO_APPROVED',
          consumed_at: null,
        });
        await identityRepository.completeRecovery(recoveryCompletionActor, recoveryId);
        const nextRecovery = { ...recoveryRequest, recoveryId: id() };
        await expect(
          identityRepository.beginRecovery(
            await authorize(
              identityActor(makerId),
              'ID-OP-RECOVERY-BEGIN',
              nextRecovery.actionIntentId,
              nextRecovery.recoveryId,
              '0',
              nextRecovery,
            ),
            nextRecovery,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1007' });
        const review = { recoveryId, note: 'Confirmed subject revocation and recovery evidence.' };
        await expect(
          identityRepository.postReviewRecovery(
            await authorize(
              identityActor(makerId),
              'ID-OP-RECOVERY-POST-REVIEW',
              'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
              recoveryId,
              '4',
              review,
            ),
            recoveryId,
            review.note,
          ),
        ).resolves.toMatchObject({ state: 'COMPLETED', postReviewStatus: 'REVIEWED' });

        const rejectedParticipantId = id();
        const createParticipantRequest = {
          participantId: rejectedParticipantId,
          displayName: 'catalog-created participant',
          idempotencyKey: 'catalog-participant-create',
        };
        const createParticipantActor = await authorize(
          participantActor(makerId),
          'ID-OP-PARTICIPANT-CREATE',
          'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
          rejectedParticipantId,
          '0',
          createParticipantRequest,
        );
        await expect(
          participantRepository.createParticipant(
            createParticipantActor,
            {
              participantId: rejectedParticipantId,
              displayName: createParticipantRequest.displayName,
              state: 'PROVISIONING',
              authorityEpoch: '0',
              rowVersion: '1',
            },
            createParticipantActor.mutationAuthorization!.idempotencyKey,
            createParticipantRequest,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1005' });
        expect(
          (
            await admin.query(
              'select participant_id from control.participant where participant_id=$1',
              [rejectedParticipantId],
            )
          ).rowCount,
        ).toBe(0);
        const activateParticipantRequest = { idempotencyKey: 'catalog-participant-activate' };
        const launderedParticipantActor = await authorize(
          participantActor(makerId),
          'ID-OP-PARTICIPANT-ACTIVATE',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          createdParticipantId,
          '1',
          activateParticipantRequest,
        );
        await expect(
          participantRepository.activateParticipant(
            launderedParticipantActor,
            createdParticipantId,
            launderedParticipantActor.mutationAuthorization!.idempotencyKey,
            activateParticipantRequest,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1009' });
        const activateParticipantActor = await authorize(
          participantActor(makerId),
          'ID-OP-PARTICIPANT-ACTIVATE',
          'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
          createdParticipantId,
          '1',
          activateParticipantRequest,
        );
        await participantRepository.activateParticipant(
          activateParticipantActor,
          createdParticipantId,
          activateParticipantActor.mutationAuthorization!.idempotencyKey,
          activateParticipantRequest,
        );

        const envelopeId = id();
        const envelope: AuthorityEnvelope = {
          ...permission,
          capabilityIds: ['CALL_RESULT_DISCLOSURE'],
          id: envelopeId,
          authorityEpoch: '7',
          state: 'DRAFT',
          semanticDigest: `sha256:${sha256('catalog-created-envelope').toString('hex')}`,
        };
        const envelopeActor = await authorize(
          participantActor(makerId),
          'ID-OP-ENVELOPE-CREATE',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          envelopeId,
          '0',
          envelope,
        );
        const stalePrincipal = { ...envelopeActor, boundPrincipalEpoch: '12' };
        await expect(
          participantRepository.createEnvelope(stalePrincipal, envelope),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1001' });
        const staleEnvelope = { ...envelopeActor, boundEnvelopeEpoch: '18' };
        await expect(
          participantRepository.createEnvelope(staleEnvelope, envelope),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1002' });
        await participantRepository.createEnvelope(envelopeActor, envelope);
        await admin.query(
          `update control.authority_envelope set state='APPROVED',checker_principal_id=$2,
           row_version=row_version+1,updated_at=clock_timestamp() where authority_envelope_id=$1`,
          [envelopeId, checkerId],
        );
        const launderedEnvelopeActor = await authorize(
          participantActor(makerId),
          'ID-OP-ENVELOPE-ACTIVATE',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          envelopeId,
          '2',
          { envelopeId },
        );
        await expect(
          participantRepository.activateEnvelope(launderedEnvelopeActor, participantId, envelopeId),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1009' });
        await participantRepository.activateEnvelope(
          await authorize(
            participantActor(makerId),
            'ID-OP-ENVELOPE-ACTIVATE',
            'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
            envelopeId,
            '2',
            { envelopeId },
          ),
          participantId,
          envelopeId,
        );

        const roleId = id();
        const role = {
          id: roleId,
          participantId,
          roleId: `urn:openpc:role:${roleId}`,
          displayName: 'Contract reviewers',
          actionIntentIds: intents,
          state: 'ACTIVE' as const,
        };
        const createdRole = await participantRepository.createRole(
          await authorize(
            participantActor(makerId),
            'ID-OP-ROLE-CREATE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            roleId,
            '0',
            role,
          ),
          role,
        );
        expect(createdRole).toMatchObject({ ...role, revision: '1', origin: 'GOVERNED' });
        const assignmentId = id();
        const assignment: Assignment = {
          ...permission,
          // Runtime authority is disjoint from the actors' administrative bootstrap grants.
          actionIntentIds: [],
          capabilityIds: ['CALL_RESULT_DISCLOSURE'],
          id: assignmentId,
          principalId: granteeId,
          roleId: role.roleId,
          authorityEnvelopeId: envelopeId,
          state: 'ACTIVE',
          delegationEpoch: '0',
          scopeDigest: `sha256:${sha256('catalog-created-assignment').toString('hex')}`,
        };
        const broadened: Assignment = {
          ...assignment,
          id: id(),
          capabilityIds: ['SIGNED_TRANSACTION_SUBMISSION'],
        };
        await expect(
          participantRepository.createAssignment(
            await authorize(
              participantActor(makerId),
              'ID-OP-ASSIGNMENT-CREATE',
              'ACT-PARTICIPANT_CREATE_MEMBER-V1',
              broadened.id,
              '0',
              broadened,
            ),
            broadened,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1002' });
        expect(
          (
            await admin.query(
              'select assignment_id from control.assignment where assignment_id=$1',
              [broadened.id],
            )
          ).rowCount,
        ).toBe(0);
        const assigned = await participantRepository.createAssignment(
          await authorize(
            participantActor(makerId),
            'ID-OP-ASSIGNMENT-CREATE',
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
            assignmentId,
            '0',
            assignment,
          ),
          assignment,
        );
        expect(assigned.roleId).toBe(assignment.roleId);
        expect(assigned.capabilityIds).toEqual(['CALL_RESULT_DISCLOSURE']);
        const storedRole = await admin.query(
          'select role_id,runtime_capability_ids from control.assignment where participant_id=$1 and assignment_id=$2',
          [participantId, assignmentId],
        );
        expect(storedRole.rows).toEqual([
          { role_id: assignment.roleId, runtime_capability_ids: ['CALL_RESULT_DISCLOSURE'] },
        ]);
        const readTarget = {
          privacyDomainId,
          actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
          resourceId: assignmentId,
        };
        const readActor: AuthenticatedActor = {
          ...participantActor(makerId),
          readAuthorization: {
            ...(await authorizeLocalPolicyAction(runtime, identityKernel, {
              ...readTarget,
              sessionToken: identityActor(makerId).sessionToken,
              stepUpRequired: true,
            })),
            ...readTarget,
          },
        };
        const readback = await participantRepository.getAssignment(
          readActor,
          participantId,
          privacyDomainId,
          assignmentId,
        );
        expect(readback).toMatchObject({
          effect: {
            id: assignmentId,
            principalId: granteeId,
            roleId: assignment.roleId,
            capabilityIds: ['CALL_RESULT_DISCLOSURE'],
            privacyDomainIds: [privacyDomainId],
            state: 'ACTIVE',
          },
          revision: '1',
        });
        expect(
          await new PostgresParticipantRepository(runtime).getAssignment(
            readActor,
            participantId,
            privacyDomainId,
            assignmentId,
          ),
        ).toEqual(readback);
        const api = await participantReadbackRuntime({
          runtime,
          identityDatabaseUrl: runtimeDatabaseUrl!,
          participantId,
          privacyDomainId,
          operatorPrincipalId: makerId,
          checkerPrincipalId: checkerId,
        });
        try {
          const token = identityActor(makerId).sessionToken;
          const getRecovery = async (
            target = recoveryId,
            privacy = privacyDomainId,
            session = token,
          ) => {
            const response = await fetch(`${api.identityUrl}/v1/identity/recoveries/${target}`, {
              headers: {
                'Cookie': `__Host-openpc_session=${session}`,
                'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
              },
              signal: AbortSignal.timeout(5000),
            });
            return {
              status: response.status,
              cacheControl: response.headers.get('cache-control'),
              body: await response.json(),
            };
          };
          const recovered = await getRecovery();
          expect(recovered).toMatchObject({
            status: 200,
            cacheControl: 'no-store',
            body: {
              effect: {
                recoveryId,
                participantId,
                privacyDomainId,
                subjectId,
                recoveryPrincipalId,
                state: 'COMPLETED',
                revision: '5',
                postReviewRequired: true,
                postReviewStatus: 'REVIEWED',
                reviewedAt: expect.any(String),
                reviewedByPrincipalId: makerId,
                reviewNote: review.note,
                subjectEpoch: '31',
                completedAt: expect.any(String),
              },
              operationId: expect.any(String),
            },
          });
          expect(JSON.stringify(recovered)).not.toMatch(/challenge_digest|credential|cose_sign1/);
          await api.restartIdentity();
          expect(await getRecovery()).toEqual(recovered);
          const missingRecovery = await getRecovery(id());
          expect(missingRecovery.status).toBe(404);
          expect(await getRecovery(recoveryId, id())).toEqual(missingRecovery);
          expect(await getRecovery(recoveryId, privacyDomainId, 'invalid')).toEqual(
            missingRecovery,
          );
          const publicReadback = await api.get(token, assignmentId);
          const publicRole = await api.get(token, roleId, privacyDomainId, 'roles');
          expect(publicRole).toMatchObject({
            status: 200,
            cacheControl: 'no-store',
            body: { effect: createdRole, operationId: expect.any(String) },
          });
          expect(publicReadback).toEqual({
            status: 200,
            cacheControl: 'no-store',
            body: JSON.parse(JSON.stringify(readback)) as unknown,
          });
          await api.restartParticipant();
          expect(await api.get(token, assignmentId)).toEqual(publicReadback);
          expect(await api.get(token, roleId, privacyDomainId, 'roles')).toEqual(publicRole);
          const hidden = {
            status: 404,
            cacheControl: 'no-store',
            body: { error: { code: 'PC-IDENTITY-1008', status: 404 } },
          };
          expect(await api.get(token, id())).toEqual(hidden);
          expect(await api.get(token, assignmentId, id())).toEqual(hidden);
          expect(await api.get('invalid-session-token', assignmentId)).toEqual(hidden);
          expect(await api.get(token, id(), privacyDomainId, 'roles')).toEqual(hidden);
          expect(await api.get(token, roleId, id(), 'roles')).toEqual(hidden);
          expect(await api.get('invalid-session-token', roleId, privacyDomainId, 'roles')).toEqual(
            hidden,
          );
        } finally {
          await api.close();
        }
        await expect(
          participantRepository.getAssignment(
            participantActor(makerId),
            participantId,
            privacyDomainId,
            assignmentId,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
        const priorAssurance = await admin.query<{
          step_up_verified_at: Date;
        }>('select step_up_verified_at from control.session where session_id=$1', [
          actorSessions.get(makerId),
        ]);
        await admin.query(
          `update control.session set step_up_verified_at=clock_timestamp()-interval '6 minutes'
             where session_id=$1`,
          [actorSessions.get(makerId)],
        );
        await expect(
          participantRepository.getAssignment(
            readActor,
            participantId,
            privacyDomainId,
            assignmentId,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
        await admin.query('update control.session set step_up_verified_at=$2 where session_id=$1', [
          actorSessions.get(makerId),
          priorAssurance.rows[0]!.step_up_verified_at,
        ]);
        const delegationId = id();
        const delegation: Delegation = {
          ...permission,
          id: delegationId,
          parentId: actorAssignments.get(makerId)!,
          grantorId: makerId,
          granteeId,
          state: 'ACTIVE',
          delegationEpoch: '0',
          scopeDigest: `sha256:${sha256('catalog-created-delegation').toString('hex')}`,
          onwardDelegationDepth: 3,
          validFrom: new Date(permission.validFrom.getTime() + 1_000),
          validUntil: new Date(permission.validUntil.getTime() - 1_000),
        };
        await participantRepository.issueDelegation(
          await authorize(
            participantActor(makerId),
            'ID-OP-DELEGATION-ISSUE',
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
            delegationId,
            '0',
            delegation,
          ),
          delegation,
        );
        await participantRepository.revokeAuthority(
          await authorize(
            participantActor(makerId),
            'ID-OP-DELEGATION-REVOKE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            delegationId,
            '1',
            { kind: 'delegation', targetId: delegationId },
          ),
          participantId,
          'delegation',
          delegationId,
        );
        await admin.query(`update control.session set participant_epoch=8 where session_id=$1`, [
          actorSessions.get(makerId),
        ]);
        // The earlier authority decision must not survive a durable epoch change.
        await expect(
          participantRepository.getAssignment(
            readActor,
            participantId,
            privacyDomainId,
            assignmentId,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1008' });
        await participantRepository.revokeAuthority(
          await authorize(
            participantActor(makerId, '8'),
            'ID-OP-ASSIGNMENT-REVOKE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            assignmentId,
            '1',
            { kind: 'assignment', targetId: assignmentId },
          ),
          participantId,
          'assignment',
          assignmentId,
        );

        await admin.query('update control.session set participant_epoch=9 where session_id=$1', [
          actorSessions.get(makerId),
        ]);
        const activeRoleAssignment = { ...assignment, id: id(), principalId: makerId };
        await participantRepository.createAssignment(
          await authorize(
            participantActor(makerId, '9'),
            'ID-OP-ASSIGNMENT-CREATE',
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
            activeRoleAssignment.id,
            '0',
            activeRoleAssignment,
          ),
          activeRoleAssignment,
        );
        const roleDelegation = {
          ...delegation,
          id: id(),
          parentId: activeRoleAssignment.id,
          actionIntentIds: [],
          capabilityIds: ['CALL_RESULT_DISCLOSURE'] as const,
        };
        await participantRepository.issueDelegation(
          await authorize(
            participantActor(makerId, '9'),
            'ID-OP-DELEGATION-ISSUE',
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
            roleDelegation.id,
            '0',
            roleDelegation,
          ),
          roleDelegation,
        );
        const archivedRole = await participantRepository.archiveRole(
          await authorize(
            participantActor(makerId, '9'),
            'ID-OP-ROLE-ARCHIVE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            roleId,
            '1',
            { roleId, state: 'ARCHIVED' },
          ),
          participantId,
          roleId,
        );
        expect(archivedRole).toMatchObject({
          effect: { id: roleId, state: 'ARCHIVED', revision: '2' },
          newEpoch: '10',
          revokedAssignments: 1,
        });
        expect(
          (
            await admin.query('select state from control.assignment where assignment_id=$1', [
              activeRoleAssignment.id,
            ])
          ).rows,
        ).toEqual([{ state: 'REVOKED' }]);
        expect(
          (
            await admin.query('select state from control.delegation where delegation_id=$1', [
              roleDelegation.id,
            ])
          ).rows,
        ).toEqual([{ state: 'REVOKED' }]);
        await expect(
          authorizeLocalPolicyAction(runtime, identityKernel, {
            ...readTarget,
            sessionToken: identityActor(makerId).sessionToken,
            stepUpRequired: true,
          }),
        ).rejects.toMatchObject({ code: 'PC-AUTH-0003' });
        await admin.query('update control.session set participant_epoch=10 where session_id=$1', [
          actorSessions.get(makerId),
        ]);
        const forbiddenAssignment = { ...assignment, id: id() };
        await expect(
          participantRepository.createAssignment(
            await authorize(
              participantActor(makerId, '10'),
              'ID-OP-ASSIGNMENT-CREATE',
              'ACT-PARTICIPANT_CREATE_MEMBER-V1',
              forbiddenAssignment.id,
              '0',
              forbiddenAssignment,
            ),
            forbiddenAssignment,
          ),
        ).rejects.toMatchObject({ code: 'PC-IDENTITY-1002' });
        expect(
          (
            await admin.query(
              'select assignment_id from control.assignment where assignment_id=$1',
              [forbiddenAssignment.id],
            )
          ).rowCount,
        ).toBe(0);

        const proof = await admin.query<{
          catalog_operation_id: string;
          idempotency_key: string;
          expected_aggregate_version: string;
          result_aggregate_version: string;
          webauthn_assertion_binding_digest: Buffer | null;
        }>(
          `select catalog_operation_id,idempotency_key,expected_aggregate_version::text,result_aggregate_version::text,
                  webauthn_assertion_binding_digest
           from control.idempotency_record where participant_id=$1 order by catalog_operation_id`,
          [participantId],
        );
        const observed = new Set(proof.rows.map((row) => row.catalog_operation_id));
        expect(new Set([...observed].filter((operation) => highRisk.has(operation)))).toEqual(
          highRisk,
        );
        expect(observed.has('ID-OP-WEBAUTHN-VERIFY')).toBe(true);
        expect(proof.rows.every((row) => row.result_aggregate_version !== null)).toBe(true);
        expect(
          proof.rows
            .find((row) => row.idempotency_key === validIdempotencyKey)
            ?.webauthn_assertion_binding_digest?.equals(storedWebAuthnBinding),
        ).toBe(true);
        const businessProof = proof.rows.filter((row) => highRisk.has(row.catalog_operation_id));
        expect(businessProof).toHaveLength(25);
        expect(
          businessProof
            .filter((row) => row.webauthn_assertion_binding_digest?.length !== 32)
            .map((row) => row.catalog_operation_id),
        ).toEqual([]);
        expect(
          proof.rows.find((row) => row.catalog_operation_id === 'ID-OP-PARTICIPANT-ACTIVATE'),
        ).toMatchObject({ expected_aggregate_version: '1', result_aggregate_version: '2' });
        expect(
          proof.rows.find((row) => row.catalog_operation_id === 'ID-OP-ENVELOPE-ACTIVATE'),
        ).toMatchObject({ expected_aggregate_version: '2', result_aggregate_version: '3' });
        expect(
          proof.rows.find((row) => row.catalog_operation_id === 'ID-OP-ASSIGNMENT-REVOKE'),
        ).toMatchObject({ expected_aggregate_version: '1', result_aggregate_version: '2' });
        expect(
          proof.rows.find((row) => row.catalog_operation_id === 'ID-OP-DELEGATION-REVOKE'),
        ).toMatchObject({ expected_aggregate_version: '1', result_aggregate_version: '2' });
        const atomic = await admin.query<{
          business_three_way_binding: number;
          committed_high_risk_idempotency: number;
          high_risk_complete: number;
          used_challenges: number;
          webauthn_idempotency_binding: number;
          webauthn_evidence_binding: number;
          webauthn_outbox_binding: number;
          webauthn_three_way_binding: number;
          webauthn_sign_count: string;
        }>(
          `select
           (select count(*)::int from control.mutation_evidence where participant_id=$1
             and catalog_operation_id<>'ID-OP-WEBAUTHN-VERIFY' and checker_principal_id is not null
             and approval_request_id is not null and mfa_challenge_id is not null
             and octet_length(webauthn_assertion_binding_digest)=32) high_risk_complete,
           (select count(*)::int from control.idempotency_record where participant_id=$1
             and catalog_operation_id=any($3::text[]) and terminal_state='COMMITTED'
             and octet_length(webauthn_assertion_binding_digest)=32) committed_high_risk_idempotency,
           (select count(*)::int from control.mfa_challenge where participant_id=$1
             and used_at is not null and used_operation_id is not null) used_challenges,
           (select count(*)::int from control.idempotency_record where participant_id=$1
             and catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
             and idempotency_key=$4
             and octet_length(webauthn_assertion_binding_digest)=32) webauthn_idempotency_binding,
           (select count(*)::int from control.mutation_evidence evidence
             join control.idempotency_record idempotency
               on idempotency.participant_id=evidence.participant_id
              and idempotency.operation_id=evidence.operation_id
             where evidence.participant_id=$1 and idempotency.idempotency_key=$4
             and evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
             and octet_length(evidence.webauthn_assertion_binding_digest)=32) webauthn_evidence_binding,
           (select count(*)::int from control.outbox_event event
             where event.participant_id=$1 and event.aggregate_type='webauthn-verification'
             and event.webauthn_assertion_binding_digest=$5) webauthn_outbox_binding,
           (select count(*)::int from control.idempotency_record i
             join control.mutation_evidence e on e.participant_id=i.participant_id
              and e.catalog_operation_id=i.catalog_operation_id
              and e.webauthn_assertion_binding_digest=i.webauthn_assertion_binding_digest
             join control.outbox_event o on o.participant_id=e.participant_id
              and o.aggregate_type='webauthn-verification'
              and o.webauthn_assertion_binding_digest=e.webauthn_assertion_binding_digest
             where i.participant_id=$1 and i.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
              and i.idempotency_key=$4
              and octet_length(i.webauthn_assertion_binding_digest)=32) webauthn_three_way_binding,
           (select count(*)::int from control.mutation_evidence business
             join control.mfa_challenge challenge
               on challenge.participant_id=business.participant_id
              and challenge.mfa_challenge_id=business.mfa_challenge_id
             join control.mutation_evidence verification
               on verification.participant_id=challenge.participant_id
              and verification.mfa_challenge_id=challenge.mfa_challenge_id
              and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
              and verification.webauthn_assertion_binding_digest=
                  business.webauthn_assertion_binding_digest
             join control.idempotency_record verification_idempotency
               on verification_idempotency.participant_id=verification.participant_id
              and verification_idempotency.operation_id=verification.operation_id
              and verification_idempotency.webauthn_assertion_binding_digest=
                  verification.webauthn_assertion_binding_digest
              and verification_idempotency.terminal_state='COMMITTED'
             join control.outbox_event verification_event
               on verification_event.participant_id=verification.participant_id
              and verification_event.aggregate_type='webauthn-verification'
              and verification_event.aggregate_id=verification.aggregate_id
              and verification_event.webauthn_assertion_binding_digest=
                  verification.webauthn_assertion_binding_digest
            where business.participant_id=$1
              and business.catalog_operation_id=any($3::text[])) business_three_way_binding,
           (select authenticator_sign_count::text from control.credential
             where participant_id=$1 and credential_id=$2) webauthn_sign_count`,
          [
            participantId,
            makerCredentialId,
            [...highRisk],
            validIdempotencyKey,
            storedWebAuthnBinding,
          ],
        );
        expect(atomic.rows).toEqual([
          {
            business_three_way_binding: 25,
            committed_high_risk_idempotency: 25,
            high_risk_complete: 25,
            used_challenges: 25,
            webauthn_idempotency_binding: 1,
            webauthn_evidence_binding: 1,
            webauthn_outbox_binding: 1,
            webauthn_three_way_binding: 1,
            webauthn_sign_count: '1',
          },
        ]);
      } catch (error) {
        operationError = error;
      }
      await runtime.end();
      // run-participant-readback gives this scenario an exclusive disposable
      // database. Its owner removes that database; retained business history
      // and security triggers must never be disabled for fixture cleanup.
      await admin.end();
      if (operationError !== undefined) throw operationError;
    },
    15_000,
  );
});
