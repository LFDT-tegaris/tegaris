import {
  stepUpOnlyConfigurationOperations,
  stepUpRuntimeAssertion,
} from '../../../../identity-service/src/domain/configuration-step-up-admission.js';
import {
  currentMutationCandidateSql,
  fenceMutationIntent,
} from '../../../../identity-service/src/db/mutation-candidate-fence.js';
import { verifyStoredStepUpEvidence } from '../../../../identity-service/src/db/verified-step-up-evidence.js';
import { persistAuthorizationEvidence } from '../../../../identity-service/src/db/authorization-evidence-store.js';
import { createHash, randomBytes } from 'node:crypto';
import { setTimeout as retryDelay } from 'node:timers/promises';

import {
  controlMutationForAction,
  businessTransitionProfileForOperation,
  decodeIdentityCredentialPayload,
  identityCredentialCoseContext,
  verifyCoseSign1Es256,
} from '@openpc/security-kernel';
import type { Pool, PoolClient } from 'pg';
import { fenceConfigurationMutation } from './authority-fence.js';
import {
  discoverBusinessSigningKey,
  fenceBusinessSigningKey,
  type BusinessSigningScope,
} from '../../../../identity-service/src/db/business-signing-store.js';
import { captureAuthoritySnapshot } from '../../../../identity-service/src/db/authority-snapshot.js';
import {
  revalidateBoundAuthorities,
  type AuthorityFence,
} from '../../../../identity-service/src/db/authority-fence.js';
import {
  appendBusinessReceipt,
  type ConfigurationBusinessEvidence,
  type PreparedBusinessReceipt,
} from './business-receipt-writer.js';
import { verifyConfigurationRuntimeAuthorization } from './runtime-authorization.js';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';

import { canonicalJson, sha256 } from '../digest.js';
import {
  ConfigurationRepositoryError,
  isRuntimeSourceProducerContention,
  type MutationContext,
  type OperationRecord,
  type MutationWriter,
  type MutationBusinessState,
} from './types.js';

function uuidv7(): string {
  const bytes = randomBytes(16);
  let time = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(time & 0xffn);
    time >>= 8n;
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function bytesForDigest(digest: string): Buffer {
  return Buffer.from(digest.slice('sha256:'.length), 'hex');
}

function requireOne<T>(rows: readonly T[], code: 'PC-AUTH-0005' | 'PC-DATA-6007'): T {
  if (rows.length !== 1) throw new ConfigurationRepositoryError(code);
  return rows[0]!;
}

function isSerializationFailure(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === '40001';
}

class ModuleReferenceProducerBusy extends Error {}
class RuntimeArtifactReferenceProducerBusy extends Error {}

const moduleReferenceProducers = new Set([
  'CFG-OP-CREATE-PROVIDER-PROFILE',
  'CFG-OP-UPDATE-PROVIDER-PROFILE',
  'CFG-OP-QUALIFY-PROVIDER-PROFILE',
  'CFG-OP-QUARANTINE-PROVIDER-PROFILE',
  'CFG-OP-CREATE-INDEXER-PROFILE',
  'CFG-OP-UPDATE-INDEXER-PROFILE',
  'CFG-OP-ADMIT-INDEXER-PROFILE',
  'CFG-OP-CREATE-PROJECTION-PLAN',
  'CFG-OP-UPDATE-PROJECTION-PLAN',
  'CFG-OP-RECOVER-PROJECTION-PLAN',
  'CFG-OP-CREATE-RUNTIME-TARGET',
  'CFG-OP-UPDATE-RUNTIME-TARGET',
]);

const runtimeArtifactReferenceProducers = new Set([
  ...moduleReferenceProducers,
  'MOD-OP-REGISTER',
  'MOD-OP-INSTALL',
  'MOD-OP-ENABLE',
  'MOD-OP-DISABLE',
]);

async function beginScopedTransaction(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
): Promise<void> {
  // This owner checks current source/reference custody after its producer
  // fences. An earlier Serializable snapshot cannot establish that currentness.
  // Keep the choice internal and bound to the exact registered operation.
  const sourceDisposition = context.catalogOperationId === 'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE';
  const physicalRetirement = context.catalogOperationId === 'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH';
  const currentRuntime = sourceDisposition || physicalRetirement;
  if (
    currentRuntime &&
    (context.actionIntentId !==
      (sourceDisposition
        ? 'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1'
        : 'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1') ||
      context.resourceType !== 'evidence-deletions' ||
      context.aggregateType !==
        (sourceDisposition ? 'runtime-artifact-disposition' : 'evidence-deletion') ||
      context.operationClass !== 'CREATE' ||
      context.expectedRevision !== '0')
  )
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  await client.query(
    currentRuntime ? 'begin isolation level read committed' : 'begin isolation level serializable',
  );
  await client.query('set local row_security=on');
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      operationId,
      context.actionIntentId,
    ],
  );
  if (currentRuntime) await client.query('select openpc.lock_runtime_artifact_disposition()');
  if (runtimeArtifactReferenceProducers.has(context.catalogOperationId)) {
    const operation = controlMutationForAction(context.actionIntentId, context.catalogOperationId);
    if (
      operation === undefined ||
      operation.resourceType !== context.resourceType ||
      operation.aggregateType !== context.aggregateType ||
      operation.operationClass !== context.operationClass
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    // Source custody takes lifecycle before module fences. Acquire the same
    // order before reservation or signing; the statement guard remains active.
    const locked = await client.query<{ locked: boolean }>(
      "select pg_try_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0)) as locked",
    );
    if (locked.rowCount !== 1 || typeof locked.rows[0]?.locked !== 'boolean')
      throw new ConfigurationRepositoryError('PC-DATA-6007');
    if (!locked.rows[0].locked) throw new RuntimeArtifactReferenceProducerBusy();
  }
  if (moduleReferenceProducers.has(context.catalogOperationId)) {
    // Hold the existing reference fence before reserving intent or preparing
    // evidence. Its statement trigger stays authoritative and reentrant.
    const locked = await client.query<{ locked: boolean }>(
      "select pg_try_advisory_xact_lock_shared(hashtextextended('module-admission:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text,0)) as locked",
    );
    if (locked.rowCount !== 1 || typeof locked.rows[0]?.locked !== 'boolean')
      throw new ConfigurationRepositoryError('PC-DATA-6007');
    if (!locked.rows[0].locked) throw new ModuleReferenceProducerBusy();
  }
}

type ActionIntent = {
  readonly resourceType: string;
  readonly operationClass: string;
  readonly makerCheckerRequired: boolean;
  readonly stepUpRequired: boolean;
  readonly idempotencyRequired: boolean;
  readonly semanticDigest: Buffer;
};

async function actionIntent(client: PoolClient, context: MutationContext): Promise<ActionIntent> {
  const result = await client.query<ActionIntent>(
    `select resource_type as "resourceType",operation_class as "operationClass",
            maker_checker_required as "makerCheckerRequired",step_up_required as "stepUpRequired",
            idempotency_required as "idempotencyRequired",semantic_digest as "semanticDigest"
       from control.action_intent where action_intent_id=$1`,
    [context.actionIntentId],
  );
  const action = requireOne(result.rows, 'PC-AUTH-0005');
  const operation = controlMutationForAction(context.actionIntentId, context.catalogOperationId);
  if (
    operation === undefined ||
    operation.catalogOperationId !== context.catalogOperationId ||
    operation.resourceType !== context.resourceType ||
    operation.operationClass !== context.operationClass ||
    action.makerCheckerRequired !== operation.makerCheckerRequired ||
    action.stepUpRequired !== operation.stepUpRequired ||
    action.resourceType !== context.resourceType ||
    action.operationClass !== context.operationClass ||
    !action.idempotencyRequired ||
    `sha256:${action.semanticDigest.toString('hex')}` !== context.actionIntentDigest
  ) {
    throw new ConfigurationRepositoryError('PC-AUTH-0005', undefined, 'proof-structure');
  }
  return action;
}

interface IdempotencyReservation<T> {
  readonly operationId: string;
  readonly replay?: T;
}

async function reserveIdempotency<T>(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
  candidateDigest: Buffer,
): Promise<IdempotencyReservation<T>> {
  const authorization = context.authorization;
  const reservation = await client.query(
    `insert into control.idempotency_record
       (participant_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,
        operation_id,input_digest,webauthn_assertion_binding_digest,expected_aggregate_version,expires_at,privacy_domain_id)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '24 hours',$10)
     on conflict (participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key)
       do nothing returning operation_id`,
    [
      authorization.participantId,
      authorization.principalId,
      context.actionIntentId,
      context.catalogOperationId,
      context.idempotencyKey,
      operationId,
      candidateDigest,
      authorization.webauthnAssertionBindingDigest ?? null,
      context.expectedRevision,
      authorization.privacyDomainId,
    ],
  );
  if (reservation.rowCount === 1) return { operationId };
  const existing = await client.query<{
    readonly operationId: string;
    readonly inputDigest: Buffer;
    readonly resultPayload: T | null;
    readonly terminalState: string | null;
    readonly expectedRevision: string;
    readonly webauthnDigest: Buffer | null;
  }>(
    `select operation_id::text as "operationId",input_digest as "inputDigest",result_payload as "resultPayload",
            terminal_state as "terminalState",expected_aggregate_version::text as "expectedRevision",
            webauthn_assertion_binding_digest as "webauthnDigest"
       from control.idempotency_record
      where participant_id=$1 and principal_id=$2 and action_intent_id=$3
        and catalog_operation_id=$4 and idempotency_key=$5 for share`,
    [
      authorization.participantId,
      authorization.principalId,
      context.actionIntentId,
      context.catalogOperationId,
      context.idempotencyKey,
    ],
  );
  const replay = requireOne(existing.rows, 'PC-DATA-6007');
  const bindingMatches =
    authorization.webauthnAssertionBindingDigest === undefined
      ? replay.webauthnDigest === null
      : replay.webauthnDigest?.equals(authorization.webauthnAssertionBindingDigest) === true;
  if (
    !replay.inputDigest.equals(candidateDigest) ||
    replay.terminalState !== 'COMMITTED' ||
    replay.resultPayload === null ||
    replay.expectedRevision !== context.expectedRevision ||
    !bindingMatches
  ) {
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  }
  return { operationId: replay.operationId, replay: replay.resultPayload };
}

async function verifyAuthorization(
  client: PoolClient,
  context: MutationContext,
  action: ActionIntent,
  operationId: string,
  candidateDigest: Buffer,
  runtimeVerifier: IdentityRuntimeVerifier | undefined,
): Promise<void> {
  const proof = context.authorization;
  if (proof.evidenceKind === 'IDENTITY_RUNTIME') {
    if (action.makerCheckerRequired || action.stepUpRequired)
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return verifyConfigurationRuntimeAuthorization(
      client,
      context,
      candidateDigest,
      runtimeVerifier,
    );
  }
  if (proof.evidenceKind === 'IDENTITY_RUNTIME_STEP_UP') {
    if (
      action.makerCheckerRequired ||
      !action.stepUpRequired ||
      !stepUpOnlyConfigurationOperations.includes(context.catalogOperationId) ||
      proof.checkerPrincipalId !== undefined ||
      proof.approvalRequestId !== undefined ||
      proof.webauthnSessionId !== proof.sessionId
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    await verifyConfigurationRuntimeAuthorization(
      client,
      { ...context, authorization: stepUpRuntimeAssertion(proof) },
      candidateDigest,
      runtimeVerifier,
    );
    return verifyConfigurationStepUp(
      client,
      context,
      operationId,
      candidateDigest,
      runtimeVerifier,
    );
  }
  if (proof.evidenceKind !== 'USER_WEBAUTHN')
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  let credential;
  try {
    credential = decodeIdentityCredentialPayload(proof.evidenceCbor);
  } catch {
    // A registered authenticator may use the Identity-signed committed verification
    // profile. Its exact approval and signature are verified below.
    if (
      !action.makerCheckerRequired ||
      proof.approvalRequestId === undefined ||
      proof.checkerPrincipalId === undefined
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
  }
  if (
    proof.sessionEpoch === undefined ||
    !createHash('sha256').update(proof.evidenceCbor).digest().equals(proof.evidenceDigest) ||
    BigInt(context.expectedRevision) < 0n ||
    (credential !== undefined &&
      (credential.participantId !== `urn:openpc:participant:${proof.participantId}` ||
        Date.parse(credential.issuedAt) > Date.now() ||
        Date.parse(credential.expiresAt) <= Date.now()))
  ) {
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  }
  // Envelope maker/checker fields record grant issuance. The shared authority
  // fence and signed approval below bind this transaction's actual actors.
  const authority = await client.query<{
    readonly publicKeyDigest: Buffer;
    readonly publicKeySpkiDer: Buffer;
    readonly signerPrincipalEpoch: string;
  }>(
    `select c.public_key_digest as "publicKeyDigest",c.public_key_spki_der as "publicKeySpkiDer",
            signer_pr.authority_epoch::text as "signerPrincipalEpoch"
       from control.session s
       join control.participant p on p.participant_id=s.participant_id and p.state='ACTIVE'
       join control.principal pr on pr.participant_id=s.participant_id and pr.principal_id=s.principal_id and pr.state='ACTIVE'
       join control.assignment a on a.participant_id=s.participant_id and a.assignment_id=$6
        and a.principal_id=s.principal_id and a.state='ACTIVE' and a.valid_during @> clock_timestamp()
        and (not $15::boolean or a.maker_checker_required=true)
        and $4=any(a.action_intent_ids) and $3::uuid::text=any(a.privacy_domain_ids)
        and ($5::uuid::text=any(a.resource_ids) or '*'=any(a.resource_ids))
       join control.authority_envelope ae on ae.participant_id=s.participant_id
        and ae.authority_envelope_id=$7 and ae.authority_envelope_id=a.authority_envelope_id
        and (ae.principal_id=s.principal_id or (ae.representation='TYPED_V1' and ae.principal_id is null))
        and (not $15::boolean or ae.maker_checker_required=true)
        and ae.state='ACTIVE' and ae.valid_from<=clock_timestamp()
        and (ae.valid_until is null or ae.valid_until>clock_timestamp())
        and $4=any(ae.action_intent_ids) and $3::uuid::text=any(ae.privacy_domain_ids)
        and ($5::uuid::text=any(ae.resource_ids) or '*'=any(ae.resource_ids))
       join control.credential c on c.participant_id=s.participant_id and c.credential_id=$12
        and c.kind='WEBAUTHN' and c.state='ACTIVE' and c.valid_from<=clock_timestamp()
        and (c.valid_until is null or c.valid_until>clock_timestamp())
       join control.principal signer_pr on signer_pr.participant_id=c.participant_id
        and signer_pr.principal_id=c.principal_id and signer_pr.state='ACTIVE'
      where s.participant_id=$1 and s.session_id=$2 and s.session_epoch=$17
        and s.principal_id=$8 and s.state='ACTIVE' and s.idle_expires_at>clock_timestamp()
        and s.absolute_expires_at>clock_timestamp() and s.participant_epoch=$9
        and s.authority_epoch=$10 and s.delegation_epoch=$11
        and p.authority_epoch=$9 and pr.authority_epoch=$10
        and a.delegation_epoch=$11 and a.row_version=$13
        and ae.authority_epoch=$14
        and c.principal_id=case when $15::boolean then $16::uuid else $8::uuid end`,
    [
      proof.participantId,
      proof.sessionId,
      proof.privacyDomainId,
      context.actionIntentId,
      context.resourceId,
      proof.assignmentId,
      proof.authorityEnvelopeId,
      proof.principalId,
      proof.participantEpoch,
      proof.principalEpoch,
      proof.delegationEpoch,
      proof.signerCredentialId,
      proof.assignmentEpoch,
      proof.authorityEpoch,
      action.makerCheckerRequired,
      proof.checkerPrincipalId ?? proof.principalId,
      proof.sessionEpoch,
    ],
  );
  if (authority.rows.length !== 1) {
    throw new ConfigurationRepositoryError('PC-AUTH-0005', undefined, 'live-authority');
  }
  const signer = authority.rows[0]!;
  if (
    (credential !== undefined &&
      (credential.principalId !==
        `urn:openpc:principal:${action.makerCheckerRequired ? proof.checkerPrincipalId : proof.principalId}` ||
        credential.authorityEpoch !== signer.signerPrincipalEpoch)) ||
    signer.publicKeySpkiDer.length === 0 ||
    !createHash('sha256').update(signer.publicKeySpkiDer).digest().equals(signer.publicKeyDigest) ||
    !(proof.approvalRequestId !== undefined && proof.checkerPrincipalId !== undefined
      ? await verifyStoredStepUpEvidence(
          client,
          {
            participantId: proof.participantId,
            privacyDomainId: proof.privacyDomainId,
            principalId: proof.checkerPrincipalId,
            credentialId: proof.signerCredentialId,
            approvalRequestId: proof.approvalRequestId,
            credentialPublicKey: signer.publicKeySpkiDer,
            evidenceCbor: proof.evidenceCbor,
            coseSign1: proof.coseSign1,
          },
          runtimeVerifier,
        )
      : verifyCoseSign1Es256(
          signer.publicKeySpkiDer,
          proof.evidenceCbor,
          proof.coseSign1,
          identityCredentialCoseContext,
        ))
  ) {
    throw new ConfigurationRepositoryError('PC-AUTH-0005', undefined, 'approval-signature');
  }
  if (action.makerCheckerRequired) {
    if (
      proof.approvalRequestId === undefined ||
      proof.checkerPrincipalId === undefined ||
      proof.checkerPrincipalId === proof.principalId
    ) {
      throw new ConfigurationRepositoryError('PC-AUTH-0005', undefined, 'maker-checker');
    }
    const approval = await client.query(
      `select 1 from control.approval_request ar
        join control.mutation_candidate candidate
          on candidate.participant_id=ar.participant_id
         and candidate.privacy_domain_id=ar.privacy_domain_id
         and candidate.mutation_candidate_id=ar.subject_id
         and candidate.action_intent_id=ar.action_intent_id
         and candidate.candidate_digest=ar.subject_digest
         and candidate.expected_revision=ar.subject_version
        join control.approval_decision_record ad on ad.participant_id=ar.participant_id
         and ad.approval_request_id=ar.approval_request_id
        join control.principal checker on checker.participant_id=ad.participant_id
         and checker.principal_id=ad.approver_principal_id and checker.state='ACTIVE'
         and checker.authority_epoch=ad.approver_principal_epoch
        join control.participant checker_participant on checker_participant.participant_id=ad.participant_id
         and checker_participant.state='ACTIVE'
         and checker_participant.authority_epoch=ad.approver_participant_epoch
        join control.assignment ca on ca.participant_id=ad.participant_id
         and ca.assignment_id=ad.approver_assignment_id and ca.principal_id=checker.principal_id
         and ca.state='ACTIVE' and ca.valid_during @> clock_timestamp()
         and ca.maker_checker_required=true
         and ca.row_version=ad.approver_assignment_row_version
         and ca.delegation_epoch=ad.approver_delegation_epoch
         and $4=any(ca.action_intent_ids) and $2::uuid::text=any(ca.privacy_domain_ids)
         and ($5::uuid::text=any(ca.resource_ids) or '*'=any(ca.resource_ids))
        join control.authority_envelope ce on ce.participant_id=ad.participant_id
         and ce.authority_envelope_id=ad.approver_authority_envelope_id
         and ce.authority_envelope_id=ca.authority_envelope_id
         and ce.principal_id=checker.principal_id and ce.state='ACTIVE'
         and ce.authority_epoch=ad.approver_envelope_epoch
         and ce.delegation_epoch=ad.approver_delegation_epoch
         and ce.valid_from<=clock_timestamp() and (ce.valid_until is null or ce.valid_until>clock_timestamp())
         and $4=any(ce.action_intent_ids) and $2::uuid::text=any(ce.privacy_domain_ids)
         and ($5::uuid::text=any(ce.resource_ids) or '*'=any(ce.resource_ids))
         and ce.maker_checker_required=true
        join control.credential decision_credential
          on decision_credential.participant_id=ad.participant_id
         and decision_credential.credential_id=ad.signer_credential_id
         and decision_credential.principal_id=ad.approver_principal_id
         and decision_credential.kind='WEBAUTHN' and decision_credential.state='ACTIVE'
         and decision_credential.valid_from<=clock_timestamp()
         and (decision_credential.valid_until is null
              or decision_credential.valid_until>clock_timestamp())
       where ar.participant_id=$1 and ar.privacy_domain_id=$2::uuid and ar.approval_request_id=$3
         and ar.action_intent_id=$4 and ar.subject_type='CONFIGURATION_CANDIDATE'
         and ar.subject_digest=$6
         and ar.subject_version=$7 and ar.maker_principal_id=$8 and ar.state='APPROVED'
         and (ar.checker_principal_id is null or ar.checker_principal_id=$9::uuid)
         and ar.expires_at>clock_timestamp() and ad.decision='APPROVE'
         and ad.approver_principal_id=$9 and ad.signer_credential_id=$10
         and ad.aggregate_version=$7 and ad.candidate_digest=$6
         and ad.evidence_cbor=$11 and ad.cose_sign1=$12 and ad.decision_digest=$13
         and candidate.catalog_operation_id=$14 and candidate.resource_type=$15
               and candidate.operation_class=$16 and candidate.resource_id=$5
               and candidate.candidate_document=$17::jsonb
               and candidate.maker_principal_id=$8 and candidate.maker_session_id=$18
               and candidate.maker_session_epoch=$19 and candidate.maker_participant_epoch=$20
               and candidate.maker_principal_epoch=$21 and candidate.maker_assignment_id=$22
               and candidate.maker_assignment_row_version=$23
               and candidate.maker_authority_envelope_id=$24
               and candidate.maker_authority_epoch=$25 and candidate.maker_delegation_epoch=$26
               and candidate.expires_at>clock_timestamp()
               and ${currentMutationCandidateSql('candidate')}
               and (candidate.state='APPROVED'
                    or (candidate.state='CONSUMED' and candidate.consumed_operation_id=$27))
         for update of ar,candidate`,
      [
        proof.participantId,
        proof.privacyDomainId,
        proof.approvalRequestId,
        context.actionIntentId,
        context.resourceId,
        candidateDigest,
        context.expectedRevision,
        proof.principalId,
        proof.checkerPrincipalId,
        proof.signerCredentialId,
        proof.evidenceCbor,
        proof.coseSign1,
        bytesForDigest(
          sha256({
            actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
            approvalRequestId: `urn:openpc:resource:${proof.approvalRequestId}`,
            candidateDigest: `sha256:${candidateDigest.toString('hex')}`,
            decision: 'APPROVE',
            expectedRevision: '1',
          }),
        ),
        context.catalogOperationId,
        context.resourceType,
        context.operationClass,
        canonicalJson(context.candidate),
        proof.sessionId,
        proof.sessionEpoch ?? '-1',
        proof.participantEpoch,
        proof.principalEpoch,
        proof.assignmentId,
        proof.assignmentEpoch,
        proof.authorityEnvelopeId,
        proof.authorityEpoch,
        proof.delegationEpoch,
        operationId,
      ],
    );
    if (approval.rowCount !== 1) {
      throw new ConfigurationRepositoryError('PC-AUTH-0005', undefined, 'approval-state');
    }
  }
  if (action.stepUpRequired)
    await verifyConfigurationStepUp(client, context, operationId, candidateDigest, runtimeVerifier);
}

async function verifyConfigurationStepUp(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
  candidateDigest: Buffer,
  runtimeVerifier: IdentityRuntimeVerifier | undefined,
): Promise<void> {
  const proof = context.authorization;

  if (
    proof.mfaChallengeId === undefined ||
    proof.webauthnSessionId === undefined ||
    proof.webauthnSignerCredentialId === undefined ||
    proof.webauthnAssertionBindingDigest === undefined ||
    proof.webauthnEvidenceCbor === undefined ||
    proof.webauthnEvidenceDigest === undefined ||
    proof.webauthnCoseSign1 === undefined ||
    !createHash('sha256')
      .update(proof.webauthnEvidenceCbor)
      .digest()
      .equals(proof.webauthnEvidenceDigest)
  ) {
    throw new ConfigurationRepositoryError('PC-AUTH-0005', undefined, 'step-up-structure');
  }
  const challenge = await client.query<{ publicKeyDigest: Buffer; publicKeySpkiDer: Buffer }>(
    `select step_up_credential.public_key_digest as "publicKeyDigest",
              step_up_credential.public_key_spki_der as "publicKeySpkiDer"
         from control.mfa_challenge challenge
        join control.mutation_evidence verification
          on verification.participant_id=challenge.participant_id
         and verification.privacy_domain_id=$12
         and verification.principal_id=challenge.principal_id
         and verification.mfa_challenge_id=challenge.mfa_challenge_id
         and verification.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
         and verification.aggregate_type='webauthn-verification'
         and verification.aggregate_id=challenge.session_id
         and verification.webauthn_assertion_binding_digest=$8
         and verification.evidence_cbor=$9 and verification.evidence_digest=$10
         and verification.cose_sign1=$11
        join control.idempotency_record verification_idempotency
          on verification_idempotency.participant_id=verification.participant_id
         and verification_idempotency.privacy_domain_id=verification.privacy_domain_id
         and verification_idempotency.principal_id=verification.principal_id
         and verification_idempotency.operation_id=verification.operation_id
         and verification_idempotency.catalog_operation_id=verification.catalog_operation_id
         and verification_idempotency.input_digest=verification.candidate_digest
         and verification_idempotency.webauthn_assertion_binding_digest=$8
         and verification_idempotency.terminal_state='COMMITTED'
        join control.outbox_event verification_event
          on verification_event.participant_id=verification.participant_id
         and verification_event.privacy_domain_id=verification.privacy_domain_id
         and verification_event.aggregate_type=verification.aggregate_type
         and verification_event.aggregate_id=verification.aggregate_id
         and verification_event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
         and verification_event.webauthn_assertion_binding_digest=$8
         and verification_event.payload_cbor=verification.evidence_cbor
         and verification_event.payload_digest=verification.evidence_digest
         and verification_event.cose_sign1=verification.cose_sign1
        join control.session proof_session on proof_session.participant_id=challenge.participant_id
         and proof_session.session_id=challenge.session_id and proof_session.principal_id=challenge.principal_id
        join control.credential step_up_credential
          on step_up_credential.participant_id=challenge.participant_id
         and step_up_credential.credential_id=$13
         and step_up_credential.principal_id=challenge.principal_id
         and step_up_credential.kind='WEBAUTHN' and step_up_credential.state='ACTIVE'
         and step_up_credential.valid_from<=clock_timestamp()
         and (step_up_credential.valid_until is null
              or step_up_credential.valid_until>clock_timestamp())
       where challenge.participant_id=$1 and challenge.mfa_challenge_id=$2
         and challenge.session_id=$3 and challenge.principal_id=$4
         and challenge.action_intent_id=$5 and challenge.resource_digest=$6
         and case when proof_session.step_up_mfa_challenge_id is null
           then challenge.consumed_at>clock_timestamp()-interval '5 minutes'
           else proof_session.step_up_mfa_challenge_id=challenge.mfa_challenge_id
             and openpc.session_step_up_valid_until(challenge.participant_id,challenge.session_id,challenge.principal_id)>clock_timestamp()
           end
         and (challenge.used_at is null or challenge.used_operation_id=$7)
         and not exists (
           select 1 from control.mutation_evidence consumed
            where consumed.participant_id=challenge.participant_id
              and consumed.mfa_challenge_id=challenge.mfa_challenge_id
              and consumed.catalog_operation_id<>'ID-OP-WEBAUTHN-VERIFY'
              and consumed.operation_id<>$7
         )
       for update of challenge`,
    [
      proof.participantId,
      proof.mfaChallengeId,
      proof.webauthnSessionId,
      proof.principalId,
      context.actionIntentId,
      candidateDigest,
      operationId,
      proof.webauthnAssertionBindingDigest,
      proof.webauthnEvidenceCbor,
      proof.webauthnEvidenceDigest,
      proof.webauthnCoseSign1,
      proof.privacyDomainId,
      proof.webauthnSignerCredentialId,
    ],
  );
  const stepUpSigner = challenge.rows[0];
  if (
    challenge.rowCount !== 1 ||
    stepUpSigner === undefined ||
    !createHash('sha256')
      .update(stepUpSigner.publicKeySpkiDer)
      .digest()
      .equals(stepUpSigner.publicKeyDigest) ||
    !(await verifyStoredStepUpEvidence(
      client,
      {
        participantId: proof.participantId,
        privacyDomainId: proof.privacyDomainId,
        principalId: proof.principalId,
        credentialId: proof.webauthnSignerCredentialId,
        mfaChallengeId: proof.mfaChallengeId,
        actionIntentId: context.actionIntentId,
        candidateDigest,
        credentialPublicKey: stepUpSigner.publicKeySpkiDer,
        evidenceCbor: proof.webauthnEvidenceCbor,
        coseSign1: proof.webauthnCoseSign1,
      },
      runtimeVerifier,
    ))
  ) {
    throw new ConfigurationRepositoryError('PC-AUTH-0005', undefined, 'step-up-state');
  }
}

async function consumeCandidate(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
): Promise<void> {
  if (context.authorization.approvalRequestId === undefined) return;
  const consumed = await client.query(
    `update control.mutation_candidate candidate
        set state='CONSUMED',consumed_operation_id=$1,updated_at=clock_timestamp()
       from control.approval_request approval
      where approval.participant_id=candidate.participant_id
        and approval.privacy_domain_id=candidate.privacy_domain_id
        and approval.subject_id=candidate.mutation_candidate_id
        and approval.approval_request_id=$2
        and candidate.participant_id=$3 and candidate.privacy_domain_id=$4
        and candidate.action_intent_id=$5 and candidate.resource_id=$6
        and candidate.state='APPROVED'`,
    [
      operationId,
      context.authorization.approvalRequestId,
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.actionIntentId,
      context.resourceId,
    ],
  );
  if (consumed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
}

async function consumeStepUp(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
): Promise<void> {
  const challengeId = context.authorization.mfaChallengeId;
  if (challengeId === undefined) return;
  const consumed = await client.query(
    `update control.mfa_challenge
        set used_at=clock_timestamp(),used_operation_id=$1,row_version=row_version+1
      where participant_id=$2 and mfa_challenge_id=$3 and used_at is null`,
    [operationId, context.authorization.participantId, challengeId],
  );
  if (consumed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
}

async function appendEvidenceAndOutbox(
  client: PoolClient,
  context: MutationContext,
  operationId: string,
  candidateDigest: Buffer,
  revision: string,
  eventType: string,
  business?: { readonly prepared: PreparedBusinessReceipt; readonly state: MutationBusinessState },
): Promise<void> {
  const proof = context.authorization;
  const evidenceId = await persistAuthorizationEvidence(
    client,
    context,
    operationId,
    candidateDigest,
    revision,
  );
  if (business !== undefined) {
    await appendBusinessReceipt(
      client,
      context,
      operationId,
      candidateDigest,
      evidenceId,
      business.state,
      business.prepared,
    );
    return;
  }
  const head = await client.query<{ readonly sequence: string }>(
    `insert into control.outbox_aggregate_head(participant_id,aggregate_type,aggregate_id,last_sequence)
     values ($1,$2,$3,1)
     on conflict (participant_id,aggregate_type,aggregate_id) do update
       set last_sequence=control.outbox_aggregate_head.last_sequence+1,updated_at=clock_timestamp()
     returning last_sequence::text as sequence`,
    [proof.participantId, context.aggregateType, context.resourceId],
  );
  const eventId = uuidv7();
  const payload = Buffer.from(
    canonicalJson({
      aggregateId: context.resourceId,
      aggregateType: context.aggregateType,
      authorizationEvidenceDigest: `sha256:${proof.evidenceDigest.toString('hex')}`,
      candidateDigest: `sha256:${candidateDigest.toString('hex')}`,
      eventId,
      eventType,
      participantId: proof.participantId,
      privacyDomainId: proof.privacyDomainId,
      revision,
    }),
    'utf8',
  );
  await client.query(
    `insert into control.outbox_event
      (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
       aggregate_sequence,payload_cbor,payload_digest,cose_sign1,webauthn_assertion_binding_digest,occurred_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())`,
    [
      proof.participantId,
      proof.privacyDomainId,
      eventId,
      eventType,
      context.aggregateType,
      context.resourceId,
      requireOne(head.rows, 'PC-DATA-6007').sequence,
      payload,
      createHash('sha256').update(payload).digest(),
      proof.coseSign1,
      proof.webauthnAssertionBindingDigest ?? null,
    ],
  );
}

/** A source owner's read fence lives through the actual commit or rollback,
 * including receipt signing. Each serialization retry acquires a fresh fence. */
export interface MutationCommitFence {
  revalidate(): Promise<void>;
  release(): Promise<void>;
}

export class AtomicConfigurationMutation {
  constructor(
    private readonly pool: Pool,
    private readonly identityRuntimeVerifier?: IdentityRuntimeVerifier,
    private readonly businessEvidence?: ConfigurationBusinessEvidence,
    private readonly validateScope?: (
      client: PoolClient,
      context: MutationContext,
    ) => Promise<void>,
  ) {}

  async execute<T>(
    context: MutationContext,
    write: MutationWriter<T>,
    profileVersion?: (client: PoolClient) => Promise<number>,
    acquireCommitFence?: (client: PoolClient) => Promise<MutationCommitFence>,
    authorityDependencies?: (client: PoolClient) => Promise<AuthorityFence>,
  ): Promise<OperationRecord> {
    const operationId = uuidv7();
    const candidateDigest = bytesForDigest(sha256(context.candidate));
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const client = await this.pool.connect();
      let commitFence: MutationCommitFence | undefined;
      let producerGateComplete = false;
      let discardClient = false;
      try {
        await beginScopedTransaction(client, context, operationId);
        producerGateComplete = true;
        const reservation = await reserveIdempotency<OperationRecord>(
          client,
          context,
          operationId,
          candidateDigest,
        );
        const action = await actionIntent(client, context);
        // Owning scope restrictions deny before discovering a signing key. This
        // check grants no authority; the ordinary fences and SQL guards remain.
        await this.validateScope?.(client, context);
        const profile =
          this.businessEvidence === undefined || reservation.replay !== undefined
            ? undefined
            : businessTransitionProfileForOperation(
                context.catalogOperationId,
                profileVersion === undefined ? 1 : await profileVersion(client),
              );
        const signingScope: BusinessSigningScope | undefined =
          profile === undefined
            ? undefined
            : {
                participantId: context.authorization.participantId,
                privacyDomainId: context.authorization.privacyDomainId,
                environmentId: this.businessEvidence!.environmentId,
                profileId: profile.profileId,
                profileVersion: profile.profileVersion,
                profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
                actionIntentId: profile.actionIntentId,
                catalogOperationId: profile.catalogOperationId,
              };
        const discovery =
          signingScope === undefined || reservation.replay !== undefined
            ? undefined
            : await discoverBusinessSigningKey(client, signingScope);
        const authority = await fenceConfigurationMutation(
          client,
          context,
          action.makerCheckerRequired,
          discovery?.authorityFence,
          await authorityDependencies?.(client),
        );
        await fenceMutationIntent(client, {
          ...context,
          participantId: context.authorization.participantId,
          privacyDomainId: context.authorization.privacyDomainId,
          principalId: context.authorization.principalId,
        });
        await verifyAuthorization(
          client,
          context,
          action,
          reservation.operationId,
          candidateDigest,
          this.identityRuntimeVerifier,
        );
        if (reservation.replay !== undefined) {
          await client.query('commit');
          return reservation.replay;
        }
        let prepared: PreparedBusinessReceipt | undefined;
        if (profile !== undefined && signingScope !== undefined && discovery !== undefined) {
          const key = await fenceBusinessSigningKey(client, signingScope, discovery);
          prepared = {
            profile,
            trust: key.trust,
            signer: this.businessEvidence!.signer,
            authoritySnapshot: await captureAuthoritySnapshot(
              client,
              context.authorization.participantId,
              context.authorization.privacyDomainId,
              operationId,
              authority.authorities,
              authority.fence,
            ),
          };
        }
        commitFence = await acquireCommitFence?.(client);
        const written = await write(client, context.resourceId, operationId, authority);
        if (prepared !== undefined && written.businessState === undefined)
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        if (action.makerCheckerRequired) {
          await consumeCandidate(client, context, reservation.operationId);
        }
        if (action.stepUpRequired) await consumeStepUp(client, context, operationId);
        await appendEvidenceAndOutbox(
          client,
          context,
          operationId,
          candidateDigest,
          written.revision,
          written.outboxEventType,
          prepared === undefined ? undefined : { prepared, state: written.businessState! },
        );
        const times = requireOne(
          (
            await client.query<{ readonly createdAt: string; readonly updatedAt: string }>(
              `select record.created_at::text as "createdAt",evidence.occurred_at::text as "updatedAt"
                 from control.idempotency_record record
                 join control.mutation_evidence evidence
                   on evidence.participant_id=record.participant_id and evidence.operation_id=record.operation_id
                where record.participant_id=$1 and record.operation_id=$2`,
              [context.authorization.participantId, operationId],
            )
          ).rows,
          'PC-DATA-6007',
        );
        const operation: OperationRecord = {
          operationId,
          resourceRef: `urn:openpc:resource:${context.resourceId}`,
          actionIntentId: context.actionIntentId,
          intentDigest: context.actionIntentDigest,
          idempotencyKey: context.idempotencyKey,
          state: written.asynchronous === true ? 'ACCEPTED' : 'SUCCEEDED',
          truthState: written.asynchronous === true ? 'UNKNOWN' : 'SUCCESS',
          createdAt: new Date(times.createdAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
          updatedAt: new Date(times.updatedAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
          revision: written.revision,
        };
        await client.query(
          `update control.idempotency_record set result_digest=$1,result_payload=$2,
            result_aggregate_version=$3,terminal_state='COMMITTED'
            where participant_id=$4 and principal_id=$5 and action_intent_id=$6
              and catalog_operation_id=$7 and idempotency_key=$8`,
          [
            bytesForDigest(sha256(operation)),
            operation,
            written.revision,
            context.authorization.participantId,
            context.authorization.principalId,
            context.actionIntentId,
            context.catalogOperationId,
            context.idempotencyKey,
          ],
        );
        await commitFence?.revalidate();
        if (authorityDependencies !== undefined) {
          await revalidateBoundAuthorities(
            client,
            context.authorization.participantId,
            authority.authorities,
            authority.fence,
          );
          if (signingScope !== undefined && discovery !== undefined)
            await fenceBusinessSigningKey(client, signingScope, discovery);
        }
        await client.query('commit');
        return operation;
      } catch (error) {
        const rolledBack = await client.query('rollback').then(
          () => true,
          () => false,
        );
        discardClient = !rolledBack;
        const producerContention =
          !producerGateComplete &&
          rolledBack &&
          ((runtimeArtifactReferenceProducers.has(context.catalogOperationId) &&
            error instanceof RuntimeArtifactReferenceProducerBusy) ||
            (moduleReferenceProducers.has(context.catalogOperationId) &&
              error instanceof ModuleReferenceProducerBusy) ||
            ([
              'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
              'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH',
            ].includes(context.catalogOperationId) &&
              isRuntimeSourceProducerContention(error)));
        if (!producerContention && !isSerializationFailure(error)) throw error;
        if (attempt === 2) throw new ConfigurationRepositoryError('PC-DATA-6007');
      } finally {
        // Cleanup cannot turn a known committed operation into a retry. Source
        // adapters must bound release, and loss before commit is fail-closed.
        await commitFence?.release().catch(() => undefined);
        client.release(discardClient);
      }
      // 40001 remains a definite transaction abort. Source-gate contention is
      // eligible only before reservation, authority, signer or callback work.
      // Release the connection before backoff; never retry an unknown COMMIT.
      await retryDelay(25 * 2 ** attempt);
    }
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  }
}
