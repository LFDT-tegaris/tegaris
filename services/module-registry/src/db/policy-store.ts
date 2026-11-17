import { isReleaseSimulation } from '../domain/policy-simulation-eligibility.js';
import { createHash, createPublicKey, verify } from 'node:crypto';

import type { Pool, PoolClient } from 'pg';

import {
  decodePolicyActivationAuthorizationPayload,
  verifyPolicyActivationAuthorizationCose,
} from '../domain/policy-activation-authorization.js';
import {
  createVerifiedWebAuthnAssertion,
  verifiedWebAuthnAssertionDigest,
} from '../../../identity-service/src/domain/trust-adapter.js';

const ACTIVATE_OPERATION = 'POL-OP-ACTIVATE';
const ACTIVATE_INTENT = 'ACT-POLICY_ACTIVATE_RELEASE-V1';
const ACTIVATE_AGGREGATE = 'policy-activation';
const ACTIVATE_EVENT = 'openpc.policy.generation.activated.v1';
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface AtomicMutation {
  participantId: string;
  privacyDomainId: string;
  principalId: string;
  checkerPrincipalId: string;
  operationId: string;
  actionIntentId: string;
  catalogOperationId: string;
  idempotencyKey: string;
  aggregateType: string;
  aggregateId: string;
  expectedAggregateVersion: bigint;
  candidateDigest: Buffer;
  approvalRequestId: string;
  mfaChallengeId: string;
  webauthnAssertionBindingDigest: Buffer;
  evidenceCbor: Buffer;
  evidenceDigest: Buffer;
  coseSign1: Buffer;
  payloadCbor: Buffer;
  payloadDigest: Buffer;
  eventId: string;
  eventType: string;
  participantEpoch: bigint;
  principalEpoch: bigint;
  checkerPrincipalEpoch: bigint;
  authorityEnvelopeId: string;
  authorityEpoch: bigint;
  delegationEpoch: bigint;
  envelopeRowVersion: bigint;
  assignmentId: string;
  assignmentRowVersion: bigint;
  checkerCredentialId: string;
  checkerCredentialEpoch: bigint;
  webauthnCredentialPublicKeySpkiDer: Buffer;
  webauthnChallenge: string;
  webauthnOrigin: string;
  webauthnAuthenticatorData: Buffer;
  webauthnClientDataJson: Buffer;
  webauthnSignature: Buffer;
  webauthnVerifiedAt: string;
}

export interface PolicyActivationMutation extends AtomicMutation {
  catalogOperationId: typeof ACTIVATE_OPERATION;
  policySimulationId: string;
  scopeDigest: Buffer;
  dependencyClosureDigest: Buffer;
  exactCohortDigest: Buffer;
  receiptDigest: Buffer;
}

function exactDigest(value: Buffer): boolean {
  return value.length === 32;
}

function isPolicyActivation(input: AtomicMutation): input is PolicyActivationMutation {
  return input.catalogOperationId === ACTIVATE_OPERATION && 'policySimulationId' in input;
}

function replayBinding(input: AtomicMutation): Record<string, string> {
  const evidenceDigest = sha256(input.evidenceCbor);
  const payloadDigest = sha256(input.payloadCbor);
  const common = {
    operationId: input.operationId,
    catalogOperationId: input.catalogOperationId,
    actionIntentId: input.actionIntentId,
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    principalId: input.principalId,
    checkerPrincipalId: input.checkerPrincipalId,
    aggregateType: input.aggregateType,
    aggregateId: input.aggregateId,
    expectedAggregateVersion: input.expectedAggregateVersion.toString(),
    candidateDigest: input.candidateDigest.toString('hex'),
    approvalRequestId: input.approvalRequestId,
    mfaChallengeId: input.mfaChallengeId,
    webauthnAssertionBindingDigest: input.webauthnAssertionBindingDigest.toString('hex'),
    participantEpoch: input.participantEpoch.toString(),
    principalEpoch: input.principalEpoch.toString(),
    checkerPrincipalEpoch: input.checkerPrincipalEpoch.toString(),
    authorityEnvelopeId: input.authorityEnvelopeId,
    authorityEpoch: input.authorityEpoch.toString(),
    delegationEpoch: input.delegationEpoch.toString(),
    envelopeRowVersion: input.envelopeRowVersion.toString(),
    assignmentId: input.assignmentId,
    assignmentRowVersion: input.assignmentRowVersion.toString(),
    checkerCredentialId: input.checkerCredentialId,
    checkerCredentialEpoch: input.checkerCredentialEpoch.toString(),
    evidenceDigest: evidenceDigest.toString('hex'),
    declaredEvidenceDigest: input.evidenceDigest.toString('hex'),
    payloadDigest: payloadDigest.toString('hex'),
    declaredPayloadDigest: input.payloadDigest.toString('hex'),
    coseSign1Digest: sha256(input.coseSign1).toString('hex'),
    eventId: input.eventId,
    eventType: input.eventType,
    webauthnCredentialPublicKeySpkiDer: input.webauthnCredentialPublicKeySpkiDer.toString('hex'),
    webauthnChallenge: input.webauthnChallenge,
    webauthnOrigin: input.webauthnOrigin,
    webauthnAuthenticatorData: input.webauthnAuthenticatorData.toString('hex'),
    webauthnClientDataJson: input.webauthnClientDataJson.toString('hex'),
    webauthnSignature: input.webauthnSignature.toString('hex'),
    webauthnVerifiedAt: input.webauthnVerifiedAt,
  };
  return isPolicyActivation(input)
    ? {
        ...common,
        policySimulationId: input.policySimulationId,
        scopeDigest: input.scopeDigest.toString('hex'),
        dependencyClosureDigest: input.dependencyClosureDigest.toString('hex'),
        exactCohortDigest: input.exactCohortDigest.toString('hex'),
        receiptDigest: input.receiptDigest.toString('hex'),
      }
    : common;
}

function stableRecord(value: Record<string, unknown>): string {
  return JSON.stringify(
    Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right))),
  );
}

function sha256(value: string | Buffer): Buffer {
  return createHash('sha256').update(value).digest();
}

function verifiesBoundWebAuthnAssertion(
  row: Record<string, unknown>,
  input: PolicyActivationMutation,
  current: Date,
): boolean {
  try {
    if (
      !Buffer.isBuffer(row.public_key_spki_der) ||
      !Buffer.isBuffer(row.public_key_digest) ||
      !Buffer.isBuffer(row.rp_id_hash) ||
      !row.public_key_spki_der.equals(input.webauthnCredentialPublicKeySpkiDer) ||
      !sha256(row.public_key_spki_der).equals(row.public_key_digest) ||
      input.webauthnAuthenticatorData.length !== 37 ||
      !input.webauthnAuthenticatorData.subarray(0, 32).equals(row.rp_id_hash) ||
      (input.webauthnAuthenticatorData[32]! & 0x05) !== 0x05
    )
      return false;
    const clientData = JSON.parse(input.webauthnClientDataJson.toString('utf8')) as Record<
      string,
      unknown
    >;
    if (
      JSON.stringify(Object.keys(clientData).sort()) !==
        JSON.stringify(['challenge', 'origin', 'type']) ||
      clientData.type !== 'webauthn.get' ||
      clientData.challenge !== input.webauthnChallenge ||
      clientData.origin !== input.webauthnOrigin
    )
      return false;
    const verifiedAt = new Date(input.webauthnVerifiedAt);
    if (
      Number.isNaN(verifiedAt.getTime()) ||
      current.getTime() - verifiedAt.getTime() > 5 * 60 * 1000 ||
      verifiedAt.getTime() > current.getTime() + 5_000
    )
      return false;
    const signedBytes = Buffer.concat([
      input.webauthnAuthenticatorData,
      sha256(input.webauthnClientDataJson),
    ]);
    if (
      !verify(
        'sha256',
        signedBytes,
        createPublicKey({
          key: input.webauthnCredentialPublicKeySpkiDer,
          format: 'der',
          type: 'spki',
        }),
        input.webauthnSignature,
      )
    )
      return false;
    const assertion = createVerifiedWebAuthnAssertion({
      credentialId: input.checkerCredentialId,
      credentialPublicKeyDigest: `sha256:${sha256(input.webauthnCredentialPublicKeySpkiDer).toString('hex')}`,
      principalId: input.checkerPrincipalId,
      sessionId: String(row.challenge_session_id),
      actionIntentId: ACTIVATE_INTENT,
      resourceDigest: `sha256:${input.candidateDigest.toString('hex')}`,
      challengeDigest: `sha256:${sha256(input.webauthnChallenge).toString('hex')}`,
      rpIdHash: `sha256:${row.rp_id_hash.toString('hex')}`,
      origin: input.webauthnOrigin,
      authenticatorDataDigest: `sha256:${sha256(input.webauthnAuthenticatorData).toString('hex')}`,
      clientDataJsonDigest: `sha256:${sha256(input.webauthnClientDataJson).toString('hex')}`,
      signatureDigest: `sha256:${sha256(input.webauthnSignature).toString('hex')}`,
      signCount: String(input.webauthnAuthenticatorData.readUInt32BE(33)),
      verifiedAt: input.webauthnVerifiedAt,
    });
    return verifiedWebAuthnAssertionDigest(assertion).equals(input.webauthnAssertionBindingDigest);
  } catch {
    return false;
  }
}

export interface SignedActivationArtifactContext {
  readonly participantId: string;
  readonly checkerPrincipalId: string;
  readonly checkerPrincipalEpoch: bigint;
  readonly publicKeySpkiDer: Buffer;
  readonly decisionEvidenceCbor: Buffer;
  readonly decisionCoseSign1: Buffer;
  readonly decision: string;
  readonly decisionAggregateVersion: bigint;
  readonly currentTime: Date;
}

export function validateSignedActivationArtifacts(
  context: SignedActivationArtifactContext,
  input: Pick<
    PolicyActivationMutation,
    | 'participantId'
    | 'checkerPrincipalId'
    | 'checkerPrincipalEpoch'
    | 'catalogOperationId'
    | 'actionIntentId'
    | 'candidateDigest'
    | 'approvalRequestId'
    | 'aggregateType'
    | 'aggregateId'
    | 'expectedAggregateVersion'
    | 'evidenceCbor'
    | 'evidenceDigest'
    | 'payloadCbor'
    | 'payloadDigest'
    | 'coseSign1'
    | 'receiptDigest'
  >,
): boolean {
  const decisionEvidence = context.decisionEvidenceCbor;
  const decisionCose = context.decisionCoseSign1;
  const publicKey = context.publicKeySpkiDer;
  if (
    !input.evidenceCbor.equals(input.payloadCbor) ||
    !sha256(input.evidenceCbor).equals(input.evidenceDigest) ||
    !sha256(input.payloadCbor).equals(input.payloadDigest) ||
    !input.evidenceDigest.equals(input.payloadDigest) ||
    !sha256(input.coseSign1).equals(input.receiptDigest) ||
    !decisionEvidence.equals(input.evidenceCbor) ||
    !sha256(decisionEvidence).equals(input.evidenceDigest) ||
    !decisionCose.equals(input.coseSign1)
  ) {
    return false;
  }
  try {
    const authorization = decodePolicyActivationAuthorizationPayload(input.evidenceCbor);
    return (
      authorization.participantId === `urn:openpc:participant:${context.participantId}` &&
      authorization.participantId === `urn:openpc:participant:${input.participantId}` &&
      authorization.checkerPrincipalId === `urn:openpc:principal:${context.checkerPrincipalId}` &&
      authorization.checkerPrincipalId === `urn:openpc:principal:${input.checkerPrincipalId}` &&
      authorization.checkerPrincipalEpoch === context.checkerPrincipalEpoch.toString() &&
      authorization.checkerPrincipalEpoch === input.checkerPrincipalEpoch.toString() &&
      authorization.operationId === input.catalogOperationId &&
      authorization.actionIntentId === input.actionIntentId &&
      authorization.candidateDigest.equals(input.candidateDigest) &&
      authorization.approvalRequestId === input.approvalRequestId &&
      authorization.aggregateType === input.aggregateType &&
      authorization.aggregateId === input.aggregateId &&
      authorization.aggregateVersion === input.expectedAggregateVersion.toString() &&
      authorization.aggregateVersion === context.decisionAggregateVersion.toString() &&
      authorization.decision === context.decision &&
      Date.parse(authorization.issuedAt) <= context.currentTime.getTime() &&
      Date.parse(authorization.expiresAt) > context.currentTime.getTime() &&
      verifyPolicyActivationAuthorizationCose(publicKey, input.evidenceCbor, input.coseSign1)
    );
  } catch {
    return false;
  }
}

function verifiesSignedActivationArtifacts(
  row: Record<string, unknown>,
  input: PolicyActivationMutation,
  current: Date,
): boolean {
  if (
    !Buffer.isBuffer(row.decision_evidence_cbor) ||
    !Buffer.isBuffer(row.decision_cose_sign1) ||
    !Buffer.isBuffer(row.public_key_spki_der)
  )
    return false;
  return validateSignedActivationArtifacts(
    {
      participantId: input.participantId,
      checkerPrincipalId: input.checkerPrincipalId,
      checkerPrincipalEpoch: input.checkerPrincipalEpoch,
      publicKeySpkiDer: row.public_key_spki_der,
      decisionEvidenceCbor: row.decision_evidence_cbor,
      decisionCoseSign1: row.decision_cose_sign1,
      decision: String(row.decision),
      decisionAggregateVersion: BigInt(String(row.decision_aggregate_version)),
      currentTime: current,
    },
    input,
  );
}

async function recordEvidenceAndOutbox(client: PoolClient, input: AtomicMutation, version: bigint) {
  const sharedBinding = ['ID-OP-WEBAUTHN-VERIFY', ACTIVATE_OPERATION].includes(
    input.catalogOperationId,
  )
    ? input.webauthnAssertionBindingDigest
    : null;
  await client.query(
    `insert into control.mutation_evidence
    (participant_id,privacy_domain_id,operation_id,principal_id,checker_principal_id,action_intent_id,catalog_operation_id,aggregate_type,aggregate_id,aggregate_version,candidate_digest,approval_request_id,mfa_challenge_id,bound_participant_epoch,bound_principal_epoch,bound_authority_envelope_id,bound_envelope_epoch,bound_assignment_id,signer_credential_id,webauthn_assertion_binding_digest,evidence_cbor,evidence_digest,cose_sign1)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
    [
      input.participantId,
      input.privacyDomainId,
      input.operationId,
      input.principalId,
      input.checkerPrincipalId,
      input.actionIntentId,
      input.catalogOperationId,
      input.aggregateType,
      input.aggregateId,
      version,
      input.candidateDigest,
      input.approvalRequestId,
      input.mfaChallengeId,
      input.participantEpoch,
      input.principalEpoch,
      input.authorityEnvelopeId,
      input.authorityEpoch,
      input.assignmentId,
      input.checkerCredentialId,
      sharedBinding,
      input.evidenceCbor,
      input.evidenceDigest,
      input.coseSign1,
    ],
  );
  const head = await client.query(
    `insert into control.outbox_aggregate_head (participant_id,aggregate_type,aggregate_id,last_sequence) values ($1,$2,$3,$4)
    on conflict (participant_id,aggregate_type,aggregate_id) do update set last_sequence=excluded.last_sequence,updated_at=clock_timestamp()
    where control.outbox_aggregate_head.last_sequence=$4-1 returning last_sequence`,
    [input.participantId, input.aggregateType, input.aggregateId, version],
  );
  if (head.rowCount !== 1) throw new Error('OUTBOX_SEQUENCE_CONFLICT');
  await client.query(
    `insert into control.outbox_event (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,aggregate_sequence,payload_cbor,payload_digest,cose_sign1,webauthn_assertion_binding_digest,occurred_at)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())`,
    [
      input.participantId,
      input.privacyDomainId,
      input.eventId,
      input.eventType,
      input.aggregateType,
      input.aggregateId,
      version,
      input.payloadCbor,
      input.payloadDigest,
      input.coseSign1,
      sharedBinding,
    ],
  );
  const committed = await client.query(
    `update control.idempotency_record set result_aggregate_version=$1,result_digest=$2,result_payload=$3,terminal_state='COMMITTED'
    where participant_id=$4 and principal_id=$5 and action_intent_id=$6 and catalog_operation_id=$7 and idempotency_key=$8
      and webauthn_assertion_binding_digest is not distinct from $9`,
    [
      version,
      input.payloadDigest,
      {
        ...replayBinding(input),
        resultAggregateVersion: version.toString(),
      },
      input.participantId,
      input.principalId,
      input.actionIntentId,
      input.catalogOperationId,
      input.idempotencyKey,
      sharedBinding,
    ],
  );
  if (committed.rowCount !== 1) throw new Error('IDEMPOTENCY_BINDING_CONFLICT');
}

export async function atomicPolicyMutation<T>(
  pool: Pool,
  input: AtomicMutation,
  mutate: (client: PoolClient) => Promise<{ value: T; resultVersion: bigint }>,
  decodeReplay: (payload: unknown) => T = (payload) => payload as T,
  validateReplay?: (client: PoolClient) => Promise<void>,
): Promise<T> {
  if (!exactDigest(input.webauthnAssertionBindingDigest))
    throw new Error('WEBAUTHN_BINDING_REQUIRED');
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const client = await pool.connect();
    try {
      await client.query('begin isolation level serializable');
      await client.query('select openpc.set_request_context($1,$2,$3,$4,$5,true)', [
        'PARTICIPANT',
        input.participantId,
        input.privacyDomainId,
        input.operationId,
        input.actionIntentId,
      ]);
      const scope = await client.query(
        `select 1 from control.participant participant
          join control.privacy_domain privacy
            on privacy.participant_id=participant.participant_id
           and privacy.privacy_domain_id=$2 and privacy.state='ACTIVE'
         where participant.participant_id=$1 and participant.state='ACTIVE'`,
        [input.participantId, input.privacyDomainId],
      );
      if (scope.rowCount !== 1) throw new Error('PC-POLICY-2005');
      const claim = await client.query(
        `insert into control.idempotency_record (participant_id,principal_id,action_intent_id,catalog_operation_id,idempotency_key,operation_id,input_digest,webauthn_assertion_binding_digest,expected_aggregate_version,expires_at,privacy_domain_id)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '24 hours',$10) on conflict do nothing returning operation_id`,
        [
          input.participantId,
          input.principalId,
          input.actionIntentId,
          input.catalogOperationId,
          input.idempotencyKey,
          input.operationId,
          input.candidateDigest,
          ['ID-OP-WEBAUTHN-VERIFY', ACTIVATE_OPERATION].includes(input.catalogOperationId)
            ? input.webauthnAssertionBindingDigest
            : null,
          input.expectedAggregateVersion,
          input.privacyDomainId,
        ],
      );
      if (claim.rowCount !== 1) {
        const replay = await client.query(
          `select operation_id,input_digest,webauthn_assertion_binding_digest,expected_aggregate_version,
                  result_aggregate_version,result_payload,terminal_state
             from control.idempotency_record
            where participant_id=$1 and principal_id=$2 and action_intent_id=$3
              and catalog_operation_id=$4 and idempotency_key=$5 for share`,
          [
            input.participantId,
            input.principalId,
            input.actionIntentId,
            input.catalogOperationId,
            input.idempotencyKey,
          ],
        );
        const row = replay.rows[0] as
          | {
              input_digest?: Buffer;
              webauthn_assertion_binding_digest?: Buffer;
              operation_id?: string;
              expected_aggregate_version?: string;
              result_aggregate_version?: string;
              result_payload?: unknown;
              terminal_state?: string;
            }
          | undefined;
        if (
          row?.terminal_state !== 'COMMITTED' ||
          row.input_digest === undefined ||
          row.result_payload === null ||
          typeof row.result_payload !== 'object' ||
          String(row.operation_id) !== input.operationId ||
          BigInt(String(row.expected_aggregate_version)) !== input.expectedAggregateVersion ||
          BigInt(String(row.result_aggregate_version)) !== input.expectedAggregateVersion + 1n ||
          !row.input_digest.equals(input.candidateDigest) ||
          !Buffer.isBuffer(row.webauthn_assertion_binding_digest) ||
          !row.webauthn_assertion_binding_digest.equals(input.webauthnAssertionBindingDigest) ||
          stableRecord(row.result_payload as Record<string, unknown>) !==
            stableRecord({
              ...replayBinding(input),
              resultAggregateVersion: String(row.result_aggregate_version),
            })
        )
          throw new Error('IDEMPOTENCY_CONFLICT');
        await validateReplay?.(client);
        await client.query('commit');
        return decodeReplay(row.result_payload);
      }
      const result = await mutate(client);
      if (result.resultVersion !== input.expectedAggregateVersion + 1n)
        throw new Error('AGGREGATE_VERSION_CONFLICT');
      await recordEvidenceAndOutbox(client, input, result.resultVersion);
      await client.query('commit');
      return result.value;
    } catch (error) {
      await client.query('rollback');
      if (
        attempt < 3 &&
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === '40001'
      )
        continue;
      throw error;
    } finally {
      client.release();
    }
  }
  throw new Error('SERIALIZABLE_RETRY_EXHAUSTED');
}

async function validateActivation(
  client: PoolClient,
  input: PolicyActivationMutation,
  activationId: string,
  mode: 'MUTATE' | 'REPLAY',
) {
  if (
    input.catalogOperationId !== ACTIVATE_OPERATION ||
    input.actionIntentId !== ACTIVATE_INTENT ||
    input.aggregateType !== ACTIVATE_AGGREGATE ||
    input.aggregateId !== activationId ||
    input.eventType !== ACTIVATE_EVENT ||
    !UUID_V7.test(input.eventId) ||
    input.principalId === input.checkerPrincipalId ||
    ![
      input.candidateDigest,
      input.scopeDigest,
      input.dependencyClosureDigest,
      input.exactCohortDigest,
      input.receiptDigest,
      input.evidenceDigest,
      input.payloadDigest,
    ].every(exactDigest)
  )
    throw new Error('PC-POLICY-2004');

  const result = await client.query(
    `select
      participant.authority_epoch participant_epoch,
      maker.authority_epoch principal_epoch, maker.state maker_state,
      checker.authority_epoch checker_epoch, checker.state checker_state,
      envelope.authority_epoch, envelope.delegation_epoch, envelope.row_version envelope_row_version,
      envelope.principal_id envelope_principal_id,
      envelope.state envelope_state, envelope.valid_from, envelope.valid_until,
      envelope.privacy_domain_ids envelope_privacy_domain_ids,
      envelope.action_intent_ids envelope_action_intent_ids,
      envelope.resource_ids envelope_resource_ids,
      assignment.delegation_epoch assignment_delegation_epoch, assignment.row_version assignment_row_version,
      assignment.principal_id assignment_principal_id,
      assignment.authority_envelope_id assignment_authority_envelope_id,
      assignment.state assignment_state, assignment.valid_during, assignment.scope_digest assignment_scope_digest,
      assignment.privacy_domain_ids assignment_privacy_domain_ids,
      assignment.action_intent_ids assignment_action_intent_ids,
      assignment.resource_ids assignment_resource_ids,
      credential.kind credential_kind, credential.public_key_digest, credential.public_key_spki_der,
      credential.participant_id credential_participant_id,
      credential.principal_id credential_principal_id,
      credential.credential_epoch, credential.state credential_state,
      credential.valid_from credential_valid_from, credential.valid_until credential_valid_until,
      approval.action_intent_id approval_action_intent_id, approval.subject_id,
      approval.subject_digest, approval.subject_version, approval.maker_principal_id,
      approval.state approval_state, approval.created_at approval_created_at,
      approval.expires_at approval_expires_at,
      decision.approver_principal_epoch, decision.approver_envelope_epoch,
      decision.approver_authority_envelope_id, decision.approver_assignment_id,
      decision.signer_credential_id, decision.privacy_domain_id decision_privacy_domain_id,
      decision.aggregate_version decision_aggregate_version, decision.candidate_digest decision_candidate_digest,
      decision.decision, decision.decided_at,
      decision.evidence_cbor decision_evidence_cbor,
      decision.cose_sign1 decision_cose_sign1,
      challenge.action_intent_id challenge_action_intent_id,
      challenge.principal_id challenge_principal_id, challenge.session_id challenge_session_id,
      challenge.resource_digest challenge_resource_digest,
      challenge.challenge_digest, challenge.rp_id_hash, challenge.created_at challenge_created_at,
      challenge.expires_at challenge_expires_at, challenge.consumed_at, challenge.used_at,
      challenge.used_operation_id,
      session.principal_id session_principal_id, session.participant_id session_participant_id,
      session.state session_state, session.authority_epoch session_authority_epoch,
      session.participant_epoch session_participant_epoch,
      session.delegation_epoch session_delegation_epoch,
      session.idle_expires_at session_idle_expires_at,
      session.absolute_expires_at session_absolute_expires_at,
      version.policy_version_id, version.semantic_digest, version.schema_digest,
      simulation.simulation_id, simulation.input_digest, simulation.fact_generation_digest simulation_fact_digest,
      simulation.dependency_closure_digest simulation_dependency_digest, simulation.truth_state,
      simulation.authority_label, simulation.result_document simulation_result_document, simulation.result_digest simulation_result_digest,
      generation.policy_generation_id, generation.scope_digest, generation.generation_digest,
      generation.fact_generation_digest, generation.dependency_closure_digest,
      generation.state generation_state, generation.approval_request_id, generation.created_at generation_created_at,
      activation.approval_request_id activation_approval_request_id,
      activation.mfa_challenge_id activation_mfa_challenge_id,
      activation.webauthn_assertion_binding_digest activation_webauthn_binding_digest,
      activation.exact_cohort_digest, activation.prior_generation_digest,
      activation.state activation_state, activation.row_version
    from control.policy_activation activation
    join control.policy_generation generation
      on (generation.participant_id,generation.privacy_domain_id,generation.policy_generation_id)=
         (activation.participant_id,activation.privacy_domain_id,activation.policy_generation_id)
    join control.policy_version version
      on (version.participant_id,version.privacy_domain_id,version.policy_version_id)=
         (generation.participant_id,generation.privacy_domain_id,generation.policy_version_id)
    join control.policy_simulation simulation
      on (simulation.participant_id,simulation.privacy_domain_id,simulation.simulation_id)=
         (generation.participant_id,generation.privacy_domain_id,generation.simulation_id)
    join control.approval_request approval
      on (approval.participant_id,approval.approval_request_id)=
         (generation.participant_id,generation.approval_request_id)
    join control.approval_decision_record decision
      on decision.participant_id=approval.participant_id
     and decision.approval_request_id=approval.approval_request_id
     and decision.approver_principal_id=$4
    join control.participant participant on participant.participant_id=activation.participant_id
    join control.principal maker
      on (maker.participant_id,maker.principal_id)=(activation.participant_id,$5)
    join control.principal checker
      on (checker.participant_id,checker.principal_id)=(activation.participant_id,$4)
    join control.authority_envelope envelope
      on (envelope.participant_id,envelope.authority_envelope_id)=
         (decision.participant_id,decision.approver_authority_envelope_id)
    join control.assignment assignment
      on (assignment.participant_id,assignment.assignment_id)=
         (decision.participant_id,decision.approver_assignment_id)
    join control.credential credential
      on (credential.participant_id,credential.principal_id,credential.credential_id)=
         (decision.participant_id,decision.approver_principal_id,decision.signer_credential_id)
    join control.mfa_challenge challenge
      on (challenge.participant_id,challenge.principal_id,challenge.mfa_challenge_id)=($2,$4,$6)
    join control.session session
      on (session.participant_id,session.principal_id,session.session_id)=
         (challenge.participant_id,challenge.principal_id,challenge.session_id)
    where activation.policy_activation_id=$1
      and activation.participant_id=$2 and activation.privacy_domain_id=$3
      and simulation.simulation_id=$7 and approval.approval_request_id=$8
      and envelope.authority_envelope_id=$9 and assignment.assignment_id=$10
      and credential.credential_id=$11
    for update of activation,generation,approval,challenge`,
    [
      activationId,
      input.participantId,
      input.privacyDomainId,
      input.checkerPrincipalId,
      input.principalId,
      input.mfaChallengeId,
      input.policySimulationId,
      input.approvalRequestId,
      input.authorityEnvelopeId,
      input.assignmentId,
      input.checkerCredentialId,
    ],
  );
  if (result.rowCount !== 1) throw new Error('PC-POLICY-2005');
  const row = result.rows[0] as Record<string, unknown>;
  const equalBuffer = (field: string, expected: Buffer) =>
    Buffer.isBuffer(row[field]) && (row[field] as Buffer).equals(expected);
  const equalEpoch = (field: string, expected: bigint) => BigInt(String(row[field])) === expected;
  const includes = (field: string, expected: string) =>
    Array.isArray(row[field]) && (row[field] as unknown[]).map(String).includes(expected);
  const current = new Date();
  const webauthnValid = verifiesBoundWebAuthnAssertion(row, input, current);
  const signedArtifactsValid = verifiesSignedActivationArtifacts(row, input, current);
  if (
    row.maker_state !== 'ACTIVE' ||
    row.checker_state !== 'ACTIVE' ||
    row.envelope_state !== 'ACTIVE' ||
    row.assignment_state !== 'ACTIVE' ||
    row.credential_state !== 'ACTIVE' ||
    row.credential_kind !== 'WEBAUTHN' ||
    !Buffer.isBuffer(row.public_key_digest) ||
    row.approval_state !== 'APPROVED' ||
    row.decision !== 'APPROVE' ||
    !isReleaseSimulation({
      truthState: row.truth_state,
      authorityLabel: row.authority_label,
      resultDocument: row.simulation_result_document,
      inputDigest: row.input_digest as Buffer,
      resultDigest: row.simulation_result_digest as Buffer,
    }) ||
    row.generation_state !== (mode === 'MUTATE' ? 'PREPARED' : 'ACTIVE') ||
    row.activation_state !== (mode === 'MUTATE' ? 'PREPARED' : 'ACTIVE') ||
    row.consumed_at === null ||
    (mode === 'MUTATE'
      ? row.used_at !== null && String(row.used_operation_id) !== input.operationId
      : row.used_at === null || String(row.used_operation_id) !== input.operationId) ||
    row.session_state !== 'ACTIVE' ||
    String(row.approval_action_intent_id) !== 'ACT-POLICY_APPROVE_REQUEST-V1' ||
    String(row.challenge_action_intent_id) !== ACTIVATE_INTENT ||
    String(row.maker_principal_id) !== input.principalId ||
    String(row.policy_version_id) !== String(row.subject_id) ||
    String(row.approval_request_id) !== input.approvalRequestId ||
    String(row.activation_approval_request_id) !== input.approvalRequestId ||
    String(row.activation_mfa_challenge_id) !== input.mfaChallengeId ||
    String(row.envelope_principal_id) !== input.checkerPrincipalId ||
    String(row.assignment_principal_id) !== input.checkerPrincipalId ||
    String(row.assignment_authority_envelope_id) !== input.authorityEnvelopeId ||
    String(row.credential_participant_id) !== input.participantId ||
    String(row.credential_principal_id) !== input.checkerPrincipalId ||
    String(row.challenge_principal_id) !== input.checkerPrincipalId ||
    String(row.session_principal_id) !== input.checkerPrincipalId ||
    String(row.session_participant_id) !== input.participantId ||
    String(row.approver_authority_envelope_id) !== input.authorityEnvelopeId ||
    String(row.approver_assignment_id) !== input.assignmentId ||
    String(row.signer_credential_id) !== input.checkerCredentialId ||
    String(row.decision_privacy_domain_id) !== input.privacyDomainId ||
    !equalEpoch('participant_epoch', input.participantEpoch) ||
    !equalEpoch('principal_epoch', input.principalEpoch) ||
    !equalEpoch('checker_epoch', input.checkerPrincipalEpoch) ||
    !equalEpoch('authority_epoch', input.authorityEpoch) ||
    !equalEpoch('delegation_epoch', input.delegationEpoch) ||
    !equalEpoch('assignment_delegation_epoch', input.delegationEpoch) ||
    !equalEpoch('session_authority_epoch', input.authorityEpoch) ||
    !equalEpoch('session_participant_epoch', input.participantEpoch) ||
    !equalEpoch('session_delegation_epoch', input.delegationEpoch) ||
    !equalEpoch('envelope_row_version', input.envelopeRowVersion) ||
    !equalEpoch('assignment_row_version', input.assignmentRowVersion) ||
    !equalEpoch('credential_epoch', input.checkerCredentialEpoch) ||
    !equalEpoch('approver_principal_epoch', input.checkerPrincipalEpoch) ||
    !equalEpoch('approver_envelope_epoch', input.authorityEpoch) ||
    !equalEpoch('decision_aggregate_version', BigInt(String(row.subject_version))) ||
    !equalEpoch(
      'row_version',
      mode === 'MUTATE' ? input.expectedAggregateVersion : input.expectedAggregateVersion + 1n,
    ) ||
    !equalBuffer('semantic_digest', input.candidateDigest) ||
    !equalBuffer('subject_digest', input.candidateDigest) ||
    !equalBuffer('decision_candidate_digest', input.candidateDigest) ||
    !equalBuffer('challenge_resource_digest', input.candidateDigest) ||
    !equalBuffer('challenge_digest', sha256(input.webauthnChallenge)) ||
    !equalBuffer('activation_webauthn_binding_digest', input.webauthnAssertionBindingDigest) ||
    !equalBuffer('input_digest', input.candidateDigest) ||
    !equalBuffer('scope_digest', input.scopeDigest) ||
    !equalBuffer('assignment_scope_digest', input.scopeDigest) ||
    !equalBuffer('dependency_closure_digest', input.dependencyClosureDigest) ||
    !equalBuffer('simulation_dependency_digest', input.dependencyClosureDigest) ||
    !equalBuffer('fact_generation_digest', row.simulation_fact_digest as Buffer) ||
    !equalBuffer('exact_cohort_digest', input.exactCohortDigest) ||
    !includes('envelope_privacy_domain_ids', input.privacyDomainId) ||
    !includes('envelope_action_intent_ids', ACTIVATE_INTENT) ||
    !includes('envelope_resource_ids', String(row.policy_version_id)) ||
    !includes('assignment_privacy_domain_ids', input.privacyDomainId) ||
    !includes('assignment_action_intent_ids', ACTIVATE_INTENT) ||
    !includes('assignment_resource_ids', String(row.policy_version_id)) ||
    new Date(String(row.approval_expires_at)) <= current ||
    new Date(String(row.decided_at)) < new Date(String(row.approval_created_at)) ||
    current.getTime() - new Date(String(row.decided_at)).getTime() > 30 * 60 * 1000 ||
    new Date(String(row.challenge_expires_at)) <= current ||
    new Date(String(row.consumed_at)) < new Date(String(row.challenge_created_at)) ||
    current.getTime() - new Date(String(row.consumed_at)).getTime() > 5 * 60 * 1000 ||
    new Date(String(row.session_idle_expires_at)) <= current ||
    new Date(String(row.session_absolute_expires_at)) <= current ||
    new Date(String(row.valid_from)) > current ||
    (row.valid_until !== null && new Date(String(row.valid_until)) <= current) ||
    new Date(String(row.credential_valid_from)) > current ||
    (row.credential_valid_until !== null &&
      new Date(String(row.credential_valid_until)) <= current) ||
    !webauthnValid ||
    !signedArtifactsValid
  )
    throw new Error('PC-POLICY-2005');

  const linkedVerification = await client.query(
    `select evidence.operation_id
       from control.mutation_evidence evidence
       join control.idempotency_record idempotency
         on idempotency.participant_id=evidence.participant_id
        and idempotency.operation_id=evidence.operation_id
        and idempotency.catalog_operation_id=evidence.catalog_operation_id
        and idempotency.terminal_state='COMMITTED'
        and idempotency.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
       join control.outbox_event outbox
         on outbox.participant_id=evidence.participant_id
        and outbox.aggregate_type=evidence.aggregate_type
        and outbox.aggregate_id=evidence.aggregate_id
        and outbox.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
      where evidence.participant_id=$1 and evidence.privacy_domain_id=$2
        and evidence.principal_id=$3 and evidence.mfa_challenge_id=$4
        and evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
        and evidence.aggregate_type='webauthn-verification'
        and evidence.aggregate_id=$5
        and evidence.webauthn_assertion_binding_digest=$6
        and outbox.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
        and evidence.occurred_at>=clock_timestamp()-interval '5 minutes'`,
    [
      input.participantId,
      input.privacyDomainId,
      input.checkerPrincipalId,
      input.mfaChallengeId,
      row.challenge_session_id,
      input.webauthnAssertionBindingDigest,
    ],
  );
  if (linkedVerification.rowCount !== 1) throw new Error('PC-POLICY-2005');

  const prerequisites = await client.query(
    `select count(distinct prerequisite_type)::int count,
            bool_and(ready) ready,
            bool_and(observed_at>= $4::timestamptz) fresh,
            bool_and(
              (prerequisite_type='SIMULATION' and prerequisite_subject_digest=$5) or
              (prerequisite_type='APPROVAL' and prerequisite_subject_digest=$5) or
              (prerequisite_type='FACT_READINESS' and prerequisite_subject_digest=$6) or
              (prerequisite_type='FLEET_READY' and prerequisite_subject_digest=$7) or
              (prerequisite_type='DEPENDENCY_CLOSURE' and prerequisite_subject_digest=$8) or
              (prerequisite_type='CONFLICT_CLOSURE' and prerequisite_subject_digest=$9)
            ) subjects
     from control.policy_activation_prerequisite
     where policy_activation_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
    [
      activationId,
      input.participantId,
      input.privacyDomainId,
      row.generation_created_at,
      input.candidateDigest,
      row.fact_generation_digest,
      input.exactCohortDigest,
      input.dependencyClosureDigest,
      row.generation_digest,
    ],
  );
  const barrier = prerequisites.rows[0] as
    { count?: number; ready?: boolean; fresh?: boolean; subjects?: boolean } | undefined;
  if (barrier?.count !== 6 || !barrier.ready || !barrier.fresh || !barrier.subjects)
    throw new Error('PC-POLICY-2005');
  return row;
}

export async function activatePolicyGeneration(
  pool: Pool,
  input: PolicyActivationMutation,
  activationId: string,
): Promise<void> {
  if (input.catalogOperationId !== ACTIVATE_OPERATION || input.actionIntentId !== ACTIVATE_INTENT)
    throw new Error('PC-POLICY-2004');
  if (!exactDigest(input.receiptDigest)) throw new Error('PC-POLICY-2005');
  await atomicPolicyMutation(
    pool,
    input,
    async (client) => {
      const current = await validateActivation(client, input, activationId, 'MUTATE');
      const result = await client.query(
        `update control.policy_activation
       set state='ACTIVE',receipt_digest=$1,activated_at=clock_timestamp(),row_version=row_version+1
       where policy_activation_id=$2 and participant_id=$3 and privacy_domain_id=$4
         and state='PREPARED' and row_version=$5
       returning row_version`,
        [
          input.receiptDigest,
          activationId,
          input.participantId,
          input.privacyDomainId,
          input.expectedAggregateVersion,
        ],
      );
      if (result.rowCount !== 1) throw new Error('PC-POLICY-2005');
      const retired = await client.query(
        `update control.policy_generation
       set state='RETIRED',active=false
       where participant_id=$1 and privacy_domain_id=$2 and scope_digest=$3 and active=true
         and policy_generation_id<>$4
         and $5::bytea is not null and generation_digest=$5
       returning policy_generation_id`,
        [
          input.participantId,
          input.privacyDomainId,
          input.scopeDigest,
          current.policy_generation_id,
          current.prior_generation_digest ?? null,
        ],
      );
      if (
        (current.prior_generation_digest === null && retired.rowCount !== 0) ||
        (current.prior_generation_digest !== null && retired.rowCount !== 1)
      )
        throw new Error('PC-POLICY-2005');
      if (retired.rowCount === 1) {
        const retiredActivation = await client.query(
          `update control.policy_activation set state='RETIRED',retired_at=clock_timestamp(),row_version=row_version+1
         where participant_id=$1 and privacy_domain_id=$2 and policy_generation_id=$3 and state='ACTIVE'
         returning policy_activation_id`,
          [input.participantId, input.privacyDomainId, retired.rows[0].policy_generation_id],
        );
        if (retiredActivation.rowCount !== 1) throw new Error('PC-POLICY-2005');
      }
      const activated = await client.query(
        `update control.policy_generation set state='ACTIVE',active=true
       where participant_id=$1 and privacy_domain_id=$2 and policy_generation_id=$3
         and scope_digest=$4 and state='PREPARED' returning policy_generation_id`,
        [
          input.participantId,
          input.privacyDomainId,
          current.policy_generation_id,
          input.scopeDigest,
        ],
      );
      if (activated.rowCount !== 1) throw new Error('PC-POLICY-2005');
      const consumed = await client.query(
        `update control.mfa_challenge
            set used_at=clock_timestamp(),used_operation_id=$1,row_version=row_version+1
          where participant_id=$2 and mfa_challenge_id=$3 and used_at is null`,
        [input.operationId, input.participantId, input.mfaChallengeId],
      );
      if (consumed.rowCount !== 1) throw new Error('PC-POLICY-2005');
      return { value: undefined, resultVersion: BigInt(String(result.rows[0].row_version)) };
    },
    () => undefined,
    async (client) => {
      await validateActivation(client, input, activationId, 'REPLAY');
    },
  );
}
