import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  decodeIdentityAuthorityEnvelope,
  identityEnvelopeSigningTrustDigest,
  type IdentityEnvelopeSigningTrust,
} from '@openpc/security-kernel';
import type {
  IdentityRuntimeAssertionVerifier,
  IdentityRuntimeEvidenceSigner,
} from '../../identity-service/src/domain/identity-kernel.js';
import { readInitialEnvelopeActivation } from '../../identity-service/src/db/identity-envelope-activation-store.js';
import {
  readEnvelopeCreation,
  readEnvelopeEffectReadback,
} from '../../identity-service/src/db/identity-envelope-readback.js';
import { validateIdentityEnvelopeProviderObservation } from '../../identity-service/src/domain/identity-envelope-signing-provider.js';

export class IdentityEnvelopeRotationConsumerUnavailable extends Error {
  constructor() {
    super('Identity envelope consumer acceptance unavailable');
  }
}
/** Actual existing typed activation/readback, never a probe or in-memory
 * success. The caller must fence the original custody/selected trust separately.
 * Discovery is read-only; a queued phase must pin the returned original ID. */
export async function readIdentityEnvelopeRotationConsumer(
  client: PoolClient,
  input: {
    trust: IdentityEnvelopeSigningTrust;
    cutoverAtNs: bigint;
    observedAtNs: bigint;
    operationId?: string;
  },
  signer: IdentityRuntimeEvidenceSigner,
) {
  const trust = input.trust;
  const scope = { participantId: trust.participantId, privacyDomainId: trust.privacyDomainId };
  const found = await client.query<ConsumerActivationSelection>(
    `select a.operation_id::text as "operationId",a.envelope_id::text as "envelopeId",a.principal_id::text as "principalId",a.idempotency_key as "idempotencyKey",
 a.reserved_at_ns::text as "reservedAtNs",(floor(extract(epoch from a.committed_at)*1000000)*1000)::text as "committedAtNs"
 from control.identity_envelope_activation a join control.identity_envelope_proposal p using(participant_id,privacy_domain_id,envelope_id)
 join control.authority_envelope e on e.authority_envelope_id=a.envelope_id and e.participant_id=a.participant_id
 where a.participant_id=$1 and a.privacy_domain_id=$2 and a.state='COMMITTED' and a.row_version=4
 and a.request->>'expectedFingerprint'=$3 and a.request->>'trustContextDigest'=$4 and a.reserved_at_ns>=$5
 and e.representation='TYPED_V1' and e.state='ACTIVE' and e.row_version=4 and e.last_mutation_operation_id=a.operation_id
 and e.cose_sign1=a.cose_sign1 and e.semantic_cbor=p.proposal_cbor and e.semantic_digest=p.proposal_digest
 and ($6::uuid is null or a.operation_id=$6) order by a.reserved_at_ns,a.operation_id limit 1 for share of a,e`,
    [
      scope.participantId,
      scope.privacyDomainId,
      trust.signerId,
      identityEnvelopeSigningTrustDigest(trust),
      input.cutoverAtNs.toString(),
      input.operationId ?? null,
    ],
  );
  if (found.rowCount === 0) return undefined;
  const selected = found.rows[0];
  if (found.rowCount !== 1 || !selected) throw new IdentityEnvelopeRotationConsumerUnavailable();
  return authenticateConsumerActivation(client, input, selected, signer, true);
}

interface ConsumerActivationSelection {
  operationId: string;
  envelopeId: string;
  principalId: string;
  idempotencyKey: string;
  reservedAtNs: string;
  committedAtNs: string;
}
interface ConsumerHistoryInput {
  trust: IdentityEnvelopeSigningTrust;
  cutoverAtNs: bigint;
  observedAtNs: bigint;
  operationId: string;
  envelopeId: string;
}

/** Authenticate this exact original typed activation, even if its envelope was
 * later revoked or expired. This is immutable use history, never today's access
 * or key eligibility. The caller must authenticate the signed completion and
 * compare these computed digests, then separately fence current key/selection.
 * No latest-consumer discovery, provider call, signing or database write. */
export async function readHistoricalIdentityEnvelopeRotationConsumer(
  client: PoolClient,
  input: ConsumerHistoryInput,
  verifier: IdentityRuntimeAssertionVerifier,
) {
  const trust = input.trust;
  const found = await client.query<ConsumerActivationSelection>(
    `select a.operation_id::text as "operationId",a.envelope_id::text as "envelopeId",a.principal_id::text as "principalId",a.idempotency_key as "idempotencyKey",
      a.reserved_at_ns::text as "reservedAtNs",(floor(extract(epoch from a.committed_at)*1000000)*1000)::text as "committedAtNs"
    from control.identity_envelope_activation a join control.identity_envelope_proposal p using(participant_id,privacy_domain_id,envelope_id)
    where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and a.envelope_id=$4
      and a.state='COMMITTED' and a.row_version=4 and a.request->>'expectedFingerprint'=$5
      and a.request->>'trustContextDigest'=$6 and a.reserved_at_ns>=$7
      and openpc.matches_participant($1::uuid) and openpc.matches_privacy($2::uuid)
    limit 2 for share of a`,
    [
      trust.participantId,
      trust.privacyDomainId,
      input.operationId,
      input.envelopeId,
      trust.signerId,
      identityEnvelopeSigningTrustDigest(trust),
      input.cutoverAtNs.toString(),
    ],
  );
  const selected = found.rows[0];
  if (
    found.rowCount !== 1 ||
    !selected ||
    selected.operationId !== input.operationId ||
    selected.envelopeId !== input.envelopeId
  )
    throw new IdentityEnvelopeRotationConsumerUnavailable();
  return authenticateConsumerActivation(client, input, selected, verifier, false);
}

async function authenticateConsumerActivation(
  client: PoolClient,
  input: {
    trust: IdentityEnvelopeSigningTrust;
    cutoverAtNs: bigint;
    observedAtNs: bigint;
    operationId?: string;
  },
  selected: ConsumerActivationSelection,
  signer: IdentityRuntimeAssertionVerifier,
  lockActivation: boolean,
) {
  const trust = input.trust;
  const scope = { participantId: trust.participantId, privacyDomainId: trust.privacyDomainId };
  if (
    (input.operationId !== undefined && selected.operationId !== input.operationId) ||
    BigInt(selected.reservedAtNs) < input.cutoverAtNs ||
    BigInt(selected.committedAtNs) < BigInt(selected.reservedAtNs) ||
    BigInt(selected.committedAtNs) > input.observedAtNs
  )
    throw new IdentityEnvelopeRotationConsumerUnavailable();
  const activation = await readInitialEnvelopeActivation(client, scope, selected, lockActivation);
  if (
    !activation ||
    activation.state !== 'COMMITTED' ||
    activation.operationId !== selected.operationId ||
    !activation.observation
  )
    throw new IdentityEnvelopeRotationConsumerUnavailable();
  const observation = validateIdentityEnvelopeProviderObservation(
    activation.request,
    activation.observation,
  );
  const descriptor = observation.descriptor;
  const request = activation.request;
  if (
    request.expectedFingerprint !== trust.signerId ||
    request.trustContextDigest !== identityEnvelopeSigningTrustDigest(trust) ||
    request.callerWorkloadCredentialId !== trust.workloadCredentialId ||
    request.reference !== trust.secretReference ||
    request.version !== trust.secretVersion ||
    descriptor.publicKeySpkiHex !== trust.publicKeySpkiDer.toString('hex') ||
    descriptor.validFromNs !== trust.validFromNs.toString() ||
    descriptor.validUntilNs !== trust.validUntilNs.toString() ||
    BigInt(observation.recordedAtNs) > BigInt(selected.committedAtNs)
  )
    throw new IdentityEnvelopeRotationConsumerUnavailable();
  const artifact = decodeIdentityAuthorityEnvelope(activation.payload);
  if (
    artifact.activation.operationId !== selected.operationId ||
    artifact.signer.participantId !== scope.participantId ||
    artifact.signer.privacyDomainId !== scope.privacyDomainId ||
    BigInt(artifact.issuedAtNs) !== BigInt(selected.reservedAtNs) ||
    BigInt(artifact.issuedAtNs) < input.cutoverAtNs
  )
    throw new IdentityEnvelopeRotationConsumerUnavailable();
  const creation = await readEnvelopeCreation(client, scope, selected.envelopeId, 'share');
  if (
    !artifact.proposalBytes.equals(creation.stored.bytes) ||
    artifact.proposalDigest !== `sha256:${creation.stored.digest.toString('hex')}`
  )
    throw new IdentityEnvelopeRotationConsumerUnavailable();
  const effect = await readEnvelopeEffectReadback(client, scope, creation);
  if (
    effect.operationId !== selected.operationId ||
    effect.state !== 'ACTIVE' ||
    effect.version !== '4'
  )
    throw new IdentityEnvelopeRotationConsumerUnavailable();
  const receipt = await client.query<{ cbor: Buffer; digest: Buffer; cose: Buffer }>(
    `select evidence.evidence_cbor as cbor,evidence.evidence_digest as digest,evidence.cose_sign1 as cose
 from control.mutation_evidence evidence join control.outbox_event event on event.participant_id=evidence.participant_id and event.privacy_domain_id=evidence.privacy_domain_id
 and event.aggregate_type='authority-envelope' and event.aggregate_id=evidence.aggregate_id and event.event_type='openpc.authority-envelope.mutation.committed.v1'
 and event.payload_cbor=evidence.evidence_cbor and event.payload_digest=evidence.evidence_digest and event.cose_sign1=evidence.cose_sign1
 where evidence.participant_id=$1 and evidence.privacy_domain_id=$2 and evidence.operation_id=$3 and evidence.aggregate_id=$4
 and evidence.action_intent_id='ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' and evidence.catalog_operation_id='ID-OP-ENVELOPE-ACTIVATE' and evidence.aggregate_version=3`,
    [scope.participantId, scope.privacyDomainId, selected.operationId, selected.envelopeId],
  );
  const evidence = receipt.rows[0];
  if (
    receipt.rowCount !== 1 ||
    !evidence ||
    !evidence.digest.equals(createHash('sha256').update(evidence.cbor).digest()) ||
    !(await signer.verifyCanonicalAssertion(evidence.cbor, evidence.cose))
  )
    throw new IdentityEnvelopeRotationConsumerUnavailable();
  return {
    operationId: selected.operationId,
    envelopeId: selected.envelopeId,
    payloadDigest: 'sha256:' + createHash('sha256').update(activation.payload).digest('hex'),
    receiptDigest: 'sha256:' + evidence.digest.toString('hex'),
  };
}
