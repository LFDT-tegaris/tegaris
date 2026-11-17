import { isDeepStrictEqual } from 'node:util';
import type { PoolClient } from 'pg';
import {
  identityEnvelopeProviderRequestDigest,
  identityEnvelopeProviderRequestSchema,
  validateIdentityEnvelopeProviderObservation,
  type IdentityEnvelopeProviderObservation,
  type IdentityEnvelopeProviderRequest,
} from '../domain/identity-envelope-signing-provider.js';
import { AuthorityFenceError, type BoundAuthority } from './authority-fence.js';
import { fenceInitialEnvelopeActivationDispatch } from './identity-envelope-activation-authority.js';
import {
  materializeInitialEnvelopeActivation,
  type EnvelopeActivationSources,
} from './identity-envelope-activation-payload.js';
import type { EnvelopeGovernanceScope } from './identity-envelope-proposal.js';

export interface StoredEnvelopeActivation {
  operationId: string;
  attemptId: string;
  envelopeId: string;
  principalId: string;
  idempotencyKey: string;
  payload: Buffer;
  request: IdentityEnvelopeProviderRequest;
  requestDigest: Buffer;
  state: 'PREPARED' | 'DISPATCHED' | 'OBSERVED' | 'COMMITTED';
  observation: IdentityEnvelopeProviderObservation | null;
}

/** Authoritative original selector. The enclosing public owner must authorize
 * current access; neither the tuple nor these historical bytes grants access.
 * This business identity has no expires-at filter or replacement branch. */
export async function readInitialEnvelopeActivation(
  client: PoolClient,
  scope: Pick<EnvelopeGovernanceScope, 'participantId' | 'privacyDomainId'>,
  identity: { principalId: string; idempotencyKey: string; envelopeId: string },
  lock = false,
): Promise<StoredEnvelopeActivation | undefined> {
  const selected = await client.query<StoredEnvelopeActivation>(
    `select operation_id::text as "operationId",attempt_id::text as "attemptId",
      envelope_id::text as "envelopeId",principal_id::text as "principalId",idempotency_key as "idempotencyKey",
      payload_cbor as payload,request,request_digest as "requestDigest",state,observation
    from control.identity_envelope_activation where participant_id=$1 and privacy_domain_id=$2
      and principal_id=$3 and idempotency_key=$4${lock ? ' for update' : ''}`,
    [scope.participantId, scope.privacyDomainId, identity.principalId, identity.idempotencyKey],
  );
  if (selected.rowCount === 0) return undefined;
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row || row.envelopeId !== identity.envelopeId)
    throw new AuthorityFenceError();
  const request = identityEnvelopeProviderRequestSchema.parse(row.request);
  if (
    request.participantId !== scope.participantId ||
    request.privacyDomainId !== scope.privacyDomainId ||
    request.attemptId !== row.attemptId ||
    request.operationId !== row.operationId ||
    request.payloadHex !== row.payload.toString('hex') ||
    identityEnvelopeProviderRequestDigest(request) !== `sha256:${row.requestDigest.toString('hex')}`
  )
    throw new AuthorityFenceError();
  if (row.observation !== null)
    validateIdentityEnvelopeProviderObservation(request, row.observation);
  return { ...row, request };
}

/** Within the prepared authority transaction only, after reserving the exact
 * idempotency row and consuming its original step-up. Unique business-subject,
 * candidate, proof and request bindings prevent a second intent from replacing
 * this reservation. Provider I/O never occurs in a database transaction. */
export async function reserveInitialEnvelopeActivation(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  sources: EnvelopeActivationSources,
  authorities: {
    maker: typeof sources.proposal.issuerAuthority;
    checker: typeof sources.proposal.issuerAuthority;
  },
) {
  if (
    scope.actionIntentId !== 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' ||
    scope.operationId !== sources.activation.operationId ||
    scope.participantId !== sources.trust.participantId ||
    scope.privacyDomainId !== sources.trust.privacyDomainId ||
    !isDeepStrictEqual(authorities.maker.binding, sources.activation.maker.authority) ||
    !isDeepStrictEqual(authorities.checker.binding, sources.activation.checker.authority)
  )
    throw new AuthorityFenceError();
  const materialized = materializeInitialEnvelopeActivation(sources);
  await client.query(
    `insert into control.identity_envelope_activation
    (operation_id,attempt_id,participant_id,privacy_domain_id,envelope_id,expected_approved_version,
     principal_id,idempotency_key,idempotency_record_id,candidate_id,candidate_digest,approval_request_id,
     maker_challenge_id,proposal_digest,maker_authority,checker_authority,payload_cbor,payload_digest,
     request,request_digest,reserved_at_ns)
    values($1,$2,$3,$4,$5,3,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
    [
      scope.operationId,
      sources.attemptId,
      scope.participantId,
      scope.privacyDomainId,
      sources.proposal.envelopeId,
      sources.idempotency.principalId,
      sources.idempotency.key,
      sources.idempotency.recordId,
      sources.activation.candidateId,
      Buffer.from(sources.activation.candidateDigest.slice(7), 'hex'),
      sources.activation.approvalRequestId,
      sources.activation.maker.stepUpChallengeId,
      sources.proposal.digest,
      authorities.maker,
      authorities.checker,
      materialized.payload,
      materialized.payloadDigest,
      materialized.request,
      materialized.requestDigest,
      String(sources.recordedAtNs),
    ],
  );
  return materialized;
}

/** The transaction must COMMIT a true result before the first network call.
 * A false result permits only lookup of the original provider request. */
export async function claimInitialEnvelopeActivationDispatch(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  attemptId: string,
  current: BoundAuthority,
): Promise<boolean> {
  const row = await client.query<{
    principalId: string;
    idempotencyKey: string;
    envelopeId: string;
    state: string;
  }>(
    `select principal_id::text as "principalId",idempotency_key as "idempotencyKey",envelope_id::text as "envelopeId",state
      from control.identity_envelope_activation where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and attempt_id=$4`,
    [scope.participantId, scope.privacyDomainId, scope.operationId, attemptId],
  );
  if (row.rowCount !== 1 || row.rows[0]?.state !== 'PREPARED') return false;
  const original = await readInitialEnvelopeActivation(client, scope, row.rows[0]);
  if (!original) throw new AuthorityFenceError();
  await fenceInitialEnvelopeActivationDispatch(client, scope, original, current);
  const claimed = await client.query(
    `update control.identity_envelope_activation set state='DISPATCHED',row_version=2,dispatched_at=clock_timestamp()
      where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and attempt_id=$4
      and state='PREPARED' and row_version=1`,
    [scope.participantId, scope.privacyDomainId, scope.operationId, attemptId],
  );
  return claimed.rowCount === 1;
}

/** Retain authenticated provider history even if final authority has since
 * expired or been revoked. Repeated readback must match the original exactly;
 * this function cannot publish an envelope or create an assignment. */
export async function recordInitialEnvelopeActivationObservation(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  original: StoredEnvelopeActivation,
  value: unknown,
) {
  const observation = validateIdentityEnvelopeProviderObservation(original.request, value);
  if (original.operationId !== scope.operationId) throw new AuthorityFenceError();
  const stored = await readInitialEnvelopeActivation(client, scope, original, true);
  if (!stored || stored.attemptId !== original.attemptId) throw new AuthorityFenceError();
  if (stored.observation !== null) {
    if (!isDeepStrictEqual(stored.observation, observation)) throw new AuthorityFenceError();
    return stored.observation;
  }
  const updated = await client.query(
    `update control.identity_envelope_activation
      set state='OBSERVED',row_version=3,observation=$5,cose_sign1=$6,observed_at=clock_timestamp()
      where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and attempt_id=$4
      and state='DISPATCHED' and row_version=2`,
    [
      scope.participantId,
      scope.privacyDomainId,
      scope.operationId,
      original.attemptId,
      observation,
      Buffer.from(observation.coseHex, 'hex'),
    ],
  );
  if (updated.rowCount !== 1) throw new AuthorityFenceError();
  return observation;
}

/** Publish only the observed original signature. The database guards bind this
 * transition to the current operation, exact envelope and immutable journal. */
export async function commitInitialEnvelopeActivation(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  original: StoredEnvelopeActivation,
) {
  if (scope.operationId !== original.operationId) throw new AuthorityFenceError();
  const stored = await readInitialEnvelopeActivation(
    client,
    scope,
    {
      principalId: original.principalId,
      idempotencyKey: original.idempotencyKey,
      envelopeId: original.envelopeId,
    },
    true,
  );
  if (!stored || stored.attemptId !== original.attemptId) throw new AuthorityFenceError();
  if (stored.state === 'COMMITTED') return stored;
  if (stored.state !== 'OBSERVED' || stored.observation === null) throw new AuthorityFenceError();
  const cose = Buffer.from(stored.observation.coseHex, 'hex');
  const published = await client.query(
    `update control.authority_envelope set state='ACTIVE',row_version=4,cose_sign1=$4,
       last_mutation_operation_id=$3,updated_at=clock_timestamp()
     where participant_id=$1 and authority_envelope_id=$2 and state='APPROVED' and row_version=3`,
    [scope.participantId, stored.envelopeId, scope.operationId, cose],
  );
  if (published.rowCount !== 1) throw new AuthorityFenceError();
  const committed = await client.query(
    `update control.identity_envelope_activation set state='COMMITTED',row_version=4,
       committed_at=clock_timestamp()
     where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3
       and attempt_id=$4 and state='OBSERVED' and row_version=3`,
    [scope.participantId, scope.privacyDomainId, scope.operationId, stored.attemptId],
  );
  if (committed.rowCount !== 1) throw new AuthorityFenceError();
  return { ...stored, state: 'COMMITTED' as const };
}
