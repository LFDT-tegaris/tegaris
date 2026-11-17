import type { PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { assertWorkloadCredentialContinuation } from './workload-credential-continuation.js';
import { z } from 'zod';
import { identityEnvelopeSigningProfileDigest } from '@openpc/security-kernel';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import {
  SigningRotationError,
  envelopeSigningRotationRequestSchema,
  type EnvelopeSigningRotationRequest,
} from '../domain/signing-rotation.js';
import {
  captureIdentityEnvelopeRotationIssuer,
  identityEnvelopeRotationIssuerSchema,
} from './identity-envelope-rotation-issuer.js';
import {
  authenticatedIdentityEnvelopeSigningTrust,
  type IdentityEnvelopeSigningKeyRow,
} from './identity-envelope-signing-store.js';

const positive = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const candidateSchema = z.strictObject({
  request: envelopeSigningRotationRequestSchema,
  oldTrustDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  oldKeyEpoch: positive,
  issuerSnapshot: identityEnvelopeRotationIssuerSchema,
  selectionAdmissionVersion: positive,
  creationOperationId: z.uuidv7(),
});

/** Prepare public candidate provenance only. The ordinary shared candidate
 * owner must still fence the actor and independently approve its exact digest.
 * Historical epoch mismatch is the repair input, never current signing authority. */
export async function captureIdentityEnvelopeRotationCandidate(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string; principalId: string },
  request: EnvelopeSigningRotationRequest,
  creationOperationId: string,
  idempotencyKey: string,
) {
  // Exact replay reads the original durable candidate. It never captures new
  // epochs, reselects a retired key or stages a successor to escape an effect.
  // The caller has already fenced current maker authority before this read.
  const previous = await client.query<{ candidate: unknown; digest: Buffer; rotationId: string }>(
    `select candidate_document as candidate,candidate_digest as digest,resource_id::text as "rotationId"
     from control.mutation_candidate
     where participant_id=$1 and privacy_domain_id=$2 and maker_principal_id=$3
       and action_intent_id='ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1'
       and catalog_operation_id='OPS-OP-CREATE-SIGNING-KEY-ROTATION' and idempotency_key=$4`,
    [scope.participantId, scope.privacyDomainId, scope.principalId, idempotencyKey],
  );
  if (previous.rowCount !== 0 && previous.rowCount !== 1)
    throw new SigningRotationError('CONFLICT');
  if (previous.rowCount === 1) {
    const old = previous.rows[0]!;
    const candidate = candidateSchema.parse(old.candidate);
    if (
      canonicalAuthorizationDigest(candidate) !== `sha256:${old.digest.toString('hex')}` ||
      canonicalAuthorizationJson(candidate.request) !== canonicalAuthorizationJson(request) ||
      candidate.issuerSnapshot.participantId !== scope.participantId ||
      candidate.issuerSnapshot.privacyDomainId !== scope.privacyDomainId ||
      !z.uuidv7().safeParse(old.rotationId).success
    )
      throw new SigningRotationError('CONFLICT');
    return {
      candidate,
      oldTrustDigest: Buffer.from(candidate.oldTrustDigest.slice(7), 'hex'),
      replayRotationId: old.rotationId,
    };
  }
  const { issuer, row, trust } = await captureIdentityEnvelopeRotationSource(
    client,
    scope,
    request,
  );
  const candidate = candidateSchema.parse({
    request,
    oldTrustDigest: `sha256:${row.trust_digest.toString('hex')}`,
    oldKeyEpoch: trust.keyEpoch.toString(),
    issuerSnapshot: issuer,
    selectionAdmissionVersion: row.admission_version,
    creationOperationId: z.uuidv7().parse(creationOperationId),
  });
  return { candidate, oldTrustDigest: row.trust_digest };
}

/** Authenticated source facts only, under the existing identity lock order.
 * Its caller must independently admit the ordinary actor or explicit custody
 * enrollment. Historical trust is never promoted to current signing authority. */
export async function captureIdentityEnvelopeRotationSource(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  request: EnvelopeSigningRotationRequest,
  verifier?: IdentityRuntimeVerifier,
) {
  const { issuer, recordedAtNs } = await captureIdentityEnvelopeRotationIssuer(client, {
    ...scope,
    workloadCredentialId: request.workloadCredentialId,
  });
  const source = await client.query<IdentityEnvelopeSigningKeyRow & { admission_version: string }>(
    `select key.*,selection.admission_version::text as admission_version,
       (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as now_ns
     from control.identity_envelope_signing_selection selection
     join control.identity_envelope_signing_grant grant_row
       on grant_row.participant_id=selection.participant_id and grant_row.privacy_domain_id=selection.privacy_domain_id
      and grant_row.signer_id=selection.signer_id and grant_row.profile_digest=selection.profile_digest
     join control.business_signing_key key
       on key.participant_id=selection.participant_id and key.privacy_domain_id=selection.privacy_domain_id
      and key.signer_id=selection.signer_id
     join control.business_signing_key_state lifecycle
       on lifecycle.participant_id=key.participant_id and lifecycle.privacy_domain_id=key.privacy_domain_id
      and lifecycle.signer_id=key.signer_id
     where selection.participant_id=$1 and selection.privacy_domain_id=$2 and selection.environment_id=$3
       and selection.profile_digest=$4 and key.signer_id=$5 and key.secret_reference=$6
       and (key.workload_credential_id=$7 or key.workload_credential_id=(
        select rotated_from_credential_id from control.credential
         where participant_id=$1 and credential_id=$7)) and key.signing_purpose_code=371
       and grant_row.signing_purpose_code=371 and lifecycle.state='ACTIVE'
       and not exists(select 1 from control.business_signing_grant receipt
        where receipt.participant_id=key.participant_id and receipt.privacy_domain_id=key.privacy_domain_id
         and receipt.signer_id=key.signer_id)
     for share of selection,lifecycle`,
    [
      scope.participantId,
      scope.privacyDomainId,
      request.environmentId,
      Buffer.from(identityEnvelopeSigningProfileDigest.slice(7), 'hex'),
      request.oldFingerprint,
      request.oldReference,
      request.workloadCredentialId,
    ],
  );
  const row = source.rows[0];
  if (source.rowCount !== 1 || !row) throw new SigningRotationError('CONFLICT');
  const trust = authenticatedIdentityEnvelopeSigningTrust(row);
  if (
    trust.environmentId !== request.environmentId ||
    !positive.safeParse(row.admission_version).success
  )
    throw new SigningRotationError('CONFLICT');
  if (trust.workloadCredentialId !== issuer.workloadCredentialId) {
    await assertWorkloadCredentialContinuation(
      client,
      {
        ...scope,
        predecessorId: trust.workloadCredentialId,
        predecessorEpoch: trust.workloadCredentialEpoch.toString(),
        successorId: issuer.workloadCredentialId,
        successorEpoch: issuer.workloadCredentialEpoch,
        principalId: issuer.workloadPrincipalId,
      },
      verifier,
    );
  } else if (trust.workloadCredentialEpoch.toString() !== issuer.workloadCredentialEpoch) {
    throw new SigningRotationError('CONFLICT');
  }
  return { issuer, row, trust, recordedAtNs };
}
