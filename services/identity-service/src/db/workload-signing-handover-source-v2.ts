import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  businessSigningTrustDigest,
  businessSigningTrustPreimage,
  type BusinessSigningTrust,
} from '@openpc/security-kernel';
import {
  signingRoleProfiles,
  signingRoleGrantBounds,
} from '../../../../packages/security-kernel/src/signing-roles.js';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
import { workloadSigningHandoverAdmissionOperation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import {
  workloadSigningHandoverRequestV2Schema,
  type WorkloadSigningHandoverRequestV2,
} from '../contracts/workload-signing-handover-v2.js';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import {
  handoverAdmissionSourceSchema,
  handoverNanosSchema,
} from '../domain/workload-signing-handover-admission-material.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import {
  fenceBoundAuthorities,
  lockAuthorityFence,
  type BoundAuthority,
} from './authority-fence.js';
import { readRetainedBusinessSigningTrust } from './business-signing-store.js';
import {
  assertIdentityEnvelopeRotationIssuerUnchanged,
  captureIdentityEnvelopeRotationIssuer,
} from './identity-envelope-rotation-issuer.js';
import { readWorkloadSigningHandoverProvenance } from './workload-signing-handover-provenance.js';
import { captureWorkloadSigningEnvelopeCarry } from './workload-signing-handover-envelope-carry.js';
import { WorkloadSigningHandoverSourceUnavailable } from './workload-signing-handover-source.js';
const deny = (): never => {
  throw new WorkloadSigningHandoverSourceUnavailable();
};
const tagged = (value: Buffer) => `sha256:${value.toString('hex')}`;
const maximumEpoch = 18446744073709551615n;

// Version two replaces receipt keys and preserves one completed envelope repair.
// The role-specific immutable receipt grants retain the version-one bounds.
const handoverBusinessProfiles: readonly string[] = [
  ...signingRoleProfiles.BUSINESS_EFFECT,
  'pc.control.module.register',
  'pc.control.module.install',
  'pc.control.module.enable',
  'pc.control.module.disable',
];

interface ReceiptSelection {
  signerId: string;
  credentialId: string;
  profileId: string;
  profileVersion: number;
  profileDigest: Buffer;
  rowVersion: string;
  admissionVersion: string;
  fenceGeneration: string;
  fencedOperationId: string | null;
}
interface EnvelopeSelection {
  signerId: string;
  credentialId: string;
  profileDigest: Buffer;
  admissionVersion: string;
}
type CapturedTrust = {
  signerRole: 'BUSINESS_EFFECT' | 'LIFECYCLE_EVIDENCE';
  trust: BusinessSigningTrust;
};

/** Current authorized source capture only. This does not establish provider
 * possession, approval, admission authorization or committed runtime effects.
 * Version one retains its own capture path and original source domain. */
export interface WorkloadSigningHandoverCaptureScopeV2 {
  participantId: string;
  privacyDomainId: string;
  authority: BoundAuthority;
  environmentId: string;
  verifier: IdentityRuntimeVerifier;
  localQaEnabled: boolean;
}
export async function captureWorkloadSigningHandoverSourceV2(
  client: PoolClient,
  scope: WorkloadSigningHandoverCaptureScopeV2,
  input: WorkloadSigningHandoverRequestV2,
) {
  return captureSourceAtAuthorityV2(client, scope, input, signingRotationActions.create, '*');
}

/** Admission has its own explicitly granted permission and exact resource.
 * The existing preparation entry point keeps its original action contract. */
export async function captureWorkloadSigningHandoverAdmissionSourceV2(
  client: PoolClient,
  scope: WorkloadSigningHandoverCaptureScopeV2 & { handoverId: string },
  input: WorkloadSigningHandoverRequestV2,
) {
  const handoverId = z.uuidv7().parse(scope.handoverId);
  if (
    scope.authority.catalogOperationId !==
    workloadSigningHandoverAdmissionOperation.catalogOperationId
  )
    deny();
  return captureSourceAtAuthorityV2(
    client,
    scope,
    input,
    workloadSigningHandoverAdmissionOperation.actionIntentId,
    handoverId,
  );
}

async function captureSourceAtAuthorityV2(
  client: PoolClient,
  scope: WorkloadSigningHandoverCaptureScopeV2,
  input: WorkloadSigningHandoverRequestV2,
  actionIntentId: string,
  resourceId: string,
) {
  const request = workloadSigningHandoverRequestV2Schema.parse(input);
  const authority = scope.authority;
  if (
    authority.privacyDomainId !== scope.privacyDomainId ||
    authority.actionIntentId !== actionIntentId ||
    authority.resourceId !== resourceId ||
    request.environmentId !== scope.environmentId ||
    typeof scope.localQaEnabled !== 'boolean'
  )
    deny();
  const context = await client.query<{ serializable: boolean }>(
    `select openpc.assert_request_context(true),current_setting('transaction_isolation')='serializable' as serializable`,
  );
  if (context.rowCount !== 1 || !context.rows[0]!.serializable) deny();
  await lockAuthorityFence(client, scope.participantId, {
    participant: [{ id: scope.participantId, write: true }],
  });
  const intent = await client.query<{ digest: Buffer }>(
    'select semantic_digest as digest from control.action_intent where action_intent_id=$1',
    [request.actionIntentId],
  );
  if (
    intent.rowCount !== 1 ||
    !intent.rows[0]!.digest.equals(Buffer.from(request.actionIntentDigest.slice(7), 'hex'))
  )
    deny();
  const partition = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
  };
  const credentials = await client.query<{
    credentialId: string;
    principalId: string;
    workloadId: string;
    epoch: string;
    state: string;
  }>(
    `select credential_id::text as "credentialId",principal_id::text as "principalId",audience as "workloadId",
      credential_epoch::text as epoch,state from control.credential
     where participant_id=$1 and credential_id=any($2::uuid[]) and kind='WORKLOAD_MTLS'`,
    [partition.participantId, [request.predecessorCredentialId, request.successorCredentialId]],
  );
  const predecessor = credentials.rows.find(
    (row) => row.credentialId === request.predecessorCredentialId,
  );
  const successor = credentials.rows.find(
    (row) => row.credentialId === request.successorCredentialId,
  );
  if (
    credentials.rowCount !== 2 ||
    !predecessor ||
    !successor ||
    predecessor.principalId !== successor.principalId ||
    predecessor.workloadId !== successor.workloadId ||
    predecessor.state !== 'REVOKED' ||
    successor.state !== 'ACTIVE' ||
    predecessor.epoch !== successor.epoch ||
    BigInt(successor.epoch) < 2n
  )
    deny();
  await fenceBoundAuthorities(client, partition.participantId, [authority], {
    principal: [{ id: successor!.principalId }],
    credential: [{ id: request.predecessorCredentialId }, { id: request.successorCredentialId }],
  });
  const current = await captureIdentityEnvelopeRotationIssuer(client, {
    ...partition,
    workloadCredentialId: request.successorCredentialId,
  });
  if (
    current.issuer.workloadPrincipalId !== successor!.principalId ||
    current.issuer.workloadCredentialEpoch !== successor!.epoch
  )
    deny();
  const predecessorEpoch = (BigInt(current.issuer.workloadCredentialEpoch) - 1n).toString();
  const provenance = await readWorkloadSigningHandoverProvenance(
    client,
    {
      ...partition,
      predecessorCredentialId: request.predecessorCredentialId,
      predecessorCredentialEpoch: predecessorEpoch,
      successorCredentialId: request.successorCredentialId,
      successorCredentialEpoch: current.issuer.workloadCredentialEpoch,
      credentialRotationOperationId: request.credentialRotationOperationId,
    },
    scope.verifier,
  );
  if (provenance.principalId !== current.issuer.workloadPrincipalId) deny();
  const carry = await captureWorkloadSigningEnvelopeCarry(
    client,
    {
      ...partition,
      environmentId: scope.environmentId,
      workloadCredentialId: request.successorCredentialId,
      localQaEnabled: scope.localQaEnabled,
    },
    request.carriedEnvelope,
    scope.verifier,
  );
  assertIdentityEnvelopeRotationIssuerUnchanged(current.issuer, carry.issuer);
  const args = [
    partition.participantId,
    partition.privacyDomainId,
    scope.environmentId,
    successor!.principalId,
    successor!.workloadId,
  ];
  const receipts = await client.query<ReceiptSelection>(
    `select selection.signer_id as "signerId",key.workload_credential_id::text as "credentialId",
       profile.profile_id as "profileId",profile.profile_version::integer as "profileVersion",selection.profile_digest as "profileDigest",
       selection.row_version::text as "rowVersion",selection.admission_version::text as "admissionVersion",
       selection.fence_generation::text as "fenceGeneration",selection.fenced_operation_id::text as "fencedOperationId"
     from control.business_signing_selection selection join control.business_signing_key key using(participant_id,privacy_domain_id,signer_id)
     join control.credential credential on credential.participant_id=key.participant_id and credential.credential_id=key.workload_credential_id
     join control.business_transition_profile profile on profile.profile_digest=selection.profile_digest
     where selection.participant_id=$1 and selection.privacy_domain_id=$2 and selection.environment_id=$3
       and credential.principal_id=$4 and credential.audience=$5 and key.signing_purpose_code=338
     order by selection.profile_digest for share of selection`,
    args,
  );
  const envelopes = await client.query<EnvelopeSelection>(
    `select selection.signer_id as "signerId",key.workload_credential_id::text as "credentialId",
       selection.profile_digest as "profileDigest",selection.admission_version::text as "admissionVersion"
     from control.identity_envelope_signing_selection selection join control.business_signing_key key using(participant_id,privacy_domain_id,signer_id)
     join control.credential credential on credential.participant_id=key.participant_id and credential.credential_id=key.workload_credential_id
     where selection.participant_id=$1 and selection.privacy_domain_id=$2 and selection.environment_id=$3
       and credential.principal_id=$4 and credential.audience=$5 and key.signing_purpose_code=371
     order by selection.profile_digest for share of selection`,
    args,
  );
  // This version admits only receipt and envelope purposes. An existing
  // renewal signer is an undisclosed selection, never an inherited grant.
  const renewal = await client.query(
    `select selection.signer_id from control.workload_renewal_signing_selection selection
     join control.business_signing_key key using(participant_id,privacy_domain_id,signer_id)
     join control.credential credential on credential.participant_id=key.participant_id
       and credential.credential_id=key.workload_credential_id
     where selection.participant_id=$1 and selection.privacy_domain_id=$2 and selection.environment_id=$3
       and credential.principal_id=$4 and credential.audience=$5 for share of selection`,
    args,
  );
  if (renewal.rowCount !== 0) deny();
  const selectedIds = [...new Set(receipts.rows.map((row) => row.signerId))].sort();
  const envelope = envelopes.rows[0];
  if (envelopes.rowCount !== 1 || !envelope) return deny();
  if (
    envelope.credentialId !== request.successorCredentialId ||
    envelope.signerId !== request.carriedEnvelope.signerId ||
    envelope.signerId !== carry.trust.signerId ||
    tagged(envelope.profileDigest) !== request.carriedEnvelope.profileDigest ||
    envelope.admissionVersion !== request.carriedEnvelope.selectionAdmissionVersion ||
    receipts.rows.some(
      (row) =>
        row.credentialId !== request.predecessorCredentialId || row.fencedOperationId !== null,
    ) ||
    selectedIds.length !== request.replacements.length ||
    selectedIds.includes(envelope.signerId) ||
    selectedIds.some((id, index) => id !== request.replacements[index]!.oldFingerprint)
  )
    deny();
  const receiptSelections = handoverAdmissionSourceSchema.shape.receiptSelections.parse(
    receipts.rows.map((row) => ({ ...row, profileDigest: tagged(row.profileDigest) })),
  );
  const envelopeSelections = handoverAdmissionSourceSchema.shape.envelopeSelections.parse(
    envelopes.rows.map((row) => ({ ...row, profileDigest: tagged(row.profileDigest) })),
  );
  if (
    new Set(receiptSelections.map((row) => row.profileDigest)).size !== receiptSelections.length ||
    receiptSelections.some((row) =>
      [row.rowVersion, row.admissionVersion, row.fenceGeneration].some(
        (counter) => BigInt(counter) >= maximumEpoch,
      ),
    )
  )
    deny();
  const protectedIds = [...selectedIds, envelope.signerId].sort();
  const lifecycle = await client.query<{ signerId: string; state: string }>(
    `select signer_id as "signerId",state from control.business_signing_key_state
     where participant_id=$1 and privacy_domain_id=$2 and signer_id=any($3::text[]) order by signer_id for share`,
    [partition.participantId, partition.privacyDomainId, protectedIds],
  );
  if (
    lifecycle.rowCount !== protectedIds.length ||
    lifecycle.rows.some(
      (row, index) => row.state !== 'ACTIVE' || row.signerId !== protectedIds[index],
    )
  )
    deny();
  const competing = await client.query(
    `select 1 from control.signing_key_rotation where participant_id=$1 and privacy_domain_id=$2
      and (old_signer_id=any($3::text[]) or new_signer_id=any($3::text[])) and state<>'COMPLETE' limit 1`,
    [partition.participantId, partition.privacyDomainId, protectedIds],
  );
  const reused = await client.query(
    `select 1 from control.business_signing_key where participant_id=$1 and privacy_domain_id=$2
      and secret_reference=any($3::text[]) limit 1`,
    [
      partition.participantId,
      partition.privacyDomainId,
      request.replacements.map((key) => key.newReference),
    ],
  );
  if (competing.rowCount !== 0 || reused.rowCount !== 0) deny();
  const trusts: CapturedTrust[] = [];
  const keys = [];
  for (const replacement of request.replacements) {
    const receipt = await readRetainedBusinessSigningTrust(
      client,
      partition,
      replacement.oldFingerprint,
    );
    const bounds = signingRoleGrantBounds[replacement.signerRole];
    if (
      receipt.grants.length < bounds.minimum ||
      receipt.grants.length > bounds.maximum ||
      receipt.grants.some(
        (grant) =>
          !(
            replacement.signerRole === 'BUSINESS_EFFECT'
              ? handoverBusinessProfiles
              : signingRoleProfiles.LIFECYCLE_EVIDENCE
          ).includes(grant.profileId),
      )
    )
      deny();
    const selectors = receipts.rows.filter((row) => row.signerId === replacement.oldFingerprint);
    if (
      selectors.length !== receipt.grants.length ||
      receipt.grants.some(
        (grant) =>
          !selectors.some(
            (row) =>
              row.profileId === grant.profileId &&
              row.profileVersion === grant.profileVersion &&
              row.profileDigest.equals(grant.profileDigest),
          ),
      )
    )
      deny();
    const trust = receipt;
    const preimage = businessSigningTrustPreimage(receipt);
    const trustDigest = tagged(businessSigningTrustDigest(receipt));
    trusts.push({ signerRole: replacement.signerRole, trust: receipt });
    if (
      trust.environmentId !== scope.environmentId ||
      trust.participantId !== scope.participantId ||
      trust.privacyDomainId !== scope.privacyDomainId ||
      trust.signerId !== replacement.oldFingerprint ||
      trustDigest !== replacement.oldTrustDigest ||
      trust.keyEpoch.toString() !== replacement.expectedKeyEpoch ||
      trust.keyEpoch >= maximumEpoch ||
      trust.workloadCredentialId !== request.predecessorCredentialId ||
      trust.workloadCredentialEpoch.toString() !== predecessorEpoch ||
      trust.secretReference !== replacement.oldReference ||
      trust.validFromNs > current.recordedAtNs
    )
      deny();
    keys.push({
      ...replacement,
      oldTrustPreimageBase64: preimage.toString('base64'),
      oldCredentialEpoch: trust.workloadCredentialEpoch.toString(),
      oldKeyValidFromNs: trust.validFromNs.toString(),
      oldKeyValidUntilNs: trust.validUntilNs.toString(),
    });
  }
  const clock = await client.query<{ nowNs: string }>(
    'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as "nowNs"',
  );
  if (clock.rowCount !== 1 || !clock.rows[0]) deny();
  const recordedAtNs = BigInt(handoverNanosSchema.parse(clock.rows[0]!.nowNs));
  if (
    recordedAtNs < carry.recordedAtNs ||
    recordedAtNs < current.recordedAtNs ||
    carry.trust.validFromNs > recordedAtNs ||
    carry.trust.validUntilNs <= recordedAtNs ||
    BigInt(current.issuer.credentialValidFromNs) > recordedAtNs ||
    (current.issuer.credentialValidUntilNs !== null &&
      BigInt(current.issuer.credentialValidUntilNs) <= recordedAtNs)
  )
    deny();
  return {
    document: Object.freeze({
      schema: 'pc.identity.workload-signing-handover.source.v2' as const,
      ...partition,
      environmentId: scope.environmentId,
      issuer: current.issuer,
      provenance,
      keys: Object.freeze(keys.map((key) => Object.freeze(key))),
      receiptSelections: Object.freeze(receiptSelections.map((row) => Object.freeze(row))),
      envelopeSelections: Object.freeze(envelopeSelections.map((row) => Object.freeze(row))),
      carriedEnvelope: carry.document,
    }),
    workloadId: successor!.workloadId,
    trusts: Object.freeze(trusts),
    carriedTrust: carry.trust,
    recordedAtNs,
  };
}

/** A source fingerprint, never evidence of approval or admission. */
export function workloadSigningHandoverSourceV2Digest(
  source: Awaited<ReturnType<typeof captureWorkloadSigningHandoverSourceV2>>['document'],
) {
  return (
    'sha256:' +
    createHash('sha256')
      .update('pc.identity.workload-signing-handover.source.v2\0')
      .update(canonicalAuthorizationJson(source))
      .digest('hex')
  );
}
