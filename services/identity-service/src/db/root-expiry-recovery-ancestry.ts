import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  decodeEnvelopeScope,
  encodeEnvelopeScope,
  platformEnvelopeScopePreimage,
  platformEnvelopeScopeSuccessorPreimage,
  platformEnvelopeScopeExpiryRecoveryPreimage,
  type PlatformEnvelopeScopeAdmission,
} from '../../../../packages/security-kernel/src/index.js';
import {
  localRootExpiryPendingAncestryWitness,
  type LocalRootExpiryPendingAncestry,
  type LocalRootExpiryPendingWitness,
} from '../contracts/local-root-expiry-recovery.js';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import type { IdentityRuntimeEvidenceSigner } from '../domain/identity-kernel.js';
import { readCompletedRootExpiryRecoverySource } from './root-expiry-recovery-command.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';

type Witness = {
  pending: LocalRootExpiryPendingWitness;
  rootAncestry: LocalRootExpiryPendingAncestry;
};
type Binding = {
  participantId: string;
  privacyDomainId: string;
  platformContextId: string;
  installationDigest: string;
  installationEnvironmentId: string;
};
const deny = (): never => {
  throw new PlatformRecoveryError();
};
const same = (a: unknown, b: unknown) =>
  canonicalAuthorizationJson(a) === canonicalAuthorizationJson(b);
function pendingIdentity(p: LocalRootExpiryPendingWitness) {
  const { administrationEffectsDigest: _effects, readinessDigest: _readiness, ...identity } = p;
  void _effects;
  void _readiness;
  return identity;
}
function permissions(scope: PlatformEnvelopeScopeAdmission['grantable']) {
  const { validFromNs: _from, validUntilNs: _until, ...dimensions } = scope;
  void _from;
  void _until;
  return dimensions;
}

async function readOriginalPendingScope(client: PoolClient, b: Binding, w: Witness) {
  const result = await client.query<{
    scope_cbor: Buffer;
    admission_preimage: Buffer;
    admission_digest: Buffer;
    platform_context_id: string;
    owner_participant_id: string;
    installation_privacy_domain_id: string;
    platform_authority_epoch: string;
    environment_id: string;
    installation_digest: string;
    predecessor_epoch: string | null;
    predecessor_digest: string | null;
    replacement_id: string | null;
    preparation_operation_id: string | null;
    recovery_id: string | null;
    activation_operation_id: string | null;
    enrollment_digest: string | null;
    intent_digest: string | null;
  }>(
    `select scope_cbor,admission_preimage,admission_digest,
      metadata->>'platform_context_id' platform_context_id,metadata->>'owner_participant_id' owner_participant_id,
      metadata->>'installation_privacy_domain_id' installation_privacy_domain_id,metadata->>'platform_authority_epoch' platform_authority_epoch,
      metadata->>'environment_id' environment_id,metadata->>'installation_digest' installation_digest,
      metadata->>'predecessor_epoch' predecessor_epoch,metadata->>'predecessor_digest' predecessor_digest,
      metadata->>'replacement_id' replacement_id,metadata->>'preparation_operation_id' preparation_operation_id,
      metadata->>'recovery_id' recovery_id,metadata->>'activation_operation_id' activation_operation_id,
      metadata->>'enrollment_digest' enrollment_digest,metadata->>'intent_digest' intent_digest
    from (
      select to_jsonb(s) metadata,s.scope_cbor,s.admission_preimage,s.admission_digest from control.platform_envelope_scope s
      union all select to_jsonb(s),s.scope_cbor,s.admission_preimage,s.admission_digest from control.platform_envelope_scope_successor s
      union all select to_jsonb(s),s.scope_cbor,s.admission_preimage,s.admission_digest from control.root_expiry_recovery_scope s
    ) s where metadata->>'platform_context_id'=$1 and metadata->>'owner_participant_id'=$2
      and metadata->>'installation_privacy_domain_id'=$3 and metadata->>'platform_authority_epoch'=$4`,
    [b.platformContextId, b.participantId, b.privacyDomainId, w.pending.predecessorEpoch],
  );
  const row = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !row ||
    !Buffer.isBuffer(row.scope_cbor) ||
    !Buffer.isBuffer(row.admission_preimage) ||
    !Buffer.isBuffer(row.admission_digest)
  )
    deny();
  const admission: PlatformEnvelopeScopeAdmission = {
    platformContextId: row!.platform_context_id,
    ownerParticipantId: row!.owner_participant_id,
    installationPrivacyDomainId: row!.installation_privacy_domain_id,
    platformAuthorityEpoch: row!.platform_authority_epoch,
    environmentId: row!.environment_id,
    installationDigest: row!.installation_digest,
    grantable: decodeEnvelopeScope(row!.scope_cbor),
  };
  const digest = (value: string | null) => {
    if (!value || !/^\\x[0-9a-f]{64}$/u.test(value)) deny();
    return 'sha256:' + value!.slice(2);
  };
  const predecessor = {
    predecessorEpoch: row!.predecessor_epoch!,
    predecessorDigest: row!.predecessor_digest === null ? '' : digest(row!.predecessor_digest),
  };
  const preimage =
    row!.recovery_id !== null
      ? platformEnvelopeScopeExpiryRecoveryPreimage({
          admission,
          ...predecessor,
          recoveryId: row!.recovery_id,
          activationOperationId: row!.activation_operation_id!,
          enrollmentDigest: digest(row!.enrollment_digest),
          intentDigest: digest(row!.intent_digest),
        })
      : row!.replacement_id !== null
        ? platformEnvelopeScopeSuccessorPreimage({
            admission,
            ...predecessor,
            replacementId: row!.replacement_id,
            preparationOperationId: row!.preparation_operation_id!,
          })
        : platformEnvelopeScopePreimage(admission);
  if (
    admission.environmentId !== b.installationEnvironmentId ||
    admission.installationDigest !== b.installationDigest ||
    !encodeEnvelopeScope(admission.grantable).equals(row!.scope_cbor) ||
    !preimage.equals(row!.admission_preimage) ||
    !createHash('sha256').update(preimage).digest().equals(row!.admission_digest) ||
    'sha256:' + row!.admission_digest.toString('hex') !== w.pending.predecessorDigest
  )
    deny();
  return admission;
}

/** Verify each original receipt at its recorded consumption. No fresh grant is inferred. */
export async function authenticateRootExpiryPendingAncestry(
  client: PoolClient,
  binding: Binding,
  input: unknown,
  verifier: Pick<IdentityRuntimeEvidenceSigner, 'verifyCanonicalAssertion'>,
) {
  if (!verifier || typeof verifier.verifyCanonicalAssertion !== 'function') deny();
  const witness = localRootExpiryPendingAncestryWitness.parse(input);
  const role = (await client.query('select current_user as role')).rows[0]?.role;
  let previous = await readOriginalPendingScope(client, binding, witness);
  for (const [index, link] of witness.rootAncestry.receipts.entries()) {
    const read = await readCompletedRootExpiryRecoverySource(
      client,
      {
        participantId: binding.participantId,
        privacyDomainId: binding.privacyDomainId,
        enrollmentId: link.enrollmentId,
        recoveryId: link.recoveryId,
      },
      verifier,
    );
    const e = read.enrollment;
    if (
      e.schemaVersion === 1 ||
      e.platformContextId !== binding.platformContextId ||
      e.installationDigest !== binding.installationDigest ||
      e.installationEnvironmentId !== binding.installationEnvironmentId ||
      !same(pendingIdentity(e.pending), pendingIdentity(witness.pending)) ||
      e.rootEpoch !== previous.platformAuthorityEpoch ||
      e.rootDigest !== link.predecessorDigest ||
      e.rootRevision !== link.predecessorRevision ||
      e.rootEpoch !== link.predecessorEpoch ||
      read.row.operation_id !== link.activationOperationId ||
      'sha256:' + read.row.evidence_digest!.toString('hex') !== link.receiptDigest ||
      read.intent.enrollmentDigest !== link.enrollmentDigest ||
      'sha256:' + read.row.intent_digest.toString('hex') !== link.intentDigest ||
      !same(read.row.result, {
        rootEpoch: link.rootEpoch,
        rootRevision: link.rootRevision,
        rootDigest: link.rootDigest,
        operationId: link.activationOperationId,
      }) ||
      !same(permissions(previous.grantable), permissions(read.intent.successorScope))
    )
      deny();
    if (index === 0 ? e.schemaVersion !== 2 : e.schemaVersion !== 3) deny();
    if (
      e.schemaVersion === 3 &&
      !same(e.rootAncestry, {
        ...witness.rootAncestry,
        rootEpoch: link.predecessorEpoch,
        rootRevision: link.predecessorRevision,
        rootDigest: link.predecessorDigest,
        receipts: witness.rootAncestry.receipts.slice(0, index),
      })
    )
      deny();
    // Trust can be revoked; keep its actual incarnation stable through the owning transaction.
    const trust = await client.query(
      `select custody_trust_id from control.root_expiry_recovery_trust where custody_trust_id=$1
      and participant_id=$2 and privacy_domain_id=$3 and document_digest=$4 and state='ACTIVE' and row_version=1${role === 'openpc_control_owner' ? ' for share' : ''}`,
      [
        e.custodyTrustId,
        binding.participantId,
        binding.privacyDomainId,
        Buffer.from(e.custodyTrustDigest.slice(7), 'hex'),
      ],
    );
    if (trust.rowCount !== 1) deny();
    previous = {
      ...previous,
      platformAuthorityEpoch: link.rootEpoch,
      grantable: read.intent.successorScope,
    };
  }
  return { witness, headScope: previous.grantable };
}

/** Existing source locks and native witness fence precede complete crypto verification. */
export async function readCurrentRootExpiryPendingAncestry(
  client: PoolClient,
  binding: Binding,
  input: unknown,
  verifier: Pick<IdentityRuntimeEvidenceSigner, 'verifyCanonicalAssertion'>,
) {
  await client.query('select openpc.lock_root_expiry_pending_source($1)', [
    binding.platformContextId,
  ]);
  const root = await readCurrentPlatformScope(client, binding.platformContextId);
  const authenticated = await authenticateRootExpiryPendingAncestry(
    client,
    binding,
    input,
    verifier,
  );
  const head = authenticated.witness.rootAncestry;
  const current = (
    await client.query(
      `select row_version::text revision,clock_timestamp() now from control.platform_context
    where platform_context_id=$1 and owner_participant_id=$2 and state='ACTIVE'`,
      [binding.platformContextId, binding.participantId],
    )
  ).rows[0];
  if (
    !current ||
    root.ownerParticipantId !== binding.participantId ||
    root.installationPrivacyDomainId !== binding.privacyDomainId ||
    root.environmentId !== binding.installationEnvironmentId ||
    root.installationDigest !== binding.installationDigest ||
    root.platformAuthorityEpoch !== head.rootEpoch ||
    current.revision !== head.rootRevision ||
    root.platformAuthorityDigest !== head.rootDigest ||
    !same(root.grantable, authenticated.headScope) ||
    BigInt(root.grantable.validUntilNs) > BigInt(new Date(current.now).getTime()) * 1000000n
  )
    deny();
  return authenticated.witness;
}
