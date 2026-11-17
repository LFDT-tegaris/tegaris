import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  identityEnvelopeRecoveryReceivingTrust,
  signedIdentityEnvelopeRecoveryEnrollment,
  type IdentityEnvelopeRecoveryReceivingTrust,
} from '../contracts/identity-envelope-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import { verifyIdentityEnvelopeRecoveryCustody } from '../domain/identity-envelope-recovery-custody.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
import { assertPlatformRecoverySigners } from './platform-recovery-enrollment.js';
import { captureIdentityEnvelopeRotationSource } from './identity-envelope-rotation-candidate.js';
import { writeRecoveryDiagnostic } from '../platform-recovery-diagnostics.js';

const deny = () => {
  throw new PlatformRecoveryError();
};
const digestBytes = (value: string) => Buffer.from(value.slice(7), 'hex');

async function diagnose<T>(
  command: string,
  action: (mark: (stage: string) => void) => Promise<T>,
): Promise<T> {
  let stage = 'ACCOUNT';
  try {
    const result = await action((value) => {
      stage = value;
    });
    writeRecoveryDiagnostic({
      boundary: 'identity_envelope_recovery_installation',
      command,
      stage: 'READBACK',
      outcome: 'ACCEPTED',
    });
    return result;
  } catch (error) {
    const sqlState =
      error !== null &&
      typeof error === 'object' &&
      'code' in error &&
      typeof error.code === 'string' &&
      /^[0-9A-Z]{5}$/u.test(error.code)
        ? error.code
        : undefined;
    writeRecoveryDiagnostic({
      boundary: 'identity_envelope_recovery_installation',
      command,
      stage,
      outcome: 'REJECTED',
      sqlState,
      errorCode: error instanceof PlatformRecoveryError ? 'PC-AUTH-0005' : 'SOURCE_UNAVAILABLE',
    });
    throw error;
  }
}

/** Host trust admission remains a distinct authenticated installation owner.
 * SQL/OS ownership supplies no custody proof and no ordinary actor permission. */
async function assertInstallationOwner(client: PoolClient) {
  const result = await client.query<{ permitted: boolean }>(
    `select current_user='openpc_control_owner'
      and pg_has_role(session_user,'openpc_control_owner','MEMBER')
      and exists(select 1 from pg_roles where rolname=session_user and rolcanlogin and not rolsuper and not rolbypassrls) permitted`,
  );
  if (result.rowCount !== 1 || result.rows[0]?.permitted !== true) deny();
}

/** Authenticates the retained installation's original bytes and current Root;
 * this returns facts only. It never creates or widens administration authority. */
async function readInstallationSource(
  client: PoolClient,
  trust: Pick<
    IdentityEnvelopeRecoveryReceivingTrust,
    | 'participantId'
    | 'privacyDomainId'
    | 'platformContextId'
    | 'installationDigest'
    | 'installationEnvironmentId'
    | 'profile'
  >,
  localQaEnabled: boolean,
  mark: (stage: string) => void,
) {
  mark('CURRENT_ROOT');
  const root = await readCurrentPlatformScope(client, trust.platformContextId);
  mark('AUTHENTICATED_INSTALLATION');
  const selected = await client.query<{
    installation: unknown;
    bytes: Buffer;
    digest: string;
    profile: string;
    sourceAuthenticated: boolean;
    now: Date;
    rootRevision: string;
    pending: boolean;
  }>(
    `select i.installation,i.installation_bytes as bytes,i.installation_digest as digest,
      i.installation#>>'{pins,profile}' as profile,openpc.operations_source_authentication_valid(i.installation) as "sourceAuthenticated",
      clock_timestamp() as now,p.row_version::text as "rootRevision",
      exists(select 1 from control.platform_scope_replacement r where r.platform_context_id=p.platform_context_id and r.state='WITHDRAWING') pending
     from control.operations_installation i join control.platform_context p on p.platform_context_id=$1
      and p.owner_participant_id=i.participant_id and p.state='ACTIVE'
     where i.participant_id=$2 and i.privacy_domain_id=$3 and i.environment_id=$4 and i.state='ACTIVE'
      and p.authority_epoch=$5 for share of i,p`,
    [
      trust.platformContextId,
      trust.participantId,
      trust.privacyDomainId,
      trust.installationEnvironmentId,
      root.platformAuthorityEpoch,
    ],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row || !Buffer.isBuffer(row.bytes)) deny();
  const current = row!;
  const now = new Date(current.now);
  if (
    current.sourceAuthenticated !== true ||
    current.pending ||
    root.ownerParticipantId !== trust.participantId ||
    root.installationPrivacyDomainId !== trust.privacyDomainId ||
    root.environmentId !== trust.installationEnvironmentId ||
    root.installationDigest !== trust.installationDigest ||
    current.digest !== trust.installationDigest ||
    `sha256:${createHash('sha256').update(current.bytes).digest('hex')}` !== current.digest ||
    current.bytes.toString('utf8') !== canonicalAuthorizationJson(current.installation) ||
    !Number.isFinite(now.getTime()) ||
    BigInt(root.grantable.validFromNs) > BigInt(now.getTime()) * 1000000n ||
    BigInt(root.grantable.validUntilNs) <= BigInt(now.getTime()) * 1000000n ||
    (trust.profile === 'LOCAL_QA'
      ? !localQaEnabled || !['local', 'development', 'test'].includes(current.profile)
      : current.profile !== 'production')
  )
    deny();
  return { root, now, rootRevision: current.rootRevision };
}

/** Explicit initial receiving trust. No verification key is accepted by the
 * subsequent enrollment request, and no private key enters this owner. */
export async function installIdentityEnvelopeRecoveryReceivingTrust(
  client: PoolClient,
  input: unknown,
  options: { readonly localQaEnabled: boolean },
) {
  return diagnose('INSTALL_RECEIVING_TRUST', (mark) =>
    installReceivingTrust(client, input, options, mark),
  );
}

async function installReceivingTrust(
  client: PoolClient,
  input: unknown,
  options: { readonly localQaEnabled: boolean },
  mark: (stage: string) => void,
) {
  await assertInstallationOwner(client);
  mark('RECEIVING_TRUST_STRUCTURE');
  const trust = identityEnvelopeRecoveryReceivingTrust.parse(input);
  const { root, now } = await readInstallationSource(client, trust, options.localQaEnabled, mark);
  if (
    Date.parse(trust.validFrom) > now.getTime() ||
    Date.parse(trust.validUntil) <= now.getTime() ||
    BigInt(Date.parse(trust.validUntil)) * 1000000n > BigInt(root.grantable.validUntilNs)
  )
    deny();
  const digest = canonicalAuthorizationDigest(trust);
  mark('INITIAL_TRUST_INSERT');
  await client.query(
    `insert into control.identity_envelope_recovery_custody_trust
      (custody_trust_id,participant_id,privacy_domain_id,platform_context_id,document,document_digest,valid_from,valid_until)
     values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(custody_trust_id) do nothing`,
    [
      trust.custodyTrustId,
      trust.participantId,
      trust.privacyDomainId,
      trust.platformContextId,
      trust,
      digestBytes(digest),
      trust.validFrom,
      trust.validUntil,
    ],
  );
  mark('ORIGINAL_RECEIVING_TRUST_READBACK');
  const saved = await client.query<{
    document: unknown;
    digest: Buffer;
    state: string;
    revision: string;
  }>(
    `select document,document_digest as digest,state,row_version::text as revision from control.identity_envelope_recovery_custody_trust
     where participant_id=$1 and privacy_domain_id=$2 and custody_trust_id=$3 for share`,
    [trust.participantId, trust.privacyDomainId, trust.custodyTrustId],
  );
  const original = saved.rows[0];
  if (
    saved.rowCount !== 1 ||
    !original ||
    original.state !== 'ACTIVE' ||
    original.revision !== '1' ||
    canonicalAuthorizationDigest(
      identityEnvelopeRecoveryReceivingTrust.parse(original.document),
    ) !== digest ||
    !original.digest.equals(digestBytes(digest))
  )
    deny();
  return {
    custodyTrustId: trust.custodyTrustId,
    digest,
    state: 'INSTALLED' as const,
    authority: 'NONE' as const,
  };
}

/** The signature proves custody separately from future RecoveryCase approvals.
 * Signature and current Root precede provisional INSERT. Exact source validation
 * then uses installation-only read fences; callers retain the Participant write
 * fence and roll back every provisional write on failure. */
export async function enrollIdentityEnvelopeRecovery(
  client: PoolClient,
  input: unknown,
  options: {
    readonly localQaEnabled: boolean;
    readonly identityRuntimeVerifier?: IdentityRuntimeVerifier;
  },
) {
  return diagnose('ENROLL_SIGNER_REPAIR_CUSTODY', (mark) =>
    enrollSignedCustody(client, input, options, mark),
  );
}

async function enrollSignedCustody(
  client: PoolClient,
  input: unknown,
  options: {
    readonly localQaEnabled: boolean;
    readonly identityRuntimeVerifier?: IdentityRuntimeVerifier;
  },
  mark: (stage: string) => void,
) {
  await assertInstallationOwner(client);
  mark('SIGNED_CUSTODY_STRUCTURE');
  const signed = signedIdentityEnvelopeRecoveryEnrollment.parse(input);
  const declaration = signed.document;
  const source = await readInstallationSource(client, declaration, options.localQaEnabled, mark);
  mark('INDEPENDENT_RECEIVING_TRUST');
  const selected = await client.query<{
    document: unknown;
    digest: Buffer;
    state: string;
    revision: string;
  }>(
    `select document,document_digest as digest,state,row_version::text as revision from control.identity_envelope_recovery_custody_trust
     where participant_id=$1 and privacy_domain_id=$2 and custody_trust_id=$3 for share`,
    [declaration.participantId, declaration.privacyDomainId, declaration.custodyTrustId],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    row.state !== 'ACTIVE' ||
    row.revision !== '1' ||
    `sha256:${row.digest.toString('hex')}` !== declaration.custodyTrustDigest
  )
    deny();
  mark('CUSTODY_SIGNATURE_AND_ROOT_BINDING');
  const enrollment = verifyIdentityEnvelopeRecoveryCustody(
    row!.document,
    signed,
    source.now,
    options.localQaEnabled,
  );
  if (
    enrollment.rootEpoch !== source.root.platformAuthorityEpoch ||
    enrollment.rootRevision !== source.rootRevision ||
    enrollment.rootDigest !== source.root.platformAuthorityDigest ||
    BigInt(Date.parse(enrollment.validUntil)) * 1000000n >
      BigInt(source.root.grantable.validUntilNs)
  )
    deny();
  // Only authenticated custody opens exact source reads inside this transaction.
  // The host owner rolls back this provisional row if any current source fails.
  const digest = canonicalAuthorizationDigest(enrollment);
  mark('PROVISIONAL_SIGNED_CUSTODY_INSERT');
  await client.query(
    `insert into control.identity_envelope_recovery_enrollment
      (enrollment_id,participant_id,privacy_domain_id,platform_context_id,custody_trust_id,custody_trust_digest,document,document_digest,signature,valid_from,valid_until)
     values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict(enrollment_id) do nothing`,
    [
      enrollment.enrollmentId,
      enrollment.participantId,
      enrollment.privacyDomainId,
      enrollment.platformContextId,
      enrollment.custodyTrustId,
      digestBytes(enrollment.custodyTrustDigest),
      enrollment,
      digestBytes(digest),
      Buffer.from(signed.signature, 'base64url'),
      enrollment.validFrom,
      enrollment.validUntil,
    ],
  );
  mark('CURRENT_CUSTODIAN_CREDENTIALS');
  await assertPlatformRecoverySigners(client, enrollment, options.localQaEnabled);
  mark('CURRENT_ISSUER_AND_OLD_TRUST');
  const current = await captureIdentityEnvelopeRotationSource(
    client,
    enrollment,
    enrollment.request,
    options.identityRuntimeVerifier,
  );
  if (
    enrollment.issuerPrincipalId !== current.issuer.workloadPrincipalId ||
    enrollment.issuerParticipantEpoch !== current.issuer.workloadParticipantEpoch ||
    enrollment.issuerPrincipalEpoch !== current.issuer.workloadPrincipalEpoch ||
    enrollment.issuerCredentialEpoch !== current.issuer.workloadCredentialEpoch ||
    enrollment.issuerCredentialPublicKeyDigest !== current.issuer.workloadPublicKeyDigest ||
    enrollment.oldTrustDigest !== `sha256:${current.row.trust_digest.toString('hex')}` ||
    enrollment.selectionAdmissionVersion !== current.row.admission_version ||
    (current.trust.workloadParticipantEpoch === BigInt(current.issuer.workloadParticipantEpoch) &&
      current.trust.workloadPrincipalEpoch === BigInt(current.issuer.workloadPrincipalEpoch) &&
      current.trust.workloadCredentialId === current.issuer.workloadCredentialId &&
      current.trust.workloadCredentialEpoch === BigInt(current.issuer.workloadCredentialEpoch)) ||
    (current.issuer.credentialValidUntilNs !== null &&
      BigInt(Date.parse(enrollment.validUntil)) * 1000000n >
        BigInt(current.issuer.credentialValidUntilNs))
  )
    deny();
  mark('UNSETTLED_EFFECTS_AND_EXECUTOR_SEPARATION');
  const pending = await client.query<{ forbidden: boolean }>(
    `select exists(select 1 from control.signing_key_rotation r where r.participant_id=$1 and r.privacy_domain_id=$2
      and r.environment_id=$3 and r.workload_credential_id=$4 and r.state<>'COMPLETE')
      or exists(select 1 from control.assignment a where a.participant_id=$1 and a.principal_id=$5 and a.state='ACTIVE') forbidden`,
    [
      enrollment.participantId,
      enrollment.privacyDomainId,
      enrollment.request.environmentId,
      enrollment.request.workloadCredentialId,
      enrollment.recoveryPrincipal.principalId,
    ],
  );
  if (pending.rowCount !== 1 || pending.rows[0]?.forbidden !== false) deny();
  mark('ORIGINAL_CUSTODY_READBACK');
  const saved = await client.query<{
    document: unknown;
    digest: Buffer;
    signature: Buffer;
    state: string;
    revision: string;
  }>(
    `select document,document_digest as digest,signature,state,row_version::text as revision from control.identity_envelope_recovery_enrollment
     where participant_id=$1 and privacy_domain_id=$2 and enrollment_id=$3 for share`,
    [enrollment.participantId, enrollment.privacyDomainId, enrollment.enrollmentId],
  );
  const original = saved.rows[0];
  if (
    saved.rowCount !== 1 ||
    !original ||
    original.state !== 'ACTIVE' ||
    original.revision !== '1' ||
    canonicalAuthorizationDigest(original.document) !== digest ||
    !original.digest.equals(digestBytes(digest))
  )
    deny();
  // ECDSA signatures can vary for identical intent. Verify the original bytes,
  // rather than overwrite them or compare a newly generated signature as intent.
  verifyIdentityEnvelopeRecoveryCustody(
    row!.document,
    { document: original!.document, signature: original!.signature.toString('base64url') },
    source.now,
    options.localQaEnabled,
  );
  return {
    enrollmentId: enrollment.enrollmentId,
    revision: '1',
    digest,
    state: 'ENROLLED' as const,
    authority: 'NONE' as const,
  };
}
