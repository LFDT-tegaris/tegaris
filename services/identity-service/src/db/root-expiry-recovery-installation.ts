import { localQaDurationMultiplier } from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  localRootExpiryRecoveryReceivingTrust,
  signedLocalRootExpiryRecoveryEnrollment,
  type LocalRootExpiryRecoveryEnrollment,
  localRootExpiryPendingWitness,
  type LocalRootExpiryPendingWitness,
  localRootExpiryPendingAncestryWitness,
  type LocalRootExpiryPendingAncestry,
} from '../contracts/local-root-expiry-recovery.js';
import {
  authenticateLocalRootExpiryRecoveryCustody,
  localRootExpirySuccessorScope,
  assertLocalRootExpiryRecoveryInstallationTime,
} from '../domain/local-root-expiry-recovery.js';
import {
  canonicalAuthorizationJson,
  canonicalAuthorizationDigest,
} from '../contracts/authorization.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
import { assertPlatformRecoverySigners } from './platform-recovery-enrollment.js';
import { readCurrentRootExpiryPendingAncestry } from './root-expiry-recovery-ancestry.js';
import type { IdentityRuntimeEvidenceSigner } from '../domain/identity-kernel.js';
const deny = (): never => {
  throw new PlatformRecoveryError();
};
const bytes = (v: string) => Buffer.from(v.slice(7), 'hex');

export async function readRootExpiryInstallationSource(
  client: PoolClient,
  source: {
    participantId: string;
    privacyDomainId: string;
    platformContextId: string;
    installationDigest: string;
    installationEnvironmentId: string;
    pending?: LocalRootExpiryPendingWitness;
    rootAncestry?: LocalRootExpiryPendingAncestry;
  },
  localQaEnabled: boolean,
  verifier?: Pick<IdentityRuntimeEvidenceSigner, 'verifyCanonicalAssertion'>,
) {
  if (!localQaEnabled) deny();
  if (source.pending !== undefined)
    await client.query('select openpc.lock_root_expiry_pending_source($1)', [
      source.platformContextId,
    ]);
  const root = await readCurrentPlatformScope(client, source.platformContextId);
  const selected = await client.query<{
    installation: unknown;
    bytes: Buffer;
    digest: string;
    profile: string;
    authenticated: boolean;
    now: Date;
    rootRevision: string;
    participantEpoch: string;
    pending: boolean;
  }>(
    `select i.installation,i.installation_bytes as bytes,i.installation_digest as digest,
      i.installation#>>'{pins,profile}' as profile,openpc.operations_source_authentication_valid(i.installation) as authenticated,
      clock_timestamp() as now,p.row_version::text as "rootRevision",participant.authority_epoch::text as "participantEpoch",
      exists(select 1 from control.platform_scope_replacement r where r.platform_context_id=p.platform_context_id and r.state='WITHDRAWING') as pending
     from control.operations_installation i join control.platform_context p on p.platform_context_id=$1 and p.owner_participant_id=i.participant_id and p.state='ACTIVE'
     join control.participant participant on participant.participant_id=i.participant_id and participant.state='ACTIVE'
     where i.participant_id=$2 and i.privacy_domain_id=$3 and i.environment_id=$4 and i.state='ACTIVE' and p.authority_epoch=$5 for share of i,p,participant`,
    [
      source.platformContextId,
      source.participantId,
      source.privacyDomainId,
      source.installationEnvironmentId,
      root.platformAuthorityEpoch,
    ],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    !Buffer.isBuffer(row.bytes) ||
    !row.authenticated ||
    row.pending !== (source.pending !== undefined) ||
    !['local', 'development', 'test'].includes(row.profile) ||
    root.ownerParticipantId !== source.participantId ||
    root.installationPrivacyDomainId !== source.privacyDomainId ||
    root.environmentId !== source.installationEnvironmentId ||
    root.installationDigest !== source.installationDigest ||
    row.digest !== source.installationDigest ||
    `sha256:${createHash('sha256').update(row.bytes).digest('hex')}` !== row.digest ||
    row.bytes.toString('utf8') !== canonicalAuthorizationJson(row.installation)
  )
    deny();
  if (source.pending !== undefined) {
    const observed = await client.query(
      source.rootAncestry === undefined
        ? 'select openpc.read_root_expiry_pending_witness($1) as witness'
        : 'select openpc.read_root_expiry_pending_ancestry_witness($1) as witness',
      [source.platformContextId],
    );
    if (
      observed.rowCount !== 1 ||
      canonicalAuthorizationJson(
        source.rootAncestry === undefined
          ? localRootExpiryPendingWitness.parse(observed.rows[0]?.witness)
          : localRootExpiryPendingAncestryWitness.parse(observed.rows[0]?.witness),
      ) !==
        canonicalAuthorizationJson(
          source.rootAncestry === undefined
            ? source.pending
            : { pending: source.pending, rootAncestry: source.rootAncestry },
        )
    )
      deny();
  }
  if (source.rootAncestry !== undefined) {
    if (!verifier) deny();
    await readCurrentRootExpiryPendingAncestry(
      client,
      source,
      { pending: source.pending, rootAncestry: source.rootAncestry },
      verifier!,
    );
  }
  return {
    root,
    now: new Date(row!.now),
    rootRevision: row!.rootRevision,
    participantEpoch: row!.participantEpoch,
  };
}

async function assertOwner(client: PoolClient) {
  const role =
    await client.query(`select current_user='openpc_control_owner' and pg_has_role(session_user,'openpc_control_owner','MEMBER')
    and exists(select 1 from pg_roles where rolname=session_user and rolcanlogin and not rolsuper and not rolbypassrls) allowed`);
  if (role.rowCount !== 1 || role.rows[0]?.allowed !== true) deny();
}
export async function installRootExpiryRecoveryTrust(
  client: PoolClient,
  input: unknown,
  localQaEnabled: boolean,
  verifier?: Pick<IdentityRuntimeEvidenceSigner, 'verifyCanonicalAssertion'>,
) {
  await assertOwner(client);
  if (localQaDurationMultiplier(process.env) === 10)
    await client.query("select set_config('openpc.local_qa_duration_profile','LOCAL_QA_10X',true)");
  const trust = localRootExpiryRecoveryReceivingTrust.parse(input);
  const source = await readRootExpiryInstallationSource(client, trust, localQaEnabled, verifier);
  const nowNs = BigInt(source.now.getTime()) * 1000000n;
  if (
    BigInt(source.root.grantable.validUntilNs) > nowNs ||
    Date.parse(trust.validFrom) > source.now.getTime() ||
    Date.parse(trust.validUntil) <= source.now.getTime()
  )
    deny();
  const digest = canonicalAuthorizationDigest(trust);
  await client.query(
    `insert into control.root_expiry_recovery_trust(custody_trust_id,participant_id,privacy_domain_id,platform_context_id,
    document,document_digest,valid_from,valid_until) values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(custody_trust_id) do nothing`,
    [
      trust.custodyTrustId,
      trust.participantId,
      trust.privacyDomainId,
      trust.platformContextId,
      trust,
      bytes(digest),
      trust.validFrom,
      trust.validUntil,
    ],
  );
  const saved = await client.query(
    `select document,document_digest,state,row_version::text,created_at from control.root_expiry_recovery_trust
    where participant_id=$1 and privacy_domain_id=$2 and custody_trust_id=$3 for share`,
    [trust.participantId, trust.privacyDomainId, trust.custodyTrustId],
  );
  const row = saved.rows[0];
  if (
    saved.rowCount !== 1 ||
    !row ||
    row.state !== 'ACTIVE' ||
    row.row_version !== '1' ||
    canonicalAuthorizationDigest(localRootExpiryRecoveryReceivingTrust.parse(row.document)) !==
      digest ||
    !row.document_digest.equals(bytes(digest))
  )
    deny();
  return {
    custodyTrustId: trust.custodyTrustId,
    digest,
    state: 'INSTALLED' as const,
    authority: 'NONE' as const,
  };
}
export async function enrollRootExpiryRecovery(
  client: PoolClient,
  input: unknown,
  localQaEnabled: boolean,
  verifier?: Pick<IdentityRuntimeEvidenceSigner, 'verifyCanonicalAssertion'>,
) {
  await assertOwner(client);
  if (localQaDurationMultiplier(process.env) === 10)
    await client.query("select set_config('openpc.local_qa_duration_profile','LOCAL_QA_10X',true)");
  const signed = signedLocalRootExpiryRecoveryEnrollment.parse(input),
    d = signed.document;
  const source = await readRootExpiryInstallationSource(client, d, localQaEnabled, verifier);
  const selected = await client.query(
    `select document,document_digest,state,row_version::text,created_at from control.root_expiry_recovery_trust
    where participant_id=$1 and privacy_domain_id=$2 and custody_trust_id=$3 for share`,
    [d.participantId, d.privacyDomainId, d.custodyTrustId],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    row.state !== 'ACTIVE' ||
    row.row_version !== '1' ||
    !row.document_digest.equals(bytes(d.custodyTrustDigest))
  )
    deny();
  const { enrollment } = authenticateLocalRootExpiryRecoveryCustody(row.document, signed);
  localRootExpirySuccessorScope(
    source.root,
    enrollment,
    source.rootRevision,
    source.now,
    localQaEnabled,
    localQaDurationMultiplier(process.env) === 10,
  );
  const digest = canonicalAuthorizationDigest(enrollment);
  const existing = await client.query(
    `select enrollment_id from control.root_expiry_recovery_enrollment
     where participant_id=$1 and privacy_domain_id=$2 and enrollment_id=$3 for share`,
    [d.participantId, d.privacyDomainId, d.enrollmentId],
  );
  if (existing.rowCount === 0)
    await client.query(
      `insert into control.root_expiry_recovery_enrollment(enrollment_id,participant_id,privacy_domain_id,platform_context_id,
    custody_trust_id,custody_trust_digest,document,document_digest,signature,valid_from,valid_until)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict(enrollment_id) do nothing`,
      [
        d.enrollmentId,
        d.participantId,
        d.privacyDomainId,
        d.platformContextId,
        d.custodyTrustId,
        bytes(d.custodyTrustDigest),
        enrollment,
        bytes(digest),
        Buffer.from(signed.signature, 'base64url'),
        d.validFrom,
        d.validUntil,
      ],
    );
  const saved = await client.query(
    `select document,document_digest,signature,state,row_version::text,created_at from control.root_expiry_recovery_enrollment
    where participant_id=$1 and privacy_domain_id=$2 and enrollment_id=$3 for share`,
    [d.participantId, d.privacyDomainId, d.enrollmentId],
  );
  const original = saved.rows[0];
  if (
    saved.rowCount !== 1 ||
    !original ||
    original.state !== 'ACTIVE' ||
    original.row_version !== '1' ||
    canonicalAuthorizationDigest(original.document) !== digest ||
    !original.document_digest.equals(bytes(digest)) ||
    !original.signature.equals(Buffer.from(signed.signature, 'base64url'))
  )
    deny();
  assertLocalRootExpiryRecoveryInstallationTime(
    enrollment,
    new Date(original.created_at),
    new Date(row.created_at),
  );
  await assertRootExpiryRecoveryHumans(client, enrollment, localQaEnabled);
  return {
    enrollmentId: d.enrollmentId,
    revision: '1',
    digest,
    state: 'ENROLLED' as const,
    authority: 'NONE' as const,
    assurance: d.assurance,
  };
}
export async function assertRootExpiryRecoveryHumans(
  client: PoolClient,
  enrollment: LocalRootExpiryRecoveryEnrollment,
  localQaEnabled: boolean,
) {
  await assertPlatformRecoverySigners(client, enrollment, localQaEnabled);
  const executorGrants = await client.query(
    `select openpc.root_expiry_recovery_executor_has_grants($1) as forbidden`,
    [enrollment.enrollmentId],
  );
  if (executorGrants.rowCount !== 1 || executorGrants.rows[0]?.forbidden !== false) deny();
  // Installation custody may preserve only the original Root-bound human recipients.
  const admins = await client.query(
    `select distinct principal_id::text from control.authority_envelope where participant_id=$1
    and platform_context_id=$2 and platform_authority_epoch=$3 and principal_id=any($4::uuid[])`,
    [
      enrollment.participantId,
      enrollment.platformContextId,
      enrollment.rootEpoch,
      enrollment.administratorPrincipalIds,
    ],
  );
  if (admins.rowCount !== 2) deny();
}
