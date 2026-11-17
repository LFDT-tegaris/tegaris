import { localQaDurationMultiplier } from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  encodeEnvelopeScope,
  decodeIdentityAuthContextAssertionPayload,
  platformEnvelopeScopeExpiryRecoveryPreimage,
  platformEnvelopeScopeExpiryRecoveryDigest,
  type PlatformEnvelopeScopeExpiryRecovery,
} from '../../../../packages/security-kernel/src/index.js';
import {
  localRootExpiryRecoveryEnrollment,
  localRootExpiryRecoveryIntent,
  localRootExpiryRecoveryAuthority,
  localRootExpiryPendingRecoveryAuthority,
  localRootExpiryPendingAncestryAuthority,
} from '../contracts/local-root-expiry-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import {
  authenticateLocalRootExpiryRecoveryCustody,
  localRootExpirySuccessorScope,
  assertLocalRootExpiryRecoveryInstallationTime,
} from '../domain/local-root-expiry-recovery.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { localRootExpiryRecoveryEvidencePayload } from '../domain/local-root-expiry-recovery-evidence.js';
import { signIdentityEnvelopeRecoveryEvidence } from '../domain/identity-envelope-recovery-evidence.js';
import {
  assertPlatformRecoveryCeremony,
  platformRecoverySignerForPhase,
  platformRecoveryProofMaxAgeMs,
} from '../domain/platform-recovery-ceremony.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeEvidenceSigner,
} from '../domain/identity-kernel.js';
import type { PlatformRecoveryCommand } from './platform-recovery-command.js';
import {
  issuePlatformRecoveryChallenge,
  acceptPlatformRecoveryProof,
  readPlatformRecoverySession,
  type PlatformRecoveryCeremonyContext,
} from './platform-recovery-proof.js';
import {
  readCurrentRootExpiryPendingAncestry,
  authenticateRootExpiryPendingAncestry,
} from './root-expiry-recovery-ancestry.js';
import { assertRootExpiryRecoveryHumans } from './root-expiry-recovery-installation.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
const deny = (): never => {
  throw new PlatformRecoveryError();
};
const bytes = (v: string) => Buffer.from(v.slice(7), 'hex');
const recoveryAuthority = (version: number) =>
  version === 3
    ? localRootExpiryPendingAncestryAuthority
    : version === 2
      ? localRootExpiryPendingRecoveryAuthority
      : localRootExpiryRecoveryAuthority;

async function readStoredEnrollment(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string | undefined,
  enrollmentId: string,
) {
  const selected = await client.query<{
    document: unknown;
    document_digest: Buffer;
    signature: Buffer;
    state: string;
    row_version: string;
    trust: unknown;
    trust_digest: Buffer;
    trust_state: string;
    trust_revision: string;
    enrollment_created_at: Date;
    trust_created_at: Date;
  }>(
    `select e.document,e.document_digest,e.signature,e.state,e.row_version::text,t.document as trust,t.document_digest as trust_digest,
      e.created_at as enrollment_created_at,t.created_at as trust_created_at,
      t.state as trust_state,t.row_version::text as trust_revision from openpc.lock_root_expiry_recovery_enrollment($1) e
      join control.root_expiry_recovery_trust t on t.custody_trust_id=e.custody_trust_id and t.participant_id=e.participant_id
      and t.privacy_domain_id=e.privacy_domain_id and t.document_digest=e.custody_trust_digest
      where e.enrollment_id=$1 and e.participant_id=$2 and ($3::uuid is null or e.privacy_domain_id=$3)`,
    [enrollmentId, participantId, privacyDomainId ?? null],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) deny();
  const enrollment = localRootExpiryRecoveryEnrollment.parse(row!.document);
  const original = authenticateLocalRootExpiryRecoveryCustody(row!.trust, {
    document: enrollment,
    signature: row!.signature.toString('base64url'),
  });
  if (
    enrollment.enrollmentId !== enrollmentId ||
    enrollment.participantId !== participantId ||
    (privacyDomainId !== undefined && enrollment.privacyDomainId !== privacyDomainId) ||
    canonicalAuthorizationDigest(enrollment) !== `sha256:${row!.document_digest.toString('hex')}` ||
    canonicalAuthorizationDigest(original.trust) !== `sha256:${row!.trust_digest.toString('hex')}`
  )
    deny();
  return {
    enrollment,
    revision: row!.row_version,
    state: row!.state,
    trust: original.trust,
    trustState: row!.trust_state,
    trustRevision: row!.trust_revision,
    enrollmentCreatedAt: new Date(row!.enrollment_created_at),
    trustCreatedAt: new Date(row!.trust_created_at),
  };
}
async function readEnrollment(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
) {
  // Existing lock/RLS selects the command privacy context. Public reads still
  // require an enrolled actor's real Platform session; historical consumers do not borrow it.
  const original = await readStoredEnrollment(client, actor.participantId, undefined, enrollmentId);
  const e = original.enrollment;
  if (
    ![
      e.recoveryPrincipal.principalId,
      ...e.custodians.map((v) => v.principalId),
      ...e.administratorPrincipalIds,
    ].includes(actor.principalId)
  )
    deny();
  await readPlatformRecoverySession(client, actor, e);
  return original;
}
async function readSource(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  localQaEnabled: boolean,
  verifier: Pick<IdentityRuntimeEvidenceSigner, 'verifyCanonicalAssertion'>,
) {
  const original = await readEnrollment(client, actor, enrollmentId);
  assertLocalRootExpiryRecoveryInstallationTime(
    original.enrollment,
    original.enrollmentCreatedAt,
    original.trustCreatedAt,
  );
  if (
    original.state !== 'ACTIVE' ||
    original.revision !== '1' ||
    original.trustState !== 'ACTIVE' ||
    original.trustRevision !== '1'
  )
    deny();
  if (!localQaEnabled) deny();
  const selected = await client.query<{
    rootRevision: string;
    participantEpoch: string;
    now: Date;
  }>(
    `select root_revision::text as "rootRevision",participant_epoch::text as "participantEpoch",server_now as now
      from openpc.read_root_expiry_recovery_source($1)`,
    [enrollmentId],
  );
  if (selected.rowCount !== 1 || !selected.rows[0]) deny();
  const source = {
    root: await readCurrentPlatformScope(client, original.enrollment.platformContextId),
    rootRevision: selected.rows[0]!.rootRevision,
    participantEpoch: selected.rows[0]!.participantEpoch,
    now: new Date(selected.rows[0]!.now),
  };
  if (
    Date.parse(original.trust.validFrom) > source.now.getTime() ||
    Date.parse(original.trust.validUntil) <= source.now.getTime()
  )
    deny();
  const successorScope = localRootExpirySuccessorScope(
    source.root,
    original.enrollment,
    source.rootRevision,
    source.now,
    localQaEnabled,
    localQaDurationMultiplier(process.env) === 10,
  );
  if (original.enrollment.schemaVersion === 3)
    await readCurrentRootExpiryPendingAncestry(
      client,
      original.enrollment,
      { pending: original.enrollment.pending, rootAncestry: original.enrollment.rootAncestry },
      verifier,
    );
  await assertRootExpiryRecoveryHumans(client, original.enrollment, localQaEnabled);
  return { ...original, ...source, successorScope };
}
async function readCase(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
) {
  const original = await readEnrollment(client, actor, enrollmentId);
  return readStoredCase(client, original, recoveryId);
}
async function readStoredCase(
  client: PoolClient,
  original: Awaited<ReturnType<typeof readStoredEnrollment>>,
  recoveryId: string,
) {
  const enrollmentId = original.enrollment.enrollmentId;
  const selected = await client.query<{
    intent: unknown;
    intent_digest: Buffer;
    state: string;
    row_version: string;
    result: unknown;
    operation_id: string | null;
    evidence_cbor: Buffer | null;
    evidence_digest: Buffer | null;
    evidence_cose: Buffer | null;
  }>(
    `select intent,intent_digest,state,row_version::text,result,operation_id::text,evidence_cbor,evidence_digest,evidence_cose
      from control.root_expiry_recovery_case where participant_id=$1 and privacy_domain_id=$2 and enrollment_id=$3 and recovery_id=$4 for update`,
    [
      original.enrollment.participantId,
      original.enrollment.privacyDomainId,
      enrollmentId,
      recoveryId,
    ],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) deny();
  const intent = localRootExpiryRecoveryIntent.parse(row!.intent);
  if (
    intent.enrollmentId !== enrollmentId ||
    intent.schemaVersion !== original.enrollment.schemaVersion ||
    (intent.schemaVersion === 2 &&
      (original.enrollment.schemaVersion !== 2 ||
        canonicalAuthorizationJson(intent.pending) !==
          canonicalAuthorizationJson(original.enrollment.pending))) ||
    (intent.schemaVersion === 3 &&
      (original.enrollment.schemaVersion !== 3 ||
        canonicalAuthorizationJson(intent.pending) !==
          canonicalAuthorizationJson(original.enrollment.pending) ||
        canonicalAuthorizationJson(intent.rootAncestry) !==
          canonicalAuthorizationJson(original.enrollment.rootAncestry))) ||
    intent.recoveryId !== recoveryId ||
    intent.enrollmentRevision !== original.revision ||
    intent.enrollmentDigest !== canonicalAuthorizationDigest(original.enrollment) ||
    canonicalAuthorizationDigest(intent) !== `sha256:${row!.intent_digest.toString('hex')}`
  )
    deny();
  const selectedProofs = await client.query<{
    proofId: string;
    principalId: string;
    principalEpoch: string;
    credentialId: string;
    credentialEpoch: string;
    sessionId: string;
    sessionEpoch: string;
    phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE';
    intentDigest: string;
    verifiedAt: Date;
    verifiedProofMaxAgeMs: 300000 | 3000000;
  }>(
    `select proof_id::text as "proofId",principal_id::text as "principalId",principal_epoch::text as "principalEpoch",
      credential_id::text as "credentialId",credential_epoch::text as "credentialEpoch",session_id::text as "sessionId",session_epoch::text as "sessionEpoch",
      phase,'sha256:'||encode(intent_digest,'hex') as "intentDigest",verified_at as "verifiedAt",
      (select h.verified_proof_max_age_ms::integer from control.root_expiry_recovery_challenge h
        where h.participant_id=proof.participant_id and h.privacy_domain_id=proof.privacy_domain_id
          and h.recovery_id=proof.recovery_id and h.challenge_id=proof.challenge_id and h.proof_id=proof.proof_id) as "verifiedProofMaxAgeMs"
      from control.root_expiry_recovery_proof proof
      where participant_id=$1 and privacy_domain_id=$2 and recovery_id=$3 order by verified_at,proof_id`,
    [original.enrollment.participantId, original.enrollment.privacyDomainId, recoveryId],
  );
  if (
    (selectedProofs.rowCount ?? 0) > 4 ||
    selectedProofs.rows.some((proof) => ![300000, 3000000].includes(proof.verifiedProofMaxAgeMs))
  )
    deny();
  return {
    ...original,
    intent,
    row: row!,
    proofs: selectedProofs.rows.map((v) => ({ ...v, verifiedAt: new Date(v.verifiedAt) })),
  };
}
/** Historical receipt authentication confers no actor/session/lease authority. Callers must separately fence their own purpose. */
export async function readCompletedRootExpiryRecoverySource(
  client: PoolClient,
  binding: {
    participantId: string;
    privacyDomainId: string;
    enrollmentId: string;
    recoveryId: string;
  },
  verifier: Pick<IdentityRuntimeEvidenceSigner, 'verifyCanonicalAssertion'>,
) {
  const original = await readStoredEnrollment(
    client,
    binding.participantId,
    binding.privacyDomainId,
    binding.enrollmentId,
  );
  assertLocalRootExpiryRecoveryInstallationTime(
    original.enrollment,
    original.enrollmentCreatedAt,
    original.trustCreatedAt,
  );
  const read = await readStoredCase(client, original, binding.recoveryId);
  await authenticateCompletedRootExpiryRecoveryReceipt(client, read, verifier);
  const effect = await client.query<{
    payload_cbor: Buffer;
    payload_digest: Buffer;
    cose_sign1: Buffer;
  }>(
    `select payload_cbor,payload_digest,cose_sign1 from control.outbox_event
      where participant_id=$1 and privacy_domain_id=$2 and aggregate_type='local-root-expiry-recovery'
        and aggregate_id=$3 and aggregate_sequence=1 and event_id=$4
        and event_type='openpc.identity.local-root-expiry-recovery.completed.v1'`,
    [binding.participantId, binding.privacyDomainId, binding.recoveryId, read.row.operation_id],
  );
  if (
    effect.rowCount !== 1 ||
    !effect.rows[0] ||
    !effect.rows[0].payload_cbor.equals(read.row.evidence_cbor!) ||
    !effect.rows[0].payload_digest.equals(read.row.evidence_digest!) ||
    !effect.rows[0].cose_sign1.equals(read.row.evidence_cose!)
  )
    deny();
  return read;
}

export async function authenticateCompletedRootExpiryRecoveryReceipt(
  client: PoolClient,
  read: Awaited<ReturnType<typeof readCase>>,
  signer: Pick<IdentityRuntimeEvidenceSigner, 'verifyCanonicalAssertion'>,
) {
  const { enrollment: e, row } = read;
  if (row.state !== 'COMPLETED') deny();
  {
    if (
      !row.evidence_cbor ||
      !row.evidence_digest ||
      !row.evidence_cose ||
      !createHash('sha256').update(row.evidence_cbor).digest().equals(row.evidence_digest) ||
      !(await signer.verifyCanonicalAssertion(row.evidence_cbor, row.evidence_cose))
    )
      deny();
    const decoded = decodeIdentityAuthContextAssertionPayload(row.evidence_cbor!);
    const required = new Set([
      `REQUEST:${e.recoveryPrincipal.principalId}`,
      `ACTIVATE:${e.recoveryPrincipal.principalId}`,
      ...e.custodians.map((v) => `APPROVE:${v.principalId}`),
    ]);
    if (read.proofs.length !== 4 || new Set(read.proofs.map((v) => v.proofId)).size !== 4) deny();
    for (const proof of read.proofs) {
      const expected = platformRecoverySignerForPhase(e, proof.principalId, proof.phase);
      const verifiedAtNs = BigInt(proof.verifiedAt.getTime()) * 1000000n;
      if (
        !required.delete(`${proof.phase}:${proof.principalId}`) ||
        proof.principalEpoch !== expected.principalEpoch ||
        proof.credentialId !== expected.credentialId ||
        proof.credentialEpoch !== expected.credentialEpoch ||
        proof.intentDigest !== canonicalAuthorizationDigest(read.intent) ||
        verifiedAtNs < BigInt(Date.parse(read.intent.validFrom)) * 1000000n ||
        verifiedAtNs > decoded.issuedAtNs ||
        decoded.issuedAtNs - verifiedAtNs >=
          BigInt(platformRecoveryProofMaxAgeMs(proof, read.intent)) * 1000000n
      )
        deny();
    }
    if (required.size !== 0) deny();

    if (
      decoded.issuedAtNs < BigInt(Date.parse(read.intent.validFrom)) * 1000000n ||
      decoded.issuedAtNs >= BigInt(Date.parse(read.intent.validUntil)) * 1000000n ||
      !localRootExpiryRecoveryEvidencePayload(
        e,
        read.intent,
        row.operation_id!,
        row.result,
        read.proofs,
        decoded.issuedAtNs,
      ).equals(row.evidence_cbor!)
    )
      deny();
    const selected = await client.query(
      `select * from control.root_expiry_recovery_scope where recovery_id=$1 and owner_participant_id=$2`,
      [read.intent.recoveryId, e.participantId],
    );
    const scope = selected.rows[0];
    if (
      selected.rowCount !== 1 ||
      !scope ||
      scope.activation_operation_id !== row.operation_id ||
      !scope.enrollment_digest.equals(bytes(read.intent.enrollmentDigest)) ||
      !scope.intent_digest.equals(bytes(canonicalAuthorizationDigest(read.intent)))
    )
      deny();
    const value: PlatformEnvelopeScopeExpiryRecovery = {
      admission: {
        platformContextId: e.platformContextId,
        ownerParticipantId: e.participantId,
        installationPrivacyDomainId: e.privacyDomainId,
        platformAuthorityEpoch: (BigInt(e.rootEpoch) + 1n).toString(),
        environmentId: e.installationEnvironmentId,
        installationDigest: e.installationDigest,
        grantable: read.intent.successorScope,
      },
      recoveryId: read.intent.recoveryId,
      activationOperationId: row.operation_id!,
      enrollmentDigest: read.intent.enrollmentDigest,
      intentDigest: canonicalAuthorizationDigest(read.intent),
      predecessorEpoch: e.rootEpoch,
      predecessorDigest: e.rootDigest,
    };
    if (
      !scope.admission_preimage.equals(platformEnvelopeScopeExpiryRecoveryPreimage(value)) ||
      !scope.admission_digest.equals(bytes(platformEnvelopeScopeExpiryRecoveryDigest(value))) ||
      !scope.scope_cbor.equals(encodeEnvelopeScope(read.intent.successorScope)) ||
      canonicalAuthorizationJson(row.result) !==
        canonicalAuthorizationJson({
          rootEpoch: value.admission.platformAuthorityEpoch,
          rootRevision: (BigInt(e.rootRevision) + 1n).toString(),
          rootDigest: platformEnvelopeScopeExpiryRecoveryDigest(value),
          operationId: row.operation_id,
        })
    )
      deny();
  }
  return read;
}

async function receipt(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  recoveryId: string,
  signer: IdentityRuntimeEvidenceSigner,
) {
  const read = await readCase(client, actor, enrollmentId, recoveryId);
  const { enrollment: e, row } = read;
  if (row.state === 'COMPLETED') {
    await authenticateCompletedRootExpiryRecoveryReceipt(client, read, signer);
    if (e.schemaVersion === 3)
      await authenticateRootExpiryPendingAncestry(
        client,
        e,
        { pending: e.pending, rootAncestry: e.rootAncestry },
        signer,
      );
  }
  return {
    actors: {
      executorPrincipalId: e.recoveryPrincipal.principalId,
      custodianPrincipalIds: e.custodians.map((v) => v.principalId),
    },
    recoveryId,
    enrollmentId,
    purpose: recoveryAuthority(e.schemaVersion),
    intent: read.intent,
    intentDigest: canonicalAuthorizationDigest(read.intent),
    revision: row.row_version,
    state: row.state,
    authority: 'NONE' as const,
    assurance: e.assurance,
    proofs: read.proofs.map(({ principalId, phase, proofId }) => ({ principalId, phase, proofId })),
    result: row.result,
  };
}

export async function executeRootExpiryRecoveryCommand(
  client: PoolClient,
  actor: AuthenticatedIdentityActor,
  enrollmentId: string,
  command: PlatformRecoveryCommand,
  origin: string,
  operationId: string,
  localQaEnabled: boolean,
  signer: IdentityRuntimeEvidenceSigner,
) {
  if (!localQaEnabled || command.kind === 'ROTATION_CREATE' || command.kind === 'ROTATION_ADVANCE')
    deny();
  if (command.kind === 'READ')
    return receipt(client, actor, enrollmentId, command.recoveryId, signer);
  if (command.kind === 'CLOSE') {
    const original = await readCase(client, actor, enrollmentId, command.recoveryId);
    if (
      ![
        original.enrollment.recoveryPrincipal.principalId,
        ...original.enrollment.custodians.map((v) => v.principalId),
      ].includes(actor.principalId)
    )
      deny();
    if (['DRAFT', 'REQUESTED'].includes(original.row.state))
      await client.query(
        `update control.root_expiry_recovery_case
      set state=case when valid_until<=clock_timestamp() then 'EXPIRED' else 'REVOKED' end,row_version=row_version+1,updated_at=clock_timestamp()
      where participant_id=$1 and recovery_id=$2 and state in ('DRAFT','REQUESTED')`,
        [actor.participantId, command.recoveryId],
      );
    return receipt(client, actor, enrollmentId, command.recoveryId, signer);
  }
  if (command.kind === 'PROVE') {
    const prior = await client.query(
      `select p.assertion_evidence->'assertion' as assertion,p.session_id::text,p.session_epoch::text
      from control.root_expiry_recovery_proof p join control.root_expiry_recovery_challenge h on h.challenge_id=p.challenge_id and h.proof_id=p.proof_id
      join control.root_expiry_recovery_case c on c.recovery_id=p.recovery_id and c.participant_id=p.participant_id
      where p.participant_id=$1 and c.enrollment_id=$2 and p.recovery_id=$3 and p.principal_id=$4 and p.phase=$5 and p.challenge_id=$6
      and p.intent_digest=$7 and h.origin=$8 and h.challenge_digest=$9 and h.consumed_at is not null`,
      [
        actor.participantId,
        enrollmentId,
        command.recoveryId,
        actor.principalId,
        command.phase,
        command.proof.challengeId,
        bytes(command.proof.intentDigest),
        origin,
        createHash('sha256').update(command.proof.challenge).digest(),
      ],
    );
    if (prior.rowCount !== 0) {
      const original = await readCase(client, actor, enrollmentId, command.recoveryId),
        session = await readPlatformRecoverySession(client, actor, original.enrollment);
      const row = prior.rows[0];
      if (
        prior.rowCount !== 1 ||
        !row ||
        canonicalAuthorizationJson(row.assertion) !==
          canonicalAuthorizationJson(JSON.parse(command.proof.assertion)) ||
        row.session_id !== session.sessionId ||
        row.session_epoch !== session.sessionEpoch
      )
        deny();
      return receipt(client, actor, enrollmentId, command.recoveryId, signer);
    }
  }
  const source = await readSource(client, actor, enrollmentId, localQaEnabled, signer),
    e = source.enrollment;
  if (command.kind === 'SOURCE') {
    const live = await client.query(
      `select recovery_id::text as "recoveryId",state from control.root_expiry_recovery_case
      where participant_id=$1 and enrollment_id=$2 and state in ('DRAFT','REQUESTED')`,
      [actor.participantId, enrollmentId],
    );
    if ((live.rowCount ?? 0) > 1) deny();
    return {
      enrollmentId,
      purpose: recoveryAuthority(e.schemaVersion),
      authority: 'NONE',
      assurance: e.assurance,
      actors: {
        executorPrincipalId: e.recoveryPrincipal.principalId,
        custodianPrincipalIds: e.custodians.map((v) => v.principalId),
      },
      source: {
        rootEpoch: e.rootEpoch,
        rootRevision: e.rootRevision,
        rootDigest: e.rootDigest,
        ...(e.schemaVersion !== 1 ? { pending: e.pending } : {}),
        ...(e.schemaVersion === 3 ? { rootAncestry: e.rootAncestry } : {}),
        expiredAt: new Date(
          Number(BigInt(source.root.grantable.validUntilNs) / 1000000n),
        ).toISOString(),
      },
      successorScope: source.successorScope,
      liveCase: live.rows[0] ?? null,
    };
  }
  if (command.kind === 'CREATE') {
    if ('preparation' in command || actor.principalId !== e.recoveryPrincipal.principalId) deny();
    const intent = localRootExpiryRecoveryIntent.parse({
      schema: 'pc.identity.local-root-expiry-recovery-intent',
      schemaVersion: e.schemaVersion,
      purpose: recoveryAuthority(e.schemaVersion),
      ...(e.schemaVersion !== 1 ? { pending: e.pending } : {}),
      ...(e.schemaVersion === 3 ? { rootAncestry: e.rootAncestry } : {}),
      recoveryId: localOperationId(),
      enrollmentId,
      enrollmentRevision: source.revision,
      enrollmentDigest: canonicalAuthorizationDigest(e),
      sourceParticipantEpoch: source.participantEpoch,
      predecessorEpoch: e.rootEpoch,
      predecessorRevision: e.rootRevision,
      predecessorDigest: e.rootDigest,
      ...(e.qaDurationProfile ? { qaDurationProfile: e.qaDurationProfile } : {}),
      successorScope: source.successorScope,
      validFrom: source.now.toISOString(),
      validUntil: new Date(
        Math.min(
          source.now.getTime() + (e.qaDurationProfile ? 9000000 : 900000),
          Date.parse(e.validUntil),
        ),
      ).toISOString(),
    });
    await client.query(
      `insert into control.root_expiry_recovery_case(recovery_id,participant_id,privacy_domain_id,enrollment_id,enrollment_revision,enrollment_digest,
      intent,intent_digest,valid_from,valid_until) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        intent.recoveryId,
        e.participantId,
        e.privacyDomainId,
        enrollmentId,
        source.revision,
        bytes(intent.enrollmentDigest),
        intent,
        bytes(canonicalAuthorizationDigest(intent)),
        intent.validFrom,
        intent.validUntil,
      ],
    );
    return {
      intent,
      intentDigest: canonicalAuthorizationDigest(intent),
      state: 'DRAFT',
      authority: 'NONE',
      assurance: e.assurance,
    };
  }
  const original = await readCase(client, actor, enrollmentId, command.recoveryId);
  if (
    original.intent.sourceParticipantEpoch !== source.participantEpoch ||
    original.intent.predecessorEpoch !== e.rootEpoch ||
    original.intent.predecessorRevision !== e.rootRevision ||
    original.intent.predecessorDigest !== e.rootDigest ||
    canonicalAuthorizationJson(original.intent.successorScope) !==
      canonicalAuthorizationJson(source.successorScope)
  )
    deny();
  const context: PlatformRecoveryCeremonyContext = {
    enrollment: e,
    intent: original.intent,
    state: original.row.state,
    proofs: original.proofs,
    now: source.now,
  };
  if (command.kind === 'CHALLENGE')
    return issuePlatformRecoveryChallenge(client, context, actor, command.phase, origin);
  if (command.kind !== 'PROVE') return deny();
  const proof = await acceptPlatformRecoveryProof(
    client,
    context,
    actor,
    command.phase,
    origin,
    command.proof,
  );
  if (command.phase === 'REQUEST') {
    const updated = await client.query(
      `update control.root_expiry_recovery_case set state='REQUESTED',row_version=row_version+1,updated_at=clock_timestamp()
      where recovery_id=$1 and participant_id=$2 and state='DRAFT' and valid_until>clock_timestamp()`,
      [command.recoveryId, actor.participantId],
    );
    if (updated.rowCount !== 1) deny();
  } else if (command.phase === 'ACTIVATE') {
    assertPlatformRecoveryCeremony(
      e,
      original.intent,
      original.row.state,
      original.proofs,
      'ACTIVATE',
      actor.principalId,
      source.now,
    );
    const intentDigest = canonicalAuthorizationDigest(original.intent);
    const value: PlatformEnvelopeScopeExpiryRecovery = {
      admission: {
        platformContextId: source.root.platformContextId,
        ownerParticipantId: source.root.ownerParticipantId,
        installationPrivacyDomainId: source.root.installationPrivacyDomainId,
        environmentId: source.root.environmentId,
        installationDigest: source.root.installationDigest,
        platformAuthorityEpoch: (BigInt(e.rootEpoch) + 1n).toString(),
        grantable: source.successorScope,
      },
      recoveryId: command.recoveryId,
      activationOperationId: operationId,
      enrollmentDigest: original.intent.enrollmentDigest,
      intentDigest,
      predecessorEpoch: e.rootEpoch,
      predecessorDigest: e.rootDigest,
    };
    const result = {
      rootEpoch: value.admission.platformAuthorityEpoch,
      rootRevision: (BigInt(e.rootRevision) + 1n).toString(),
      rootDigest: platformEnvelopeScopeExpiryRecoveryDigest(value),
      operationId,
    };
    const payload = localRootExpiryRecoveryEvidencePayload(
      e,
      original.intent,
      operationId,
      result,
      [...original.proofs, proof],
      BigInt(source.now.getTime()) * 1000000n,
    );
    const signed = await signIdentityEnvelopeRecoveryEvidence(payload, signer);
    const committed = await client.query(
      `select openpc.commit_root_expiry_recovery($1,$2,$3,$4,$5,$6,$7,$8) as result`,
      [
        command.recoveryId,
        proof.proofId,
        encodeEnvelopeScope(source.successorScope),
        platformEnvelopeScopeExpiryRecoveryPreimage(value),
        signed.evidenceCbor,
        signed.evidenceDigest,
        signed.coseSign1,
        result,
      ],
    );
    if (
      committed.rowCount !== 1 ||
      canonicalAuthorizationJson(committed.rows[0]?.result) !== canonicalAuthorizationJson(result)
    )
      deny();
  }
  return receipt(client, actor, enrollmentId, command.recoveryId, signer);
}
