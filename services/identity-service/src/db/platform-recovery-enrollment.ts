import { createHash } from 'node:crypto';
import { readClosedPlatformApprovalSource } from './platform-recovery-closed-approval.js';
import type { PoolClient } from 'pg';
import {
  platformAdministrationRecoveryEnrollment,
  type RootExpiryPlatformRecoveryEnrollment,
  type PendingPlatformRecoveryEnrollment,
  type PendingExpiryPlatformRecoveryEnrollment,
  type PlatformRecoveryIntent,
} from '../contracts/platform-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformScopeReplacementPreparation } from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import {
  PlatformRecoveryError,
  assertPlatformRecoverySource,
  platformRecoverySourceCeiling,
  type PlatformRecoverySource,
} from '../domain/platform-recovery-policy.js';
import { localRootExpiryRecoveryReceiptView } from '../contracts/local-root-expiry-recovery.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
import type { RecoveryCustodyEnrollment } from '../domain/platform-recovery-ceremony.js';
import { discoveryCertificateRecoveryEnrollment } from '../contracts/discovery-certificate-recovery.js';
import { readDiscoveryCertificateRecoverySource } from './discovery-certificate-recovery-source.js';
import { readCompletedRootExpiryRecoverySource } from './root-expiry-recovery-command.js';
import {
  readPendingPlatformRecoveryContinuation,
  readPendingPlatformRecoveryExpiry,
  readUneffectedPlatformRecoveryPredecessor,
} from './platform-recovery-continuation.js';
import type { IdentityRuntimeAssertionVerifier } from '../domain/identity-kernel.js';

const deny = () => new PlatformRecoveryError();

/** Read original intent and real expiry. Revocation, partial expiry or a different current Root is not recovery eligibility. */
export async function readExpiredPlatformAdministration(
  client: PoolClient,
  enrollment: RecoveryCustodyEnrollment,
) {
  if (
    enrollment.schema === 'pc.identity.identity-envelope-recovery-enrollment' ||
    enrollment.schema === 'pc.identity.local-root-expiry-recovery-enrollment' ||
    enrollment.schemaVersion !== 1
  )
    throw deny();
  const root = await readCurrentPlatformScope(
    client,
    enrollment.platformContextId,
    enrollment.rootEpoch,
  );
  const selected = await client.query<{
    candidate: unknown;
    candidateDigest: Buffer;
    rootRevision: string;
    rootState: string;
    now: Date;
    pending: string | null;
  }>(
    `select r.candidate,r.candidate_digest as "candidateDigest",p.row_version::text as "rootRevision",p.state as "rootState",
       clock_timestamp() as now,(select q.replacement_id::text from control.platform_scope_replacement q
         where q.platform_context_id=p.platform_context_id and q.state='WITHDRAWING') as pending
     from control.platform_context p join control.platform_envelope_scope_successor s
       on s.platform_context_id=p.platform_context_id and s.platform_authority_epoch=p.authority_epoch
     join control.platform_scope_replacement r on r.replacement_id=s.replacement_id
       and r.platform_context_id=p.platform_context_id and r.state='COMMITTED'
       and r.successor_digest=s.admission_digest
     where p.platform_context_id=$1 and p.owner_participant_id=$2 and r.privacy_domain_id=$3
       and r.replacement_id=$4 and p.authority_epoch=$5`,
    [
      enrollment.platformContextId,
      enrollment.participantId,
      enrollment.privacyDomainId,
      enrollment.expiredReplacementId,
      enrollment.rootEpoch,
    ],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw deny();
  const preparation = platformScopeReplacementPreparation.parse(row.candidate);
  if (canonicalAuthorizationDigest(preparation) !== `sha256:${row.candidateDigest.toString('hex')}`)
    throw deny();
  const now = new Date(row.now);
  const nowNs = BigInt(now.getTime()) * 1_000_000n;
  const declared = preparation.administrators;
  const expired =
    declared.length === 2 &&
    declared.every(
      (v) => BigInt(v.usable.validUntilNs) <= nowNs && BigInt(v.grantable.validUntilNs) <= nowNs,
    );
  const actual = await client.query<{
    principalId: string;
    principalEpoch: string;
    assignmentId: string;
    envelopeId: string;
  }>(
    `select a.principal_id::text as "principalId",p.authority_epoch::text as "principalEpoch",
       a.assignment_id::text as "assignmentId",e.authority_envelope_id::text as "envelopeId" from control.assignment a
       join control.authority_envelope e on e.participant_id=a.participant_id and e.authority_envelope_id=a.authority_envelope_id
       join control.principal p on p.participant_id=a.participant_id and p.principal_id=a.principal_id and p.state='ACTIVE'
     join unnest($2::uuid[],$3::uuid[],$6::uuid[]) declared(assignment_id,envelope_id,principal_id)
       on declared.assignment_id=a.assignment_id and declared.envelope_id=e.authority_envelope_id and declared.principal_id=a.principal_id
     where a.participant_id=$1
       and a.state='ACTIVE' and e.state='ACTIVE' and upper(a.valid_during)<=clock_timestamp()
       and e.valid_until<=clock_timestamp() and e.platform_context_id=$4 and e.platform_authority_epoch=$5
     order by p.principal_id for share of a,e,p`,
    [
      enrollment.participantId,
      declared.map((v) => v.assignmentId),
      declared.map((v) => v.envelopeId),
      enrollment.platformContextId,
      enrollment.rootEpoch,
      declared.map((v) => v.principalId),
    ],
  );
  return {
    root,
    rootRevision: row.rootRevision,
    rootState: row.rootState,
    rootDigest: root.platformAuthorityDigest,
    now,
    pendingReplacementId: row.pending,
    preparation,
    originalAdministrators: declared,
    administratorPrincipalIds: declared.map((v) => v.principalId),
    administratorEpochs: actual.rows.map(({ principalId, principalEpoch }) => ({
      principalId,
      principalEpoch,
    })),
    administrationExpired:
      expired &&
      actual.rowCount === 2 &&
      declared.every((v) =>
        actual.rows.some(
          (a) =>
            a.principalId === v.principalId &&
            a.assignmentId === v.assignmentId &&
            a.envelopeId === v.envelopeId,
        ),
      ),
  };
}

/** Receipt facts do not restore a grant. The installation owner separately
 * enrolls finite declarations, bound to the exact displaced original rows. */
export async function readRootExpiryPlatformAdministration<
  E extends Omit<
    | RootExpiryPlatformRecoveryEnrollment
    | PendingPlatformRecoveryEnrollment
    | PendingExpiryPlatformRecoveryEnrollment,
    'schema'
  >,
>(client: PoolClient, enrollment: E, verifier: IdentityRuntimeAssertionVerifier | undefined) {
  if (!verifier || enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR') throw deny();
  const references = [enrollment.source, ...(enrollment.source.ancestorReceipts ?? [])];
  if (
    references.length > 32 ||
    ['recoveryId', 'enrollmentId', 'activationOperationId'].some(
      (field) =>
        new Set(
          references.map(
            (v) => v[field as 'recoveryId' | 'enrollmentId' | 'activationOperationId'],
          ),
        ).size !== references.length,
    )
  )
    throw deny();
  const receipts: Awaited<ReturnType<typeof readCompletedRootExpiryRecoverySource>>[] = [];
  for (const reference of references) {
    const current = await readCompletedRootExpiryRecoverySource(
      client,
      {
        participantId: enrollment.participantId,
        privacyDomainId: enrollment.privacyDomainId,
        enrollmentId: reference.enrollmentId,
        recoveryId: reference.recoveryId,
      },
      verifier,
    );
    if (
      current.row.operation_id !== reference.activationOperationId ||
      !current.row.evidence_digest ||
      `sha256:${current.row.evidence_digest.toString('hex')}` !== reference.receiptDigest ||
      current.enrollment.platformContextId !== enrollment.platformContextId ||
      current.enrollment.participantId !== enrollment.participantId ||
      current.enrollment.privacyDomainId !== enrollment.privacyDomainId ||
      enrollment.administratorPrincipalIds.some(
        (id, i) => id !== current.enrollment.administratorPrincipalIds[i],
      )
    )
      throw deny();
    const next = receipts.at(-1);
    const result = localRootExpiryRecoveryReceiptView.shape.result.parse(current.row.result);
    if (
      next &&
      (result?.rootEpoch !== next.enrollment.rootEpoch ||
        result?.rootRevision !== next.enrollment.rootRevision ||
        result?.rootDigest !== next.enrollment.rootDigest ||
        (BigInt(current.enrollment.rootEpoch) + 1n).toString() !== next.enrollment.rootEpoch ||
        (BigInt(current.enrollment.rootRevision) + 1n).toString() !== next.enrollment.rootRevision)
    )
      throw deny();
    receipts.push(current);
  }
  const receipt = receipts[0]!;
  const administrationReceipt = receipts.at(-1)!;
  const latestResult = localRootExpiryRecoveryReceiptView.shape.result.parse(receipt.row.result);
  const root = await readCurrentPlatformScope(
    client,
    enrollment.platformContextId,
    enrollment.rootEpoch,
  );
  if (
    latestResult?.rootEpoch !== enrollment.rootEpoch ||
    latestResult?.rootRevision !== enrollment.rootRevision ||
    latestResult?.rootDigest !== enrollment.rootDigest ||
    latestResult?.operationId !== receipt.row.operation_id ||
    receipts.some(
      (v) =>
        canonicalAuthorizationDigest(v.intent.successorScope.runtime) !==
        canonicalAuthorizationDigest(root.grantable.runtime),
    ) ||
    receipt.row.operation_id !== enrollment.source.activationOperationId ||
    !receipt.row.evidence_digest ||
    `sha256:${receipt.row.evidence_digest.toString('hex')}` !== enrollment.source.receiptDigest ||
    receipt.enrollment.platformContextId !== enrollment.platformContextId ||
    (BigInt(receipt.enrollment.rootEpoch) + 1n).toString() !== enrollment.rootEpoch ||
    (BigInt(receipt.enrollment.rootRevision) + 1n).toString() !== enrollment.rootRevision ||
    root.platformAuthorityDigest !== enrollment.rootDigest ||
    enrollment.administratorPrincipalIds.some(
      (id, i) => id !== receipt.enrollment.administratorPrincipalIds[i],
    )
  )
    throw deny();
  const state = await client.query<{
    rootRevision: string;
    rootState: string;
    now: Date;
    pending: string | null;
  }>(
    `select row_version::text as "rootRevision",state as "rootState",clock_timestamp() as now,
    (select replacement_id::text from control.platform_scope_replacement where platform_context_id=$1 and state='WITHDRAWING') as pending
    from control.platform_context where platform_context_id=$1 and owner_participant_id=$2 and authority_epoch=$3`,
    [enrollment.platformContextId, enrollment.participantId, enrollment.rootEpoch],
  );
  if (state.rowCount !== 1 || !state.rows[0]) throw deny();
  const declared = enrollment.source.originalAdministrators;
  const actual = await client.query<{
    principalId: string;
    principalEpoch: string;
    assignmentId: string;
    envelopeId: string;
    assignmentRevision: string;
    envelopeRevision: string;
    roleId: string;
    role: { roleId: string; version: string; actions: string[] };
    envelopeActions: string[];
    assignmentActions: string[];
  }>(
    `select p.principal_id::text as "principalId",p.authority_epoch::text as "principalEpoch",
      a.assignment_id::text as "assignmentId",e.authority_envelope_id::text as "envelopeId",
      a.row_version::text as "assignmentRevision",e.row_version::text as "envelopeRevision",r.authority_role_id::text as "roleId",
      e.action_intent_ids as "envelopeActions",a.action_intent_ids as "assignmentActions",
      jsonb_build_object('roleId',r.role_id,'version',r.row_version::text,'actions',r.action_intent_ids,
        'origin',r.origin,'createdByPrincipalId',r.created_by_principal_id::text,'creatorParticipantId',r.creator_participant_id::text,
        'bootstrapMandateId',r.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',r.bootstrap_platform_participant_id::text) as role
    from control.assignment a join control.authority_envelope e on e.participant_id=a.participant_id and e.authority_envelope_id=a.authority_envelope_id
    join control.principal p on p.participant_id=a.participant_id and p.principal_id=a.principal_id
    join control.authority_role r on r.participant_id=a.participant_id and r.role_id=a.role_id
    join unnest($2::uuid[],$3::uuid[],$4::uuid[]) selected(assignment_id,envelope_id,principal_id)
      on selected.assignment_id=a.assignment_id and selected.envelope_id=e.authority_envelope_id and selected.principal_id=a.principal_id
    where a.participant_id=$1 and a.state='ACTIVE' and e.state='ACTIVE' and p.state='ACTIVE' and p.kind='PLATFORM_OPERATOR'
      and e.principal_id=a.principal_id and e.platform_context_id=$5 and e.platform_authority_epoch=$6
      and e.representation='LEGACY' and a.delegation_epoch=e.delegation_epoch and r.state='ACTIVE'
    order by p.principal_id for share of a,e,p,r`,
    [
      enrollment.participantId,
      declared.map((v) => v.assignmentId),
      declared.map((v) => v.envelopeId),
      declared.map((v) => v.principalId),
      enrollment.platformContextId,
      administrationReceipt.enrollment.rootEpoch,
    ],
  );
  if (actual.rowCount !== 2 || actual.rows.length !== 2) throw deny();
  for (const administrator of declared) {
    const row = actual.rows.find((v) => v.principalId === administrator.principalId);
    if (
      !row ||
      row.assignmentId !== administrator.assignmentId ||
      row.envelopeId !== administrator.envelopeId ||
      row.assignmentRevision !== administrator.assignmentRevision ||
      row.envelopeRevision !== administrator.envelopeRevision ||
      row.roleId !== administrator.roleId ||
      row.role.version !== administrator.expectedRoleRevision ||
      canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId: enrollment.participantId,
        role: row.role,
      }) !== administrator.roleDigest
    )
      throw deny();
    for (const scope of [administrator.usable, administrator.grantable]) {
      if (
        scope.administration.participantIds.length !== 1 ||
        scope.administration.participantIds[0] !== enrollment.participantId ||
        scope.administration.privacyDomainIds.length !== 1 ||
        scope.administration.privacyDomainIds[0] !== enrollment.privacyDomainId ||
        scope.administration.actionIntentIds.some(
          (action) =>
            !row.role.actions.includes(action) ||
            !row.envelopeActions.includes(action) ||
            !row.assignmentActions.includes(action),
        ) ||
        BigInt(scope.validUntilNs) > BigInt(root.grantable.validUntilNs)
      )
        throw deny();
    }
  }
  const originalAdministrators = declared.map((v) => ({
    principalId: v.principalId,
    envelopeId: v.envelopeId,
    assignmentId: v.assignmentId,
    roleId: v.roleId,
    expectedRoleRevision: v.expectedRoleRevision,
    roleDigest: v.roleDigest,
    usable: v.usable,
    grantable: v.grantable,
  }));
  const rootExpiryPendingBridge: PlatformRecoverySource['rootExpiryPendingBridge'] =
    receipt.enrollment.schemaVersion === 2 && latestResult
      ? {
          pending: receipt.enrollment.pending,
          rootEpoch: latestResult.rootEpoch,
          rootRevision: latestResult.rootRevision,
          rootDigest: latestResult.rootDigest,
          receipt: {
            recoveryId: enrollment.source.recoveryId,
            enrollmentId: enrollment.source.enrollmentId,
            activationOperationId: enrollment.source.activationOperationId,
            receiptDigest: enrollment.source.receiptDigest,
          },
        }
      : undefined;
  const source = {
    root,
    ...(rootExpiryPendingBridge ? { rootExpiryPendingBridge } : {}),
    ...state.rows[0],
    now: new Date(state.rows[0].now),
    rootDigest: root.platformAuthorityDigest,
    pendingReplacementId: state.rows[0].pending,
    enrollment,
    enrollmentState: 'ACTIVE',
    enrollmentRevision: '1',
    expiredReplacementId: null,
    originalAdministrators,
    administratorPrincipalIds: enrollment.administratorPrincipalIds,
    administratorEpochs: actual.rows.map(({ principalId, principalEpoch }) => ({
      principalId,
      principalEpoch,
    })),
    administrationExpired: false,
    originalAdministrationDisplaced: true,
    plannedRecordIds: [],
    localQaEnabled: true,
  };
  const preparation: PlatformRecoveryIntent['preparation'] = {
    schema: 'pc.identity.platform-scope-replacement' as const,
    schemaVersion: 1 as const,
    replacementId: enrollment.source.recoveryId,
    platformContextId: enrollment.platformContextId,
    expectedRootRevision: enrollment.rootRevision,
    predecessorEpoch: enrollment.rootEpoch,
    predecessorDigest: enrollment.rootDigest,
    successorScope: platformRecoverySourceCeiling(source),
    administrators: originalAdministrators,
    affectedTargets: [],
    reason: 'Restore finite administration after the independently governed Root expiry recovery.',
  };
  return { ...source, preparation };
}

/** Current credential facts, checked on enrollment and every subsequent ceremony/lease boundary. */
export async function assertPlatformRecoverySigners(
  client: PoolClient,
  enrollment: Pick<
    RecoveryCustodyEnrollment,
    'participantId' | 'assurance' | 'recoveryPrincipal' | 'custodians' | 'validUntil'
  >,
  localQaEnabled: boolean,
): Promise<void> {
  if (enrollment.assurance === 'LOCAL_QA_VIRTUAL_AUTHENTICATOR' && !localQaEnabled) throw deny();
  const signers = [enrollment.recoveryPrincipal, ...enrollment.custodians].sort((a, b) =>
    a.principalId.localeCompare(b.principalId),
  );
  for (const signer of signers) {
    const result = await client.query<{
      publicKey: Buffer;
      publicKeyDigest: Buffer;
      hardware: boolean;
    }>(
      `select c.public_key_spki_der as "publicKey",c.public_key_digest as "publicKeyDigest",
         exists(select 1 from control.hardware_authenticator h where h.participant_id=c.participant_id
           and h.principal_id=c.principal_id and h.credential_id=c.credential_id) as hardware
       from control.principal p join control.credential c on c.participant_id=p.participant_id and c.principal_id=p.principal_id
       where p.participant_id=$1 and p.principal_id=$2 and p.state='ACTIVE' and p.kind in ('USER','PLATFORM_OPERATOR')
         and p.authority_epoch=$3 and c.credential_id=$4 and c.credential_epoch=$5 and c.kind='WEBAUTHN' and c.state='ACTIVE'
         and c.valid_from<=clock_timestamp() and (c.valid_until is null or c.valid_until>= $6::timestamptz)
       for share of p,c`,
      [
        enrollment.participantId,
        signer.principalId,
        signer.principalEpoch,
        signer.credentialId,
        signer.credentialEpoch,
        enrollment.validUntil,
      ],
    );
    const row = result.rows[0];
    if (
      result.rowCount !== 1 ||
      !row ||
      !Buffer.isBuffer(row.publicKey) ||
      !Buffer.isBuffer(row.publicKeyDigest) ||
      !createHash('sha256').update(row.publicKey).digest().equals(row.publicKeyDigest) ||
      (enrollment.assurance === 'HARDWARE_ATTESTED' && !row.hardware)
    )
      throw deny();
  }
}

/** Supported installation-owner transaction. The caller must roll back on any
 * failure: provisional trust enables exact source reads but confers no authority.
 * Source and credential validation complete before the transaction may commit. */
export async function enrollPlatformRecovery(
  client: PoolClient,
  input: unknown,
  options: {
    readonly localQaEnabled: boolean;
    readonly verifier?: IdentityRuntimeAssertionVerifier;
  },
) {
  const discovery =
    input !== null &&
    typeof input === 'object' &&
    'schema' in input &&
    input.schema === 'pc.identity.discovery-certificate-recovery-enrollment';
  const enrollment = discovery
    ? discoveryCertificateRecoveryEnrollment.parse(input)
    : platformAdministrationRecoveryEnrollment.parse(input);
  if (enrollment.schemaVersion !== 1 && (!options.localQaEnabled || !options.verifier))
    throw deny();
  const role = await client.query<{ permitted: boolean }>(
    `select current_user='openpc_control_owner' as permitted`,
  );
  if (role.rowCount !== 1 || role.rows[0]?.permitted !== true) throw deny();
  const digest = canonicalAuthorizationDigest(enrollment);
  await client.query(
    `insert into control.platform_recovery_enrollment(enrollment_id,participant_id,privacy_domain_id,platform_context_id,
       expired_replacement_id,root_epoch,root_revision,root_digest,document,document_digest,valid_from,valid_until,source_purpose,root_expiry_recovery_id)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) on conflict(enrollment_id) do nothing`,
    [
      enrollment.enrollmentId,
      enrollment.participantId,
      enrollment.privacyDomainId,
      enrollment.platformContextId,
      enrollment.schemaVersion !== 1 ? null : enrollment.expiredReplacementId,
      enrollment.rootEpoch,
      enrollment.rootRevision,
      Buffer.from(enrollment.rootDigest.slice(7), 'hex'),
      enrollment,
      Buffer.from(digest.slice(7), 'hex'),
      enrollment.validFrom,
      enrollment.validUntil,
      enrollment.schemaVersion === 4
        ? 'PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
        : enrollment.schemaVersion === 3
          ? 'ROOT_EXPIRY_RECOVERY_CONTINUATION'
          : enrollment.schemaVersion === 2
            ? 'ROOT_EXPIRY_RECOVERY'
            : 'EXPIRED_REPLACEMENT',
      enrollment.schemaVersion !== 1 ? enrollment.source.recoveryId : null,
    ],
  );
  const result = await client.query<{
    document: unknown;
    digest: Buffer;
    revision: string;
    state: string;
  }>(
    `select document,document_digest as digest,row_version::text as revision,state from control.platform_recovery_enrollment
      where enrollment_id=$1 and participant_id=$2 and privacy_domain_id=$3 for share`,
    [enrollment.enrollmentId, enrollment.participantId, enrollment.privacyDomainId],
  );
  const row = result.rows[0];
  if (
    result.rowCount !== 1 ||
    !row ||
    row.state !== 'ACTIVE' ||
    row.revision !== '1' ||
    canonicalAuthorizationDigest(
      discovery
        ? discoveryCertificateRecoveryEnrollment.parse(row.document)
        : platformAdministrationRecoveryEnrollment.parse(row.document),
    ) !== digest ||
    row.digest.toString('hex') !== digest.slice(7)
  )
    throw deny();
  if (enrollment.schema === 'pc.identity.discovery-certificate-recovery-enrollment') {
    await readDiscoveryCertificateRecoverySource(
      client,
      enrollment.enrollmentId,
      options.localQaEnabled,
      undefined,
      null,
      options.verifier,
    );
    return {
      enrollmentId: enrollment.enrollmentId,
      revision: row.revision,
      digest,
      state: 'ENROLLED' as const,
      authority: 'NONE' as const,
      assurance: enrollment.assurance,
    };
  }
  const recovered =
    enrollment.schemaVersion !== 1
      ? await readRootExpiryPlatformAdministration(client, enrollment, options.verifier)
      : undefined;
  const source = recovered ?? (await readExpiredPlatformAdministration(client, enrollment));
  assertPlatformRecoverySource({
    ...source,
    enrollment,
    enrollmentState: 'ACTIVE',
    enrollmentRevision: '1',
    expiredReplacementId: enrollment.schemaVersion !== 1 ? null : enrollment.expiredReplacementId,
    plannedRecordIds: [],
    localQaEnabled: options.localQaEnabled,
  });
  if (enrollment.schemaVersion === 4) {
    await readPendingPlatformRecoveryExpiry(client, enrollment, options.verifier);
    if (enrollment.source.closedApproval)
      await readClosedPlatformApprovalSource(client, enrollment, options.verifier);
    if (source.pendingReplacementId !== enrollment.source.pendingExpiry.preparation.replacementId)
      throw deny();
  } else if (enrollment.schemaVersion === 3) {
    await readPendingPlatformRecoveryContinuation(client, enrollment, options.verifier);
    if (source.pendingReplacementId !== enrollment.source.continuation.replacementId) throw deny();
  } else if (enrollment.schemaVersion === 2 && enrollment.uneffectedPredecessor) {
    await readUneffectedPlatformRecoveryPredecessor(
      client,
      enrollment,
      options.verifier,
      recovered?.rootExpiryPendingBridge,
    );
    if (source.pendingReplacementId !== enrollment.uneffectedPredecessor.replacementId)
      throw deny();
  } else if (source.pendingReplacementId !== null) throw deny();
  await assertPlatformRecoverySigners(client, enrollment, options.localQaEnabled);
  return {
    enrollmentId: enrollment.enrollmentId,
    revision: row.revision,
    digest,
    state: 'ENROLLED' as const,
    authority: 'NONE' as const,
    assurance: enrollment.assurance,
  };
}
