import type { PoolClient } from 'pg';
import {
  discoveryCertificateRecoveryEnrollment,
  discoveryCertificateRecoveryIntent,
  type DiscoveryCertificateRecoveryEnrollment,
  type DiscoveryCertificateRecoveryIntent,
} from '../contracts/discovery-certificate-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  assertDiscoveryCertificateRecoverySource,
  discoveryCertificateRecoveryAdministratorEpochs,
  assertDiscoveryCertificateRecoveryTrust,
  discoveryCertificateRecoveryPermissions,
  discoveryCertificateRecoveryResumeActions,
  type DiscoveryCertificateRecoverySource,
} from '../domain/discovery-certificate-recovery.js';
import { PlatformRecoveryError } from '../domain/platform-recovery-policy.js';
import {
  readExpiredPlatformAdministration,
  assertPlatformRecoverySigners,
  readRootExpiryPlatformAdministration,
} from './platform-recovery-enrollment.js';
import { readPlatformRecoverySession } from './platform-recovery-proof.js';
import type {
  AuthenticatedIdentityActor,
  IdentityRuntimeAssertionVerifier,
} from '../domain/identity-kernel.js';
import { platformRecoverySourceCeiling } from '../domain/platform-recovery-policy.js';

/** Must retain the Participant write fence and exact enrollment/Root locks.
 * The SQL owner returns scoped facts only, never credential bytes or authority. */
export async function readDiscoveryCertificateRecoveryTransport(
  client: PoolClient,
  enrollment: DiscoveryCertificateRecoveryEnrollment,
  recoveryId: string | null = null,
) {
  const result = await client.query<{ source: DiscoveryCertificateRecoverySource }>(
    'select source from openpc.lock_discovery_certificate_recovery_source($1,$2)',
    [enrollment.enrollmentId, recoveryId],
  );
  const row = result.rows[0];
  if (result.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const source = {
    ...row.source,
    now: new Date(row.source.now),
    notBefore: new Date(row.source.notBefore),
    notAfter: new Date(row.source.notAfter),
  };
  assertDiscoveryCertificateRecoverySource(enrollment.certificateRecovery, source);
  return source;
}

/** Current installation trust, original expired administration and exact
 * workload facts precede every new custody challenge and lease activation. */
export async function readDiscoveryCertificateRecoverySource(
  client: PoolClient,
  enrollmentId: string,
  localQaEnabled: boolean,
  actor?: AuthenticatedIdentityActor,
  recoveryId: string | null = null,
  verifier?: IdentityRuntimeAssertionVerifier,
) {
  const selected = await client.query<{
    document: unknown;
    document_digest: Buffer;
    row_version: string;
    state: string;
  }>(
    'select document,document_digest,row_version::text,state from openpc.lock_platform_recovery_enrollment($1)',
    [enrollmentId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw new PlatformRecoveryError();
  const enrollment = discoveryCertificateRecoveryEnrollment.parse(row.document);
  if (
    enrollment.enrollmentId !== enrollmentId ||
    canonicalAuthorizationDigest(enrollment) !== `sha256:${row.document_digest.toString('hex')}`
  )
    throw new PlatformRecoveryError();
  if (actor) {
    if (
      ![
        enrollment.recoveryPrincipal.principalId,
        ...enrollment.custodians.map((v) => v.principalId),
        ...enrollment.administratorPrincipalIds,
      ].includes(actor.principalId)
    )
      throw new PlatformRecoveryError();
    await readPlatformRecoverySession(client, actor, enrollment);
  } else {
    const owner = await client.query<{ allowed: boolean }>(
      "select current_user='openpc_control_owner' allowed",
    );
    if (owner.rows[0]?.allowed !== true) throw new PlatformRecoveryError();
  }
  if (enrollment.schemaVersion === 2 && !localQaEnabled) throw new PlatformRecoveryError();
  const current =
    enrollment.schemaVersion === 2
      ? await readRootExpiryPlatformAdministration(client, enrollment, verifier)
      : await readExpiredPlatformAdministration(client, enrollment);
  const ceiling = platformRecoverySourceCeiling({ root: current.root, enrollment });
  const administrators = current.originalAdministrators.map((v) => {
    const epoch = current.administratorEpochs.find((p) => p.principalId === v.principalId);
    if (!epoch) throw new PlatformRecoveryError();
    const permissions = discoveryCertificateRecoveryPermissions(
      enrollment.certificateRecovery,
      enrollment.privacyDomainId,
      v.principalId,
    );
    if (
      permissions.actionIntentIds.some(
        (action) =>
          !ceiling.administration.actionIntentIds.includes(action) ||
          (enrollment.schemaVersion === 2 &&
            (!v.usable.administration.actionIntentIds.includes(action) ||
              !v.grantable.administration.actionIntentIds.includes(action))),
      )
    )
      throw new PlatformRecoveryError();
    return {
      principalId: v.principalId,
      principalEpoch: epoch.principalEpoch,
      roleId: v.roleId,
      roleRevision: v.expectedRoleRevision,
      roleDigest: v.roleDigest,
      riskClasses: v.usable.administration.riskClasses.filter((risk) =>
        ceiling.administration.riskClasses.includes(risk),
      ),
    };
  });
  if (administrators.length !== 2 || administrators.some((v) => v.riskClasses.length === 0))
    throw new PlatformRecoveryError();
  let frozenAdministrators: DiscoveryCertificateRecoveryIntent['administrators'] = [
    administrators[0]!,
    administrators[1]!,
  ];
  let intentVersion: 1 | 2 | undefined;
  if (recoveryId !== null) {
    const selectedCase = await client.query<{
      intent: unknown;
      intentDigest: Buffer;
      state: string;
      bindings: { principalId: string; principalEpoch: string }[] | null;
    }>(
      `select intent,intent_digest as "intentDigest",state,lease_bindings as bindings from control.platform_recovery_case
       where participant_id=$1 and privacy_domain_id=$2 and enrollment_id=$3 and recovery_id=$4 for share`,
      [enrollment.participantId, enrollment.privacyDomainId, enrollmentId, recoveryId],
    );
    const stored = selectedCase.rows[0];
    if (selectedCase.rowCount !== 1 || !stored) throw new PlatformRecoveryError();
    const intent = discoveryCertificateRecoveryIntent.parse(stored.intent);
    intentVersion = intent.schemaVersion;
    if (
      intent.recoveryId !== recoveryId ||
      intent.enrollmentId !== enrollmentId ||
      intent.enrollmentRevision !== row.row_version ||
      intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
      canonicalAuthorizationDigest(intent) !== `sha256:${stored.intentDigest.toString('hex')}`
    )
      throw new PlatformRecoveryError();
    frozenAdministrators = discoveryCertificateRecoveryAdministratorEpochs(
      frozenAdministrators,
      intent,
      stored.state,
      stored.bindings,
    );
  }
  const source = {
    enrollment,
    enrollmentState: row.state,
    enrollmentRevision: row.row_version,
    rootState: current.rootState,
    platformContextId: current.root.platformContextId,
    rootOwnerParticipantId: current.root.ownerParticipantId,
    rootPrivacyDomainId: current.root.installationPrivacyDomainId,
    rootEpoch: current.root.platformAuthorityEpoch,
    rootRevision: current.rootRevision,
    rootDigest: current.rootDigest,
    rootValidFrom: new Date(Number(BigInt(current.root.grantable.validFromNs) / 1000000n)),
    rootValidUntil: new Date(Number(BigInt(current.root.grantable.validUntilNs) / 1000000n)),
    administrationExpired: current.administrationExpired,
    originalAdministrationDisplaced:
      'originalAdministrationDisplaced' in current &&
      current.originalAdministrationDisplaced === true,
    rootAdministrationEmpty: Object.values(current.root.grantable.administration).every(
      (values) => values.length === 0,
    ),
    localQaEnabled,
    now: current.now,
    administrators: frozenAdministrators,
  };
  assertDiscoveryCertificateRecoveryTrust(source);
  await assertPlatformRecoverySigners(client, enrollment, localQaEnabled);
  const rolesPermitResume = await assertDiscoveryCertificateRecoveryRoles(
    client,
    source,
    intentVersion ?? 1,
  );
  const declaredPermitResume =
    enrollment.schemaVersion === 2 &&
    enrollment.source.originalAdministrators.every((administrator) =>
      ['usable', 'grantable'].every(
        (scope) =>
          canonicalAuthorizationDigest(
            administrator[scope as 'usable' | 'grantable'].administration.actionIntentIds,
          ) === canonicalAuthorizationDigest(discoveryCertificateRecoveryResumeActions),
      ),
    );
  if (intentVersion === 2 && (!declaredPermitResume || !rolesPermitResume || !localQaEnabled))
    throw new PlatformRecoveryError();
  const transport = await readDiscoveryCertificateRecoveryTransport(client, enrollment, recoveryId);
  return {
    ...source,
    transport,
    intentVersion:
      intentVersion ??
      ((declaredPermitResume && rolesPermitResume && localQaEnabled ? 2 : 1) as 1 | 2),
  };
}

async function assertDiscoveryCertificateRecoveryRoles(
  client: PoolClient,
  source: {
    enrollment: DiscoveryCertificateRecoveryEnrollment;
    administrators: DiscoveryCertificateRecoveryIntent['administrators'];
  },
  intentVersion: 1 | 2,
) {
  let supportsResume = true;
  for (const administrator of source.administrators) {
    const result = await client.query<{
      role: { roleId: string; version: string; actions: string[] };
    }>(
      `select jsonb_build_object('roleId',r.role_id,'version',r.row_version::text,'actions',r.action_intent_ids,
        'origin',r.origin,'createdByPrincipalId',r.created_by_principal_id::text,'creatorParticipantId',r.creator_participant_id::text,
        'bootstrapMandateId',r.bootstrap_mandate_id::text,'bootstrapPlatformParticipantId',r.bootstrap_platform_participant_id::text) role
       from control.authority_role r where r.participant_id=$1 and r.authority_role_id=$2 and r.state='ACTIVE' for share`,
      [source.enrollment.participantId, administrator.roleId],
    );
    const role = result.rows[0]?.role;
    if (
      result.rowCount !== 1 ||
      !role ||
      role.version !== administrator.roleRevision ||
      canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId: source.enrollment.participantId,
        role,
      }) !== administrator.roleDigest ||
      discoveryCertificateRecoveryPermissions(
        source.enrollment.certificateRecovery,
        source.enrollment.privacyDomainId,
        administrator.principalId,
        intentVersion,
      ).actionIntentIds.some((v) => !role.actions.includes(v))
    )
      throw new PlatformRecoveryError();
    supportsResume &&= discoveryCertificateRecoveryResumeActions.every((action) =>
      role.actions.includes(action),
    );
  }
  return supportsResume;
}
