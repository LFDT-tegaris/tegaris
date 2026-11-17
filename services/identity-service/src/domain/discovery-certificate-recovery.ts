import {
  discoveryCertificateRecovery,
  discoveryCertificateRotationCandidate,
  discoveryCertificateRecoveryEnrollment,
  discoveryCertificateRecoveryIntent,
  type DiscoveryCertificateRecovery,
  type DiscoveryCertificateRecoveryEnrollment,
  type DiscoveryCertificateRecoveryIntent,
} from '../contracts/discovery-certificate-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';

export interface DiscoveryCertificateRecoveryTrustSource {
  readonly enrollment: DiscoveryCertificateRecoveryEnrollment;
  readonly enrollmentState: string;
  readonly enrollmentRevision: string;
  readonly rootState: string;
  readonly platformContextId: string;
  readonly rootOwnerParticipantId: string;
  readonly rootPrivacyDomainId: string;
  readonly rootEpoch: string;
  readonly rootRevision: string;
  readonly rootDigest: string;
  readonly rootValidFrom: Date;
  readonly rootValidUntil: Date;
  readonly administrationExpired: boolean;
  /** Set only by the shared cryptographic receipt/original-row owner. */
  readonly originalAdministrationDisplaced?: boolean;
  readonly rootAdministrationEmpty?: boolean;
  readonly administrators: DiscoveryCertificateRecoveryIntent['administrators'];
  readonly localQaEnabled: boolean;
  readonly now: Date;
}

/** Independently validates installed trust and the current Root before any case exists. */
export function assertDiscoveryCertificateRecoveryTrust(
  source: DiscoveryCertificateRecoveryTrustSource,
): void {
  const enrollment = discoveryCertificateRecoveryEnrollment.parse(source.enrollment);
  const now = source.now.getTime();
  if (
    !Number.isFinite(now) ||
    source.enrollmentState !== 'ACTIVE' ||
    source.rootState !== 'ACTIVE' ||
    (enrollment.schemaVersion === 1
      ? !source.administrationExpired
      : !source.originalAdministrationDisplaced ||
        !source.rootAdministrationEmpty ||
        !source.localQaEnabled ||
        source.administrators.some((administrator) => {
          const declared = enrollment.source.originalAdministrators.find(
            (v) => v.principalId === administrator.principalId,
          );
          return (
            !declared ||
            administrator.roleId !== declared.roleId ||
            administrator.roleRevision !== declared.expectedRoleRevision ||
            administrator.roleDigest !== declared.roleDigest ||
            administrator.riskClasses.length === 0 ||
            administrator.riskClasses.some(
              (risk) =>
                !declared.usable.administration.riskClasses.includes(risk) ||
                !declared.grantable.administration.riskClasses.includes(risk),
            ) ||
            discoveryCertificateRecoveryPermissions(
              enrollment.certificateRecovery,
              enrollment.privacyDomainId,
              administrator.principalId,
            ).actionIntentIds.some(
              (action) =>
                !declared.usable.administration.actionIntentIds.includes(action) ||
                !declared.grantable.administration.actionIntentIds.includes(action),
            )
          );
        })) ||
    enrollment.platformContextId !== source.platformContextId ||
    enrollment.participantId !== source.rootOwnerParticipantId ||
    enrollment.privacyDomainId !== source.rootPrivacyDomainId ||
    enrollment.rootEpoch !== source.rootEpoch ||
    enrollment.rootRevision !== source.rootRevision ||
    enrollment.rootDigest !== source.rootDigest ||
    !Number.isFinite(source.rootValidFrom.getTime()) ||
    !Number.isFinite(source.rootValidUntil.getTime()) ||
    source.rootValidFrom.getTime() > now ||
    source.rootValidUntil.getTime() <= now ||
    Date.parse(enrollment.validFrom) > now ||
    Date.parse(enrollment.validUntil) <= now ||
    (enrollment.assurance === 'LOCAL_QA_VIRTUAL_AUTHENTICATOR' && !source.localQaEnabled)
  )
    throw new PlatformRecoveryError();
}

/** Freeze the pre-activation epochs only after the exact durable case proves
 * the one-step rotation. Current role/risk bounds are never normalized away. */
export function discoveryCertificateRecoveryAdministratorEpochs(
  current: DiscoveryCertificateRecoveryIntent['administrators'],
  intent: DiscoveryCertificateRecoveryIntent,
  state: string,
  bindings: readonly { principalId: string; principalEpoch: string }[] | null,
): DiscoveryCertificateRecoveryIntent['administrators'] {
  const frozen = discoveryCertificateRecoveryIntent.parse(intent).administrators;
  if (state !== 'ACTIVE') {
    if (
      bindings !== null ||
      canonicalAuthorizationDigest(current) !== canonicalAuthorizationDigest(frozen)
    )
      throw new PlatformRecoveryError();
    return current;
  }
  if (!bindings || bindings.length !== 2 || new Set(bindings.map((v) => v.principalId)).size !== 2)
    throw new PlatformRecoveryError();
  const normalized = current.map((v) => {
    const original = frozen.find((p) => p.principalId === v.principalId);
    const binding = bindings.find((p) => p.principalId === v.principalId);
    if (
      !original ||
      !binding ||
      v.principalEpoch !== binding.principalEpoch ||
      BigInt(v.principalEpoch) !== BigInt(original.principalEpoch) + 1n
    )
      throw new PlatformRecoveryError();
    return { ...v, principalEpoch: original.principalEpoch };
  }) as DiscoveryCertificateRecoveryIntent['administrators'];
  if (canonicalAuthorizationDigest(normalized) !== canonicalAuthorizationDigest(frozen))
    throw new PlatformRecoveryError();
  return normalized;
}

/** The installed purpose supplies credential authority explicitly. Root facts
 * remain current dependencies; finite target membership supplies no bridge. */
export function assertDiscoveryCertificateRecoveryIntent(
  input: DiscoveryCertificateRecoveryIntent,
  source: DiscoveryCertificateRecoveryTrustSource,
): void {
  assertDiscoveryCertificateRecoveryTrust(source);
  const enrollment = source.enrollment;
  const intent = discoveryCertificateRecoveryIntent.parse(input);
  const now = source.now.getTime();
  const from = Date.parse(intent.validFrom),
    until = Date.parse(intent.validUntil);
  if (
    (intent.schemaVersion === 2 &&
      (enrollment.schemaVersion !== 2 ||
        !source.localQaEnabled ||
        source.administrators.some((administrator) => {
          if (enrollment.schemaVersion !== 2) return true;
          const declared = enrollment.source.originalAdministrators.find(
            (v) => v.principalId === administrator.principalId,
          );
          return (
            !declared ||
            ['usable', 'grantable'].some(
              (scope) =>
                canonicalAuthorizationDigest(
                  declared[scope as 'usable' | 'grantable'].administration.actionIntentIds,
                ) !== canonicalAuthorizationDigest(discoveryCertificateRecoveryResumeActions),
            )
          );
        }))) ||
    intent.enrollmentId !== enrollment.enrollmentId ||
    intent.enrollmentRevision !== source.enrollmentRevision ||
    intent.enrollmentDigest !== canonicalAuthorizationDigest(enrollment) ||
    canonicalAuthorizationDigest(intent.certificateRecovery) !==
      canonicalAuthorizationDigest(enrollment.certificateRecovery) ||
    canonicalAuthorizationDigest(intent.administrators) !==
      canonicalAuthorizationDigest(source.administrators) ||
    intent.administrators.some(
      (v) => !enrollment.administratorPrincipalIds.includes(v.principalId),
    ) ||
    from > now ||
    until <= now ||
    from < Date.parse(enrollment.validFrom) ||
    until > Date.parse(enrollment.validUntil) ||
    until > source.rootValidUntil.getTime() ||
    (intent.lifetimes.profile !== 'C17' &&
      (!source.localQaEnabled || enrollment.assurance !== 'LOCAL_QA_VIRTUAL_AUTHENTICATOR'))
  )
    throw new PlatformRecoveryError();
}

export interface DiscoveryCertificateRecoverySource {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly participantState: string;
  readonly privacyState: string;
  readonly targetId: string;
  readonly targetParticipantId: string;
  readonly targetPrivacyDomainId: string;
  readonly targetRevision: string;
  readonly requiresAuthenticatedDiscovery: boolean;
  readonly workloadPrincipalId: string;
  readonly workloadPrincipalParticipantId: string;
  readonly workloadPrincipalState: string;
  readonly workloadPrincipalKind: string;
  readonly workloadPrincipalEpoch: string;
  readonly credentialId: string;
  readonly credentialParticipantId: string;
  readonly credentialPrincipalId: string;
  readonly credentialState: string;
  readonly credentialKind: string;
  readonly credentialRevision: string;
  readonly credentialEpoch: string;
  readonly certificateFingerprint: string;
  readonly certificateBytesDigest: string;
  readonly publicKeyDigest: string;
  readonly publicKeyBytesDigest: string;
  readonly issuer: string;
  readonly subject: string;
  readonly audience: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  /** An exact owner read under the same write fence, including pending issuance. */
  readonly competingSuccessor: boolean;
  readonly successorExists: boolean;
  readonly now: Date;
}

/** Additional source restriction only. The caller must independently validate
 * enrolled trust, current Root, custody, selected purpose lease and approvals. */
export function assertDiscoveryCertificateRecoverySource(
  input: DiscoveryCertificateRecovery,
  source: DiscoveryCertificateRecoverySource,
): void {
  const binding = discoveryCertificateRecovery.parse(input);
  const san = `urn:openpc:participant:${source.participantId}:workload:${binding.targetId}`;
  if (
    source.participantState !== 'ACTIVE' ||
    source.privacyState !== 'ACTIVE' ||
    source.targetParticipantId !== source.participantId ||
    source.targetPrivacyDomainId !== source.privacyDomainId ||
    source.targetId !== binding.targetId ||
    source.targetRevision !== binding.targetRevision ||
    !source.requiresAuthenticatedDiscovery ||
    source.workloadPrincipalId !== binding.workloadPrincipalId ||
    source.workloadPrincipalParticipantId !== source.participantId ||
    source.workloadPrincipalKind !== 'WORKLOAD' ||
    source.workloadPrincipalState !== 'ACTIVE' ||
    source.workloadPrincipalEpoch !== binding.workloadPrincipalEpoch ||
    source.credentialId !== binding.predecessorCredentialId ||
    source.credentialParticipantId !== source.participantId ||
    source.credentialPrincipalId !== binding.workloadPrincipalId ||
    source.credentialKind !== 'WORKLOAD_MTLS' ||
    source.credentialState !== 'ACTIVE' ||
    source.credentialRevision !== binding.predecessorRevision ||
    source.credentialEpoch !== binding.predecessorEpoch ||
    source.certificateFingerprint !== binding.predecessorFingerprint ||
    source.certificateBytesDigest !== binding.predecessorFingerprint ||
    source.publicKeyDigest !== binding.predecessorPublicKeyDigest ||
    source.publicKeyBytesDigest !== binding.predecessorPublicKeyDigest ||
    source.issuer !== binding.issuer ||
    source.subject !== san ||
    source.audience !== `urn:openpc:workload:${binding.targetId}` ||
    !Number.isFinite(source.now.getTime()) ||
    !Number.isFinite(source.notBefore.getTime()) ||
    !Number.isFinite(source.notAfter.getTime()) ||
    source.notBefore > source.now ||
    source.notAfter <= source.notBefore ||
    source.notAfter > source.now ||
    source.notAfter.getTime() !== Date.parse(binding.predecessorNotAfter) ||
    source.competingSuccessor ||
    source.successorExists
  )
    throw new PlatformRecoveryError();
}

/** Purpose never admits a different credential, key, operation or candidate.
 * Apply at staging AND again under commit fences before external issuer I/O. */
export function assertDiscoveryCertificateRecoveryOperation(
  binding: DiscoveryCertificateRecovery,
  catalogOperationId: string,
  resourceId: string,
  expectedRevision: string,
  candidate: unknown,
): void {
  if (
    catalogOperationId !== 'ID-OP-WORKLOAD-ROTATE' ||
    resourceId !== binding.predecessorCredentialId ||
    expectedRevision !== binding.predecessorRevision ||
    canonicalAuthorizationDigest(candidate) !==
      canonicalAuthorizationDigest(discoveryCertificateRotationCandidate(binding))
  )
    throw new PlatformRecoveryError();
}

/** Finite transport-purpose scope; existing role remains an additional bound. */
export const discoveryCertificateRecoveryActions = [
  'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-IDENTITY_DELETE_SESSION-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  'ACT-OPERATIONS_READ_OPERATION-V1',
  'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  'ACT-POLICY_APPROVE_REQUEST-V1',
  'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
] as const;

/** Version one remains the immutable ten-action signed contract. The new
 * command is admitted only by the stored approval-backed Discovery owner. */
export const discoveryCertificateRecoveryResumeActions = [
  ...discoveryCertificateRecoveryActions.slice(0, 2),
  'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
  ...discoveryCertificateRecoveryActions.slice(2),
] as const;

export function discoveryCertificateRecoveryPermissions(
  binding: DiscoveryCertificateRecovery,
  privacyDomainId: string,
  principalId: string,
  intentVersion: 1 | 2 = 1,
) {
  discoveryCertificateRecovery.parse(binding);
  return {
    actionIntentIds: [
      ...(intentVersion === 2
        ? discoveryCertificateRecoveryResumeActions
        : discoveryCertificateRecoveryActions),
    ],
    resourceIds: [
      ...new Set([
        binding.targetId,
        binding.workloadPrincipalId,
        binding.predecessorCredentialId,
        binding.successorCredentialId,
        principalId,
        `urn:openpc:self-session:${principalId}`,
      ]),
    ].sort(),
    privacyDomainIds: [privacyDomainId],
    capabilityIds: [] as string[],
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
}
