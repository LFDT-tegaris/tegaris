import type {
  PlatformRecoveryIntent,
  PlatformAdministrationRecoveryEnrollment,
} from '../contracts/platform-recovery.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';

/** Fixed ceremony purpose; a custom role cannot add actions to this list. */
export const platformRecoveryLeaseActions = [
  'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1',
  'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-IDENTITY_DELETE_SESSION-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
  'ACT-OPERATIONS_READ_OPERATION-V1',
  'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
  'ACT-PARTICIPANT_CREATE_MEMBER-V1',
  'ACT-POLICY_APPROVE_REQUEST-V1',
  'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
] as const;

export const platformRecoveryContinuationLeaseActions = [
  ...platformRecoveryLeaseActions,
  'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
] as const;

/** Flat grants remain minimal even before the mandatory case/operation guard is applied. */
export function platformRecoveryLeasePermissions(
  enrollment: PlatformAdministrationRecoveryEnrollment,
  intent: PlatformRecoveryIntent,
  principalId: string,
  now: Date,
) {
  if (
    !enrollment.administratorPrincipalIds.includes(principalId) ||
    intent.enrollmentId !== enrollment.enrollmentId ||
    now.getTime() < Date.parse(intent.validFrom) ||
    now.getTime() >= Date.parse(intent.validUntil)
  )
    throw new PlatformRecoveryError();
  const administrator = intent.preparation.administrators.find(
    (v) => v.principalId === principalId,
  );
  if (!administrator) throw new PlatformRecoveryError();
  const allowed = intent.preparation.successorScope.administration.actionIntentIds;
  const actions =
    (enrollment.schemaVersion === 3 && !enrollment.source.activatedHandoff) ||
    (enrollment.schemaVersion === 4 && intent.approvalContinuation)
      ? platformRecoveryContinuationLeaseActions
      : platformRecoveryLeaseActions;
  const declaration =
    (enrollment.schemaVersion === 3 && !enrollment.source.activatedHandoff) ||
    (enrollment.schemaVersion === 4 && intent.approvalContinuation)
      ? enrollment.source.originalAdministrators.find((a) => a.principalId === principalId)
      : undefined;
  const actionIntentIds = actions.filter(
    (action) =>
      allowed.includes(action) ||
      (action === 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' &&
        (intent.continuation || intent.approvalContinuation) &&
        declaration?.usable.administration.actionIntentIds.includes(action) &&
        declaration.grantable.administration.actionIntentIds.includes(action)),
  );
  if (
    ((enrollment.schemaVersion === 3 && !enrollment.source.activatedHandoff) ||
      (enrollment.schemaVersion === 4 && intent.approvalContinuation)) &&
    !actionIntentIds.includes('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')
  )
    throw new PlatformRecoveryError();
  if (
    [
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
      'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      'ACT-POLICY_APPROVE_REQUEST-V1',
      'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
      'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    ].some((action) => !actionIntentIds.includes(action as (typeof actionIntentIds)[number]))
  )
    throw new PlatformRecoveryError();
  const resourceIds = [
    intent.preparation.platformContextId,
    intent.preparation.replacementId,
    principalId,
    `urn:openpc:self-session:${principalId}`,
    ...intent.preparation.administrators.flatMap((v) => [v.envelopeId, v.assignmentId, v.roleId]),
  ];
  return {
    privacyDomainIds: [enrollment.privacyDomainId],
    actionIntentIds: [...actionIntentIds].sort(),
    resourceIds: [...new Set(resourceIds)].sort(),
    riskClasses: [...administrator.usable.administration.riskClasses],
    capabilityIds: [] as string[],
    validFrom: now.toISOString(),
    validUntil: intent.validUntil,
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
    // Existing role remains an additional upper bound. The fixed recovery case supplies purpose authority.
    roleId: administrator.roleId,
  };
}
