import type { RuntimeInvocationCapability } from '@openpc/security-kernel';

export type AuthorityDecision =
  'ALLOW' | 'DENY' | 'UNKNOWN' | 'UNAVAILABLE' | 'STALE' | 'CONFLICT' | 'TAMPERED' | 'INCOMPATIBLE';

export type AuthorityError =
  | 'PC-IDENTITY-1000'
  | 'PC-IDENTITY-1001'
  | 'PC-IDENTITY-1002'
  | 'PC-IDENTITY-1003'
  | 'PC-IDENTITY-1004'
  | 'PC-IDENTITY-1005'
  | 'PC-IDENTITY-1008'
  | 'PC-IDENTITY-1009';

export interface PermissionSet {
  readonly participantId: string;
  readonly privacyDomainIds: readonly string[];
  readonly actionIntentIds: readonly string[];
  /** Empty/absent grants no actor-facing runtime capability. */
  readonly capabilityIds?: readonly RuntimeInvocationCapability[];
  readonly resourceIds: readonly string[];
  readonly riskClasses: readonly string[];
  readonly validFrom: Date;
  readonly validUntil: Date | null;
  readonly makerCheckerRequired: boolean;
  readonly stepUpRequired: boolean;
  readonly onwardDelegationDepth: number;
}

export interface AuthorityEnvelope extends PermissionSet {
  readonly id: string;
  readonly authorityEpoch: string;
  /** Aggregate revision for governed lifecycle fencing and readback. */
  readonly revision?: string;
  readonly state: 'DRAFT' | 'SUBMITTED' | 'APPROVED' | 'ACTIVE' | 'SUPERSEDED' | 'REVOKED';
  readonly semanticDigest: string;
  /** Authenticated original CREATE binding for a governed administration handoff. */
  readonly platformScopeReplacementId?: string;
}

export interface Assignment extends PermissionSet {
  readonly id: string;
  readonly principalId: string;
  /** Absent on legacy assignments; absence grants no contract-policy role. */
  readonly roleId?: string;
  /** An additional membership constraint on this explicit grant; never a source of permissions. */
  readonly groupId?: string;
  readonly authorityEnvelopeId: string;
  readonly state: 'PROPOSED' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'EXPIRED';
  readonly delegationEpoch: string;
  readonly scopeDigest: string;
}

export interface Delegation extends PermissionSet {
  readonly id: string;
  readonly parentId: string;
  readonly grantorId: string;
  readonly granteeId: string;
  readonly state: 'PROPOSED' | 'ACTIVE' | 'SUSPENDED' | 'REVOKED' | 'EXPIRED';
  readonly delegationEpoch: string;
  readonly scopeDigest: string;
}

export interface AuthorizationRequest {
  readonly principalId: string;
  readonly participantId: string;
  readonly participantContextCount: number;
  readonly privacyDomainId: string;
  readonly actionIntentId: string;
  readonly resourceId: string;
  readonly riskClass: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly authorityEpoch: string;
  readonly delegationEpoch: string;
  readonly currentParticipantEpoch: string;
  readonly currentPrincipalEpoch: string;
  readonly currentAuthorityEpoch: string;
  readonly platformPermits: boolean;
  readonly policyAvailable: boolean;
  readonly factsAvailable: boolean;
  readonly factsTampered: boolean;
  readonly existenceVisible: boolean;
  readonly payloadVisible: boolean;
  readonly stepUpFresh: boolean;
  readonly makerPrincipalId?: string;
  readonly checkerPrincipalId?: string;
  readonly envelope: AuthorityEnvelope;
  readonly assignment: Assignment;
  readonly delegations: readonly Delegation[];
  readonly now: Date;
}

export interface AuthorizationEvaluation {
  readonly decision: AuthorityDecision;
  readonly authorized: boolean;
  readonly terminal: boolean;
  readonly existenceVisible: boolean;
  readonly payloadVisible: boolean;
  readonly explanationCodes: readonly string[];
  readonly errorCode?: AuthorityError;
}

function terminal(
  decision: Exclude<AuthorityDecision, 'ALLOW'>,
  code: AuthorityError,
): AuthorizationEvaluation {
  return {
    decision,
    authorized: false,
    terminal: true,
    existenceVisible: false,
    payloadVisible: false,
    explanationCodes: [code.replaceAll('-', '_')],
    errorCode: code,
  };
}

function contains(values: readonly string[], value: string): boolean {
  return values.includes(value);
}

function resourcePermits(values: readonly string[], resourceId: string): boolean {
  return contains(values, '*') || contains(values, resourceId);
}

function resourceSubset(child: readonly string[], parent: readonly string[]): boolean {
  return (
    contains(parent, '*') ||
    (!contains(child, '*') && child.every((value) => contains(parent, value)))
  );
}

function active(state: string): boolean {
  return state === 'ACTIVE';
}

function validAt(value: PermissionSet, now: Date): boolean {
  return value.validFrom <= now && (value.validUntil === null || now < value.validUntil);
}

function validityContainedBy(child: PermissionSet, parent: PermissionSet): boolean {
  return (
    child.validFrom >= parent.validFrom &&
    (parent.validUntil === null ||
      (child.validUntil !== null && child.validUntil <= parent.validUntil))
  );
}

function isSubset(child: PermissionSet, parent: PermissionSet): boolean {
  const subset = (values: readonly string[], ancestor: readonly string[]) =>
    values.every((value) => contains(ancestor, value));
  return (
    child.participantId === parent.participantId &&
    subset(child.privacyDomainIds, parent.privacyDomainIds) &&
    subset(child.actionIntentIds, parent.actionIntentIds) &&
    subset(child.capabilityIds ?? [], parent.capabilityIds ?? []) &&
    resourceSubset(child.resourceIds, parent.resourceIds) &&
    subset(child.riskClasses, parent.riskClasses) &&
    validityContainedBy(child, parent) &&
    (!parent.makerCheckerRequired || child.makerCheckerRequired) &&
    (!parent.stepUpRequired || child.stepUpRequired) &&
    child.onwardDelegationDepth < parent.onwardDelegationDepth
  );
}

export function validateDelegation(
  child: Delegation,
  parent: Assignment | Delegation,
): AuthorityError | undefined {
  if (
    child.id === child.parentId ||
    child.grantorId !== ('principalId' in parent ? parent.principalId : parent.granteeId) ||
    child.grantorId === child.granteeId ||
    !active(child.state) ||
    !active(parent.state) ||
    !isSubset(child, parent)
  ) {
    return 'PC-IDENTITY-1003';
  }
  return undefined;
}

export function evaluateAuthority(request: AuthorizationRequest): AuthorizationEvaluation {
  if (request.participantContextCount !== 1) {
    return terminal('CONFLICT', 'PC-IDENTITY-1000');
  }
  if (
    request.participantEpoch !== request.currentParticipantEpoch ||
    request.principalEpoch !== request.currentPrincipalEpoch ||
    request.authorityEpoch !== request.currentAuthorityEpoch
  ) {
    return terminal('STALE', 'PC-IDENTITY-1001');
  }
  if (!request.platformPermits) {
    return terminal('DENY', 'PC-IDENTITY-1004');
  }
  if (request.factsTampered) {
    return terminal('TAMPERED', 'PC-IDENTITY-1004');
  }
  if (!request.policyAvailable || !request.factsAvailable) {
    return terminal('UNAVAILABLE', 'PC-IDENTITY-1004');
  }
  if (
    request.envelope.participantId !== request.participantId ||
    request.assignment.participantId !== request.participantId ||
    (request.delegations.length === 0 && request.assignment.principalId !== request.principalId) ||
    request.assignment.authorityEnvelopeId !== request.envelope.id ||
    request.envelope.authorityEpoch !== request.currentAuthorityEpoch ||
    request.assignment.delegationEpoch !== request.delegationEpoch ||
    !active(request.envelope.state) ||
    !active(request.assignment.state) ||
    !validAt(request.envelope, request.now) ||
    !validAt(request.assignment, request.now)
  ) {
    return terminal('CONFLICT', 'PC-IDENTITY-1002');
  }
  if (
    request.makerPrincipalId !== undefined &&
    request.checkerPrincipalId !== undefined &&
    request.makerPrincipalId === request.checkerPrincipalId
  ) {
    return terminal('CONFLICT', 'PC-IDENTITY-1005');
  }

  let parent: Assignment | Delegation = request.assignment;
  let expectedGrantorId = request.assignment.principalId;
  for (const delegation of request.delegations) {
    if (
      delegation.participantId !== request.participantId ||
      delegation.grantorId !== expectedGrantorId ||
      delegation.delegationEpoch !== request.delegationEpoch ||
      delegation.parentId !== parent.id ||
      !validAt(delegation, request.now)
    ) {
      return terminal('CONFLICT', 'PC-IDENTITY-1003');
    }
    const error = validateDelegation(delegation, parent);
    if (error !== undefined) {
      return terminal('CONFLICT', error);
    }
    parent = delegation;
    expectedGrantorId = delegation.granteeId;
  }
  if (expectedGrantorId !== request.principalId) {
    return terminal('CONFLICT', 'PC-IDENTITY-1003');
  }

  const effective = [request.envelope, request.assignment, ...request.delegations];
  const allowed = effective.every(
    (permission) =>
      contains(permission.privacyDomainIds, request.privacyDomainId) &&
      contains(permission.actionIntentIds, request.actionIntentId) &&
      resourcePermits(permission.resourceIds, request.resourceId) &&
      contains(permission.riskClasses, request.riskClass),
  );
  if (!allowed) {
    return terminal('DENY', 'PC-IDENTITY-1002');
  }
  if (effective.some((permission) => permission.stepUpRequired) && !request.stepUpFresh) {
    return terminal('DENY', 'PC-IDENTITY-1004');
  }
  if (!request.existenceVisible || !request.payloadVisible) {
    return terminal('DENY', 'PC-IDENTITY-1008');
  }
  return {
    decision: 'ALLOW',
    authorized: true,
    terminal: false,
    existenceVisible: true,
    payloadVisible: true,
    explanationCodes: ['EFFECTIVE_INTERSECTION_ALLOW'],
  };
}
