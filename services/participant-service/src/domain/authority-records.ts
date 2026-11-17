import type {
  Assignment,
  AuthorityEnvelope,
  Delegation,
  PermissionSet,
} from './authority-kernel.js';

export interface PermissionRow {
  participant_id: string;
  privacy_domain_ids: string[];
  action_intent_ids: string[];
  runtime_capability_ids?: NonNullable<PermissionSet['capabilityIds']>;
  resource_ids: string[];
  risk_classes: string[];
  maker_checker_required: boolean;
  step_up_required: boolean;
  onward_delegation_depth: number;
}
export interface EnvelopeRow extends PermissionRow {
  authority_envelope_id: string;
  authority_epoch: string;
  delegation_epoch: string;
  state: AuthorityEnvelope['state'];
  valid_from: Date;
  valid_until: Date | null;
  semantic_digest: Buffer;
  row_version?: string;
}
export interface AssignmentRow extends PermissionRow {
  assignment_id: string;
  principal_id: string;
  role_id: string | null;
  authority_group_id?: string | null;
  authority_envelope_id: string;
  state: Assignment['state'];
  delegation_epoch: string;
  scope_digest: Buffer;
  valid_from: Date;
  valid_until: Date | null;
}
export interface DelegationRow extends PermissionRow {
  delegation_id: string;
  parent_assignment_id: string | null;
  parent_delegation_id: string | null;
  grantor_principal_id: string;
  delegate_principal_id: string;
  state: Delegation['state'];
  delegation_epoch: string;
  scope_digest: Buffer;
  valid_from: Date;
  valid_until: Date | null;
}

function permission(row: PermissionRow): Omit<PermissionSet, 'validFrom' | 'validUntil'> {
  return {
    participantId: row.participant_id,
    privacyDomainIds: row.privacy_domain_ids,
    actionIntentIds: row.action_intent_ids,
    capabilityIds: row.runtime_capability_ids ?? [],
    resourceIds: row.resource_ids,
    riskClasses: row.risk_classes,
    makerCheckerRequired: row.maker_checker_required,
    stepUpRequired: row.step_up_required,
    onwardDelegationDepth: row.onward_delegation_depth,
  };
}
export function envelopeFromRow(row: EnvelopeRow): AuthorityEnvelope {
  return {
    ...permission(row),
    id: row.authority_envelope_id,
    authorityEpoch: String(row.authority_epoch),
    ...(row.row_version === undefined ? {} : { revision: String(row.row_version) }),
    state: row.state,
    semanticDigest: `sha256:${row.semantic_digest.toString('hex')}`,
    validFrom: new Date(row.valid_from),
    validUntil: row.valid_until === null ? null : new Date(row.valid_until),
  };
}
/** Project only the authenticated CREATE binding onto its exact durable row.
 * Callers retain current disclosure and original consumed-candidate fences. */
export function envelopeFromGovernedCreation(
  row: EnvelopeRow,
  creation: { envelopeId: string; participantId: string; platformScopeReplacementId?: string },
): AuthorityEnvelope {
  if (
    creation.envelopeId !== row.authority_envelope_id ||
    creation.participantId !== row.participant_id
  )
    throw new Error('Envelope creation readback identity mismatch');
  return {
    ...envelopeFromRow(row),
    ...(creation.platformScopeReplacementId === undefined
      ? {}
      : { platformScopeReplacementId: creation.platformScopeReplacementId }),
  };
}
export function assignmentFromRow(row: AssignmentRow): Assignment {
  return {
    ...permission(row),
    id: row.assignment_id,
    principalId: row.principal_id,
    ...(row.role_id === null || row.role_id === undefined ? {} : { roleId: row.role_id }),
    ...(row.authority_group_id === null || row.authority_group_id === undefined
      ? {}
      : { groupId: row.authority_group_id }),
    authorityEnvelopeId: row.authority_envelope_id,
    state: row.state,
    delegationEpoch: String(row.delegation_epoch),
    scopeDigest: `sha256:${row.scope_digest.toString('hex')}`,
    validFrom: new Date(row.valid_from),
    validUntil: row.valid_until === null ? null : new Date(row.valid_until),
  };
}
export function delegationFromRow(row: DelegationRow): Delegation {
  return {
    ...permission(row),
    id: row.delegation_id,
    parentId: row.parent_delegation_id ?? row.parent_assignment_id ?? '',
    grantorId: row.grantor_principal_id,
    granteeId: row.delegate_principal_id,
    state: row.state,
    delegationEpoch: String(row.delegation_epoch),
    scopeDigest: `sha256:${row.scope_digest.toString('hex')}`,
    validFrom: new Date(row.valid_from),
    validUntil: row.valid_until === null ? null : new Date(row.valid_until),
  };
}
