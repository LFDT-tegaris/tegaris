import { sql } from 'drizzle-orm';
import { customType, pgPolicy, pgRole, pgSchema } from 'drizzle-orm/pg-core';

export const control = pgSchema('control');

// These are NOLOGIN group roles. Deployments grant exactly one of them to a
// separately managed login role; application pools never connect as a table
// owner or a BYPASSRLS role.
export const controlOwnerRole = pgRole('openpc_control_owner', { inherit: false });
export const controlMigratorRole = pgRole('openpc_control_migrator', { inherit: false });
export const controlRuntimeRole = pgRole('openpc_control_runtime', { inherit: false });
export const controlWorkerRole = pgRole('openpc_control_worker', { inherit: false });
export const controlPlatformRuntimeRole = pgRole('openpc_control_platform_runtime', {
  inherit: false,
});
export const controlReaderRole = pgRole('openpc_control_reader', { inherit: false });
export const controlMaintenanceRole = pgRole('openpc_control_maintenance', { inherit: false });
// Private function owner; never granted to application login roles.
export const identityBindingOwnerRole = pgRole('openpc_identity_binding_owner', { inherit: false });
export const identityBindingResolverRole = pgRole('openpc_identity_binding_resolver', {
  inherit: false,
});

export const participantState = control.enum('participant_state', [
  'PROVISIONING',
  'ACTIVE',
  'SUSPENDED',
  'RETIRING',
  'RETIRED',
]);
export const privacyDomainState = control.enum('privacy_domain_state', [
  'PROVISIONING',
  'ACTIVE',
  'FENCED',
  'RETIRING',
  'RETIRED',
]);
export const principalKind = control.enum('principal_kind', [
  'USER',
  'WALLET',
  'WORKLOAD',
  'PLATFORM_OPERATOR',
]);
export const principalState = control.enum('principal_state', [
  'PENDING',
  'PROVISIONED',
  'ACTIVE',
  'SUSPENDED',
  'REVOKED',
  'OFFBOARDED',
  'DISABLED',
  'LOCKED',
  'RETIRED',
]);
export const credentialKind = control.enum('credential_kind', [
  'OIDC_SUBJECT',
  'WEBAUTHN',
  'WALLET_PROOF',
  'WORKLOAD_OIDC',
  'WORKLOAD_MTLS',
]);
export const credentialState = control.enum('credential_state', [
  'PENDING',
  'ISSUED',
  'ACTIVE',
  'ROTATING',
  'REVOKED',
  'EXPIRED',
]);
export const sessionState = control.enum('session_state', [
  'AUTHENTICATING',
  'ACTIVE',
  'STEP_UP_REQUIRED',
  'IDLE_EXPIRED',
  'ABSOLUTE_EXPIRED',
  'EXPIRED',
  'REVOKED',
  'COMPROMISED',
  'TERMINATED',
]);
export const sessionContextMode = control.enum('session_context_mode', ['PLATFORM', 'PARTICIPANT']);
export const authorityState = control.enum('authority_state', [
  'DRAFT',
  'SUBMITTED',
  'PENDING_APPROVAL',
  'APPROVED',
  'ACTIVE',
  'PROPOSED',
  'SUSPENDED',
  'SUPERSEDED',
  'REVOKED',
  'EXPIRED',
  'RETIRED',
]);
export const approvalState = control.enum('approval_state', [
  'OPEN',
  'APPROVED',
  'REJECTED',
  'EXPIRED',
  'CANCELLED',
]);
export const approvalDecision = control.enum('approval_decision', ['APPROVE', 'REJECT']);
export const mutationCandidateState = control.enum('mutation_candidate_state', [
  'PROPOSED',
  'APPROVAL_REQUESTED',
  'APPROVED',
  'CONSUMED',
  'CANCELLED',
]);
export const workItemKind = control.enum('work_item_kind', [
  'APPROVAL',
  'REMEDIATION',
  'DELIVERY_FAILURE',
  'FLEET_FAILURE',
  'EVIDENCE_BACKLOG',
]);
export const workItemState = control.enum('work_item_state', [
  'OPEN',
  'CLAIMED',
  'COMPLETED',
  'CANCELLED',
]);

export const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType: () => 'bytea',
});
export const timestampRange = customType<{ data: string; driverData: string }>({
  dataType: () => 'tstzrange',
});
export const cidrArray = customType<{ data: string[]; driverData: string[] }>({
  dataType: () => 'cidr[]',
});

export const participantIsolationPolicy = (participantColumn: unknown) =>
  pgPolicy('participant_isolation', {
    as: 'permissive',
    for: 'all',
    to: [controlRuntimeRole, controlWorkerRole, controlPlatformRuntimeRole, controlReaderRole],
    using: sql`openpc.matches_participant(${participantColumn})`,
    withCheck: sql`openpc.matches_participant(${participantColumn})`,
  });

export const privacyDomainIsolationPolicy = (
  participantColumn: unknown,
  privacyDomainColumn: unknown,
) =>
  pgPolicy('privacy_domain_isolation', {
    as: 'restrictive',
    for: 'all',
    to: [controlRuntimeRole, controlWorkerRole, controlPlatformRuntimeRole, controlReaderRole],
    using: sql`
      openpc.matches_participant(${participantColumn})
      and openpc.matches_privacy(${privacyDomainColumn})
    `,
    withCheck: sql`
      openpc.matches_participant(${participantColumn})
      and openpc.matches_privacy(${privacyDomainColumn})
    `,
  });
