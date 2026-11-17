import { sql, type SQLWrapper } from 'drizzle-orm';
import { pgPolicy } from 'drizzle-orm/pg-core';
import { controlOwnerRole } from './common.js';

/** Read validation of signed, provisional installation custody only. The host
 * transaction rolls back the enrollment on rejection. These policies admit no
 * application role, unrelated identity, business write or recovery lease. */
export function identityEnvelopeRecoveryInstallationSourcePolicies(
  participantId: SQLWrapper,
  identity: SQLWrapper,
  kind: 'principal' | 'credential' | 'executor-assignment',
  lock = true,
) {
  const actors = sql`jsonb_build_array(enrollment.document->'recoveryPrincipal') || (enrollment.document->'custodians')`;
  const match =
    kind === 'principal'
      ? sql`(exists(select 1 from jsonb_array_elements(${actors}) actor where actor->>'principalId'=${identity}::text)
          or enrollment.document->>'issuerPrincipalId'=${identity}::text)`
      : kind === 'credential'
        ? sql`(exists(select 1 from jsonb_array_elements(${actors}) actor where actor->>'credentialId'=${identity}::text)
          or enrollment.document#>>'{request,workloadCredentialId}'=${identity}::text)`
        : sql`enrollment.document#>>'{recoveryPrincipal,principalId}'=${identity}::text`;
  return sourcePolicies(participantId, match, lock && kind !== 'executor-assignment');
}

/** Exact public old-key provenance, including receipt grants needed to reject
 * cross-purpose reuse. No successor key or unrelated signing row is visible. */
export function identityEnvelopeRecoverySigningSourcePolicies(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  signerId: SQLWrapper,
  lock = false,
) {
  return sourcePolicies(
    participantId,
    sql`enrollment.privacy_domain_id=${privacyDomainId}
      and enrollment.document#>>'{request,oldFingerprint}'=${signerId}::text`,
    lock,
  );
}

/** Detect existing effects for the exact target credential/environment. */
export function identityEnvelopeRecoveryRotationSourcePolicies(
  participantId: SQLWrapper,
  privacyDomainId: SQLWrapper,
  environmentId: SQLWrapper,
  workloadCredentialId: SQLWrapper,
) {
  return sourcePolicies(
    participantId,
    sql`enrollment.privacy_domain_id=${privacyDomainId}
      and enrollment.document#>>'{request,environmentId}'=${environmentId}
      and enrollment.document#>>'{request,workloadCredentialId}'=${workloadCredentialId}::text`,
    false,
  );
}

function sourcePolicies(participantId: SQLWrapper, match: SQLWrapper, lock: boolean) {
  const using = sql`openpc.matches_participant(${participantId})
    and openpc.current_action_intent_id() in ('ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')
    and exists(select 1 from control.identity_envelope_recovery_enrollment enrollment
      where enrollment.participant_id=${participantId} and openpc.matches_privacy(enrollment.privacy_domain_id)
        and enrollment.state='ACTIVE' and enrollment.row_version=1
        and openpc.identity_envelope_recovery_installation_source_current(enrollment.enrollment_id)
        and enrollment.valid_from<=clock_timestamp() and enrollment.valid_until>clock_timestamp() and ${match})`;
  return [
    pgPolicy('identity_envelope_recovery_installation_source_read', {
      for: 'select',
      to: [controlOwnerRole],
      using,
    }),
    ...(lock
      ? [
          pgPolicy('identity_envelope_recovery_installation_source_lock', {
            for: 'update',
            to: [controlOwnerRole],
            using,
            withCheck: sql`false`,
          }),
        ]
      : []),
  ];
}
