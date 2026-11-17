import { readPlatformRecoveryApprovalResumePurpose } from './platform-recovery-approval-resume.js';
import { readDiscoveryApprovalResumePurpose } from './discovery-approval-resume.js';
import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  verifiedWebAuthnAssertionDigest,
  type VerifiedWebAuthnAssertion,
} from '../domain/trust-adapter.js';
import { platformRecoveryIntent } from '../contracts/platform-recovery.js';
import {
  discoveryCertificateRecoveryIntent,
  discoveryCertificateRotationCandidate,
  type DiscoveryCertificateRecoveryIntent,
} from '../contracts/discovery-certificate-recovery.js';
import { assertDiscoveryCertificateRecoveryOperation } from '../domain/discovery-certificate-recovery.js';
import { decodeEnvelopeProposal } from '@openpc/security-kernel';
import { findEnvelopeProposal } from './identity-envelope-proposal.js';
import { platformScopeReplacementCommit } from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import { approvalCreateIntent } from '../../../module-registry/src/public-approval-contract.js';
import { assertPlatformRecoveryOperation } from '../domain/platform-recovery-operation.js';
import { IdentityKernelError } from '../domain/identity-errors.js';

/** Called after the shared authority and source write fences, immediately before
 * the business callback. Staging a valid candidate does not authorize a changed
 * recovery purpose at execution. Historical replay never calls this effect guard. */
export async function assertPlatformRecoveryCommitPurpose(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly authorityEnvelopeId: string;
    readonly catalogOperationId: string;
    readonly resourceId: string;
    readonly candidate: unknown;
    readonly expectedRevision?: string;
    readonly principalId?: string;
    readonly verifiedStepUp?: VerifiedWebAuthnAssertion;
  },
): Promise<void> {
  const selected = await client.query<{
    representation: string;
    recoveryIntent: unknown;
    current: boolean;
    recoveryId: string;
  }>(
    `select e.representation,e.recovery_case_id::text as "recoveryId",c.intent as "recoveryIntent",
       case when e.representation='RECOVERY_V1' then
         c.privacy_domain_id=$3::uuid and openpc.platform_recovery_envelope_current(e.authority_envelope_id)
       else true end as current
     from control.authority_envelope e left join control.platform_recovery_case c
       on c.participant_id=e.participant_id and c.recovery_id=e.recovery_case_id
     where e.participant_id=$1 and e.authority_envelope_id=$2`,
    [input.participantId, input.authorityEnvelopeId, input.privacyDomainId],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || !row) throw new IdentityKernelError('PC-AUTH-0005');
  if (row.representation !== 'RECOVERY_V1') return;
  try {
    if (row.current !== true) throw new Error('Recovery purpose unavailable');
    if (isDiscoveryCertificateRecoveryIntent(row.recoveryIntent)) {
      const intent = discoveryCertificateRecoveryIntent.parse(row.recoveryIntent);
      if (intent.recoveryId !== row.recoveryId) throw new Error('Recovery purpose unavailable');
      if (input.catalogOperationId === 'ID-OP-WEBAUTHN-VERIFY') {
        await assertDiscoveryRecoveryVerificationPurpose(client, intent, input);
      } else {
        if (input.principalId !== intent.administrators[0].principalId)
          throw new Error('Recovery maker unavailable');
        assertDiscoveryCertificateRecoveryOperation(
          intent.certificateRecovery,
          input.catalogOperationId,
          input.resourceId,
          input.expectedRevision ?? '',
          input.candidate,
        );
      }
      return;
    }
    const intent = platformRecoveryIntent.parse(row.recoveryIntent);
    if (input.catalogOperationId === 'ID-OP-WEBAUTHN-VERIFY') {
      await assertRecoveryVerificationPurpose(client, intent, input, row.recoveryId);
      return;
    }
    assertPlatformRecoveryOperation(
      intent,
      input.participantId,
      input.catalogOperationId,
      input.resourceId,
      input.candidate,
    );
  } catch {
    throw new IdentityKernelError('PC-AUTH-0005');
  }
}

const hashText = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const verificationCandidate = z.strictObject({
  sessionToken: z.string(),
  actionIntentId: z.string(),
  resourceId: z.uuidv7(),
  resourceDigest: hashText,
  challenge: z.string().min(32).max(2048),
  rpIdHash: hashText,
  verifiedAssertionDigest: hashText,
});

/** A strict discriminator prevents malformed discovery documents from falling
 * through to the administration purpose. Parsing and current-source admission
 * remain mandatory at each caller. */
export function isDiscoveryCertificateRecoveryIntent(value: unknown): boolean {
  return (
    typeof value === 'object' &&
    value !== null &&
    'schema' in value &&
    value.schema === 'pc.identity.discovery-certificate-recovery-intent'
  );
}

function assertRecoveryVerificationBinding(
  input: Parameters<typeof assertPlatformRecoveryCommitPurpose>[1],
  administrators: readonly { readonly principalId: string }[],
) {
  const value = verificationCandidate.parse(input.candidate);
  const assertion = input.verifiedStepUp;
  if (
    assertion === undefined ||
    input.principalId === undefined ||
    !administrators.some((v) => v.principalId === input.principalId) ||
    value.sessionToken !== `${input.participantId}.${input.resourceId}` ||
    assertion.sessionId !== input.resourceId ||
    assertion.principalId !== input.principalId ||
    assertion.actionIntentId !== value.actionIntentId ||
    assertion.resourceDigest !== value.resourceDigest ||
    assertion.rpIdHash !== value.rpIdHash ||
    assertion.challengeDigest !==
      `sha256:${createHash('sha256').update(value.challenge).digest('hex')}` ||
    value.verifiedAssertionDigest !==
      `sha256:${verifiedWebAuthnAssertionDigest(assertion).toString('hex')}`
  )
    throw new Error('Recovery verification purpose unavailable');
  return value;
}

async function assertDiscoveryRecoveryVerificationPurpose(
  client: PoolClient,
  intent: DiscoveryCertificateRecoveryIntent,
  input: Parameters<typeof assertPlatformRecoveryCommitPurpose>[1],
): Promise<void> {
  const value = assertRecoveryVerificationBinding(input, intent.administrators);
  const maker = intent.administrators[0].principalId;
  const checker = intent.administrators[1].principalId;
  const binding = intent.certificateRecovery;
  if (
    input.principalId === maker &&
    value.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' &&
    value.resourceId === binding.predecessorCredentialId &&
    value.resourceDigest ===
      canonicalAuthorizationDigest(discoveryCertificateRotationCandidate(binding))
  )
    return;
  if (
    intent.schemaVersion === 2 &&
    input.principalId === maker &&
    value.actionIntentId === 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
  ) {
    const purpose = await readDiscoveryApprovalResumePurpose(client, {
      participantId: input.participantId,
      privacyDomainId: input.privacyDomainId,
      principalId: maker,
      authorityEnvelopeId: input.authorityEnvelopeId,
      approvalId: value.resourceId,
    });
    if (purpose?.requestDigest === value.resourceDigest) return;
    throw new Error('Recovery verification purpose unavailable');
  }
  if (input.principalId !== checker || value.actionIntentId !== 'ACT-POLICY_APPROVE_REQUEST-V1')
    throw new Error('Recovery verification purpose unavailable');
  const selected = await client.query<{
    candidate: unknown;
    candidateDigest: Buffer;
    expectedRevision: string;
    catalogOperationId: string;
    resourceId: string;
    approvalRevision: string;
  }>(
    `select c.candidate_document as candidate,c.candidate_digest as "candidateDigest",
      c.expected_revision::text as "expectedRevision",c.catalog_operation_id as "catalogOperationId",
      c.resource_id::text as "resourceId",a.row_version::text as "approvalRevision"
     from control.approval_request a join control.mutation_candidate c
       on c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id
       and c.mutation_candidate_id=a.subject_id and c.candidate_digest=a.subject_digest
       and c.expected_revision=a.subject_version and c.action_intent_id=a.action_intent_id
       and c.maker_principal_id=a.maker_principal_id
     join control.authority_envelope maker on maker.participant_id=c.participant_id
       and maker.authority_envelope_id=c.maker_authority_envelope_id
       and maker.representation='RECOVERY_V1' and maker.recovery_case_id=$6
       and openpc.platform_recovery_envelope_current(maker.authority_envelope_id)
     where a.participant_id=$1 and a.privacy_domain_id=$2 and a.approval_request_id=$3
       and a.subject_type='CONFIGURATION_CANDIDATE' and a.state in ('OPEN','APPROVED')
       and c.state in ('APPROVAL_REQUESTED','APPROVED')
       and a.expires_at>clock_timestamp() and c.expires_at>clock_timestamp()
       and a.maker_principal_id=$5 and a.maker_principal_id<>$4 and a.checker_principal_id=$4
       and not exists(select 1 from control.mutation_candidate successor
         where successor.participant_id=c.participant_id and successor.privacy_domain_id=c.privacy_domain_id
           and successor.predecessor_candidate_id=c.mutation_candidate_id)`,
    [
      input.participantId,
      input.privacyDomainId,
      value.resourceId,
      checker,
      maker,
      intent.recoveryId,
    ],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    row.candidateDigest.length !== 32 ||
    canonicalAuthorizationDigest(row.candidate) !==
      `sha256:${row.candidateDigest.toString('hex')}` ||
    canonicalAuthorizationDigest({
      actionIntentId: value.actionIntentId,
      approvalRequestId: `urn:openpc:resource:${value.resourceId}`,
      candidateDigest: `sha256:${row.candidateDigest.toString('hex')}`,
      expectedRevision: row.approvalRevision,
      decision: 'APPROVE',
    }) !== value.resourceDigest
  )
    throw new Error('Recovery verification purpose unavailable');
  assertDiscoveryCertificateRecoveryOperation(
    binding,
    row.catalogOperationId,
    row.resourceId,
    row.expectedRevision,
    row.candidate,
  );
}

/** This read grants no authority. It only admits the Platform session exception
 * for an actual selected, current, exactly enrolled native rotation purpose. */
export async function discoveryCertificateRecoveryContextEligible(
  client: PoolClient,
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly authorityEnvelopeId: string;
    readonly principalId: string;
    readonly catalogOperationId: string;
    readonly actionIntentId: string;
    readonly resourceId: string;
    readonly expectedRevision: string;
    readonly candidate: unknown;
  },
): Promise<boolean> {
  if (
    input.catalogOperationId !== 'ID-OP-WORKLOAD-ROTATE' ||
    input.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
  )
    return false;
  const selected = await client.query<{ intent: unknown; recoveryId: string }>(
    `select c.intent,c.recovery_id::text as "recoveryId"
     from control.authority_envelope e join control.platform_recovery_case c
       on c.participant_id=e.participant_id and c.recovery_id=e.recovery_case_id
     join control.participant p on p.participant_id=e.participant_id and p.state='ACTIVE'
       and p.root_privacy_domain_id=c.privacy_domain_id
     join control.principal principal on principal.participant_id=e.participant_id
       and principal.principal_id=e.principal_id and principal.kind='PLATFORM_OPERATOR' and principal.state='ACTIVE'
     where e.participant_id=$1 and e.authority_envelope_id=$2 and e.principal_id=$4
       and e.representation='RECOVERY_V1' and c.privacy_domain_id=$3
       and c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
       and openpc.platform_recovery_envelope_current(e.authority_envelope_id)`,
    [input.participantId, input.authorityEnvelopeId, input.privacyDomainId, input.principalId],
  );
  if (selected.rowCount !== 1) return false;
  try {
    const intent = discoveryCertificateRecoveryIntent.parse(selected.rows[0]!.intent);
    if (
      intent.recoveryId !== selected.rows[0]!.recoveryId ||
      input.principalId !== intent.administrators[0].principalId
    )
      return false;
    assertDiscoveryCertificateRecoveryOperation(
      intent.certificateRecovery,
      input.catalogOperationId,
      input.resourceId,
      input.expectedRevision,
      input.candidate,
    );
    return true;
  } catch {
    return false;
  }
}

/** Verification records authenticator evidence only. The owning business
 * mutation still rechecks the complete fixed purpose, approval and write fence. */
async function assertRecoveryVerificationPurpose(
  client: PoolClient,
  intent: z.infer<typeof platformRecoveryIntent>,
  input: Parameters<typeof assertPlatformRecoveryCommitPurpose>[1],
  recoveryId: string,
): Promise<void> {
  if (recoveryId !== intent.recoveryId)
    throw new Error('Recovery verification purpose unavailable');
  const plan = intent.preparation;
  const value = assertRecoveryVerificationBinding(input, plan.administrators);
  if (
    intent.continuation &&
    value.actionIntentId === 'ACT-PARTICIPANTS_READ_RESOURCE-V1' &&
    value.resourceId === plan.replacementId &&
    plan.administrators.some(
      (administrator) =>
        value.resourceDigest ===
        canonicalAuthorizationDigest({
          purpose: 'platform-administrator-handoff-read',
          preparationApprovalId: intent.continuation!.preparationApprovalId,
          principalId: administrator.principalId,
          preparation: plan,
        }),
    )
  )
    return;
  if (
    (intent.continuation || intent.approvalContinuation) &&
    input.principalId !== undefined &&
    input.principalId === plan.administrators[0]?.principalId &&
    value.actionIntentId === 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
  ) {
    const purpose = await readPlatformRecoveryApprovalResumePurpose(client, {
      participantId: input.participantId,
      privacyDomainId: input.privacyDomainId,
      principalId: input.principalId,
      authorityEnvelopeId: input.authorityEnvelopeId,
      approvalId: value.resourceId,
    });
    if (purpose?.requestDigest === value.resourceDigest) return;
    throw new Error('Recovery resume verification purpose unavailable');
  }

  const maker = plan.administrators[0]!;
  if (
    input.principalId === maker.principalId &&
    value.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' &&
    value.resourceId === plan.replacementId &&
    value.resourceDigest === canonicalAuthorizationDigest(plan)
  )
    return;
  if (input.principalId === maker.principalId) {
    for (const administrator of plan.administrators) {
      const envelopeCandidate = {
        schema: 'pc.identity.authority-envelope-proposal',
        schemaVersion: 1,
        envelopeId: administrator.envelopeId,
        issuance: 'PLATFORM_ROOT',
        platformScopeReplacementId: plan.replacementId,
        usable: administrator.usable,
        grantable: administrator.grantable,
        id: administrator.envelopeId,
        participantId: input.participantId,
        state: 'DRAFT',
      };
      if (
        value.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' &&
        value.resourceId === administrator.envelopeId &&
        value.resourceDigest === canonicalAuthorizationDigest(envelopeCandidate)
      )
        return;
      if (
        value.actionIntentId === 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' &&
        value.resourceId === administrator.envelopeId &&
        value.resourceDigest ===
          canonicalAuthorizationDigest({ envelopeId: administrator.envelopeId })
      )
        return;
      if (
        value.actionIntentId === 'ACT-PARTICIPANT_CREATE_MEMBER-V1' &&
        value.resourceId === administrator.assignmentId &&
        value.resourceDigest ===
          canonicalAuthorizationDigest(
            recoveryAssignmentCandidate(input.participantId, administrator),
          )
      )
        return;
      if (
        value.actionIntentId === 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' &&
        value.resourceId === administrator.envelopeId
      ) {
        const proposal = await readRecoveryEnvelopePurpose(
          client,
          intent,
          input,
          recoveryId,
          administrator.envelopeId,
        );
        const action = await client.query<{ digest: Buffer }>(
          'select semantic_digest as digest from control.action_intent where action_intent_id=$1',
          [value.actionIntentId],
        );
        const digest = action.rows[0]?.digest;
        if (
          action.rowCount === 1 &&
          digest?.length === 32 &&
          value.resourceDigest ===
            approvalCreateIntent({
              actionIntentId: value.actionIntentId,
              actionIntentDigest: `sha256:${digest.toString('hex')}`,
              candidateDigest: proposal.digest,
              makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
              checkerSubjectRef: `urn:openpc:resource:${plan.administrators[1]!.principalId}`,
              // The retained rendered producer supplies this exact submission
              // reason and no reservation. Its full request digest is distinct
              // from the immutable preparation reason and proposal digest.
              reason: 'Submit the typed Platform-root RPC envelope for independent approval.',
            }).intentDigest
        )
          return;
      }
    }
    if (
      value.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' &&
      value.resourceId === plan.replacementId
    ) {
      // The supported public /commit/prepare owner already checked full
      // authoritative readiness under UPDATE before staging this exact body.
      // Resolve its original authenticated session/selected grant; proof records
      // that immutable intent and final execution independently rechecks readiness.
      const staged = await client.query<{ candidate: unknown; digest: Buffer }>(
        `select c.candidate_document as candidate,c.candidate_digest as digest
         from control.mutation_candidate c
         join control.authority_envelope e on e.participant_id=c.participant_id
           and e.authority_envelope_id=c.maker_authority_envelope_id
           and e.principal_id=c.maker_principal_id and e.representation='RECOVERY_V1'
           and e.recovery_case_id=$5 and openpc.platform_recovery_envelope_current(e.authority_envelope_id)
         join control.session s on s.participant_id=c.participant_id and s.session_id=c.maker_session_id
           and s.principal_id=c.maker_principal_id and s.state='ACTIVE'
           and s.session_epoch=c.maker_session_epoch and s.participant_epoch=c.maker_participant_epoch
           and s.authority_epoch=c.maker_principal_epoch and s.delegation_epoch=c.maker_delegation_epoch
           and s.idle_expires_at>clock_timestamp() and s.absolute_expires_at>clock_timestamp()
         join control.participant p on p.participant_id=c.participant_id and p.state='ACTIVE'
           and p.authority_epoch=s.participant_epoch
         join control.principal principal on principal.participant_id=c.participant_id
           and principal.principal_id=c.maker_principal_id and principal.state='ACTIVE'
           and principal.authority_epoch=s.authority_epoch
         join control.privacy_domain privacy on privacy.participant_id=c.participant_id
           and privacy.privacy_domain_id=c.privacy_domain_id and privacy.state='ACTIVE'
         join control.assignment a on a.participant_id=c.participant_id and a.assignment_id=c.maker_assignment_id
           and a.authority_envelope_id=e.authority_envelope_id and a.principal_id=c.maker_principal_id
           and a.row_version=c.maker_assignment_row_version and a.state='ACTIVE'
           and a.valid_during @> clock_timestamp() and a.delegation_epoch=c.maker_delegation_epoch
           and e.authority_epoch=c.maker_authority_epoch
           and a.maker_checker_required=true and a.step_up_required=true
           and c.action_intent_id=any(a.action_intent_ids)
           and c.privacy_domain_id::text=any(a.privacy_domain_ids)
           and openpc.assignment_role_permits(a.participant_id,a.role_id,c.action_intent_id)
           and openpc.assignment_group_permits(a.participant_id,a.authority_group_id,a.principal_id,a.valid_during)
           and (c.resource_id::text=any(a.resource_ids) or '*'=any(a.resource_ids))
           and e.state='ACTIVE' and e.valid_from<=clock_timestamp()
           and (e.valid_until is null or e.valid_until>clock_timestamp())
           and e.delegation_epoch=c.maker_delegation_epoch
           and c.action_intent_id=any(e.action_intent_ids)
           and c.privacy_domain_id::text=any(e.privacy_domain_ids)
           and (c.resource_id::text=any(e.resource_ids) or '*'=any(e.resource_ids))
         join control.platform_scope_replacement r on r.participant_id=c.participant_id
           and r.privacy_domain_id=c.privacy_domain_id and r.replacement_id=c.resource_id
           and r.state='WITHDRAWING' and r.row_version=c.expected_revision and r.candidate=$7::jsonb
           and c.candidate_document->>'successorDigest'='sha256:'||encode(r.successor_digest,'hex')
         join control.platform_context root on root.platform_context_id=r.platform_context_id
           and root.owner_participant_id=c.participant_id and root.state='ACTIVE'
           and root.authority_epoch=r.predecessor_epoch and root.row_version=r.expected_root_revision
         where c.participant_id=$1 and c.privacy_domain_id=$2 and c.resource_id=$3
           and c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-COMMIT'
           and c.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' and c.expected_revision=1
           and c.maker_authority_envelope_id=$4 and c.maker_session_id=$6 and c.maker_principal_id=$8
           and ((s.context_mode='PARTICIPANT' and s.privacy_domain_id=c.privacy_domain_id)
             or (s.context_mode='PLATFORM' and s.privacy_domain_id is null
               and p.root_privacy_domain_id=c.privacy_domain_id and principal.kind='PLATFORM_OPERATOR'))
           and c.state in ('PROPOSED','APPROVAL_REQUESTED','APPROVED') and c.expires_at>clock_timestamp()
           and not exists(select 1 from control.mutation_candidate successor
             where successor.participant_id=c.participant_id and successor.privacy_domain_id=c.privacy_domain_id
               and successor.predecessor_candidate_id=c.mutation_candidate_id)`,
        [
          input.participantId,
          input.privacyDomainId,
          plan.replacementId,
          input.authorityEnvelopeId,
          recoveryId,
          input.resourceId,
          plan,
          input.principalId,
        ],
      );
      const row = staged.rows[0];
      if (
        staged.rowCount === 1 &&
        row &&
        row.digest.length === 32 &&
        canonicalAuthorizationDigest(row.candidate) === `sha256:${row.digest.toString('hex')}` &&
        value.resourceDigest === `sha256:${row.digest.toString('hex')}`
      ) {
        const candidate = platformScopeReplacementCommit.parse(row.candidate);
        assertPlatformRecoveryOperation(
          intent,
          input.participantId,
          'ID-OP-PLATFORM-SCOPE-COMMIT',
          plan.replacementId,
          candidate,
        );
        return;
      }
    }
  }
  if (
    value.actionIntentId === 'ACT-POLICY_APPROVE_REQUEST-V1' &&
    input.principalId === plan.administrators[1]?.principalId
  ) {
    // Approval identifiers are owner allocated. Resolve their exact current
    // candidate instead of accepting a caller-supplied business target.
    const selected = await client.query<{
      catalogOperationId: string;
      resourceId: string;
      candidate: unknown;
      candidateDigest: Buffer;
      approvalRevision: string;
    }>(
      `select c.catalog_operation_id as "catalogOperationId",c.resource_id::text as "resourceId",c.candidate_document as candidate,c.candidate_digest as "candidateDigest",a.row_version::text as "approvalRevision"
       from control.approval_request a join control.mutation_candidate c
         on c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id
         and c.mutation_candidate_id=a.subject_id and c.candidate_digest=a.subject_digest
         and c.expected_revision=a.subject_version and c.action_intent_id=a.action_intent_id
         and c.maker_principal_id=a.maker_principal_id
       join control.authority_envelope maker on maker.participant_id=c.participant_id
         and maker.authority_envelope_id=c.maker_authority_envelope_id
         and maker.representation='RECOVERY_V1' and maker.recovery_case_id=$6
       where a.participant_id=$1 and a.privacy_domain_id=$2 and a.approval_request_id=$3
         and a.subject_type='CONFIGURATION_CANDIDATE' and a.state in ('OPEN','APPROVED')
         and c.state in ('APPROVAL_REQUESTED','APPROVED')
         and a.expires_at>clock_timestamp() and c.expires_at>clock_timestamp()
         and a.maker_principal_id=$5 and a.maker_principal_id<>$4 and a.checker_principal_id=$4
         and not exists(select 1 from control.mutation_candidate successor
           where successor.participant_id=c.participant_id and successor.privacy_domain_id=c.privacy_domain_id
             and successor.predecessor_candidate_id=c.mutation_candidate_id)`,
      [
        input.participantId,
        input.privacyDomainId,
        value.resourceId,
        input.principalId,
        plan.administrators[0]!.principalId,
        recoveryId,
      ],
    );
    const candidate = selected.rows[0];
    if (
      selected.rowCount === 1 &&
      candidate &&
      candidate.candidateDigest.length === 32 &&
      canonicalAuthorizationDigest(candidate.candidate) ===
        `sha256:${candidate.candidateDigest.toString('hex')}` &&
      canonicalAuthorizationDigest({
        actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
        approvalRequestId: `urn:openpc:resource:${value.resourceId}`,
        candidateDigest: `sha256:${candidate.candidateDigest.toString('hex')}`,
        expectedRevision: candidate.approvalRevision,
        decision: 'APPROVE',
      }) === value.resourceDigest
    ) {
      assertPlatformRecoveryOperation(
        intent,
        input.participantId,
        candidate.catalogOperationId,
        candidate.resourceId,
        candidate.candidate,
      );
      return;
    }
    if (selected.rowCount !== 0) throw new Error('Recovery verification purpose unavailable');
    const proposal = await readRecoveryEnvelopePurpose(
      client,
      intent,
      input,
      recoveryId,
      undefined,
      value.resourceId,
    );
    if (
      canonicalAuthorizationDigest({
        actionIntentId: value.actionIntentId,
        approvalRequestId: `urn:openpc:resource:${value.resourceId}`,
        candidateDigest: proposal.digest,
        expectedRevision: proposal.approvalRevision,
        decision: 'APPROVE',
      }) === value.resourceDigest
    )
      return;
  }
  throw new Error('Recovery verification purpose unavailable');
}

/** Reconstruct the full public producer body, including its permission digest.
 * No named target or caller-supplied hash establishes a recovery purpose. */
function recoveryAssignmentCandidate(
  participantId: string,
  administrator: z.infer<typeof platformRecoveryIntent>['preparation']['administrators'][number],
) {
  const scope = administrator.usable;
  const permission = {
    privacyDomainIds: [...scope.administration.privacyDomainIds],
    actionIntentIds: [...scope.administration.actionIntentIds].sort(),
    resourceIds: [...scope.administration.resourceIds].sort(),
    riskClasses: [...scope.administration.riskClasses].sort(),
    capabilityIds: [],
    validFrom: new Date(Number(BigInt(scope.validFromNs) / 1000000n)).toISOString(),
    validUntil: new Date(Number(BigInt(scope.validUntilNs) / 1000000n)).toISOString(),
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
  const candidate = {
    ...permission,
    id: administrator.assignmentId,
    assignmentId: administrator.assignmentId,
    participantId,
    state: 'ACTIVE',
    delegationEpoch: '0',
    principalId: administrator.principalId,
    authorityEnvelopeId: administrator.envelopeId,
    roleId: `urn:openpc:role:${administrator.roleId}`,
    scopeDigest: canonicalAuthorizationDigest({ participantId, ...permission }),
  };
  return candidate;
}

/** Resolve the real typed proposal and the same-case consumed creation. This
 * qualifies proof recording only; submission/decision still use their owners. */
async function readRecoveryEnvelopePurpose(
  client: PoolClient,
  intent: z.infer<typeof platformRecoveryIntent>,
  input: Parameters<typeof assertPlatformRecoveryCommitPurpose>[1],
  recoveryId: string,
  envelopeId?: string,
  approvalId?: string,
) {
  const plan = intent.preparation;
  const selected = await client.query<{
    envelopeId: string;
    proposalDigest: Buffer;
    candidate: unknown;
    candidateDigest: Buffer;
    makerEnvelopeId: string;
    successorDigest: Buffer;
    approvalRevision: string | null;
  }>(
    `select p.envelope_id::text as "envelopeId",p.proposal_digest as "proposalDigest",
       c.candidate_document as candidate,c.candidate_digest as "candidateDigest",
       maker.authority_envelope_id::text as "makerEnvelopeId",r.successor_digest as "successorDigest",
       a.row_version::text as "approvalRevision"
     from control.identity_envelope_proposal p join control.mutation_candidate c
       on c.participant_id=p.participant_id and c.privacy_domain_id=p.privacy_domain_id
       and c.mutation_candidate_id=p.create_candidate_id and c.resource_id=p.envelope_id
       and c.catalog_operation_id='ID-OP-ENVELOPE-CREATE' and c.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
       and c.state='CONSUMED' and c.consumed_operation_id=p.create_operation_id and c.maker_principal_id=p.maker_principal_id
     join control.authority_envelope maker on maker.participant_id=c.participant_id
       and maker.authority_envelope_id=c.maker_authority_envelope_id and maker.principal_id=c.maker_principal_id
       and maker.representation='RECOVERY_V1'
       and ((maker.recovery_case_id=$6 and openpc.platform_recovery_envelope_current(maker.authority_envelope_id))
         or openpc.platform_recovery_proposal_history_current($1,$2,$9,p.envelope_id))
     join control.platform_scope_replacement r on r.participant_id=p.participant_id and r.privacy_domain_id=p.privacy_domain_id
       and r.replacement_id::text=c.candidate_document->>'platformScopeReplacementId'
       and r.state='WITHDRAWING' and r.candidate=$8::jsonb
     left join control.approval_request a on a.participant_id=p.participant_id and a.privacy_domain_id=p.privacy_domain_id
       and a.approval_request_id=p.submission_approval_id and a.subject_type='AUTHORITY_ENVELOPE'
       and a.subject_id=p.envelope_id and a.subject_digest=p.proposal_digest and a.subject_version=1
       and a.maker_principal_id=p.maker_principal_id and a.action_intent_id='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
     where p.participant_id=$1 and p.privacy_domain_id=$2 and p.target_participant_id=$1
       and p.maker_principal_id=$4 and ($3::uuid is null or p.envelope_id=$3)
       and (($7::uuid is null and p.state='DRAFT' and p.row_version=1 and p.submission_approval_id is null)
        or ($7::uuid is not null and a.approval_request_id=$7 and a.checker_principal_id=$5
         and a.checker_principal_id<>a.maker_principal_id and a.expires_at>clock_timestamp()
         and ((p.state='SUBMITTED' and p.row_version=2 and a.state='OPEN')
           or (p.state='APPROVED' and p.row_version=3 and a.state='APPROVED'))))
       and not exists(select 1 from control.mutation_candidate successor
         where successor.participant_id=c.participant_id and successor.privacy_domain_id=c.privacy_domain_id
           and successor.predecessor_candidate_id=c.mutation_candidate_id)`,
    [
      input.participantId,
      input.privacyDomainId,
      envelopeId ?? null,
      plan.administrators[0]!.principalId,
      plan.administrators[1]!.principalId,
      recoveryId,
      approvalId ?? null,
      plan,
      input.authorityEnvelopeId,
    ],
  );
  const row = selected.rows[0];
  const administrator = plan.administrators.find((v) => v.envelopeId === row?.envelopeId);
  if (
    selected.rowCount !== 1 ||
    !row ||
    !administrator ||
    row.proposalDigest.length !== 32 ||
    row.candidateDigest.length !== 32 ||
    row.successorDigest.length !== 32 ||
    canonicalAuthorizationDigest(row.candidate) !== `sha256:${row.candidateDigest.toString('hex')}`
  )
    throw new Error('Recovery verification purpose unavailable');
  assertPlatformRecoveryOperation(
    intent,
    input.participantId,
    'ID-OP-ENVELOPE-CREATE',
    row.envelopeId,
    row.candidate,
  );
  const stored = await findEnvelopeProposal(client, input, row.proposalDigest);
  if (!stored || stored.envelopeId !== row.envelopeId)
    throw new Error('Recovery verification purpose unavailable');
  const proposal = decodeEnvelopeProposal(stored.bytes);
  if (
    proposal.issuance !== 'PLATFORM_ROOT' ||
    proposal.issuer.kind !== 'PLATFORM' ||
    proposal.issuer.authority.authorityEnvelopeId !== row.makerEnvelopeId ||
    proposal.issuer.authority.principalId !== plan.administrators[0]!.principalId ||
    proposal.issuer.platformContextId !== plan.platformContextId ||
    proposal.issuer.platformAuthorityEpoch !== (BigInt(plan.predecessorEpoch) + 1n).toString() ||
    proposal.issuer.platformAuthorityDigest !== `sha256:${row.successorDigest.toString('hex')}` ||
    canonicalAuthorizationDigest(proposal.usable) !==
      canonicalAuthorizationDigest(administrator.usable) ||
    canonicalAuthorizationDigest(proposal.grantable) !==
      canonicalAuthorizationDigest(administrator.grantable)
  )
    throw new Error('Recovery verification purpose unavailable');
  return {
    digest: `sha256:${row.proposalDigest.toString('hex')}`,
    approvalRevision: row.approvalRevision,
  };
}
