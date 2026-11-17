import type { PoolClient } from 'pg';
import { isDeepStrictEqual } from 'node:util';
import {
  encodeEnvelopeScope,
  platformEnvelopeScopeSuccessorDigest,
  platformEnvelopeScopeSuccessorPreimage,
} from '@openpc/security-kernel';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { AuthorityFenceError } from './authority-fence.js';
import { fenceEnvelopePlatformScope, readCurrentPlatformScope } from './platform-envelope-scope.js';
import { assertPlatformScopeReplacementPreparation } from '../domain/platform-scope-replacement.js';
import { platformScopeAffectedTarget } from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import {
  PlatformScopeOwnerFailure,
  type PlatformScopeOwnerStage,
} from './platform-scope-owner-failure.js';
import type {
  PlatformScopeAffectedTarget,
  PlatformScopeReplacementPreparation,
} from '../../../participant-service/src/contracts/platform-scope-replacement.js';

export interface PlatformScopeReplacementOwner {
  participantId: string;
  privacyDomainId: string;
  operationId: string;
  approvalRequestId: string;
  makerPrincipalId: string;
  checkerPrincipalId: string;
  makerCredentialId: string;
  checkerCredentialId: string;
}

/** Catalogue readback only. This aggregate is owned by the security-definer
 * prepare/commit operations, which lock and validate the exact predecessor
 * themselves. Runtime callers must not obtain direct UPDATE privileges merely
 * to run the generic catalogue pre/post checks. Existing actor and RLS fences
 * still apply, and this read cannot admit or execute a replacement. */
export async function readPlatformScopeReplacementCatalog(
  client: PoolClient,
  participantId: string,
  replacementId: string,
) {
  const rows = await client.query<{ state: string; revision: string }>(
    `select state,row_version::text as revision from control.platform_scope_replacement
      where participant_id=$1 and privacy_domain_id=openpc.current_privacy_domain_id()
        and replacement_id=$2`,
    [participantId, replacementId],
  );
  if (rows.rowCount === 0) return undefined;
  const row = rows.rows[0];
  if (
    rows.rowCount !== 1 ||
    !row ||
    !(
      (row.state === 'WITHDRAWING' && row.revision === '1') ||
      (['COMMITTED', 'SUPERSEDED'].includes(row.state) && row.revision === '2')
    )
  )
    throw new AuthorityFenceError();
  return row;
}

/** Source readback, not permission. The caller holds real actor/context fences.
 * This first extension deliberately admits only a single owner privacy scope;
 * it cannot silently omit a child or foreign-context runtime dependency. */
export async function readPlatformScopeReplacementSource(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  platformContextId: string,
) {
  const root = await readCurrentPlatformScope(client, platformContextId);
  if (
    root.ownerParticipantId !== participantId ||
    root.installationPrivacyDomainId !== privacyDomainId
  )
    throw new AuthorityFenceError();
  if (
    root.grantable.runtime.participantIds.some((id) => id !== participantId) ||
    root.grantable.runtime.privacyDomainIds.some((id) => id !== privacyDomainId)
  )
    throw new AuthorityFenceError();
  const state = await client.query<{
    revision: string;
    epoch: string;
    state: string;
    now: string;
    pending: string | null;
    pendingIntent: PlatformScopeReplacementPreparation['supersedes'] | null;
    pendingAdministrationExpiresAtNs: string | null;
  }>(
    `select p.row_version::text as revision,p.authority_epoch::text as epoch,p.state,
      (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text as now,
      (select r.replacement_id::text from control.platform_scope_replacement r
        where r.platform_context_id=p.platform_context_id and r.state='WITHDRAWING') as pending,
      (select jsonb_build_object('replacementId',r.replacement_id::text,'expectedRevision',r.row_version::text,
        'successorDigest','sha256:'||encode(r.successor_digest,'hex')) from control.platform_scope_replacement r
        where r.platform_context_id=p.platform_context_id and r.state='WITHDRAWING') as "pendingIntent",
      (select max(greatest((a#>>'{usable,validUntilNs}')::numeric,(a#>>'{grantable,validUntilNs}')::numeric))::text
        from control.platform_scope_replacement r cross join lateral jsonb_array_elements(r.candidate->'administrators') a
        where r.platform_context_id=p.platform_context_id and r.state='WITHDRAWING') as "pendingAdministrationExpiresAtNs"
    from control.platform_context p where p.platform_context_id=$1 and p.owner_participant_id=$2`,
    [platformContextId, participantId],
  );
  if (state.rowCount !== 1 || state.rows[0]!.epoch !== root.platformAuthorityEpoch)
    throw new AuthorityFenceError();
  const targets = await client.query<{ target: PlatformScopeAffectedTarget }>(
    `select target from openpc.read_platform_scope_affected_targets($1)`,
    [platformContextId],
  );
  if (targets.rows.length > 256) throw new AuthorityFenceError();
  return {
    root,
    ...state.rows[0]!,
    affectedTargets: targets.rows.map((row) => platformScopeAffectedTarget.parse(row.target)),
  };
}

/** Called only inside the existing maker/checker/WebAuthn mutation transaction.
 * It prepares an immutable replacement intent; it does not advance the root,
 * activate successor grants or report runtime withdrawal as acknowledged. */
export async function preparePlatformScopeReplacement(
  client: PoolClient,
  owner: PlatformScopeReplacementOwner,
  candidate: PlatformScopeReplacementPreparation,
) {
  let ownerStage: PlatformScopeOwnerStage = 'approval_binding';
  try {
    const approval = await client.query<{
      candidateId: string;
      makerEnvelope: string;
      checkerEnvelope: string;
    }>(
      `select c.mutation_candidate_id::text as "candidateId",c.maker_authority_envelope_id::text as "makerEnvelope",
      d.approver_authority_envelope_id::text as "checkerEnvelope"
    from control.mutation_candidate c join control.approval_request a
      on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
      and a.subject_id=c.mutation_candidate_id and a.subject_type='CONFIGURATION_CANDIDATE'
      and a.subject_digest=c.candidate_digest and a.subject_version=c.expected_revision
    join control.approval_decision_record d on d.participant_id=a.participant_id
      and d.privacy_domain_id=a.privacy_domain_id and d.approval_request_id=a.approval_request_id
      and d.decision='APPROVE' and d.candidate_digest=c.candidate_digest
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.resource_id=$3
      and c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-PREPARE' and c.state='APPROVED'
      and c.maker_principal_id=$4 and d.approver_principal_id=$5
      and d.signer_credential_id=$6 and a.approval_request_id=$7 and a.state='APPROVED'`,
      [
        owner.participantId,
        owner.privacyDomainId,
        candidate.replacementId,
        owner.makerPrincipalId,
        owner.checkerPrincipalId,
        owner.checkerCredentialId,
        owner.approvalRequestId,
      ],
    );
    if (approval.rowCount !== 1) throw new AuthorityFenceError();
    ownerStage = 'current_actor_root';
    for (const envelopeId of [approval.rows[0]!.makerEnvelope, approval.rows[0]!.checkerEnvelope]) {
      const bound = await fenceEnvelopePlatformScope(client, owner.participantId, envelopeId);
      if (
        bound.platformContextId !== candidate.platformContextId ||
        bound.platformAuthorityEpoch !== candidate.predecessorEpoch ||
        bound.platformAuthorityDigest !== candidate.predecessorDigest
      )
        throw new AuthorityFenceError();
    }
    ownerStage = 'current_root_and_cohort';
    const source = await readPlatformScopeReplacementSource(
      client,
      owner.participantId,
      owner.privacyDomainId,
      candidate.platformContextId,
    );
    ownerStage = 'current_webauthn_credentials';
    const credentials = await client.query<{ expires: string | null }>(
      `select case when valid_until is null then null else
      (floor(extract(epoch from valid_until)*1000000)*1000)::text end as expires
    from control.credential where participant_id=$1 and kind='WEBAUTHN' and state='ACTIVE'
      and valid_from<=clock_timestamp() and (valid_until is null or valid_until>clock_timestamp())
      and ((credential_id=$2 and principal_id=$3) or (credential_id=$4 and principal_id=$5)) for share`,
      [
        owner.participantId,
        owner.makerCredentialId,
        owner.makerPrincipalId,
        owner.checkerCredentialId,
        owner.checkerPrincipalId,
      ],
    );
    if (credentials.rowCount !== 2) throw new AuthorityFenceError();
    const expires = credentials.rows.reduce(
      (bound, row) =>
        row.expires !== null && BigInt(row.expires) < bound ? BigInt(row.expires) : bound,
      BigInt(source.root.grantable.validUntilNs),
    );
    ownerStage = 'scope_and_source_bounds';
    assertPlatformScopeReplacementPreparation(candidate, {
      root: source.root,
      rootRevision: source.revision,
      rootDigest: source.root.platformAuthorityDigest,
      rootState: source.state,
      makerPrincipalId: owner.makerPrincipalId,
      checkerPrincipalId: owner.checkerPrincipalId,
      sourceExpiresAtNs: expires.toString(),
      nowNs: source.now,
      affectedTargets: source.affectedTargets,
      pendingReplacementId: source.pending,
      pendingIntent: source.pendingIntent,
      pendingAdministrationExpiresAtNs: source.pendingAdministrationExpiresAtNs,
    });
    ownerStage = 'administrator_role_binding';
    for (const administrator of candidate.administrators) {
      const role = await client.query<{
        role: { roleId: string; version: string; actions: string[] };
      }>(
        `select jsonb_build_object('roleId',r.role_id,'version',r.row_version::text,'actions',r.action_intent_ids,
        'origin',r.origin,'createdByPrincipalId',r.created_by_principal_id::text,
        'creatorParticipantId',r.creator_participant_id::text,'bootstrapMandateId',r.bootstrap_mandate_id::text,
        'bootstrapPlatformParticipantId',r.bootstrap_platform_participant_id::text) as role
      from control.authority_role r join control.principal p on p.participant_id=r.participant_id
      where r.participant_id=$1 and r.authority_role_id=$2 and r.state='ACTIVE'
        and p.principal_id=$3 and p.state='ACTIVE' and p.kind IN('USER','PLATFORM_OPERATOR') for share of r,p`,
        [owner.participantId, administrator.roleId, administrator.principalId],
      );
      if (
        role.rowCount !== 1 ||
        role.rows[0]!.role.version !== administrator.expectedRoleRevision ||
        canonicalAuthorizationDigest({
          domain: 'pc.identity.envelope-role-binding.v1',
          participantId: owner.participantId,
          role: role.rows[0]!.role,
        }) !== administrator.roleDigest ||
        [administrator.usable, administrator.grantable].some((scope) =>
          scope.administration.actionIntentIds.some(
            (action) => !role.rows[0]!.role.actions.includes(action),
          ),
        )
      )
        throw new AuthorityFenceError();
    }
    const successor = {
      admission: {
        platformContextId: source.root.platformContextId,
        ownerParticipantId: source.root.ownerParticipantId,
        installationPrivacyDomainId: source.root.installationPrivacyDomainId,
        environmentId: source.root.environmentId,
        installationDigest: source.root.installationDigest,
        platformAuthorityEpoch: (BigInt(candidate.predecessorEpoch) + 1n).toString(),
        grantable: candidate.successorScope,
      },
      replacementId: candidate.replacementId,
      preparationOperationId: owner.operationId,
      predecessorEpoch: candidate.predecessorEpoch,
      predecessorDigest: candidate.predecessorDigest,
    };
    const boundSuccessor = successor;
    const digest = platformEnvelopeScopeSuccessorDigest(boundSuccessor);
    ownerStage = 'atomic_prepare';
    const effect = await client.query<{ replacement: unknown }>(
      `select replacement from openpc.prepare_platform_scope_replacement($1::jsonb,$2,$3,$4,$5)`,
      [
        candidate,
        encodeEnvelopeScope(candidate.successorScope),
        platformEnvelopeScopeSuccessorPreimage(boundSuccessor),
        approval.rows[0]!.candidateId,
        owner.approvalRequestId,
      ],
    );
    const expected = {
      replacementId: candidate.replacementId,
      successorDigest: digest,
      state: 'WITHDRAWING' as const,
      revision: '1',
      operationId: owner.operationId,
    };
    ownerStage = 'effect_readback';
    if (effect.rowCount !== 1 || !isDeepStrictEqual(effect.rows[0]!.replacement, expected))
      throw new AuthorityFenceError();
    return expected;
  } catch (error) {
    throw new PlatformScopeOwnerFailure(ownerStage, error);
  }
}
