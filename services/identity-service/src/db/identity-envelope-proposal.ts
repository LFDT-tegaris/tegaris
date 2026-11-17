import { hasPlatformRecoveryProposalHistory } from './platform-recovery-continuation.js';
import {
  pendingPlatformAdministrator,
  platformScopeForEnvelopeProposal,
} from './pending-platform-administrator.js';
import type { PoolClient } from 'pg';
import { isDeepStrictEqual } from 'node:util';
import {
  assertEnvelopeScopeNarrowing,
  authorityEnvelopeDigest,
  encodeEnvelopeProposal,
  decodeEnvelopeProposal,
  type EnvelopeAuthorityBinding,
  type EnvelopeActorEvidence,
  type EnvelopeProposal,
} from '@openpc/security-kernel';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
  fenceDurableAuthorities,
  type BoundAuthority,
  type DurableAuthority,
} from './authority-fence.js';
import { captureFencedEnvelopeAuthority } from './identity-envelope-authority.js';
import { fenceEnvelopePlatformScope } from './platform-envelope-scope.js';
import { assertPlatformBootstrapActor } from '../domain/bootstrap-authority.js';
import type { TypedEnvelopeCreateCandidate } from '../../../participant-service/src/contracts/envelope.js';

export interface EnvelopeGovernanceScope {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly operationId: string;
  readonly actionIntentId: string;
}

export interface StoredEnvelopeProposal {
  envelopeId: string;
  targetParticipantId: string;
  makerPrincipalId: string;
  bytes: Buffer;
  digest: Buffer;
  issuerAuthority: { binding: EnvelopeAuthorityBinding; durable: DurableAuthority };
  state: 'DRAFT' | 'SUBMITTED' | 'APPROVED';
  version: string;
  submissionApprovalId: string | null;
  submissionMaker: EnvelopeActorEvidence | null;
  submissionChecker: EnvelopeActorEvidence | null;
  submissionCheckerAuthority: {
    binding: EnvelopeAuthorityBinding;
    durable: DurableAuthority;
  } | null;
}

/** Issuer/privacy-scoped lookup. A digest match is only subject resolution;
 * it is not a grant, a proof of current lineage, or target read authority. */
export async function findEnvelopeProposal(
  client: PoolClient,
  scope: Pick<EnvelopeGovernanceScope, 'participantId' | 'privacyDomainId'>,
  digest: Buffer,
  lock: boolean | 'share' = false,
): Promise<StoredEnvelopeProposal | undefined> {
  const result = await client.query<StoredEnvelopeProposal>(
    `select envelope_id::text as "envelopeId",
    target_participant_id::text as "targetParticipantId",maker_principal_id::text as "makerPrincipalId",
    proposal_cbor as bytes,proposal_digest as digest,issuer_authority as "issuerAuthority",state,row_version::text as version,
    submission_approval_id::text as "submissionApprovalId",submission_maker as "submissionMaker",
    submission_checker as "submissionChecker",submission_checker_authority as "submissionCheckerAuthority" from control.identity_envelope_proposal
    where participant_id=$1 and privacy_domain_id=$2 and proposal_digest=$3${lock === 'share' ? ' for share' : lock ? ' for update' : ''}`,
    [scope.participantId, scope.privacyDomainId, digest],
  );
  if (result.rowCount === 0) return undefined;
  const row = result.rows[0];
  if (result.rowCount !== 1 || !row) throw new AuthorityFenceError();
  try {
    const proposal = decodeEnvelopeProposal(row.bytes);
    if (
      authorityEnvelopeDigest(row.bytes) !== `sha256:${row.digest.toString('hex')}` ||
      proposal.envelopeId !== row.envelopeId ||
      proposal.participantId !== row.targetParticipantId ||
      proposal.issuer.authority.participantId !== scope.participantId ||
      proposal.issuer.authority.principalId !== row.makerPrincipalId ||
      !isDeepStrictEqual(proposal.issuer.authority, row.issuerAuthority.binding) ||
      row.issuerAuthority.durable.grant.privacyDomainId !== scope.privacyDomainId ||
      (row.state === 'APPROVED' &&
        (!row.submissionChecker ||
          !row.submissionCheckerAuthority ||
          !isDeepStrictEqual(
            row.submissionChecker.authority,
            row.submissionCheckerAuthority.binding,
          ) ||
          row.submissionCheckerAuthority.durable.grant.privacyDomainId !== scope.privacyDomainId))
    )
      throw new AuthorityFenceError();
    return row;
  } catch {
    throw new AuthorityFenceError();
  }
}

/** Revalidate the original issuer grant and exact installed root under current
 * fences. Historical signatures and persisted dependency snapshots do not
 * substitute for these current checks. Call before locking the proposal row. */
export async function fenceInitialEnvelopeProposal(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  stored: StoredEnvelopeProposal,
  actor: BoundAuthority,
  makerMustMatch: boolean,
) {
  const proposal = decodeEnvelopeProposal(stored.bytes);
  if (
    proposal.issuance !== 'PLATFORM_ROOT' ||
    actor.privacyDomainId !== scope.privacyDomainId ||
    actor.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' ||
    actor.resourceId !== stored.envelopeId
  )
    throw new AuthorityFenceError();
  const targetEpoch = await fenceEnvelopeProposalParticipants(
    client,
    scope,
    stored.targetParticipantId,
  );
  if (targetEpoch !== proposal.participantEpoch) throw new AuthorityFenceError();
  await fenceBoundAuthorities(client, scope.participantId, [actor]);
  const continuation = await hasPlatformRecoveryProposalHistory(
    client,
    scope,
    actor.authorityEnvelopeId,
    stored.envelopeId,
  );
  if (!continuation)
    await fenceDurableAuthorities(client, scope.participantId, [stored.issuerAuthority.durable]);
  else if (actor.principalId !== stored.makerPrincipalId && makerMustMatch)
    throw new AuthorityFenceError();
  await assertPlatformBootstrapActor(
    client,
    scope.participantId,
    actor.principalId,
    actor.sessionId,
  );
  const direct = await client.query(
    `select 1 from control.assignment assignment join control.authority_envelope envelope
      on envelope.participant_id=assignment.participant_id and envelope.authority_envelope_id=assignment.authority_envelope_id
    where assignment.participant_id=$1 and assignment.assignment_id=$2
    and assignment.principal_id=$3 and assignment.authority_envelope_id=$4 and assignment.state='ACTIVE'
    and assignment.maker_checker_required=true and envelope.maker_checker_required=true`,
    [scope.participantId, actor.assignmentId, actor.principalId, actor.authorityEnvelopeId],
  );
  if (direct.rowCount !== 1) throw new AuthorityFenceError();
  const captured = await captureFencedEnvelopeAuthority(client, scope.participantId, actor);
  if (makerMustMatch && !continuation && !isDeepStrictEqual(captured, stored.issuerAuthority))
    throw new AuthorityFenceError();
  const issuerRoot = continuation
    ? undefined
    : await fenceEnvelopePlatformScope(
        client,
        scope.participantId,
        proposal.issuer.authority.authorityEnvelopeId,
      );
  const actorRoot = await fenceEnvelopePlatformScope(
    client,
    scope.participantId,
    actor.authorityEnvelopeId,
  );
  for (const current of issuerRoot ? [issuerRoot, actorRoot] : [actorRoot]) {
    const root = await platformScopeForEnvelopeProposal(client, scope, current, proposal);
    if (
      root.ownerParticipantId !== scope.participantId ||
      root.platformContextId !== proposal.issuer.platformContextId ||
      root.platformAuthorityEpoch !== proposal.issuer.platformAuthorityEpoch ||
      root.platformAuthorityDigest !== proposal.issuer.platformAuthorityDigest
    )
      throw new AuthorityFenceError();
  }
  if (
    continuation &&
    !(await hasPlatformRecoveryProposalHistory(
      client,
      scope,
      actor.authorityEnvelopeId,
      stored.envelopeId,
    ))
  )
    throw new AuthorityFenceError();
  return captured;
}

/** Explicit invoker-scoped transition, matching the existing bootstrap owner.
 * Callers must derive the target from an authenticated proposal, not a public
 * selector. It grants no authority and never changes the database role. */
export async function inEnvelopeParticipantScope<T>(
  client: PoolClient,
  owner: EnvelopeGovernanceScope,
  targetParticipantId: string,
  operation: () => Promise<T>,
): Promise<T> {
  const current = await client.query<{ matches: boolean }>(
    `select openpc.current_participant_id()=$1 and openpc.current_privacy_domain_id()=$2
      and openpc.current_operation_id()=$3 and openpc.current_action_intent_id()=$4 as matches`,
    [owner.participantId, owner.privacyDomainId, owner.operationId, owner.actionIntentId],
  );
  if (current.rows[0]?.matches !== true) throw new AuthorityFenceError();
  await client.query(`select openpc.set_request_context('PARTICIPANT',$1,NULL,$2,$3,false)`, [
    targetParticipantId,
    owner.operationId,
    owner.actionIntentId,
  ]);
  // On failure the enclosing transaction must roll back. Attempting another
  // query in an aborted transaction would conceal the original failure.
  const result = await operation();
  await client.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
    owner.participantId,
    owner.privacyDomainId,
    owner.operationId,
    owner.actionIntentId,
  ]);
  return result;
}

/** Lock all participating tenant roots before child authority/Platform locks.
 * This is only a prerequisite: the caller still fences both current actors. */
export async function fenceEnvelopeProposalParticipants(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  targetParticipantId: string,
): Promise<string> {
  let targetEpoch: string | undefined;
  for (const participantId of [...new Set([scope.participantId, targetParticipantId])].sort()) {
    const row = await inEnvelopeParticipantScope(client, scope, participantId, async () =>
      client.query<{ epoch: string }>(
        `select authority_epoch::text as epoch from control.participant
          where participant_id=$1 and state='ACTIVE' for share`,
        [participantId],
      ),
    );
    if (row.rowCount !== 1) throw new AuthorityFenceError();
    if (participantId === targetParticipantId) targetEpoch = row.rows[0]!.epoch;
  }
  if (targetEpoch === undefined) throw new AuthorityFenceError();
  return targetEpoch;
}

/** First root proposal only. A legacy usable scope is never grantable scope.
 * CHILD needs its separate sealed-parent/current-lineage owner; this initial
 * root function cannot silently reinterpret a child as a Platform issuance. */
export async function captureInitialRootEnvelopeProposal(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  input: TypedEnvelopeCreateCandidate,
  targetEpoch: string,
  maker: BoundAuthority,
  checker: BoundAuthority,
) {
  if (
    input.issuance !== 'PLATFORM_ROOT' ||
    maker.principalId === checker.principalId ||
    [maker, checker].some(
      (actor) =>
        actor.actionIntentId !== 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' ||
        actor.resourceId !== input.envelopeId ||
        actor.privacyDomainId !== scope.privacyDomainId,
    )
  ) {
    throw new AuthorityFenceError();
  }
  // The enclosing owner holds the full current session/role/grant fences.
  for (const actor of [maker, checker]) {
    await assertPlatformBootstrapActor(
      client,
      scope.participantId,
      actor.principalId,
      actor.sessionId,
    );
    const direct = await client.query(
      `select 1 from control.assignment assignment join control.authority_envelope envelope
        on envelope.participant_id=assignment.participant_id and envelope.authority_envelope_id=assignment.authority_envelope_id
      where assignment.participant_id=$1 and assignment.assignment_id=$2 and assignment.principal_id=$3
        and assignment.authority_envelope_id=$4 and assignment.row_version=$5 and assignment.state='ACTIVE'
        and assignment.maker_checker_required=true and envelope.maker_checker_required=true`,
      [
        scope.participantId,
        actor.assignmentId,
        actor.principalId,
        actor.authorityEnvelopeId,
        actor.assignmentRowVersion,
      ],
    );
    if (direct.rowCount !== 1) throw new AuthorityFenceError();
  }
  await fenceBoundAuthorities(client, scope.participantId, [maker, checker]);
  const issuerAuthority = await captureFencedEnvelopeAuthority(client, scope.participantId, maker);
  const root = await fenceEnvelopePlatformScope(
    client,
    scope.participantId,
    maker.authorityEnvelopeId,
  );
  const checkerRoot = await fenceEnvelopePlatformScope(
    client,
    scope.participantId,
    checker.authorityEnvelopeId,
  );
  if (
    root.ownerParticipantId !== scope.participantId ||
    root.platformContextId !== checkerRoot.platformContextId ||
    root.platformAuthorityEpoch !== checkerRoot.platformAuthorityEpoch ||
    root.platformAuthorityDigest !== checkerRoot.platformAuthorityDigest
  )
    throw new AuthorityFenceError();
  let issuanceRoot = root;
  if (input.platformScopeReplacementId !== undefined) {
    const pending = await pendingPlatformAdministrator(
      client,
      scope,
      root,
      input.envelopeId,
      input.platformScopeReplacementId,
    );
    if (
      input.participantId !== scope.participantId ||
      !isDeepStrictEqual(input.usable, pending.administrator.usable) ||
      !isDeepStrictEqual(input.grantable, pending.administrator.grantable)
    )
      throw new AuthorityFenceError();
    issuanceRoot = pending.root;
  }
  // Both scopes independently narrow the exact installed or approved successor bound.
  try {
    assertEnvelopeScopeNarrowing(issuanceRoot.grantable, input.usable);
    assertEnvelopeScopeNarrowing(issuanceRoot.grantable, input.grantable);
  } catch {
    process.stderr.write(
      JSON.stringify({
        event: 'initial_root_envelope_scope_rejected',
        stage: 'current_platform_grantable_bounds',
        participantId: scope.participantId,
        envelopeId: input.envelopeId,
        platformContextId: issuanceRoot.platformContextId,
        sourceValidUntilNs: issuanceRoot.grantable.validUntilNs,
        usableValidUntilNs: input.usable.validUntilNs,
        grantableValidUntilNs: input.grantable.validUntilNs,
        disposition: 'NO_ENVELOPE_EFFECT',
      }) + '\n',
    );
    throw new AuthorityFenceError();
  }
  const proposal: EnvelopeProposal = {
    envelopeId: input.envelopeId,
    semanticRevision: '1',
    participantId: input.participantId,
    participantEpoch: targetEpoch,
    authorityEpoch: targetEpoch,
    delegationEpoch: '0',
    issuance: 'PLATFORM_ROOT',
    usable: input.usable,
    grantable: input.grantable,
    issuer: {
      kind: 'PLATFORM',
      authority: issuerAuthority.binding,
      platformContextId: issuanceRoot.platformContextId,
      platformAuthorityEpoch: issuanceRoot.platformAuthorityEpoch,
      platformAuthorityDigest: issuanceRoot.platformAuthorityDigest,
      parent: null,
    },
  };
  const bytes = encodeEnvelopeProposal(proposal);
  return { proposal, bytes, digest: authorityEnvelopeDigest(bytes), issuerAuthority };
}

function timestampFromNs(value: string): string {
  const nanos = BigInt(value);
  const seconds = nanos / 1_000_000_000n;
  const micros = (nanos % 1_000_000_000n) / 1000n;
  return `${new Date(Number(seconds) * 1000).toISOString().slice(0, 19)}.${micros.toString().padStart(6, '0')}Z`;
}

function emptyDimensions(
  value: EnvelopeProposal['usable']['administration'] | EnvelopeProposal['usable']['runtime'],
): boolean {
  return (
    value.participantIds.length === 0 &&
    value.privacyDomainIds.length === 0 &&
    value.resourceIds.length === 0 &&
    value.dataClasses.length === 0 &&
    value.targetProfileIds.length === 0 &&
    value.riskClasses.length === 0
  );
}

/** The current authority tables store one flat permission slice. Preserve the
 * selected typed slice exactly and reject a mixed administration/runtime scope,
 * which would otherwise create an unsafe cross-product during projection. */
export function projectUsableEnvelopePermission(proposal: EnvelopeProposal) {
  const admin = proposal.usable.administration;
  const runtime = proposal.usable.runtime;
  const hasAdmin = admin.actionIntentIds.length > 0;
  const hasRuntime = runtime.capabilityIds.length > 0;
  if (
    hasAdmin === hasRuntime ||
    (hasAdmin && !emptyDimensions(runtime)) ||
    (hasRuntime && !emptyDimensions(admin))
  )
    throw new AuthorityFenceError();
  const selected = hasAdmin ? admin : runtime;
  if (
    selected.participantIds.length !== 1 ||
    selected.participantIds[0] !== proposal.participantId ||
    selected.privacyDomainIds.length === 0 ||
    selected.resourceIds.length === 0 ||
    selected.riskClasses.length === 0
  )
    throw new AuthorityFenceError();
  return {
    privacyDomainIds: selected.privacyDomainIds,
    actionIntentIds: admin.actionIntentIds,
    runtimeCapabilityIds: runtime.capabilityIds,
    resourceIds: selected.resourceIds,
    dataClasses: selected.dataClasses,
    targetProfileIds: selected.targetProfileIds,
    riskClasses: selected.riskClasses,
  };
}

/** Called only within the existing governed CREATE transaction. Deferred SQL
 * guards require its original consumed candidate, approval, evidence and
 * committed idempotency result before either row can become durable. */
export async function insertInitialEnvelopeProposal(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  captured: Awaited<ReturnType<typeof captureInitialRootEnvelopeProposal>>,
  createApprovalId: string,
) {
  const { proposal, bytes, digest, issuerAuthority } = captured;
  const candidate = await client.query<{ id: string }>(
    `select candidate.mutation_candidate_id::text as id from control.mutation_candidate candidate
      join control.approval_request approval on approval.participant_id=candidate.participant_id
        and approval.privacy_domain_id=candidate.privacy_domain_id and approval.subject_id=candidate.mutation_candidate_id
        and approval.subject_type='CONFIGURATION_CANDIDATE' and approval.subject_digest=candidate.candidate_digest
      where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.resource_id=$3
        and candidate.catalog_operation_id='ID-OP-ENVELOPE-CREATE' and candidate.state='APPROVED'
        and approval.approval_request_id=$4 and approval.state='APPROVED'`,
    [scope.participantId, scope.privacyDomainId, proposal.envelopeId, createApprovalId],
  );
  if (candidate.rowCount !== 1) throw new AuthorityFenceError();
  const permission = projectUsableEnvelopePermission(proposal);
  await inEnvelopeParticipantScope(client, scope, proposal.participantId, async () => {
    await client.query(
      `insert into control.authority_envelope
      (authority_envelope_id,participant_id,representation,principal_id,issuer_participant_id,issuer_privacy_domain_id,
       maker_principal_id,authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,semantic_digest,cose_sign1,
       privacy_domain_ids,action_intent_ids,runtime_capability_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,
       onward_delegation_depth,platform_context_id,platform_authority_epoch,last_mutation_operation_id)
      values($1,$2,'TYPED_V1',NULL,$3,$4,$5,$6,$7,'DRAFT',$8,$9,$10,$11,decode('','hex'),$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
      [
        proposal.envelopeId,
        proposal.participantId,
        scope.participantId,
        scope.privacyDomainId,
        proposal.issuer.authority.principalId,
        proposal.authorityEpoch,
        proposal.delegationEpoch,
        timestampFromNs(proposal.usable.validFromNs),
        timestampFromNs(proposal.usable.validUntilNs),
        bytes,
        Buffer.from(digest.slice(7), 'hex'),
        permission.privacyDomainIds,
        permission.actionIntentIds,
        permission.runtimeCapabilityIds,
        permission.resourceIds,
        permission.riskClasses,
        proposal.usable.makerCheckerRequired,
        proposal.usable.stepUpRequired,
        proposal.usable.onwardDelegationDepth,
        proposal.issuer.platformContextId,
        proposal.issuer.platformAuthorityEpoch,
        scope.operationId,
      ],
    );
  });
  await client.query(
    `insert into control.identity_envelope_proposal
    (envelope_id,participant_id,privacy_domain_id,target_participant_id,maker_principal_id,proposal_cbor,proposal_digest,
     issuer_authority,create_operation_id,create_candidate_id,create_approval_id)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      proposal.envelopeId,
      scope.participantId,
      scope.privacyDomainId,
      proposal.participantId,
      proposal.issuer.authority.principalId,
      bytes,
      Buffer.from(digest.slice(7), 'hex'),
      issuerAuthority,
      scope.operationId,
      candidate.rows[0]!.id,
      createApprovalId,
    ],
  );
}
