import { hasPlatformRecoveryProposalHistory } from './platform-recovery-continuation.js';
import { platformScopeForEnvelopeProposal } from './pending-platform-administrator.js';
import { isDeepStrictEqual } from 'node:util';
import type { PoolClient } from 'pg';
import { decodeEnvelopeProposal } from '@openpc/security-kernel';
import { assertPlatformBootstrapActor } from '../domain/bootstrap-authority.js';
import {
  AuthorityFenceError,
  fenceDurableAuthorities,
  fenceBoundAuthorities,
  type AuthorityFence,
  type BoundAuthority,
} from './authority-fence.js';
import { captureFencedEnvelopeAuthority } from './identity-envelope-authority.js';
import {
  fenceEnvelopeProposalParticipants,
  type EnvelopeGovernanceScope,
  type StoredEnvelopeProposal,
} from './identity-envelope-proposal.js';
import { fenceEnvelopePlatformScope } from './platform-envelope-scope.js';
import { decodeIdentityAuthorityEnvelope } from '@openpc/security-kernel';
import { readEnvelopeCreation } from './identity-envelope-readback.js';
import { fenceIdentityEnvelopeSigningTrust } from './identity-envelope-signing-store.js';
import type { StoredEnvelopeActivation } from './identity-envelope-activation-store.js';
import { fenceMutationIntent } from './mutation-candidate-fence.js';

/** Current ACTIVATE actors are distinct from the historical SUBMIT actors.
 * The latter's durable grants must remain valid, but an expired issuing browser
 * session is not a revocation of the committed proposal. No new grant is made.
 * Caller holds these fences through preparation. Publication additionally
 * uses the reserved activation grants, without reviving their old sessions. */
export async function fenceInitialEnvelopeActivation(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  stored: StoredEnvelopeProposal,
  maker: BoundAuthority,
  checker: BoundAuthority,
  dependencies: { authorities: readonly BoundAuthority[]; rows: AuthorityFence },
) {
  const proposal = decodeEnvelopeProposal(stored.bytes);
  if (
    scope.actionIntentId !== 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' ||
    stored.state !== 'APPROVED' ||
    stored.version !== '3' ||
    stored.submissionMaker === null ||
    stored.submissionChecker === null ||
    stored.submissionCheckerAuthority === null ||
    proposal.issuance !== 'PLATFORM_ROOT' ||
    proposal.participantId !== scope.participantId ||
    proposal.issuer.authority.participantId !== scope.participantId ||
    stored.targetParticipantId !== scope.participantId ||
    maker.principalId === checker.principalId ||
    [maker, checker].some(
      (actor) =>
        actor.privacyDomainId !== scope.privacyDomainId ||
        actor.actionIntentId !== scope.actionIntentId ||
        actor.resourceId !== stored.envelopeId,
    ) ||
    !isDeepStrictEqual(stored.submissionMaker.authority, stored.issuerAuthority.binding) ||
    !isDeepStrictEqual(
      stored.submissionChecker.authority,
      stored.submissionCheckerAuthority.binding,
    )
  )
    throw new AuthorityFenceError();
  // Historical grants and current actors share one complete, sorted lock set.
  // In particular, never add historical principals after locking live sessions.
  const continuation =
    (await hasPlatformRecoveryProposalHistory(
      client,
      scope,
      maker.authorityEnvelopeId,
      stored.envelopeId,
    )) &&
    (await hasPlatformRecoveryProposalHistory(
      client,
      scope,
      checker.authorityEnvelopeId,
      stored.envelopeId,
    ));
  if (
    continuation &&
    (maker.principalId !== stored.makerPrincipalId ||
      checker.principalId !== stored.submissionChecker.authority.principalId)
  )
    throw new AuthorityFenceError();
  if (continuation)
    await fenceBoundAuthorities(
      client,
      scope.participantId,
      [...dependencies.authorities, maker, checker],
      dependencies.rows,
    );
  else
    await fenceDurableAuthorities(
      client,
      scope.participantId,
      [stored.issuerAuthority.durable, stored.submissionCheckerAuthority.durable],
      dependencies.rows,
      [...dependencies.authorities, maker, checker],
    );
  const targetEpoch = await fenceEnvelopeProposalParticipants(
    client,
    scope,
    stored.targetParticipantId,
  );
  if (targetEpoch !== proposal.participantEpoch || targetEpoch !== proposal.authorityEpoch)
    throw new AuthorityFenceError();
  for (const actor of [maker, checker]) {
    await assertPlatformBootstrapActor(
      client,
      scope.participantId,
      actor.principalId,
      actor.sessionId,
    );
    const direct = await client.query(
      `select 1 from control.assignment assignment join control.authority_envelope envelope
        on envelope.participant_id=assignment.participant_id
        and envelope.authority_envelope_id=assignment.authority_envelope_id
      where assignment.participant_id=$1 and assignment.assignment_id=$2
        and assignment.principal_id=$3 and assignment.authority_envelope_id=$4
        and assignment.row_version=$5 and assignment.state='ACTIVE'
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
  for (const envelopeId of [
    ...new Set([
      ...(continuation
        ? []
        : [
            stored.issuerAuthority.binding.authorityEnvelopeId,
            stored.submissionCheckerAuthority.binding.authorityEnvelopeId,
          ]),
      maker.authorityEnvelopeId,
      checker.authorityEnvelopeId,
    ]),
  ].sort()) {
    const current = await fenceEnvelopePlatformScope(client, scope.participantId, envelopeId);
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
    (!(await hasPlatformRecoveryProposalHistory(
      client,
      scope,
      maker.authorityEnvelopeId,
      stored.envelopeId,
    )) ||
      !(await hasPlatformRecoveryProposalHistory(
        client,
        scope,
        checker.authorityEnvelopeId,
        stored.envelopeId,
      )))
  )
    throw new AuthorityFenceError();
  return {
    maker: await captureFencedEnvelopeAuthority(client, scope.participantId, maker),
    checker: await captureFencedEnvelopeAuthority(client, scope.participantId, checker),
  };
}

/** Before claiming the first send, take the same full ranked grant fence and
 * verify the current authenticated recovery actor. Reserved historical sessions
 * are deliberately not revived. No lock is retained across provider I/O. */
export async function fenceInitialEnvelopeActivationDispatch(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  original: StoredEnvelopeActivation,
  current: BoundAuthority,
) {
  if (
    current.principalId !== original.principalId ||
    current.actionIntentId !== scope.actionIntentId ||
    current.resourceId !== original.envelopeId ||
    current.privacyDomainId !== scope.privacyDomainId
  )
    throw new AuthorityFenceError();
  const creation = await readEnvelopeCreation(client, scope, original.envelopeId);
  const source = creation.stored;
  const artifact = decodeIdentityAuthorityEnvelope(original.payload);
  const captured = await client.query<{
    maker: typeof source.issuerAuthority;
    checker: typeof source.issuerAuthority;
  }>(
    `select maker_authority as maker,checker_authority as checker from control.identity_envelope_activation
      where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and attempt_id=$4`,
    [scope.participantId, scope.privacyDomainId, original.operationId, original.attemptId],
  );
  const row = captured.rows[0];
  if (
    captured.rowCount !== 1 ||
    !row ||
    source.state !== 'APPROVED' ||
    source.version !== '3' ||
    !source.submissionCheckerAuthority ||
    !artifact.proposalBytes.equals(source.bytes) ||
    !isDeepStrictEqual(row.maker.binding, artifact.activation.maker.authority) ||
    !isDeepStrictEqual(row.checker.binding, artifact.activation.checker.authority)
  )
    throw new AuthorityFenceError();
  const workloads = await client.query<{ id: string; principalId: string }>(
    `select credential_id::text id,principal_id::text as "principalId" from control.credential
      where participant_id=$1 and credential_id=any($2::uuid[]) and state='ACTIVE' and kind='WORKLOAD_MTLS'
        and valid_from<=clock_timestamp() and valid_until>clock_timestamp()`,
    [
      scope.participantId,
      [original.request.workloadCredentialId, original.request.callerWorkloadCredentialId],
    ],
  );
  if (
    workloads.rowCount !==
    new Set([original.request.workloadCredentialId, original.request.callerWorkloadCredentialId])
      .size
  )
    throw new AuthorityFenceError();
  const continuation =
    (await hasPlatformRecoveryProposalHistory(
      client,
      scope,
      row.maker.binding.authorityEnvelopeId,
      source.envelopeId,
    )) &&
    (await hasPlatformRecoveryProposalHistory(
      client,
      scope,
      row.checker.binding.authorityEnvelopeId,
      source.envelopeId,
    ));
  if (
    continuation &&
    (row.maker.binding.principalId !== source.makerPrincipalId ||
      row.checker.binding.principalId !== source.submissionChecker?.authority.principalId)
  )
    throw new AuthorityFenceError();
  await fenceDurableAuthorities(
    client,
    scope.participantId,
    [
      ...(continuation
        ? []
        : [source.issuerAuthority.durable, source.submissionCheckerAuthority.durable]),

      row.maker.durable,
      row.checker.durable,
    ],
    {
      credential: workloads.rows.map((value) => ({ id: value.id })),
      principal: workloads.rows.map((value) => ({ id: value.principalId })),
    },
    [current],
  );
  await assertPlatformBootstrapActor(
    client,
    scope.participantId,
    current.principalId,
    current.sessionId,
  );
  const proposal = decodeEnvelopeProposal(source.bytes);
  for (const envelopeId of [
    ...new Set([
      ...(continuation
        ? []
        : [
            source.issuerAuthority.binding.authorityEnvelopeId,
            source.submissionCheckerAuthority.binding.authorityEnvelopeId,
          ]),
      row.maker.binding.authorityEnvelopeId,
      row.checker.binding.authorityEnvelopeId,
      current.authorityEnvelopeId,
    ]),
  ].sort()) {
    const current = await fenceEnvelopePlatformScope(client, scope.participantId, envelopeId);
    const root = await platformScopeForEnvelopeProposal(client, scope, current, proposal);
    if (
      root.platformContextId !== proposal.issuer.platformContextId ||
      root.platformAuthorityEpoch !== proposal.issuer.platformAuthorityEpoch ||
      root.platformAuthorityDigest !== proposal.issuer.platformAuthorityDigest
    )
      throw new AuthorityFenceError();
  }
  const trust = await fenceIdentityEnvelopeSigningTrust(client, {
    ...scope,
    environmentId: original.request.environmentId,
  });
  if (trust.trust.signerId !== original.request.expectedFingerprint)
    throw new AuthorityFenceError();
  await fenceInitialEnvelopeActivationIntent(client, scope, original);
  if (
    continuation &&
    (!(await hasPlatformRecoveryProposalHistory(
      client,
      scope,
      row.maker.binding.authorityEnvelopeId,
      source.envelopeId,
    )) ||
      !(await hasPlatformRecoveryProposalHistory(
        client,
        scope,
        row.checker.binding.authorityEnvelopeId,
        source.envelopeId,
      )))
  )
    throw new AuthorityFenceError();
  // The mutation trigger revalidates all captured epochs, root digest, actual
  // role/risk membership and selected key under these held row locks.
}

/** Lock the original business intent after its complete authority fence, then
 * re-read freshness. Cache expiry cannot replace the original, and consumed
 * proof does not extend an unconsumed candidate or its independent approval. */
export async function fenceInitialEnvelopeActivationIntent(
  client: PoolClient,
  scope: EnvelopeGovernanceScope,
  original: StoredEnvelopeActivation,
) {
  if (
    scope.operationId !== original.operationId ||
    scope.actionIntentId !== 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1'
  )
    throw new AuthorityFenceError();
  await fenceMutationIntent(client, {
    ...scope,
    principalId: original.principalId,
    idempotencyKey: original.idempotencyKey,
    catalogOperationId: 'ID-OP-ENVELOPE-ACTIVATE',
  });
  const selected = await client.query<{ candidateId: string; approvalId: string }>(
    `select c.mutation_candidate_id::text as "candidateId",a.approval_request_id::text as "approvalId"
     from control.identity_envelope_activation original
     join control.mutation_candidate c on c.participant_id=original.participant_id
       and c.privacy_domain_id=original.privacy_domain_id and c.mutation_candidate_id=original.candidate_id
     join control.approval_request a on a.participant_id=original.participant_id
       and a.privacy_domain_id=original.privacy_domain_id and a.approval_request_id=original.approval_request_id
     where original.participant_id=$1 and original.privacy_domain_id=$2 and original.operation_id=$3
       and original.attempt_id=$4 and original.envelope_id=$5 and original.principal_id=$6 and original.idempotency_key=$7
     for share of c,a`,
    [
      scope.participantId,
      scope.privacyDomainId,
      original.operationId,
      original.attemptId,
      original.envelopeId,
      original.principalId,
      original.idempotencyKey,
    ],
  );
  const intent = selected.rows[0];
  if (selected.rowCount !== 1 || !intent) throw new AuthorityFenceError();
  const current = await client.query<{ current: boolean }>(
    `select openpc.identity_envelope_activation_intent_current($1,$2,$3,$4) as current`,
    [scope.participantId, scope.privacyDomainId, intent.candidateId, intent.approvalId],
  );
  if (current.rows[0]?.current !== true) throw new AuthorityFenceError();
}
