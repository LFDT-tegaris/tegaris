import type { PoolClient } from 'pg';
import { isDeepStrictEqual } from 'node:util';
import { platformScopeReadinessSchema as readinessSchema } from '../../../participant-service/src/contracts/platform-scope-readback.js';
import { AuthorityFenceError } from './authority-fence.js';
import { assertPlatformScopeReplacementCommit } from '../domain/platform-scope-replacement.js';
import {
  platformScopeReplacementCommit,
  type PlatformScopeReplacementCommit,
} from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import { fenceEnvelopePlatformScope } from './platform-envelope-scope.js';
import type { PlatformScopeReplacementOwner } from './platform-scope-replacement-store.js';
import {
  PlatformScopeOwnerFailure,
  type PlatformScopeOwnerStage,
} from './platform-scope-owner-failure.js';

/** Read under actual scoped actor fences. All counts and signed receipt
 * bindings come from the owning database; this read grants no authority. */
export async function readPlatformScopeReadiness(client: PoolClient, replacementId: string) {
  const rows = await client.query<{ readiness: unknown }>(
    'select openpc.read_platform_scope_replacement_readiness($1) readiness',
    [replacementId],
  );
  const parsed = readinessSchema.safeParse(rows.rows[0]?.readiness);
  if (rows.rowCount !== 1 || !parsed.success || parsed.data.replacementId !== replacementId)
    throw new AuthorityFenceError();
  return parsed.data;
}

/** Same real governed mutation transaction as preparation. The SQL owner
 * independently rechecks readiness while holding root and target custody,
 * installs the append-only successor and advances the root exactly once. */
export async function commitPlatformScopeReplacement(
  client: PoolClient,
  owner: PlatformScopeReplacementOwner,
  input: PlatformScopeReplacementCommit,
) {
  let ownerStage: PlatformScopeOwnerStage = 'approval_binding';
  try {
    const candidate = platformScopeReplacementCommit.parse(input);
    if (owner.makerPrincipalId === owner.checkerPrincipalId) throw new AuthorityFenceError();
    const approval = await client.query<{
      candidateId: string;
      makerEnvelope: string;
      checkerEnvelope: string;
    }>(
      `select c.mutation_candidate_id::text "candidateId",c.maker_authority_envelope_id::text "makerEnvelope",
      d.approver_authority_envelope_id::text "checkerEnvelope"
    from control.mutation_candidate c join control.approval_request a on a.participant_id=c.participant_id
      and a.privacy_domain_id=c.privacy_domain_id and a.subject_type='CONFIGURATION_CANDIDATE'
      and a.subject_id=c.mutation_candidate_id and a.subject_digest=c.candidate_digest and a.subject_version=c.expected_revision
    join control.approval_decision_record d on d.participant_id=a.participant_id and d.privacy_domain_id=a.privacy_domain_id
      and d.approval_request_id=a.approval_request_id and d.decision='APPROVE' and d.candidate_digest=c.candidate_digest
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.resource_id=$3 and c.catalog_operation_id='ID-OP-PLATFORM-SCOPE-COMMIT'
      and c.state='APPROVED' and c.maker_principal_id=$4 and d.approver_principal_id=$5 and d.signer_credential_id=$6
      and a.approval_request_id=$7 and a.state='APPROVED' and c.candidate_document=$8::jsonb`,
      [
        owner.participantId,
        owner.privacyDomainId,
        candidate.replacementId,
        owner.makerPrincipalId,
        owner.checkerPrincipalId,
        owner.checkerCredentialId,
        owner.approvalRequestId,
        candidate,
      ],
    );
    if (approval.rowCount !== 1) throw new AuthorityFenceError();
    ownerStage = 'current_actor_root';
    for (const envelopeId of [approval.rows[0]!.makerEnvelope, approval.rows[0]!.checkerEnvelope]) {
      const root = await fenceEnvelopePlatformScope(client, owner.participantId, envelopeId);
      if (
        root.platformContextId !== candidate.platformContextId ||
        root.platformAuthorityEpoch !== candidate.predecessorEpoch ||
        root.platformAuthorityDigest !== candidate.predecessorDigest ||
        root.ownerParticipantId !== owner.participantId ||
        root.installationPrivacyDomainId !== owner.privacyDomainId
      )
        throw new AuthorityFenceError();
    }
    ownerStage = 'withdrawal_and_handoff_readiness';
    const readiness = await readPlatformScopeReadiness(client, candidate.replacementId);
    assertPlatformScopeReplacementCommit(candidate, readiness);
    ownerStage = 'atomic_commit';
    const effect = await client.query<{ replacement: unknown }>(
      'select openpc.commit_platform_scope_replacement($1::jsonb,$2,$3) replacement',
      [candidate, approval.rows[0]!.candidateId, owner.approvalRequestId],
    );
    const expected = {
      replacementId: candidate.replacementId,
      successorDigest: candidate.successorDigest,
      state: 'COMMITTED' as const,
      revision: '2',
      operationId: owner.operationId,
      platformAuthorityEpoch: (BigInt(candidate.predecessorEpoch) + 1n).toString(),
    };
    ownerStage = 'effect_readback';
    if (effect.rowCount !== 1 || !isDeepStrictEqual(effect.rows[0]!.replacement, expected))
      throw new AuthorityFenceError();
    return expected;
  } catch (error) {
    throw new PlatformScopeOwnerFailure(ownerStage, error);
  }
}
