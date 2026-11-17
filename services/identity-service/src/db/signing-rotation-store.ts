import { signingRotationCandidateOperation } from '../../../../packages/security-kernel/src/signing-operations.js';
import { createHash } from 'node:crypto';
import { receiptRotationKey } from './signing-rotation-key.js';
import type { Pool, PoolClient } from 'pg';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import { localOperationId } from '../domain/local-operation-id.js';
import {
  signingRotationActions,
  signingRotationRequestSchema,
  SigningRotationError,
  type SigningRotationRequest,
  type SigningRotationState,
} from '../domain/signing-rotation.js';
import { runScopedTransaction } from './scoped-transaction.js';
import {
  fenceBoundAuthorities,
  type BoundAuthority,
  type AuthorityFence,
} from './authority-fence.js';
import {
  stageMutationCandidateInTransaction,
  type MutationCandidateAuthority,
} from './mutation-candidate-store.js';
import { approvalAuthorityDependencies } from './approval-authority-fence.js';
import { signingGenerationHistoricalFence } from './signing-generation-fence.js';
import { captureIdentityEnvelopeRotationCandidate } from './identity-envelope-rotation-candidate.js';

export const rotationDigest = (value: unknown): Buffer =>
  createHash('sha256').update(canonicalAuthorizationJson(value)).digest();
export interface SigningRotationPartition {
  readonly participantId: string;
  readonly privacyDomainId: string;
}
export interface SigningRotationScope extends SigningRotationPartition {
  readonly authorizationGenerationId?: string;
  readonly authority: BoundAuthority;
}
export interface SigningRotationPendingOperation {
  readonly operationId: string;
  readonly state: 'WRITE_AMBIGUITY';
  readonly targetState: SigningRotationState;
  readonly attempts: readonly {
    readonly attemptId: string;
    readonly method: string;
    readonly observationKind: 'UNRESOLVED' | 'NOT_FOUND' | 'PROVIDER_RESULT';
    readonly observationDigest: string;
  }[];
}
export interface RotationRow {
  rotationId: string;
  request: SigningRotationRequest;
  candidateDigest: Buffer;
  oldTrustDigest: Buffer;
  state: SigningRotationState;
  revision: string;
  approvalRequestId: string | null;
  makerPrincipalId: string;
  cutoverAtNs: string | null;
  newSignerId: string | null;
  recoveryFromState: SigningRotationState | null;
  recoveryFromRevision: string | null;
  pendingOperation: SigningRotationPendingOperation | null;
  recoveryContext: {
    originalOperationId: string;
    attempts: SigningRotationPendingOperation['attempts'];
  } | null;
  authorizationGeneration: {
    generationId: string;
    approvalRequestId: string;
    revision: string;
  } | null;
  authorityHold: {
    holdId: string;
    reason: 'AUTHORITY_CHANGED_AFTER_DISPATCH';
    originalOperationId: string;
  } | null;
}
export const rotationPendingOperationProjection = `(select jsonb_build_object('operationId',c.operation_id,'state',c.state,'targetState',c.to_state,'attempts',
      (select coalesce(jsonb_agg(jsonb_build_object('attemptId',a.attempt_id,'method',a.request->>'method',
        'observationKind',o.kind,'observationDigest','sha256:'||encode(o.observation_digest,'hex')) order by a.attempt_id),'[]'::jsonb)
       from control.signing_provider_attempt a join lateral(select kind,observation_digest from control.signing_rotation_observation
        where participant_id=a.participant_id and privacy_domain_id=a.privacy_domain_id and attempt_id=a.attempt_id
        order by observed_at_ns desc,observation_id desc limit 1) o on true
       where a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id and a.operation_id=c.operation_id))
     from control.signing_rotation_command c where c.participant_id=control.signing_key_rotation.participant_id and c.privacy_domain_id=control.signing_key_rotation.privacy_domain_id and c.rotation_id=control.signing_key_rotation.rotation_id
      and c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' and c.state='WRITE_AMBIGUITY'
      order by c.created_at,c.operation_id limit 1) as "pendingOperation",
 (select jsonb_build_object('originalOperationId',c.operation_id,'attempts',
   (select coalesce(jsonb_agg(jsonb_build_object('attemptId',a.attempt_id,'method',a.request->>'method',
    'observationKind',o.kind,'observationDigest','sha256:'||encode(o.observation_digest,'hex')) order by a.attempt_id),'[]'::jsonb)
    from control.signing_provider_attempt a join lateral(select kind,observation_digest from control.signing_rotation_observation
     where participant_id=a.participant_id and privacy_domain_id=a.privacy_domain_id and attempt_id=a.attempt_id
     order by observed_at_ns desc,observation_id desc limit 1) o on true
    where a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id and a.operation_id=c.operation_id
     and a.request->>'method'<>'SIGN_RECEIPT'))
  from control.signing_rotation_command c where c.participant_id=control.signing_key_rotation.participant_id
   and c.privacy_domain_id=control.signing_key_rotation.privacy_domain_id and c.rotation_id=control.signing_key_rotation.rotation_id
   and c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' and
    ((control.signing_key_rotation.state='FAILED' and c.state='FAILED' and c.result_kind='PROVIDER_REJECTED'
      and c.result_revision=control.signing_key_rotation.revision) or exists(select 1 from control.signing_rotation_authority_hold h
       where h.participant_id=c.participant_id and h.privacy_domain_id=c.privacy_domain_id and h.operation_id=c.operation_id and h.state='ACTIVE'))
   order by c.updated_at desc,c.operation_id desc limit 1) as "recoveryContext",
 (select jsonb_build_object('holdId',h.hold_id,'reason',h.reason,'originalOperationId',h.operation_id)
  from control.signing_rotation_authority_hold h where h.participant_id=control.signing_key_rotation.participant_id
   and h.privacy_domain_id=control.signing_key_rotation.privacy_domain_id and h.rotation_id=control.signing_key_rotation.rotation_id
   and h.state='ACTIVE') as "authorityHold",
 (select jsonb_build_object('generationId',g.generation_id,'approvalRequestId',a.approval_request_id,'revision',g.result_revision::text)
  from control.signing_authorization_generation g join control.approval_request a on a.participant_id=g.participant_id
   and a.privacy_domain_id=g.privacy_domain_id and a.subject_id=g.candidate_id and a.subject_digest=g.candidate_digest
  where g.participant_id=control.signing_key_rotation.participant_id and g.privacy_domain_id=control.signing_key_rotation.privacy_domain_id
   and g.rotation_id=control.signing_key_rotation.rotation_id and g.state='CONSUMED' order by g.result_revision desc limit 1) as "authorizationGeneration"`;
export async function rotationRow(
  client: PoolClient,
  scope: SigningRotationPartition,
  id: string,
  lock = false,
): Promise<RotationRow> {
  const result = await client.query<RotationRow>(
    `select rotation_id::text as "rotationId",request,
    candidate_digest as "candidateDigest",old_trust_digest as "oldTrustDigest",state,revision::text,
    approval_request_id::text as "approvalRequestId",maker_principal_id::text as "makerPrincipalId",
    cutover_at_ns::text as "cutoverAtNs",new_signer_id as "newSignerId",recovery_from_state as "recoveryFromState",recovery_from_revision::text as "recoveryFromRevision",
    ${rotationPendingOperationProjection} from control.signing_key_rotation
    where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 ${lock ? 'for update' : ''}`,
    [scope.participantId, scope.privacyDomainId, id],
  );
  if (result.rowCount !== 1 || result.rows[0] === undefined)
    throw new SigningRotationError('NOT_FOUND');
  return result.rows[0];
}
export function rotationView(row: RotationRow) {
  return {
    rotationId: `urn:openpc:resource:${row.rotationId}`,
    ...row.request,
    candidateDigest: `sha256:${row.candidateDigest.toString('hex')}`,
    state: row.state,
    revision: row.revision,
    approvalRequestId:
      row.approvalRequestId === null ? null : `urn:openpc:resource:${row.approvalRequestId}`,
    cutoverAtNs: row.cutoverAtNs,
    recoveryFromState: row.recoveryFromState,
    recoveryFromRevision: row.recoveryFromRevision,
    newFingerprint: row.newSignerId,
    pendingOperation: row.pendingOperation,
    recoveryContext: row.recoveryContext,
    authorityHold: row.authorityHold,
    authorizationGeneration: row.authorizationGeneration,
  };
}

/** Atomically stage the exact immutable request and shared candidate; provider state is untouched. */
export async function createSigningRotation(
  pool: Pool,
  authority: MutationCandidateAuthority,
  requestInput: SigningRotationRequest,
  idempotencyKey: string,
) {
  const request = signingRotationRequestSchema.parse(requestInput);
  return runScopedTransaction(
    pool,
    { ...authority, actionIntentId: signingRotationActions.create },
    localOperationId,
    async (client, creationOperationId) => {
      let candidate: unknown;
      let oldTrustDigest: Buffer;
      if (request.signerRole === 'IDENTITY_ENVELOPE') {
        // Authenticate the maker before exposing or locking issuer provenance.
        // Candidate staging below rechecks the same ordinary authority fence.
        await fenceBoundAuthorities(client, authority.participantId, [
          {
            ...authority,
            actionIntentId: signingRotationActions.create,
            resourceId: '*',
          },
        ]);
        const prepared = await captureIdentityEnvelopeRotationCandidate(
          client,
          authority,
          request,
          creationOperationId,
          idempotencyKey,
        );
        if (prepared.replayRotationId !== undefined)
          return rotationView(await rotationRow(client, authority, prepared.replayRotationId));
        candidate = prepared.candidate;
        oldTrustDigest = prepared.oldTrustDigest;
      } else {
        const key = await receiptRotationKey(client, authority, request, idempotencyKey);
        if (key.rowCount !== 1 || key.rows[0] === undefined)
          throw new SigningRotationError('CONFLICT');
        oldTrustDigest = key.rows[0].trustDigest;
        candidate = {
          request,
          oldTrustDigest: `sha256:${oldTrustDigest.toString('hex')}`,
          oldKeyEpoch: key.rows[0].keyEpoch,
        };
      }
      const candidateDigest = rotationDigest(candidate);
      const operation = signingRotationCandidateOperation(signingRotationActions.create);
      const id = await stageMutationCandidateInTransaction(client, {
        authorization: authority,
        participantId: authority.participantId,
        privacyDomainId: authority.privacyDomainId,
        actionIntentId: signingRotationActions.create,
        actionIntentDigest: request.actionIntentDigest,
        catalogOperationId: operation.catalogOperationId,
        resourceType: operation.resourceType,
        operationClass: operation.operationClass,
        resourceId: localOperationId(),
        serverGeneratedResourceId: true,
        expectedRevision: '1',
        idempotencyKey,
        candidateDigest: `sha256:${candidateDigest.toString('hex')}`,
        candidate,
      });
      await client.query(
        `insert into control.signing_key_rotation(participant_id,privacy_domain_id,rotation_id,request,candidate_digest,
      maker_principal_id,environment_id,workload_credential_id,old_signer_id,new_signer_id,old_trust_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict (participant_id,privacy_domain_id,rotation_id) do nothing`,
        [
          authority.participantId,
          authority.privacyDomainId,
          id,
          request,
          candidateDigest,
          authority.principalId,
          request.environmentId,
          request.workloadCredentialId,
          request.oldFingerprint,
          request.newFingerprint ?? null,
          oldTrustDigest,
        ],
      );
      return rotationView(await rotationRow(client, authority, id));
    },
  );
}

/** Called only by the existing approval owner, after its live maker/checker and one-use WebAuthn decision. */
export async function consumeSigningRotationApproval(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string; operationId: string },
  approvalRequestId: string,
): Promise<void> {
  const selected = await client.query<{ rotationId: string }>(
    `select r.rotation_id::text as "rotationId"
    from control.approval_request a join control.mutation_candidate c on c.participant_id=a.participant_id
      and c.privacy_domain_id=a.privacy_domain_id and c.mutation_candidate_id=a.subject_id
    join control.signing_key_rotation r on r.participant_id=c.participant_id and r.privacy_domain_id=c.privacy_domain_id
      and r.rotation_id=c.resource_id and r.candidate_digest=c.candidate_digest and r.maker_principal_id=c.maker_principal_id
    where a.participant_id=$1 and a.privacy_domain_id=$2 and a.approval_request_id=$3 and a.state='APPROVED'
      and a.action_intent_id=$4 and a.subject_type='CONFIGURATION_CANDIDATE'
      and a.subject_digest=c.candidate_digest and a.subject_version=c.expected_revision
      and a.maker_principal_id=c.maker_principal_id and a.expires_at>clock_timestamp()
      and c.state='APPROVED' and c.expires_at>clock_timestamp() and c.expected_revision=r.revision
      and c.resource_type='signing-key-rotation' and c.catalog_operation_id='OPS-OP-CREATE-SIGNING-KEY-ROTATION'
      and r.state='REQUESTED' for update of r,c`,
    [scope.participantId, scope.privacyDomainId, approvalRequestId, signingRotationActions.create],
  );
  if (selected.rowCount !== 1) throw new SigningRotationError('DENIED');
  await client.query(
    `update control.mutation_candidate c set state='CONSUMED',consumed_operation_id=$4,updated_at=clock_timestamp()
    from control.approval_request a where a.participant_id=$1 and a.privacy_domain_id=$2 and a.approval_request_id=$3
      and c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id and c.mutation_candidate_id=a.subject_id`,
    [scope.participantId, scope.privacyDomainId, approvalRequestId, scope.operationId],
  );
  await client.query(
    `update control.signing_key_rotation set state='APPROVED',revision=revision+1,
    approval_request_id=$4,approved_operation_id=$5,updated_at=clock_timestamp()
    where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3`,
    [
      scope.participantId,
      scope.privacyDomainId,
      selected.rows[0]!.rotationId,
      approvalRequestId,
      scope.operationId,
    ],
  );
}

/** All lifecycle work repeats the persisted approval's live epochs before business-row locks. */
export async function fenceSigningRotation(
  client: PoolClient,
  scope: SigningRotationScope,
  id: string,
  lifecycleCredentialId?: string,
): Promise<
  RotationRow & {
    readonly authorityFence: AuthorityFence;
    readonly authorities: readonly BoundAuthority[];
  }
> {
  const discovered = await rotationRow(client, scope, id);
  if (discovered.approvalRequestId === null) throw new SigningRotationError('CONFLICT');
  const generation = await client.query<{ generationId: string; approvalRequestId: string }>(
    `select g.generation_id::text as "generationId",a.approval_request_id::text as "approvalRequestId"
     from control.signing_authorization_generation g join control.approval_request a
      on a.participant_id=g.participant_id and a.privacy_domain_id=g.privacy_domain_id and a.subject_id=g.candidate_id
      and a.subject_digest=g.candidate_digest and a.state='APPROVED'
     where g.participant_id=$1 and g.privacy_domain_id=$2 and g.rotation_id=$3
      and (($4::uuid is null and g.state='CONSUMED') or g.generation_id=$4)
     order by g.result_revision desc nulls last limit 1`,
    [scope.participantId, scope.privacyDomainId, id, scope.authorizationGenerationId ?? null],
  );
  if (scope.authorizationGenerationId && generation.rowCount !== 1)
    throw new SigningRotationError('DENIED');
  const approvalRequestId = generation.rows[0]?.approvalRequestId ?? discovered.approvalRequestId;
  const dependencies = await approvalAuthorityDependencies(client, scope, approvalRequestId, true);
  const workload = await client.query<{ principalId: string }>(
    `select principal_id::text as "principalId" from control.credential
    where participant_id=$1 and credential_id=any($2::uuid[]) and state='ACTIVE'
      and valid_from<=clock_timestamp() and (valid_until is null or valid_until>clock_timestamp())`,
    [
      scope.participantId,
      [
        discovered.request.workloadCredentialId,
        ...(lifecycleCredentialId ? [lifecycleCredentialId] : []),
      ],
    ],
  );
  if (workload.rowCount !== (lifecycleCredentialId ? 2 : 1))
    throw new SigningRotationError('DENIED');
  const authorities = [scope.authority, ...dependencies.authorities];
  const historical = scope.authorizationGenerationId
    ? await signingGenerationHistoricalFence(
        client,
        scope.participantId,
        scope.privacyDomainId,
        scope.authorizationGenerationId,
      )
    : {};
  const currentRows: AuthorityFence = {
    ...dependencies.rows,
    principal: workload.rows.map(({ principalId }) => ({ id: principalId })),
    credential: [
      ...(dependencies.rows.credential ?? []),
      { id: discovered.request.workloadCredentialId },
      ...(lifecycleCredentialId ? [{ id: lifecycleCredentialId }] : []),
    ],
  };
  if (scope.authorizationGenerationId)
    await fenceBoundAuthorities(
      client,
      scope.participantId,
      authorities,
      Object.fromEntries(
        [...new Set([...Object.keys(historical), ...Object.keys(currentRows)])].map((table) => [
          table,
          [
            ...(historical[table as keyof AuthorityFence] ?? []),
            ...(currentRows[table as keyof AuthorityFence] ?? []),
          ],
        ]),
      ),
    );
  const authorityFence = await fenceBoundAuthorities(
    client,
    scope.participantId,
    authorities,
    currentRows,
  );
  const repeated = await approvalAuthorityDependencies(client, scope, approvalRequestId, true);
  if (canonicalAuthorizationJson(dependencies) !== canonicalAuthorizationJson(repeated))
    throw new SigningRotationError('DENIED');
  const row = await lockSigningRotationKeys(client, scope, discovered);
  if (
    !row.oldTrustDigest.equals(discovered.oldTrustDigest) ||
    row.approvalRequestId !== discovered.approvalRequestId
  )
    throw new SigningRotationError('CONFLICT');
  const live = await client.query(
    `select 1 from control.business_signing_key old
    join control.credential c on c.participant_id=old.participant_id and c.credential_id=old.workload_credential_id
    join control.principal p on p.participant_id=c.participant_id and p.principal_id=c.principal_id
    join control.business_signing_key effective on effective.participant_id=old.participant_id and effective.privacy_domain_id=old.privacy_domain_id
      and effective.signer_id=$5
    join control.business_signing_key_state s on s.participant_id=effective.participant_id and s.privacy_domain_id=effective.privacy_domain_id and s.signer_id=effective.signer_id
    where old.participant_id=$1 and old.privacy_domain_id=$2 and old.signer_id=$3 and old.trust_digest=$4
      and c.credential_epoch=old.workload_credential_epoch and c.state='ACTIVE' and p.kind='WORKLOAD' and p.state='ACTIVE'
      and c.valid_from<=clock_timestamp() and (c.valid_until is null or c.valid_until>clock_timestamp())
      and s.state='ACTIVE' and effective.valid_from_ns<=floor(extract(epoch from clock_timestamp())*1000000)*1000
      and effective.valid_until_ns>floor(extract(epoch from clock_timestamp())*1000000)*1000`,
    [
      scope.participantId,
      scope.privacyDomainId,
      row.request.oldFingerprint,
      row.oldTrustDigest,
      row.cutoverAtNs === null ? row.request.oldFingerprint : row.newSignerId,
    ],
  );
  if (live.rowCount !== 1) throw new SigningRotationError('DENIED');
  return { ...row, authorityFence, authorities };
}

/** Fail closed before receipt-only rotation, selection or recovery work. */
export async function assertReceiptRotationPurpose(
  client: PoolClient,
  scope: SigningRotationPartition,
  signerId: string,
) {
  // Purpose is immutable. The existing rotation and recovery protocol only
  // governs receipt keys; an envelope key must never reach that provider port.
  const key = await client.query<{ signing_purpose_code: number }>(
    `select signing_purpose_code from control.business_signing_key
     where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3`,
    [scope.participantId, scope.privacyDomainId, signerId],
  );
  if (key.rowCount !== 1 || key.rows[0]?.signing_purpose_code !== 338)
    throw new SigningRotationError('DENIED');
}

/** Shared lock order for public lifecycle commands and closed workload reconciliation. */
export async function lockSigningRotationKeys(
  client: PoolClient,
  scope: SigningRotationPartition,
  discovered: RotationRow,
) {
  await assertReceiptRotationPurpose(client, scope, discovered.request.oldFingerprint);
  // Receipt writers lock selections before key state. Preserve that ordering at every cutover.
  await client.query(
    `select s.profile_digest from control.business_signing_selection s join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
    where s.participant_id=$1 and s.privacy_domain_id=$2 and s.environment_id=$3
    and k.workload_credential_id=$4 order by s.profile_digest for update of s`,
    [
      scope.participantId,
      scope.privacyDomainId,
      discovered.request.environmentId,
      discovered.request.workloadCredentialId,
    ],
  );
  await client.query(
    `select signer_id from control.business_signing_key_state where participant_id=$1 and privacy_domain_id=$2
    and (signer_id in ($3,$4) or signer_id in(select s.signer_id from control.business_signing_selection s
      join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id)
      where s.participant_id=$1 and s.privacy_domain_id=$2 and s.environment_id=$5 and k.workload_credential_id=$6)) order by signer_id for update`,
    [
      scope.participantId,
      scope.privacyDomainId,
      discovered.request.oldFingerprint,
      discovered.newSignerId,
      discovered.request.environmentId,
      discovered.request.workloadCredentialId,
    ],
  );
  const row = await rotationRow(client, scope, discovered.rotationId, true);
  return row;
}
