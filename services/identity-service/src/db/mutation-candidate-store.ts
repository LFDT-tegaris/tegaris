import {
  readDiscoveryReceivingProof,
  type DiscoveryReceivingAuthenticator,
} from './discovery-preapproval-proof.js';
import { currentPlatformEnvelopeSql } from './current-platform-envelope.js';
import { discoveryCertificateRecoveryIntent } from '../contracts/discovery-certificate-recovery.js';
import { assertDiscoveryCertificateRecoveryOperation } from '../domain/discovery-certificate-recovery.js';
import {
  discoveryCertificateRecoveryContextEligible,
  isDiscoveryCertificateRecoveryIntent,
} from './platform-recovery-commit-purpose.js';
import { platformRecoveryIntent } from '../contracts/platform-recovery.js';
import { assertPlatformRecoveryOperation } from '../domain/platform-recovery-operation.js';
import { currentMutationCandidateSql, fenceMutationIntent } from './mutation-candidate-fence.js';
import { signingCandidateStagingSql } from './signing-candidate-catalog.js';
import { workloadSigningHandoverAdmissionOperation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import { handoverAdmissionCandidateSchema } from '../domain/workload-signing-handover-admission-candidate.js';
import type { PoolClient } from 'pg';
import { initialEnvelopeActivationEligible } from '../domain/platform-envelope-activation-policy.js';
import { typedEnvelopeCreateCandidate } from '../../../participant-service/src/contracts/envelope.js';
import { platformScopeReplacementContextEligible } from './platform-scope-replacement-eligibility.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import { readPlatformScopeReadiness } from './platform-scope-commit-store.js';
import { assertPlatformScopeReplacementCommit } from '../domain/platform-scope-replacement.js';
import { platformScopeReplacementCommit } from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import {
  fenceBoundAuthorities,
  type AuthorityFence,
  type BoundAuthority,
} from './authority-fence.js';

export type MutationCandidateAuthority = Omit<BoundAuthority, 'actionIntentId' | 'resourceId'> & {
  readonly participantId: string;
};
export class MutationCandidateError extends Error {
  constructor(readonly code: 'PC-AUTH-0005' | 'PC-DATA-6004' | 'PC-DATA-6007') {
    super(code);
  }
}

export interface MutationCandidateContext {
  readonly authorization: MutationCandidateAuthority;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly actionIntentId: string;
  readonly actionIntentDigest: string;
  readonly catalogOperationId: string;
  readonly resourceType: string;
  readonly operationClass: 'CREATE' | 'UPDATE' | 'APPROVE' | 'ACTIVATE' | 'RECOVER' | 'EXPORT';
  readonly resourceId: string;
  readonly serverGeneratedResourceId: boolean;
  readonly expectedRevision: string;
  readonly idempotencyKey: string;
  readonly candidateDigest: string;
  readonly candidate: unknown;
}

interface CandidateRow {
  readonly mutationCandidateId: string;
  readonly attempt: string;
  readonly resourceId: string;
  readonly candidateDigest: Buffer;
  readonly candidateDocument: unknown;
  readonly expectedRevision: string;
  readonly state: 'PROPOSED' | 'APPROVAL_REQUESTED' | 'APPROVED' | 'CONSUMED' | 'CANCELLED';
  readonly unexpired: boolean;
  readonly current: boolean;
  readonly makerAuthority: MutationCandidateAuthority;
}

function digestBytes(value: string): Buffer {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) throw new MutationCandidateError('PC-DATA-6004');
  const bytes = Buffer.from(value.slice('sha256:'.length), 'hex');
  if (bytes.length !== 32) throw new MutationCandidateError('PC-DATA-6004');
  return bytes;
}

function sameDocument(left: unknown, right: unknown): boolean {
  return canonicalAuthorizationJson(left) === canonicalAuthorizationJson(right);
}

/**
 * Owns candidate staging inside the caller's participant/privacy-scoped transaction.
 * Call before business row locks. Discover additional authority dependencies first:
 * this owner takes one ranked fence and repeats the actual maker authorization.
 * It never commits; a rotation request and its candidate therefore roll back together.
 */
export async function assertMutationCandidateAuthority(
  client: PoolClient,
  context: MutationCandidateContext,
  additional: AuthorityFence = {},
): Promise<void> {
  const authorization = context.authorization;
  const envelope =
    context.catalogOperationId === 'ID-OP-ENVELOPE-CREATE'
      ? typedEnvelopeCreateCandidate.safeParse(context.candidate)
      : undefined;
  const typedPlatformEnvelope =
    envelope?.success === true &&
    envelope.data.issuance === 'PLATFORM_ROOT' &&
    envelope.data.envelopeId === context.resourceId &&
    context.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' &&
    context.operationClass === 'UPDATE' &&
    context.resourceType === 'participant' &&
    context.expectedRevision === '0';
  const typedPlatformActivation =
    context.catalogOperationId === 'ID-OP-ENVELOPE-ACTIVATE' &&
    context.actionIntentId === 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1' &&
    context.operationClass === 'ACTIVATE' &&
    context.resourceType === 'participant' &&
    context.expectedRevision === '3' &&
    sameDocument(context.candidate, { envelopeId: context.resourceId }) &&
    (await initialEnvelopeActivationEligible(
      client,
      context.participantId,
      context.privacyDomainId,
      context.resourceId,
    ));
  if (
    authorization.participantId !== context.participantId ||
    authorization.privacyDomainId !== context.privacyDomainId
  ) {
    throw new MutationCandidateError('PC-AUTH-0005');
  }
  await fenceBoundAuthorities(
    client,
    context.participantId,
    [
      {
        ...authorization,
        catalogOperationId: context.catalogOperationId,
        actionIntentId: context.actionIntentId,
        resourceId: context.resourceId,
      },
    ],
    additional,
  );
  const live = await client.query<{ representation: string; recoveryIntent: unknown }>(
    `select envelope.representation,(select recovery.intent from control.platform_recovery_case recovery
      where recovery.recovery_id=envelope.recovery_case_id and recovery.participant_id=envelope.participant_id) as "recoveryIntent"
   from control.action_intent intent
   join control.participant participant on participant.participant_id=$1
    and participant.state='ACTIVE' and participant.authority_epoch=$9
   join control.privacy_domain privacy on privacy.participant_id=$1
    and privacy.privacy_domain_id=$2::uuid and privacy.state='ACTIVE'
   join control.principal principal on principal.participant_id=$1
    and principal.principal_id=$3 and principal.state='ACTIVE'
    and principal.authority_epoch=$10
   join control.session session on session.participant_id=$1
    and session.session_id=$4 and session.principal_id=$3 and session.state='ACTIVE'
    and session.session_epoch=$11 and session.participant_epoch=$9
    and session.authority_epoch=$10 and session.delegation_epoch=$12
    and ((session.context_mode='PARTICIPANT' and session.privacy_domain_id=$2::uuid)
      or ($19 and session.context_mode='PLATFORM' and session.privacy_domain_id is null
        and participant.root_privacy_domain_id=$2::uuid and principal.kind='PLATFORM_OPERATOR'))
    and session.idle_expires_at>clock_timestamp()
    and session.absolute_expires_at>clock_timestamp()
   join control.assignment assignment on assignment.participant_id=$1
    and assignment.assignment_id=$5 and assignment.state='ACTIVE'
    and assignment.principal_id=$3
    and assignment.row_version=$13 and assignment.valid_during @> clock_timestamp()
    and assignment.delegation_epoch=$12 and assignment.maker_checker_required=true
    and $6=any(assignment.action_intent_ids)
    and $2::text=any(assignment.privacy_domain_ids)
    and ($7::text=any(assignment.resource_ids) or '*'=any(assignment.resource_ids))
   join control.authority_envelope envelope on envelope.participant_id=$1
    and envelope.authority_envelope_id=$8
    and envelope.authority_envelope_id=assignment.authority_envelope_id
    and (envelope.principal_id=$3 or (envelope.representation='TYPED_V1' and envelope.principal_id is null))
    and envelope.state='ACTIVE' and ${currentPlatformEnvelopeSql('envelope', false, true)} and envelope.authority_epoch=$14
    and envelope.delegation_epoch=$12
    and envelope.maker_checker_required=true
    and envelope.valid_from<=clock_timestamp()
    and (envelope.valid_until is null or envelope.valid_until>clock_timestamp())
    and $6=any(envelope.action_intent_ids)
    and $2::text=any(envelope.privacy_domain_ids)
    and ($7::text=any(envelope.resource_ids) or '*'=any(envelope.resource_ids))
  where intent.action_intent_id=$6 and intent.resource_type=$15
    and intent.operation_class=$16 and (intent.maker_checker_required=true
      or openpc.signing_governance_required($1,$2::uuid,$7::uuid,$6))
    and intent.idempotency_required=true and intent.semantic_digest=$17
    and ${signingCandidateStagingSql}`,
    [
      context.participantId,
      context.privacyDomainId,
      authorization.principalId,
      authorization.sessionId,
      authorization.assignmentId,
      context.actionIntentId,
      context.resourceId,
      authorization.authorityEnvelopeId,
      authorization.participantEpoch,
      authorization.principalEpoch,
      authorization.sessionEpoch,
      authorization.delegationEpoch,
      authorization.assignmentRowVersion,
      authorization.authorityEpoch,
      context.resourceType,
      context.operationClass,
      digestBytes(context.actionIntentDigest),
      context.catalogOperationId,
      typedPlatformEnvelope ||
        typedPlatformActivation ||
        (await discoveryCertificateRecoveryContextEligible(client, {
          ...context,
          authorityEnvelopeId: authorization.authorityEnvelopeId,
          principalId: authorization.principalId,
        })) ||
        (await platformScopeReplacementContextEligible(client, {
          ...context,
          authorityEnvelopeId: authorization.authorityEnvelopeId,
        })) ||
        ([
          'ID-OP-PARTICIPANT-TRANSFER',
          'ID-OP-PARTICIPANT-SHRINK',
          'ID-OP-PARTICIPANT-ARCHIVE',
          'ID-OP-PARTICIPANT-RESTORE',
          'ID-OP-PARTICIPANT-CREATE',
          'ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE',
          'ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE',
        ].includes(context.catalogOperationId) &&
          typeof context.candidate === 'object' &&
          context.candidate !== null &&
          ('firstAdministrator' in context.candidate ||
            'mandateId' in context.candidate ||
            ('mutation' in context.candidate &&
              [
                'ID-OP-PARTICIPANT-TRANSFER',
                'ID-OP-PARTICIPANT-SHRINK',
                'ID-OP-PARTICIPANT-ARCHIVE',
                'ID-OP-PARTICIPANT-RESTORE',
              ].includes(context.catalogOperationId)))),
    ],
  );
  if (live.rowCount !== 1) throw new MutationCandidateError('PC-AUTH-0005');
  if (live.rows[0]?.representation === 'RECOVERY_V1') {
    try {
      if (isDiscoveryCertificateRecoveryIntent(live.rows[0].recoveryIntent)) {
        const intent = discoveryCertificateRecoveryIntent.parse(live.rows[0].recoveryIntent);
        if (authorization.principalId !== intent.administrators[0].principalId)
          throw new MutationCandidateError('PC-AUTH-0005');
        assertDiscoveryCertificateRecoveryOperation(
          intent.certificateRecovery,
          context.catalogOperationId,
          context.resourceId,
          context.expectedRevision,
          context.candidate,
        );
        return;
      }
      assertPlatformRecoveryOperation(
        platformRecoveryIntent.parse(live.rows[0].recoveryIntent),
        context.participantId,
        context.catalogOperationId,
        context.resourceId,
        context.candidate,
      );
    } catch {
      throw new MutationCandidateError('PC-AUTH-0005');
    }
  }
}

/** Resolve all workload and selected-purpose signer dependencies before the
 * ranked authority fence; both staging and approved resume use this owner. */
export async function workloadRotationAuthorityDependencies(
  client: PoolClient,
  context: Pick<MutationCandidateContext, 'participantId' | 'resourceId' | 'authorization'>,
  proof: Pick<MutationCandidateContext, 'actionIntentId' | 'candidateDigest'>,
  additional: AuthorityFence = {},
): Promise<AuthorityFence> {
  const source = await client.query<{ principalId: string }>(
    'select principal_id::text as "principalId" from control.credential where participant_id=$1 and credential_id=$2 and kind=\'WORKLOAD_MTLS\'',
    [context.participantId, context.resourceId],
  );
  if (source.rowCount !== 1 || !source.rows[0]) throw new MutationCandidateError('PC-AUTH-0005');
  const signers = await client.query<{ credentialId: string }>(
    `select distinct signer_credential_id::text as "credentialId" from control.mfa_challenge
        where participant_id=$1 and session_id=$2 and principal_id=$3 and action_intent_id=$4
          and resource_digest=$5 and signer_credential_id is not null`,
    [
      context.participantId,
      context.authorization.sessionId,
      context.authorization.principalId,
      proof.actionIntentId,
      digestBytes(proof.candidateDigest),
    ],
  );
  return {
    ...additional,
    participant: [...(additional.participant ?? []), { id: context.participantId, write: true }],
    principal: [...(additional.principal ?? []), { id: source.rows[0].principalId }],
    credential: [
      ...(additional.credential ?? []),
      ...signers.rows.map((signer) => ({ id: signer.credentialId })),
      { id: context.resourceId, write: true },
    ],
  };
}

export async function stageMutationCandidateInTransaction(
  client: PoolClient,
  context: MutationCandidateContext,
  additional: AuthorityFence = {},
  receiving?: DiscoveryReceivingAuthenticator,
): Promise<string> {
  const handover =
    context.catalogOperationId === workloadSigningHandoverAdmissionOperation.catalogOperationId
      ? handoverAdmissionCandidateSchema.parse(context.candidate)
      : undefined;
  if (
    handover &&
    (context.actionIntentId !== handover.request.actionIntentId ||
      context.actionIntentDigest !== handover.request.actionIntentDigest ||
      context.resourceType !== workloadSigningHandoverAdmissionOperation.resourceType ||
      context.operationClass !== workloadSigningHandoverAdmissionOperation.operationClass ||
      context.participantId !== handover.participantId ||
      context.privacyDomainId !== handover.privacyDomainId ||
      context.authorization.principalId !== handover.makerPrincipalId ||
      context.resourceId !== handover.handoverId ||
      context.serverGeneratedResourceId ||
      context.expectedRevision !== handover.expectedRevision ||
      context.candidateDigest !== canonicalAuthorizationDigest(handover))
  )
    throw new MutationCandidateError('PC-DATA-6004');
  const owningFence =
    context.catalogOperationId === 'ID-OP-WORKLOAD-ROTATE'
      ? await workloadRotationAuthorityDependencies(client, context, context, additional)
      : additional;
  await assertMutationCandidateAuthority(client, context, owningFence);
  const authorization = context.authorization;
  const commit = context.catalogOperationId === 'ID-OP-PLATFORM-SCOPE-COMMIT';
  await fenceMutationIntent(client, { ...context, principalId: authorization.principalId });
  const candidateDigest = digestBytes(context.candidateDigest);
  const readOriginal = () =>
    client.query<CandidateRow>(
      `select mutation_candidate_id::text as "mutationCandidateId",attempt::text as attempt,
        resource_id::text as "resourceId",candidate_digest as "candidateDigest",
        candidate_document as "candidateDocument",expected_revision::text as "expectedRevision",
        state,expires_at>clock_timestamp() as unexpired,
        ${currentMutationCandidateSql('candidate')} as current,
        jsonb_build_object('participantId',participant_id::text,'principalId',maker_principal_id::text,
          'sessionId',maker_session_id::text,'sessionEpoch',maker_session_epoch::text,
          'participantEpoch',maker_participant_epoch::text,'principalEpoch',maker_principal_epoch::text,
          'assignmentId',maker_assignment_id::text,'assignmentRowVersion',maker_assignment_row_version::text,
          'authorityEnvelopeId',maker_authority_envelope_id::text,'authorityEpoch',maker_authority_epoch::text,
          'delegationEpoch',maker_delegation_epoch::text) as "makerAuthority"
     from control.mutation_candidate candidate
    where participant_id=$1 and maker_principal_id=$2 and action_intent_id=$3
      and catalog_operation_id=$4 and idempotency_key=$5 and privacy_domain_id=$6
      ${commit ? '' : `and ${currentMutationCandidateSql('candidate')}`} for update`,
      [
        context.participantId,
        authorization.principalId,
        context.actionIntentId,
        context.catalogOperationId,
        context.idempotencyKey,
        context.privacyDomainId,
      ],
    );
  const reconcile = (existing: Awaited<ReturnType<typeof readOriginal>>) => {
    const current = commit ? existing.rows.filter((row) => row.current) : existing.rows;
    const row = current[0];
    if (
      current.length !== 1 ||
      row === undefined ||
      !row.candidateDigest.equals(candidateDigest) ||
      !sameDocument(row.candidateDocument, context.candidate) ||
      row.expectedRevision !== context.expectedRevision ||
      (!context.serverGeneratedResourceId && row.resourceId !== context.resourceId) ||
      row.state === 'CANCELLED' ||
      !row.unexpired ||
      (commit &&
        !sameDocument(row.makerAuthority, {
          participantId: context.participantId,
          principalId: authorization.principalId,
          sessionId: authorization.sessionId,
          sessionEpoch: authorization.sessionEpoch,
          participantEpoch: authorization.participantEpoch,
          principalEpoch: authorization.principalEpoch,
          assignmentId: authorization.assignmentId,
          assignmentRowVersion: authorization.assignmentRowVersion,
          authorityEnvelopeId: authorization.authorityEnvelopeId,
          authorityEpoch: authorization.authorityEpoch,
          delegationEpoch: authorization.delegationEpoch,
        }))
    )
      throw new MutationCandidateError('PC-DATA-6007');
    // A consumed original may be read for idempotent effect reconciliation;
    // the proof owner independently forbids using it as fresh authority.
    return row.resourceId;
  };
  const original = await readOriginal();
  if (!commit && original.rowCount !== 0) {
    const row = original.rows[0];
    if (
      original.rowCount === 1 &&
      row &&
      row.state === 'PROPOSED' &&
      row.current &&
      row.candidateDigest.equals(candidateDigest) &&
      sameDocument(row.candidateDocument, context.candidate) &&
      row.expectedRevision === context.expectedRevision &&
      row.resourceId === context.resourceId &&
      row.makerAuthority.authorityEnvelopeId !== authorization.authorityEnvelopeId &&
      (await discoveryCertificateRecoveryContextEligible(client, {
        ...context,
        authorityEnvelopeId: authorization.authorityEnvelopeId,
        principalId: authorization.principalId,
      }))
    ) {
      if (!receiving) throw new MutationCandidateError('PC-AUTH-0005');
      const proof = await readDiscoveryReceivingProof(client, context, receiving);
      if (!proof) throw new MutationCandidateError('PC-AUTH-0005');
      // The trigger closes provenance, fresh receiving custody and ALL no-effect
      // predicates. The original row/key/body/expiry never changes.
      const inserted = await client.query<{ resourceId: string }>(
        `insert into control.mutation_candidate(
         predecessor_candidate_id,resume_request,attempt,participant_id,privacy_domain_id,
         action_intent_id,catalog_operation_id,resource_type,operation_class,resource_id,
         candidate_digest,candidate_document,expected_revision,idempotency_key,maker_principal_id,
         maker_session_id,maker_session_epoch,maker_participant_epoch,maker_principal_epoch,
         maker_assignment_id,maker_assignment_row_version,maker_authority_envelope_id,
         maker_authority_epoch,maker_delegation_epoch,state,expires_at)
        select old.mutation_candidate_id,jsonb_build_object('command','DISCOVERY_PREAPPROVAL_CONTINUE',
          'predecessorCandidateId',old.mutation_candidate_id::text,'expectedAttempt',old.attempt::text,
          'candidateDigest','sha256:'||encode(old.candidate_digest,'hex'),
          'predecessorRecoveryId',previous.recovery_id::text,'recoveryId',fresh.recovery_id::text,'receivingProof',$11::jsonb),
          old.attempt+1,old.participant_id,old.privacy_domain_id,old.action_intent_id,old.catalog_operation_id,
          old.resource_type,old.operation_class,old.resource_id,old.candidate_digest,old.candidate_document,
          old.expected_revision,old.idempotency_key,old.maker_principal_id,$2,$3,$4,$5,$6,$7,$8,$9,$10,
          'PROPOSED',least(clock_timestamp()+interval '30 minutes',fresh.valid_until)
        from control.mutation_candidate old join control.authority_envelope predecessor
          on predecessor.participant_id=old.participant_id and predecessor.authority_envelope_id=old.maker_authority_envelope_id
        join control.platform_recovery_case previous on previous.participant_id=old.participant_id
          and previous.recovery_id=predecessor.recovery_case_id
        join control.authority_envelope receiving on receiving.participant_id=old.participant_id
          and receiving.authority_envelope_id=$8
        join control.platform_recovery_case fresh on fresh.participant_id=old.participant_id
          and fresh.recovery_id=receiving.recovery_case_id
        where old.mutation_candidate_id=$1 returning resource_id::text as "resourceId"`,
        [
          row.mutationCandidateId,
          authorization.sessionId,
          authorization.sessionEpoch,
          authorization.participantEpoch,
          authorization.principalEpoch,
          authorization.assignmentId,
          authorization.assignmentRowVersion,
          authorization.authorityEnvelopeId,
          authorization.authorityEpoch,
          authorization.delegationEpoch,
          proof,
        ],
      );
      if (inserted.rowCount !== 1) throw new MutationCandidateError('PC-DATA-6007');
      return reconcile(await readOriginal());
    }
    return reconcile(original);
  }
  if (commit) {
    // The authenticated original key/body is already retained by the caller.
    // Under its intent lock resolve any durable original BEFORE another INSERT.
    // Supersession, expiry or a changed session cannot manufacture a new intent.
    if (original.rowCount !== 0) return reconcile(original);
    try {
      const candidate = platformScopeReplacementCommit.parse(context.candidate);
      if (
        candidate.replacementId !== context.resourceId ||
        candidate.expectedReplacementRevision !== context.expectedRevision ||
        canonicalAuthorizationDigest(candidate) !== context.candidateDigest
      )
        throw new MutationCandidateError('PC-DATA-6007');
      const readiness = await readPlatformScopeReadiness(client, candidate.replacementId);
      assertPlatformScopeReplacementCommit(candidate, readiness);
    } catch {
      throw new MutationCandidateError('PC-AUTH-0005');
    }
  }
  await client.query(
    `insert into control.mutation_candidate(
   participant_id,privacy_domain_id,action_intent_id,catalog_operation_id,
   resource_type,operation_class,resource_id,candidate_digest,candidate_document,
   expected_revision,idempotency_key,maker_principal_id,maker_session_id,
   maker_session_epoch,maker_participant_epoch,maker_principal_epoch,
   maker_assignment_id,maker_assignment_row_version,maker_authority_envelope_id,
   maker_authority_epoch,maker_delegation_epoch,state,expires_at)
 values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,
        'PROPOSED',least(clock_timestamp()+interval '30 minutes',
          to_timestamp(floor($22::numeric/1000000000)::double precision)
            +(mod($22::numeric,1000000000)/1000)::integer*interval '1 microsecond'))
 on conflict do nothing
 returning resource_id::text as "resourceId"`,
    [
      context.participantId,
      context.privacyDomainId,
      context.actionIntentId,
      context.catalogOperationId,
      context.resourceType,
      context.operationClass,
      context.resourceId,
      candidateDigest,
      context.candidate,
      context.expectedRevision,
      context.idempotencyKey,
      authorization.principalId,
      authorization.sessionId,
      authorization.sessionEpoch,
      authorization.participantEpoch,
      authorization.principalEpoch,
      authorization.assignmentId,
      authorization.assignmentRowVersion,
      authorization.authorityEnvelopeId,
      authorization.authorityEpoch,
      authorization.delegationEpoch,
      handover?.expiresAtNs ?? null,
    ],
  );
  // The digest uniqueness constraint may reject a different business key.
  // Only the exact retained key/body can resolve the authoritative original.
  return reconcile(await readOriginal());
}
