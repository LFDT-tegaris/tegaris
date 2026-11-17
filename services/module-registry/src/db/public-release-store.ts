import { createHash } from 'node:crypto';
import { resourceReadAuthoritySql } from './resource-read-authority.js';

import type { Pool, PoolClient } from 'pg';
import {
  approvalAuthorityDependencies,
  stepUpCredentialDependencies,
} from '../../../identity-service/src/db/approval-authority-fence.js';

import { canonicalJson } from '../domain/digest.js';
import { ContractError } from '../domain/errors.js';
import {
  assertActionIntent,
  completeOperation,
  inScope,
  reserveOperation,
  type ApprovalDecisionAuthority,
  type PublicApprovalScope,
  type PublicOperation,
} from './public-approval-store.js';

export type ReleaseState =
  | 'DRAFT'
  | 'APPROVAL_PENDING'
  | 'APPROVED'
  | 'PUBLISHED'
  | 'STAGED'
  | 'ACTIVE'
  | 'ROLLED_BACK'
  | 'RETIRED';

export interface ReleaseBundleView {
  readonly releaseBundleId: string;
  readonly participantId: string;
  readonly manifestDigest: string;
  readonly dependencyClosureDigest: string;
  readonly state: ReleaseState;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

interface ReleaseRow {
  readonly releaseBundleId: string;
  readonly participantId: string;
  readonly policyVersionId: string;
  readonly approvalRequestId: string | null;
  readonly createdByPrincipalId: string;
  readonly manifestDigest: Buffer;
  readonly dependencyClosureDigest: Buffer;
  readonly state: ReleaseState;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface PublicReleaseListRequest {
  readonly limit: number;
  readonly state?: ReleaseState;
  readonly snapshotAt: string;
  readonly snapshotRevision: string;
  readonly sort: 'updatedAt' | '-updatedAt';
  readonly after?: { readonly updatedAt: string; readonly id: string };
}

export interface PublicReleasePage {
  readonly items: readonly ReleaseBundleView[];
  readonly next?: { readonly updatedAt: string; readonly id: string };
  readonly total: string;
  readonly snapshotRevision: string;
}

const digest = (value: unknown) => createHash('sha256').update(canonicalJson(value)).digest();
const bytes = (value: string) => Buffer.from(value.slice('sha256:'.length), 'hex');
const digestString = (value: Buffer) => `sha256:${value.toString('hex')}`;
const timestamp = (value: string | Date) =>
  new Date(value).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
const urn = (id: string) => `urn:openpc:resource:${id}`;

async function conflictSafe<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === '23505') {
      throw new ContractError('PC-POLICY-2002');
    }
    throw error;
  }
}

function view(row: ReleaseRow): ReleaseBundleView {
  return {
    releaseBundleId: urn(row.releaseBundleId),
    participantId: `urn:openpc:participant:${row.participantId}`,
    manifestDigest: digestString(row.manifestDigest),
    dependencyClosureDigest: digestString(row.dependencyClosureDigest),
    state: row.state,
    revision: row.revision,
    createdAt: timestamp(row.createdAt),
    updatedAt: timestamp(row.updatedAt),
  };
}

const selectRelease = `select release_bundle_id::text as "releaseBundleId",
       participant_id::text as "participantId",policy_version_id::text as "policyVersionId",
       approval_request_id::text as "approvalRequestId",
       created_by_principal_id::text as "createdByPrincipalId",manifest_digest as "manifestDigest",
       dependency_closure_digest as "dependencyClosureDigest",state,revision::text as revision,
       created_at::text as "createdAt",updated_at::text as "updatedAt"
  from control.policy_release_bundle`;

async function releaseRow(
  client: PoolClient,
  scope: PublicApprovalScope,
  id: string,
  lock = false,
): Promise<ReleaseRow> {
  const selected = await client.query<ReleaseRow>(
    `${selectRelease} where participant_id=$1 and privacy_domain_id=$2 and release_bundle_id=$3${lock ? ' for update' : ''}`,
    [scope.participantId, scope.privacyDomainId, id],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2001');
  return row;
}

async function exactVersion(
  client: PoolClient,
  scope: PublicApprovalScope,
  manifestDigest: string,
  dependencyClosureDigest?: string,
): Promise<{ readonly policyVersionId: string; readonly dependencyClosureDigest: Buffer }> {
  const selected = await client.query<{
    readonly policyVersionId: string;
    readonly dependencyClosureDigest: Buffer;
  }>(
    `select version.policy_version_id::text as "policyVersionId",
            artifact.dependency_closure_digest as "dependencyClosureDigest"
       from control.policy_version version
       join control.policy_artifact artifact
         on artifact.participant_id=version.participant_id
        and artifact.privacy_domain_id=version.privacy_domain_id
        and artifact.semantic_digest=version.semantic_digest
      where version.participant_id=$1 and version.privacy_domain_id=$2
        and version.semantic_digest=$3
        ${dependencyClosureDigest === undefined ? '' : 'and artifact.dependency_closure_digest=$4'}
      limit 2`,
    dependencyClosureDigest === undefined
      ? [scope.participantId, scope.privacyDomainId, bytes(manifestDigest)]
      : [
          scope.participantId,
          scope.privacyDomainId,
          bytes(manifestDigest),
          bytes(dependencyClosureDigest),
        ],
  );
  const row = selected.rows[0];
  if (selected.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2003');
  return row;
}

export async function createPublicReleaseBundle(
  pool: Pool,
  scope: PublicApprovalScope,
  input: {
    readonly manifestDigest: string;
    readonly dependencyClosureDigest: string;
    readonly request: unknown;
  },
): Promise<PublicOperation> {
  return inScope(pool, scope, async (client) => {
    const intent = await assertActionIntent(client, scope, 'CREATE', ['release-bundles']);
    const replay = await reserveOperation(client, scope, digest(input.request), '0');
    if (replay !== undefined) return replay;
    const version = await exactVersion(
      client,
      scope,
      input.manifestDigest,
      input.dependencyClosureDigest,
    );
    const inserted = await conflictSafe(() =>
      client.query<{ id: string }>(
        `insert into control.policy_release_bundle
         (participant_id,privacy_domain_id,policy_version_id,created_by_principal_id,
          manifest_digest,dependency_closure_digest,state)
       values($1,$2,$3,$4,$5,$6,'DRAFT') returning release_bundle_id::text as id`,
        [
          scope.participantId,
          scope.privacyDomainId,
          version.policyVersionId,
          scope.principalId,
          bytes(input.manifestDigest),
          version.dependencyClosureDigest,
        ],
      ),
    );
    const row = inserted.rows[0];
    if (inserted.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2005');
    return completeOperation(client, scope, intent, row.id, '1');
  });
}

export async function getPublicReleaseBundle(pool: Pool, scope: PublicApprovalScope, id: string) {
  return inScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['release-bundles']);
    return view(await releaseRow(client, scope, id));
  });
}

export async function listPublicReleaseBundles(
  pool: Pool,
  scope: PublicApprovalScope,
  request: PublicReleaseListRequest,
): Promise<PublicReleasePage> {
  return inScope(pool, scope, async (client) => {
    await assertActionIntent(client, scope, 'READ', ['release-bundles']);
    const values: unknown[] = [
      scope.participantId,
      scope.privacyDomainId,
      request.snapshotAt,
      scope.principalId,
      scope.authority.sessionId,
    ];
    const where = [
      'participant_id=$1',
      'privacy_domain_id=$2',
      'updated_at <= $3::timestamptz',
      resourceReadAuthoritySql(
        'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1',
        'policy_release_bundle.release_bundle_id',
      ),
    ];
    if (request.state !== undefined) {
      values.push(request.state);
      where.push(`state=$${values.length}`);
    }
    const count = await client.query<{ total: string }>(
      `select count(*)::text as total from control.policy_release_bundle where ${where.join(' and ')}`,
      values,
    );
    if (request.after !== undefined) {
      values.push(request.after.updatedAt, request.after.id);
      where.push(
        `(updated_at,release_bundle_id) ${request.sort === '-updatedAt' ? '<' : '>'} ($${values.length - 1}::timestamptz,$${values.length}::uuid)`,
      );
    }
    values.push(request.limit + 1);
    const direction = request.sort === '-updatedAt' ? 'desc' : 'asc';
    const selected = await client.query<ReleaseRow>(
      `${selectRelease} where ${where.join(' and ')} order by updated_at ${direction},release_bundle_id ${direction} limit $${values.length}`,
      values,
    );
    const hasNext = selected.rows.length > request.limit;
    const rows = selected.rows.slice(0, request.limit);
    const last = hasNext ? rows.at(-1) : undefined;
    return {
      items: rows.map(view),
      ...(last === undefined
        ? {}
        : { next: { updatedAt: timestamp(last.updatedAt), id: last.releaseBundleId } }),
      total: count.rows[0]?.total ?? '0',
      snapshotRevision: request.snapshotRevision,
    };
  });
}

export async function updatePublicReleaseBundle(
  pool: Pool,
  scope: PublicApprovalScope,
  id: string,
  expectedRevision: string,
  replacementDigest: string,
  request: unknown,
): Promise<PublicOperation> {
  return inScope(pool, scope, async (client) => {
    const intent = await assertActionIntent(client, scope, 'UPDATE', ['release-bundles']);
    const replay = await reserveOperation(client, scope, digest(request), expectedRevision);
    if (replay !== undefined) return replay;
    const current = await releaseRow(client, scope, id, true);
    if (current.state === 'ROLLED_BACK') {
      if (
        current.revision !== expectedRevision ||
        current.approvalRequestId === null ||
        digestString(current.manifestDigest) !== replacementDigest
      ) {
        throw new ContractError('PC-POLICY-2003');
      }
      if (current.createdByPrincipalId === scope.principalId)
        throw new ContractError('PC-POLICY-2004');
      const checker = await client.query(
        `select 1
           from control.approval_request request
           join control.approval_decision_record decision
             on decision.participant_id=request.participant_id
            and decision.approval_request_id=request.approval_request_id
            and decision.decision='APPROVE'
            and decision.candidate_digest=request.subject_digest
          where request.participant_id=$1 and request.privacy_domain_id=$2
            and request.approval_request_id=$3 and request.subject_type='POLICY_VERSION'
            and request.subject_id=$4 and request.subject_digest=$5
            and request.maker_principal_id=$6 and decision.approver_principal_id=$7
          limit 2`,
        [
          scope.participantId,
          scope.privacyDomainId,
          current.approvalRequestId,
          current.policyVersionId,
          current.manifestDigest,
          current.createdByPrincipalId,
          scope.principalId,
        ],
      );
      if (checker.rowCount !== 1) throw new ContractError('PC-POLICY-2004');
      const retired = await client.query<{ revision: string }>(
        `update control.policy_release_bundle
            set state='RETIRED',revision=revision+1,updated_at=clock_timestamp()
          where participant_id=$1 and privacy_domain_id=$2 and release_bundle_id=$3
            and revision=$4 and state='ROLLED_BACK'
          returning revision::text as revision`,
        [scope.participantId, scope.privacyDomainId, id, expectedRevision],
      );
      const retiredRow = retired.rows[0];
      if (retired.rowCount !== 1 || retiredRow === undefined)
        throw new ContractError('PC-POLICY-2002');
      return completeOperation(client, scope, intent, id, retiredRow.revision);
    }
    if (
      current.state !== 'DRAFT' ||
      current.revision !== expectedRevision ||
      current.createdByPrincipalId !== scope.principalId ||
      digestString(current.manifestDigest) === replacementDigest
    ) {
      throw new ContractError('PC-POLICY-2003');
    }
    const replacement = await exactVersion(client, scope, replacementDigest);
    const updated = await conflictSafe(() =>
      client.query<{ revision: string }>(
        `update control.policy_release_bundle set policy_version_id=$4,manifest_digest=$5,
              dependency_closure_digest=$6,revision=revision+1,updated_at=clock_timestamp()
        where participant_id=$1 and release_bundle_id=$2 and revision=$3 and state='DRAFT'
        returning revision::text as revision`,
        [
          scope.participantId,
          id,
          expectedRevision,
          replacement.policyVersionId,
          bytes(replacementDigest),
          replacement.dependencyClosureDigest,
        ],
      ),
    );
    const row = updated.rows[0];
    if (updated.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2002');
    return completeOperation(client, scope, intent, id, row.revision);
  });
}

export async function publishPublicReleaseBundle(
  pool: Pool,
  scope: PublicApprovalScope,
  decisionAuthority: ApprovalDecisionAuthority,
  id: string,
  expectedRevision: string,
  inputDigest: string,
): Promise<PublicOperation> {
  return inScope(
    pool,
    scope,
    async (client) => {
      const intent = await assertActionIntent(client, scope, 'ACTIVATE', ['release-bundle']);
      const replay = await reserveOperation(client, scope, bytes(inputDigest), expectedRevision);
      if (replay !== undefined) return replay;
      const current = await releaseRow(client, scope, id, true);
      const expectedInputDigest = digestString(
        digest({
          actionIntentId: scope.actionIntentId,
          targetRef: urn(id),
          manifestDigest: digestString(current.manifestDigest),
          dependencyClosureDigest: digestString(current.dependencyClosureDigest),
          expectedRevision,
        }),
      );
      if (
        current.state !== 'DRAFT' ||
        current.revision !== expectedRevision ||
        current.createdByPrincipalId === scope.principalId ||
        inputDigest !== expectedInputDigest
      ) {
        throw new ContractError('PC-POLICY-2004');
      }
      const approved = await client.query<{ approvalRequestId: string }>(
        `select request.approval_request_id::text as "approvalRequestId"
         from control.approval_request request
         join control.approval_decision_record decision on decision.participant_id=request.participant_id
          and decision.approval_request_id=request.approval_request_id and decision.decision='APPROVE'
          and decision.candidate_digest=request.subject_digest
        where request.participant_id=$1 and request.privacy_domain_id=$2
          and request.subject_type='POLICY_VERSION' and request.subject_id=$3
          and request.subject_digest=$4 and request.state='APPROVED'
          and request.expires_at>clock_timestamp()
          and request.maker_principal_id=$5 and decision.approver_principal_id=$6
        order by decision.decided_at desc limit 2 for share of request`,
        [
          scope.participantId,
          scope.privacyDomainId,
          current.policyVersionId,
          current.manifestDigest,
          current.createdByPrincipalId,
          scope.principalId,
        ],
      );
      const approvedAuthority = approved.rows[0];
      if (approved.rowCount !== 1 || approvedAuthority === undefined)
        throw new ContractError('PC-POLICY-2004');
      const stepUp = await client.query<{
        mfaChallengeId: string;
        evidenceCbor: Buffer;
        evidenceDigest: Buffer;
        coseSign1: Buffer;
        assertionBindingDigest: Buffer;
      }>(
        `select challenge.mfa_challenge_id::text as "mfaChallengeId",
              evidence.evidence_cbor as "evidenceCbor",evidence.evidence_digest as "evidenceDigest",
              evidence.cose_sign1 as "coseSign1",
              evidence.webauthn_assertion_binding_digest as "assertionBindingDigest"
         from control.mfa_challenge challenge
         join control.mutation_evidence evidence
           on evidence.participant_id=challenge.participant_id
          and evidence.privacy_domain_id=$2 and evidence.principal_id=challenge.principal_id
          and evidence.mfa_challenge_id=challenge.mfa_challenge_id
          and evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
          and evidence.aggregate_type='webauthn-verification'
          and evidence.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
         join control.idempotency_record verification
           on verification.participant_id=evidence.participant_id
          and verification.operation_id=evidence.operation_id
          and verification.catalog_operation_id=evidence.catalog_operation_id
          and verification.terminal_state='COMMITTED'
          and verification.input_digest=evidence.candidate_digest
          and verification.webauthn_assertion_binding_digest=evidence.webauthn_assertion_binding_digest
        where challenge.participant_id=$1 and challenge.session_id=$3
          and challenge.principal_id=$4 and challenge.action_intent_id=$5
          and challenge.resource_digest=$6 and challenge.consumed_at is not null
          and challenge.consumed_at>=clock_timestamp()-interval '5 minutes'
          and challenge.expires_at>clock_timestamp()
          and (challenge.used_at is null or challenge.used_operation_id=$7)
          and evidence.bound_participant_epoch=$8 and evidence.bound_principal_epoch=$9
        order by challenge.consumed_at desc,challenge.mfa_challenge_id desc
        limit 2 for update of challenge`,
        [
          scope.participantId,
          scope.privacyDomainId,
          decisionAuthority.sessionId,
          scope.principalId,
          scope.actionIntentId,
          bytes(inputDigest),
          scope.operationId,
          decisionAuthority.participantEpoch,
          decisionAuthority.principalEpoch,
        ],
      );
      const stepUpRow = stepUp.rows[0];
      if (stepUp.rowCount !== 1 || stepUpRow === undefined)
        throw new ContractError('PC-POLICY-2004');
      const updated = await client.query<{ revision: string }>(
        `update control.policy_release_bundle set approval_request_id=$4,state='PUBLISHED',
              revision=revision+1,published_at=clock_timestamp(),updated_at=clock_timestamp()
        where participant_id=$1 and release_bundle_id=$2 and revision=$3 and state='DRAFT'
        returning revision::text as revision`,
        [scope.participantId, id, expectedRevision, approvedAuthority.approvalRequestId],
      );
      const row = updated.rows[0];
      if (updated.rowCount !== 1 || row === undefined) throw new ContractError('PC-POLICY-2002');
      const used = await client.query(
        `update control.mfa_challenge
          set used_at=clock_timestamp(),used_operation_id=$2,row_version=row_version+1
        where mfa_challenge_id=$1 and used_at is null`,
        [stepUpRow.mfaChallengeId, scope.operationId],
      );
      if (used.rowCount !== 1) throw new ContractError('PC-POLICY-2004');
      const sequence = await client.query<{ sequence: string }>(
        `insert into control.outbox_aggregate_head
         (participant_id,aggregate_type,aggregate_id,last_sequence)
       values($1,'policy-release-bundle',$2,1)
       on conflict (participant_id,aggregate_type,aggregate_id) do update
         set last_sequence=control.outbox_aggregate_head.last_sequence+1,
             updated_at=clock_timestamp()
       returning last_sequence::text as sequence`,
        [scope.participantId, id],
      );
      const sequenceRow = sequence.rows[0];
      if (sequence.rowCount !== 1 || sequenceRow === undefined)
        throw new ContractError('PC-POLICY-2005');
      await client.query(
        `insert into control.outbox_event
         (participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,
          aggregate_sequence,payload_cbor,payload_digest,cose_sign1,
          webauthn_assertion_binding_digest,occurred_at)
       values($1,$2,uuidv7(),'openpc.policy.release.created.v1','policy-release-bundle',
              $3,$4,$5,$6,$7,$8,clock_timestamp())`,
        [
          scope.participantId,
          scope.privacyDomainId,
          id,
          sequenceRow.sequence,
          stepUpRow.evidenceCbor,
          stepUpRow.evidenceDigest,
          stepUpRow.coseSign1,
          stepUpRow.assertionBindingDigest,
        ],
      );
      return completeOperation(client, scope, intent, id, row.revision);
    },
    async (client) => {
      const release = await releaseRow(client, scope, id);
      const selected = await client.query<{ approvalRequestId: string }>(
        `select request.approval_request_id::text as "approvalRequestId"
         from control.approval_request request
         join control.approval_decision_record decision on decision.participant_id=request.participant_id
          and decision.approval_request_id=request.approval_request_id and decision.decision='APPROVE'
          and decision.candidate_digest=request.subject_digest
        where request.participant_id=$1 and request.privacy_domain_id=$2
          and request.subject_type='POLICY_VERSION' and request.subject_id=$3
          and request.subject_digest=$4 and request.state='APPROVED'
          and request.expires_at>clock_timestamp()
          and request.maker_principal_id=$5 and decision.approver_principal_id=$6`,
        [
          scope.participantId,
          scope.privacyDomainId,
          release.policyVersionId,
          release.manifestDigest,
          release.createdByPrincipalId,
          scope.principalId,
        ],
      );
      const approved = selected.rows[0];
      if (selected.rowCount !== 1 || approved === undefined)
        throw new ContractError('PC-POLICY-2004');
      const approval = await approvalAuthorityDependencies(
        client,
        scope,
        approved.approvalRequestId,
        true,
      );
      const stepUp = await stepUpCredentialDependencies(
        client,
        scope,
        decisionAuthority.sessionId,
        bytes(inputDigest),
      );
      return {
        authorities: approval.authorities,
        rows: {
          credential: [...(approval.rows.credential ?? []), ...(stepUp.credential ?? [])],
        },
      };
    },
  );
}
