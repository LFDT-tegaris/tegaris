import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import { AtomicConfigurationMutation } from '../configuration/persistence/atomic-mutation.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import { selectPage, type ListRequest } from '../configuration/pagination.js';
import type { ResourceApiOptions } from '../configuration/governed-mutation-http.js';
import {
  createEvidenceHold,
  encodeEvidenceHoldSelector,
  evidenceHoldView,
} from './hold-contracts.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { bindHoldTransition, readHoldBusinessState } from './hold-business-state.js';

type HoldRow = z.infer<typeof evidenceHoldView>;
async function requireHoldGovernanceScope(client: PoolClient, context: MutationContext) {
  if (
    context.catalogOperationId !== 'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD' &&
    context.catalogOperationId !== 'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD'
  )
    return;
  const root = await client.query(
    `select 1 from control.participant where participant_id=$1 and root_privacy_domain_id=$2`,
    [context.authorization.participantId, context.authorization.privacyDomainId],
  );
  if (root.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
}
const projection = `retention_hold_id::text as "holdId",participant_id::text as "participantId",
 hold_kind as "holdKind",selector,selector_digest as "selectorDigest",state,revision::text,
 privacy_domain_id::text as "governancePrivacyDomainId",
 current_setting('openpc.privacy_domain_id') as "coveragePrivacyDomainId",
 creation_operation_id::text as "creationOperationId",release_operation_id::text as "releaseOperationId",
 creation_receipt_digest as "creationReceiptDigest",release_receipt_digest as "releaseReceiptDigest",
 to_char(effective_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "effectiveAt",
 to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "createdAt",
 to_char(updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "updatedAt",coverage`;
// Every matching version must have an acknowledgement for the current revision.
// No sink or a not-yet-archived match is pending, never vacuously verified.
// Remote coverage requires a signed exact-version observation for the complete
// current rule set; a transport observation alone remains PENDING.
const source = `(select h.*,
 (select 'sha256:'||encode(a.receipt_digest,'hex') from control.audit_occurrence a
   where a.participant_id=h.participant_id and a.privacy_domain_id=h.privacy_domain_id
    and a.operation_id=h.creation_operation_id and a.aggregate_type='evidence-hold'
    and a.aggregate_id=h.retention_hold_id and a.profile_id in ('pc.control.evidence-hold.create','pc.control.evidence-participant-hold.create')) creation_receipt_digest,
 (select 'sha256:'||encode(a.receipt_digest,'hex') from control.audit_occurrence a
   where a.participant_id=h.participant_id and a.privacy_domain_id=h.privacy_domain_id
    and a.operation_id=h.release_operation_id and a.aggregate_type='evidence-hold'
    and a.aggregate_id=h.retention_hold_id and a.profile_id in ('pc.control.evidence-hold.release','pc.control.evidence-participant-hold.release')) release_receipt_digest,
 case when exists(select 1 from control.evidence_segment s
   where s.participant_id=h.participant_id and s.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
    and (h.state='ACTIVE' or s.admitted_at<=h.updated_at)
    and openpc.evidence_hold_match_state(h.selector,s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id)='UNKNOWN') then 'UNAVAILABLE'
  when not exists(select 1 from control.evidence_checkpoint p
   where p.participant_id=h.participant_id and p.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid)
  or exists(select 1 from control.store_retirement_admission a
    left join control.store_retirement_outcome o using(participant_id,privacy_domain_id,attempt_id)
    cross join lateral jsonb_array_elements(a.source_binding->'manifest') item
   where a.participant_id=h.participant_id and a.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
    and o.attempt_id is null
    and openpc.evidence_hold_requires_coverage(h,item->>'streamId',(item->>'segmentId')::uuid))
  or exists(select 1 from control.evidence_remote_archive_intent i where i.participant_id=h.participant_id
    and (h.selector_type='PARTICIPANT' or i.privacy_domain_id=h.privacy_domain_id) and i.source_kind='PROTECTED_PROOF'
    and (openpc.protected_remote_archive_rules(i.participant_id,i.privacy_domain_id,i.protected_object_id,i.sink_id) is null
      or exists(select 1 from jsonb_array_elements(openpc.protected_remote_archive_rules(i.participant_id,i.privacy_domain_id,i.protected_object_id,i.sink_id)) rule
        where rule->>'holdId'=h.retention_hold_id::text))
    and not openpc.protected_remote_archive_covers(i.participant_id,i.privacy_domain_id,i.protected_object_id,i.sink_id))
  or exists(select 1 from control.evidence_remote_archive_intent i join control.evidence_segment s
    using(participant_id,privacy_domain_id,stream_id,segment_id)
   where i.participant_id=h.participant_id and i.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
    and openpc.evidence_hold_requires_coverage(h,i.stream_id,i.segment_id)
    and not openpc.remote_archive_covers(s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id,i.sink_id))
  or exists(select 1 from control.evidence_segment s
   where s.participant_id=h.participant_id and s.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid
    and openpc.evidence_hold_requires_coverage(h,s.stream_id,s.segment_id)
    and (not exists(select 1 from control.evidence_checkpoint p where p.participant_id=s.participant_id
      and p.privacy_domain_id=s.privacy_domain_id and p.stream_id=s.stream_id and p.segment_id=s.segment_id)
     or exists(select 1 from control.evidence_checkpoint p where p.participant_id=s.participant_id
      and p.privacy_domain_id=s.privacy_domain_id and p.stream_id=s.stream_id and p.segment_id=s.segment_id
      and not (p.receipt->>'kind' is not distinct from 'SIGNED_REMOTE_ARCHIVE_V1' and openpc.remote_archive_covers(s.participant_id,s.privacy_domain_id,s.stream_id,s.segment_id,p.sink_id))
      and not exists(select 1 from control.evidence_hold_coverage c where c.participant_id=h.participant_id
       and c.privacy_domain_id=s.privacy_domain_id and c.retention_hold_id=h.retention_hold_id
       and c.hold_revision=h.revision and c.sink_id=p.sink_id and c.segment_id=s.segment_id
       and c.object_digest=s.object_digest)))) then 'PENDING' else 'VERIFIED' end coverage
 from control.retention_hold h where h.participant_id=current_setting('openpc.participant_id')::uuid
 and (h.selector_type='PARTICIPANT' or h.privacy_domain_id=current_setting('openpc.privacy_domain_id')::uuid)) holds`;
function view(row: HoldRow) {
  return evidenceHoldView.parse({
    ...row,
    holdId: `urn:openpc:resource:${row.holdId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
  });
}
export class EvidenceHoldRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(
    pool: Pool,
    options: Pick<ResourceApiOptions, 'identityRuntimeVerifier' | 'businessEvidence'> = {},
  ) {
    this.mutations = new AtomicConfigurationMutation(
      pool,
      options.identityRuntimeVerifier,
      options.businessEvidence,
      requireHoldGovernanceScope,
    );
    this.reads = new ScopedConfigurationRead(pool);
  }
  create(context: MutationContext, input: z.infer<typeof createEvidenceHold>) {
    const scope = context.authorization;
    const bound = encodeEvidenceHoldSelector(scope, input.selector);
    return this.mutations.execute(context, async (client, holdId, operationId) => {
      await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
      const before = await readHoldBusinessState(client, context);
      await client.query(
        `insert into control.retention_hold(retention_hold_id,participant_id,privacy_domain_id,
       hold_kind,selector_type,selector,selector_cbor,selector_digest,approval_request_id,creation_operation_id)
       values($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10)`,
        [
          holdId,
          scope.participantId,
          scope.privacyDomainId,
          input.holdKind,
          bound.selector.type,
          JSON.stringify(bound.selector),
          bound.bytes,
          bound.digest,
          scope.approvalRequestId,
          operationId,
        ],
      );
      return {
        result: undefined,
        revision: '1',
        businessState: bindHoldTransition(
          context,
          operationId,
          before,
          await readHoldBusinessState(client, context),
        ),
        outboxEventType: 'openpc.evidence.hold.created.v1',
      };
    });
  }
  release(context: MutationContext) {
    const scope = context.authorization;
    return this.mutations.execute(context, async (client, holdId, operationId) => {
      await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
      const before = await readHoldBusinessState(client, context);
      const changed = await client.query(
        `update control.retention_hold set state='RELEASED',revision=2,
       release_operation_id=$4,release_approval_request_id=$5 where participant_id=$1 and privacy_domain_id=$2
       and retention_hold_id=$3 and state='ACTIVE' and revision=$6 returning retention_hold_id`,
        [
          scope.participantId,
          scope.privacyDomainId,
          holdId,
          operationId,
          scope.approvalRequestId,
          context.expectedRevision,
        ],
      );
      if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
      return {
        result: undefined,
        revision: '2',
        businessState: bindHoldTransition(
          context,
          operationId,
          before,
          await readHoldBusinessState(client, context),
        ),
        outboxEventType: 'openpc.evidence.hold.released.v1',
      };
    });
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<HoldRow>(
        `select ${projection} from ${source} where retention_hold_id=$1`,
        [context.resourceId],
      );
      if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      return view(result.rows[0]!);
    });
  }
  list(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: source,
        idColumn: 'retention_hold_id',
        projection,
        filterColumns: { state: 'state', holdKind: 'hold_kind' },
        rowId: (row: HoldRow) => row.holdId,
        rowUpdatedAt: (row: HoldRow) => row.updatedAt,
        map: view,
      }),
    );
  }
}
