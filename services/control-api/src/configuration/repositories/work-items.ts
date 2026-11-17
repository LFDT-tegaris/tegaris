import {
  businessTransitionProfileForOperation,
  controlMutationForAction,
} from '@openpc/security-kernel';
import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';

import { sha256 } from '../digest.js';
import { type ListRequest, type PageResult, selectPage } from '../pagination.js';
import {
  claimWorkItemSchema,
  completeWorkItemSchema,
  createWorkItemSchema,
  updateWorkItemSchema,
} from '../resource-contracts.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import type { ConfigurationBusinessEvidence } from '../persistence/business-receipt-writer.js';
import {
  assertWorkItemBusinessTransition,
  bindWorkItemBusinessState,
  readWorkItemBusinessState,
  type WorkItemBusinessState,
  type WorkItemStateCommand,
} from '../persistence/business-state/work-item.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type MutationWriter,
  type OperationRecord,
} from '../persistence/types.js';

export type WorkItemKind = WorkItemBusinessState['kind'];

export interface WorkItemRecord {
  readonly workItemId: string;
  readonly participantId: string;
  readonly kind: WorkItemKind;
  readonly state: WorkItemBusinessState['state'];
  readonly assigneeRef: string | null;
  readonly resourceRef: string;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

interface WorkItemRow {
  readonly workItemId: string;
  readonly participantId: string;
  readonly kind: WorkItemKind;
  readonly state: WorkItemRecord['state'];
  readonly assigneePrincipalId: string | null;
  readonly resourceRef: string;
  readonly revision: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

const projection = `work_item_id::text as "workItemId",participant_id::text as "participantId",
  kind,state,assignee_principal_id::text as "assigneePrincipalId",resource_ref as "resourceRef",
  row_version::text as revision,created_at::text as "createdAt",updated_at::text as "updatedAt"`;

function timestamp(value: string): string {
  return new Date(value).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
}

function record(row: WorkItemRow): WorkItemRecord {
  return {
    workItemId: `urn:openpc:resource:${row.workItemId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
    kind: row.kind,
    state: row.state,
    assigneeRef:
      row.assigneePrincipalId === null ? null : `urn:openpc:resource:${row.assigneePrincipalId}`,
    resourceRef: row.resourceRef,
    revision: row.revision,
    createdAt: timestamp(row.createdAt),
    updatedAt: timestamp(row.updatedAt),
  };
}

function digestBytes(value: string): Buffer {
  return Buffer.from(value.slice('sha256:'.length), 'hex');
}

function expectedTransitionDigest(
  actionIntentId: string,
  workItemId: string,
  expectedRevision: string,
  transition: 'CLAIM' | 'COMPLETE',
): string {
  return sha256({
    actionIntentId,
    targetRef: `urn:openpc:resource:${workItemId}`,
    expectedRevision,
    transition,
  });
}

export class WorkItemRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(
    private readonly pool: Pool,
    identityRuntimeVerifier?: IdentityRuntimeVerifier,
    private readonly businessEvidence?: ConfigurationBusinessEvidence,
  ) {
    this.mutations = new AtomicConfigurationMutation(
      pool,
      identityRuntimeVerifier,
      businessEvidence,
    );
    this.reads = new ScopedConfigurationRead(pool);
  }

  private async execute(
    context: MutationContext,
    command: WorkItemStateCommand,
    write: MutationWriter<WorkItemRecord>,
  ): Promise<OperationRecord> {
    const operationId = `CFG-OP-${command.kind}-WORK-ITEM`;
    const operation = controlMutationForAction(context.actionIntentId, operationId);
    const profile = businessTransitionProfileForOperation(operationId);
    // P0 owns admission and construction. Never silently take AtomicConfigurationMutation's
    // legacy unsigned path when the work-item receipt capability/profile is absent.
    if (
      this.businessEvidence === undefined ||
      profile === undefined ||
      operation === undefined ||
      context.catalogOperationId !== operationId ||
      command.expectedRevision !== context.expectedRevision ||
      profile.aggregateType !== context.aggregateType ||
      profile.actionIntentId !== context.actionIntentId ||
      profile.resourceType !== context.resourceType ||
      operation.resourceType !== context.resourceType ||
      operation.operationClass !== context.operationClass ||
      context.aggregateType !== 'work-item'
    ) {
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    }
    const scope = {
      participantId: context.authorization.participantId,
      privacyDomainId: context.authorization.privacyDomainId,
      aggregateId: context.resourceId,
    };
    const binding = {
      ...scope,
      aggregateType: context.aggregateType,
      profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
    };
    return this.mutations.execute(
      context,
      async (client, resourceId, mutationOperationId, authority) => {
        const before = await readWorkItemBusinessState(client, scope);
        const written = await write(client, resourceId, mutationOperationId, authority);
        const after = await readWorkItemBusinessState(client, scope);
        assertWorkItemBusinessTransition(scope, command, before, after);
        return {
          ...written,
          businessState: {
            before: bindWorkItemBusinessState(binding, before),
            after: bindWorkItemBusinessState(binding, after),
          },
        };
      },
    );
  }

  async get(context: ReadContext): Promise<WorkItemRecord> {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<WorkItemRow>(
        `select ${projection} from control.work_item where work_item_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return record(selected.rows[0]!);
    });
  }

  async list(context: ReadContext, request: ListRequest): Promise<PageResult<WorkItemRecord>> {
    return this.reads.execute(context, async (client) => {
      return selectPage(client, request, {
        table: 'control.work_item',
        idColumn: 'work_item_id',
        projection,
        filterColumns: {
          state: 'state',
          kind: 'kind',
          assigneeRef: "'urn:openpc:resource:'||assignee_principal_id::text",
          resourceRef: 'resource_ref',
        },
        rowId: (row: WorkItemRow) => row.workItemId,
        rowUpdatedAt: (row: WorkItemRow) => row.updatedAt,
        map: record,
      });
    });
  }

  async create(
    context: MutationContext,
    input: {
      readonly kind: WorkItemKind;
      readonly assigneePrincipalId: string | null;
      readonly resourceRef: string;
      readonly reason: string;
    },
  ): Promise<OperationRecord> {
    const candidate = createWorkItemSchema.safeParse(context.candidate);
    if (
      !candidate.success ||
      candidate.data.actionIntentId !== context.actionIntentId ||
      candidate.data.actionIntentDigest !== context.actionIntentDigest ||
      candidate.data.participantId !==
        `urn:openpc:participant:${context.authorization.participantId}` ||
      candidate.data.kind !== input.kind ||
      candidate.data.resourceRef !== input.resourceRef ||
      candidate.data.reason !== input.reason ||
      (candidate.data.assigneeRef === null
        ? null
        : candidate.data.assigneeRef.split(':').at(-1)) !== input.assigneePrincipalId
    ) {
      throw new ConfigurationRepositoryError('PC-DATA-6007');
    }
    return this.execute(
      context,
      {
        kind: 'CREATE',
        actorPrincipalId: context.authorization.principalId,
        expectedRevision: '0',
        workItemKind: input.kind,
        assigneePrincipalId: input.assigneePrincipalId,
        resourceRef: input.resourceRef,
        payloadDigest: sha256(context.candidate),
        reasonDigest: sha256(Buffer.from(input.reason, 'utf8')),
      },
      async (client, workItemId) => {
        const inserted = await client.query<WorkItemRow>(
          `insert into control.work_item
           (work_item_id,participant_id,privacy_domain_id,kind,assignee_principal_id,
            resource_ref,payload_digest,reason,created_by_principal_id)
         select $1,$2,$3,$4,$5,$6,$7,$8,$9
          where $5::uuid is null or exists (
            select 1 from control.principal
             where participant_id=$2 and principal_id=$5 and state='ACTIVE'
          )
         returning ${projection}`,
          [
            workItemId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            input.kind,
            input.assigneePrincipalId,
            input.resourceRef,
            digestBytes(sha256(context.candidate)),
            input.reason,
            context.authorization.principalId,
          ],
        );
        if (inserted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const result = record(inserted.rows[0]!);
        return { result, revision: result.revision, outboxEventType: 'work-item.created.v1' };
      },
    );
  }

  async update(
    context: MutationContext,
    replacementDigest: string,
    reason: string,
  ): Promise<OperationRecord> {
    const candidate = updateWorkItemSchema.safeParse(context.candidate);
    if (
      !candidate.success ||
      candidate.data.actionIntentId !== context.actionIntentId ||
      candidate.data.actionIntentDigest !== context.actionIntentDigest ||
      candidate.data.expectedRevision !== context.expectedRevision ||
      candidate.data.replacementDigest !== replacementDigest ||
      candidate.data.reason !== reason
    ) {
      throw new ConfigurationRepositoryError('PC-DATA-6007');
    }
    return this.execute(
      context,
      {
        kind: 'UPDATE',
        actorPrincipalId: context.authorization.principalId,
        expectedRevision: context.expectedRevision,
        replacementDigest,
        reasonDigest: sha256(Buffer.from(reason, 'utf8')),
      },
      async (client) => {
        const changed = await client.query<WorkItemRow>(
          `update control.work_item
            set payload_digest=$1,reason=$2,row_version=row_version+1,updated_at=clock_timestamp()
          where work_item_id=$3 and row_version=$4 and state='OPEN'
            and payload_digest<>$1
          returning ${projection}`,
          [digestBytes(replacementDigest), reason, context.resourceId, context.expectedRevision],
        );
        if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const result = record(changed.rows[0]!);
        return { result, revision: result.revision, outboxEventType: 'work-item.updated.v1' };
      },
    );
  }

  async claim(context: MutationContext, inputDigest: string): Promise<OperationRecord> {
    const candidate = claimWorkItemSchema.safeParse(context.candidate);
    if (
      !candidate.success ||
      candidate.data.actionIntentId !== context.actionIntentId ||
      candidate.data.actionIntentDigest !== context.actionIntentDigest ||
      candidate.data.expectedRevision !== context.expectedRevision ||
      candidate.data.targetRef !== `urn:openpc:resource:${context.resourceId}` ||
      candidate.data.inputDigest !== inputDigest ||
      inputDigest !==
        expectedTransitionDigest(
          context.actionIntentId,
          context.resourceId,
          context.expectedRevision,
          'CLAIM',
        )
    ) {
      throw new ConfigurationRepositoryError('PC-DATA-6007');
    }
    return this.execute(
      context,
      {
        kind: 'CLAIM',
        actorPrincipalId: context.authorization.principalId,
        expectedRevision: context.expectedRevision,
      },
      async (client) => {
        const changed = await client.query<WorkItemRow>(
          `update control.work_item
            set state='CLAIMED',assignee_principal_id=coalesce(assignee_principal_id,$1),
                claimed_by_principal_id=$1,row_version=row_version+1,updated_at=clock_timestamp()
          where work_item_id=$2 and row_version=$3 and state='OPEN'
            and (assignee_principal_id is null or assignee_principal_id=$1)
          returning ${projection}`,
          [context.authorization.principalId, context.resourceId, context.expectedRevision],
        );
        if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const result = record(changed.rows[0]!);
        return { result, revision: result.revision, outboxEventType: 'work-item.claimed.v1' };
      },
    );
  }

  async complete(context: MutationContext, inputDigest: string): Promise<OperationRecord> {
    const candidate = completeWorkItemSchema.safeParse(context.candidate);
    if (
      !candidate.success ||
      candidate.data.actionIntentId !== context.actionIntentId ||
      candidate.data.actionIntentDigest !== context.actionIntentDigest ||
      candidate.data.expectedRevision !== context.expectedRevision ||
      candidate.data.targetRef !== `urn:openpc:resource:${context.resourceId}` ||
      candidate.data.inputDigest !== inputDigest ||
      inputDigest !==
        expectedTransitionDigest(
          context.actionIntentId,
          context.resourceId,
          context.expectedRevision,
          'COMPLETE',
        )
    ) {
      throw new ConfigurationRepositoryError('PC-DATA-6007');
    }
    return this.execute(
      context,
      {
        kind: 'COMPLETE',
        actorPrincipalId: context.authorization.principalId,
        expectedRevision: context.expectedRevision,
      },
      async (client) => {
        const changed = await client.query<WorkItemRow>(
          `update control.work_item
            set state='COMPLETED',completed_by_principal_id=$1,
                row_version=row_version+1,updated_at=clock_timestamp()
          where work_item_id=$2 and row_version=$3 and state='CLAIMED'
            and assignee_principal_id=$1 and claimed_by_principal_id=$1
          returning ${projection}`,
          [context.authorization.principalId, context.resourceId, context.expectedRevision],
        );
        if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const result = record(changed.rows[0]!);
        return { result, revision: result.revision, outboxEventType: 'work-item.completed.v1' };
      },
    );
  }
}
