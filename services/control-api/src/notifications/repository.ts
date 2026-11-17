import {
  businessTransitionProfileForOperation,
  controlMutationForAction,
} from '@openpc/security-kernel';
import type { Pool } from 'pg';
import type { Notification } from '../../../../generated/typescript/openapi/types.gen.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import { sha256 } from '../configuration/digest.js';
import { selectPage, type ListRequest, type PageResult } from '../configuration/pagination.js';
import { AtomicConfigurationMutation } from '../configuration/persistence/atomic-mutation.js';
import type { ConfigurationBusinessEvidence } from '../configuration/persistence/business-receipt-writer.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type MutationWriter,
  type OperationRecord,
} from '../configuration/persistence/types.js';
import {
  assertNotificationAcknowledgement,
  assertNotificationCreate,
  bindNotificationBusinessState,
  readNotificationBusinessState,
  type NotificationBusinessState,
  type NotificationStateScope,
} from './business-state.js';
import { acknowledgeNotificationSchema, createNotificationSchema } from './contracts.js';

export type NotificationRecord = Notification;

// SQL rows retain UUIDs until the public projection below. Keep PostgreSQL's
// actual microseconds for readback and pagination rather than truncating via Date.
const projection = `notification_id::text as "notificationId",participant_id::text as "participantId",
  severity,state,resource_ref as "resourceRef",message_key as "messageKey",revision::text,
  to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "createdAt",
  to_char(updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "updatedAt"`;

function record(row: Notification): NotificationRecord {
  return {
    notificationId: `urn:openpc:resource:${row.notificationId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
    severity: row.severity,
    state: row.state,
    resourceRef: row.resourceRef,
    messageKey: row.messageKey,
    revision: row.revision,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export class NotificationRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(
    pool: Pool,
    private readonly identityRuntimeVerifier?: IdentityRuntimeVerifier,
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
    operationId: 'CFG-OP-CREATE-NOTIFICATION' | 'CFG-OP-ACKNOWLEDGE-NOTIFICATION',
    assertTransition: (
      scope: NotificationStateScope,
      before: NotificationBusinessState | undefined,
      after: NotificationBusinessState | undefined,
    ) => void,
    write: MutationWriter<NotificationRecord>,
  ): Promise<OperationRecord> {
    const operation = controlMutationForAction(context.actionIntentId, operationId);
    const profile = businessTransitionProfileForOperation(operationId);
    // Never fall through to the shared owner's legacy unsigned mutation path.
    if (
      this.identityRuntimeVerifier === undefined ||
      this.businessEvidence === undefined ||
      operation === undefined ||
      profile === undefined ||
      context.catalogOperationId !== operationId ||
      context.aggregateType !== 'notification' ||
      profile.aggregateType !== context.aggregateType ||
      profile.actionIntentId !== context.actionIntentId ||
      profile.resourceType !== context.resourceType ||
      operation.resourceType !== context.resourceType ||
      operation.operationClass !== context.operationClass
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');

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
        const before = await readNotificationBusinessState(client, scope);
        const written = await write(client, resourceId, mutationOperationId, authority);
        const after = await readNotificationBusinessState(client, scope);
        assertTransition(scope, before, after);
        return {
          ...written,
          businessState: {
            before: bindNotificationBusinessState(binding, before),
            after: bindNotificationBusinessState(binding, after),
          },
        };
      },
    );
  }

  async create(
    context: MutationContext,
    input: {
      readonly severity: Notification['severity'];
      readonly resourceRef: string | null;
      readonly messageKey: string;
      readonly reason: string;
    },
  ): Promise<OperationRecord> {
    const candidate = createNotificationSchema.safeParse(context.candidate);
    if (
      !candidate.success ||
      context.expectedRevision !== '0' ||
      candidate.data.actionIntentId !== context.actionIntentId ||
      candidate.data.actionIntentDigest !== context.actionIntentDigest ||
      candidate.data.participantId !==
        `urn:openpc:participant:${context.authorization.participantId}` ||
      candidate.data.severity !== input.severity ||
      candidate.data.resourceRef !== input.resourceRef ||
      candidate.data.messageKey !== input.messageKey ||
      candidate.data.reason !== input.reason
    )
      throw new ConfigurationRepositoryError('PC-DATA-6007');

    const candidateDigest = sha256(context.candidate);
    return this.execute(
      context,
      'CFG-OP-CREATE-NOTIFICATION',
      (scope, before, after) =>
        assertNotificationCreate(scope, before, after, { ...input, candidateDigest }),
      async (client, notificationId) => {
        const inserted = await client.query<Notification>(
          `insert into control.notification
            (notification_id,participant_id,privacy_domain_id,severity,state,resource_ref,message_key,candidate_digest,revision)
           values ($1,$2,$3,$4,'UNREAD',$5,$6,$7,1)
           returning ${projection}`,
          [
            notificationId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            input.severity,
            input.resourceRef,
            input.messageKey,
            candidateDigest,
          ],
        );
        if (inserted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const result = record(inserted.rows[0]!);
        return {
          result,
          revision: result.revision,
          outboxEventType: 'io.openpc.control.command.committed.v1',
        };
      },
    );
  }

  async acknowledge(context: MutationContext, inputDigest: string): Promise<OperationRecord> {
    const candidate = acknowledgeNotificationSchema.safeParse(context.candidate);
    if (
      !candidate.success ||
      candidate.data.actionIntentId !== context.actionIntentId ||
      candidate.data.actionIntentDigest !== context.actionIntentDigest ||
      candidate.data.targetRef !== `urn:openpc:resource:${context.resourceId}` ||
      candidate.data.expectedRevision !== context.expectedRevision ||
      candidate.data.inputDigest !== inputDigest ||
      inputDigest !==
        sha256({
          actionIntentId: context.actionIntentId,
          targetRef: `urn:openpc:resource:${context.resourceId}`,
          expectedRevision: context.expectedRevision,
          transition: 'ACKNOWLEDGE',
        })
    )
      throw new ConfigurationRepositoryError('PC-DATA-6007');

    // The authenticated candidate binds inputDigest. The original creation
    // candidate digest stays in the row; this command never replaces it.
    return this.execute(
      context,
      'CFG-OP-ACKNOWLEDGE-NOTIFICATION',
      (scope, before, after) =>
        assertNotificationAcknowledgement(scope, before, after, context.expectedRevision),
      async (client, notificationId) => {
        const changed = await client.query<Notification>(
          `update control.notification
              set state='ACKNOWLEDGED',revision=revision+1,updated_at=clock_timestamp()
            where notification_id=$1 and participant_id=$2 and privacy_domain_id=$3
              and revision=$4 and state in ('UNREAD','READ')
            returning ${projection}`,
          [
            notificationId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            context.expectedRevision,
          ],
        );
        if (changed.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const result = record(changed.rows[0]!);
        return {
          result,
          revision: result.revision,
          outboxEventType: 'io.openpc.control.command.committed.v1',
        };
      },
    );
  }

  async get(context: ReadContext): Promise<NotificationRecord> {
    if (
      context.actionIntentId !== 'ACT-NOTIFICATIONS_READ_RESOURCE-V1' ||
      context.resourceType !== 'notifications'
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<Notification>(
        `select ${projection} from control.notification
          where notification_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
        [
          context.resourceId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
        ],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return record(selected.rows[0]!);
    });
  }

  async list(context: ReadContext, request: ListRequest): Promise<PageResult<NotificationRecord>> {
    if (
      context.actionIntentId !== 'ACT-NOTIFICATIONS_READ_COLLECTION-V1' ||
      context.resourceType !== 'notifications' ||
      context.resourceId !== '*'
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    // Shared read admission requires the collection grant before counting;
    // FORCE RLS applies the same participant/privacy scope to count and rows.
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: 'control.notification',
        idColumn: 'notification_id',
        projection,
        filterColumns: {
          state: 'state',
          severity: 'severity',
          resourceRef: 'resource_ref',
          messageKey: 'message_key',
        },
        rowId: (row: Notification) => row.notificationId,
        rowUpdatedAt: (row: Notification) => row.updatedAt,
        map: record,
      }),
    );
  }
}
