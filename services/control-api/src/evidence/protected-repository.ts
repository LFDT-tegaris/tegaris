import type { Pool, PoolClient } from 'pg';
import type { z } from 'zod';
import { AtomicConfigurationMutation } from '../configuration/persistence/atomic-mutation.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import type { ResourceApiOptions } from '../configuration/governed-mutation-http.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { selectPage, type ListRequest } from '../configuration/pagination.js';
import {
  consumeProtectedAccess,
  protectedAccessView,
  protectedDisclosure,
  protectedObjectView,
  requestProtectedAccess,
  retainProtectedProof,
} from './protected-contracts.js';
import { decryptProtectedProof, encryptProtectedProof } from './protected-crypto.js';
import { readProtectedProofSource, requireExactProofSource } from './protected-source.js';

const timestamp = (column: string) =>
  `to_char(${column} at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
const objectProjection = `jsonb_build_object('objectRef','urn:openpc:resource:'||object_id::text,
 'objectVersion',object_version::text,'objectDigest',object_digest,'source',source,
 'participantId','urn:openpc:participant:'||participant_id::text,'privacyDomainId',privacy_domain_id::text,
 'purpose',purpose,'caseReference',case_reference,'retainUntil',${timestamp('retain_until')},
 'creationOperationId',creation_operation_id::text,'createdAt',${timestamp('created_at')},
 'updatedAt',${timestamp('created_at')},'revision','1') document`;
const accessProjection = `jsonb_build_object('accessRef','urn:openpc:resource:'||access_id::text,
 'participantId','urn:openpc:participant:'||participant_id::text,'privacyDomainId',privacy_domain_id::text,
 'object',object_binding,'purpose',purpose,'caseReference',case_reference,'recipientPrincipalId',recipient_principal_id::text,
 'expiresAt',${timestamp('expires_at')},'state',case when consumed_at is not null then 'CONSUMED'
 when expires_at<=clock_timestamp() then 'EXPIRED' else 'AVAILABLE' end,
 'creationOperationId',creation_operation_id::text,'consumptionOperationId',consumption_operation_id::text,
 'revision',revision::text,'createdAt',${timestamp('created_at')},'updatedAt',${timestamp('updated_at')}) document`;
async function object(client: PoolClient, objectId: string) {
  const result = await client.query<{ document: unknown }>(
    `select ${objectProjection} from control.protected_proof_object where object_id=$1`,
    [objectId],
  );
  if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
  return protectedObjectView.parse(result.rows[0]!.document);
}
function exactObject(
  expected: z.infer<typeof requestProtectedAccess>['object'],
  actual: z.infer<typeof protectedObjectView>,
) {
  const { objectRef, objectVersion, objectDigest, source } = actual;
  if (canonicalJson(expected) !== canonicalJson({ objectRef, objectVersion, objectDigest, source }))
    throw new ConfigurationRepositoryError('PC-DATA-6007');
}
export class ProtectedProofRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(
    pool: Pool,
    private readonly options: Pick<
      ResourceApiOptions,
      'identityRuntimeVerifier' | 'businessEvidence' | 'protectedProofKeys'
    >,
  ) {
    this.mutations = new AtomicConfigurationMutation(
      pool,
      options.identityRuntimeVerifier,
      options.businessEvidence,
    );
    this.reads = new ScopedConfigurationRead(pool);
  }
  source(context: ReadContext) {
    return this.reads.execute(
      context,
      async (client) =>
        (
          await readProtectedProofSource(
            client,
            context.authorization,
            `urn:openpc:resource:${context.resourceId}`,
            this.options.identityRuntimeVerifier,
          )
        ).source,
    );
  }
  retain(context: MutationContext, input: z.infer<typeof retainProtectedProof>) {
    if (!this.options.protectedProofKeys) throw new ConfigurationRepositoryError('PC-OPS-9002');
    const keys = this.options.protectedProofKeys,
      scope = context.authorization;
    return this.mutations.execute(context, async (client, objectId, operationId) => {
      const retained = await readProtectedProofSource(
        client,
        scope,
        input.source.evidenceId,
        this.options.identityRuntimeVerifier,
      );
      requireExactProofSource(input.source, retained.source);
      const plaintext = Buffer.from(canonicalJson(retained.disclosure));
      const objectDigest = sha256(plaintext);
      let encrypted;
      try {
        encrypted = encryptProtectedProof(
          keys,
          {
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            objectRef: `urn:openpc:resource:${objectId}`,
            objectVersion: '1',
            objectDigest,
            source: retained.source,
          },
          plaintext,
        );
      } finally {
        plaintext.fill(0);
      }
      await client.query(
        `insert into control.protected_proof_object(object_id,participant_id,privacy_domain_id,
        source,object_digest,purpose,case_reference,retain_until,approval_request_id,creation_operation_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [
          objectId,
          scope.participantId,
          scope.privacyDomainId,
          retained.source,
          objectDigest,
          input.purpose,
          input.caseReference,
          input.retainUntil,
          scope.approvalRequestId,
          operationId,
        ],
      );
      await client.query(
        `insert into control.protected_proof_payload(object_id,participant_id,privacy_domain_id,key_id,nonce,ciphertext)
        values($1,$2,$3,$4,$5,$6)`,
        [
          objectId,
          scope.participantId,
          scope.privacyDomainId,
          encrypted.keyId,
          encrypted.nonce,
          encrypted.ciphertext,
        ],
      );
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'openpc.evidence.protected.retained.v1',
      };
    });
  }
  request(context: MutationContext, input: z.infer<typeof requestProtectedAccess>) {
    const scope = context.authorization;
    return this.mutations.execute(context, async (client, accessId, operationId) => {
      if (input.recipientPrincipalId !== scope.principalId || !scope.sessionId)
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      exactObject(input.object, await object(client, input.object.objectRef.slice(-36)));
      await client.query(
        `insert into control.protected_proof_access(access_id,participant_id,privacy_domain_id,object_id,
        object_binding,purpose,case_reference,recipient_principal_id,sender_session_id,expires_at,approval_request_id,creation_operation_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [
          accessId,
          scope.participantId,
          scope.privacyDomainId,
          input.object.objectRef.slice(-36),
          input.object,
          input.purpose,
          input.caseReference,
          scope.principalId,
          scope.sessionId,
          input.expiresAt,
          scope.approvalRequestId,
          operationId,
        ],
      );
      return {
        result: undefined,
        revision: '1',
        outboxEventType: 'openpc.evidence.protected.access-requested.v1',
      };
    });
  }
  async consume(context: MutationContext, input: z.infer<typeof consumeProtectedAccess>) {
    const keys = this.options.protectedProofKeys,
      scope = context.authorization;
    if (!keys) throw new ConfigurationRepositoryError('PC-OPS-9002');
    let disclosure: z.infer<typeof protectedDisclosure> | null = null;
    let deliveryOperation: string | undefined;
    const operation = await this.mutations.execute(
      context,
      async (client, accessId, operationId) => {
        // Reset per attempt: a serialization abort can never leave releasable bytes.
        disclosure = null;
        deliveryOperation = undefined;
        const access = await client.query(
          `select a.*,${timestamp('a.expires_at')} as exact_expiry from control.protected_proof_access a
        join control.protected_proof_object o on o.object_id=a.object_id and o.participant_id=a.participant_id
          and o.privacy_domain_id=a.privacy_domain_id and o.retain_until>clock_timestamp()
        join control.mutation_evidence e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id
          and e.operation_id=a.creation_operation_id and e.bound_participant_epoch=$4 and e.bound_principal_epoch=$5
          and e.bound_authority_envelope_id=$6 and e.bound_envelope_epoch=$7 and e.bound_assignment_id=$8
        where a.access_id=$1 and a.recipient_principal_id=$2 and a.sender_session_id=$3
          and a.consumed_at is null and a.expires_at>clock_timestamp() and a.revision=1 for update of a`,
          [
            accessId,
            scope.principalId,
            scope.sessionId,
            scope.participantEpoch,
            scope.principalEpoch,
            scope.authorityEnvelopeId,
            scope.authorityEpoch,
            scope.assignmentId,
          ],
        );
        if (access.rowCount !== 1 || input.recipientPrincipalId !== scope.principalId)
          throw new ConfigurationRepositoryError('PC-AUTH-0005');
        const a = access.rows[0]!;
        if (
          canonicalJson(a.object_binding) !== canonicalJson(input.object) ||
          a.purpose !== input.purpose ||
          a.case_reference !== input.caseReference ||
          a.exact_expiry !== input.expiresAt
        )
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        exactObject(input.object, await object(client, a.object_id));
        const stored = await client.query<{ keyId: string; nonce: Buffer; ciphertext: Buffer }>(
          `select key_id as "keyId",nonce,ciphertext from control.protected_proof_payload where object_id=$1`,
          [a.object_id],
        );
        if (stored.rowCount !== 1) throw new ConfigurationRepositoryError('PC-OPS-9002');
        const value = decryptProtectedProof(
          keys,
          {
            ...input.object,
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
          },
          stored.rows[0]!,
        );
        await client.query(
          `update control.protected_proof_access set consumption_operation_id=$2,
        consumed_at=clock_timestamp(),revision=2,updated_at=clock_timestamp(),consumption_request=$3 where access_id=$1`,
          [accessId, operationId, input],
        );
        disclosure = value;
        deliveryOperation = operationId;
        return {
          result: undefined,
          revision: '2',
          outboxEventType: 'openpc.evidence.protected.consumed.v1',
        };
      },
    );
    return {
      operation,
      disclosure:
        operation.state === 'SUCCEEDED' && operation.operationId === deliveryOperation
          ? disclosure
          : null,
    };
  }
  getObject(context: ReadContext) {
    return this.reads.execute(context, (client) => object(client, context.resourceId));
  }
  getAccess(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<{ document: unknown }>(
        `select ${accessProjection} from control.protected_proof_access where access_id=$1`,
        [context.resourceId],
      );
      if (result.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      return protectedAccessView.parse(result.rows[0]!.document);
    });
  }
  list(context: ReadContext, request: ListRequest, access: boolean) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: access ? 'control.protected_proof_access' : 'control.protected_proof_object',
        idColumn: access ? 'access_id' : 'object_id',
        projection: access ? accessProjection : objectProjection,
        filterColumns: {},
        rowId: (row: { document: Record<string, string> }) =>
          row.document[access ? 'accessRef' : 'objectRef']!.slice(-36),
        rowUpdatedAt: (row) => row.document.updatedAt!,
        map: (row) =>
          access
            ? protectedAccessView.parse(row.document)
            : protectedObjectView.parse(row.document),
      }),
    );
  }
}
