import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import { selectPage, type ListRequest } from '../pagination.js';
import {
  runtimeTargetProfileBindingResponseSchema,
  type CreateRuntimeTargetProfileBinding,
} from './contract.js';
import { runtimeTargetProfileBindingDigest } from './digest.js';

interface BindingRow {
  bindingId: string;
  participantId: string;
  privacyDomainId: string;
  runtimeTargetId: string;
  targetProfileId: string;
  bindingDigest: string;
  publicationOperationId: string;
  createdAt: Date;
}
const projection = `binding_id::text as "bindingId",participant_id::text as "participantId",
 privacy_domain_id::text as "privacyDomainId",runtime_target_id::text as "runtimeTargetId",
 target_profile_id as "targetProfileId",binding_digest as "bindingDigest",
 publication_operation_id::text as "publicationOperationId",created_at as "createdAt"`;

function bindingFailure(error: unknown): never {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    if (
      error.code === '23505' &&
      'constraint' in error &&
      ['runtime_profile_target_uq', 'runtime_profile_name_uq'].includes(String(error.constraint))
    )
      throw new ConfigurationRepositoryError('PC-DATA-6007');
    if (error.code === 'P0001' && 'message' in error) {
      if (error.message === 'PC-DATA-6007-RUNTIME-PROFILE-TARGET')
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      if (
        ['PC-AUTH-0005-RUNTIME-PROFILE-OWNER', 'PC-AUTH-0005-RUNTIME-PROFILE-PROVENANCE'].includes(
          String(error.message),
        )
      )
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
    }
  }
  throw error;
}

function record(row: BindingRow) {
  if (
    row.bindingDigest !==
    runtimeTargetProfileBindingDigest({
      participantId: row.participantId,
      privacyDomainId: row.privacyDomainId,
      targetRuntimeId: row.runtimeTargetId,
      targetProfileId: row.targetProfileId,
    })
  )
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  return runtimeTargetProfileBindingResponseSchema.parse({
    bindingRef: `urn:openpc:resource:${row.bindingId}`,
    targetRef: `urn:openpc:resource:${row.runtimeTargetId}`,
    targetProfileId: row.targetProfileId,
    bindingDigest: row.bindingDigest,
    publicationOperationRef: `urn:openpc:resource:${row.publicationOperationId}`,
    revision: '1',
    runtimePermission: 'NONE_WITHOUT_MATCHING_ENVELOPE',
    createdAt: new Date(row.createdAt).toISOString(),
  });
}

export class RuntimeTargetProfileBindingRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(pool: Pool, verifier?: IdentityRuntimeVerifier) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  create(context: MutationContext, input: CreateRuntimeTargetProfileBinding) {
    const runtimeTargetId = input.runtimeTargetRef.slice('urn:openpc:resource:'.length);
    const bindingDigest = runtimeTargetProfileBindingDigest({
      participantId: context.authorization.participantId,
      privacyDomainId: context.authorization.privacyDomainId,
      targetRuntimeId: runtimeTargetId,
      targetProfileId: input.targetProfileId,
    });
    return this.mutations
      .execute(context, async (client, bindingId, operationId) => {
        const target = await client.query(
          `select runtime_target_id from control.runtime_target
         where participant_id=$1 and privacy_domain_id=$2 and runtime_target_id=$3
           and revision=$4 and state in ('OFFLINE','DISCOVERED')
           and active_generation_digest is null and desired_generation_digest is null for share`,
          [
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            runtimeTargetId,
            input.targetRevision,
          ],
        );
        if (target.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const inserted = await client.query<BindingRow>(
          `insert into control.runtime_target_profile_binding
         (binding_id,participant_id,privacy_domain_id,runtime_target_id,target_revision,target_profile_id,
          binding_digest,publication_operation_id,publication_authority_digest)
         values($1,$2,$3,$4,$5,$6,$7,$8,$9) returning ${projection}`,
          [
            bindingId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            runtimeTargetId,
            input.targetRevision,
            input.targetProfileId,
            bindingDigest,
            operationId,
            `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
          ],
        );
        if (inserted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        return {
          result: record(inserted.rows[0]!),
          revision: '1',
          outboxEventType: 'openpc.runtime-target.profile-bound.v1',
        };
      })
      .catch(bindingFailure);
  }

  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const rows = await client.query<BindingRow>(
        `select ${projection} from control.runtime_target_profile_binding where binding_id=$1`,
        [context.resourceId],
      );
      if (rows.rowCount !== 1) throw new ConfigurationRepositoryError('PC-FACT-4001');
      return record(rows.rows[0]!);
    });
  }

  list(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: 'control.runtime_target_profile_binding',
        idColumn: 'binding_id',
        projection,
        filterColumns: {
          targetProfileId: 'target_profile_id',
          targetId: 'runtime_target_id::text',
        },
        rowId: (row: BindingRow) => row.bindingId,
        rowUpdatedAt: (row: BindingRow) => new Date(row.createdAt).toISOString(),
        map: record,
      }),
    );
  }
}
