import { validateCiglGrant } from './grant-core.js';
import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../../identity-service/src/domain/identity-runtime-crypto.js';
import { AtomicConfigurationMutation } from '../persistence/atomic-mutation.js';
import { selectPage, type ListRequest } from '../pagination.js';
import { ScopedConfigurationRead, type ReadContext } from '../persistence/scoped-read.js';
import { ConfigurationRepositoryError, type MutationContext } from '../persistence/types.js';
import {
  ciglGrantDefinitionSchema,
  ciglGrantResponseSchema,
  type CiglGrantDefinition,
} from './grant-contract.js';
import type { CiglDependencyBundle } from './dependency-contract.js';
import {
  materializeCiglDependencies,
  reconcileGeneratedCiglGrants,
  readCiglDependencies,
} from './dependency-repository.js';

interface GrantRow {
  grantId: string;
  definition: CiglGrantDefinition;
  origin: 'SHARED' | 'GENERATED';
  generatedByGrantId: string | null;
  runtimeBindingRevision: string;
  methodRevision: string;
  status: 'ACTIVE' | 'DISABLED';
  revision: string;
  grantDigest: string;
  publicationOperationId: string;
  publicationAuthorityDigest: string;
  createdAt: Date;
  updatedAt: Date;
}
const projection = `grant_id::text as "grantId",definition,origin,generated_by_grant_id::text as "generatedByGrantId",binding_revision::text as "runtimeBindingRevision",method_revision::text as "methodRevision",
 status,revision::text,grant_digest as "grantDigest",
 publication_operation_id::text as "publicationOperationId",publication_authority_digest as "publicationAuthorityDigest",
 created_at as "createdAt",updated_at as "updatedAt"`;

function grantFailure(error: unknown): never {
  // A reference rejection aborts the transaction before any durable effect. Do
  // not disclose which subject, tenant or method reference was unavailable.
  if (
    error instanceof Error &&
    'code' in error &&
    error.code === 'P0001' &&
    error.message === 'PC-AUTH-0005-CIGL-GRANT-REFERENCE'
  )
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  throw error;
}

function record(row: GrantRow) {
  const definition = ciglGrantDefinitionSchema.parse(row.definition);
  if (validateCiglGrant(row.grantId, definition, row.status).grantDigest !== row.grantDigest)
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  return ciglGrantResponseSchema.parse({
    ...row,
    definition,
    grantId: `urn:openpc:resource:${row.grantId}`,
    generatedByGrantId:
      row.generatedByGrantId === null ? null : `urn:openpc:resource:${row.generatedByGrantId}`,
    runtimePermission: 'NONE_WITHOUT_CURRENT_PROFILE',
    createdAt: new Date(row.createdAt).toISOString(),
    updatedAt: new Date(row.updatedAt).toISOString(),
  });
}

export class CiglGrantRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(pool: Pool, verifier?: IdentityRuntimeVerifier) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }
  list(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table: 'control.cigl_method_access_grants',
        idColumn: 'grant_id',
        projection,
        filterColumns: {
          status: 'status',
          runtimeBindingId: "definition->>'runtimeBindingId'",
          selector: 'selector',
          effect: "definition->>'effect'",
        },
        rowId: (row: GrantRow) => row.grantId,
        rowUpdatedAt: (row: GrantRow) => new Date(row.updatedAt).toISOString(),
        map: record,
      }),
    );
  }
  dependencies(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) => readCiglDependencies(client, request));
  }
  create(
    context: MutationContext,
    input: {
      definition: CiglGrantDefinition;
      expectedRuntimeBindingRevision: string;
      expectedMethodRevision: string;
    },
  ) {
    const definition = ciglGrantDefinitionSchema.parse(input.definition);
    return this.mutations
      .execute(context, async (client, grantId, operationId) => {
        await client.query('select openpc.lock_cigl_grant_sources()');
        const validated = validateCiglGrant(grantId, definition, 'DISABLED');
        await client.query(
          `insert into control.cigl_method_access_grants(grant_id,participant_id,privacy_domain_id,
        runtime_binding_id,selector,binding_revision,method_revision,definition,status,grant_digest,publication_operation_id,publication_authority_digest)
        values($1,$2,$3,$4,$5,$6,$7,$8::jsonb,'DISABLED',$9,$10,$11)`,
          [
            grantId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            definition.runtimeBindingId.slice('urn:openpc:resource:'.length),
            definition.selector,
            input.expectedRuntimeBindingRevision,
            input.expectedMethodRevision,
            JSON.stringify(definition),
            validated.grantDigest,
            operationId,
            `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
          ],
        );
        return {
          result: undefined,
          revision: '1',
          outboxEventType: 'openpc.cigl.grant.created.v1',
        };
      })
      .catch(grantFailure);
  }
  change(
    context: MutationContext,
    input: {
      expectedRevision: string;
      status: 'ACTIVE' | 'DISABLED';
      dependencyBundle?: CiglDependencyBundle;
    },
  ) {
    return this.mutations
      .execute(context, async (client, grantId, operationId) => {
        await client.query('select openpc.lock_cigl_grant_sources()');
        const result = await client.query<GrantRow>(
          `select ${projection} from control.cigl_method_access_grants
        where grant_id=$1 and participant_id=$2 and privacy_domain_id=$3 for update`,
          [grantId, context.authorization.participantId, context.authorization.privacyDomainId],
        );
        const row = result.rows[0];
        if (result.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-AUTH-0005');
        if (row.origin !== 'SHARED') throw new ConfigurationRepositoryError('PC-AUTH-0005');
        if (
          row.revision !== input.expectedRevision ||
          (row.status === input.status && input.dependencyBundle === undefined)
        )
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        const validated = validateCiglGrant(
          grantId,
          ciglGrantDefinitionSchema.parse(row.definition),
          input.status,
        );
        const changed = await client.query<{ revision: string }>(
          `update control.cigl_method_access_grants
        set status=$2,revision=revision+1,grant_digest=$3,publication_operation_id=$4,publication_authority_digest=$5
        where grant_id=$1 returning revision::text`,
          [
            grantId,
            input.status,
            validated.grantDigest,
            operationId,
            `sha256:${context.authorization.evidenceDigest.toString('hex')}`,
          ],
        );
        if (input.dependencyBundle !== undefined) {
          if (input.status !== 'ACTIVE') throw new ConfigurationRepositoryError('PC-DATA-6004');
          await materializeCiglDependencies(
            client,
            context,
            grantId,
            operationId,
            input.dependencyBundle,
          );
        }
        await reconcileGeneratedCiglGrants(client, context, operationId);
        return {
          result: undefined,
          revision: changed.rows[0]!.revision,
          outboxEventType: 'openpc.cigl.grant.status.v1',
        };
      })
      .catch(grantFailure);
  }
  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const result = await client.query<GrantRow>(
        `select ${projection} from control.cigl_method_access_grants
        where grant_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
        [
          context.resourceId,
          context.authorization.participantId,
          context.authorization.privacyDomainId,
        ],
      );
      const row = result.rows[0];
      if (result.rowCount !== 1 || !row) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      return record(row);
    });
  }
}
