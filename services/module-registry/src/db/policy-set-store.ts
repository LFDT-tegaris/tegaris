import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import { AtomicConfigurationMutation } from '../../../control-api/src/configuration/persistence/atomic-mutation.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../../../control-api/src/configuration/persistence/scoped-read.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../../../control-api/src/configuration/persistence/types.js';
import { selectPage, type ListRequest } from '../../../control-api/src/configuration/pagination.js';
import type { PolicySetView } from '../policy-set-contract.js';

interface Row {
  policySetId: string;
  participantId: string;
  name: string;
  state: PolicySetView['state'];
  activeDigests: string[];
  revision: string;
  createdAt: string;
  updatedAt: string;
}

// Read actual active generations. Neither a draft nor a merely published
// version establishes an active version. Ambiguous scope digests fail closed.
const table = `(select p.*,
  case when p.state='RETIRED' then 'RETIRED'
       when cardinality(active.digests)>0 then 'ACTIVE' else 'DRAFT' end public_state,
  active.digests active_digests
  from control.policy p cross join lateral (
    select array(select distinct 'sha256:'||encode(v.semantic_digest,'hex')
      from control.policy_generation g join control.policy_version v
        on (v.participant_id,v.privacy_domain_id,v.policy_version_id)=
           (g.participant_id,g.privacy_domain_id,g.policy_version_id)
      where (v.participant_id,v.privacy_domain_id,v.policy_id)=
            (p.participant_id,p.privacy_domain_id,p.policy_id)
        and g.active and g.state='ACTIVE') digests
  ) active) policy_sets`;
const projection = `policy_id::text as "policySetId",participant_id::text as "participantId",
  policy_name as name,public_state as state,active_digests as "activeDigests",
  row_version::text as revision,created_at::text as "createdAt",updated_at::text as "updatedAt"`;

function view(row: Row): PolicySetView {
  if (row.activeDigests.length > 1 || (row.state === 'RETIRED' && row.activeDigests.length > 0))
    throw new ConfigurationRepositoryError('PC-DATA-6001');
  return {
    policySetId: `urn:openpc:policy-set:${row.policySetId}`,
    participantId: `urn:openpc:participant:${row.participantId}`,
    name: row.name,
    state: row.state,
    activeVersionDigest: row.activeDigests[0] ?? null,
    revision: row.revision,
    createdAt: new Date(row.createdAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
    updatedAt: new Date(row.updatedAt).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
  };
}

export class PolicySetRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;

  constructor(pool: Pool, verifier?: IdentityRuntimeVerifier) {
    this.mutations = new AtomicConfigurationMutation(pool, verifier);
    this.reads = new ScopedConfigurationRead(pool);
  }

  async create(
    context: MutationContext,
    input: { name: string; activeVersionDigest: string | null },
  ) {
    if (input.activeVersionDigest !== null) throw new ConfigurationRepositoryError('PC-DATA-6001');
    try {
      return await this.mutations.execute(context, async (client, resourceId) => {
        const inserted = await client.query<{ revision: string }>(
          `insert into control.policy(policy_id,participant_id,privacy_domain_id,policy_name)
           values($1,$2,$3,$4) returning row_version::text as revision`,
          [
            resourceId,
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            input.name,
          ],
        );
        if (inserted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        return {
          result: resourceId,
          revision: inserted.rows[0]!.revision,
          outboxEventType: 'policy-set.created.v1',
        };
      });
    } catch (error) {
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === '23505')
        throw new ConfigurationRepositoryError('PC-DATA-6001');
      throw error;
    }
  }

  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<Row>(
        `select ${projection} from ${table} where policy_id=$1`,
        [context.resourceId],
      );
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
      return view(selected.rows[0]!);
    });
  }

  list(context: ReadContext, request: ListRequest) {
    return this.reads.execute(context, (client) =>
      selectPage(client, request, {
        table,
        visibilityAlias: 'policy_sets',
        idColumn: 'policy_id',
        projection,
        filterColumns: { state: 'public_state', name: 'policy_name' },
        rowId: (row: Row) => row.policySetId,
        rowUpdatedAt: (row: Row) => row.updatedAt,
        map: view,
      }),
    );
  }
}
