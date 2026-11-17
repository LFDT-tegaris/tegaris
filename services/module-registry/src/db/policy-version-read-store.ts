import type { Pool } from 'pg';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../../../control-api/src/configuration/persistence/scoped-read.js';
import { ConfigurationRepositoryError } from '../../../control-api/src/configuration/persistence/types.js';
import { selectPage, type ListRequest } from '../../../control-api/src/configuration/pagination.js';
import { ContractError } from '../domain/errors.js';
import { policyVersionResponseSchema, type PolicyVersionView } from '../policy-version-contract.js';

interface Row {
  policyVersionId: string;
  policySetId: string;
  semanticVersion: string;
  normalizedPolicyDigest: string;
  dependencyClosureDigest: string | null;
  createdAt: string;
  updatedAt: string;
}

// Missing artifact metadata must fail the read, rather than disappear from a
// supposedly complete collection. Version records remain immutable drafts;
// release and activation evidence belongs to the respective public owners.
const table = `(select v.*,v.created_at as updated_at,
  'urn:openpc:policy-set:'||v.policy_id::text as policy_set_ref,
  a.dependency_closure_digest,'DRAFT'::text as public_state
  from control.policy_version v left join control.policy_artifact a
    on (a.participant_id,a.privacy_domain_id,a.policy_id,a.semantic_version,a.semantic_digest)=
       (v.participant_id,v.privacy_domain_id,v.policy_id,v.version,v.semantic_digest)) policy_versions`;
const projection = `policy_version_id::text as "policyVersionId",policy_id::text as "policySetId",
  version as "semanticVersion",'sha256:'||encode(semantic_digest,'hex') as "normalizedPolicyDigest",
  'sha256:'||encode(dependency_closure_digest,'hex') as "dependencyClosureDigest",
  to_char(created_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "createdAt",
  to_char(updated_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "updatedAt"`;

function view(row: Row): PolicyVersionView {
  const parsed = policyVersionResponseSchema.safeParse({
    ...row,
    policyVersionId: `urn:openpc:policy-version:${row.policyVersionId}`,
    policySetId: `urn:openpc:policy-set:${row.policySetId}`,
    state: 'DRAFT',
    revision: '1',
  });
  if (!parsed.success) throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
  return parsed.data;
}

export class PolicyVersionReadRepository {
  private readonly reads: ScopedConfigurationRead;
  constructor(pool: Pool) {
    this.reads = new ScopedConfigurationRead(pool);
  }

  get(context: ReadContext) {
    return this.reads.execute(context, async (client) => {
      const selected = await client.query<Row>(
        `select ${projection} from ${table} where participant_id=$1 and privacy_domain_id=$2 and policy_version_id=$3`,
        [
          context.authorization.participantId,
          context.authorization.privacyDomainId,
          context.resourceId,
        ],
      );
      if (selected.rowCount === 0) throw new ContractError('PC-POLICY-2001');
      if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
      return view(selected.rows[0]!);
    });
  }

  list(context: ReadContext, request: ListRequest) {
    const actor = context.authorization;
    return this.reads.execute(context, (client) =>
      selectPage(
        client,
        {
          ...request,
          visibility: {
            participantId: actor.participantId,
            privacyDomainId: actor.privacyDomainId,
            principalId: actor.principalId,
            sessionId: actor.sessionId,
            actionIntentId: 'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
          },
        },
        {
          table,
          visibilityAlias: 'policy_versions',
          idColumn: 'policy_version_id',
          projection,
          filterColumns: {
            policySetId: 'policy_set_ref',
            semanticVersion: 'version',
            state: 'public_state',
          },
          rowId: (row: Row) => row.policyVersionId,
          rowUpdatedAt: (row: Row) => row.updatedAt,
          map: view,
        },
      ),
    );
  }
}
