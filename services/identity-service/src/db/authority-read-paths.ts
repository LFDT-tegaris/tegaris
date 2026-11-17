import type { PoolClient } from 'pg';
import { currentPlatformEnvelopeSql } from './current-platform-envelope.js';

export interface AuthorityPath {
  readonly resource_id: string;
  readonly assignment_id: string;
  readonly delegation_path: string[];
}

/** Candidate discovery only. Every returned path still requires full evaluation and a live read fence. */
export function authorityReadPaths(
  client: PoolClient,
  participantId: string,
  principalId: string,
  privacyDomainId: string,
  actionIntentId: string,
  resourceIds: readonly string[],
  riskClass: string,
) {
  return client.query<AuthorityPath>(
    `with recursive targets as (select unnest($5::text[]) resource_id), authority_chain as (
           select target.resource_id,a.assignment_id,null::uuid current_delegation_id,array[]::uuid[] delegation_path,
                  a.principal_id terminal_principal_id,0 depth
             from targets target cross join control.assignment a
             join control.authority_envelope e on e.participant_id=a.participant_id
              and e.authority_envelope_id=a.authority_envelope_id and e.state='ACTIVE'
              and ${currentPlatformEnvelopeSql('e', false, true)}
              and e.valid_from<=clock_timestamp()
              and (e.valid_until is null or e.valid_until>clock_timestamp())
              and $3=any(e.privacy_domain_ids) and $4=any(e.action_intent_ids)
              and openpc.administration_resource_permits(e.resource_ids,target.resource_id,$4,$1,$2,null,e.authority_envelope_id)
              and $6=any(e.risk_classes)
            where a.participant_id=$1 and a.state='ACTIVE' and a.valid_during @> clock_timestamp()
              and $3=any(a.privacy_domain_ids) and $4=any(a.action_intent_ids)
              and openpc.administration_resource_permits(a.resource_ids,target.resource_id,$4,$1,$2,null,a.authority_envelope_id)
              and $6=any(a.risk_classes)
           union all
           select c.resource_id,c.assignment_id,d.delegation_id,c.delegation_path||d.delegation_id,
                  d.delegate_principal_id,c.depth+1
             from authority_chain c
             join control.delegation d on d.participant_id=$1
              and ((c.current_delegation_id is null and d.parent_assignment_id=c.assignment_id)
                or d.parent_delegation_id=c.current_delegation_id)
              and d.grantor_principal_id=c.terminal_principal_id
              and d.state='ACTIVE' and d.valid_during @> clock_timestamp()
              and $3=any(d.privacy_domain_ids) and $4=any(d.action_intent_ids)
              and (c.resource_id=any(d.resource_ids) or '*'=any(d.resource_ids))
              and $6=any(d.risk_classes)
            where c.depth < 32
         )
         select resource_id,assignment_id,delegation_path from authority_chain
          where terminal_principal_id=$2 order by cardinality(delegation_path) desc`,
    [participantId, principalId, privacyDomainId, actionIntentId, resourceIds, riskClass],
  );
}
