import { currentPlatformEnvelopeSql } from './current-platform-envelope.js';

type PolicyAuthoritySqlParameters = readonly [
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
  string,
];

/** Only owning query builders supply SQL expressions. Caller values remain
 * PostgreSQL parameters; no request field is substituted as SQL. */
export function bindPolicyAuthoritySelectionSql(parameters: PolicyAuthoritySqlParameters): string {
  return policyAuthoritySelectionSql.replace(
    /\$(\d+)/gu,
    (_, index: string) => parameters[Number(index) - 1]!,
  );
}

/** Shared live authority selector. Parameters are server-owned, never caller SQL.
 * The lateral envelope lookup evaluates its existing guards only after the
 * assignment selects that exact envelope. OFFSET 0 preserves this boundary. */
export const policyAuthoritySelectionSql = `with recursive authority_chain as (
           select assignment.assignment_id,null::uuid current_delegation_id,
                  assignment.principal_id terminal_principal_id,
                  assignment.delegation_epoch current_delegation_epoch,
                  assignment.onward_delegation_depth remaining_depth,0 depth,
                  upper(assignment.valid_during) authority_valid_until
             from control.assignment assignment
            where assignment.participant_id=$1 and assignment.state='ACTIVE'
              -- A different terminal principal needs at least one permitted hop.
              -- Zero-depth foreign roots can never reach the final caller predicate.
              and (assignment.principal_id=$5 or assignment.onward_delegation_depth>0)
              and assignment.valid_during @> clock_timestamp()
              and $3=any(assignment.action_intent_ids)
              and openpc.assignment_role_permits(assignment.participant_id,assignment.role_id,$3)
              and openpc.assignment_group_permits(assignment.participant_id,assignment.authority_group_id,assignment.principal_id,assignment.valid_during)
              and $2::text=any(assignment.privacy_domain_ids)
              and openpc.administration_resource_permits(assignment.resource_ids,$4,$3,$1,$5,$6,assignment.authority_envelope_id)
              and ($10::text is null or (assignment.maker_checker_required
                and $10=any(assignment.action_intent_ids)
                and openpc.assignment_role_permits(assignment.participant_id,assignment.role_id,$10)
                and ($11=any(assignment.resource_ids) or '*'=any(assignment.resource_ids))))
           union all
           select chain.assignment_id,delegation.delegation_id,
                  delegation.delegate_principal_id,delegation.delegation_epoch,
                  delegation.onward_delegation_depth,chain.depth+1,
                  least(chain.authority_valid_until,upper(delegation.valid_during))
             from authority_chain chain
             join control.delegation delegation on delegation.participant_id=$1
              and ((chain.current_delegation_id is null
                    and delegation.parent_assignment_id=chain.assignment_id)
                or delegation.parent_delegation_id=chain.current_delegation_id)
              and delegation.grantor_principal_id=chain.terminal_principal_id
              and delegation.state='ACTIVE'
              and delegation.valid_during @> clock_timestamp()
              and $3=any(delegation.action_intent_ids)
              and $2::text=any(delegation.privacy_domain_ids)
              and ($4=any(delegation.resource_ids) or '*'=any(delegation.resource_ids))
              and ($10::text is null or ($10=any(delegation.action_intent_ids)
                and ($11=any(delegation.resource_ids) or '*'=any(delegation.resource_ids))))
              and delegation.onward_delegation_depth<chain.remaining_depth
            where chain.remaining_depth>0 and chain.depth<32
         )
         select session.session_id::text "sessionId",participant.participant_id::text "participantId",
                principal.principal_id::text "principalId",
                session.session_epoch::text "sessionEpoch",session.issued_at "sessionIssuedAt",
                session.idle_expires_at "sessionIdleExpiresAt",
                session.absolute_expires_at "sessionAbsoluteExpiresAt",
                participant.authority_epoch::text "participantEpoch",
                principal.authority_epoch::text "principalEpoch",
                assignment.assignment_id::text "assignmentId",
                assignment.role_id "roleId",
                assignment.row_version::text "assignmentRowVersion",
                envelope.authority_envelope_id::text "authorityEnvelopeId",
                envelope.authority_epoch::text "authorityEpoch",
                chain.current_delegation_epoch::text "delegationEpoch",
                least(chain.authority_valid_until,envelope.valid_until,mapping.fresh_until,
                  mapping.observed_at+make_interval(secs=>connector.external_group_freshness_seconds)) "authorityValidUntil"
           from authority_chain chain
           join control.assignment assignment on assignment.participant_id=$1
            and assignment.assignment_id=chain.assignment_id
           left join control.directory_group_mapping mapping on mapping.participant_id=$1
            and mapping.authority_group_id=assignment.authority_group_id
           left join control.directory_connector connector on connector.participant_id=$1
            and connector.connector_id=mapping.connector_id
           join lateral (select * from control.authority_envelope envelope where envelope.participant_id=$1
            and envelope.authority_envelope_id=assignment.authority_envelope_id
            and envelope.state='ACTIVE' and ${currentPlatformEnvelopeSql('envelope', false, true)}
            and envelope.valid_from<=clock_timestamp()
            and (envelope.valid_until is null or envelope.valid_until>clock_timestamp())
            and $3=any(envelope.action_intent_ids)
            and $2::text=any(envelope.privacy_domain_ids)
            and openpc.administration_resource_permits(envelope.resource_ids,$4,$3,$1,$5,$6,envelope.authority_envelope_id)
            and ($10::text is null or (envelope.maker_checker_required
              and (envelope.principal_id=$5 or (envelope.representation='TYPED_V1' and envelope.principal_id is null))
              and assignment.principal_id=$5
              and $10=any(envelope.action_intent_ids)
              and ($11=any(envelope.resource_ids) or '*'=any(envelope.resource_ids))))
           offset 0) envelope on true
           join control.participant participant on participant.participant_id=$1
            and participant.state='ACTIVE'
           join control.principal principal on principal.participant_id=$1
            and principal.principal_id=$5 and principal.state='ACTIVE'
           join control.session session on session.participant_id=$1
            and session.session_id=$6 and session.principal_id=$5 and session.state='ACTIVE'
            and ((session.context_mode='PARTICIPANT' and session.privacy_domain_id=$2::uuid)
              or ($8 and session.context_mode='PLATFORM' and session.privacy_domain_id is null
                and participant.root_privacy_domain_id=$2::uuid)
              or ($9 and session.context_mode='PLATFORM' and session.privacy_domain_id is null
                and participant.root_privacy_domain_id=$2::uuid and principal.kind='PLATFORM_OPERATOR'
                and chain.depth=0 and assignment.principal_id=principal.principal_id))
            and session.authority_epoch=principal.authority_epoch
            and session.participant_epoch=participant.authority_epoch
            and session.delegation_epoch=chain.current_delegation_epoch
            and session.idle_expires_at>clock_timestamp()
            and session.absolute_expires_at>clock_timestamp()
          where chain.terminal_principal_id=$5
            and (not $7 or case when session.step_up_mfa_challenge_id is null
              then session.step_up_verified_at>=clock_timestamp()-interval '5 minutes'
              else openpc.session_step_up_valid_until(session.participant_id,session.session_id,session.principal_id)>clock_timestamp()
              end)`;
