-- Shared immutable input lookup for the worker consumer and management readback.
select r.command_id::text, r.attempt_id::text, i.deployment_intent_id::text, i.runtime_target_id::text target_runtime_id, r.chain_id,
 substring(r.genesis_digest from 8) genesis_digest, r.transaction_hash,
 substring(r.intent_digest from 8) intent_digest,
 substring(r.prepared_record_digest from 8) preparation_digest,
 i.preparation_bytes, i.publication_bytes, i.execution_principal_id::text,
 i.execution_workload_id, i.actor_principal_id::text,
 latest.sequence::text, latest.signed_bytes, latest.result_digest,
 latest.created_at::text result_created_at, successor.command_id::text successor_command_id,
 association.document_bytes association_bytes, association.activation_sequence::text,
 association.current_sequence::text association_sequence, association.participant_epoch::text,
 activation.signed_bytes activation_bytes,
 (association.state='ACTIVE' and participant.state='ACTIVE' and participant.archived_at is null
  and participant.authority_epoch=association.participant_epoch) association_current
from control.deployment_address_reservation r
join control.participant participant on participant.participant_id=r.participant_id
join control.deployment_intent i on i.participant_id=r.participant_id and i.privacy_domain_id=r.privacy_domain_id
 and i.preparation_digest=r.prepared_record_digest and i.intent_digest=r.intent_digest
 and r.target_runtime_id='urn:openpc:resource:'||i.runtime_target_id::text
join control.idempotency_record operation on operation.participant_id=r.participant_id
 and operation.privacy_domain_id=r.privacy_domain_id and operation.operation_id=r.command_id
 and operation.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT' and operation.terminal_state='COMMITTED'
join control.mutation_candidate candidate on candidate.participant_id=r.participant_id and candidate.privacy_domain_id=r.privacy_domain_id
 and candidate.consumed_operation_id=r.command_id and candidate.resource_id=r.attempt_id and candidate.state='CONSUMED'
 and candidate.catalog_operation_id=operation.catalog_operation_id and candidate.candidate_digest=operation.input_digest
 and candidate.maker_principal_id=i.actor_principal_id
 and candidate.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||i.deployment_intent_id::text
left join lateral (select result.sequence,result.signed_bytes,result.result_digest,result.created_at
 from control.deployment_result result where result.command_id=r.command_id
 and result.participant_id=r.participant_id and result.privacy_domain_id=r.privacy_domain_id order by result.sequence desc limit 1) latest on true
left join control.contract_governance_association association on association.command_id=r.command_id
 and association.participant_id=r.participant_id and association.privacy_domain_id=r.privacy_domain_id
left join control.deployment_result activation on activation.command_id=r.command_id and activation.sequence=association.activation_sequence
 and activation.participant_id=r.participant_id and activation.privacy_domain_id=r.privacy_domain_id
left join control.deployment_address_reservation successor on successor.predecessor_command_id=r.command_id
 and successor.participant_id=r.participant_id and successor.privacy_domain_id=r.privacy_domain_id
where r.command_id=$1::text::uuid and r.participant_id=$2::text::uuid and r.privacy_domain_id=$3::text::uuid and r.state='HANDOFF'
