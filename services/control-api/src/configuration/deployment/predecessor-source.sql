-- HANDOFF custody and preparation bytes are immutable. The worker owns
-- atomic successor allocation; the API must not acquire worker UPDATE rights.
select intent.preparation_bytes as "preparationBytes"
from control.deployment_address_reservation reservation
join control.mutation_candidate original on original.consumed_operation_id=reservation.command_id
and original.participant_id=reservation.participant_id and original.privacy_domain_id=reservation.privacy_domain_id
and original.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT' and original.state='CONSUMED'
and original.maker_principal_id=$3
join control.deployment_intent intent on intent.participant_id=reservation.participant_id
and intent.privacy_domain_id=reservation.privacy_domain_id and intent.preparation_digest=reservation.prepared_record_digest
and 'urn:openpc:resource:'||intent.deployment_intent_id::text=original.candidate_document->>'deploymentIntentId'
where reservation.participant_id=$1 and reservation.privacy_domain_id=$2 and reservation.command_id=$4
and reservation.state='HANDOFF' and reservation.predecessor_command_id is null
and not exists(select 1 from control.deployment_address_reservation child where child.predecessor_command_id=reservation.command_id)
