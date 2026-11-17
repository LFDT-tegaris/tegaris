-- Shared immutable rejection source: signed command completion, never absence alone.
select result.signed_bytes,result.result_digest,result.created_at::text,
      intent.preparation_bytes,intent.publication_bytes,candidate.candidate_document->>'signedTransaction' signed_transaction,
      encode(candidate.candidate_digest,'hex') candidate_digest,encode(evidence.evidence_digest,'hex') evidence_digest,
      candidate.resource_id::text attempt_id,intent.actor_principal_id::text
     from control.deployment_result result
     join control.mutation_candidate candidate on candidate.participant_id=result.participant_id
      and candidate.privacy_domain_id=result.privacy_domain_id and candidate.consumed_operation_id=result.command_id
      and candidate.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT' and candidate.state='CONSUMED'
      and candidate.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
      and candidate.resource_type='deployment-submission' and candidate.operation_class='CREATE'
     join control.idempotency_record receipt on receipt.participant_id=candidate.participant_id
      and receipt.privacy_domain_id=candidate.privacy_domain_id and receipt.operation_id=candidate.consumed_operation_id
      and receipt.catalog_operation_id=candidate.catalog_operation_id and receipt.input_digest=candidate.candidate_digest
      and receipt.principal_id=candidate.maker_principal_id and receipt.terminal_state='COMMITTED'
     join control.mutation_evidence evidence on evidence.participant_id=candidate.participant_id
      and evidence.privacy_domain_id=candidate.privacy_domain_id and evidence.operation_id=candidate.consumed_operation_id
      and evidence.catalog_operation_id=candidate.catalog_operation_id and evidence.candidate_digest=candidate.candidate_digest
      and evidence.aggregate_id=candidate.resource_id and evidence.aggregate_type='deployment-submission'
     join control.deployment_intent intent on intent.participant_id=candidate.participant_id
      and intent.privacy_domain_id=candidate.privacy_domain_id and intent.actor_principal_id=candidate.maker_principal_id
      and candidate.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||intent.deployment_intent_id::text
     where result.command_id=$1 and result.participant_id=$2 and result.privacy_domain_id=$3 and result.sequence=1
      and not exists(select 1 from control.deployment_address_reservation reservation where reservation.command_id=result.command_id)
