import { deploymentRejectionSourceSql } from './rejection-source.mjs';

/** Control command completion before any target handoff. This shares the
 * existing immutable result owner and grants no deployment or chain authority. */
export const deploymentRejectionGuardsSql = `
${deploymentRejectionSourceSql}
CREATE OR REPLACE FUNCTION openpc.lock_deployment_command(command_id uuid)
RETURNS void LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT pg_advisory_xact_lock(hashtextextended('openpc:deployment-command:'||command_id::text,0))
$$;
REVOKE ALL ON FUNCTION openpc.lock_deployment_command(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.lock_deployment_command(uuid) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.validate_deployment_rejection(result control.deployment_result)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE claims jsonb; expected jsonb; issued_at timestamptz; expires_at timestamptz;
BEGIN
 PERFORM openpc.assert_request_context(true);
 PERFORM openpc.lock_deployment_command(result.command_id);
 claims:=convert_from(result.signed_bytes,'UTF8')::jsonb->'claims';
 IF NOT openpc.matches_participant(result.participant_id) OR NOT openpc.matches_privacy(result.privacy_domain_id)
  OR result.sequence<>1 OR claims->>'schema' IS DISTINCT FROM 'PC-DEPLOYMENT-RESERVATION-REJECTION-1'
  OR NOT coalesce(claims->>'reason' IN ('CUSTODY_CONFLICT','PREPARATION_EXPIRED','MODULE_GENERATION_UNAVAILABLE'),false)
  OR NOT coalesce(claims->'binding'->>'transactionHash' ~ '^0x[0-9a-f]{64}$',false)
  OR EXISTS(SELECT 1 FROM control.deployment_address_reservation WHERE command_id=result.command_id)
  OR EXISTS(SELECT 1 FROM control.deployment_result prior WHERE prior.command_id=result.command_id)
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 IF claims->>'reason'='MODULE_GENERATION_UNAVAILABLE' THEN
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('module-admission:'||result.participant_id::text||':'||result.privacy_domain_id::text,0));
  IF EXISTS(SELECT 1 FROM control.deployment_intent i WHERE i.participant_id=result.participant_id
   AND i.privacy_domain_id=result.privacy_domain_id
   AND i.preparation_digest='sha256:'||(claims->'binding'->>'preparationDigest')
   AND i.module_generation_digest IS NOT NULL
   AND i.module_generation_digest=openpc.deployment_module_generation(i.participant_id,i.privacy_domain_id))
  THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 END IF;
 SELECT jsonb_build_object(
   'targetRuntimeId',intent.runtime_target_id::text,
   'owner',jsonb_build_object('participant_id',candidate.participant_id::text,
     'privacy_domain_id',candidate.privacy_domain_id::text,'actor_principal_id',intent.execution_principal_id::text,
     'workload_id',intent.execution_workload_id),
   'commandId',candidate.consumed_operation_id::text,'attemptId',candidate.resource_id::text,
   'intentDigest',substring(intent.intent_digest from 8),'preparationDigest',substring(intent.preparation_digest from 8),
   'chainId',prepared.document->'intent'->>'chainId','genesisDigest',prepared.document->'intent'->>'genesisHash',
   'transactionHash',claims->'binding'->>'transactionHash'),candidate.created_at,intent.expires_at
 INTO STRICT expected,issued_at,expires_at
 FROM control.mutation_candidate candidate
 JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id
  AND receipt.privacy_domain_id=candidate.privacy_domain_id AND receipt.operation_id=candidate.consumed_operation_id
  AND receipt.catalog_operation_id=candidate.catalog_operation_id AND receipt.input_digest=candidate.candidate_digest
  AND receipt.principal_id=candidate.maker_principal_id AND receipt.terminal_state='COMMITTED'
 JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id
  AND evidence.privacy_domain_id=candidate.privacy_domain_id AND evidence.operation_id=candidate.consumed_operation_id
  AND evidence.catalog_operation_id=candidate.catalog_operation_id AND evidence.candidate_digest=candidate.candidate_digest
  AND evidence.aggregate_id=candidate.resource_id AND evidence.aggregate_type='deployment-submission'
 JOIN control.deployment_intent intent ON intent.participant_id=candidate.participant_id
  AND intent.privacy_domain_id=candidate.privacy_domain_id AND intent.actor_principal_id=candidate.maker_principal_id
  AND candidate.candidate_document->>'deploymentIntentId'='urn:openpc:resource:'||intent.deployment_intent_id::text
 CROSS JOIN LATERAL (SELECT convert_from(intent.preparation_bytes,'UTF8')::jsonb document) prepared
 WHERE candidate.participant_id=result.participant_id AND candidate.privacy_domain_id=result.privacy_domain_id
  AND candidate.consumed_operation_id=result.command_id AND candidate.state='CONSUMED'
  AND candidate.catalog_operation_id='CFG-OP-SUBMIT-DEPLOYMENT'
  AND candidate.action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND candidate.resource_type='deployment-submission' AND candidate.operation_class='CREATE'
  AND encode(candidate.candidate_digest,'hex')=claims->>'candidateDigest'
  AND encode(evidence.evidence_digest,'hex')=claims->>'authorizationEvidenceDigest';
 IF claims->'binding' IS DISTINCT FROM expected OR claims->>'observedAt' IS NULL
  OR (claims->>'observedAt')::timestamptz<issued_at
  OR (claims->>'observedAt')::timestamptz>clock_timestamp()+interval '5 seconds'
  OR (claims->>'reason'='PREPARATION_EXPIRED' AND
    (expires_at>clock_timestamp() OR (claims->>'observedAt')::timestamptz<expires_at))
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.validate_deployment_rejection(control.deployment_result) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.validate_deployment_rejection(control.deployment_result) TO openpc_control_worker;
`;
