/** Participant Governance owns initial controller generation and suspension.
 * The Control adapter supplies verified signed facts; neither caller-provided
 * association documents nor direct runtime-role writes can create authority. */
export const deploymentAssociationGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES('ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1','deployment-submission','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','REDACTED','DEPLOYMENT_RESULT_READ') ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.action_intent WHERE action_intent_id='ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1'
  AND resource_type='deployment-submission' AND operation_class='READ' AND risk_class='STANDARD'
  AND NOT maker_checker_required AND NOT step_up_required AND NOT idempotency_required
  AND existence_disclosure='AUTHORIZED_ONLY' AND payload_disclosure='REDACTED' AND evidence_class='DEPLOYMENT_RESULT_READ')
 THEN RAISE EXCEPTION 'PC-AUTH-0002-DEPLOYMENT-READ-ACTION'; END IF;
END $$;
-- The migration owner is deliberately subject to Participant FORCE RLS.
-- This permits its association trigger to read/lock only the selected
-- Participant during result ingestion. It grants no runtime role access and
-- permits no Participant mutation, including through this definer.
DROP POLICY IF EXISTS deployment_association_owner_scope ON control.participant;
CREATE POLICY deployment_association_owner_scope ON control.participant FOR ALL TO openpc_control_owner
 USING(openpc.matches_participant(participant_id)
  AND openpc.current_action_intent_id()='ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1'
  AND pg_trigger_depth()>0)
 WITH CHECK(false);
CREATE OR REPLACE FUNCTION openpc.deployment_flat_document(value jsonb)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to('{'||string_agg(to_jsonb(key)::text||':'||item::text,',' ORDER BY key COLLATE "C")||'}','UTF8')
 FROM jsonb_each(value) entry(key,item)
$$;
REVOKE ALL ON FUNCTION openpc.deployment_flat_document(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.deployment_flat_document(jsonb) TO openpc_control_worker;

CREATE OR REPLACE FUNCTION openpc.guard_deployment_result()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE reservation control.deployment_address_reservation%ROWTYPE; envelope jsonb; claims jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 envelope:=convert_from(NEW.signed_bytes,'UTF8')::jsonb; claims:=envelope->'claims';
 IF envelope->>'purpose'='openpc:deployment-reservation-rejection:v1' THEN
  PERFORM openpc.validate_deployment_rejection(NEW);
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT reservation FROM control.deployment_address_reservation
  WHERE command_id=NEW.command_id AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR UPDATE;
 IF reservation.state<>'HANDOFF' OR envelope->>'purpose' IS DISTINCT FROM 'openpc:deployment-journal-projection:v1'
  OR claims->>'schema' IS DISTINCT FROM 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1'
  OR claims->'owner'->>'participant_id' IS DISTINCT FROM NEW.participant_id::text
  OR claims->'owner'->>'privacy_domain_id' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR 'urn:openpc:resource:'||(claims->>'targetRuntimeId') IS DISTINCT FROM reservation.target_runtime_id
  OR claims->>'sequence' IS DISTINCT FROM NEW.sequence::text
  OR claims->>'intentDigest' IS DISTINCT FROM substring(reservation.intent_digest from 8)
  OR claims->>'preparationDigest' IS DISTINCT FROM substring(reservation.prepared_record_digest from 8)
  OR claims->>'chainId' IS DISTINCT FROM reservation.chain_id
  OR claims->>'genesisDigest' IS DISTINCT FROM substring(reservation.genesis_digest from 8)
  OR claims->'status'->>'operationId' IS DISTINCT FROM 'urn:openpc:operation:'||NEW.command_id::text
  OR claims->'status'->>'attemptId' IS DISTINCT FROM reservation.attempt_id::text
  OR claims->'status'->>'signedTransactionHash' IS DISTINCT FROM reservation.transaction_hash
  OR (claims->>'observedAt')::timestamptz>clock_timestamp()+interval '5 seconds'
  OR EXISTS(SELECT 1 FROM control.deployment_result result WHERE result.command_id=NEW.command_id AND result.sequence>=NEW.sequence)
 THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS deployment_result_guard ON control.deployment_result;
CREATE TRIGGER deployment_result_guard BEFORE INSERT OR UPDATE OR DELETE ON control.deployment_result
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_deployment_result();

CREATE OR REPLACE FUNCTION openpc.project_deployment_association()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE claims jsonb; occurrence jsonb; invalidation jsonb; preparation jsonb;
 reservation control.deployment_address_reservation%ROWTYPE; participant control.participant%ROWTYPE;
 association control.contract_governance_association%ROWTYPE; document jsonb; encoded bytea; digest text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.participant_id) OR NOT openpc.matches_privacy(NEW.privacy_domain_id) THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- A Control rejection has no target occurrence and can never create or
 -- suspend an association. The result guard owns its separate proof above.
 IF convert_from(NEW.signed_bytes,'UTF8')::jsonb->>'purpose'='openpc:deployment-reservation-rejection:v1' THEN RETURN NEW; END IF;
 claims:=convert_from(NEW.signed_bytes,'UTF8')::jsonb->'claims';
 occurrence:=claims->'outcome'->'occurrence'; invalidation:=claims->'outcome'->'invalidation';
 SELECT * INTO STRICT reservation FROM control.deployment_address_reservation WHERE command_id=NEW.command_id;
 SELECT * INTO STRICT participant FROM control.participant WHERE participant_id=NEW.participant_id FOR SHARE;
 SELECT convert_from(intent.preparation_bytes,'UTF8')::jsonb INTO STRICT preparation FROM control.deployment_intent intent
  WHERE intent.participant_id=NEW.participant_id AND intent.privacy_domain_id=NEW.privacy_domain_id
   AND intent.preparation_digest=reservation.prepared_record_digest AND intent.intent_digest=reservation.intent_digest;
 SELECT * INTO association FROM control.contract_governance_association WHERE command_id=NEW.command_id FOR UPDATE;
 IF FOUND THEN
  document:=convert_from(association.document_bytes,'UTF8')::jsonb;
  IF association.state<>'ACTIVE' OR invalidation IS NULL OR invalidation='null'::jsonb
   OR invalidation->>'occurrenceId' IS DISTINCT FROM document->>'occurrenceId'
   OR invalidation->>'occurrenceDigest' IS DISTINCT FROM document->>'occurrenceDigest'
   OR invalidation->>'reason' NOT IN ('REORG','CODE_IDENTITY_MISMATCH')
   OR occurrence IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  document:=(document-'semanticDigest')||jsonb_build_object('state','SUSPENDED_REORG');
  digest:=encode(sha256(openpc.deployment_flat_document(document)),'hex');
  encoded:=openpc.deployment_flat_document(document||jsonb_build_object('semanticDigest',digest));
  UPDATE control.contract_governance_association SET state='SUSPENDED_REORG',current_sequence=NEW.sequence,
   document_bytes=encoded,semantic_digest='sha256:'||digest,updated_at=clock_timestamp() WHERE association_id=association.association_id;
 ELSIF occurrence IS NOT NULL AND occurrence<>'null'::jsonb THEN
  IF claims->'status'->>'state' IS DISTINCT FROM 'CONFIRMED' OR claims->'status'->>'truthState' IS DISTINCT FROM 'SUCCESS'
   OR occurrence->>'finality' IS DISTINCT FROM 'FINALIZED' OR occurrence->>'reorgStatus' IS DISTINCT FROM 'CANONICAL'
   OR occurrence->>'receiptStatus' IS DISTINCT FROM '1' OR occurrence->>'creationGraphComplete' IS DISTINCT FROM 'true'
   OR occurrence->>'runtimeCodePresent' IS DISTINCT FROM 'true' OR occurrence->>'internalNativeTransfers' IS DISTINCT FROM '0'
   OR invalidation IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
  -- A retired/restored Participant cannot acquire new control from an older
  -- epoch's deployment. The effect remains truthful; association stays absent.
  IF participant.state<>'ACTIVE' OR participant.archived_at IS NOT NULL
   OR participant.authority_epoch::text IS DISTINCT FROM preparation->'context'->>'participantEpoch' THEN RETURN NEW; END IF;
  document:=jsonb_build_object('associationId',reservation.attempt_id::text,'occurrenceId',occurrence->>'occurrenceId',
   'occurrenceDigest',occurrence->>'semanticDigest','contractAddress',occurrence->>'derivedContractAddress',
   'chainEnvironmentId',claims->>'chainEnvironmentId','chainId',claims->>'chainId','genesisHash',claims->>'genesisDigest',
   'controllerParticipantId',NEW.participant_id::text,'controllerParticipantEpoch',participant.authority_epoch,
   'controllerGeneration',1,'state','ACTIVE','activatedAt',to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
  digest:=encode(sha256(openpc.deployment_flat_document(document)),'hex');
  encoded:=openpc.deployment_flat_document(document||jsonb_build_object('semanticDigest',digest));
  INSERT INTO control.contract_governance_association(association_id,participant_id,privacy_domain_id,command_id,
   activation_sequence,current_sequence,participant_epoch,document_bytes,semantic_digest,state)
  VALUES(reservation.attempt_id,NEW.participant_id,NEW.privacy_domain_id,NEW.command_id,NEW.sequence,NEW.sequence,
   participant.authority_epoch,encoded,'sha256:'||digest,'ACTIVE');
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION openpc.project_deployment_association() FROM PUBLIC;
DROP TRIGGER IF EXISTS deployment_result_association ON control.deployment_result;
CREATE TRIGGER deployment_result_association AFTER INSERT ON control.deployment_result
 FOR EACH ROW EXECUTE FUNCTION openpc.project_deployment_association();
`;
