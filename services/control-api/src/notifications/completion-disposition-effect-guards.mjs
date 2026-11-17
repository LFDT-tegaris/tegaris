import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.ts';
const producerTrustField = notificationCoseProfiles.NotificationWorkerProfileV1.fields.find(
  (f) => f.name === 'producerTrustDigest',
).key;
/** Feature predicates only. Canonical owns installation, grants and shared
 * dispatch. Phase identity is not signature verification or durable custody. */
export const notificationCompletionDispositionPhaseGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_effect_binding(event uuid,phase text,installation text,authority text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE admitted record;
BEGIN
 IF event IS NULL OR phase IS NULL OR phase NOT IN ('SOURCE','CLAIM','LIMIT','FINISH','PREPARE','SIGN_CLAIM','OBSERVE','PUBLISH')
 OR (installation ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
 OR (authority ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'COMPLETION-EFFECT-BINDING'; END IF;
 -- STRICT proves cardinality. The native owner verifies MAC, exact login,
 -- backend/transaction/event/phase, live identity and current installed worker.
 SELECT * INTO STRICT admitted FROM openpc.notification_completion_phase_binding(event,phase);
 IF admitted.installation_digest IS DISTINCT FROM installation OR admitted.authority_digest IS DISTINCT FROM authority
 THEN RAISE EXCEPTION 'COMPLETION-EFFECT-BINDING'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.check_notification_completion_effect_binding(uuid,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION openpc.check_notification_completion_phase_source(event uuid,phase text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE binding record; current_worker control.installed_notification_completion_worker%ROWTYPE;
 original control.notification_delivery_outcome%ROWTYPE;producer control.installed_notification_worker%ROWTYPE;producer_profile jsonb;
BEGIN
 SELECT * INTO STRICT binding FROM openpc.notification_completion_phase_binding(event,phase);
 SELECT * INTO STRICT current_worker FROM control.installed_notification_completion_worker WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND installation_digest=binding.installation_digest AND state='ACTIVE';
 SELECT * INTO STRICT original FROM control.notification_delivery_outcome WHERE participant_id=current_worker.participant_id
  AND privacy_domain_id=current_worker.privacy_domain_id AND receipt_id=event;
 PERFORM openpc.check_notification_completion_source_origin(event,original.receipt_digest);
 SELECT * INTO STRICT producer FROM control.installed_notification_worker WHERE participant_id=original.participant_id
  AND privacy_domain_id=original.privacy_domain_id AND installation_digest=original.worker_installation_digest;
 producer_profile:=openpc.business_cbor(decode(producer.installation->'signed'->>'payloadHex','hex'));
 IF producer_profile->'${producerTrustField}' IS DISTINCT FROM openpc.business_bytes(decode(substr(current_worker.producer_trust_digest,8),'hex'))
 OR current_worker.installation->'pins'->>'environmentId' IS DISTINCT FROM producer.installation->'pins'->>'environmentId'
 OR original.transition->'receipt'->>'environmentId' IS DISTINCT FROM current_worker.installation->'pins'->>'environmentId'
 THEN RAISE EXCEPTION 'COMPLETION-PHASE-PRODUCER'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.check_notification_completion_phase_source(uuid,text) FROM PUBLIC;

-- Immediate admission only: the native owner cryptographically verified these
-- exact bytes under privileged installed trust, then MAC-bound them to this
-- actual TLS transaction/event/phase. Neither framing nor phase identity suffices.
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_receipt_admission(event uuid,phase text,observation jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE verified jsonb;expected jsonb;q jsonb;
 s control.notification_completion_disposition_signing%ROWTYPE;
 signer control.notification_completion_disposition_signer_installation%ROWTYPE;
 worker control.installed_notification_completion_worker%ROWTYPE;
BEGIN
 IF event IS NULL OR phase IS NULL OR phase NOT IN ('OBSERVE','PUBLISH') OR observation IS NULL
 THEN RAISE EXCEPTION 'COMPLETION-RECEIPT-ADMISSION'; END IF;
 verified:=openpc.notification_completion_verified_receipt(event,phase);
 SELECT * INTO STRICT s FROM control.notification_completion_disposition_signing WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 q:=s.preparation->'request';
 SELECT * INTO STRICT signer FROM control.notification_completion_disposition_signer_installation WHERE participant_id=s.participant_id
  AND privacy_domain_id=s.privacy_domain_id AND trust_digest=s.signer_installation_digest;
 SELECT * INTO STRICT worker FROM control.installed_notification_completion_worker WHERE participant_id=s.participant_id
  AND privacy_domain_id=s.privacy_domain_id AND installation_digest=signer.worker_installation_digest;
 IF verified IS NULL OR s.state NOT IN ('DISPATCHED','OBSERVED') OR observation->>'outcome' IS DISTINCT FROM 'SIGNED'
 OR (phase='PUBLISH' AND s.state IS DISTINCT FROM 'OBSERVED')
 OR (s.state='OBSERVED' AND observation IS DISTINCT FROM s.observation)
 OR s.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(s.preparation),'UTF8')
 OR s.preparation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(s.preparation_bytes),'hex')
 OR s.request_digest IS DISTINCT FROM s.preparation->>'requestDigest'
 OR s.request_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to('pc.notification.completion-disposition-provider-request.v1','UTF8')||decode('00','hex')||convert_to(openpc.signing_canonical_json(q),'UTF8')),'hex')
 OR q->>'signerInstallationDigest' IS DISTINCT FROM signer.trust_digest
 OR q->>'signerKeyId' IS DISTINCT FROM signer.trust->>'signerKeyId'
 OR q->>'workerInstallationDigest' IS DISTINCT FROM worker.installation_digest
 OR q->>'environmentId' IS DISTINCT FROM worker.installation->'pins'->>'environmentId'
 OR q->>'dispositionPreparationDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(s.preparation->'preparation'),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'COMPLETION-RECEIPT-ADMISSION'; END IF;
 expected:=jsonb_build_object(
  'schema','pc.notification.completion-verified-receipt.v1',
  'purpose','pc.cose.notification-completion-disposition-receipt.v1',
  'requestDigest',s.request_digest,
  'preparationDigest',q->>'dispositionPreparationDigest',
  'payloadDigest','sha256:'||encode(sha256(decode(q->>'payloadHex','hex')),'hex'),
  'coseDigest','sha256:'||encode(sha256(decode(observation->>'coseHex','hex')),'hex'),
  'observationDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(observation),'UTF8')),'hex'),
  'signerInstallationDigest',signer.trust_digest,'signerKeyId',signer.trust->>'signerKeyId',
  'originalWorkerInstallationDigest',worker.installation_digest,
  'producerTrustDigest',worker.producer_trust_digest,'environmentId',worker.installation->'pins'->>'environmentId');
 IF verified IS DISTINCT FROM expected THEN RAISE EXCEPTION 'COMPLETION-RECEIPT-ADMISSION'; END IF;
END $$;
REVOKE ALL ON FUNCTION openpc.check_notification_completion_receipt_admission(uuid,text,jsonb) FROM PUBLIC;

`;

/** Durable structural checks intentionally do not consult current phase rows:
 * Identity clears those before COMMIT. These predicates are suitable components
 * of deferred completeness/readback, but do not authenticate an ECDSA signature.
 * Durable authenticity relies on the installed immutable immediate guards;
 * canonical must authenticate their registration before enabling any writes. */
export const notificationCompletionDispositionStructureGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.notification_completion_remediation_projection(item control.notification_completion_disposition) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE r jsonb:=item.transition->'receipt';w control.installed_notification_completion_worker%ROWTYPE;
BEGIN
 IF item.participant_id IS DISTINCT FROM openpc.current_participant_id() OR item.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR item.disposition IS DISTINCT FROM 'QUARANTINED' OR r->>'workItemKind' IS DISTINCT FROM 'REMEDIATION'
 OR r->>'workItemId' IS DISTINCT FROM item.receipt_id::text OR r->>'sourceEventId' IS DISTINCT FROM item.event_id::text
 THEN RAISE EXCEPTION 'COMPLETION-REMEDIATION-BINDING'; END IF;
 SELECT * INTO STRICT w FROM control.installed_notification_completion_worker
 WHERE participant_id=item.participant_id AND privacy_domain_id=item.privacy_domain_id AND installation_digest=r->>'workerInstallationDigest';
 RETURN jsonb_build_object('0','REMEDIATION','1','OPEN','2','urn:openpc:resource:'||item.event_id::text,
 '3',openpc.business_bytes(sha256(item.receipt_payload)),
 '4',openpc.business_bytes(sha256(convert_to('Notification completion could not be processed.','UTF8'))),
 '5',openpc.business_uuid(w.principal_id),'6',0,'8',0,'10',0);
END $$;

CREATE OR REPLACE FUNCTION openpc.check_notification_completion_disposition_structure(event uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d control.notification_completion_disposition%ROWTYPE;s control.notification_completion_source%ROWTYPE;
 signing control.notification_completion_disposition_signing%ROWTYPE;e control.outbox_event%ROWTYPE;
 inbox control.notification_source_inbox%ROWTYPE;cursor_row control.notification_source_cursor%ROWTYPE;
 work control.work_item%ROWTYPE;history control.audit_occurrence%ROWTYPE;r jsonb;expected jsonb;partition_key text;
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 SELECT * INTO STRICT d FROM control.notification_completion_disposition WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 SELECT * INTO STRICT s FROM control.notification_completion_source WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=event;
 SELECT * INTO STRICT signing FROM control.notification_completion_disposition_signing WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=event;
 SELECT * INTO STRICT e FROM control.outbox_event WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=event;
 -- Existing checker binds original producer outbox, immutable attempt chain,
 -- canonical receipt claims and observed COSE framing. It is NOT crypto proof.
 PERFORM openpc.check_notification_completion_disposition_signed(event,d.transition);
 r:=d.transition->'receipt';partition_key:='urn:openpc:resource:'||e.aggregate_id::text;
 IF d.transition_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(d.transition),'UTF8')
 OR d.transition_digest IS DISTINCT FROM 'sha256:'||encode(sha256(d.transition_bytes),'hex')
 OR d.receipt_payload IS DISTINCT FROM decode(d.transition->>'payloadHex','hex') OR d.cose_sign1 IS DISTINCT FROM decode(d.transition->>'coseHex','hex')
 OR r->>'participantId' IS DISTINCT FROM d.participant_id::text OR r->>'privacyDomainId' IS DISTINCT FROM d.privacy_domain_id::text
 OR r->>'sourceEventId' IS DISTINCT FROM event::text OR r->>'receiptId' IS DISTINCT FROM d.receipt_id::text OR r->>'operationId' IS DISTINCT FROM d.operation_id::text
 OR r->>'disposition' IS DISTINCT FROM d.disposition OR signing.state IS DISTINCT FROM 'OBSERVED'
 OR signing.operation_id IS DISTINCT FROM d.operation_id OR signing.signing_attempt_id IS DISTINCT FROM d.receipt_id
 OR signing.observation->>'outcome' IS DISTINCT FROM 'SIGNED' OR signing.observation->>'coseHex' IS DISTINCT FROM encode(d.cose_sign1,'hex')
 OR signing.preparation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(signing.preparation),'UTF8')
 OR signing.preparation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(signing.preparation_bytes),'hex')
 OR signing.observation_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(signing.observation),'UTF8')
 OR signing.observation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(signing.observation_bytes),'hex')
 OR s.source_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(s.source),'UTF8')
 OR s.source_digest IS DISTINCT FROM 'sha256:'||encode(sha256(s.source_bytes),'hex')
 OR s.source->'envelope' IS DISTINCT FROM openpc.notification_completion_source_envelope(e)
 OR s.original_selector IS DISTINCT FROM s.source->'originalSelector'
 OR e.business_sequence IS DISTINCT FROM 1 OR e.aggregate_type IS DISTINCT FROM 'notification-occurrence'
 OR e.source IS DISTINCT FROM 'urn:openpc:service:LS-NOTIFICATION'
 THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-STRUCTURE'; END IF;
 SELECT * INTO STRICT inbox FROM control.notification_source_inbox WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id
 AND subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1' AND event_id=event;
 IF inbox.source IS DISTINCT FROM e.source OR inbox.partition IS DISTINCT FROM partition_key OR inbox.source_sequence IS DISTINCT FROM e.business_sequence
 OR inbox.data_digest IS DISTINCT FROM s.source->'reference'->>'dataDigest' OR inbox.data_digest IS DISTINCT FROM r->>'sourceDataDigest'
 OR inbox.envelope IS DISTINCT FROM convert_to(openpc.signing_canonical_json(s.source->'envelope'),'UTF8')
 OR inbox.envelope_digest IS DISTINCT FROM 'sha256:'||encode(sha256(inbox.envelope),'hex') OR inbox.envelope_digest IS DISTINCT FROM r->>'sourceEnvelopeDigest'
 OR inbox.admission_operation_id IS DISTINCT FROM d.operation_id OR inbox.state IS DISTINCT FROM d.disposition
 OR inbox.safe_problem_code IS DISTINCT FROM (CASE d.disposition WHEN 'QUARANTINED' THEN 'PC-OPS-9001' ELSE NULL END)
 THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-INBOX'; END IF;
 IF d.disposition='ADMITTED' THEN
  IF r->>'cursorMode' IS DISTINCT FROM 'ADVANCE' OR r->>'safeProblem' IS DISTINCT FROM 'NONE'
  THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-ADMITTED'; END IF;
  -- This authentic producer's publication checker preserves an existing failure
  -- WorkItem through its original human transition history; never reset it OPEN.
  PERFORM openpc.check_notification_completion_validated_source(event);
  SELECT * INTO STRICT cursor_row FROM control.notification_source_cursor WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id
   AND subscription_id=inbox.subscription_id AND source=inbox.source AND partition=inbox.partition;
  IF cursor_row.last_sequence IS DISTINCT FROM inbox.source_sequence OR cursor_row.last_event_id IS DISTINCT FROM event
   OR cursor_row.last_data_digest IS DISTINCT FROM inbox.data_digest OR cursor_row.revision<1
  THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-CURSOR'; END IF;
  IF EXISTS(SELECT 1 FROM control.work_item WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND work_item_id=d.receipt_id)
  THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-UNEXPECTED-WORK'; END IF;
 ELSIF d.disposition='QUARANTINED' THEN
  IF r->>'cursorMode' IS DISTINCT FROM 'HOLD' OR r->>'safeProblem' IS DISTINCT FROM 'PC-OPS-9001'
  THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-QUARANTINE'; END IF;
  -- HOLD permits an absent cursor or its untouched empty initial position.
  IF EXISTS(SELECT 1 FROM control.notification_source_cursor WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id
   AND subscription_id=inbox.subscription_id AND source=inbox.source AND partition=inbox.partition
   AND (last_sequence<>0 OR last_event_id IS NOT NULL OR last_data_digest IS NOT NULL OR revision<>1))
  THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-CURSOR-HOLD'; END IF;
  SELECT * INTO STRICT work FROM control.work_item WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND work_item_id=d.receipt_id;
  expected:=openpc.notification_completion_remediation_projection(d);
  IF work.row_version=1 THEN
   IF openpc.work_item_business_projection(work) IS DISTINCT FROM expected THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-REMEDIATION'; END IF;
  ELSE
   SELECT * INTO STRICT history FROM control.audit_occurrence WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id
    AND aggregate_type='work-item' AND aggregate_id=work.work_item_id AND before_revision=1;
   IF history.before_existence<>1 OR history.before_state_digest IS DISTINCT FROM sha256(history.before_state_preimage)
    OR history.receipt_digest IS DISTINCT FROM sha256(history.receipt_cbor)
    OR openpc.business_cbor(history.receipt_cbor)->'18' IS DISTINCT FROM jsonb_build_object('0',1,'1',1,'2',openpc.business_bytes(history.before_state_digest))
    OR openpc.business_cbor(history.before_state_preimage)->8 IS DISTINCT FROM expected
   THEN RAISE EXCEPTION 'COMPLETION-ORIGINAL-REMEDIATION-HISTORY'; END IF;
  END IF;
 ELSE RAISE EXCEPTION 'COMPLETION-ORIGINAL-DISPOSITION'; END IF;
END $$;
-- This readback never creates or renews authority. Shared-owner registration
-- must enforce the immediate exact-byte receipt guards and immutable originals.
-- Current phase rows are intentionally absent after the native callback returns.
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_disposition_original(event uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.check_notification_completion_disposition_structure(event);
END $$;
REVOKE ALL ON FUNCTION openpc.check_notification_completion_disposition_original(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION openpc.notification_completion_remediation_projection(control.notification_completion_disposition),
 openpc.check_notification_completion_disposition_structure(uuid) FROM PUBLIC;
`;
