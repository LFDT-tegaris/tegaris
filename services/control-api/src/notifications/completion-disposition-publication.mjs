/** Install after the completion disposition guards. Canonical owns authenticated
 * function/trigger registration, runtime grants, RLS and generated migrations.
 * Shared inbox/cursor and WorkItem guards must independently bind direct DML to
 * the same immutable receipt; invoking this function is never an authorization
 * substitute. Its existing TypeScript caller inserts the disposition in this
 * transaction, calls this function, then rechecks current native authority.
 * Deferred checks use immutable originals after live phase rows are cleared. */
export const notificationCompletionDispositionPublicationSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.publish_notification_completion_disposition_effects(event uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE d control.notification_completion_disposition%ROWTYPE;
 signing control.notification_completion_disposition_signing%ROWTYPE;
 s control.notification_completion_source%ROWTYPE;e control.outbox_event%ROWTYPE;
 inbox control.notification_source_inbox%ROWTYPE;cursor_row control.notification_source_cursor%ROWTYPE;
 worker control.installed_notification_completion_worker%ROWTYPE;
 has_inbox boolean;has_cursor boolean;partition_key text;envelope_bytes bytea;problem text;
 subscription constant text:='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1';
BEGIN
 PERFORM openpc.assert_notification_completion_disposition_shared_owner();
 IF event IS NULL THEN RAISE EXCEPTION 'COMPLETION-PUBLICATION-EVENT'; END IF;
 -- Same source fence as preparation, observation, publication and recovery.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-completion-source:'||openpc.current_participant_id()::text||':'||openpc.current_privacy_domain_id()::text||':'||event::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 SELECT * INTO STRICT d FROM control.notification_completion_disposition WHERE participant_id=openpc.current_participant_id()
  AND privacy_domain_id=openpc.current_privacy_domain_id() AND event_id=event;
 SELECT * INTO STRICT signing FROM control.notification_completion_disposition_signing WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=event;
 -- Consume actual current TLS/event/phase admission and the exact canonical
 -- cryptographically verified observation before either replay or mutation.
 PERFORM openpc.check_notification_completion_phase_source(event,'PUBLISH');
 PERFORM openpc.check_notification_completion_receipt_admission(event,'PUBLISH',signing.observation);
 PERFORM openpc.check_notification_completion_disposition_signed(event,d.transition);
 SELECT * INTO STRICT s FROM control.notification_completion_source WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=event;
 SELECT * INTO STRICT e FROM control.outbox_event WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND event_id=event;
 partition_key:='urn:openpc:resource:'||e.aggregate_id::text;
 envelope_bytes:=convert_to(openpc.signing_canonical_json(s.source->'envelope'),'UTF8');
 problem:=CASE d.disposition WHEN 'QUARANTINED' THEN 'PC-OPS-9001' ELSE NULL END;
 IF d.disposition NOT IN ('ADMITTED','QUARANTINED')
 OR d.transition_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(d.transition),'UTF8')
 OR d.transition_digest IS DISTINCT FROM 'sha256:'||encode(sha256(d.transition_bytes),'hex')
 OR d.receipt_payload IS DISTINCT FROM decode(signing.preparation->'request'->>'payloadHex','hex')
 OR d.cose_sign1 IS DISTINCT FROM decode(signing.observation->>'coseHex','hex')
 OR d.operation_id IS DISTINCT FROM signing.operation_id OR d.receipt_id IS DISTINCT FROM signing.signing_attempt_id
 OR d.disposition IS DISTINCT FROM d.transition->'receipt'->>'disposition'
 OR s.source_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(s.source),'UTF8')
 OR s.source_digest IS DISTINCT FROM 'sha256:'||encode(sha256(s.source_bytes),'hex')
 OR s.original_selector IS DISTINCT FROM s.source->'originalSelector'
 OR s.source->'envelope' IS DISTINCT FROM openpc.notification_completion_source_envelope(e)
 OR s.source->'reference'->>'envelopeDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(envelope_bytes),'hex')
 OR s.source->'reference'->>'dataDigest' IS DISTINCT FROM 'sha256:'||encode(e.payload_digest,'hex')
 OR e.source IS DISTINCT FROM 'urn:openpc:service:LS-NOTIFICATION' OR e.aggregate_type IS DISTINCT FROM 'notification-occurrence' OR e.business_sequence IS DISTINCT FROM 1
 THEN RAISE EXCEPTION 'COMPLETION-PUBLICATION-ORIGINAL'; END IF;
 SELECT * INTO inbox FROM control.notification_source_inbox WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id
  AND subscription_id=subscription AND event_id=event FOR UPDATE;
 has_inbox:=FOUND;
 IF has_inbox THEN
  IF inbox.source IS DISTINCT FROM e.source OR inbox.partition IS DISTINCT FROM partition_key OR inbox.source_sequence IS DISTINCT FROM e.business_sequence
  OR inbox.data_digest IS DISTINCT FROM s.source->'reference'->>'dataDigest'
  OR inbox.envelope IS DISTINCT FROM envelope_bytes OR inbox.envelope_digest IS DISTINCT FROM s.source->'reference'->>'envelopeDigest'
  THEN RAISE EXCEPTION 'COMPLETION-PUBLICATION-INBOX'; END IF;
  IF inbox.state IN ('ADMITTED','QUARANTINED') THEN
   -- A terminal inbox is a replay only when every original effect still binds.
   -- Never repair a partial publication, reset human work, or advance twice.
   PERFORM openpc.check_notification_completion_disposition_original(event);
   PERFORM openpc.check_notification_completion_receipt_admission(event,'PUBLISH',signing.observation);
   RETURN;
  END IF;
  IF inbox.state IS DISTINCT FROM 'PENDING' OR inbox.admission_operation_id IS NOT NULL OR inbox.safe_problem_code IS NOT NULL
  THEN RAISE EXCEPTION 'COMPLETION-PUBLICATION-INBOX'; END IF;
 END IF;
 SELECT * INTO cursor_row FROM control.notification_source_cursor WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id
  AND subscription_id=subscription AND source=e.source AND partition=partition_key FOR UPDATE;
 has_cursor:=FOUND;
 IF has_cursor AND (cursor_row.last_sequence IS DISTINCT FROM 0 OR cursor_row.last_event_id IS NOT NULL OR cursor_row.last_data_digest IS NOT NULL OR cursor_row.revision IS DISTINCT FROM 1)
 THEN RAISE EXCEPTION 'COMPLETION-PUBLICATION-CURSOR'; END IF;
 IF EXISTS(SELECT 1 FROM control.work_item WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND work_item_id=d.receipt_id)
 THEN RAISE EXCEPTION 'COMPLETION-PUBLICATION-PARTIAL-WORK'; END IF;
 IF d.disposition='ADMITTED' THEN
  PERFORM openpc.check_notification_completion_validated_source(event);
 ELSE
  -- Historical creator belongs to the immutable original receipt. The current
  -- publisher's independent authority cannot rewrite that recorded identity.
  PERFORM openpc.notification_completion_remediation_projection(d);
  SELECT * INTO STRICT worker FROM control.installed_notification_completion_worker WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id
   AND installation_digest=d.transition->'receipt'->>'workerInstallationDigest';
 END IF;
 IF has_inbox THEN
  UPDATE control.notification_source_inbox SET state=d.disposition,safe_problem_code=problem,admission_operation_id=d.operation_id
   WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND subscription_id=subscription AND event_id=event AND state='PENDING';
  IF NOT FOUND THEN RAISE EXCEPTION 'COMPLETION-PUBLICATION-INBOX'; END IF;
 ELSE
  INSERT INTO control.notification_source_inbox(participant_id,privacy_domain_id,subscription_id,event_id,source,partition,source_sequence,data_digest,envelope_digest,envelope,state,safe_problem_code,admission_operation_id)
   VALUES(d.participant_id,d.privacy_domain_id,subscription,event,e.source,partition_key,e.business_sequence,s.source->'reference'->>'dataDigest',s.source->'reference'->>'envelopeDigest',envelope_bytes,d.disposition,problem,d.operation_id);
 END IF;
 IF d.disposition='ADMITTED' THEN
  IF has_cursor THEN
   UPDATE control.notification_source_cursor SET last_sequence=e.business_sequence,last_event_id=event,last_data_digest=s.source->'reference'->>'dataDigest',revision=revision+1
    WHERE participant_id=d.participant_id AND privacy_domain_id=d.privacy_domain_id AND subscription_id=subscription AND source=e.source AND partition=partition_key
     AND last_sequence=0 AND last_event_id IS NULL AND last_data_digest IS NULL AND revision=1;
   IF NOT FOUND THEN RAISE EXCEPTION 'COMPLETION-PUBLICATION-CURSOR'; END IF;
  ELSE
   INSERT INTO control.notification_source_cursor(participant_id,privacy_domain_id,subscription_id,source,partition,last_sequence,last_event_id,last_data_digest,revision)
    VALUES(d.participant_id,d.privacy_domain_id,subscription,e.source,partition_key,e.business_sequence,event,s.source->'reference'->>'dataDigest',1);
  END IF;
 ELSE
  -- HOLD performs no cursor mutation. Minimized remediation is the only new
  -- WorkItem; an ADMITTED producer failure WorkItem is never modified here.
  INSERT INTO control.work_item(work_item_id,participant_id,privacy_domain_id,kind,state,resource_ref,payload_digest,reason,created_by_principal_id,assignee_principal_id,claimed_by_principal_id,completed_by_principal_id,row_version)
   VALUES(d.receipt_id,d.participant_id,d.privacy_domain_id,'REMEDIATION','OPEN','urn:openpc:resource:'||event::text,sha256(d.receipt_payload),
    'Notification completion could not be processed.',worker.principal_id,NULL,NULL,NULL,1);
 END IF;
 -- Any failed completeness/currentness check propagates, rolling back every
 -- effect of this SQL statement. The caller preserves UNKNOWN on commit doubt
 -- and reconciles the original signing intent; this leaf never calls a signer.
 PERFORM openpc.check_notification_completion_disposition_original(event);
 PERFORM openpc.check_notification_completion_receipt_admission(event,'PUBLISH',signing.observation);
END $$;
REVOKE ALL ON FUNCTION openpc.publish_notification_completion_disposition_effects(uuid) FROM PUBLIC;
`;
