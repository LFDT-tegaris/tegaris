/** Generated with Drizzle. The Participant row is the common lifecycle serialization owner. */
export const participantLifecycleGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_participant_authority_creation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE p control.participant%ROWTYPE;
BEGIN
 -- Revocation remains possible while fenced; no insertion or live-state write does.
 IF TG_OP='UPDATE' AND coalesce(to_jsonb(NEW)->>'state','') IN ('REVOKED','EXPIRED','CANCELLED','ARCHIVED','REMOVED','OFFBOARDED') THEN RETURN NEW; END IF;
 SELECT * INTO p FROM control.participant WHERE participant_id=NEW.participant_id FOR SHARE;
 IF NOT FOUND OR p.archived_at IS NOT NULL OR p.state NOT IN ('ACTIVE','PROVISIONING') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-FENCED';
 END IF;
 RETURN NEW;
END $$;
${[
  'principal',
  'participant_membership',
  'privacy_domain',
  'authority_envelope',
  'authority_role',
  'authority_group',
  'authority_group_member',
  'assignment',
  'delegation',
  'session',
  'credential',
  'participant_invitation',
  'participant_invitation_token',
  'participant_invitation_proof',
  'participant_invitation_acceptance',
]
  .map(
    (table) => `
DROP TRIGGER IF EXISTS aa_participant_lifecycle_fence ON control.${table};
CREATE TRIGGER aa_participant_lifecycle_fence BEFORE INSERT OR UPDATE ON control.${table}
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_authority_creation();`,
  )
  .join('\n')}

CREATE OR REPLACE FUNCTION openpc.guard_participant_lifecycle_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-HISTORY-IMMUTABLE';
END $$;
DROP TRIGGER IF EXISTS participant_lifecycle_history ON control.participant_lifecycle_transition;
CREATE TRIGGER participant_lifecycle_history BEFORE UPDATE OR DELETE ON control.participant_lifecycle_transition
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_participant_lifecycle_history();

CREATE OR REPLACE FUNCTION openpc.require_participant_lifecycle_history()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE mode text:=current_setting('openpc.context_mode');
 owner uuid:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 privacy uuid:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 op uuid:=current_setting('openpc.operation_id')::uuid;
 action text:=current_setting('openpc.action_intent_id'); valid boolean;
BEGIN
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.participant_id,NEW.privacy_domain_id,op,action,true);
 SELECT EXISTS(SELECT 1 FROM control.participant p JOIN control.outbox_event event ON event.participant_id=p.participant_id
   AND event.event_id=NEW.operation_id AND event.event_type='openpc.identity.participant.epoch.advanced.v1'
   WHERE p.participant_id=NEW.participant_id AND p.authority_epoch=NEW.new_epoch AND p.row_version=NEW.revision
    AND p.root_privacy_domain_id=NEW.privacy_domain_id
    AND (p.archived_at IS NOT NULL)=(NEW.mutation='ARCHIVE')) INTO valid;
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-EFFECT'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',NEW.source_participant_id,NEW.source_privacy_domain_id,op,action,true);
 SELECT EXISTS(SELECT 1 FROM control.mutation_candidate candidate JOIN control.mutation_evidence evidence
   ON evidence.participant_id=candidate.participant_id AND evidence.operation_id=candidate.consumed_operation_id
    AND evidence.candidate_digest=candidate.candidate_digest AND evidence.catalog_operation_id=candidate.catalog_operation_id
   JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id
    AND receipt.operation_id=NEW.operation_id AND receipt.terminal_state='COMMITTED'
   WHERE candidate.participant_id=NEW.source_participant_id AND candidate.privacy_domain_id=NEW.source_privacy_domain_id
    AND candidate.state='CONSUMED' AND candidate.consumed_operation_id=NEW.operation_id
    AND candidate.catalog_operation_id='ID-OP-PARTICIPANT-'||NEW.mutation AND candidate.resource_id=NEW.participant_id
    AND candidate.candidate_document->>'privacyDomainId'=NEW.privacy_domain_id::text
    AND candidate.candidate_document->>'expectedEpoch'=NEW.prior_epoch::text
    AND candidate.expected_revision=NEW.revision-1 AND receipt.result_payload#>>'{result,epoch}'=NEW.new_epoch::text)
 INTO valid;
 PERFORM openpc.set_request_context(mode,owner,privacy,op,action,privacy IS NOT NULL);
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS participant_lifecycle_history_provenance ON control.participant_lifecycle_transition;
CREATE CONSTRAINT TRIGGER participant_lifecycle_history_provenance AFTER INSERT ON control.participant_lifecycle_transition
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_participant_lifecycle_history();

CREATE OR REPLACE FUNCTION openpc.require_participant_lifecycle_transition()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
DECLARE transition control.participant_lifecycle_transition%ROWTYPE;
 mode text; owner uuid; privacy uuid; op uuid; action text;
 valid boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-HISTORY-RETAINED'; END IF;
 IF NEW.archived_at IS NOT DISTINCT FROM OLD.archived_at THEN RETURN NULL; END IF;
 mode:=current_setting('openpc.context_mode');
 owner:=nullif(current_setting('openpc.participant_id'),'')::uuid;
 privacy:=nullif(current_setting('openpc.privacy_domain_id'),'')::uuid;
 op:=current_setting('openpc.operation_id')::uuid;
 action:=current_setting('openpc.action_intent_id');
 IF NOT ((OLD.state='ACTIVE' AND NEW.state='SUSPENDED' AND OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL)
      OR (OLD.state='SUSPENDED' AND NEW.state='ACTIVE' AND OLD.archived_at IS NOT NULL AND NEW.archived_at IS NULL))
    OR NEW.authority_epoch<>OLD.authority_epoch+1 OR NEW.row_version<>OLD.row_version+1 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-TRANSITION';
 END IF;
 PERFORM openpc.set_request_context('PLATFORM',NEW.participant_id,null,op,action,false);
 SELECT * INTO transition FROM control.participant_lifecycle_transition
  WHERE participant_id=NEW.participant_id AND new_epoch=NEW.authority_epoch AND prior_epoch=OLD.authority_epoch
   AND revision=NEW.row_version AND mutation=CASE WHEN NEW.archived_at IS NULL THEN 'RESTORE' ELSE 'ARCHIVE' END;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-HISTORY'; END IF;
 PERFORM openpc.set_request_context('PARTICIPANT',transition.source_participant_id,transition.source_privacy_domain_id,op,action,true);
 SELECT EXISTS(
  SELECT 1 FROM control.mutation_candidate candidate
  JOIN control.mutation_evidence evidence ON evidence.participant_id=candidate.participant_id
   AND evidence.operation_id=candidate.consumed_operation_id AND evidence.candidate_digest=candidate.candidate_digest
   AND evidence.catalog_operation_id=candidate.catalog_operation_id AND evidence.principal_id<>evidence.checker_principal_id
  JOIN control.idempotency_record receipt ON receipt.participant_id=candidate.participant_id
   AND receipt.operation_id=candidate.consumed_operation_id AND receipt.terminal_state='COMMITTED'
  WHERE candidate.participant_id=transition.source_participant_id AND candidate.privacy_domain_id=transition.source_privacy_domain_id
   AND candidate.consumed_operation_id=transition.operation_id AND candidate.state='CONSUMED'
   AND candidate.catalog_operation_id='ID-OP-PARTICIPANT-'||transition.mutation
   AND candidate.resource_id=NEW.participant_id AND candidate.candidate_document->>'participantId'=NEW.participant_id::text
   AND candidate.candidate_document->>'expectedEpoch'=OLD.authority_epoch::text
   AND candidate.expected_revision=OLD.row_version
   AND receipt.result_payload#>>'{result,epoch}'=NEW.authority_epoch::text
 ) INTO valid;
 PERFORM openpc.set_request_context(mode,owner,privacy,op,action,privacy IS NOT NULL);
 IF NOT coalesce(valid,false) THEN RAISE EXCEPTION 'PC-AUTH-0002-PARTICIPANT-LIFECYCLE-PROVENANCE'; END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS participant_lifecycle_transition ON control.participant;
CREATE CONSTRAINT TRIGGER participant_lifecycle_transition AFTER UPDATE OR DELETE ON control.participant
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_participant_lifecycle_transition();
`;
