export const ciglSettingsGuardsSql = `
INSERT INTO control.action_intent(action_intent_id,resource_type,operation_class,risk_class,
 maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES ('ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1','cigl-settings','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_SETTINGS_PUBLICATION'),
 ('ACT-CIGL_SETTINGS_READ_RESOURCE-V1','cigl-settings','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_SETTINGS_READ')
ON CONFLICT DO NOTHING;
DO $$ BEGIN
 IF (SELECT count(*) FROM control.action_intent WHERE
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,step_up_required,
   idempotency_required,existence_disclosure,payload_disclosure,evidence_class) IN (
  ('ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1','cigl-settings','CREATE','HIGH',true,true,true,'AUTHORIZED_ONLY','REDACTED','CIGL_SETTINGS_PUBLICATION'),
  ('ACT-CIGL_SETTINGS_READ_RESOURCE-V1','cigl-settings','READ','STANDARD',false,false,false,'AUTHORIZED_ONLY','AUTHORIZED_FULL','CIGL_SETTINGS_READ')))<>2 THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS-ACTION';
 END IF;
END $$;
ALTER TABLE control.cigl_settings FORCE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION openpc.guard_cigl_settings()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-DATA-6004'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NEW.participant_id<>current_setting('openpc.participant_id')::uuid
  OR NEW.privacy_domain_id<>current_setting('openpc.privacy_domain_id')::uuid
  OR NEW.publication_operation_id<>current_setting('openpc.operation_id')::uuid
  OR current_setting('openpc.action_intent_id')<>'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1'
  OR NEW.definition_digest<>'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(NEW.definition),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS';
 END IF;
 NEW.created_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS cigl_settings_guard ON control.cigl_settings;
CREATE TRIGGER cigl_settings_guard BEFORE INSERT OR UPDATE OR DELETE ON control.cigl_settings
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_cigl_settings();

CREATE OR REPLACE FUNCTION openpc.require_cigl_settings_publication()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,control AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM control.mutation_evidence evidence
  JOIN control.idempotency_record receipt ON receipt.participant_id=evidence.participant_id
   AND receipt.privacy_domain_id=evidence.privacy_domain_id AND receipt.operation_id=evidence.operation_id
   AND receipt.catalog_operation_id=evidence.catalog_operation_id AND receipt.input_digest=evidence.candidate_digest
  JOIN control.mutation_candidate candidate ON candidate.participant_id=evidence.participant_id
   AND candidate.privacy_domain_id=evidence.privacy_domain_id AND candidate.consumed_operation_id=evidence.operation_id
   AND candidate.catalog_operation_id=evidence.catalog_operation_id AND candidate.candidate_digest=evidence.candidate_digest
  WHERE evidence.participant_id=NEW.participant_id AND evidence.privacy_domain_id=NEW.privacy_domain_id
   AND evidence.operation_id=NEW.publication_operation_id AND evidence.aggregate_type='cigl-settings'
   AND evidence.aggregate_id=NEW.cigl_settings_id AND evidence.catalog_operation_id='CFG-OP-CREATE-CIGL-SETTINGS'
   AND evidence.action_intent_id='ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1'
   AND NEW.publication_authority_digest='sha256:'||encode(evidence.evidence_digest,'hex')
   AND candidate.resource_id=NEW.cigl_settings_id AND candidate.state='CONSUMED' AND candidate.expected_revision=0
   AND candidate.candidate_document->'definition'=NEW.definition
   AND receipt.terminal_state='COMMITTED'
   AND receipt.result_payload->>'resourceRef'='urn:openpc:resource:'||NEW.cigl_settings_id::text
   AND EXISTS(SELECT 1 FROM control.outbox_event event WHERE event.participant_id=NEW.participant_id
    AND event.privacy_domain_id=NEW.privacy_domain_id AND event.aggregate_id=NEW.cigl_settings_id
    AND event.aggregate_type='cigl-settings' AND event.event_type='openpc.cigl.settings.staged.v1')) THEN
  RAISE EXCEPTION 'PC-AUTH-0002-CIGL-SETTINGS-PROVENANCE';
 END IF;
 RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS cigl_settings_publication ON control.cigl_settings;
CREATE CONSTRAINT TRIGGER cigl_settings_publication AFTER INSERT ON control.cigl_settings
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION openpc.require_cigl_settings_publication();
`;
