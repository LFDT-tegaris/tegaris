export const businessCustodyGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_business_custody_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='outbox_event' THEN
  IF OLD.proof_kind<>'LEGACY' OR (TG_OP='UPDATE' AND (NEW.proof_kind<>OLD.proof_kind OR
    NEW.sequence_namespace<>OLD.sequence_namespace OR NEW.receipt_id IS DISTINCT FROM OLD.receipt_id)) THEN
    RAISE EXCEPTION 'DATA-6020-IMMUTABLE-BUSINESS-OUTBOX'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM control.audit_occurrence a WHERE a.participant_id=OLD.participant_id
   AND a.privacy_domain_id=OLD.privacy_domain_id AND a.operation_id=OLD.operation_id) AND OLD.terminal_state='COMMITTED' THEN
    RAISE EXCEPTION 'DATA-6020-IMMUTABLE-BUSINESS-IDEMPOTENCY'; END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER business_outbox_immutable BEFORE UPDATE OR DELETE ON control.outbox_event
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_custody_mutation();
CREATE TRIGGER business_idempotency_immutable BEFORE UPDATE OR DELETE ON control.idempotency_record
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_business_custody_mutation();
`;
