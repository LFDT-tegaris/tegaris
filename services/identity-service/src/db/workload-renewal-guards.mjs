/** Structural invariants only. These triggers confer no worker, policy,
 * attestation, provider or issuance authority and grant no application writes. */
export const workloadRenewalGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.guard_workload_renewal_original() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $wr_original$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'renewal original history is immutable'; END IF;
 IF (NEW.participant_id,NEW.privacy_domain_id,NEW.renewal_id,NEW.family_id,NEW.operation_id,
     NEW.credential_id,NEW.original,NEW.request_bytes,NEW.request_digest,NEW.family_security_epoch,
     NEW.admission_operation_id,NEW.attestation_evidence,NEW.attestation_valid_until,NEW.renewal_deadline,NEW.created_at)
   IS DISTINCT FROM
    (OLD.participant_id,OLD.privacy_domain_id,OLD.renewal_id,OLD.family_id,OLD.operation_id,
     OLD.credential_id,OLD.original,OLD.request_bytes,OLD.request_digest,OLD.family_security_epoch,
     OLD.admission_operation_id,OLD.attestation_evidence,OLD.attestation_valid_until,OLD.renewal_deadline,OLD.created_at)
   OR NEW.lease_fence<OLD.lease_fence OR NEW.row_version<OLD.row_version
   OR (OLD.provider_outcome='ISSUED' AND NEW.provider_outcome<>'ISSUED')
   OR (OLD.certificate_der IS NOT NULL AND (NEW.certificate_der,NEW.certificate_fingerprint)
       IS DISTINCT FROM (OLD.certificate_der,OLD.certificate_fingerprint))
 THEN RAISE EXCEPTION 'renewal original or monotonic fence changed'; END IF;
 RETURN NEW;
END $wr_original$;
ALTER FUNCTION openpc.guard_workload_renewal_original() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_workload_renewal_original() FROM PUBLIC;
DROP TRIGGER IF EXISTS wr_original_immutable ON control.workload_renewal_intent;
CREATE TRIGGER wr_original_immutable BEFORE UPDATE OR DELETE ON control.workload_renewal_intent
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_renewal_original();

CREATE OR REPLACE FUNCTION openpc.guard_workload_renewal_policy() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $wr_policy$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'renewal policy provenance is immutable'; END IF;
 RAISE EXCEPTION 'renewal policy revisions are immutable';
END $wr_policy$;
ALTER FUNCTION openpc.guard_workload_renewal_policy() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_workload_renewal_policy() FROM PUBLIC;
DROP TRIGGER IF EXISTS wr_policy_immutable ON control.workload_renewal_policy;
CREATE TRIGGER wr_policy_immutable BEFORE UPDATE OR DELETE ON control.workload_renewal_policy
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_renewal_policy();

CREATE OR REPLACE FUNCTION openpc.guard_workload_credential_family() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $wr_family$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'workload instance history is immutable'; END IF;
 IF (NEW.participant_id,NEW.privacy_domain_id,NEW.family_id,NEW.principal_id,NEW.workload_id,
     NEW.instance_id,NEW.instance_generation,NEW.instance_admission_operation_id)
   IS DISTINCT FROM (OLD.participant_id,OLD.privacy_domain_id,OLD.family_id,OLD.principal_id,OLD.workload_id,
     OLD.instance_id,OLD.instance_generation,OLD.instance_admission_operation_id)
   OR NEW.security_epoch<OLD.security_epoch OR NEW.row_version<=OLD.row_version
   OR (OLD.state<>'ACTIVE' AND NEW.state<>OLD.state)
   OR (NEW.current_credential_id=OLD.current_credential_id AND
       (NEW.generation<>OLD.generation OR NEW.current_fingerprint<>OLD.current_fingerprint))
   OR (NEW.current_credential_id<>OLD.current_credential_id AND NEW.generation<>OLD.generation+1)
 THEN RAISE EXCEPTION 'workload family transition rejected'; END IF;
 RETURN NEW;
END $wr_family$;
ALTER FUNCTION openpc.guard_workload_credential_family() OWNER TO openpc_control_owner;
REVOKE ALL ON FUNCTION openpc.guard_workload_credential_family() FROM PUBLIC;
DROP TRIGGER IF EXISTS wr_family_guard ON control.workload_credential_family;
CREATE TRIGGER wr_family_guard BEFORE UPDATE OR DELETE ON control.workload_credential_family
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_workload_credential_family();
${[
  'workload_renewal_attempt',
  'workload_renewal_observation',
  'workload_renewal_issue_authorization',
]
  .map(
    (table) => `
DROP TRIGGER IF EXISTS wr_history_immutable ON control.${table};
CREATE TRIGGER wr_history_immutable BEFORE UPDATE OR DELETE ON control.${table}
 FOR EACH ROW EXECUTE FUNCTION openpc.reject_mutation();`,
  )
  .join('\n')}
`;
