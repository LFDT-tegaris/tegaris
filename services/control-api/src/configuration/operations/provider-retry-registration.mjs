/** Canonical migration registration. Roles have no login or application
 * membership; provisioning a real external root remains a separate operation. */
export const providerRetryQualificationRolesSql = String.raw`
RESET ROLE;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='openpc_operations_qualification_owner') THEN
  CREATE ROLE openpc_operations_qualification_owner NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='openpc_operations_qualification_bootstrap') THEN
  CREATE ROLE openpc_operations_qualification_bootstrap NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('openpc_operations_qualification_owner','openpc_operations_qualification_bootstrap')
   AND (rolcanlogin OR rolinherit OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))
 OR pg_has_role('openpc_operations_qualification_owner','openpc_operations_qualification_bootstrap','MEMBER')
 OR pg_has_role('openpc_operations_qualification_bootstrap','openpc_operations_qualification_owner','MEMBER')
 THEN RAISE EXCEPTION 'OPS_QUALIFICATION_ROLE_SEPARATION'; END IF;
END $$;
GRANT USAGE ON SCHEMA control,openpc TO openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap;
GRANT EXECUTE ON FUNCTION openpc.require_uuid_setting(text),openpc.set_request_context(text,uuid,uuid,uuid,text,boolean),openpc.assert_request_context(boolean),openpc.matches_participant(uuid),openpc.matches_privacy(uuid),openpc.current_participant_id(),openpc.current_privacy_domain_id(),openpc.current_operation_id(),openpc.current_action_intent_id()
 TO openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap;
GRANT EXECUTE ON FUNCTION openpc.signing_canonical_json(jsonb),openpc.business_cbor_item(bytea,integer,integer),openpc.business_cbor(bytea),openpc.business_bytes(bytea),openpc.archive_cose_binding(bytea,bytea,text,integer,integer),openpc.operations_generation_source_authenticated(text,uuid),openpc.operations_source_authentication_valid(jsonb)
 TO openpc_operations_qualification_owner;
SET ROLE openpc_control_owner;
${['operations_installation', 'operations_generation']
  .map(
    (table) => `
GRANT SELECT,UPDATE ON control.${table} TO openpc_operations_qualification_owner${table === 'operations_installation' ? ',openpc_operations_qualification_bootstrap' : ''};
DROP POLICY IF EXISTS qualification_source_read ON control.${table};
CREATE POLICY qualification_source_read ON control.${table} FOR SELECT TO openpc_operations_qualification_owner${table === 'operations_installation' ? ',openpc_operations_qualification_bootstrap' : ''}
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) AND openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1');
DROP POLICY IF EXISTS qualification_source_lock ON control.${table};
CREATE POLICY qualification_source_lock ON control.${table} FOR UPDATE TO openpc_operations_qualification_owner${table === 'operations_installation' ? ',openpc_operations_qualification_bootstrap' : ''}
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) AND openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1') WITH CHECK(false);`,
  )
  .join('\n')}
`;
