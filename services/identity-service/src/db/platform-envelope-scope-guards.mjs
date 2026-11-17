import { identityEnvelopeContext } from '../../../../packages/security-kernel/src/identity-envelope/generated.ts';

/** Independent SQL validation of the frozen24034 Scope subset. The existing
 * canonical CBOR owner enforces minimal integers, map order, UTF8/NFC and bounds. */
export const platformEnvelopeScopeGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.identity_envelope_scope_valid(p_bytes bytea)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE scope jsonb; module jsonb; items jsonb; item jsonb; previous bytea; current_bytes bytea;
 dimension integer; module_id integer; value text;
BEGIN
 scope:=openpc.business_cbor(p_bytes);
 IF jsonb_typeof(scope) IS DISTINCT FROM 'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(scope) key) IS DISTINCT FROM ARRAY['1','2','3','4','5','6','7'] THEN RETURN false; END IF;
 FOR dimension IN 3..7 LOOP
  IF jsonb_typeof(scope->dimension::text)<>'number' OR (scope->>dimension::text)!~'^(0|[1-9][0-9]{0,19})$' THEN RETURN false; END IF;
 END LOOP;
 IF (scope->>'3')::numeric>18446744073709551615 OR (scope->>'4')::numeric>18446744073709551615
   OR (scope->>'4')::numeric<=(scope->>'3')::numeric OR mod((scope->>'3')::numeric,1000)<>0
   OR mod((scope->>'4')::numeric,1000)<>0 OR (scope->>'5')::numeric NOT IN(0,1)
   OR (scope->>'6')::numeric NOT IN(0,1) OR (scope->>'7')::numeric>32 THEN RETURN false; END IF;
 FOR module_id IN 1..2 LOOP
  module:=scope->module_id::text;
  IF jsonb_typeof(module) IS DISTINCT FROM 'object' OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(module) key) IS DISTINCT FROM ARRAY['1','2','3','4','5','6','7'] THEN RETURN false; END IF;
  FOR dimension IN 1..7 LOOP
   items:=module->dimension::text; previous:=NULL;
   IF jsonb_typeof(items)<>'array' OR jsonb_array_length(items)>256 THEN RETURN false; END IF;
   FOR item IN SELECT v FROM jsonb_array_elements(items) v LOOP
    IF dimension IN(1,2) THEN
     IF jsonb_typeof(item)<>'object' OR jsonb_typeof(item->'bytes') IS DISTINCT FROM 'string' OR item<>jsonb_build_object('bytes',item->>'bytes')
       OR (item->>'bytes')!~'^[0-9a-f]{12}[1-8][0-9a-f]{3}[89ab][0-9a-f]{15}$' THEN RETURN false; END IF;
     current_bytes:=decode(item->>'bytes','hex');
    ELSE
     IF jsonb_typeof(item)<>'string' THEN RETURN false; END IF;
     value:=item#>>'{}'; current_bytes:=convert_to(value,'UTF8');
     IF octet_length(current_bytes) NOT BETWEEN 1 AND 160 OR value!~'^[A-Za-z0-9][A-Za-z0-9:._/-]*$' THEN RETURN false; END IF;
     IF dimension=6 AND value NOT IN('BREAK_GLASS','HIGH','LOW','STANDARD') THEN RETURN false; END IF;
     IF dimension=7 AND module_id=1 AND value!~'^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$' THEN RETURN false; END IF;
     IF dimension=7 AND module_id=2 AND value NOT IN('CALL_RESULT_DISCLOSURE','GAS_ESTIMATE_DISCLOSURE','ACCESS_LIST_DISCLOSURE',
       'UNSIGNED_TRANSACTION_PREPARATION','SIGNED_TRANSACTION_SUBMISSION','OPERATION_STATUS_DISCLOSURE','MULTI_CALL_SIMULATION_DISCLOSURE') THEN RETURN false; END IF;
    END IF;
    IF previous IS NOT NULL AND current_bytes<=previous THEN RETURN false; END IF;
    previous:=current_bytes;
   END LOOP;
  END LOOP;
 END LOOP;
 RETURN true;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_platform_envelope_scope()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE expected jsonb;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PC-AUTH-0005-IMMUTABLE-PLATFORM-SCOPE'; END IF;
 IF current_user<>'openpc_control_owner' OR NOT pg_has_role(session_user,'openpc_control_owner','MEMBER')
   OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
   OR NEW.installed_by<>session_user THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-INSTALLATION-AUTHORITY'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF NOT openpc.matches_participant(NEW.owner_participant_id) OR NOT openpc.matches_privacy(NEW.installation_privacy_domain_id)
   OR NEW.platform_authority_epoch<>1 OR NEW.admission_version<>1 OR NOT openpc.identity_envelope_scope_valid(NEW.scope_cbor)
   THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-BINDING'; END IF;
 -- Configuration's installation owner creates this source before this adapter;
 -- the Identity migration may be installed before that cross-lane table exists.
 PERFORM 1 FROM control.participant WHERE participant_id=NEW.owner_participant_id AND state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-INSTALLATION-PARTICIPANT'; END IF;
 PERFORM 1 FROM control.privacy_domain WHERE participant_id=NEW.owner_participant_id
  AND privacy_domain_id=NEW.installation_privacy_domain_id AND state='ACTIVE' FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-INSTALLATION-PRIVACY'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('operations-generation:'||NEW.environment_id,0))
  THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-INSTALLATION-BUSY'; END IF;
 PERFORM 1 FROM control.operations_installation i
  WHERE i.participant_id=NEW.owner_participant_id AND i.privacy_domain_id=NEW.installation_privacy_domain_id
    AND i.environment_id=NEW.environment_id AND i.state='ACTIVE' AND i.installation_digest=NEW.installation_digest
    AND openpc.operations_source_authentication_valid(i.installation)
    AND NOT EXISTS(SELECT 1 FROM control.operations_generation_commit c WHERE c.environment_id=i.environment_id)
  FOR SHARE OF i;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-INSTALLATION-PROVENANCE'; END IF;
 PERFORM 1 FROM control.platform_context p WHERE p.platform_context_id=NEW.platform_context_id
   AND p.owner_participant_id=NEW.owner_participant_id AND p.authority_epoch=NEW.platform_authority_epoch AND p.state='ACTIVE'
   AND p.row_version=1 AND p.xmin=(mod(pg_current_xact_id()::text::numeric,4294967296))::text::xid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-INITIAL-ROOT'; END IF;
 expected:=jsonb_build_array('pc.identity.platform-envelope-scope.v1',24034,1,
  openpc.business_bytes(decode('${identityEnvelopeContext.definitionDigest.slice(7)}','hex')),
  openpc.business_uuid(NEW.platform_context_id),openpc.business_uuid(NEW.owner_participant_id),
  openpc.business_uuid(NEW.installation_privacy_domain_id),NEW.platform_authority_epoch,NEW.environment_id,
  openpc.business_bytes(decode(substring(NEW.installation_digest FROM 8),'hex')),openpc.business_bytes(NEW.scope_cbor));
 IF openpc.business_cbor(NEW.admission_preimage) IS DISTINCT FROM expected OR NEW.admission_digest<>sha256(NEW.admission_preimage)
   THEN RAISE EXCEPTION 'PC-AUTH-0005-PLATFORM-SCOPE-DIGEST'; END IF;
 NEW.installed_at:=clock_timestamp();
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS platform_envelope_scope_guard ON control.platform_envelope_scope;
CREATE TRIGGER platform_envelope_scope_guard BEFORE INSERT OR UPDATE OR DELETE ON control.platform_envelope_scope
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_platform_envelope_scope();
`;
