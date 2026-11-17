/** Explicit named self-session scope. Original target IDs remain in assertions,
 * receipts and mutations. This relation is never a caller-selected alias. */
export const administrationResourceScopeSql = `
CREATE OR REPLACE FUNCTION openpc.administration_resource_permits(
 resources text[], target text, action text, participant uuid, principal uuid, authenticated_session uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT coalesce(target=ANY(resources) OR '*'=ANY(resources) OR (
   action IN('ACT-IDENTITY_UPDATE_STEP_UP-V1','ACT-IDENTITY_DELETE_SESSION-V1')
   AND authenticated_session IS NOT NULL AND target=authenticated_session::text
   AND ('urn:openpc:self-session:'||principal::text)=ANY(resources)
   AND openpc.matches_participant(participant)
   AND EXISTS(SELECT 1 FROM control.session s WHERE s.participant_id=participant
     AND s.session_id=authenticated_session AND s.principal_id=principal AND s.state='ACTIVE'
     AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()
     AND ((s.context_mode='PARTICIPANT' AND openpc.matches_privacy(s.privacy_domain_id))
       OR (s.context_mode='PLATFORM' AND s.privacy_domain_id IS NULL AND EXISTS(
         SELECT 1 FROM control.participant p WHERE p.participant_id=participant
           AND openpc.matches_privacy(p.root_privacy_domain_id)))))
 ),false)
$$;
REVOKE ALL ON FUNCTION openpc.administration_resource_permits(text[],text,text,uuid,uuid,uuid) FROM PUBLIC;
`;

export const administrationResourceScopeGrantsSql = `GRANT EXECUTE ON FUNCTION openpc.administration_resource_permits(text[],text,text,uuid,uuid,uuid)
 TO openpc_control_owner,openpc_control_runtime,openpc_control_platform_runtime;
`;
