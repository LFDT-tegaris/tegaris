/** Initial configuration custody. Privileged input authentication belongs to the
 * installer; runtime has read-only scope-limited access and cannot install trust. */
export const notificationRoutingInstallationGuardsSql = String.raw`
ALTER TABLE control.installed_notification_routing FORCE ROW LEVEL SECURITY;
GRANT EXECUTE ON FUNCTION openpc.evidence_export_producer_authority(text) TO openpc_control_owner;
GRANT SELECT ON control.notification_endpoint,control.notification_endpoint_verification,control.installed_notification_channel TO openpc_control_owner;
DROP POLICY IF EXISTS notification_routing_installer_endpoint ON control.notification_endpoint;
CREATE POLICY notification_routing_installer_endpoint ON control.notification_endpoint FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) AND openpc.current_action_intent_id()='ACT-EVIDENCE_EXPORT_RECORDS-V1');
DROP POLICY IF EXISTS notification_routing_installer_verification ON control.notification_endpoint_verification;
CREATE POLICY notification_routing_installer_verification ON control.notification_endpoint_verification FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id) AND openpc.current_action_intent_id()='ACT-EVIDENCE_EXPORT_RECORDS-V1');
REVOKE ALL ON control.installed_notification_routing FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.installed_notification_routing TO openpc_control_runtime;
GRANT SELECT,INSERT,UPDATE ON control.installed_notification_routing TO openpc_control_owner;
DROP POLICY IF EXISTS notification_routing_installer ON control.installed_notification_routing;
CREATE POLICY notification_routing_installer ON control.installed_notification_routing TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
CREATE OR REPLACE FUNCTION openpc.guard_notification_routing_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE')
  OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
  OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND (OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'))
  OR (TG_OP='INSERT' AND NEW.state<>'ACTIVE') THEN RAISE EXCEPTION 'DATA-6020-NOTIFICATION-ROUTING-IMMUTABLE'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('notification-routing:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text||':'||NEW.profile_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF convert_from(NEW.installation_bytes,'UTF8') IS DISTINCT FROM openpc.signing_canonical_json(NEW.installation)
  OR NEW.installation->'trust'->>'participantId' IS DISTINCT FROM NEW.participant_id::text
  OR NEW.installation->'trust'->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
  OR NEW.installation->'trust'->>'signedProfileDigest' IS DISTINCT FROM NEW.signed_profile_digest
  OR NEW.installation->>'producerTrustDigest' IS DISTINCT FROM NEW.producer_trust_digest
  OR NEW.installation->'recipientSet'->>'endpointId' IS DISTINCT FROM NEW.endpoint_id::text
 THEN RAISE EXCEPTION 'DATA-6020-NOTIFICATION-ROUTING-BINDING'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS notification_routing_installation_guard ON control.installed_notification_routing;
CREATE TRIGGER notification_routing_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.installed_notification_routing
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_notification_routing_installation();
`;
