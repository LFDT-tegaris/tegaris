import { evidenceExportCoseContext } from '../../../../packages/security-kernel/src/evidence-export/generated.ts';

/** Privileged public trust registration only. This does not admit a completion,
 * grant provider key access, or authenticate a workload transport. */
export const evidenceExportProducerGuardsSql = String.raw`
ALTER TABLE control.evidence_export_producer_installation FORCE ROW LEVEL SECURITY;
GRANT SELECT,INSERT,UPDATE ON control.evidence_export_producer_installation TO openpc_control_owner;
DROP POLICY IF EXISTS evidence_export_producer_installer ON control.evidence_export_producer_installation;
CREATE POLICY evidence_export_producer_installer ON control.evidence_export_producer_installation
 TO openpc_control_owner USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
REVOKE ALL ON control.evidence_export_producer_installation FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_export_producer_installation TO openpc_control_worker,openpc_control_runtime;

-- The non-superuser installation owner verifies only the scoped initial
-- credential tuple. Runtime principals receive no enrollment or Identity writes.
DROP POLICY IF EXISTS export_producer_installation_identity_read ON control.credential;
CREATE POLICY export_producer_installation_identity_read ON control.credential FOR SELECT TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.current_action_intent_id()='ACT-EVIDENCE_EXPORT_RECORDS-V1');

CREATE OR REPLACE FUNCTION openpc.evidence_export_producer_authority(wanted text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE installed control.evidence_export_producer_installation; authority jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 SELECT * INTO STRICT installed FROM control.evidence_export_producer_installation
 WHERE participant_id=openpc.current_participant_id() AND privacy_domain_id=openpc.current_privacy_domain_id()
 AND trust_digest=wanted AND state='ACTIVE';
select jsonb_build_object('schema','pc.evidence-export.producer-authority.v1',
      'installationDigest',(installed.trust_digest)::text,'participantEpoch',p.authority_epoch::text,'principalEpoch',a.authority_epoch::text,
      'workloadEpoch',c.credential_epoch::text,'workloadCredentialId',c.credential_id::text,
      'participantId',p.participant_id::text,'privacyDomainId',d.privacy_domain_id::text,
      'principalId',a.principal_id::text,'workloadId',c.audience,'certificateFingerprint',c.secret_fingerprint,
      'keyDigest','sha256:'||encode(c.public_key_digest,'hex'),
      'participantVersion',p.row_version::text,'privacyVersion',d.row_version::text,
      'principalVersion',a.row_version::text,'credentialVersion',c.row_version::text,
      'subject',c.subject,'validFrom',c.valid_from::text,'validUntil',c.valid_until::text) authority
      INTO STRICT authority
      from control.participant p join control.privacy_domain d on d.participant_id=p.participant_id
      join control.principal a on a.participant_id=p.participant_id
      join control.credential c on c.participant_id=a.participant_id and c.principal_id=a.principal_id
      where p.participant_id=(installed.participant_id) and d.privacy_domain_id=(installed.privacy_domain_id) and a.principal_id=(installed.principal_id) and c.credential_id=(installed.workload_credential_id)
      and p.state='ACTIVE' and d.state='ACTIVE' and a.state='ACTIVE' and a.kind='WORKLOAD'
      and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and c.credential_epoch=(installed.workload_epoch) and c.audience=(installed.trust->>'workloadId')
      and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
      and c.public_key_digest<>decode(substring((installed.signer_id)::text from 8),'hex')
      and floor(extract(epoch from clock_timestamp())*1000000)*1000 between (installed.trust->>'validFromNs')::numeric and (installed.trust->>'validUntilNs')::numeric-1 FOR SHARE OF p,d,a,c;
 RETURN authority;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RAISE EXCEPTION 'PC-AUTH-0005-EXPORT-PRODUCER';
END $$;
REVOKE ALL ON FUNCTION openpc.evidence_export_producer_authority(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.evidence_export_producer_authority(text) TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_export_producer_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE t jsonb;
BEGIN
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM openpc.assert_request_context(true);
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-EXPORT-PRODUCER-IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
   OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
   OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 -- A direct UPDATE already has its row lock. Do not wait in reverse order.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-export-producer:'||NEW.participant_id::text||':'||NEW.privacy_domain_id::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_OP='UPDATE' THEN
   IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
   THEN RAISE EXCEPTION 'DATA-6020-EXPORT-PRODUCER-IMMUTABLE'; END IF;
   RETURN NEW;
 END IF;
 t:=NEW.trust;
 IF NEW.state<>'ACTIVE' OR jsonb_typeof(t) IS DISTINCT FROM 'object'
   OR t - ARRAY['schema','schemaDefinitionDigest','owner','purpose','environmentId','participantId','privacyDomainId','sourceId','principalId','workloadCredentialId','workloadEpoch','workloadId','secretClass','secretReference','secretVersion','publicKeySpkiHex','keyEpoch','validFromNs','validUntilNs','installationReference','signerKeyId'] IS DISTINCT FROM '{}'::jsonb
   OR (SELECT count(*) FROM jsonb_object_keys(t))<>21
   OR t->>'schema' IS DISTINCT FROM 'pc.evidence-export.producer-trust.v1'
   OR t->>'schemaDefinitionDigest' IS DISTINCT FROM '${evidenceExportCoseContext.definitionDigest}'
   OR t->>'owner' IS DISTINCT FROM 'LS-EVIDENCE-EXPORT'
   OR t->>'purpose' IS DISTINCT FROM 'pc.cose.evidence-export-completion-receipt.v1'
   OR t->>'secretClass' IS DISTINCT FROM 'SECRET-SIGNING-KEY'
   OR t->>'participantId' IS DISTINCT FROM NEW.participant_id::text
   OR t->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
   OR t->>'sourceId' IS DISTINCT FROM NEW.source_id::text
   OR t->>'principalId' IS DISTINCT FROM NEW.principal_id::text
   OR t->>'workloadCredentialId' IS DISTINCT FROM NEW.workload_credential_id::text
   OR t->>'workloadEpoch' IS DISTINCT FROM NEW.workload_epoch::text
   OR t->>'environmentId' IS DISTINCT FROM NEW.environment_id
   OR t->>'signerKeyId' IS DISTINCT FROM NEW.signer_id
   OR EXISTS(SELECT 1 FROM jsonb_each(t) e WHERE jsonb_typeof(e.value)<>'string' OR e.value#>>'{}'<>btrim(e.value#>>'{}'))
   OR NOT coalesce(t->>'environmentId' ~ '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$',false)
   OR NOT coalesce(t->>'secretReference' ~ '^secret://[a-z][a-z0-9-]{1,31}/[A-Za-z0-9._/-]{1,192}#[A-Za-z0-9._-]{1,96}$',false)
   OR split_part(t->>'secretReference','#',2) IS DISTINCT FROM t->>'secretVersion'
   OR lower(t->>'secretVersion') IN ('latest','current')
   OR length(t->>'workloadId') NOT BETWEEN 1 AND 160 OR length(t->>'installationReference') NOT BETWEEN 1 AND 256
   OR NEW.trust_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(t),'UTF8')
   OR NEW.signer_id IS DISTINCT FROM 'sha256:'||encode(sha256(decode(t->>'publicKeySpkiHex','hex')),'hex')
   OR NOT coalesce(t->>'publicKeySpkiHex' ~ '^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$',false)
   OR NOT coalesce(t->>'keyEpoch' ~ '^[1-9][0-9]{0,19}$',false)
   OR NOT coalesce(t->>'validFromNs' ~ '^(0|[1-9][0-9]{0,19})$',false)
   OR NOT coalesce(t->>'validUntilNs' ~ '^[1-9][0-9]{0,19}$',false)
 THEN RAISE EXCEPTION 'DATA-6021-EXPORT-PRODUCER-TRUST'; END IF;
 IF (t->>'keyEpoch')::numeric>18446744073709551615 OR (t->>'validUntilNs')::numeric>18446744073709551615
   OR (t->>'validFromNs')::numeric>=(t->>'validUntilNs')::numeric
   OR mod((t->>'validFromNs')::numeric,1000)<>0 OR mod((t->>'validUntilNs')::numeric,1000)<>0
   OR NOT EXISTS(SELECT 1 FROM control.credential c WHERE c.participant_id=NEW.participant_id
      AND c.credential_id=NEW.workload_credential_id AND c.principal_id=NEW.principal_id
      AND c.kind='WORKLOAD_MTLS' AND c.audience=t->>'workloadId'
      AND c.credential_epoch=NEW.workload_epoch
      AND c.public_key_digest<>decode(substr(NEW.signer_id,8),'hex'))
 THEN RAISE EXCEPTION 'DATA-6021-EXPORT-PRODUCER-IDENTITY'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_export_producer_installation_guard ON control.evidence_export_producer_installation;
CREATE TRIGGER evidence_export_producer_installation_guard BEFORE INSERT OR UPDATE OR DELETE
 ON control.evidence_export_producer_installation FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_export_producer_installation();
`;
