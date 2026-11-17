/** Identity authenticates the live TLS peer. SQL accepts only its private MAC
 * bound to this login/backend/transaction and rechecks current dependency rows.
 * No authentication occurrence, role, GUC or caller digest is proof of TLS. */
const bodies = `
CREATE OR REPLACE FUNCTION openpc.check_notification_completion_phase_proof(proof jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE now_ms numeric; p uuid; privacy uuid; installation record;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 PERFORM openpc.assert_request_context(true);
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF current_setting('transaction_isolation')<>'read committed'
  OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
  OR jsonb_typeof(proof) IS DISTINCT FROM 'object'
  OR proof IS DISTINCT FROM jsonb_build_object('version',2,'receiptBinding',proof->'receiptBinding','transactionId',pg_current_xact_id()::text,
   'backendPid',pg_backend_pid(),'databaseRole',session_user,
   'participantId',openpc.current_participant_id()::text,'privacyDomainId',openpc.current_privacy_domain_id()::text,
   'eventId',proof->'eventId','phase',proof->'phase','installationDigest',proof->'installationDigest',
   'authorityDigest',proof->'authorityDigest','principalId',proof->'principalId','credentialId',proof->'credentialId',
   'participantEpoch',proof->'participantEpoch','principalEpoch',proof->'principalEpoch','workloadEpoch',proof->'workloadEpoch',
   'workloadId',proof->'workloadId','uriSan',proof->'uriSan','keyId',proof->'keyId',
   'issuedAtMs',proof->'issuedAtMs','expiresAtMs',proof->'expiresAtMs')
  OR coalesce(proof->>'phase','') NOT IN ('SOURCE','CLAIM','LIMIT','FINISH','PREPARE','SIGN_CLAIM','OBSERVE','PUBLISH')
  OR EXISTS(SELECT 1 FROM (VALUES('eventId'),('principalId'),('credentialId')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM 'string' OR coalesce(proof->>f.name,'') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
  OR EXISTS(SELECT 1 FROM (VALUES('installationDigest'),('authorityDigest'),('keyId')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM 'string' OR coalesce(proof->>f.name,'') !~ '^sha256:[0-9a-f]{64}$')
  OR EXISTS(SELECT 1 FROM (VALUES('participantEpoch'),('principalEpoch'),('workloadEpoch')) f(name)
   WHERE jsonb_typeof(proof->f.name) IS DISTINCT FROM 'string' OR coalesce(proof->>f.name,'') !~ '^[1-9][0-9]{0,19}$')
  OR jsonb_typeof(proof->'issuedAtMs') IS DISTINCT FROM 'number'
  OR jsonb_typeof(proof->'expiresAtMs') IS DISTINCT FROM 'number'
  OR (proof->>'issuedAtMs')::numeric<>trunc((proof->>'issuedAtMs')::numeric)
  OR (proof->>'expiresAtMs')::numeric<>trunc((proof->>'expiresAtMs')::numeric)
  OR (proof->>'issuedAtMs')::numeric>now_ms OR (proof->>'issuedAtMs')::numeric<now_ms-5000
  OR (proof->>'expiresAtMs')::numeric<=now_ms
  OR (proof->>'expiresAtMs')::numeric>(proof->>'issuedAtMs')::numeric+5000
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-PROOF'; END IF;
 IF proof->'receiptBinding' IS DISTINCT FROM 'null'::jsonb THEN
  IF proof->>'phase' NOT IN ('OBSERVE','PUBLISH') OR jsonb_typeof(proof->'receiptBinding') IS DISTINCT FROM 'object'
   OR proof->'receiptBinding' IS DISTINCT FROM jsonb_build_object(
    'schema','pc.notification.completion-verified-receipt.v1','purpose','pc.cose.notification-completion-disposition-receipt.v1',
    'requestDigest',proof->'receiptBinding'->'requestDigest','preparationDigest',proof->'receiptBinding'->'preparationDigest',
    'payloadDigest',proof->'receiptBinding'->'payloadDigest','coseDigest',proof->'receiptBinding'->'coseDigest',
    'observationDigest',proof->'receiptBinding'->'observationDigest','signerInstallationDigest',proof->'receiptBinding'->'signerInstallationDigest',
    'signerKeyId',proof->'receiptBinding'->'signerKeyId','originalWorkerInstallationDigest',proof->'receiptBinding'->'originalWorkerInstallationDigest',
    'producerTrustDigest',proof->'receiptBinding'->'producerTrustDigest','environmentId',proof->'receiptBinding'->'environmentId')
   OR EXISTS(SELECT 1 FROM (VALUES('requestDigest'),('preparationDigest'),('payloadDigest'),('coseDigest'),('observationDigest'),
     ('signerInstallationDigest'),('signerKeyId'),('originalWorkerInstallationDigest'),('producerTrustDigest')) f(name)
     WHERE jsonb_typeof(proof->'receiptBinding'->f.name) IS DISTINCT FROM 'string'
      OR coalesce(proof->'receiptBinding'->>f.name,'') !~ '^sha256:[0-9a-f]{64}$')
   OR jsonb_typeof(proof->'receiptBinding'->'environmentId') IS DISTINCT FROM 'string'
   OR length(proof->'receiptBinding'->>'environmentId') NOT BETWEEN 1 AND 160
  THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-RECEIPT'; END IF;
 END IF;
 p:=openpc.current_participant_id(); privacy:=openpc.current_privacy_domain_id();
 -- The Identity callback holds the authority fences. These exact row locks
 -- also prevent a direct verifier invocation racing a committed withdrawal.
 PERFORM 1 FROM control.participant x WHERE x.participant_id=p AND x.state='ACTIVE'
  AND x.authority_epoch::text=proof->>'participantEpoch' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CURRENT'; END IF;
 PERFORM 1 FROM control.privacy_domain x WHERE x.participant_id=p AND x.privacy_domain_id=privacy
  AND x.state='ACTIVE' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CURRENT'; END IF;
 PERFORM 1 FROM control.principal x WHERE x.participant_id=p AND x.principal_id=(proof->>'principalId')::uuid
  AND x.kind='WORKLOAD' AND x.state='ACTIVE' AND x.authority_epoch::text=proof->>'principalEpoch' FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CURRENT'; END IF;
 PERFORM 1 FROM control.credential x WHERE x.participant_id=p AND x.credential_id=(proof->>'credentialId')::uuid
  AND x.principal_id=(proof->>'principalId')::uuid AND x.kind='WORKLOAD_MTLS' AND x.state='ACTIVE'
  AND x.credential_epoch::text=proof->>'workloadEpoch' AND x.audience=proof->>'workloadId'
  AND x.subject=proof->>'uriSan' AND x.public_key_digest=decode(substring(proof->>'keyId' from 8),'hex')
  AND x.valid_from<=clock_timestamp() AND x.valid_until>clock_timestamp()
  AND extract(epoch from x.valid_until)*1000>=(proof->>'expiresAtMs')::numeric FOR SHARE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CURRENT'; END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended('notification-completion-worker:'||p::text||':'||privacy::text,0))
 THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 PERFORM openpc.assert_notification_completion_worker_installation_owner();
 SELECT * INTO STRICT installation FROM control.installed_notification_completion_worker x
  WHERE x.participant_id=p AND x.privacy_domain_id=privacy AND x.installation_digest=proof->>'installationDigest'
   AND x.state='ACTIVE' AND x.principal_id=(proof->>'principalId')::uuid
   AND x.workload_credential_id=(proof->>'credentialId')::uuid
   AND x.service_id='LS-CONTROL-WORK' AND x.subscription_id='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1' FOR SHARE NOWAIT;
 IF installation.installation->'pins'->>'workloadEpoch' IS DISTINCT FROM proof->>'workloadEpoch'
  OR installation.installation->'pins'->>'workloadId' IS DISTINCT FROM proof->>'workloadId'
  OR installation.installation->'pins'->>'workloadKeyDigest' IS DISTINCT FROM proof->>'keyId'
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-WORKER'; END IF;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'PC-DATA-6007';
END $$;

CREATE OR REPLACE FUNCTION openpc.admit_notification_completion_phase(wire bytea,nonce bytea,mac bytea) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE proof jsonb; secret bytea; expected bytea; different integer:=0;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 IF wire IS NULL OR octet_length(wire) NOT BETWEEN 1 AND 8192 OR nonce IS NULL OR octet_length(nonce)<>32
  OR mac IS NULL OR octet_length(mac)<>32 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT verifier_secret INTO STRICT secret FROM control.notification_completion_admission_key WHERE database_role=session_user;
 expected:=public.hmac(convert_to('OPENPC_NOTIFICATION_COMPLETION_PHASE_ADMISSION_V1','UTF8')||sha256(wire)||nonce,secret,'sha256');
 FOR i IN 0..31 LOOP different:=different | (get_byte(expected,i) # get_byte(mac,i)); END LOOP;
 IF different<>0 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 proof:=convert_from(wire,'UTF8')::jsonb;
 PERFORM openpc.check_notification_completion_phase_proof(proof);
 INSERT INTO control.notification_completion_phase_admission(database_role,transaction_id,backend_pid,
  participant_id,privacy_domain_id,event_id,phase,proof,receipt_binding)
 VALUES(session_user,pg_current_xact_id()::text,pg_backend_pid(),openpc.current_participant_id(),
  openpc.current_privacy_domain_id(),(proof->>'eventId')::uuid,proof->>'phase',proof,nullif(proof->'receiptBinding','null'::jsonb))
 ON CONFLICT(database_role,transaction_id,event_id,phase) DO UPDATE SET proof=excluded.proof,receipt_binding=excluded.receipt_binding
 WHERE notification_completion_phase_admission.participant_id=excluded.participant_id
  AND notification_completion_phase_admission.privacy_domain_id=excluded.privacy_domain_id
  AND notification_completion_phase_admission.backend_pid=excluded.backend_pid
  AND notification_completion_phase_admission.proof->>'installationDigest'=excluded.proof->>'installationDigest'
  AND notification_completion_phase_admission.proof->>'authorityDigest'=excluded.proof->>'authorityDigest'
  AND (notification_completion_phase_admission.receipt_binding IS NULL
   OR notification_completion_phase_admission.receipt_binding=excluded.receipt_binding);
 IF NOT FOUND THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-CONFLICT'; END IF;
END $$;

CREATE OR REPLACE FUNCTION openpc.require_notification_completion_disposition_authority(event uuid,phase text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE original jsonb;
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 SELECT a.proof INTO STRICT original FROM control.notification_completion_phase_admission a
 WHERE a.database_role=session_user AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
  AND a.event_id=event AND a.phase=$2;
 PERFORM openpc.check_notification_completion_phase_proof(original);
END $$;

CREATE OR REPLACE FUNCTION openpc.clear_notification_completion_phases() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
BEGIN
 PERFORM openpc.assert_notification_completion_admission_owner();
 PERFORM openpc.assert_request_context(true);
 DELETE FROM control.notification_completion_phase_admission a WHERE a.database_role=session_user
  AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id();
END $$;

CREATE OR REPLACE FUNCTION openpc.notification_completion_verified_receipt(event uuid,phase text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
DECLARE verified jsonb;
BEGIN
 PERFORM openpc.require_notification_completion_disposition_authority(event,phase);
 IF phase IS NULL OR phase NOT IN ('OBSERVE','PUBLISH') THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-RECEIPT'; END IF;
 SELECT a.receipt_binding INTO STRICT verified FROM control.notification_completion_phase_admission a
  WHERE a.database_role=session_user AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
   AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
   AND a.event_id=event AND a.phase=$2 AND a.receipt_binding=a.proof->'receiptBinding';
 IF verified IS NULL THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-RECEIPT'; END IF;
 RETURN verified;
END $$;

CREATE OR REPLACE FUNCTION openpc.notification_completion_phase_binding(event uuid,phase text)
RETURNS TABLE(installation_digest text,authority_digest text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET row_security=on AS $$
BEGIN
 PERFORM openpc.require_notification_completion_disposition_authority(event,phase);
 RETURN QUERY SELECT a.proof->>'installationDigest',a.proof->>'authorityDigest'
 FROM control.notification_completion_phase_admission a WHERE a.database_role=session_user
  AND a.transaction_id=pg_current_xact_id()::text AND a.backend_pid=pg_backend_pid()
  AND a.participant_id=openpc.current_participant_id() AND a.privacy_domain_id=openpc.current_privacy_domain_id()
  AND a.event_id=event AND a.phase=$2;
END $$;
`;
const quote = (value) => `'${value.replaceAll("'", "''")}'`;
const functions = [
  ['check_notification_completion_phase_proof', 'jsonb'],
  ['admit_notification_completion_phase', 'bytea,bytea,bytea'],
  ['require_notification_completion_disposition_authority', 'uuid,text'],
  ['clear_notification_completion_phases', ''],
  ['notification_completion_phase_binding', 'uuid,text'],
  ['notification_completion_verified_receipt', 'uuid,text'],
];
const checks = functions.map(([name, args]) => {
  const start = bodies.indexOf(`CREATE OR REPLACE FUNCTION openpc.${name}(`),
    begin = bodies.indexOf('AS $$', start),
    end = bodies.indexOf('$$;', begin);
  if (start < 0 || begin < start || end < begin) throw new Error('Native completion owner missing');
  return `NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_language l ON l.oid=p.prolang
   WHERE p.oid=to_regprocedure('openpc.${name}(${args})') AND r.rolname='openpc_control_owner'
   AND l.lanname='plpgsql' AND p.prosecdef AND p.provolatile='v'
   AND p.proconfig=ARRAY['search_path=pg_catalog','row_security=on'] AND p.prosrc=${quote(bodies.slice(begin + 5, end))})`;
});
export const notificationCompletionAdmissionSql = `${bodies}
CREATE OR REPLACE FUNCTION openpc.assert_notification_completion_admission_owner() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF current_setting('row_security')<>'on' OR current_setting('session_replication_role')<>'origin'
 OR ${checks.join('\n OR ')}
 OR EXISTS(SELECT 1 FROM unnest(ARRAY['notification_completion_admission_key','notification_completion_phase_admission']) n(name)
  WHERE NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
   WHERE c.oid=to_regclass('control.'||n.name) AND c.relkind='r' AND NOT c.relispartition AND r.rolname='openpc_control_owner'
    AND NOT EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=c.oid OR inhparent=c.oid))
   OR EXISTS(SELECT 1 FROM unnest(ARRAY['openpc_control_runtime','openpc_control_platform_runtime','openpc_control_worker','openpc_control_reader']) role(name)
    WHERE has_table_privilege(role.name,'control.'||n.name,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
     OR has_any_column_privilege(role.name,'control.'||n.name,'SELECT,INSERT,UPDATE'))
   OR EXISTS(SELECT 1 FROM pg_class c,aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
    WHERE c.oid=to_regclass('control.'||n.name) AND a.grantee=0))
 OR NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='control.notification_completion_phase_admission'::regclass AND relrowsecurity AND relforcerowsecurity)
 THEN RAISE EXCEPTION 'NOTIFICATION-COMPLETION-NATIVE-OWNER'; END IF;
END $$;
`;
export const notificationCompletionAdmissionGrantsSql = `
REVOKE ALL ON control.notification_completion_admission_key,control.notification_completion_phase_admission
 FROM PUBLIC,openpc_control_runtime,openpc_control_platform_runtime,openpc_control_worker,openpc_control_reader,openpc_control_maintenance,openpc_backup_operator;
ALTER TABLE control.notification_completion_phase_admission FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS notification_completion_native_owner ON control.notification_completion_phase_admission;
CREATE POLICY notification_completion_native_owner ON control.notification_completion_phase_admission TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));
REVOKE ALL ON FUNCTION ${functions.map(([name, args]) => `openpc.${name}(${args})`).join(',')},openpc.assert_notification_completion_admission_owner() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.admit_notification_completion_phase(bytea,bytea,bytea),
 openpc.require_notification_completion_disposition_authority(uuid,text),openpc.clear_notification_completion_phases(),
 openpc.notification_completion_phase_binding(uuid,text),openpc.notification_completion_verified_receipt(uuid,text),
 openpc.assert_notification_completion_admission_owner() TO openpc_control_runtime;
SELECT openpc.assert_notification_completion_admission_owner();
`;
