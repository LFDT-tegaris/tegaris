import { evidenceKmsCoseProfiles } from '../../../../packages/security-kernel/src/evidence-kms/generated.ts';

/** Drizzle owns table creation. This tail enforces immutable public installation
 * trust and irreversible local withdrawal; it is not a provider receipt verifier. */
export const evidenceKmsInstallationGuardsSql = String.raw`
ALTER TABLE control.evidence_kms_installation FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_kms_installation FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT ON control.evidence_kms_installation TO openpc_control_runtime;
GRANT SELECT,INSERT,UPDATE ON control.evidence_kms_installation TO openpc_control_owner;
DROP POLICY IF EXISTS evidence_kms_installer ON control.evidence_kms_installation;
CREATE POLICY evidence_kms_installer ON control.evidence_kms_installation TO openpc_control_owner
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));

CREATE OR REPLACE FUNCTION openpc.guard_evidence_kms_installation() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb; allowed text[]; item text;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_owner','USAGE')
 OR current_setting('openpc.action_intent_id')<>'ACT-EVIDENCE_EXPORT_RECORDS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-EVIDENCE-KMS-IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended('evidence-kms-installation:'||NEW.participant_id::text||':'||
 NEW.privacy_domain_id::text||':'||NEW.installation_id::text,0)) THEN RAISE EXCEPTION 'PC-DATA-6007'; END IF;
 IF TG_OP='UPDATE' THEN
   IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED'
   OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
   THEN RAISE EXCEPTION 'DATA-6020-EVIDENCE-KMS-IMMUTABLE'; END IF;
   RETURN NEW;
 END IF;
 p:=NEW.pins;
 allowed:=ARRAY['owner','secretClass','environmentId','participantId','privacyDomainId','installationId',
 'producerTrustDigest','reference','version','keyEpoch','providerId','providerOrigin','providerTlsSpkiDigest',
 'profileIssuerSpkiHex','providerReceiptSpkiHex','recoveryAuthoritySpkiHex','providerKeyId','providerKeyVersion','wrapProfileDigest',
 'policyDigest','recoveryProfileDigest','profileDigest','permissions','validFromMs','validUntilMs'];
 IF NEW.state<>'ACTIVE' OR jsonb_typeof(p) IS DISTINCT FROM 'object'
 OR p-allowed IS DISTINCT FROM '{}'::jsonb OR NOT p ?& allowed
 OR p->>'owner' IS DISTINCT FROM 'LS-EVIDENCE-EXPORT'
 OR p->>'secretClass' IS DISTINCT FROM 'SECRET-EVIDENCE-VAULT'
 OR p->>'participantId' IS DISTINCT FROM NEW.participant_id::text
 OR p->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
 OR p->>'installationId' IS DISTINCT FROM NEW.installation_id::text
 OR p->>'producerTrustDigest' IS DISTINCT FROM NEW.producer_trust_digest
 OR NEW.pins_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(p),'UTF8')
 OR NEW.installation_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.pins_bytes),'hex')
 OR EXISTS(SELECT 1 FROM jsonb_each(p-ARRAY['permissions','validFromMs','validUntilMs']) e
   WHERE jsonb_typeof(e.value)<>'string' OR e.value#>>'{}'<>btrim(e.value#>>'{}')
   OR e.value#>>'{}' ~ '[[:cntrl:]]')
 OR NOT coalesce(p->>'reference' ~ '^secret://[a-z][a-z0-9-]{1,31}/[A-Za-z0-9._/-]{1,192}#[A-Za-z0-9._-]{1,96}$',false)
 OR split_part(p->>'reference','#',2) IS DISTINCT FROM p->>'version'
 OR split_part(p->>'reference','/',3) IS DISTINCT FROM p->>'providerId'
 OR p->>'reference' ~ '/(\.|\.\.)/' OR p->>'reference' ~ '/(\.|\.\.)#'
 OR p->>'reference' ~ '^secret://[^/]+//|^secret://[^/]+/[^#]*//'
 OR lower(p->>'version') IN ('latest','current')
 OR lower(p->>'providerKeyVersion') IN ('latest','current')
 OR NOT coalesce(p->>'providerOrigin' ~ '^https://[a-z0-9.-]+(:[1-9][0-9]{0,4})?$',false)
 OR NOT coalesce(p->>'environmentId' ~ '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$',false)
 OR length(p->>'providerKeyId') NOT BETWEEN 1 AND 256
 OR length(p->>'providerKeyVersion') NOT BETWEEN 1 AND 96
 OR length(p->>'providerOrigin') NOT BETWEEN 1 AND 512
 OR jsonb_typeof(p->'permissions') IS DISTINCT FROM 'array'
 OR NOT coalesce(p->'permissions' IN ('["ENCRYPT"]'::jsonb,'["DECRYPT"]'::jsonb,'["DECRYPT","ENCRYPT"]'::jsonb),false)
 OR NOT coalesce(p->>'keyEpoch' ~ '^[1-9][0-9]{0,19}$',false)
 OR jsonb_typeof(p->'validFromMs') IS DISTINCT FROM 'number'
 OR jsonb_typeof(p->'validUntilMs') IS DISTINCT FROM 'number'
 OR NOT coalesce(p->>'validFromMs' ~ '^(0|[1-9][0-9]{0,15})$',false)
 OR NOT coalesce(p->>'validUntilMs' ~ '^[1-9][0-9]{0,15}$',false)
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-INSTALLATION'; END IF;
 FOREACH item IN ARRAY ARRAY['producerTrustDigest','providerTlsSpkiDigest','wrapProfileDigest','policyDigest','recoveryProfileDigest','profileDigest'] LOOP
  IF NOT coalesce(p->>item ~ '^sha256:[0-9a-f]{64}$',false) THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-DIGEST'; END IF;
 END LOOP;
 FOREACH item IN ARRAY ARRAY['profileIssuerSpkiHex','providerReceiptSpkiHex','recoveryAuthoritySpkiHex'] LOOP
  IF NOT coalesce(p->>item ~ '^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$',false)
  THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-TRUST'; END IF;
 END LOOP;
 IF p->>'profileIssuerSpkiHex' IN (p->>'providerReceiptSpkiHex',p->>'recoveryAuthoritySpkiHex')
 OR p->>'providerReceiptSpkiHex'=p->>'recoveryAuthoritySpkiHex'
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-ROLE-SEPARATION'; END IF;
 IF (p->>'keyEpoch')::numeric>18446744073709551615
 OR (p->>'validUntilMs')::numeric>9007199254740991
 OR (p->>'validFromMs')::numeric>=(p->>'validUntilMs')::numeric
 OR NOT EXISTS(SELECT 1 FROM control.evidence_export_producer_installation e
   WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id
   AND e.trust_digest=NEW.producer_trust_digest AND e.state='ACTIVE'
   AND e.environment_id=p->>'environmentId')
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-PRODUCER'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_kms_installation_guard ON control.evidence_kms_installation;
CREATE TRIGGER evidence_kms_installation_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_kms_installation
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_kms_installation();
`;

const claimJson = (context) =>
  context.fields
    .slice(1)
    .flatMap((field) => {
      const v = `m->'${field.key}'`;
      let expression = `m->>'${field.key}'`;
      if (field.type === 'H32') expression = `'sha256:'||(${v}->>'bytes')`;
      else if (field.type === 'uuidv7') expression = `(${v}->>'bytes')::uuid::text`;
      else if (field.type === 'hex32' || field.type === 'bytes8192hex')
        expression = `${v}->>'bytes'`;
      return [`'${field.name}'`, expression];
    })
    .join(',');

/** Structural COSE/attempt/role cross-binding for cryptographically verified
 * application results. ECDSA verification remains mandatory in the pinned shared
 * codec. This SQL cannot turn an unsigned provider DTO into a verified result. */
export const evidenceKmsReceiptGuardsSql = String.raw`
CREATE OR REPLACE FUNCTION openpc.evidence_kms_cose_binding(payload bytea,cose bytea,family text,signer text)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE m jsonb; c jsonb; h jsonb; parsed jsonb; wanted_schema integer; wanted_purpose integer; wanted_digest text; wanted_fields integer;
BEGIN
 CASE family
 ${Object.entries(evidenceKmsCoseProfiles)
   .map(
     ([name, c]) =>
       `WHEN '${name}' THEN wanted_schema:=${c.schemaId}; wanted_purpose:=${c.purposeCode}; wanted_digest:='${c.definitionDigest.slice(7)}'; wanted_fields:=${c.fields.length};`,
   )
   .join('\n')}
 ELSE RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-FAMILY'; END CASE;
 IF octet_length(payload) NOT BETWEEN 1 AND 65536 OR octet_length(cose) NOT BETWEEN 1 AND 131072 OR get_byte(cose,0)<>210
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-COSE'; END IF;
 parsed:=openpc.business_cbor_item(cose,1,0); c:=parsed->'value';
 IF (parsed->>'next')::integer<>octet_length(cose) OR jsonb_typeof(c) IS DISTINCT FROM 'array'
 OR jsonb_array_length(c)<>4 OR c->1 IS DISTINCT FROM '{}'::jsonb
 OR c->2 IS DISTINCT FROM jsonb_build_object('bytes',encode(payload,'hex'))
 OR length(c->3->>'bytes') IS DISTINCT FROM 128 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-COSE'; END IF;
 h:=openpc.business_cbor(decode(c->0->>'bytes','hex'));
 IF h IS DISTINCT FROM jsonb_build_object('1',-7,'2',jsonb_build_array(100,101,102,103),'3','application/pc+cbor',
 '4',jsonb_build_object('bytes',encode(convert_to(signer,'UTF8'),'hex')),'100',wanted_schema,'101',1,'102',wanted_purpose,'103',2)
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-ROLE'; END IF;
 m:=openpc.business_cbor(payload);
 IF jsonb_typeof(m) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(m))<>wanted_fields
 OR m->'0' IS DISTINCT FROM jsonb_build_object('bytes',wanted_digest)
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-DEFINITION'; END IF;
 CASE family
 ${Object.entries(evidenceKmsCoseProfiles)
   .map(([name, c]) => `WHEN '${name}' THEN RETURN jsonb_build_object(${claimJson(c)});`)
   .join('\n')}
 END CASE;
END $$;
CREATE OR REPLACE FUNCTION openpc.evidence_kms_stored_outcome(pack bytea)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE p jsonb; m jsonb;
BEGIN
 p:=convert_from(pack,'UTF8')::jsonb;
 m:=openpc.business_cbor(decode(p->'receipt'->>'payloadHex','hex'));
 RETURN m->>'${evidenceKmsCoseProfiles.EvidenceKmsReceiptV1.fields.find((f) => f.name === 'outcome').key}';
END $$;

GRANT INSERT,UPDATE ON control.evidence_kms_exchange TO openpc_control_runtime;
GRANT INSERT ON control.evidence_wrapped_key TO openpc_control_runtime;
CREATE OR REPLACE FUNCTION openpc.guard_evidence_kms_exchange() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a control.evidence_kms_attempt; i control.evidence_kms_installation; request jsonb; pack jsonb;
 p jsonb; r jsonb; f jsonb; k jsonb; item text; now_ms numeric; original_key text; original_use text; fields text[];
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR current_setting('openpc.action_intent_id')<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-EVIDENCE-KMS-IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id() THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT a FROM control.evidence_kms_attempt WHERE participant_id=NEW.participant_id
 AND privacy_domain_id=NEW.privacy_domain_id AND attempt_id=NEW.attempt_id FOR UPDATE;
 SELECT * INTO STRICT i FROM control.evidence_kms_installation WHERE participant_id=a.participant_id
 AND privacy_domain_id=a.privacy_domain_id AND installation_digest=a.installation_digest;
 PERFORM openpc.evidence_export_producer_authority(i.producer_trust_digest);
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('evidence-kms-installation:'||NEW.participant_id::text||':'||
 NEW.privacy_domain_id::text||':'||i.installation_id::text,0));
 SELECT * INTO STRICT i FROM control.evidence_kms_installation WHERE participant_id=a.participant_id
 AND privacy_domain_id=a.privacy_domain_id AND installation_digest=a.installation_digest;
 request:=convert_from(NEW.request_bytes,'UTF8')::jsonb;
 IF NEW.request_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(request),'UTF8')
 OR request->>'operation' IS DISTINCT FROM NEW.kind OR request->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
 OR request->>'challenge' IS DISTINCT FROM NEW.challenge
 OR request->'recipient' IS DISTINCT FROM jsonb_build_object('participantId',a.participant_id::text,
 'privacyDomainId',a.privacy_domain_id::text,'installationDigest',a.installation_digest,'producerTrustDigest',i.producer_trust_digest)
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-EXCHANGE'; END IF;
 IF NEW.kind='PREPARE' THEN
  IF NEW.exchange_id<>NEW.attempt_id OR NEW.request_bytes<>a.request_bytes THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-ORIGINAL'; END IF;
  original_key:='sha256:'||repeat('0',64); original_use:='NONE';
 ELSE
  fields:=ARRAY['operation','exchangeId','attemptId','recipient','originalRequestDigest','objectIntentDigest','keyId','keyUse','challenge'];
  IF NEW.kind='READ_ATTEMPT' THEN fields:=fields||ARRAY['readExchangeId','readRequestDigest']; END IF;
  IF jsonb_typeof(request) IS DISTINCT FROM 'object' OR request-fields IS DISTINCT FROM '{}'::jsonb OR NOT request ?& fields
  THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-EXCHANGE-SHAPE'; END IF;
  IF request->>'exchangeId' IS DISTINCT FROM NEW.exchange_id::text
  OR request->>'originalRequestDigest' IS DISTINCT FROM a.request_digest
  OR request->>'objectIntentDigest' IS DISTINCT FROM a.object_intent_digest
  THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-ORIGINAL'; END IF;
  original_key:=request->>'keyId'; original_use:=request->>'keyUse';
  IF NEW.kind='READ_ATTEMPT' AND NOT EXISTS(SELECT 1 FROM control.evidence_kms_exchange target
   WHERE target.participant_id=a.participant_id AND target.privacy_domain_id=a.privacy_domain_id
   AND target.attempt_id=a.attempt_id AND target.exchange_id::text=request->>'readExchangeId'
   AND target.request_digest=request->>'readRequestDigest' AND target.kind IN ('PREPARE','UNWRAP'))
  THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-READBACK-TARGET'; END IF;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'PREPARED' OR NEW.receipt_bytes IS NOT NULL THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-EXCHANGE'; END IF;
  IF NEW.kind='UNWRAP' THEN
   IF a.state<>'PROVED' OR original_use NOT IN ('ENCRYPT','DECRYPT') OR NOT EXISTS(SELECT 1 FROM control.evidence_wrapped_key
    WHERE participant_id=a.participant_id AND privacy_domain_id=a.privacy_domain_id AND attempt_id=a.attempt_id AND key_id=original_key)
   THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-UNWRAP'; END IF;
   IF original_use='ENCRYPT' AND EXISTS(SELECT 1 FROM control.evidence_kms_exchange e WHERE e.participant_id=a.participant_id
     AND e.privacy_domain_id=a.privacy_domain_id AND e.attempt_id=a.attempt_id AND e.kind='UNWRAP'
     AND convert_from(e.request_bytes,'UTF8')::jsonb->>'keyUse'='ENCRYPT')
   THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-NO-RESEAL'; END IF;
   IF EXISTS(SELECT 1 FROM control.evidence_kms_exchange e WHERE e.participant_id=a.participant_id
    AND e.privacy_domain_id=a.privacy_domain_id AND e.attempt_id=a.attempt_id AND e.kind='UNWRAP'
    AND e.state IN ('PREPARED','DISPATCHED','UNKNOWN') AND NOT EXISTS(SELECT 1 FROM control.evidence_kms_exchange done
      WHERE done.participant_id=e.participant_id AND done.privacy_domain_id=e.privacy_domain_id AND done.attempt_id=e.attempt_id
      AND done.kind='READ_ATTEMPT' AND done.state='PROVED' AND openpc.evidence_kms_stored_outcome(done.receipt_bytes) IN ('1','2')
      AND convert_from(done.request_bytes,'UTF8')::jsonb->>'readExchangeId'=e.exchange_id::text
      AND convert_from(done.request_bytes,'UTF8')::jsonb->>'readRequestDigest'=e.request_digest))
   THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-UNKNOWN'; END IF;
  ELSIF original_use IS DISTINCT FROM 'NONE' THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-KEY-USE'; END IF;
  IF NEW.kind<>'READ_ATTEMPT' AND (i.state<>'ACTIVE' OR NOT i.pins->'permissions' ? CASE WHEN original_use='DECRYPT' THEN 'DECRYPT' ELSE 'ENCRYPT' END)
  THEN RAISE EXCEPTION 'OPS_SECRET_REVOKED'; END IF;
  RETURN NEW;
 END IF;
 IF to_jsonb(OLD)-ARRAY['state','receipt_bytes','receipt_digest','provider_sequence','recovery_floor'] IS DISTINCT FROM
 to_jsonb(NEW)-ARRAY['state','receipt_bytes','receipt_digest','provider_sequence','recovery_floor']
 THEN RAISE EXCEPTION 'DATA-6020-EVIDENCE-KMS-IMMUTABLE'; END IF;
 IF NEW.state IN ('DISPATCHED','UNKNOWN') THEN
  IF NOT ((OLD.state='PREPARED' AND NEW.state='DISPATCHED') OR (OLD.state IN ('DISPATCHED','UNKNOWN') AND NEW.state='UNKNOWN'))
  OR NEW.receipt_bytes IS NOT NULL OR NEW.provider_sequence IS NOT NULL OR NEW.recovery_floor IS NOT NULL
  THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-EXCHANGE-TRANSITION'; END IF;
  IF NEW.state='DISPATCHED' AND NEW.kind<>'READ_ATTEMPT' AND (i.state<>'ACTIVE'
   OR NOT i.pins->'permissions' ? CASE WHEN original_use='DECRYPT' THEN 'DECRYPT' ELSE 'ENCRYPT' END
   OR floor(extract(epoch from clock_timestamp())*1000)<(i.pins->>'validFromMs')::numeric
   OR floor(extract(epoch from clock_timestamp())*1000)>=(i.pins->>'validUntilMs')::numeric)
   THEN RAISE EXCEPTION 'OPS_SECRET_REVOKED'; END IF;
  RETURN NEW;
 END IF;
 IF OLD.state NOT IN ('DISPATCHED','UNKNOWN') OR NEW.state<>'PROVED' THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-EXCHANGE-TRANSITION'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('evidence-kms-provider-key:'||jsonb_build_array(
  NEW.participant_id,NEW.privacy_domain_id,i.pins->>'providerId',i.pins->>'providerKeyId',i.pins->>'providerKeyVersion')::text,0));
 IF EXISTS(SELECT 1 FROM control.evidence_kms_exchange e
   JOIN control.evidence_kms_attempt prior USING(participant_id,privacy_domain_id,attempt_id)
   JOIN control.evidence_kms_installation prior_i USING(participant_id,privacy_domain_id,installation_digest)
   WHERE e.participant_id=NEW.participant_id AND e.privacy_domain_id=NEW.privacy_domain_id
   AND prior_i.pins->>'providerId'=i.pins->>'providerId' AND prior_i.pins->>'providerKeyId'=i.pins->>'providerKeyId'
   AND prior_i.pins->>'providerKeyVersion'=i.pins->>'providerKeyVersion'
   AND (e.provider_sequence>NEW.provider_sequence OR e.recovery_floor>NEW.recovery_floor))
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-RECOVERY-FLOOR'; END IF;
 pack:=convert_from(NEW.receipt_bytes,'UTF8')::jsonb;
 IF jsonb_typeof(pack) IS DISTINCT FROM 'object' OR pack-ARRAY['profile','receipt','record','recovery'] IS DISTINCT FROM '{}'::jsonb
 OR NOT pack ?& ARRAY['profile','receipt','record','recovery']
 OR NEW.receipt_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(pack),'UTF8') THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-PACK'; END IF;
 FOREACH item IN ARRAY ARRAY['profile','receipt','record','recovery'] LOOP
  IF jsonb_typeof(pack->item) IS DISTINCT FROM 'object' OR (pack->item)-ARRAY['payloadHex','coseHex'] IS DISTINCT FROM '{}'::jsonb
  OR NOT (pack->item) ?& ARRAY['payloadHex','coseHex']
  OR NOT coalesce(pack->item->>'payloadHex' ~ '^([0-9a-f]{2})*$',false)
  OR NOT coalesce(pack->item->>'coseHex' ~ '^([0-9a-f]{2})*$',false) THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-PACK'; END IF;
 END LOOP;
 p:=openpc.evidence_kms_cose_binding(decode(pack->'profile'->>'payloadHex','hex'),decode(pack->'profile'->>'coseHex','hex'),
 'EvidenceKmsProfileV1','sha256:'||encode(sha256(decode(i.pins->>'profileIssuerSpkiHex','hex')),'hex'));
 IF 'sha256:'||encode(sha256(decode(pack->'profile'->>'coseHex','hex')),'hex') IS DISTINCT FROM i.pins->>'profileDigest'
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-PROFILE'; END IF;
 r:=openpc.evidence_kms_cose_binding(decode(pack->'receipt'->>'payloadHex','hex'),decode(pack->'receipt'->>'coseHex','hex'),
 'EvidenceKmsReceiptV1','sha256:'||encode(sha256(decode(i.pins->>'providerReceiptSpkiHex','hex')),'hex'));
 f:=openpc.evidence_kms_cose_binding(decode(pack->'recovery'->>'payloadHex','hex'),decode(pack->'recovery'->>'coseHex','hex'),
 'EvidenceKmsReceiptV1','sha256:'||encode(sha256(decode(i.pins->>'recoveryAuthoritySpkiHex','hex')),'hex'));
 FOREACH item IN ARRAY ARRAY['environmentId','participantId','privacyDomainId','providerId','reference','version','providerKeyId','providerKeyVersion','keyEpoch','wrapProfileDigest','policyDigest','recoveryProfileDigest'] LOOP
  IF r->>item IS DISTINCT FROM i.pins->>item OR f->>item IS DISTINCT FROM i.pins->>item OR p->>item IS DISTINCT FROM i.pins->>item
  THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-SCOPE'; END IF;
 END LOOP;
 IF r->>'operation' IS DISTINCT FROM (CASE NEW.kind WHEN 'PREPARE' THEN '1' WHEN 'READ_ATTEMPT' THEN '2' WHEN 'STATUS' THEN '3' WHEN 'UNWRAP' THEN '4' END)
 OR r->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text OR r->>'exchangeId' IS DISTINCT FROM NEW.exchange_id::text
 OR r->>'requestDigest' IS DISTINCT FROM NEW.request_digest OR r->>'challenge' IS DISTINCT FROM NEW.challenge
 OR r->>'objectIntentDigest' IS DISTINCT FROM a.object_intent_digest OR r->>'profileDigest' IS DISTINCT FROM i.pins->>'profileDigest'
 OR r->>'keyUse' IS DISTINCT FROM (CASE original_use WHEN 'NONE' THEN '1' WHEN 'ENCRYPT' THEN '2' WHEN 'DECRYPT' THEN '3' END)
 OR r->>'providerSequence' IS DISTINCT FROM NEW.provider_sequence::text OR r->>'recoveryFloor' IS DISTINCT FROM NEW.recovery_floor::text
 OR f->>'operation' IS DISTINCT FROM '5' OR f->>'keyUse' IS DISTINCT FROM '1' OR f->>'outcome' IS DISTINCT FROM '1'
 OR f-ARRAY['operation','keyUse','outcome','materialDigest','receiptId','signerKeyId','observedAtMs','validUntilMs'] IS DISTINCT FROM
 r-ARRAY['operation','keyUse','outcome','materialDigest','receiptId','signerKeyId','observedAtMs','validUntilMs']
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-RECEIPT'; END IF;
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF (r->>'observedAtMs')::numeric>now_ms OR (r->>'observedAtMs')::numeric<now_ms-5000 OR (r->>'validUntilMs')::numeric<=now_ms
 OR (r->>'validUntilMs')::numeric-(r->>'observedAtMs')::numeric NOT BETWEEN 1 AND 5000
 OR (f->>'observedAtMs')::numeric>now_ms OR (f->>'observedAtMs')::numeric<now_ms-5000 OR (f->>'validUntilMs')::numeric<=now_ms
 OR (f->>'validUntilMs')::numeric-(f->>'observedAtMs')::numeric NOT BETWEEN 1 AND 5000
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-STALE'; END IF;
 IF original_key<>'sha256:'||repeat('0',64) AND r->>'keyId' IS DISTINCT FROM original_key THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-KEY'; END IF;
 IF NEW.kind='UNWRAP' AND r->>'outcome'='1' THEN
  IF i.state<>'ACTIVE' OR NOT i.pins->'permissions' ? original_use OR r->>'keyState' NOT IN ('1','2')
  OR (original_use='ENCRYPT' AND r->>'keyState'<>'1') OR now_ms<(i.pins->>'validFromMs')::numeric
  OR now_ms>=(i.pins->>'validUntilMs')::numeric OR r->>'materialDigest'='sha256:'||repeat('0',64)
  THEN RAISE EXCEPTION 'OPS_SECRET_REVOKED'; END IF;
 ELSIF r->>'materialDigest' IS DISTINCT FROM 'sha256:'||repeat('0',64) THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-MATERIAL'; END IF;
 IF pack->'record'->>'payloadHex'<>'' THEN
  k:=openpc.evidence_kms_cose_binding(decode(pack->'record'->>'payloadHex','hex'),decode(pack->'record'->>'coseHex','hex'),
   'EvidenceWrappedKeyRecordV1','sha256:'||encode(sha256(decode(i.pins->>'providerReceiptSpkiHex','hex')),'hex'));
  FOREACH item IN ARRAY ARRAY['environmentId','participantId','privacyDomainId','providerId','reference','version','providerKeyId','providerKeyVersion','keyEpoch','wrapProfileDigest','policyDigest','recoveryProfileDigest'] LOOP
   IF k->>item IS DISTINCT FROM i.pins->>item THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-RECORD-SCOPE'; END IF;
  END LOOP;
  IF k->>'attemptId' IS DISTINCT FROM a.attempt_id::text OR k->>'originalRequestDigest' IS DISTINCT FROM a.request_digest
   OR k->>'objectIntentDigest' IS DISTINCT FROM a.object_intent_digest OR k->>'profileDigest' IS DISTINCT FROM i.pins->>'profileDigest'
   OR r->>'keyId' IS DISTINCT FROM 'sha256:'||encode(sha256(decode(pack->'record'->>'payloadHex','hex')),'hex')
   THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-RECORD'; END IF;
 ELSE
  IF pack->'record'->>'coseHex'<>'' OR (NEW.kind IN ('PREPARE','READ_ATTEMPT','UNWRAP') AND r->>'outcome'='1')
   THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-RECORD'; END IF;
 END IF;
 RETURN NEW;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RAISE EXCEPTION 'PC-AUTH-0005';
END $$;
DROP TRIGGER IF EXISTS evidence_kms_exchange_guard ON control.evidence_kms_exchange;
CREATE TRIGGER evidence_kms_exchange_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_kms_exchange
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_kms_exchange();

CREATE OR REPLACE FUNCTION openpc.guard_evidence_wrapped_key() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'DATA-6020-EVIDENCE-KMS-IMMUTABLE'; END IF;
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE') OR NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR NOT EXISTS(SELECT 1 FROM control.evidence_kms_exchange e WHERE e.participant_id=NEW.participant_id
 AND e.privacy_domain_id=NEW.privacy_domain_id AND e.attempt_id=NEW.attempt_id AND e.state='PROVED' AND e.kind IN ('PREPARE','READ_ATTEMPT')
 AND openpc.evidence_kms_stored_outcome(e.receipt_bytes)='1'
 AND convert_from(e.receipt_bytes,'UTF8')::jsonb->'record' IS NOT DISTINCT FROM
 jsonb_build_object('payloadHex',encode(NEW.record_bytes,'hex'),'coseHex',encode(NEW.record_cose,'hex')))
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-RECORD-BINDING'; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS evidence_wrapped_key_guard ON control.evidence_wrapped_key;
CREATE TRIGGER evidence_wrapped_key_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_wrapped_key
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_wrapped_key();
REVOKE ALL ON control.evidence_kms_attempt,control.evidence_wrapped_key,control.evidence_kms_exchange FROM openpc_control_owner;
-- PostgreSQL checks the exchange/wrapped-record foreign keys as the referenced
-- table owner with FOR KEY SHARE, requiring SELECT and an UPDATE column privilege.
-- FORCE RLS still denies direct owner reads/updates without a matching policy;
-- the attempt/wrapped-record guards also reject owner runtime mutations.
GRANT SELECT ON control.evidence_kms_attempt TO openpc_control_owner;
GRANT UPDATE(attempt_id) ON control.evidence_kms_attempt TO openpc_control_owner;
GRANT SELECT ON control.evidence_wrapped_key TO openpc_control_owner;
GRANT UPDATE(key_id) ON control.evidence_wrapped_key TO openpc_control_owner;
`;

/** Composition must also install evidenceKmsReceiptGuardsSql below. Without it,
 * terminal outcomes and wrapped-record inserts stay denied. */
export const evidenceKmsPreparationGuardsSql = String.raw`
ALTER TABLE control.evidence_kms_attempt FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_wrapped_key FORCE ROW LEVEL SECURITY;
ALTER TABLE control.evidence_kms_exchange FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.evidence_kms_attempt,control.evidence_wrapped_key,control.evidence_kms_exchange
 FROM PUBLIC,openpc_control_runtime,openpc_control_worker,openpc_control_reader,openpc_control_owner;
-- This migration runs as the table owner. Restore only its DDL privilege while
-- replacing triggers; the complete receipt tail revokes it again before commit.
GRANT TRIGGER ON control.evidence_kms_attempt,control.evidence_wrapped_key,control.evidence_kms_exchange TO openpc_control_owner;
GRANT SELECT,INSERT,UPDATE ON control.evidence_kms_attempt TO openpc_control_runtime;
GRANT SELECT ON control.evidence_wrapped_key,control.evidence_kms_exchange TO openpc_control_runtime;

CREATE OR REPLACE FUNCTION openpc.guard_evidence_kms_attempt() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE installed control.evidence_kms_installation; r jsonb; o jsonb; authority jsonb;
BEGIN
 PERFORM openpc.assert_request_context(true);
 IF NOT pg_has_role(current_user,'openpc_control_runtime','USAGE')
 OR current_setting('openpc.action_intent_id')<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1'
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DATA-6020-EVIDENCE-KMS-IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id()
 OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 SELECT * INTO STRICT installed FROM control.evidence_kms_installation
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
 AND installation_digest=NEW.installation_digest;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('evidence-kms-installation:'||NEW.participant_id::text||':'||
 NEW.privacy_domain_id::text||':'||installed.installation_id::text,0));
 SELECT * INTO STRICT installed FROM control.evidence_kms_installation
 WHERE participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id
 AND installation_digest=NEW.installation_digest;
 -- Current Identity authority is necessary; it does not authenticate a peer or
 -- replace the application owner using its actual TLS socket.
 authority:=openpc.evidence_export_producer_authority(installed.producer_trust_digest);
 IF TG_OP='UPDATE' THEN
  IF NEW.state IN ('PROVED','REJECTED') THEN
   IF OLD.state NOT IN ('DISPATCHED','UNKNOWN') OR
     to_jsonb(OLD)-ARRAY['state','result_receipt_bytes','result_receipt_digest'] IS DISTINCT FROM
     to_jsonb(NEW)-ARRAY['state','result_receipt_bytes','result_receipt_digest'] OR
     NOT EXISTS(SELECT 1 FROM control.evidence_kms_exchange e WHERE e.participant_id=NEW.participant_id
       AND e.privacy_domain_id=NEW.privacy_domain_id AND e.attempt_id=NEW.attempt_id AND e.state='PROVED'
       AND e.kind IN ('PREPARE','READ_ATTEMPT') AND e.receipt_bytes=NEW.result_receipt_bytes
       AND e.receipt_digest=NEW.result_receipt_digest
       AND openpc.evidence_kms_stored_outcome(e.receipt_bytes)=CASE WHEN NEW.state='PROVED' THEN '1' ELSE '2' END)
   THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-RESULT-BINDING'; END IF;
   IF NEW.state='PROVED' AND NOT EXISTS(SELECT 1 FROM control.evidence_wrapped_key k
     WHERE k.participant_id=NEW.participant_id AND k.privacy_domain_id=NEW.privacy_domain_id AND k.attempt_id=NEW.attempt_id)
   THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-RECORD-MISSING'; END IF;
   RETURN NEW;
  END IF;
  IF to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state'
    OR NOT ((OLD.state='PREPARED' AND NEW.state='DISPATCHED')
      OR (OLD.state IN ('DISPATCHED','UNKNOWN') AND NEW.state='UNKNOWN'))
  THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-TRANSITION'; END IF;
  IF NEW.state='UNKNOWN' THEN RETURN NEW; END IF;
 ELSE
  IF NEW.state<>'PREPARED' OR NEW.result_receipt_bytes IS NOT NULL OR NEW.result_receipt_digest IS NOT NULL
  THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-PREPARE'; END IF;
 END IF;
 IF installed.state<>'ACTIVE' OR NOT installed.pins->'permissions' ? 'ENCRYPT'
 OR floor(extract(epoch from clock_timestamp())*1000)<(installed.pins->>'validFromMs')::numeric
 OR floor(extract(epoch from clock_timestamp())*1000)>=(installed.pins->>'validUntilMs')::numeric
 THEN RAISE EXCEPTION 'OPS_SECRET_REVOKED'; END IF;
 IF TG_OP='UPDATE' THEN RETURN NEW; END IF;
 IF NEW.authority_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(authority),'UTF8')),'hex')
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-AUTHORITY'; END IF;
 r:=NEW.request; o:=r->'objectIntent';
 IF jsonb_typeof(r) IS DISTINCT FROM 'object'
 OR r-ARRAY['operation','recipient','attemptId','objectIntent','challenge'] IS DISTINCT FROM '{}'::jsonb
 OR NOT r ?& ARRAY['operation','recipient','attemptId','objectIntent','challenge']
 OR r->>'operation' IS DISTINCT FROM 'PREPARE'
 OR r->'recipient' IS DISTINCT FROM jsonb_build_object('participantId',NEW.participant_id::text,
   'privacyDomainId',NEW.privacy_domain_id::text,'installationDigest',NEW.installation_digest,
   'producerTrustDigest',installed.producer_trust_digest)
 OR r->>'attemptId' IS DISTINCT FROM NEW.attempt_id::text
 OR NOT coalesce(r->>'challenge' ~ '^[0-9a-f]{64}$',false)
 OR jsonb_typeof(o) IS DISTINCT FROM 'object'
 OR o-ARRAY['environmentId','participantId','privacyDomainId','payloadObjectId','objectVersion',
   'notificationOccurrenceRef','routingProfileDigest','templateDigest','recipientSetDigest',
   'redactionProfileDigest','preferenceGeneration','payloadDigest'] IS DISTINCT FROM '{}'::jsonb
 OR NOT o ?& ARRAY['environmentId','participantId','privacyDomainId','payloadObjectId','objectVersion',
   'notificationOccurrenceRef','routingProfileDigest','templateDigest','recipientSetDigest',
   'redactionProfileDigest','preferenceGeneration','payloadDigest']
 OR o->>'environmentId' IS DISTINCT FROM installed.pins->>'environmentId'
 OR o->>'participantId' IS DISTINCT FROM NEW.participant_id::text
 OR o->>'privacyDomainId' IS DISTINCT FROM NEW.privacy_domain_id::text
 OR o->>'payloadObjectId' IS DISTINCT FROM NEW.object_id::text
 OR o->>'objectVersion' IS DISTINCT FROM NEW.object_version
 OR NEW.object_intent_digest IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(o),'UTF8')),'hex')
 OR NEW.request_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(r),'UTF8')
 THEN RAISE EXCEPTION 'DATA-6021-EVIDENCE-KMS-REQUEST'; END IF;
 RETURN NEW;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RAISE EXCEPTION 'PC-AUTH-0005';
END $$;
DROP TRIGGER IF EXISTS evidence_kms_attempt_guard ON control.evidence_kms_attempt;
CREATE TRIGGER evidence_kms_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON control.evidence_kms_attempt
 FOR EACH ROW EXECUTE FUNCTION openpc.guard_evidence_kms_attempt();
`;
