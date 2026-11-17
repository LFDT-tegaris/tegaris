import { operationsConfigurationCoseProfiles as profiles } from '../../../../../packages/security-kernel/src/operations-configuration/generated.ts';
import { qualificationOnlinePurposes } from '../../../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.ts';
const families = {
  input: profiles.OperationsQualificationInputV1,
  receipt: profiles.OperationsQualificationExecutedReceiptV1,
  keyset: profiles.OperationsQualificationKeysetV1,
  revocations: profiles.OperationsQualificationRevocationsV1,
};
const tables = [
  'operations_qualification_root',
  'operations_qualification_state',
  'operations_provider_retry_qualification',
];
const context = `PERFORM openpc.assert_request_context(true);
 IF current_setting('transaction_isolation')<>'read committed' OR current_setting('row_security')<>'on'
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;`;
function value(field) {
  const m = `m->'${field.key}'`;
  if (field.type === 'H32') return `'sha256:'||(${m}->>'bytes')`;
  if (field.type === 'uuidv7') return `((${m}->>'bytes')::uuid)::text`;
  if (field.type === 'u64p') return `m->>'${field.key}'`;
  if (field.type.startsWith('enum '))
    return `CASE m->>'${field.key}' ${field.type
      .slice(5)
      .split(' ')
      .map((v) => {
        const [name, n] = v.split('=');
        return `WHEN '${n}' THEN '${name}'`;
      })
      .join(' ')} ELSE NULL END`;
  return m;
}
/** Requires canonical roles before registration; creates neither roles nor root
 * trust. SQL checks exact framing/state; ES256 is independently reverified by the
 * dedicated adapter at admission and every withCurrent consumption. */
export const providerRetryQualificationGuardsSql = String.raw`
${tables
  .map(
    (name) => `ALTER TABLE control.${name} FORCE ROW LEVEL SECURITY;
REVOKE ALL ON control.${name} FROM PUBLIC,openpc_control_owner,openpc_control_runtime,openpc_control_worker,openpc_control_reader;
GRANT SELECT,TRIGGER ON control.${name} TO openpc_control_owner;
GRANT SELECT ON control.${name} TO openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap;
DROP POLICY IF EXISTS provider_retry_scoped ON control.${name};
CREATE POLICY provider_retry_scoped ON control.${name} TO openpc_control_owner,openpc_operations_qualification_owner,openpc_operations_qualification_bootstrap
 USING(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id))
 WITH CHECK(openpc.matches_participant(participant_id) AND openpc.matches_privacy(privacy_domain_id));`,
  )
  .join('\n')}
GRANT INSERT,UPDATE ON control.operations_qualification_root TO openpc_operations_qualification_bootstrap;
-- PostgreSQL row locks require UPDATE; the root trigger still forbids this role's UPDATE.
GRANT UPDATE ON control.operations_qualification_root TO openpc_operations_qualification_owner,openpc_control_owner;
GRANT INSERT ON control.operations_qualification_state,control.operations_provider_retry_qualification TO openpc_operations_qualification_owner;

CREATE OR REPLACE FUNCTION openpc.provider_retry_claims(family text,payload bytea,cose bytea,key_id text)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE m jsonb; result jsonb;
BEGIN
 IF octet_length(payload) NOT BETWEEN 1 AND 65536 OR octet_length(cose) NOT BETWEEN 65 AND 66560 THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
 m:=openpc.business_cbor(payload);
 CASE family
 ${Object.entries(families)
   .map(
     ([name, p]) => `WHEN '${name}' THEN
 PERFORM openpc.archive_cose_binding(payload,cose,key_id,${p.schemaId},${p.purposeCode});
 IF (SELECT count(*) FROM jsonb_object_keys(m))<>${p.fields.length} OR NOT m ?& ARRAY[${p.fields.map((f) => `'${f.key}'`).join(',')}]
 OR m->'0' IS DISTINCT FROM jsonb_build_object('bytes','${p.definitionDigest.slice(7)}') THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
 result:=jsonb_build_object(${p.fields
   .slice(1)
   .map((f) => `'${f.name}',${value(f)}`)
   .join(',')});`,
   )
   .join('\n')}
 ELSE RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END CASE;
 IF EXISTS(SELECT 1 FROM jsonb_each(result) j WHERE j.value='null'::jsonb)
 THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
 RETURN result;
END $$;

-- This seam is deliberately absent until canonical connects the ACTUAL provider
-- method/subject, non-exportable signer custody, raw executed evidence and
-- independent reviewer owners under transaction-held source fences. Its result
-- is exactly {input,receiptDocument}, not a boolean or a caller-built proof.
CREATE OR REPLACE FUNCTION openpc.require_provider_retry_evidence(p_environment text,p_generation uuid,p_input text,p_receipt text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 ${context}
 IF to_regprocedure('openpc.operations_provider_retry_evidence_current(text,uuid,text,text)') IS NULL
 THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_EVIDENCE_OWNER_UNBOUND'; END IF;
 EXECUTE 'select openpc.operations_provider_retry_evidence_current($1,$2,$3,$4)' INTO result USING p_environment,p_generation,p_input,p_receipt;
 IF result IS NULL OR jsonb_typeof(result)<>'object' OR NOT result ?& ARRAY['input','receiptDocument'] OR (SELECT count(*) FROM jsonb_object_keys(result))<>2
 THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
 RETURN result;
END $$;

CREATE OR REPLACE FUNCTION openpc.guard_provider_retry_qualification() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE root control.operations_qualification_root%ROWTYPE; prior control.operations_qualification_state%ROWTYPE;
 current_state control.operations_qualification_state%ROWTYPE; issuance control.operations_qualification_state%ROWTYPE;
 g control.operations_generation%ROWTYPE; installed control.operations_installation%ROWTYPE;
 k jsonb; r jsonb; kd jsonb; rd jsonb; old_kd jsonb; old_rd jsonb; i jsonb; receipt jsonb; doc jsonb; evidence jsonb; now_ms numeric;
BEGIN
 ${context}
 IF TG_OP IN ('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_IMMUTABLE'; END IF;
 IF NEW.participant_id IS DISTINCT FROM openpc.current_participant_id() OR NEW.privacy_domain_id IS DISTINCT FROM openpc.current_privacy_domain_id()
 OR openpc.current_action_intent_id()<>'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('operations-generation:'||NEW.environment_id,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('operations-qualification:'||NEW.environment_id||':'||NEW.authority_id,0));
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 IF TG_TABLE_NAME='operations_qualification_root' THEN
  IF NOT pg_has_role(current_user,'openpc_operations_qualification_bootstrap','USAGE') OR pg_has_role(current_user,'openpc_operations_qualification_owner','USAGE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
  IF TG_OP='UPDATE' THEN
   IF OLD.state<>'ACTIVE' OR NEW.state<>'REVOKED' OR to_jsonb(OLD)-'state' IS DISTINCT FROM to_jsonb(NEW)-'state' THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_IMMUTABLE'; END IF;
   RETURN NEW;
  END IF;
  IF EXISTS(SELECT 1 FROM control.operations_qualification_state history CROSS JOIN LATERAL jsonb_array_elements((convert_from(decode(history.custody->'keyset'->>'documentHex','hex'),'UTF8')::jsonb)->'keys') key WHERE history.environment_id=NEW.environment_id AND history.authority_id=NEW.authority_id AND key->>'keyId'=NEW.root_key_id)
   OR NEW.state<>'ACTIVE' OR NEW.valid_from_ms>now_ms OR NEW.valid_until_ms<=now_ms
   OR NEW.root_epoch<=coalesce((SELECT max(root_epoch) FROM control.operations_qualification_root WHERE environment_id=NEW.environment_id AND authority_id=NEW.authority_id),0)
   OR encode(NEW.root_spki,'hex') !~ '^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$'
  THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
  PERFORM 1 FROM control.operations_installation WHERE environment_id=NEW.environment_id AND state='ACTIVE' AND participant_id=NEW.participant_id AND privacy_domain_id=NEW.privacy_domain_id FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_IMMUTABLE'; END IF;
 IF NOT pg_has_role(current_user,'openpc_operations_qualification_owner','USAGE') OR pg_has_role(current_user,'openpc_operations_qualification_bootstrap','USAGE') THEN RAISE EXCEPTION 'PC-AUTH-0005'; END IF;
 IF octet_length(NEW.custody_bytes) NOT BETWEEN 1 AND (CASE WHEN TG_TABLE_NAME='operations_qualification_state' THEN 10000000 ELSE 1500000 END)
 OR NEW.custody_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.custody_bytes),'hex')
 OR NEW.custody IS DISTINCT FROM convert_from(NEW.custody_bytes,'UTF8')::jsonb OR NEW.custody_bytes IS DISTINCT FROM convert_to(openpc.signing_canonical_json(NEW.custody),'UTF8') THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
 SELECT * INTO root FROM control.operations_qualification_root WHERE environment_id=NEW.environment_id AND authority_id=NEW.authority_id ORDER BY root_epoch DESC LIMIT 1 FOR SHARE;
 IF root.authority_id IS NULL OR root.state<>'ACTIVE' OR root.participant_id<>NEW.participant_id OR root.privacy_domain_id<>NEW.privacy_domain_id OR root.valid_from_ms>now_ms OR root.valid_until_ms<=now_ms THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_ROOT_UNBOUND'; END IF;
 IF TG_TABLE_NAME='operations_qualification_state' THEN
  k:=openpc.provider_retry_claims('keyset',decode(NEW.custody->'keyset'->>'payloadHex','hex'),decode(NEW.custody->'keyset'->>'coseHex','hex'),root.root_key_id);
  r:=openpc.provider_retry_claims('revocations',decode(NEW.custody->'revocations'->>'payloadHex','hex'),decode(NEW.custody->'revocations'->>'coseHex','hex'),root.root_key_id);
  kd:=convert_from(decode(NEW.custody->'keyset'->>'documentHex','hex'),'UTF8')::jsonb;
  rd:=convert_from(decode(NEW.custody->'revocations'->>'documentHex','hex'),'UTF8')::jsonb;
  IF (SELECT count(*) FROM jsonb_object_keys(NEW.custody))<>2 OR NOT NEW.custody ?& ARRAY['keyset','revocations']
   OR (SELECT count(*) FROM jsonb_object_keys(kd))<>6 OR NOT kd ?& ARRAY['schemaVersion','authorityId','policySigner','keys','issuedAt','signatureEnvelope']
   OR (SELECT count(*) FROM jsonb_object_keys(rd))<>3 OR NOT rd ?& ARRAY['schemaVersion','authorityId','revocations']
   OR kd->>'schemaVersion'<>'1.0' OR rd->>'schemaVersion'<>'1.0' OR kd->>'policySigner'<>root.policy_signer
   OR jsonb_typeof(kd->'keys')<>'array' OR jsonb_array_length(kd->'keys') NOT BETWEEN 1 AND 64
   OR jsonb_typeof(rd->'revocations')<>'array' OR jsonb_array_length(rd->'revocations')>4096
   OR (k->>'issuedAtMs')::numeric<root.valid_from_ms OR (r->>'issuedAtMs')::numeric<root.valid_from_ms
   OR (k->>'validUntilMs')::numeric>root.valid_until_ms OR (r->>'validUntilMs')::numeric>root.valid_until_ms
   OR NEW.root_epoch<>root.root_epoch OR k->>'rootEpoch'<>root.root_epoch::text OR r->>'rootEpoch'<>root.root_epoch::text
   OR k->>'authorityId'<>NEW.authority_id OR r->>'authorityId'<>NEW.authority_id
   OR k->>'rootKeyId'<>root.root_key_id OR r->>'rootKeyId'<>root.root_key_id OR k->>'policySigner'<>root.policy_signer
   OR NEW.sequence::text<>k->>'sequence' OR NEW.snapshot_sequence::text<>r->>'sequence'
   OR NEW.keyset_digest IS DISTINCT FROM 'sha256:'||encode(sha256(decode(NEW.custody->'keyset'->>'payloadHex','hex')),'hex')
   OR NEW.revocations_digest IS DISTINCT FROM 'sha256:'||encode(sha256(decode(NEW.custody->'revocations'->>'payloadHex','hex')),'hex')
   OR k->>'revocationPayloadDigest'<>NEW.revocations_digest
   OR k->>'keysetDocumentDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(kd),'UTF8')),'hex')
   OR r->>'revocationDocumentDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(rd),'UTF8')),'hex')
   OR (k->>'issuedAtMs')::numeric>now_ms OR (r->>'issuedAtMs')::numeric>now_ms
   OR NEW.valid_until_ms IS DISTINCT FROM least((k->>'validUntilMs')::numeric,(r->>'validUntilMs')::numeric,root.valid_until_ms)
   OR NEW.valid_until_ms<=now_ms OR kd->>'authorityId'<>NEW.authority_id OR rd->>'authorityId'<>NEW.authority_id
  THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(kd->'keys') key WHERE
    (SELECT count(*) FROM jsonb_object_keys(key))<>9 OR NOT key ?& ARRAY['keyId','epoch','state','purpose','nonExportable','backend','publicKeySpkiHex','validFromMs','validUntilMs']
    OR EXISTS(SELECT 1 FROM control.operations_qualification_root installed_root WHERE installed_root.environment_id=NEW.environment_id AND installed_root.authority_id=NEW.authority_id AND installed_root.root_key_id=key->>'keyId') OR key->>'keyId' IS DISTINCT FROM 'sha256:'||encode(sha256(decode(key->>'publicKeySpkiHex','hex')),'hex')
    OR key->>'publicKeySpkiHex' !~ '^3059301306072a8648ce3d020106082a8648ce3d03010703420004[0-9a-f]{128}$'
    OR key->'nonExportable' IS DISTINCT FROM 'true'::jsonb OR key->>'backend' NOT IN ('KMS','HSM')
    OR key->>'state' NOT IN ('DRAFT','ACTIVE','SUSPENDED','RETIRED','REVOKED')
    OR key->>'purpose' NOT IN (${qualificationOnlinePurposes.map((purpose) => `'${purpose}'`).join(',')})
    OR key->>'epoch' !~ '^[1-9][0-9]*$' OR (key->>'epoch')::numeric>9007199254740991
    OR (key->>'validFromMs')::numeric<0 OR (key->>'validUntilMs')::numeric<=(key->>'validFromMs')::numeric OR (key->>'validUntilMs')::numeric>9007199254740991)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(kd->'keys') a JOIN jsonb_array_elements(kd->'keys') b ON a->>'keyId'=b->>'keyId' WHERE a->>'purpose'<>b->>'purpose')
   OR (SELECT count(*) FROM jsonb_array_elements(kd->'keys'))<>(SELECT count(DISTINCT (key->>'keyId',key->>'epoch')) FROM jsonb_array_elements(kd->'keys') key)
   THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
  SELECT * INTO prior FROM control.operations_qualification_state WHERE environment_id=NEW.environment_id AND authority_id=NEW.authority_id ORDER BY sequence DESC LIMIT 1;
  IF prior.authority_id IS NOT NULL THEN
   old_kd:=convert_from(decode(prior.custody->'keyset'->>'documentHex','hex'),'UTF8')::jsonb;
   old_rd:=convert_from(decode(prior.custody->'revocations'->>'documentHex','hex'),'UTF8')::jsonb;
   IF NEW.sequence<=prior.sequence OR NEW.snapshot_sequence<=prior.snapshot_sequence OR NEW.root_epoch<prior.root_epoch
    OR (k->>'issuedAtMs')::numeric<(openpc.business_cbor(decode(prior.custody->'keyset'->>'payloadHex','hex'))->>'9')::numeric
    OR (r->>'issuedAtMs')::numeric<(openpc.business_cbor(decode(prior.custody->'revocations'->>'payloadHex','hex'))->>'7')::numeric
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(old_kd->'keys') AS retained_key(value) WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(kd->'keys') AS next_key(value) WHERE retained_key.value->>'keyId'=next_key.value->>'keyId' AND retained_key.value->'epoch'=next_key.value->'epoch' AND retained_key.value-'state'=next_key.value-'state' AND (retained_key.value->>'state'<>'REVOKED' OR next_key.value->>'state'='REVOKED') AND (retained_key.value->>'state'<>'RETIRED' OR next_key.value->>'state' IN ('RETIRED','REVOKED'))))
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(old_rd->'revocations') AS retained_revocation(value) WHERE NOT (rd->'revocations') @> jsonb_build_array(retained_revocation.value))
   THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_STATE_ROLLBACK'; END IF;
  END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO current_state FROM control.operations_qualification_state WHERE environment_id=NEW.environment_id AND authority_id=NEW.authority_id ORDER BY sequence DESC LIMIT 1;
 SELECT * INTO issuance FROM control.operations_qualification_state WHERE environment_id=NEW.environment_id AND authority_id=NEW.authority_id AND sequence=NEW.issuance_sequence;
 IF issuance.authority_id IS NULL OR current_state.authority_id IS NULL OR current_state.root_epoch<>root.root_epoch OR current_state.valid_until_ms<=now_ms THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
 -- The dedicated writer verifies both signatures and documents before INSERT.
 -- Derive issuer identities from actual payloads; never accept a replacement JWK.
 i:=openpc.business_cbor(decode(NEW.custody->'input'->>'payloadHex','hex'));
 i:=openpc.provider_retry_claims('input',decode(NEW.custody->'input'->>'payloadHex','hex'),decode(NEW.custody->'input'->>'coseHex','hex'),'sha256:'||(i->'18'->>'bytes'));
 receipt:=openpc.business_cbor(decode(NEW.custody->'receipt'->>'payloadHex','hex'));
 receipt:=openpc.provider_retry_claims('receipt',decode(NEW.custody->'receipt'->>'payloadHex','hex'),decode(NEW.custody->'receipt'->>'coseHex','hex'),'sha256:'||(receipt->'11'->>'bytes'));
 doc:=convert_from(decode(NEW.custody->'receipt'->>'documentHex','hex'),'UTF8')::jsonb;
 SELECT * INTO g FROM control.operations_generation WHERE environment_id=NEW.environment_id AND generation_id=NEW.generation_id FOR SHARE;
 SELECT * INTO installed FROM control.operations_installation WHERE environment_id=NEW.environment_id FOR SHARE;
 IF (SELECT count(*) FROM jsonb_object_keys(NEW.custody))<>2 OR NOT NEW.custody ?& ARRAY['input','receipt']
  OR g.state IS DISTINCT FROM 'STAGED' OR installed.state IS DISTINCT FROM 'ACTIVE' OR NOT openpc.operations_generation_source_authenticated(NEW.environment_id,NEW.generation_id)
  OR i->>'authorityId'<>NEW.authority_id OR i->>'environmentId'<>NEW.environment_id OR receipt->>'environmentId'<>NEW.environment_id OR receipt->>'authorityId'<>NEW.authority_id
  OR i->>'profile' IS DISTINCT FROM g.candidate->'configuration'->>'profile' OR i->>'profile' IS DISTINCT FROM receipt->>'profile'
  OR i->>'slot' IS DISTINCT FROM installed.installation->'namedProfile'->'requiredSettingInputs'->>'provider.read_retry_limit'
  OR i->>'setting' IS DISTINCT FROM 'provider.read_retry_limit' OR i->>'methodClass' IS DISTINCT FROM 'RETRY_SAFE_READ'
  OR (i->>'value')::integer NOT BETWEEN 0 AND 3 OR i->'value' IS DISTINCT FROM g.candidate->'configuration'->'settings'->'provider.read_retry_limit'
  OR i->>'configurationSchemaDigest' IS DISTINCT FROM installed.installation->'pins'->>'configurationSchemaDigest'
  OR i->>'namedProfileDigest' IS DISTINCT FROM installed.installation->'pins'->>'namedProfileDigest'
  OR NEW.input_digest IS DISTINCT FROM 'sha256:'||encode(sha256(decode(NEW.custody->'input'->>'payloadHex','hex')),'hex')
  OR NEW.receipt_digest IS DISTINCT FROM 'sha256:'||encode(sha256(decode(NEW.custody->'receipt'->>'payloadHex','hex')),'hex')
  OR receipt->>'inputPayloadDigest'<>NEW.input_digest OR receipt->>'qualificationRef' IS DISTINCT FROM 'qualification://'||NEW.authority_id||'/'||(i->>'inputId')||'@'||NEW.input_digest
  OR receipt->>'qualificationRef' IS DISTINCT FROM g.candidate->'configuration'->'qualificationInputBindings'->>'provider.read_retry_limit'
  OR receipt->>'keysetPayloadDigest'<>issuance.keyset_digest OR receipt->>'revocationPayloadDigest'<>issuance.revocations_digest
  OR receipt->>'receiptDocumentDigest' IS DISTINCT FROM 'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(doc),'UTF8')),'hex')
  OR (i->>'validFromMs')::numeric>now_ms OR (receipt->>'issuedAtMs')::numeric>now_ms OR (i->>'validUntilMs')::numeric<=now_ms
  OR NEW.valid_until_ms IS DISTINCT FROM (receipt->>'expiresAtMs')::numeric OR NEW.valid_until_ms<=now_ms
 THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
 evidence:=openpc.require_provider_retry_evidence(NEW.environment_id,NEW.generation_id,NEW.input_digest,receipt->>'receiptDocumentDigest');
 IF evidence->'input' IS DISTINCT FROM i OR evidence->'receiptDocument' IS DISTINCT FROM doc THEN RAISE EXCEPTION 'OPS_PROVIDER_RETRY_UNQUALIFIED'; END IF;
 RETURN NEW;
END $$;

-- Current source binding only. Canonical clears ONLY the provider.read_retry_limit
-- requirement, and calls the TypeScript withCurrent adapter around consumption;
-- this predicate is never a replacement for ES256/execution-owner verification.
CREATE OR REPLACE FUNCTION openpc.operations_provider_retry_qualification_bound(p_environment text,p_generation uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE b control.operations_provider_retry_qualification%ROWTYPE;
 root control.operations_qualification_root%ROWTYPE; current_state control.operations_qualification_state%ROWTYPE;
 issuance control.operations_qualification_state%ROWTYPE; g control.operations_generation%ROWTYPE;
 installed control.operations_installation%ROWTYPE; i jsonb; r jsonb; doc jsonb; kd jsonb; rd jsonb; ikd jsonb; ird jsonb;
 evidence jsonb; key_entry jsonb; claims jsonb; purpose text; issued numeric; expiry numeric; now_ms numeric;
BEGIN
 ${context}
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('operations-generation:'||p_environment,0));
 SELECT * INTO b FROM control.operations_provider_retry_qualification WHERE environment_id=p_environment AND generation_id=p_generation;
 IF b.generation_id IS NULL THEN RETURN false; END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('operations-qualification:'||p_environment||':'||b.authority_id,0));
 now_ms:=floor(extract(epoch from clock_timestamp())*1000);
 SELECT * INTO root FROM control.operations_qualification_root WHERE environment_id=p_environment AND authority_id=b.authority_id ORDER BY root_epoch DESC LIMIT 1 FOR SHARE;
 SELECT * INTO current_state FROM control.operations_qualification_state WHERE environment_id=p_environment AND authority_id=b.authority_id ORDER BY sequence DESC LIMIT 1;
 SELECT * INTO issuance FROM control.operations_qualification_state WHERE environment_id=p_environment AND authority_id=b.authority_id AND sequence=b.issuance_sequence;
 SELECT * INTO g FROM control.operations_generation WHERE environment_id=p_environment AND generation_id=p_generation FOR SHARE;
 SELECT * INTO installed FROM control.operations_installation WHERE environment_id=p_environment FOR SHARE;
 IF root.authority_id IS NULL OR current_state.authority_id IS NULL OR issuance.authority_id IS NULL
 OR root.state<>'ACTIVE' OR root.valid_from_ms>now_ms OR root.valid_until_ms<=now_ms
 OR current_state.root_epoch<>root.root_epoch OR current_state.valid_until_ms<=now_ms OR b.valid_until_ms<=now_ms
 OR g.state IS DISTINCT FROM 'STAGED' OR installed.state IS DISTINCT FROM 'ACTIVE'
 OR NOT openpc.operations_generation_source_authenticated(p_environment,p_generation)
 OR NOT EXISTS(SELECT 1 FROM control.operations_qualification_root WHERE environment_id=p_environment AND authority_id=b.authority_id AND root_epoch=issuance.root_epoch AND state='ACTIVE')
 THEN RETURN false; END IF;
 i:=openpc.business_cbor(decode(b.custody->'input'->>'payloadHex','hex'));
 i:=openpc.provider_retry_claims('input',decode(b.custody->'input'->>'payloadHex','hex'),decode(b.custody->'input'->>'coseHex','hex'),'sha256:'||(i->'18'->>'bytes'));
 r:=openpc.business_cbor(decode(b.custody->'receipt'->>'payloadHex','hex'));
 r:=openpc.provider_retry_claims('receipt',decode(b.custody->'receipt'->>'payloadHex','hex'),decode(b.custody->'receipt'->>'coseHex','hex'),'sha256:'||(r->'11'->>'bytes'));
 doc:=convert_from(decode(b.custody->'receipt'->>'documentHex','hex'),'UTF8')::jsonb;
 kd:=convert_from(decode(current_state.custody->'keyset'->>'documentHex','hex'),'UTF8')::jsonb;
 rd:=convert_from(decode(current_state.custody->'revocations'->>'documentHex','hex'),'UTF8')::jsonb;
 ikd:=convert_from(decode(issuance.custody->'keyset'->>'documentHex','hex'),'UTF8')::jsonb;
 ird:=convert_from(decode(issuance.custody->'revocations'->>'documentHex','hex'),'UTF8')::jsonb;
 IF i->>'environmentId'<>p_environment OR i->>'authorityId'<>b.authority_id
 OR i->>'profile' IS DISTINCT FROM g.candidate->'configuration'->>'profile'
 OR i->>'configurationSchemaDigest' IS DISTINCT FROM installed.installation->'pins'->>'configurationSchemaDigest'
 OR i->>'namedProfileDigest' IS DISTINCT FROM installed.installation->'pins'->>'namedProfileDigest'
 OR i->>'slot' IS DISTINCT FROM installed.installation->'namedProfile'->'requiredSettingInputs'->>'provider.read_retry_limit'
 OR i->'value' IS DISTINCT FROM g.candidate->'configuration'->'settings'->'provider.read_retry_limit'
 OR r->>'qualificationRef' IS DISTINCT FROM g.candidate->'configuration'->'qualificationInputBindings'->>'provider.read_retry_limit'
 OR (i->>'validFromMs')::numeric>now_ms OR (i->>'validUntilMs')::numeric<=now_ms
 OR (r->>'issuedAtMs')::numeric>now_ms OR (r->>'expiresAtMs')::numeric<=now_ms
 OR r->>'keysetPayloadDigest'<>issuance.keyset_digest OR r->>'revocationPayloadDigest'<>issuance.revocations_digest
 THEN RETURN false; END IF;
 FOR claims,purpose,issued,expiry IN SELECT i,'pc.cose.operations-qualification-input.v1',(i->>'validFromMs')::numeric,(i->>'validUntilMs')::numeric
 UNION ALL SELECT r,'pc.cose.operations-qualification-executed-receipt.v1',(r->>'issuedAtMs')::numeric,(r->>'expiresAtMs')::numeric LOOP
  SELECT key INTO key_entry FROM jsonb_array_elements(kd->'keys') key WHERE key->>'keyId'=claims->>'issuerKeyId' AND key->>'epoch'=claims->>'issuerEpoch' AND key->>'purpose'=purpose;
  IF key_entry IS NULL OR key_entry->>'state' NOT IN ('ACTIVE','RETIRED') OR (key_entry->>'validFromMs')::numeric>issued OR (key_entry->>'validUntilMs')::numeric<expiry
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(ikd->'keys') key WHERE key->>'keyId'=claims->>'issuerKeyId' AND key->>'epoch'=claims->>'issuerEpoch' AND key->>'purpose'=purpose AND key->>'state'='ACTIVE' AND key-'state'=key_entry-'state')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(rd->'revocations') rev WHERE rev->>'keyId'=claims->>'issuerKeyId' AND rev->>'keyEpoch'=claims->>'issuerEpoch' AND (rev->>'effectiveAt')::timestamptz<=clock_timestamp())
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(ird->'revocations') rev WHERE rev->>'keyId'=claims->>'issuerKeyId' AND rev->>'keyEpoch'=claims->>'issuerEpoch' AND extract(epoch from (rev->>'effectiveAt')::timestamptz)*1000<=(r->>'issuedAtMs')::numeric)
  THEN RETURN false; END IF;
 END LOOP;
 evidence:=openpc.require_provider_retry_evidence(p_environment,p_generation,b.input_digest,r->>'receiptDocumentDigest');
 RETURN evidence->'input'=i AND evidence->'receiptDocument'=doc;
END $$;
REVOKE ALL ON FUNCTION openpc.operations_provider_retry_qualification_bound(text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.operations_provider_retry_qualification_bound(text,uuid) TO openpc_control_owner,openpc_operations_qualification_owner;

${tables
  .map(
    (name) => `DROP TRIGGER IF EXISTS provider_retry_guard ON control.${name};
CREATE TRIGGER provider_retry_guard BEFORE INSERT OR UPDATE OR DELETE ON control.${name} FOR EACH ROW EXECUTE FUNCTION openpc.guard_provider_retry_qualification();
DROP TRIGGER IF EXISTS provider_retry_truncate_guard ON control.${name};
CREATE TRIGGER provider_retry_truncate_guard BEFORE TRUNCATE ON control.${name} FOR EACH STATEMENT EXECUTE FUNCTION openpc.guard_provider_retry_qualification();
REVOKE TRIGGER ON control.${name} FROM openpc_control_owner;`,
  )
  .join('\n')}
REVOKE ALL ON FUNCTION openpc.provider_retry_claims(text,bytea,bytea,text),openpc.require_provider_retry_evidence(text,uuid,text,text),openpc.guard_provider_retry_qualification() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.provider_retry_claims(text,bytea,bytea,text),openpc.require_provider_retry_evidence(text,uuid,text,text) TO openpc_operations_qualification_owner,openpc_control_owner;
`;
