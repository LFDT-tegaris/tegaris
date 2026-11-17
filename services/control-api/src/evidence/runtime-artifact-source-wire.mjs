// Closed typed Rust V2 wire layout. Control business receipts use a different,
// sorted JSON format; changing native encoding would invalidate originals.
const installation = {
  participant_id: 'string',
  privacy_domain_id: 'string',
  source_owner_id: 'string',
  source_file_binding: 'string',
};
export const runtimeSourceDenialClaimsShape = {
  version: 'uint',
  admission: {
    installation,
    disposition_id: 'string',
    operation_id: 'string',
    input_id: 'string',
    configuration_digest: 'string',
    admission_receipt_digest: 'string',
    selection_digest: 'string',
  },
  sequence: 'uint',
  previous_denial_digest: 'nullable-string',
  recovery: 'string',
  custody: {
    profile: 'string',
    binding: {
      generation_id: 'string',
      journal_binding: 'string',
      retained_root_binding: 'string',
      consumer_profile: 'string',
      database: { system_identifier: 'string', database_oid: 'string' },
    },
    input: {
      input_id: 'string',
      module_installation_id: 'string',
      module_configuration_generation_id: 'string',
      configuration_digest: 'string',
    },
    pending_digest: 'string',
    committed_digest: 'string',
    history_sequence: 'uint',
    history_head_digest: 'string',
    retained_head_digest: 'string',
    consumers: ['string'],
  },
};
export const runtimeSourceDenialEnvelopeShape = {
  purpose: 'string',
  claims: runtimeSourceDenialClaimsShape,
  claims_digest: 'string',
  signature_p1363_hex: 'string',
};

// Generate only this fixed schema. Invalid shapes yield NULL, so the trigger's
// exact byte comparison denies rather than accepting JSON semantic equivalence.
function orderedSql(value, shape) {
  if (shape === 'string')
    return `(CASE WHEN jsonb_typeof(${value})='string' THEN (${value})::text END)`;
  if (shape === 'nullable-string')
    return `(CASE WHEN ${value}='null'::jsonb THEN 'null' ELSE ${orderedSql(value, 'string')} END)`;
  if (shape === 'uint')
    return `(CASE WHEN jsonb_typeof(${value})='number' AND (${value})::text ~ '^(0|[1-9][0-9]{0,19})$'
      AND (${value})::numeric BETWEEN 0 AND 18446744073709551615 THEN (${value})::text END)`;
  if (Array.isArray(shape))
    return `(CASE WHEN jsonb_typeof(${value})='array' AND NOT EXISTS(
      SELECT 1 FROM jsonb_array_elements(${value}) item WHERE jsonb_typeof(item)<>'string')
      THEN openpc.signing_canonical_json(${value}) END)`;
  const fields = Object.entries(shape);
  const keys = `ARRAY[${fields.map(([key]) => `'${key}'`).join(',')}]::text[]`;
  return `(CASE WHEN jsonb_typeof(${value})='object' AND (${value}) ?& ${keys}
    AND (${value})-${keys}='{}'::jsonb THEN '{'||${fields
      .map(([key, nested]) => `'"${key}":'||${orderedSql(`(${value}->'${key}')`, nested)}`)
      .join("||','||")}||'}' END)`;
}

export const runtimeArtifactSourceWireSql = [
  ['claims', runtimeSourceDenialClaimsShape],
  ['envelope', runtimeSourceDenialEnvelopeShape],
]
  .map(
    ([kind, shape]) => `
CREATE OR REPLACE FUNCTION openpc.runtime_artifact_source_denial_${kind}_bytes(value jsonb)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT convert_to(${orderedSql('value', shape)},'UTF8')
$$;
REVOKE ALL ON FUNCTION openpc.runtime_artifact_source_denial_${kind}_bytes(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.runtime_artifact_source_denial_${kind}_bytes(jsonb) TO openpc_control_worker;
`,
  )
  .join('\n');
