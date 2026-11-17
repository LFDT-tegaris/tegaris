/** Closed syntax only. The calling guards independently check actual role,
 * workload, signed profile and current scope. UUID casts have canonical text;
 * this fixed tuple is byte-identical to the native installer's compact JSON. */
export function factConsumerDatabaseRoleSql(role, participant, privacy) {
  return `(${role}~'^[a-z_][a-z0-9_]{0,62}$' OR (
    ${participant}::text~'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND ${privacy}::text~'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND ${role}='openpc_rs_login_'||translate(rtrim(encode(sha256(convert_to(
      '["openpc:runtime-source-scope:v1","'||${participant}::text||'","'||${privacy}::text||'"]',
      'UTF8')),'base64'),'='),'+/','-_')))`;
}
