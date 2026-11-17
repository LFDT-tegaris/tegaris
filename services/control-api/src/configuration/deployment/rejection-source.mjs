import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('./rejection-source.sql', import.meta.url), 'utf8');

/** The same immutable source lookup feeds cryptographic readback and retention.
 * SECURITY INVOKER preserves the caller's actual scope and table privileges.
 */
export const deploymentRejectionSourceSql = `
CREATE OR REPLACE FUNCTION openpc.deployment_rejection_source(command uuid,participant uuid,privacy uuid)
RETURNS TABLE(signed_bytes bytea,result_digest text,created_at text,preparation_bytes bytea,
 publication_bytes bytea,signed_transaction text,candidate_digest text,evidence_digest text,
 attempt_id text,actor_principal_id text)
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
${source}
$$;
REVOKE ALL ON FUNCTION openpc.deployment_rejection_source(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openpc.deployment_rejection_source(uuid,uuid,uuid)
 TO openpc_control_worker,openpc_control_runtime;
`;
