import { signingTransitionMatrix } from '../../../../packages/security-kernel/src/signing-transitions.ts';
const literal = (value) => `'${value.replaceAll("'", "''")}'`;
const rows = signingTransitionMatrix
  .map(
    ({ action, prior, target, effects }) =>
      `(${[action, prior, target, JSON.stringify(effects)].map(literal).join(',')})`,
  )
  .join(',\n');
/** A missing action/prior/target tuple returns NULL and every consuming guard rejects it. */
export const signingTransitionGuardsSql = `
CREATE OR REPLACE FUNCTION openpc.signing_transition_effects(p_action text,p_prior text,p_target text)
RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT effects::jsonb FROM (VALUES ${rows}) matrix(action,prior,target,effects)
 WHERE action=p_action AND prior=p_prior AND target=p_target
$$;
`;
