import { bindPolicyAuthoritySelectionSql } from '../../../identity-service/src/db/policy-authority-selection.js';

/** Collection builders own aliases/action IDs; request values remain bound. */
export function resourceReadAuthoritySql(actionIntentId: string, resourceColumn: string): string {
  if (
    !/^ACT-[A-Z][A-Z0-9_]*_READ_RESOURCE-V[1-9][0-9]*$/u.test(actionIntentId) ||
    !/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/u.test(resourceColumn)
  )
    throw new Error('Invalid collection authority query');
  return `(select count(*) from (${bindPolicyAuthoritySelectionSql([
    '$1::uuid',
    '$2::uuid',
    `'${actionIntentId}'`,
    `${resourceColumn}::text`,
    '$4::uuid',
    '$5::uuid',
    'false',
    'false',
    'true',
    'null::text',
    'null::text',
  ])}) live_read_authority)=1`;
}
