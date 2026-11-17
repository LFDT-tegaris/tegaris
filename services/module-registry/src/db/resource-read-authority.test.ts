import { describe, expect, it } from 'vitest';
import { resourceReadAuthoritySql } from './resource-read-authority.js';

describe('collection resource authority bindings', () => {
  it('keeps UUID identity parameters typed when privacy checks also need text', () => {
    const sql = resourceReadAuthoritySql(
      'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1',
      'target.runtime_target_id',
    );
    expect(sql).toContain('assignment.participant_id=$1::uuid');
    expect(sql).toContain('$2::uuid::text=any(assignment.privacy_domain_ids)');
    expect(sql).toContain('principal.principal_id=$4::uuid');
    expect(sql).toContain('session.session_id=$5::uuid');
    expect(sql).toContain('session.privacy_domain_id=$2::uuid::uuid');
    expect(sql).toContain('target.runtime_target_id::text');
    expect(sql).toContain('session.authority_epoch=principal.authority_epoch');
    expect(sql).toContain(')=1');
  });

  it.each([
    ['ACT-RUNTIME_TARGETS_DELETE_RESOURCE-V1', 'target.runtime_target_id'],
    ['ACT-RUNTIME_TARGETS_READ_RESOURCE-V1', 'target.runtime_target_id; select 1'],
  ])('rejects an invalid owning action or resource expression', (action, column) => {
    expect(() => resourceReadAuthoritySql(action, column)).toThrow(
      'Invalid collection authority query',
    );
  });
});
