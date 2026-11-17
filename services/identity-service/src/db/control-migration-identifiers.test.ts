import { describe, expect, it } from 'vitest';
import { getTableConfig } from 'drizzle-orm/pg-core';
import {
  assertPostgresConstraintNames,
  postgresIdentifier,
} from './control-migration-identifiers.js';
import { identityEnvelopeRecoveryEnrollments } from './schema/identity-envelope-recovery.js';

describe('PostgreSQL constraint identifiers', () => {
  it('rejects distinct generated foreign keys with the same stored identifier', () => {
    const prefix = 'identity_envelope_recovery_enrollment_participant_id_privacy_domain_id';
    expect(() =>
      assertPostgresConstraintNames('control', 'enrollment', [
        prefix + '_privacy_domain_fk',
        prefix + '_custody_trust_fk',
      ]),
    ).toThrow('identifier collision');
  });
  it('accounts for UTF-8 bytes without splitting characters', () => {
    expect(postgresIdentifier('é'.repeat(32))).toBe('é'.repeat(31));
    expect(() =>
      assertPostgresConstraintNames('control', 'example', [
        'é'.repeat(32) + 'a',
        'é'.repeat(32) + 'b',
      ]),
    ).toThrow('identifier collision');
  });
  it('checks constraints across kinds in the same table namespace', () => {
    expect(() => assertPostgresConstraintNames('control', 'example', ['same', 'same'])).toThrow();
    expect(() => assertPostgresConstraintNames('control', 'example', [''])).toThrow();
  });
  it('accepts the actual independent enrollment foreign keys', () => {
    const names = getTableConfig(identityEnvelopeRecoveryEnrollments).foreignKeys.map((k) =>
      k.getName(),
    );
    expect(names).toContain('identity_envelope_recovery_enrollment_privacy_fk');
    expect(names).toContain('identity_envelope_recovery_enrollment_custody_fk');
    expect(() =>
      assertPostgresConstraintNames('control', 'identity_envelope_recovery_enrollment', names),
    ).not.toThrow();
  });
});
