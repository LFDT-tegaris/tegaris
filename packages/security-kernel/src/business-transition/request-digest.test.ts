import { describe, expect, it } from 'vitest';
import { configurationRequestDigest, type ConfigurationRequestBinding } from './request-digest.js';

const binding: ConfigurationRequestBinding = {
  participantId: '01990000-0000-7000-8000-000000000001',
  privacyDomainId: '01990000-0000-7000-8000-000000000002',
  principalId: '01990000-0000-7000-8000-000000000003',
  actionIntentId: 'ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1',
  catalogOperationId: 'CFG-OP-UPDATE-INDEXER-PROFILE',
  aggregateType: 'indexer-profile',
  aggregateId: '01990000-0000-7000-8000-000000000004',
  expectedRevision: '18446744073709551615',
  candidateDigest: Buffer.alloc(32, 0x71),
  idempotencyKey: 'indexer-é-0001',
};

describe('normalized configuration request digest', () => {
  it('matches independent Python SHA-256 over 409 explicitly framed UTF-8 bytes including maximum u64', () => {
    expect(configurationRequestDigest(binding).toString('hex')).toBe(
      '7f6544e11f99aa3953b7e1bed7b5a9d8badfde746323b5940c7bc6393152d43f',
    );
  });
  it('binds every request field and distinguishes adjacent text boundaries', () => {
    const digest = configurationRequestDigest(binding);
    for (const key of Object.keys(binding) as (keyof ConfigurationRequestBinding)[]) {
      const value =
        key === 'candidateDigest'
          ? Buffer.alloc(32, 0x72)
          : key === 'expectedRevision'
            ? '9007199254740993'
            : `${binding[key]}a`;
      expect(configurationRequestDigest({ ...binding, [key]: value })).not.toEqual(digest);
    }
    expect(
      configurationRequestDigest({ ...binding, catalogOperationId: 'ab', aggregateType: 'c' }),
    ).not.toEqual(
      configurationRequestDigest({ ...binding, catalogOperationId: 'a', aggregateType: 'bc' }),
    );
  });
  it('rejects lossy, noncanonical, absent and oversized inputs', () => {
    for (const change of [
      { expectedRevision: '18446744073709551616' },
      { expectedRevision: '01' },
      { expectedRevision: '1e3' },
      { expectedRevision: '-1' },
      { expectedRevision: '' },
      { candidateDigest: Buffer.alloc(31) },
      { idempotencyKey: 'e\u0301' },
      { idempotencyKey: 'é'.repeat(129) },
      { privacyDomainId: '' },
    ])
      expect(() => configurationRequestDigest({ ...binding, ...change })).toThrow();
  });
});
