import { describe, expect, it } from 'vitest';
import { PlatformScopeOwnerFailure } from './platform-scope-owner-failure.js';
import { PlatformScopeReplacementError } from '../domain/platform-scope-replacement.js';

describe('closed Platform owner failure metadata', () => {
  it('retains SQLSTATE and stage without retaining driver or authority inputs', () => {
    const input = Object.assign(new Error('secret SQL bound inputs'), {
      code: '42501',
      detail: 'secret signed bytes',
      query: 'secret query',
    });
    const failure = new PlatformScopeOwnerFailure('atomic_commit', input);
    expect(failure).toMatchObject({
      ownerStage: 'atomic_commit',
      sqlstate: '42501',
      code: 'PC-IDENTITY-1001',
    });
    expect(failure).not.toHaveProperty('cause');
    expect(JSON.stringify(failure)).not.toContain('secret');
    expect(failure.message).not.toContain('secret');
  });
  it.each(['secret bytes', '42501 secret', 'pc-private-error'])(
    'rejects an unsafe SQLSTATE label %s',
    (code) => {
      expect(new PlatformScopeOwnerFailure('approval_binding', { code }).sqlstate).toBeUndefined();
    },
  );
  it('preserves a closed domain disposition for blocked readiness', () => {
    expect(
      new PlatformScopeOwnerFailure(
        'withdrawal_and_handoff_readiness',
        new PlatformScopeReplacementError('PENDING_WITHDRAWAL'),
      ),
    ).toMatchObject({
      ownerStage: 'withdrawal_and_handoff_readiness',
      disposition: 'PENDING_WITHDRAWAL',
      code: 'PC-IDENTITY-1009',
    });
  });
});
