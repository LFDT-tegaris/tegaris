import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import type { IdentityRuntimeEvidenceSigner } from '../domain/identity-kernel.js';
import { identityEnvelopeEffectiveProofFixture } from '../../../participant-service/src/identity-envelope-rotation-proof.test-fixture.js';
import { recoveryFixtureId as id } from '../domain/identity-envelope-recovery.test-fixture.js';
import {
  requireCurrentRecoveryRotationActor,
  type RecoveryRotationContext,
} from './identity-envelope-recovery-rotation-context.js';
import {
  resolveIdentityEnvelopeRecoveryRotationPhase,
  resolveIdentityEnvelopeRecoveryPreparedDescriptor,
  resolveIdentityEnvelopeRecoveryDistributedDescriptor,
} from './identity-envelope-recovery-rotation-prepare.js';
import { resolveIdentityEnvelopeRecoveryVerification } from './identity-envelope-recovery-rotation-verification.js';
import { resolveIdentityEnvelopeRecoveryCutover } from './identity-envelope-recovery-rotation-cutover.js';
import { resolveIdentityEnvelopeRecoveryObservation } from './identity-envelope-recovery-rotation-observation.js';
import { resolveIdentityEnvelopeRecoveryRetirement } from './identity-envelope-recovery-rotation-retirement.js';

function fixture() {
  const f = identityEnvelopeEffectiveProofFixture();
  if (!('kind' in f.input.admission)) throw new Error();
  const { enrollment, lease } = f.input.admission;
  const context = {
    kind: 'HISTORICAL',
    subject: { participantId: enrollment.participantId, principalId: lease.executorPrincipalId },
  } satisfies RecoveryRotationContext;
  const signer: IdentityRuntimeEvidenceSigner = {
    verifyCanonicalAssertion: vi.fn(async () => undefined),
    signCanonicalAssertion: vi.fn(async () => {
      throw new Error('Historical read attempted signing');
    }),
  };
  return { enrollment, lease, context, signer };
}
const resolvers = [
  ['dispatch', resolveIdentityEnvelopeRecoveryRotationPhase],
  ['verification', resolveIdentityEnvelopeRecoveryVerification],
  ['cutover', resolveIdentityEnvelopeRecoveryCutover],
  ['observation', resolveIdentityEnvelopeRecoveryObservation],
  ['retirement', resolveIdentityEnvelopeRecoveryRetirement],
] as const;

it.each(resolvers)(
  '%s denies every unfinished historical step before recursion or live work',
  async (_name, resolve) => {
    for (const state of [undefined, 'READY', 'STARTED', 'WRITE_AMBIGUITY', 'FAILED']) {
      const f = fixture();
      const query = vi.fn(async (sql: string) => {
        if (!/^select /u.test(sql) || !sql.includes('for update of s'))
          throw new Error('Unexpected historical query');
        return { rowCount: state ? 1 : 0, rows: state ? [{ state, bound: true }] : [] };
      });
      await expect(
        resolve(
          { query } as unknown as PoolClient,
          f.context,
          f.enrollment,
          f.lease,
          id(900),
          false,
          f.signer,
        ),
      ).rejects.toThrow();
      expect(query).toHaveBeenCalledTimes(1);
      expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
      expect(f.signer.verifyCanonicalAssertion).not.toHaveBeenCalled();
    }
  },
);
it.each(resolvers)(
  '%s rejects a committed step whose original authority is not bound',
  async (_name, resolve) => {
    const f = fixture();
    const query = vi.fn(async () => ({
      rowCount: 1,
      rows: [{ state: 'COMMITTED', bound: false }],
    }));
    await expect(
      resolve(
        { query } as unknown as PoolClient,
        f.context,
        f.enrollment,
        f.lease,
        id(900),
        false,
        f.signer,
      ),
    ).rejects.toThrow();
    expect(query).toHaveBeenCalledTimes(1);
    expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  },
);
it.each(resolvers)(
  '%s rejects an unrelated historical subject before database access',
  async (_name, resolve) => {
    const f = fixture();
    for (const subject of [
      { participantId: id(990), principalId: f.lease.executorPrincipalId },
      { participantId: f.enrollment.participantId, principalId: id(991) },
    ]) {
      const query = vi.fn();
      await expect(
        resolve(
          { query } as unknown as PoolClient,
          { kind: 'HISTORICAL', subject },
          f.enrollment,
          f.lease,
          id(900),
          false,
          f.signer,
        ),
      ).rejects.toThrow();
      expect(query).not.toHaveBeenCalled();
      expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
    }
  },
);
it('keeps the full current authenticated actor for the live owners', () => {
  const f = fixture();
  const actor = { ...f.context.subject, sessionToken: 'unit-current-session', platform: true };
  expect(requireCurrentRecoveryRotationActor({ kind: 'CURRENT', actor })).toBe(actor);
  expect(() => requireCurrentRecoveryRotationActor(f.context)).toThrow();
});
it('propagates historical restriction into the original consumer-observation recursion', async () => {
  const f = fixture();
  const query = vi
    .fn()
    .mockResolvedValueOnce({
      rowCount: 1,
      rows: [
        {
          state: 'COMMITTED',
          bound: true,
          fromRevision: '9',
          fromState: 'OLD_RETIRED',
          toState: 'COMPLETE',
          consumerObservationId: id(901),
        },
      ],
    })
    .mockResolvedValueOnce({
      rowCount: 1,
      rows: [
        {
          state: 'STARTED',
          bound: true,
          fromRevision: '6',
          fromState: 'CUTOVER_FENCED',
          toState: 'OBSERVING',
        },
      ],
    });
  await expect(
    resolveIdentityEnvelopeRecoveryRetirement(
      { query } as unknown as PoolClient,
      f.context,
      f.enrollment,
      f.lease,
      id(900),
      false,
      f.signer,
    ),
  ).rejects.toThrow();
  expect(query).toHaveBeenCalledTimes(2);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
  expect(f.signer.verifyCanonicalAssertion).not.toHaveBeenCalled();
});
it.each([
  ['prepared', resolveIdentityEnvelopeRecoveryPreparedDescriptor],
  ['distributed', resolveIdentityEnvelopeRecoveryDistributedDescriptor],
] as const)('retains historical mode when resolving the %s descriptor', async (_name, resolve) => {
  const f = fixture();
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ operationId: id(900) }] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [{ state: 'STARTED', bound: true }] });
  await expect(
    resolve({ query } as unknown as PoolClient, f.context, f.enrollment, f.lease, false, f.signer),
  ).rejects.toThrow();
  expect(query).toHaveBeenCalledTimes(2);
  expect(f.signer.signCanonicalAssertion).not.toHaveBeenCalled();
});
