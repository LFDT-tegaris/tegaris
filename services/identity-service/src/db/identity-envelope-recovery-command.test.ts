import { beforeEach, expect, it, vi } from 'vitest';
import { executeIdentityEnvelopeRecoveryCommand } from './identity-envelope-recovery-command.js';
import {
  platformRecoveryCommand,
  platformRecoveryAdministrationCommand,
} from '../contracts/platform-recovery.js';
import {
  discoveryCertificateRecoveryCommand,
  discoveryCertificateRecoveryOperations,
} from '../contracts/discovery-certificate-recovery.js';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from '../domain/identity-envelope-recovery.test-fixture.js';
const owner = vi.hoisted(() => ({
  create: vi.fn(),
  ceremony: vi.fn(),
  source: vi.fn(),
  read: vi.fn(),
  challenge: vi.fn(),
  proof: vi.fn(),
  activate: vi.fn(),
  close: vi.fn(),
  rotate: vi.fn(),
  queue: vi.fn(),
}));
vi.mock('./identity-envelope-recovery-rotation-queue.js', () => ({
  queueIdentityEnvelopeRecoveryRotation: owner.queue,
}));
vi.mock('./identity-envelope-recovery-rotation.js', () => ({
  createIdentityEnvelopeRecoveryRotation: owner.rotate,
}));
vi.mock('./identity-envelope-recovery-activation.js', () => ({
  activateIdentityEnvelopeRecoveryLease: owner.activate,
}));
vi.mock('./identity-envelope-recovery-closure.js', () => ({
  closeIdentityEnvelopeRecoveryCase: owner.close,
}));
vi.mock('./identity-envelope-recovery-case.js', () => ({
  createIdentityEnvelopeRecoveryCase: owner.create,
  readIdentityEnvelopeRecoveryCeremony: owner.ceremony,
}));
vi.mock('./identity-envelope-recovery-source.js', () => ({
  readIdentityEnvelopeRecoverySource: owner.source,
}));
vi.mock('./identity-envelope-recovery-readback.js', () => ({
  readIdentityEnvelopeRecoveryReceipt: owner.read,
}));
vi.mock('./platform-recovery-proof.js', () => ({
  issuePlatformRecoveryChallenge: owner.challenge,
  acceptPlatformRecoveryProof: owner.proof,
}));
beforeEach(() => vi.resetAllMocks());
it.each(['ROTATION_CREATE', 'ROTATION_ADVANCE'] as const)(
  'signer %s is strict and excluded from administration/discovery parsers',
  (kind) => {
    const command = {
      kind,
      recoveryId: id(200),
      ...(kind === 'ROTATION_ADVANCE'
        ? { expectedRevision: '2', idempotencyKey: 'original-phase-0001' }
        : {}),
    };
    expect(platformRecoveryCommand.safeParse(command).success).toBe(true);
    expect(platformRecoveryAdministrationCommand.safeParse(command).success).toBe(false);
    expect(discoveryCertificateRecoveryCommand.safeParse(command).success).toBe(false);
    expect(
      discoveryCertificateRecoveryOperations.some(
        (operation) => operation.command === (kind as string),
      ),
    ).toBe(false);
    expect(
      platformRecoveryCommand.safeParse({
        ...command,
        issuerPrincipalEpoch: '99',
        providerResult: { outcome: 'SUCCEEDED' },
      }).success,
    ).toBe(false);
  },
);
function fixture() {
  const f = identityEnvelopeRecoveryFixture();
  const actor = {
    participantId: f.enrollment.participantId,
    principalId: f.enrollment.recoveryPrincipal.principalId,
    sessionToken: 'unit-only',
    platform: true,
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 0, rows: [] });
  const client = { query } as never;
  const receipt = { state: 'REQUESTED', authority: 'NONE' };
  owner.read.mockResolvedValue({ receipt, session: { sessionId: id(220), sessionEpoch: '1' } });
  const invoke = (command: Parameters<typeof executeIdentityEnvelopeRecoveryCommand>[3]) =>
    executeIdentityEnvelopeRecoveryCommand(
      client,
      actor,
      f.enrollment.enrollmentId,
      command,
      'https://openpc.local',
      id(900),
      true,
      {} as never,
      { profile: 'C17', leaseMs: 900000, administratorMs: 3600000 },
    );
  return { ...f, actor, query, client, receipt, invoke };
}
it('empty CREATE invokes only the reserved signer case owner; Root preparation is forbidden', async () => {
  const f = fixture();
  owner.create.mockResolvedValue({ state: 'DRAFT', authority: 'NONE' });
  await expect(f.invoke({ kind: 'CREATE' })).resolves.toMatchObject({ authority: 'NONE' });
  await expect(f.invoke({ kind: 'CREATE', preparation: {} as never })).rejects.toThrow();
  expect(owner.create).toHaveBeenCalledOnce();
});
it('dispatches rotation creation to the exact custody owner without new WebAuthn consumption or ordinary approval', async () => {
  const f = fixture();
  owner.rotate.mockResolvedValue({ state: 'APPROVED', replay: false });
  await expect(f.invoke({ kind: 'ROTATION_CREATE', recoveryId: id(200) })).resolves.toMatchObject({
    state: 'APPROVED',
  });
  expect(owner.rotate).toHaveBeenCalledOnce();
  expect(owner.proof).not.toHaveBeenCalled();
  expect(owner.activate).not.toHaveBeenCalled();
});
it('routes advance to durable queue ownership and never consumes another custody proof', async () => {
  const f = fixture();
  owner.queue.mockResolvedValue({ state: 'READY', permissionEffect: 'NONE' });
  await expect(
    f.invoke({
      kind: 'ROTATION_ADVANCE',
      recoveryId: id(200),
      expectedRevision: '2',
      idempotencyKey: 'exact-original-phase-key',
    }),
  ).resolves.toMatchObject({ state: 'READY', permissionEffect: 'NONE' });
  expect(owner.queue).toHaveBeenCalledOnce();
  expect(owner.proof).not.toHaveBeenCalled();
  expect(owner.rotate).not.toHaveBeenCalled();
});
it('reconciles an exact consumed proof without verifying, reissuing or activating', async () => {
  const f = fixture();
  const assertion = JSON.stringify({ unit: 'original' });
  f.query.mockResolvedValue({
    rowCount: 1,
    rows: [{ assertion: JSON.parse(assertion), sessionId: id(220), sessionEpoch: '1' }],
  });
  await expect(
    f.invoke({
      kind: 'PROVE',
      phase: 'APPROVE',
      recoveryId: id(200),
      proof: {
        challengeId: id(201),
        challenge: 'a'.repeat(43),
        intentDigest: 'sha256:' + '11'.repeat(32),
        assertion,
      },
    }),
  ).resolves.toEqual(f.receipt);
  expect(owner.ceremony).not.toHaveBeenCalled();
  expect(owner.proof).not.toHaveBeenCalled();
  expect(f.query.mock.calls.some(([sql]) => /^(insert|update|delete)/iu.test(sql))).toBe(false);
});
it('persists the request proof before its exact case state transition', async () => {
  const f = fixture();
  f.query
    .mockResolvedValueOnce({ rowCount: 0, rows: [] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [] });
  owner.ceremony.mockResolvedValue({ state: 'DRAFT' });
  await f.invoke({
    kind: 'PROVE',
    phase: 'REQUEST',
    recoveryId: id(200),
    proof: {
      challengeId: id(201),
      challenge: 'a'.repeat(43),
      intentDigest: 'sha256:' + '11'.repeat(32),
      assertion: '{}',
    },
  });
  expect(owner.proof.mock.invocationCallOrder[0]).toBeLessThan(
    f.query.mock.invocationCallOrder[1]!,
  );
  expect(f.query.mock.calls[1]![0]).toContain('signer_repair_enrollment_id');
});
it('rejects invalid live activation context before consuming a proof or signing authority', async () => {
  const f = fixture();
  owner.ceremony.mockRejectedValue(new Error('invalid original custody'));
  await expect(
    f.invoke({ kind: 'CHALLENGE', phase: 'ACTIVATE', recoveryId: id(200) }),
  ).rejects.toThrow();
  expect(owner.proof).not.toHaveBeenCalled();
  expect(owner.challenge).not.toHaveBeenCalled();
  expect(owner.activate).not.toHaveBeenCalled();
});
it('dispatches fresh activation only to the dedicated signer fence owner', async () => {
  const f = fixture();
  owner.ceremony.mockResolvedValue({ state: 'REQUESTED' });
  owner.proof.mockResolvedValue({ proofId: id(703) });
  await f.invoke({
    kind: 'PROVE',
    phase: 'ACTIVATE',
    recoveryId: id(200),
    proof: {
      challengeId: id(201),
      challenge: 'a'.repeat(43),
      intentDigest: 'sha256:' + '11'.repeat(32),
      assertion: '{}',
    },
  });
  expect(owner.activate).toHaveBeenCalledOnce();
  expect(owner.activate.mock.calls[0]![3]).toEqual({ proofId: id(703) });
  expect(owner.proof.mock.invocationCallOrder[0]).toBeLessThan(
    owner.activate.mock.invocationCallOrder[0]!,
  );
});
it('terminal closure returns the existing receipt without a new closure/signature', async () => {
  const f = fixture();
  owner.read.mockResolvedValue({
    receipt: { state: 'REVOKED' },
    session: { sessionId: id(220), sessionEpoch: '1' },
  });
  await expect(f.invoke({ kind: 'CLOSE', recoveryId: id(200) })).resolves.toEqual({
    state: 'REVOKED',
  });
  expect(owner.close).not.toHaveBeenCalled();
});
