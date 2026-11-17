import {
  platformRecoveryCommand,
  platformRecoveryAdministrationCommand,
} from '../contracts/platform-recovery.js';
import { discoveryCertificateRecoveryCommand } from '../contracts/discovery-certificate-recovery.js';
import { readRecoveryEnrollmentPurpose } from './recovery-enrollment-purpose.js';
import { executeIdentityEnvelopeRecoveryCommand } from './identity-envelope-recovery-command.js';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  executeDiscoveryCertificateRecoveryCommand,
  executePlatformRecoveryCommand,
} from './platform-recovery-command.js';
import {
  readPlatformRecoveryCeremony,
  readPlatformRecoverySource,
} from './platform-recovery-case.js';
import {
  acceptPlatformRecoveryProof,
  readPlatformRecoverySession,
} from './platform-recovery-proof.js';
import { readPlatformScopeReplacementSource } from './platform-scope-replacement-store.js';
import { activatePlatformRecoveryLease } from './platform-recovery-activation.js';
import { readPlatformRecoveryReceipt } from './platform-recovery-readback.js';
import { platformRecoveryFixture } from '../domain/platform-recovery.test-fixture.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
vi.mock('./platform-recovery-case.js', () => ({
  readPlatformRecoveryCeremony: vi.fn(),
  createPlatformRecoveryCase: vi.fn(),
  readPlatformRecoverySource: vi.fn(),
}));
vi.mock('./platform-recovery-proof.js', () => ({
  acceptPlatformRecoveryProof: vi.fn(),
  issuePlatformRecoveryChallenge: vi.fn(),
  readPlatformRecoverySession: vi.fn(),
}));
vi.mock('./platform-scope-replacement-store.js', () => ({
  readPlatformScopeReplacementSource: vi.fn(),
}));
vi.mock('./platform-recovery-activation.js', () => ({ activatePlatformRecoveryLease: vi.fn() }));
vi.mock('./platform-recovery-readback.js', () => ({ readPlatformRecoveryReceipt: vi.fn() }));
vi.mock('./recovery-enrollment-purpose.js', () => ({ readRecoveryEnrollmentPurpose: vi.fn() }));
vi.mock('./identity-envelope-recovery-command.js', () => ({
  executeIdentityEnvelopeRecoveryCommand: vi.fn(),
}));
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(readRecoveryEnrollmentPurpose).mockResolvedValue(
    'pc.identity.platform-recovery-enrollment',
  );
});
it.each(['ROTATION_CREATE', 'ROTATION_ADVANCE'] as const)(
  'stored administration custody never admits signer %s',
  async (kind) => {
    const f = fixture('REQUEST');
    const command =
      kind === 'ROTATION_CREATE'
        ? { kind, recoveryId: id(200) }
        : {
            kind,
            recoveryId: id(200),
            expectedRevision: '2',
            idempotencyKey: 'original-phase-0001',
          };
    await expect(
      executePlatformRecoveryCommand(
        f.client,
        f.actor,
        f.enrollmentId,
        command,
        'https://openpc.local',
        id(900),
        true,
        f.signer,
      ),
    ).rejects.toThrow();
    expect(f.query).not.toHaveBeenCalled();
    expect(executeIdentityEnvelopeRecoveryCommand).not.toHaveBeenCalled();
  },
);
function fixture(phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE') {
  const { source, intent } = platformRecoveryFixture();
  const actor = {
    participantId: source.enrollment.participantId,
    principalId: source.enrollment.recoveryPrincipal.principalId,
    platform: true,
    sessionToken: `${source.enrollment.participantId}.${id(800)}`,
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 0, rows: [] });
  const client = { query } as never;
  const command = {
    kind: 'PROVE' as const,
    recoveryId: intent.recoveryId,
    phase,
    proof: {
      challengeId: id(810),
      challenge: 'a'.repeat(43),
      intentDigest: 'sha256:' + 'a'.repeat(64),
      assertion: JSON.stringify({ test: 'signed proof' }),
    },
  };
  const context = {
    enrollment: source.enrollment,
    intent,
    state: phase === 'REQUEST' ? 'DRAFT' : 'REQUESTED',
    proofs: [],
    now: source.now,
  };
  const proof = {
    ...source.enrollment.recoveryPrincipal,
    proofId: id(811),
    sessionId: id(800),
    sessionEpoch: '1',
    phase,
    intentDigest: command.proof.intentDigest,
    verifiedAt: source.now,
  };
  vi.mocked(readPlatformRecoveryCeremony).mockResolvedValue(context);
  vi.mocked(acceptPlatformRecoveryProof).mockResolvedValue(proof);
  const receipt = { state: 'ACTIVE', authority: 'FIXED_PLATFORM_HANDOFF_ONLY' };
  vi.mocked(readPlatformRecoveryReceipt).mockResolvedValue({
    receipt,
    session: { sessionId: id(800), sessionEpoch: '1' },
    enrollment: source.enrollment,
  } as never);
  return {
    client,
    query,
    command,
    context,
    proof,
    receipt,
    actor,
    enrollmentId: source.enrollment.enrollmentId,
    signer: {} as never,
  };
}
it('persists REQUEST before its state transition in the same supplied transaction', async () => {
  const v = fixture('REQUEST');
  v.query
    .mockResolvedValueOnce({ rowCount: 0, rows: [] })
    .mockResolvedValueOnce({ rowCount: 1, rows: [] });
  await expect(
    executePlatformRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      v.command,
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).resolves.toEqual(v.receipt);
  expect(v.query.mock.calls[1]![0]).toContain("state='REQUESTED'");
  expect(vi.mocked(acceptPlatformRecoveryProof).mock.invocationCallOrder[0]).toBeLessThan(
    v.query.mock.invocationCallOrder[1]!,
  );
  expect(activatePlatformRecoveryLease).not.toHaveBeenCalled();
});
it('ACTIVATE consumes its fresh proof before invoking the durable lease owner exactly once', async () => {
  const v = fixture('ACTIVATE');
  await executePlatformRecoveryCommand(
    v.client,
    v.actor,
    v.enrollmentId,
    v.command,
    'https://openpc.local',
    id(900),
    true,
    v.signer,
  );
  expect(activatePlatformRecoveryLease).toHaveBeenCalledWith(
    v.client,
    v.context,
    v.proof,
    id(900),
    v.signer,
  );
  expect(vi.mocked(acceptPlatformRecoveryProof).mock.invocationCallOrder[0]).toBeLessThan(
    vi.mocked(activatePlatformRecoveryLease).mock.invocationCallOrder[0]!,
  );
});
it('reconciles an exact consumed assertion without re-verification, signing or epoch rotation', async () => {
  const v = fixture('ACTIVATE');
  v.query.mockResolvedValue({
    rowCount: 1,
    rows: [
      { assertion: JSON.parse(v.command.proof.assertion), sessionId: id(800), sessionEpoch: '1' },
    ],
  });
  await expect(
    executePlatformRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      v.command,
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).resolves.toEqual(v.receipt);
  expect(acceptPlatformRecoveryProof).not.toHaveBeenCalled();
  expect(activatePlatformRecoveryLease).not.toHaveBeenCalled();
  expect(readPlatformRecoveryCeremony).not.toHaveBeenCalled();
});
it.each(['changed assertion', 'changed session'])(
  'denies consumed-proof replay with %s',
  async (failure) => {
    const v = fixture('ACTIVATE');
    v.query.mockResolvedValue({
      rowCount: 1,
      rows: [
        {
          assertion: failure === 'changed assertion' ? {} : JSON.parse(v.command.proof.assertion),
          sessionId: failure === 'changed session' ? id(999) : id(800),
          sessionEpoch: '1',
        },
      ],
    });
    await expect(
      executePlatformRecoveryCommand(
        v.client,
        v.actor,
        v.enrollmentId,
        v.command,
        'https://openpc.local',
        id(900),
        true,
        v.signer,
      ),
    ).rejects.toThrow();
    expect(acceptPlatformRecoveryProof).not.toHaveBeenCalled();
    expect(activatePlatformRecoveryLease).not.toHaveBeenCalled();
  },
);
it('a failed fresh proof prevents all downstream state and lease writes', async () => {
  const v = fixture('ACTIVATE');
  vi.mocked(acceptPlatformRecoveryProof).mockRejectedValue(new Error('invalid proof'));
  await expect(
    executePlatformRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      v.command,
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).rejects.toThrow('invalid proof');
  expect(activatePlatformRecoveryLease).not.toHaveBeenCalled();
  expect(v.query).toHaveBeenCalledOnce();
});

it.each([false, true])(
  'previews an exact handoff without creating authority (unused predecessor: %s)',
  async (unused) => {
    const v = fixture('REQUEST');
    const { source, intent } = platformRecoveryFixture();
    const oldNames = [
      intent.preparation.replacementId,
      ...intent.preparation.administrators.flatMap((a) => [a.envelopeId, a.assignmentId]),
    ];
    const originalTargets = [...intent.preparation.successorScope.administration.resourceIds];
    if (unused) source.root.grantable.administration.resourceIds.push(id(991));
    vi.mocked(readPlatformRecoverySource).mockResolvedValue({
      ...source,
      preparation: intent.preparation,
      ...(unused ? { uneffectedPreparation: intent.preparation } : {}),
    } as never);
    vi.mocked(readPlatformScopeReplacementSource).mockResolvedValue({
      affectedTargets: [],
    } as never);
    vi.mocked(readPlatformRecoverySession).mockResolvedValue({
      sessionId: id(800),
      sessionEpoch: '1',
      durationProfile: 'C17',
      expiresAt: new Date(source.now.getTime() + 900_000),
    });
    const result = await executePlatformRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      { kind: 'SOURCE' },
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    );
    expect(result).toMatchObject({
      authority: 'NONE',
      source: {
        rootEpoch: '2',
        rootRevision: '2',
        executorPrincipalId: source.enrollment.recoveryPrincipal.principalId,
      },
    });
    expect(result).toHaveProperty('preparation.predecessorDigest', source.rootDigest);
    if (unused && 'preparation' in result) {
      const next = result.preparation;
      const newNames = [
        next.replacementId,
        ...next.administrators.flatMap((a) => [a.envelopeId, a.assignmentId]),
      ];
      expect(new Set(next.successorScope.administration.resourceIds)).toEqual(
        new Set(
          originalTargets.map((name) =>
            oldNames.includes(name) ? newNames[oldNames.indexOf(name)] : name,
          ),
        ),
      );
      expect(next.successorScope.administration.resourceIds).not.toContain(id(991));
    }
    expect(v.query).not.toHaveBeenCalled();
    expect(activatePlatformRecoveryLease).not.toHaveBeenCalled();
  },
);
it('rejects a foreign actor before exposing the recovery source or Root target catalogue', async () => {
  const v = fixture('REQUEST');
  const { source, intent } = platformRecoveryFixture();
  vi.mocked(readPlatformRecoverySource).mockResolvedValue({
    ...source,
    preparation: intent.preparation,
  } as never);
  await expect(
    executePlatformRecoveryCommand(
      v.client,
      { ...v.actor, principalId: id(999) },
      v.enrollmentId,
      { kind: 'SOURCE' },
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).rejects.toThrow();
  expect(readPlatformScopeReplacementSource).not.toHaveBeenCalled();
  expect(readPlatformRecoverySession).not.toHaveBeenCalled();
});

it('dispatches only the stored signer purpose and never interprets empty CREATE as Root recovery', async () => {
  const v = fixture('REQUEST');
  vi.mocked(readRecoveryEnrollmentPurpose).mockResolvedValue(
    'pc.identity.identity-envelope-recovery-enrollment',
  );
  vi.mocked(executeIdentityEnvelopeRecoveryCommand).mockResolvedValue({
    state: 'DRAFT',
    authority: 'NONE',
  } as never);
  await expect(
    executePlatformRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      { kind: 'CREATE' },
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).resolves.toMatchObject({ authority: 'NONE' });
  expect(executeIdentityEnvelopeRecoveryCommand).toHaveBeenCalledOnce();
  vi.mocked(readRecoveryEnrollmentPurpose).mockResolvedValue(
    'pc.identity.platform-recovery-enrollment',
  );
  await expect(
    executePlatformRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      { kind: 'CREATE' },
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).rejects.toThrow();
  expect(executeIdentityEnvelopeRecoveryCommand).toHaveBeenCalledOnce();
  expect(activatePlatformRecoveryLease).not.toHaveBeenCalled();
});

it('denies a discovery enrollment on the shared Platform command owner', async () => {
  const v = fixture('REQUEST');
  vi.mocked(readRecoveryEnrollmentPurpose).mockResolvedValue(
    'pc.identity.discovery-certificate-recovery-enrollment',
  );
  await expect(
    executePlatformRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      { kind: 'CREATE' },
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).rejects.toThrow();
  expect(executeIdentityEnvelopeRecoveryCommand).not.toHaveBeenCalled();
  expect(activatePlatformRecoveryLease).not.toHaveBeenCalled();
  expect(acceptPlatformRecoveryProof).not.toHaveBeenCalled();
});

it('passes opt-in closed preparation digest only to the existing authenticated receipt owner', async () => {
  const v = fixture('REQUEST'),
    preparationDigest = 'sha256:' + 'a'.repeat(64);
  const command = { kind: 'READ' as const, recoveryId: id(200), preparationDigest };
  await expect(
    executePlatformRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      command,
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).resolves.toEqual(v.receipt);
  expect(readPlatformRecoveryReceipt).toHaveBeenCalledWith(
    v.client,
    v.actor,
    v.enrollmentId,
    command.recoveryId,
    v.signer,
    preparationDigest,
  );
  expect(v.query).not.toHaveBeenCalled();
  expect(activatePlatformRecoveryLease).not.toHaveBeenCalled();
});
it.each([
  'pc.identity.local-root-expiry-recovery-enrollment',
  'pc.identity.identity-envelope-recovery-enrollment',
] as const)(
  'denies opt-in correspondence for %s before other-purpose delegation',
  async (purpose) => {
    const v = fixture('REQUEST');
    vi.mocked(readRecoveryEnrollmentPurpose).mockResolvedValue(purpose);
    await expect(
      executePlatformRecoveryCommand(
        v.client,
        v.actor,
        v.enrollmentId,
        { kind: 'READ', recoveryId: id(200), preparationDigest: 'sha256:' + 'a'.repeat(64) },
        'https://openpc.local',
        id(900),
        true,
        v.signer,
      ),
    ).rejects.toThrow();
    expect(readPlatformRecoveryReceipt).not.toHaveBeenCalled();
    expect(executeIdentityEnvelopeRecoveryCommand).not.toHaveBeenCalled();
    expect(v.query).not.toHaveBeenCalled();
  },
);
it('Discovery rejects opt-in correspondence even for an internal typed caller', async () => {
  const v = fixture('REQUEST');
  await expect(
    executeDiscoveryCertificateRecoveryCommand(
      v.client,
      v.actor,
      v.enrollmentId,
      { kind: 'READ', recoveryId: id(200), preparationDigest: 'sha256:' + 'a'.repeat(64) },
      'https://openpc.local',
      id(900),
      true,
      v.signer,
    ),
  ).rejects.toThrow();
  expect(v.query).not.toHaveBeenCalled();
  expect(readPlatformRecoveryReceipt).not.toHaveBeenCalled();
});

it('opts the public platform schema into typed READ correspondence without widening shared administration or Discovery schemas', () => {
  const command = {
    kind: 'READ',
    recoveryId: id(200),
    preparationDigest: 'sha256:' + 'a'.repeat(64),
  };
  expect(platformRecoveryCommand.safeParse(command).success).toBe(true);
  expect(platformRecoveryAdministrationCommand.safeParse(command).success).toBe(false);
  expect(discoveryCertificateRecoveryCommand.safeParse(command).success).toBe(false);
  expect(platformRecoveryCommand.safeParse({ ...command, kind: 'CLOSE' }).success).toBe(false);
  expect(
    platformRecoveryCommand.safeParse({ ...command, preparationDigest: 'invalid' }).success,
  ).toBe(false);
});
