import { describe, expect, it, vi } from 'vitest';

import { buildB5Harness } from '../../../../tests/privacy/i07-gate2-b5-test-support.js';
import {
  executionRegistry,
  type EvidenceReferenceV1,
} from '../contracts/privacy-explorer-adapter.js';
import { sha256CanonicalJson } from './canonical.js';
import {
  createEvidenceVerificationBoundary,
  readGovernedProjection,
  verifyEvidenceReference,
  type GovernedProjectionExecutionControl,
} from './consumer-port.js';
import { narrowIntent } from './narrowing.js';
import { preauthorize } from './preauthorization.js';
import { safeProblemForCondition } from './problems.js';
import { createProjectionRequest } from './request.js';

const digest = (character: string) => `sha256:${character.repeat(64)}`;

const verificationBoundary = (harness: ReturnType<typeof buildB5Harness>, deadlineAt?: string) => {
  const intent = preauthorize(harness.input.context, harness.input.purposeAction);
  const evidenceDigest = digest('e');
  const referencePreimage = {
    schemaVersion: '1.0' as const,
    evidenceDigest,
    occurrenceId: harness.input.context.occurrenceId,
    profileDigest: harness.input.profile.digest,
  };
  const reference: EvidenceReferenceV1 = {
    ...referencePreimage,
    referenceDigest: sha256CanonicalJson(referencePreimage),
  };
  return createEvidenceVerificationBoundary(
    intent,
    harness.input.profile,
    reference,
    deadlineAt ?? harness.input.seed.deadlineAt,
  );
};

const projectionBoundary = (harness: ReturnType<typeof buildB5Harness>) =>
  createProjectionRequest(
    narrowIntent(
      preauthorize(harness.input.context, harness.input.purposeAction),
      harness.input.profile,
      harness.input.query,
    ),
    harness.input.seed,
  );

describe('Privacy Explorer evidence-reference consumer boundary', () => {
  it('validates one exact reference and one exact verification result', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        verifyEvidenceReference(reference, context) {
          calls += 1;
          expect(context.idempotencyDigest).toBe(reference.referenceDigest);
          const preimage = {
            schemaVersion: '1.0' as const,
            referenceDigest: reference.referenceDigest,
            evidenceDigest: reference.evidenceDigest,
            verified: true,
          };
          return Promise.resolve({
            ...preimage,
            verificationDigest: sha256CanonicalJson(preimage),
          });
        },
      },
    });
    const boundary = verificationBoundary(harness);
    const result = await verifyEvidenceReference(harness.port, boundary);
    expect(result).toMatchObject({ verified: true });
    expect(Object.isFrozen(result)).toBe(true);
    expect(calls).toBe(1);
  });

  it('retains immutable validated reference and context bytes after construction', async () => {
    let observedEvidenceDigest = '';
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        verifyEvidenceReference(reference) {
          observedEvidenceDigest = reference.evidenceDigest;
          const preimage = {
            schemaVersion: '1.0' as const,
            referenceDigest: reference.referenceDigest,
            evidenceDigest: reference.evidenceDigest,
            verified: true,
          };
          return Promise.resolve({
            ...preimage,
            verificationDigest: sha256CanonicalJson(preimage),
          });
        },
      },
    });
    const intent = preauthorize(harness.input.context, harness.input.purposeAction);
    const evidenceDigest = digest('e');
    const referencePreimage = {
      schemaVersion: '1.0' as const,
      evidenceDigest,
      occurrenceId: harness.input.context.occurrenceId,
      profileDigest: harness.input.profile.digest,
    };
    const source: EvidenceReferenceV1 = {
      ...referencePreimage,
      referenceDigest: sha256CanonicalJson(referencePreimage),
    };
    const boundary = createEvidenceVerificationBoundary(
      intent,
      harness.input.profile,
      source,
      harness.input.seed.deadlineAt,
    );
    source.evidenceDigest = digest('f');
    expect(Object.isFrozen(boundary.reference)).toBe(true);
    expect(Object.isFrozen(boundary.context)).toBe(true);
    expect(Object.isFrozen(boundary.context.cancellation)).toBe(true);
    await expect(verifyEvidenceReference(harness.port, boundary)).resolves.toMatchObject({
      evidenceDigest,
    });
    expect(observedEvidenceDigest).toBe(evidenceDigest);
  });

  it('rejects a forged reference before invocation and contains a forged result after one invocation', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        verifyEvidenceReference(reference) {
          calls += 1;
          return Promise.resolve({
            schemaVersion: '1.0',
            referenceDigest: reference.referenceDigest,
            evidenceDigest: reference.evidenceDigest,
            verified: true,
            verificationDigest: digest('f'),
          });
        },
      },
    });
    const boundary = verificationBoundary(harness);
    const intent = preauthorize(harness.input.context, harness.input.purposeAction);
    expect(() =>
      createEvidenceVerificationBoundary(
        intent,
        harness.input.profile,
        { ...boundary.reference, referenceDigest: digest('a') },
        harness.input.seed.deadlineAt,
      ),
    ).toThrow('invalid evidence reference boundary');
    expect(calls).toBe(0);
    await expect(verifyEvidenceReference(harness.port, boundary)).resolves.toEqual(
      safeProblemForCondition('EXP-EVIDENCE'),
    );
    expect(calls).toBe(1);
  });

  it.each(executionRegistry.conditionDefinitions)(
    'preserves exact registered verification problem $id',
    async (condition) => {
      const problem = safeProblemForCondition(condition.id);
      const harness = buildB5Harness({
        implementation: {
          readGovernedProjection: async () => undefined,
          verifyEvidenceReference: async () => problem,
        },
      });
      await expect(
        verifyEvidenceReference(harness.port, verificationBoundary(harness)),
      ).resolves.toEqual(problem);
    },
  );

  it('rejects forged or accessor cancellation controls before invocation', async () => {
    let calls = 0;
    let getterCalls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        verifyEvidenceReference() {
          calls += 1;
          return Promise.resolve(undefined);
        },
      },
    });
    const boundary = verificationBoundary(harness);
    const accessor = Object.defineProperty({}, 'signal', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return new AbortController().signal;
      },
    });
    await expect(
      verifyEvidenceReference(harness.port, boundary, accessor as never),
    ).rejects.toThrow('invalid governed projection execution control');
    await expect(
      verifyEvidenceReference(harness.port, boundary, { signal: {} as AbortSignal }),
    ).rejects.toThrow('invalid governed projection execution control');
    expect(getterCalls).toBe(0);
    expect(calls).toBe(0);
  });

  it('blocks pre-aborted read and verification controls before either bound operation', async () => {
    let readCalls = 0;
    let verificationCalls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection() {
          readCalls += 1;
          return Promise.resolve(undefined);
        },
        verifyEvidenceReference() {
          verificationCalls += 1;
          return Promise.resolve(undefined);
        },
      },
    });
    const controller = new AbortController();
    controller.abort();
    await expect(
      readGovernedProjection(harness.port, projectionBoundary(harness), {
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: 'AbortError' });
    await expect(
      verifyEvidenceReference(harness.port, verificationBoundary(harness), {
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(readCalls).toBe(0);
    expect(verificationCalls).toBe(0);
  });

  it('passes the exact captured signal to never-settling read and verification operations', async () => {
    const readController = new AbortController();
    const verificationController = new AbortController();
    let readSignal: AbortSignal | undefined;
    let verificationSignal: AbortSignal | undefined;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection(...arguments_: unknown[]) {
          const control = arguments_[2] as GovernedProjectionExecutionControl;
          readSignal = control.signal;
          return new Promise((resolve) =>
            control.signal?.addEventListener('abort', () => resolve(undefined), {
              once: true,
            }),
          );
        },
        verifyEvidenceReference(...arguments_: unknown[]) {
          const control = arguments_[2] as GovernedProjectionExecutionControl;
          verificationSignal = control.signal;
          return new Promise(() => undefined);
        },
      },
    });
    const pendingRead = readGovernedProjection(harness.port, projectionBoundary(harness), {
      signal: readController.signal,
    });
    const pendingVerification = verifyEvidenceReference(
      harness.port,
      verificationBoundary(harness),
      { signal: verificationController.signal },
    );
    await Promise.resolve();
    expect(readSignal).toBe(readController.signal);
    expect(verificationSignal).toBe(verificationController.signal);
    readController.abort();
    verificationController.abort();
    await expect(pendingRead).rejects.toMatchObject({ name: 'AbortError' });
    await expect(pendingVerification).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('does not retry rejection and closes never-settling deadline/cancellation promptly', async () => {
    let rejectionCalls = 0;
    const rejecting = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        verifyEvidenceReference() {
          rejectionCalls += 1;
          return Promise.reject(new Error('private verification failure'));
        },
      },
    });
    const rejectedBoundary = verificationBoundary(rejecting);
    await expect(verifyEvidenceReference(rejecting.port, rejectedBoundary)).resolves.toMatchObject({
      code: 'PC-INTEGRATION-5001',
    });
    expect(rejectionCalls).toBe(1);

    let deadlineCalls = 0;
    const never = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        verifyEvidenceReference() {
          deadlineCalls += 1;
          return new Promise(() => {});
        },
      },
    });
    const deadlineBoundary = verificationBoundary(never, new Date(Date.now() + 30).toISOString());
    await expect(verifyEvidenceReference(never.port, deadlineBoundary)).resolves.toMatchObject({
      code: 'PC-OPS-9003',
    });
    expect(deadlineCalls).toBe(1);

    const preAborted = new AbortController();
    preAborted.abort();
    const preAbortedBoundary = verificationBoundary(never, '2099-01-01T00:00:00.000Z');
    await expect(
      verifyEvidenceReference(never.port, preAbortedBoundary, {
        signal: preAborted.signal,
      }),
    ).rejects.toMatchObject({
      name: 'AbortError',
      occurrenceId: preAbortedBoundary.reference.occurrenceId,
    });
    expect(deadlineCalls).toBe(1);

    const controller = new AbortController();
    const cancelBoundary = verificationBoundary(never, '2099-01-01T00:00:00.000Z');
    const timeoutSpy = vi.spyOn(globalThis, 'setTimeout');
    const pending = verifyEvidenceReference(never.port, cancelBoundary, {
      signal: controller.signal,
    });
    expect(timeoutSpy.mock.calls.some((call) => call[1] === 2_147_483_647)).toBe(true);
    controller.abort();
    await expect(pending).rejects.toMatchObject({
      name: 'AbortError',
      occurrenceId: cancelBoundary.reference.occurrenceId,
    });
    timeoutSpy.mockRestore();
    expect(deadlineCalls).toBe(2);
  });

  it('consumes one admitted verification signal despite caller replacement', async () => {
    let settle!: () => void;
    const settled = new Promise<void>((resolve) => {
      settle = resolve;
    });
    const admitted = new AbortController();
    const replacement = new AbortController();
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        async verifyEvidenceReference(reference) {
          await settled;
          const preimage = {
            schemaVersion: '1.0' as const,
            referenceDigest: reference.referenceDigest,
            evidenceDigest: reference.evidenceDigest,
            verified: true,
          };
          return { ...preimage, verificationDigest: sha256CanonicalJson(preimage) };
        },
      },
    });
    const control = { signal: admitted.signal };
    const pending = verifyEvidenceReference(harness.port, verificationBoundary(harness), control);
    control.signal = replacement.signal;
    replacement.abort();
    settle();

    await expect(pending).resolves.toMatchObject({ verified: true });
    expect(admitted.signal.aborted).toBe(false);
  });

  it('honours the admitted verification signal after caller deletion and redefinition', async () => {
    const admitted = new AbortController();
    const replacement = new AbortController();
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        verifyEvidenceReference: () => new Promise(() => {}),
      },
    });
    const boundary = verificationBoundary(harness);
    const control: { signal?: AbortSignal } = { signal: admitted.signal };
    const pending = verifyEvidenceReference(harness.port, boundary, control);
    delete control.signal;
    Object.defineProperty(control, 'signal', {
      configurable: true,
      enumerable: true,
      value: replacement.signal,
      writable: true,
    });
    admitted.abort();

    await expect(pending).rejects.toMatchObject({
      name: 'AbortError',
      occurrenceId: boundary.reference.occurrenceId,
    });
    expect(replacement.signal.aborted).toBe(false);
  });

  it('rejects a reference for a foreign profile before invocation', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection: async () => undefined,
        verifyEvidenceReference() {
          calls += 1;
          return Promise.resolve(undefined);
        },
      },
    });
    const foreign = buildB5Harness({
      profileRegistrationId: '123e4567-e89b-42d3-a456-426614174199',
      occurrenceId: '123e4567-e89b-42d3-a456-426614174198',
      correlationId: '123e4567-e89b-42d3-a456-426614174197',
      implementation: { readGovernedProjection: async () => undefined },
    });
    const boundary = verificationBoundary(foreign);
    await expect(verifyEvidenceReference(harness.port, boundary)).rejects.toThrow(
      'projection consumer registration mismatch',
    );
    expect(calls).toBe(0);
  });
});
