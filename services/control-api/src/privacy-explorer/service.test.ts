import { describe, expect, it, vi } from 'vitest';

import {
  buildB5Harness,
  projectionFor,
} from '../../../../tests/privacy/i07-gate2-b5-test-support.js';
import { executionRegistry } from '../contracts/privacy-explorer-adapter.js';
import {
  bindGovernedProjectionConsumer,
  type GovernedProjectionExecutionControl,
} from './consumer-port.js';
import { sha256CanonicalJson } from './canonical.js';
import { safeProblemForCondition } from './problems.js';
import { createPrivacyExplorerService } from './service.js';
import type { ExecutionPersistence } from './execution-persistence.js';
import { narrowIntent } from './narrowing.js';
import { preauthorize } from './preauthorization.js';
import { createProjectionRequest } from './request.js';
import { redactProjection } from './redaction.js';

describe('durable Privacy Explorer execution boundary', () => {
  it('keeps provider provenance and binds the public result to its opaque continuation', async () => {
    const harness = buildB5Harness({ implementation: { readGovernedProjection: vi.fn() } });
    const input = {
      ...harness.input,
      query: { ...harness.input.query, page: { limit: 2, cursor: 'pec1.public-reference' } },
    };
    const source = createProjectionRequest(
      narrowIntent(preauthorize(input.context, input.purposeAction), input.profile, {
        ...input.query,
        page: { limit: 2, cursor: 'external-secret-cursor' },
      }),
      input.seed,
    );
    const logical = createProjectionRequest(
      narrowIntent(preauthorize(input.context, input.purposeAction), input.profile, input.query),
      input.seed,
    );
    const provider = projectionFor(source.request, source.context);
    const received: unknown[] = [];
    const port = bindGovernedProjectionConsumer(input.profile, {
      readGovernedProjection: async (request) => {
        received.push(request);
        return provider;
      },
      verifyEvidenceReference: async () => {
        throw new Error('unused evidence verification');
      },
    });
    const result = await createPrivacyExplorerService(
      port,
      undefined,
      async (value) => {
        expect(value.projection.responseDigest).toBe(provider.responseDigest);
        expect(value.projection.requestDigest).toBe(source.requestDigest);
        expect(value.boundary.requestDigest).toBe(logical.requestDigest);
        return redactProjection(value, {
          fieldsForRecord: () => ['PEF-A'],
          recordReference: () => 'per1.opaque',
          cursor: null,
        });
      },
      source,
    ).read(input);
    expect(result.response).toMatchObject({ requestDigest: logical.requestDigest });
    expect(result.evidence.requestDigest).toBe(logical.requestDigest);
    expect(received).toEqual([logical.request]);
    expect(JSON.stringify(result)).not.toContain('external-secret-cursor');
  });

  it('rejects a continuation that changes fields before custody or an external effect', async () => {
    const read = vi.fn();
    const harness = buildB5Harness({ implementation: { readGovernedProjection: read } });
    const input = harness.input;
    const widened = createProjectionRequest(
      narrowIntent(preauthorize(input.context, input.purposeAction), input.profile, {
        ...input.query,
        projectionFields: ['PEF-A'],
      }),
      input.seed,
    );
    const persistence: ExecutionPersistence = { create: vi.fn(), transition: vi.fn() };
    await expect(
      createPrivacyExplorerService(harness.port, persistence, undefined, widened).read(input),
    ).rejects.toThrow('continuation broadened');
    expect(read).not.toHaveBeenCalled();
    expect(persistence.create).not.toHaveBeenCalled();
  });
  it('does not contact the external system when occurrence custody is unavailable', async () => {
    const read = vi.fn();
    const harness = buildB5Harness({ implementation: { readGovernedProjection: read } });
    const persistence: ExecutionPersistence = {
      create: async () => {
        throw new Error('custody unavailable');
      },
      transition: vi.fn(),
    };
    await expect(
      createPrivacyExplorerService(harness.port, persistence).read(harness.input),
    ).rejects.toThrow('custody unavailable');
    expect(read).not.toHaveBeenCalled();
    expect(persistence.transition).not.toHaveBeenCalled();
  });

  it('waits for dispatch custody and never returns a candidate after an ambiguous evidence write', async () => {
    let unblock!: () => void;
    const dispatch = new Promise<void>((resolve) => {
      unblock = resolve;
    });
    let dispatchRecorded!: () => void;
    const recording = new Promise<void>((resolve) => {
      dispatchRecorded = resolve;
    });
    const stored: unknown[] = [];
    const read = vi.fn((request, context) => Promise.resolve(projectionFor(request, context)));
    const harness = buildB5Harness({ implementation: { readGovernedProjection: read } });
    const persistence: ExecutionPersistence = {
      create: async (_boundary, initial) => {
        stored.push(initial);
      },
      transition: async (_boundary, _previous, next, evidence) => {
        stored.push(next);
        if (next.adapterEffectId === 'DISPATCH_STARTED') {
          dispatchRecorded();
          await dispatch;
        }
        if (evidence) throw new Error('ambiguous custody acknowledgement');
      },
    };
    const result = createPrivacyExplorerService(harness.port, persistence).read(harness.input);
    await recording;
    expect(read).not.toHaveBeenCalled();
    unblock();
    await expect(result).rejects.toThrow('ambiguous custody acknowledgement');
    expect(read).toHaveBeenCalledTimes(1);
    for (const snapshot of stored) {
      expect(snapshot).not.toHaveProperty('records');
      expect(snapshot).not.toHaveProperty('response');
      expect(snapshot).not.toHaveProperty('request');
    }
  });
});

describe('I07 Gate 2 B5 server-side Privacy Explorer composition', () => {
  it.each(['COMPLETE', 'PARTIAL', 'UNKNOWN', 'UNAVAILABLE'] as const)(
    'releases one generated %s result and matching disposed-raw evidence',
    async (outcome) => {
      let calls = 0;
      const harness = buildB5Harness({
        implementation: {
          readGovernedProjection(request, context) {
            calls += 1;
            return Promise.resolve(projectionFor(request, context, outcome));
          },
        },
      });
      const result = await createPrivacyExplorerService(harness.port).read(harness.input);
      expect(calls).toBe(1);
      expect(result.response).toMatchObject({
        outcome,
        truthState: outcome === 'COMPLETE' ? 'TRUE' : outcome === 'PARTIAL' ? 'PARTIAL' : outcome,
      });
      expect(result.evidence).toMatchObject({ outcome, rawState: 'DISPOSED' });
      expect(result.response).toHaveProperty('requestDigest', result.evidence.requestDigest);
      expect(result.response).not.toHaveProperty('freshness');
      expect(result.response).not.toHaveProperty('conflict');
      expect(result.evidence).not.toHaveProperty('records');
    },
  );

  it('denies a mismatched terminal purpose before creating a call or effect', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection() {
          calls += 1;
          return Promise.resolve(undefined);
        },
      },
    });
    await expect(
      createPrivacyExplorerService(harness.port).read({
        ...harness.input,
        purposeAction: { purpose: 'audit', action: 'write', resource: 'resource-a' },
      }),
    ).rejects.toThrow('common terminal denial');
    expect(calls).toBe(0);
  });

  it('admits a genuinely returned complete empty projection without fabricating fallback data', async () => {
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection(request, context) {
          const projection = { ...projectionFor(request, context), records: [] };
          const preimage = Object.fromEntries(
            Object.entries(projection).filter(([key]) => key !== 'responseDigest'),
          );
          return Promise.resolve({ ...preimage, responseDigest: sha256CanonicalJson(preimage) });
        },
      },
    });
    const result = await createPrivacyExplorerService(harness.port).read(harness.input);
    expect(result.response).toMatchObject({ outcome: 'COMPLETE', records: [] });
    expect(result.evidence.rawState).toBe('DISPOSED');
  });

  it('rejects extra service fields and accessor inputs without evaluating the accessor', async () => {
    let calls = 0;
    let getterCalls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection() {
          calls += 1;
          return Promise.resolve(undefined);
        },
      },
    });
    await expect(
      createPrivacyExplorerService(harness.port).read({
        ...harness.input,
        endpoint: 'https://caller.invalid',
      } as typeof harness.input),
    ).rejects.toThrow('invalid Privacy Explorer service input');
    const accessor = { ...harness.input };
    Object.defineProperty(accessor, 'query', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return harness.input.query;
      },
    });
    await expect(createPrivacyExplorerService(harness.port).read(accessor)).rejects.toThrow(
      'invalid Privacy Explorer service input',
    );
    expect(getterCalls).toBe(0);
    expect(calls).toBe(0);
  });

  it('rejects invalid query input and a foreign profile-bound port before invocation', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection() {
          calls += 1;
          return Promise.resolve(undefined);
        },
      },
    });
    await expect(
      createPrivacyExplorerService(harness.port).read({
        ...harness.input,
        query: { ...harness.input.query, projectionFields: ['PEF-X'] },
      }),
    ).rejects.toThrow('forbidden projection field');
    const foreign = bindGovernedProjectionConsumer(harness.profile, {
      verifyEvidenceReference: async () => ({}),
      readGovernedProjection: () => Promise.resolve(undefined),
    } as never);
    const other = buildB5Harness({
      authorizationContextId: '123e4567-e89b-42d3-a456-426614174109',
      profileRegistrationId: '123e4567-e89b-42d3-a456-426614174111',
      implementation: { readGovernedProjection: () => Promise.resolve(undefined) },
    });
    await expect(createPrivacyExplorerService(foreign).read(other.input)).rejects.toThrow(
      'projection consumer registration mismatch',
    );
    expect(calls).toBe(0);
  });

  it.each([
    [
      'malformed',
      (raw: Record<string, unknown>) => {
        raw.schemaVersion = '2.0';
      },
      'PC-RUNTIME-3009',
    ],
    [
      'order',
      (raw: Record<string, unknown>) => {
        (raw.records as Array<{ id: string; fields: unknown[] }>).push({
          ...(raw.records as Array<{ id: string; fields: unknown[] }>)[0]!,
          fields: [],
        });
      },
      'PC-OPS-9004',
    ],
    [
      'stale',
      (raw: Record<string, unknown>) => {
        raw.freshness = 'STALE';
      },
      'PC-FACT-4002',
    ],
    [
      'reorg',
      (raw: Record<string, unknown>) => {
        raw.conflict = 'REORG';
      },
      'PC-FACT-4003',
    ],
    [
      'conflict',
      (raw: Record<string, unknown>) => {
        raw.conflict = 'CONFLICT';
      },
      'PC-RUNTIME-3011',
    ],
  ] as const)(
    'turns an isolated %s return into its safe no-leak response',
    async (_name, mutate, code) => {
      const harness = buildB5Harness({
        implementation: {
          readGovernedProjection(request, context) {
            const raw = projectionFor(request, context) as unknown as Record<string, unknown>;
            mutate(raw);
            const preimage = Object.fromEntries(
              Object.entries(raw).filter(([key]) => key !== 'responseDigest'),
            );
            raw.responseDigest = sha256CanonicalJson(preimage);
            return Promise.resolve(raw);
          },
        },
      });
      const result = await createPrivacyExplorerService(harness.port).read(harness.input);
      expect(result.response).toMatchObject({ code });
      expect(result.evidence.rawState).toBe('DISPOSED');
    },
  );

  it('closes a no-byte rejection without fabricating an empty success', async () => {
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection() {
          return Promise.reject(new Error('private connector failure'));
        },
      },
    });
    const result = await createPrivacyExplorerService(harness.port).read(harness.input);
    expect(result.response).toMatchObject({ code: 'PC-INTEGRATION-5001' });
    expect(result.evidence.rawState).toBe('NEVER_CREATED');
  });

  it.each(executionRegistry.conditionDefinitions)(
    'preserves exact registered adapter problem $id without creating raw state',
    async (condition) => {
      const problem = safeProblemForCondition(condition.id);
      const harness = buildB5Harness({
        implementation: {
          readGovernedProjection() {
            return Promise.resolve(problem);
          },
        },
      });
      const result = await createPrivacyExplorerService(harness.port).read(harness.input);
      expect(result.disposition).toBe('RELEASED');
      expect(result.response).toEqual(problem);
      expect(result.evidence.rawState).toBe('NEVER_CREATED');
    },
  );

  it('suppresses a cancellation before dispatch with no consumer call', async () => {
    let calls = 0;
    const controller = new AbortController();
    controller.abort();
    const harness = buildB5Harness({
      signal: controller.signal,
      implementation: {
        readGovernedProjection() {
          calls += 1;
          return Promise.resolve(undefined);
        },
      },
    });
    const result = await createPrivacyExplorerService(harness.port).read(harness.input);
    expect(calls).toBe(0);
    expect(result.disposition).toBe('SUPPRESSED');
    expect(result).not.toHaveProperty('response');
    expect(result.evidence.rawState).toBe('NEVER_CREATED');
  });

  it('closes promptly on cancellation and ignores a later adapter settlement', async () => {
    const controller = new AbortController();
    let resolveRead!: (value: unknown) => void;
    let callStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      callStarted = resolve;
    });
    const returned = new Promise<unknown>((resolve) => {
      resolveRead = resolve;
    });
    const harness = buildB5Harness({
      signal: controller.signal,
      implementation: {
        readGovernedProjection(...arguments_: unknown[]) {
          const [request, context, control] = arguments_ as [
            Parameters<typeof projectionFor>[0],
            Parameters<typeof projectionFor>[1],
            GovernedProjectionExecutionControl,
          ];
          expect(control.signal).toBe(controller.signal);
          callStarted();
          return returned.then(() => projectionFor(request, context));
        },
      },
    });
    const pending = createPrivacyExplorerService(harness.port).read(harness.input);
    await started;
    controller.abort();
    await Promise.resolve();
    resolveRead(undefined);
    const result = await pending;
    expect(result.disposition).toBe('SUPPRESSED');
    expect(result).not.toHaveProperty('response');
    expect(result.evidence.rawState).toBe('NEVER_CREATED');
  });

  it.each(['VALUE', 'REJECTION'] as const)(
    'lets admitted cancellation beat a simultaneous retryable %s without retry or release',
    async (settlement) => {
      const controller = new AbortController();
      let calls = 0;
      const harness = buildB5Harness({
        signal: controller.signal,
        implementation: {
          readGovernedProjection() {
            calls += 1;
            controller.abort();
            return settlement === 'VALUE'
              ? Promise.resolve(safeProblemForCondition('EXP-COND-004'))
              : Promise.reject(new Error('private connector failure'));
          },
        },
      });
      const result = await createPrivacyExplorerService(harness.port).read(harness.input);
      expect(calls).toBe(1);
      expect(result.disposition).toBe('SUPPRESSED');
      expect(result).not.toHaveProperty('response');
      expect(result.evidence.rawState).toBe('NEVER_CREATED');
    },
  );

  it('consumes one admitted signal identity across caller replacement and bounded retry', async () => {
    let calls = 0;
    const admitted = new AbortController();
    const replacement = new AbortController();
    const harness = buildB5Harness({
      signal: admitted.signal,
      implementation: {
        readGovernedProjection(request, context) {
          calls += 1;
          return calls === 1
            ? Promise.resolve(safeProblemForCondition('EXP-COND-004'))
            : Promise.resolve(projectionFor(request, context));
        },
      },
    });
    const mutableInput = { ...harness.input };
    const pending = createPrivacyExplorerService(harness.port).read(mutableInput);
    mutableInput.signal = replacement.signal;
    replacement.abort();

    const result = await pending;
    expect(admitted.signal.aborted).toBe(false);
    expect(calls).toBe(2);
    expect(result.disposition).toBe('RELEASED');
    expect(result.response).toMatchObject({ outcome: 'COMPLETE' });
  });

  it('honours the admitted signal after caller deletion and redefinition', async () => {
    let calls = 0;
    let callStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      callStarted = resolve;
    });
    const admitted = new AbortController();
    const replacement = new AbortController();
    const harness = buildB5Harness({
      signal: admitted.signal,
      implementation: {
        readGovernedProjection() {
          calls += 1;
          callStarted();
          return new Promise(() => {});
        },
      },
    });
    const mutableInput = { ...harness.input };
    const pending = createPrivacyExplorerService(harness.port).read(mutableInput);
    await started;
    delete mutableInput.signal;
    Object.defineProperty(mutableInput, 'signal', {
      configurable: true,
      enumerable: true,
      value: replacement.signal,
      writable: true,
    });
    admitted.abort();

    const result = await pending;
    expect(replacement.signal.aborted).toBe(false);
    expect(calls).toBe(1);
    expect(result.disposition).toBe('SUPPRESSED');
    expect(result).not.toHaveProperty('response');
    expect(result.evidence.rawState).toBe('NEVER_CREATED');
  });

  it('retries only retryable no-byte/unavailable reads within the registered bound', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection(request, context) {
          calls += 1;
          return calls === 1
            ? Promise.reject(new Error('private connector failure'))
            : Promise.resolve(projectionFor(request, context));
        },
      },
    });
    const result = await createPrivacyExplorerService(harness.port).read(harness.input);
    expect(calls).toBe(2);
    expect(result.response).toMatchObject({ outcome: 'COMPLETE' });
  });

  it('does not retry a returned non-retryable problem', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection() {
          calls += 1;
          return Promise.resolve(safeProblemForCondition('EXP-COND-002'));
        },
      },
    });
    const result = await createPrivacyExplorerService(harness.port).read(harness.input);
    expect(calls).toBe(1);
    expect(result.response).toMatchObject({ code: 'PC-RUNTIME-3009' });
  });

  it('closes a never-settling read at the caller deadline without awaiting late bytes', async () => {
    vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout'] });
    try {
      let calls = 0;
      let settled = false;
      const harness = buildB5Harness({
        implementation: {
          readGovernedProjection() {
            calls += 1;
            return new Promise(() => {});
          },
        },
      });
      const now = Date.now();
      const pending = createPrivacyExplorerService(harness.port)
        .read({
          ...harness.input,
          seed: {
            ...harness.input.seed,
            now: new Date(now).toISOString(),
            deadlineAt: new Date(now + 30).toISOString(),
          },
        })
        .then((result) => {
          settled = true;
          return result;
        });
      await vi.advanceTimersByTimeAsync(29);
      expect(calls).toBe(1);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      const result = await pending;
      expect(calls).toBe(1);
      expect(result.response).toMatchObject({ code: 'PC-OPS-9003' });
      expect(result.evidence.rawState).toBe('NEVER_CREATED');
    } finally {
      vi.useRealTimers();
    }
  });

  it('closes a never-settling read promptly when cancelled and starts no retry', async () => {
    let calls = 0;
    let started!: () => void;
    const dispatched = new Promise<void>((resolve) => {
      started = resolve;
    });
    const controller = new AbortController();
    const harness = buildB5Harness({
      signal: controller.signal,
      implementation: {
        readGovernedProjection() {
          calls += 1;
          started();
          return new Promise(() => {});
        },
      },
    });
    const pending = createPrivacyExplorerService(harness.port).read(harness.input);
    await dispatched;
    controller.abort();
    const result = await pending;
    expect(calls).toBe(1);
    expect(result.disposition).toBe('SUPPRESSED');
    expect(result).not.toHaveProperty('response');
    expect(result.evidence.rawState).toBe('NEVER_CREATED');
  });

  it('closes cancellation after a no-byte settlement without a response', async () => {
    const controller = new AbortController();
    let rejectRead!: (reason: Error) => void;
    let callStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      callStarted = resolve;
    });
    const returned = new Promise<never>((_resolve, reject) => {
      rejectRead = reject;
    });
    const harness = buildB5Harness({
      signal: controller.signal,
      implementation: {
        readGovernedProjection() {
          callStarted();
          return returned;
        },
      },
    });
    const pending = createPrivacyExplorerService(harness.port).read(harness.input);
    await started;
    controller.abort();
    await Promise.resolve();
    rejectRead(new Error('private connector failure'));
    const result = await pending;
    expect(result.disposition).toBe('SUPPRESSED');
    expect(result).not.toHaveProperty('response');
    expect(result.evidence.rawState).toBe('NEVER_CREATED');
  });

  it('rejects exact replay and conflicting occurrence before a second consumer call', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection(request, context) {
          calls += 1;
          return Promise.resolve(projectionFor(request, context));
        },
      },
    });
    const service = createPrivacyExplorerService(harness.port);
    await service.read(harness.input);
    await expect(service.read(harness.input)).rejects.toThrow('undeclared execution event');
    expect(calls).toBe(1);

    const conflicting = buildB5Harness({
      authorizationContextId: '123e4567-e89b-42d3-a456-426614174110',
      implementation: {
        readGovernedProjection() {
          calls += 1;
          return Promise.resolve(undefined);
        },
      },
    });
    await expect(service.read({ ...conflicting.input, profile: harness.profile })).rejects.toThrow(
      'conflicting execution occurrence',
    );
    expect(calls).toBe(1);
  });
});
