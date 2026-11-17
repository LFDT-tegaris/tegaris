import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { executionRegistry } from '../../services/control-api/src/contracts/privacy-explorer-adapter.js';
import {
  createPrivacyExplorerExecutionOracle,
  type ExecutionEventId,
  type PrivacyExplorerExecutionOracle,
} from '../../services/control-api/src/privacy-explorer/execution-oracle.js';
import { createEvidenceLifecycleOwner } from '../../services/control-api/src/privacy-explorer/evidence.js';
import { createExecutionOwner } from '../../services/control-api/src/privacy-explorer/execution-owner.js';
import type {
  ExecutionHandle,
  ExecutionSnapshot,
} from '../../services/control-api/src/privacy-explorer/execution-repository.js';
import { createExecutionRepository } from '../../services/control-api/src/privacy-explorer/execution-repository.js';
import { safeProblemForCondition } from '../../services/control-api/src/privacy-explorer/problems.js';
import {
  buildSafeProblemCandidate,
  type PublicResponseCandidate,
} from '../../services/control-api/src/privacy-explorer/result-candidate.js';
import type { GovernedProjectionBoundary } from '../../services/control-api/src/privacy-explorer/request.js';
import { buildB4Boundary, buildB4Candidate } from './i07-gate2-b4-test-support.js';

type Application =
  | (typeof executionRegistry.lifecycleApplications)[number]
  | (typeof executionRegistry.conditionApplications)[number]
  | (typeof executionRegistry.cancellationApplications)[number]
  | (typeof executionRegistry.contributionApplications)[number];

const allRows: readonly Application[] = [
  ...executionRegistry.lifecycleApplications,
  ...executionRegistry.conditionApplications,
  ...executionRegistry.cancellationApplications,
  ...executionRegistry.contributionApplications,
];

type Running = {
  oracle: PrivacyExplorerExecutionOracle;
  handle: ExecutionHandle;
  boundary: GovernedProjectionBoundary;
};

const event = (
  running: Running,
  eventId: ExecutionEventId,
  candidate?: PublicResponseCandidate,
) => {
  const before = running.oracle.inspect(running.handle);
  return running.oracle.apply(
    running.handle,
    before.revision,
    eventId,
    candidate ? { candidate } : undefined,
  );
};

const start = (): Running => {
  const oracle = createPrivacyExplorerExecutionOracle();
  const boundary = buildB4Boundary();
  return { oracle, boundary, handle: oracle.create(boundary) };
};

const reach = (target: string, row?: Application): Running => {
  const running = start();
  if (target === 'OPEN') return running;
  event(running, 'BIND_LOCAL_CONTEXT');
  if (target === 'CONTEXT_BOUND') return running;
  event(running, 'PREAUTHORIZE');
  if (target === 'PREAUTHORIZED') return running;
  event(running, 'NARROW_INTENT');
  if (target === 'INTENT_NARROWED') return running;
  event(running, 'CREATE_REQUEST');
  if (target === 'REQUEST_READY') return running;
  event(running, 'START_READ');
  if (target === 'READ_IN_FLIGHT_NO_RAW') return running;
  if (target === 'CANCEL_PENDING_NO_RAW') {
    event(running, 'CANCEL_DURING_READ');
    return running;
  }
  event(running, 'CAPTURE_BYTES');
  if (target === 'RESPONSE_CAPTURED_RAW_LIVE') return running;
  if (target === 'CANCEL_PENDING_RAW_LIVE') {
    event(running, 'CANCEL_AFTER_BYTES');
    return running;
  }
  event(running, 'VALIDATE_PROJECTION');
  if (target === 'PROJECTION_VALIDATED_RAW_LIVE') return running;
  event(running, 'REDACT_PROJECTION');
  if (target === 'PROJECTION_REDACTED_RAW_LIVE') return running;
  event(running, 'SELECT_COMPLETE', buildB4Candidate(running.boundary));
  if (target === 'OUTCOME_SELECTED_RAW_LIVE') return running;
  if (target === 'OUTCOME_READY_RAW_DISPOSED') {
    if (row?.eventId === 'CLOSE_CANCELLED') {
      event(running, 'CANCEL_AFTER_OUTCOME_SELECTION');
      event(running, 'DISPOSE_RAW');
    } else {
      event(running, 'DISPOSE_RAW');
    }
    return running;
  }
  throw new Error(`unsupported reachable state: ${target}`);
};

const reachTerminal = (
  target: 'OUTCOME_READY_NO_RAW' | 'RELEASED' | 'CANCELLED_CLOSED' | 'EVIDENCE_SEALED',
  row?: Application,
) => {
  if (target === 'OUTCOME_READY_NO_RAW') {
    if (row?.eventId === 'CLOSE_CANCELLED') {
      const running = reach('REQUEST_READY');
      event(running, 'CANCEL_BEFORE_DISPATCH');
      return running;
    }
    const running = start();
    event(running, 'DIRECT_BROWSER_ATTEMPT');
    return running;
  }
  if (target === 'CANCELLED_CLOSED') {
    const running = reach('REQUEST_READY');
    event(running, 'CANCEL_BEFORE_DISPATCH');
    event(running, 'CLOSE_CANCELLED');
    return running;
  }
  const running = start();
  event(running, 'DIRECT_BROWSER_ATTEMPT');
  event(running, 'RELEASE');
  if (target === 'EVIDENCE_SEALED') event(running, 'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS');
  return running;
};

const reachForRow = (row: Application) =>
  row.fromStateId === 'OUTCOME_READY_NO_RAW' ||
  row.fromStateId === 'RELEASED' ||
  row.fromStateId === 'CANCELLED_CLOSED' ||
  row.fromStateId === 'EVIDENCE_SEALED'
    ? reachTerminal(row.fromStateId, row)
    : reach(row.fromStateId, row);

const rowCandidate = (row: Application, boundary: GovernedProjectionBoundary) => {
  if (row.eventId === 'REGISTERED_SAFE_PROBLEM_RETURNED')
    return buildSafeProblemCandidate(boundary, safeProblemForCondition('EXP-COND-003'));
  const outcome = row.eventId.replace('SELECT_', '') as
    'COMPLETE' | 'PARTIAL' | 'UNKNOWN' | 'UNAVAILABLE';
  return row.eventId.startsWith('SELECT_') ? buildB4Candidate(boundary, outcome) : undefined;
};

const expectedRawState = (before: ExecutionSnapshot, effect: string) => {
  if (effect === 'NEVER_CREATED_TO_LIVE' || effect === 'LIVE') return 'LIVE';
  if (effect === 'LIVE_TO_DISPOSED' || effect === 'DISPOSED') return 'DISPOSED';
  return before.rawState;
};

const expectedDelivery = (before: ExecutionSnapshot, effect: string) => {
  if (effect === 'SUPPRESSED') return 'SUPPRESSED';
  if (effect === 'RELEASED') return 'RELEASED';
  return before.delivery;
};

describe('I07 Gate 2 B4 registry-derived lifecycle denominator', () => {
  it('derives exactly the generated 22/37/10/2 applications with unique state-event ownership', () => {
    expect(executionRegistry.lifecycleApplications).toHaveLength(22);
    expect(executionRegistry.conditionApplications).toHaveLength(37);
    expect(executionRegistry.cancellationApplications).toHaveLength(10);
    expect(executionRegistry.contributionApplications).toHaveLength(2);
    expect(new Set(allRows.map((row) => `${row.fromStateId}\u0000${row.eventId}`)).size).toBe(71);
  });

  it.each(allRows)('$id applies its generated transition and exact effects', (row) => {
    const running = reachForRow(row);
    const before = running.oracle.inspect(running.handle);
    const result = event(running, row.eventId, rowCandidate(row, running.boundary));
    expect(before.state).toBe(row.fromStateId);
    expect(result.snapshot.state).toBe(row.toStateId);
    expect(result.snapshot.occurrenceId).toBe(before.occurrenceId);
    expect(result.snapshot.rawState).toBe(expectedRawState(before, row.rawStateEffectId));
    expect(result.snapshot.delivery).toBe(expectedDelivery(before, row.deliveryEffectId));
    const disposition = row.disposition as Record<string, unknown>;
    if (disposition.kind === 'CONDITION')
      expect(result.problem).toEqual(
        safeProblemForCondition(disposition.conditionDefinitionId as string),
      );
    if (disposition.kind === 'RESULT') {
      const definition = executionRegistry.resultDefinitions.find(
        (entry) => entry.id === disposition.resultDefinitionId,
      );
      expect(result.snapshot.outcome).toBe(definition?.outcome);
    }
    if (
      row.toStateId === row.fromStateId &&
      row.rawStateEffectId !== 'NEVER_CREATED_TO_LIVE' &&
      row.rawStateEffectId !== 'LIVE_TO_DISPOSED' &&
      row.deliveryEffectId === 'UNCHANGED' &&
      row.adapterEffectId === 'NONE'
    ) {
      expect(result.snapshot).toBe(before);
      expect(result.snapshot.revision).toBe(before.revision);
    } else {
      expect(result.snapshot.revision).toBe(before.revision + 1);
      expect(result.snapshot.adapterEffectId).toBe(row.adapterEffectId);
      expect(result.snapshot.retainedFactId).toBe(row.retainedFactId);
    }
  });

  it.each(allRows)('$id rejects an isolated undeclared event with exact no effect', (row) => {
    const running = reachForRow(row);
    const before = running.oracle.inspect(running.handle);
    expect(() =>
      running.oracle.apply(
        running.handle,
        before.revision,
        `INVALID_${row.eventId}` as ExecutionEventId,
      ),
    ).toThrow('undeclared execution event');
    expect(running.oracle.inspect(running.handle)).toBe(before);
  });

  it('rejects stale CAS, caller-selected fields, cross-occurrence candidates, and competing writes', () => {
    const running = start();
    const initial = running.oracle.inspect(running.handle);
    event(running, 'BIND_LOCAL_CONTEXT');
    expect(() => running.oracle.apply(running.handle, initial.revision, 'PREAUTHORIZE')).toThrow(
      'stale execution revision',
    );
    const beforePayload = running.oracle.inspect(running.handle);
    expect(() =>
      running.oracle.apply(running.handle, beforePayload.revision, 'PREAUTHORIZE', {
        fromStateId: 'CONTEXT_BOUND',
      } as never),
    ).toThrow('invalid execution event payload');
    expect(running.oracle.inspect(running.handle)).toBe(beforePayload);

    let getterReads = 0;
    const accessorPayload = Object.defineProperty({}, 'candidate', {
      enumerable: true,
      get: () => {
        getterReads += 1;
        return buildB4Candidate(running.boundary);
      },
    });
    expect(() =>
      running.oracle.apply(
        running.handle,
        beforePayload.revision,
        'SELECT_COMPLETE',
        accessorPayload,
      ),
    ).toThrow('invalid execution event payload');
    expect(getterReads).toBe(0);
    expect(running.oracle.inspect(running.handle)).toBe(beforePayload);

    const selectable = reach('PROJECTION_REDACTED_RAW_LIVE');
    const otherCandidate = buildB4Candidate(buildB4Boundary());
    const beforeCross = selectable.oracle.inspect(selectable.handle);
    expect(() =>
      selectable.oracle.apply(selectable.handle, beforeCross.revision, 'SELECT_COMPLETE', {
        candidate: otherCandidate,
      }),
    ).toThrow('cross-occurrence candidate rejected');
    expect(selectable.oracle.inspect(selectable.handle)).toBe(beforeCross);

    const safeReturn = reach('READ_IN_FLIGHT_NO_RAW');
    const beforeUnsafeReturn = safeReturn.oracle.inspect(safeReturn.handle);
    expect(() =>
      event(safeReturn, 'REGISTERED_SAFE_PROBLEM_RETURNED', buildB4Candidate(safeReturn.boundary)),
    ).toThrow('execution event guard rejected');
    expect(safeReturn.oracle.inspect(safeReturn.handle)).toBe(beforeUnsafeReturn);

    const race = start();
    const revision = race.oracle.inspect(race.handle).revision;
    race.oracle.apply(race.handle, revision, 'BIND_LOCAL_CONTEXT');
    expect(() => race.oracle.apply(race.handle, revision, 'BIND_LOCAL_CONTEXT')).toThrow(
      'stale execution revision',
    );
  });

  it('binds exact occurrence replay to every admitted request and authorization-context byte', () => {
    const occurrenceId = '123e4567-e89b-42d3-a456-00000000abcd';
    const correlationId = '123e4567-e89b-42d3-a456-00000000abce';
    const first = buildB4Boundary({ occurrenceId, correlationId });
    const changedContext = buildB4Boundary({
      occurrenceId,
      correlationId,
      authorizationContextId: '123e4567-e89b-42d3-a456-00000000abcf',
    });
    const oracle = createPrivacyExplorerExecutionOracle();
    const handle = oracle.create(first);
    expect(oracle.create(first)).toBe(handle);
    expect(() => oracle.create(changedContext)).toThrow('conflicting execution occurrence');
    expect(oracle.inspect(handle).revision).toBe(0);
  });

  it('rejects a foreign repository snapshot at the raw-transition owner', () => {
    const boundary = buildB4Boundary();
    const firstRepository = createExecutionRepository();
    const secondRepository = createExecutionRepository();
    const executionOwner = createExecutionOwner(firstRepository, createEvidenceLifecycleOwner());
    const foreign = secondRepository.inspect(secondRepository.create(boundary));
    expect(() => executionOwner.authorizeCapture(foreign)).toThrow('foreign execution snapshot');
    expect(foreign).toBe(secondRepository.inspect(secondRepository.create(boundary)));
  });

  it('executes the complete undeclared reachable state-event grammar with no effect', () => {
    const eventIds = [...new Set(allRows.map((row) => row.eventId))];
    const declared = new Set(allRows.map((row) => `${row.fromStateId}\u0000${row.eventId}`));
    let rejected = 0;
    for (const state of executionRegistry.states) {
      for (const eventId of eventIds) {
        if (declared.has(`${state}\u0000${eventId}`)) continue;
        const running =
          state === 'OUTCOME_READY_NO_RAW' ||
          state === 'RELEASED' ||
          state === 'CANCELLED_CLOSED' ||
          state === 'EVIDENCE_SEALED'
            ? reachTerminal(state)
            : reach(state);
        const before = running.oracle.inspect(running.handle);
        expect(() => running.oracle.apply(running.handle, before.revision, eventId)).toThrow(
          'undeclared execution event',
        );
        expect(running.oracle.inspect(running.handle)).toBe(before);
        rejected += 1;
      }
    }
    expect(rejected).toBe(executionRegistry.states.length * eventIds.length - allRows.length);
  });

  it('blocks raw-live release, seals only safe raw evidence, and makes late cancellation immutable', () => {
    const rawLive = reach('OUTCOME_SELECTED_RAW_LIVE');
    const beforeLiveRelease = rawLive.oracle.inspect(rawLive.handle);
    expect(() => event(rawLive, 'RELEASE')).toThrow('undeclared execution event');
    expect(rawLive.oracle.inspect(rawLive.handle)).toBe(beforeLiveRelease);

    event(rawLive, 'DISPOSE_RAW');
    const released = event(rawLive, 'RELEASE');
    expect(released.released).toMatchObject({ outcome: 'COMPLETE', truthState: 'TRUE' });
    const beforeLate = released.snapshot;
    const late = event(rawLive, 'CANCEL_LATE_RELEASED');
    expect(late.snapshot).toBe(beforeLate);
    const sealed = event(rawLive, 'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS');
    expect(sealed.evidence).toMatchObject({ rawState: 'DISPOSED', outcome: 'COMPLETE' });
    const beforeEvidenceLate = sealed.snapshot;
    expect(event(rawLive, 'CANCEL_LATE_EVIDENCE').snapshot).toBe(beforeEvidenceLate);

    const noRaw = reachTerminal('RELEASED');
    expect(event(noRaw, 'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS').evidence).toMatchObject({
      rawState: 'NEVER_CREATED',
    });
  });

  it('keeps internal owners, raw state, contribution constructors, and browser bypass absent publicly', async () => {
    const publicIndex = await import('../../services/control-api/src/privacy-explorer/index.js');
    for (const forbidden of [
      'createExecutionRepository',
      'createPrivacyExplorerExecutionOracle',
      'createExecutionOwner',
      'createCompletionOwner',
      'createEvidenceLifecycleOwner',
      'PublicResponseCandidate',
      'RawStateWitness',
    ])
      expect(publicIndex).not.toHaveProperty(forbidden);
    const packageJson = JSON.parse(
      await readFile(new URL('../../services/control-api/package.json', import.meta.url), 'utf8'),
    ) as { exports: Record<string, string> };
    expect(Object.keys(packageJson.exports)).toEqual(['./privacy-explorer']);
    expect(JSON.stringify(publicIndex)).not.toContain('providerUrl');
    expect(JSON.stringify(publicIndex)).not.toContain('rawState');
  });
});
