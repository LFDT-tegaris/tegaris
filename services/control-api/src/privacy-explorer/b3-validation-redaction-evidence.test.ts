import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import type { ExplorerProjectionResultV1 } from '../contracts/privacy-explorer-adapter.js';
import { bindLocalContext, type TerminalAuthorizationFacts } from './context.js';
import { createEvidenceLifecycleOwner } from './evidence.js';
import { isSafeProblem, type SafeProblem } from './problems.js';
import { narrowIntent, sha256CanonicalJson } from './narrowing.js';
import { preauthorize } from './preauthorization.js';
import {
  registerExplorerProfile,
  type ExplorerProfileRegistrationFacts,
} from './profile-registration.js';
import { redactProjection } from './redaction.js';
import {
  buildProjectionCandidate,
  buildSafeProblemCandidate,
  buildSuppressedCandidate,
  requirePublicResponseCandidate,
} from './result-candidate.js';
import { createProjectionRequest } from './request.js';
import { requireValidatedProjection, validateProjection } from './validation.js';
import {
  privacyExplorerNarrowing,
  privacyExplorerProfileFacts,
  privacyExplorerScope,
} from '../../../../tests/privacy/i07-gate2-contract-fixture.js';

type ParityFixture = Readonly<{
  context: Readonly<{
    profileDigest: string;
    requestId: string;
    correlationId: string;
  }>;
  completeRaw: ExplorerProjectionResultV1;
  expected: Readonly<{
    queryDigest: string;
    requestDigest: string;
    resultDigest: string;
    resultPreimageCanonical: string;
  }>;
}>;

const fixture = JSON.parse(
  await readFile(
    new URL(
      '../../../../tests/fixtures/privacy-explorer/i07-gate2-b3-parity-vectors.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as ParityFixture;
type MutableRaw = ExplorerProjectionResultV1 & Record<string, unknown>;
const digest = (character: string) => `sha256:${character.repeat(64)}`;

const buildBoundary = (suffix = '012') => {
  const occurrenceId = `123e4567-e89b-42d3-a456-426614174${suffix}`;
  const correlationId = `123e4567-e89b-42d3-a456-426614174${suffix === '012' ? '011' : '019'}`;
  const facts: TerminalAuthorizationFacts = {
    authorizationDigest: digest('b'),
    authorizationContextId: '123e4567-e89b-42d3-a456-426614174010',
    authorizationContextEpoch: 4,
    subject: 'subject-a',
    resource: 'resource-a',
    ...privacyExplorerScope,
    accessClassIds: ['ACCESS-PRIVATE'],
    allowedPurposeActions: [{ purpose: 'audit', action: 'read' }],
    allowedFieldIds: ['PEF-A', 'PEF-B'],
    auditCorrelationId: correlationId,
    occurrenceId,
    deadlineAt: '2028-01-01T00:00:00.000Z',
  };
  const profileFacts: ExplorerProfileRegistrationFacts = privacyExplorerProfileFacts(
    suffix === '012'
      ? '123e4567-e89b-42d3-a456-426614174013'
      : '123e4567-e89b-42d3-a456-426614174018',
    ['PEFILTER-A', 'PEFILTER-B'],
    '2028-01-01T00:00:00.000Z',
  );
  const context = bindLocalContext('terminal', {
    verify: (candidate) => (candidate === 'terminal' ? facts : undefined),
  });
  const profile = registerExplorerProfile('profile', {
    verify: (candidate) => (candidate === 'profile' ? profileFacts : undefined),
  });
  const intent = preauthorize(context, {
    purpose: 'audit',
    action: 'read',
    resource: 'resource-a',
  });
  const narrowed = narrowIntent(intent, profile, {
    ...privacyExplorerNarrowing,
    filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 7 }],
    projectionFields: ['PEF-A', 'PEF-B'],
    page: { limit: 2, cursor: null },
  });
  return createProjectionRequest(narrowed, {
    now: '2027-01-01T00:00:00.000Z',
    deadlineAt: '2027-01-01T00:01:00.000Z',
    occurrenceId,
    auditCorrelationId: correlationId,
    cancellationOccurrenceId: occurrenceId,
    reconciliationOccurrenceId: occurrenceId,
  });
};

const mutableRaw = () => structuredClone(fixture.completeRaw);
const refreshResponseDigest = (raw: ExplorerProjectionResultV1) => {
  const preimage = Object.fromEntries(
    Object.entries(raw).filter(([key]) => key !== 'responseDigest'),
  );
  raw.responseDigest = sha256CanonicalJson(preimage);
  return raw;
};
const conditionCode = (value: unknown) => {
  expect(isSafeProblem(value)).toBe(true);
  return (value as SafeProblem).code;
};
const validatedComplete = () => {
  const value = validateProjection(buildBoundary(), mutableRaw());
  expect(isSafeProblem(value)).toBe(false);
  return requireValidatedProjection(value);
};

describe('I07 Gate 2 B3 validation, redaction, candidate, and evidence boundary', () => {
  it('matches the shared TypeScript/Rust canonical digests and constructs only a private candidate', () => {
    const boundary = buildBoundary();
    expect(boundary.request.queryDigest).toBe(fixture.expected.queryDigest);
    expect(boundary.requestDigest).toBe(fixture.expected.requestDigest);
    const candidate = buildProjectionCandidate(
      redactProjection(requireValidatedProjection(validateProjection(boundary, mutableRaw()))),
    );
    const admitted = requirePublicResponseCandidate(candidate);
    expect(admitted.resultDigest).toBe(fixture.expected.resultDigest);
    expect(admitted.response).toMatchObject({
      outcome: 'COMPLETE',
      truthState: 'TRUE',
      resultDigest: fixture.expected.resultDigest,
    });
    expect(admitted.response).toHaveProperty('requestDigest', boundary.requestDigest);
    expect(admitted.response).not.toHaveProperty('freshness');
    expect(admitted.response).not.toHaveProperty('conflict');
    expect(() => requirePublicResponseCandidate({ ...candidate })).toThrow(
      'invalid public response candidate',
    );
  });

  it.each([
    [
      'schema version',
      (raw: Record<string, unknown>) => (raw.schemaVersion = '2.0'),
      'PC-RUNTIME-3009',
    ],
    [
      'request digest',
      (raw: Record<string, unknown>) => (raw.requestDigest = digest('d')),
      'PC-RUNTIME-3009',
    ],
    [
      'profile digest',
      (raw: Record<string, unknown>) => (raw.profileDigest = digest('d')),
      'PC-RUNTIME-3009',
    ],
    ['record order', (raw: MutableRaw) => raw.records.reverse(), 'PC-OPS-9004'],
    [
      'record duplicate',
      (raw: MutableRaw) => (raw.records[1]!.id = raw.records[0]!.id),
      'PC-OPS-9004',
    ],
    ['field order', (raw: MutableRaw) => raw.records[0]!.fields.reverse(), 'PC-OPS-9004'],
    [
      'field duplicate',
      (raw: MutableRaw) => (raw.records[0]!.fields[1]!.fieldId = 'PEF-A'),
      'PC-OPS-9004',
    ],
    [
      'forbidden field',
      (raw: MutableRaw) => (raw.records[0]!.fields[1]!.fieldId = 'PEF-X'),
      'PC-INTEGRATION-5002',
    ],
    ['hidden total', (raw: Record<string, unknown>) => (raw.total = 2), 'PC-RUNTIME-3009'],
    [
      'provider endpoint',
      (raw: Record<string, unknown>) => (raw.providerUrl = 'https://invalid'),
      'PC-RUNTIME-3009',
    ],
    ['complete gap', (raw: MutableRaw) => (raw.page.gapFree = false), 'PC-OPS-9004'],
    ['complete cursor', (raw: MutableRaw) => (raw.page.cursor = 'next'), 'PC-OPS-9004'],
    [
      'unknown records',
      (raw: MutableRaw) => {
        raw.completeness = 'UNKNOWN';
        raw.freshness = 'UNKNOWN';
        raw.page.gapFree = false;
      },
      'PC-FACT-4001',
    ],
    [
      'unavailable records',
      (raw: MutableRaw) => {
        raw.completeness = 'UNAVAILABLE';
        raw.freshness = 'UNKNOWN';
        raw.page.gapFree = false;
      },
      'PC-INTEGRATION-5001',
    ],
    ['stale', (raw: MutableRaw) => (raw.freshness = 'STALE'), 'PC-FACT-4002'],
    [
      'future observation',
      (raw: MutableRaw) => (raw.observedAt = '2027-01-01T00:00:01.000Z'),
      'PC-FACT-4002',
    ],
    ['reorg', (raw: MutableRaw) => (raw.conflict = 'REORG'), 'PC-FACT-4003'],
    ['conflict', (raw: MutableRaw) => (raw.conflict = 'CONFLICT'), 'PC-RUNTIME-3011'],
  ] as const)('rejects the isolated %s relation at its intended branch', (_name, mutate, code) => {
    const raw = mutableRaw() as MutableRaw;
    mutate(raw);
    refreshResponseDigest(raw);
    expect(conditionCode(validateProjection(buildBoundary(), raw))).toBe(code);
  });

  it('keeps PARTIAL, UNKNOWN, and UNAVAILABLE distinct and record-safe', () => {
    for (const outcome of ['PARTIAL', 'UNKNOWN', 'UNAVAILABLE'] as const) {
      const raw = mutableRaw();
      raw.completeness = outcome;
      raw.page = { cursor: outcome === 'PARTIAL' ? 'next' : null, gapFree: false };
      if (outcome !== 'PARTIAL') {
        raw.records = [];
        raw.freshness = 'UNKNOWN';
      }
      refreshResponseDigest(raw);
      const candidate = buildProjectionCandidate(
        redactProjection(requireValidatedProjection(validateProjection(buildBoundary(), raw))),
      );
      const response = requirePublicResponseCandidate(candidate).response;
      expect(response).toMatchObject({ outcome });
      if (outcome !== 'PARTIAL') expect(response).toMatchObject({ records: [] });
    }
  });

  it('rejects accessor-bearing raw objects before schema traversal', () => {
    const raw = mutableRaw() as unknown as Record<string, unknown>;
    Object.defineProperty(raw, 'records', {
      enumerable: true,
      get: () => fixture.completeRaw.records,
    });
    expect(conditionCode(validateProjection(buildBoundary(), raw))).toBe('PC-RUNTIME-3009');
  });

  it('seals one matching digest-only evidence record after ordered disposal and rejects replay', () => {
    const candidate = buildProjectionCandidate(redactProjection(validatedComplete()));
    const owner = createEvidenceLifecycleOwner();
    const input = {
      adapter: [owner.adapterContribution(candidate, 7)],
      completion: [owner.completionContribution(candidate, 8)],
      rawState: [owner.rawStateWitness(candidate, 'DISPOSED', 9)],
    };
    const evidence = owner.assemble(input);
    expect(evidence).toMatchObject({
      occurrenceId: fixture.context.requestId,
      correlationId: fixture.context.correlationId,
      profileDigest: fixture.context.profileDigest,
      queryDigest: fixture.expected.queryDigest,
      requestDigest: fixture.expected.requestDigest,
      outcome: 'COMPLETE',
      resultDigest: fixture.expected.resultDigest,
      rawState: 'DISPOSED',
    });
    for (const field of [
      'authorizationDigest',
      'contextDigest',
      'scopeDigest',
      'responseDigest',
      'validationDigest',
      'redactionDigest',
    ] as const)
      expect(evidence).toHaveProperty(field, expect.stringMatching(/^sha256:[0-9a-f]{64}$/));
    expect(evidence).not.toHaveProperty('records');
    expect(conditionCode(owner.assemble(input))).toBe('PC-RUNTIME-3007');
  });

  it('rejects missing, duplicate, mismatched, cross-occurrence, forged, and LIVE evidence', () => {
    const candidate = buildProjectionCandidate(redactProjection(validatedComplete()));
    const otherBoundary = buildBoundary('017');
    const otherRaw = mutableRaw();
    otherRaw.requestDigest = otherBoundary.requestDigest;
    otherRaw.provenanceDigest = sha256CanonicalJson({
      profileDigest: otherBoundary.request.exportProfile.digest,
      requestDigest: otherBoundary.requestDigest,
      provenanceProfileDigest: otherBoundary.request.exportProfile.provenanceProfileDigest,
    });
    refreshResponseDigest(otherRaw);
    const other = buildProjectionCandidate(
      redactProjection(requireValidatedProjection(validateProjection(otherBoundary, otherRaw))),
    );
    const owner = createEvidenceLifecycleOwner();
    const adapter = owner.adapterContribution(candidate, 1);
    const completion = owner.completionContribution(candidate, 2);
    const rawState = owner.rawStateWitness(candidate, 'DISPOSED', 3);
    const failed = [
      { adapter: [], completion: [completion], rawState: [rawState] },
      {
        adapter: [adapter],
        completion: [owner.completionContribution(other, 2)],
        rawState: [rawState],
      },
      {
        adapter: [adapter],
        completion: [completion],
        rawState: [owner.rawStateWitness(other, 'DISPOSED', 3)],
      },
      {
        adapter: [{ ...adapter }],
        completion: [completion],
        rawState: [rawState],
      },
    ];
    for (const input of failed)
      expect(conditionCode(owner.assemble(input as never))).toBe('PC-RUNTIME-3010');
    expect(
      conditionCode(
        owner.assemble({
          adapter: [adapter, adapter],
          completion: [completion],
          rawState: [rawState],
        }),
      ),
    ).toBe('PC-RUNTIME-3007');
    expect(() => owner.rawStateWitness(candidate, 'LIVE' as never, 3)).toThrow(
      'unproven raw state',
    );
  });

  it('uses a distinct minimal digest for suppressed cancellation and creates no response', () => {
    const boundary = buildBoundary();
    const candidate = requirePublicResponseCandidate(
      buildSuppressedCandidate(boundary, 'CANCELLED_AFTER_DISPATCH_NO_RAW'),
    );
    expect(candidate.delivery).toBe('SUPPRESSED');
    expect(candidate).not.toHaveProperty('response');
    expect(candidate.resultDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(candidate.resultDigest).not.toBe(fixture.expected.resultDigest);
  });

  it.each([
    ['EXP-COND-003', 'PARTIAL'],
    ['EXP-COND-004', 'UNAVAILABLE'],
    ['EXP-ABSENCE', 'UNKNOWN'],
    ['EXP-COND-002', 'FAILED'],
  ] as const)('preserves the generated %s safe-problem outcome as %s', (condition, outcome) => {
    const boundary = buildBoundary();
    const problem = validateProjection(boundary, { malformed: condition });
    const exact = condition === 'EXP-COND-002' ? problem : undefined;
    const candidate = buildSafeProblemCandidate(
      boundary,
      exact && isSafeProblem(exact) ? exact : (awaitCondition(condition) as SafeProblem),
    );
    expect(requirePublicResponseCandidate(candidate).outcome).toBe(outcome);
  });

  it('keeps validation, redaction, candidates, and evidence off the public service export', async () => {
    const publicIndex = await readFile(new URL('./index.ts', import.meta.url), 'utf8');
    for (const forbidden of [
      'validateProjection',
      'redactProjection',
      'PublicResponseCandidate',
      'createEvidenceLifecycleOwner',
      'ExplorerProjectionResultV1',
    ])
      expect(publicIndex).not.toContain(forbidden);
  });
});

const awaitCondition = (condition: string) => {
  const boundary = buildBoundary();
  switch (condition) {
    case 'EXP-COND-003': {
      const raw = mutableRaw();
      raw.page.gapFree = false;
      return validateProjection(boundary, refreshResponseDigest(raw));
    }
    case 'EXP-COND-004': {
      const raw = mutableRaw();
      raw.completeness = 'UNAVAILABLE';
      raw.freshness = 'UNKNOWN';
      raw.page.gapFree = false;
      return validateProjection(boundary, refreshResponseDigest(raw));
    }
    case 'EXP-ABSENCE': {
      const raw = mutableRaw();
      raw.completeness = 'UNKNOWN';
      raw.freshness = 'UNKNOWN';
      raw.page.gapFree = false;
      return validateProjection(boundary, refreshResponseDigest(raw));
    }
    default:
      return validateProjection(boundary, { malformed: true });
  }
};
