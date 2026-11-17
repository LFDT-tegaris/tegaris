import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
  executionRegistry,
  type AdapterCallContextV1,
  type ExplorerProjectionRequestV1,
} from '../contracts/privacy-explorer-adapter.js';
import { bindGovernedProjectionConsumer, readGovernedProjection } from './consumer-port.js';
import { bindLocalContext, type TerminalAuthorizationFacts } from './context.js';
import { narrowIntent, sha256CanonicalJson } from './narrowing.js';
import { classifyOutcome, rejectEmptySuccess } from './outcomes.js';
import { preauthorize } from './preauthorization.js';
import {
  registerExplorerProfile,
  type ExplorerProfileRegistrationFacts,
  type RegisteredExplorerProfile,
} from './profile-registration.js';
import { isSafeProblem, safeProblemForCondition } from './problems.js';
import { createProjectionRequest } from './request.js';
import { initialPrivacyExplorerState, reducePrivacyExplorerTransition } from './reducer.js';
import {
  privacyExplorerNarrowing,
  privacyExplorerScope,
} from '../../../../tests/privacy/i07-gate2-contract-fixture.js';

type B2Fixture = Readonly<{
  fixtureId: string;
  terminalAuthorizationCandidate: string;
  profileRegistrationCandidate: string;
  profileRegistration: ExplorerProfileRegistrationFacts;
}>;

const fixture = JSON.parse(
  await readFile(
    new URL(
      '../../../../tests/fixtures/privacy-explorer/i07-gate2-b2-registered-profile.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as B2Fixture;
const digest = (character: string) => `sha256:${character.repeat(64)}`;
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
  auditCorrelationId: '123e4567-e89b-42d3-a456-426614174011',
  occurrenceId: '123e4567-e89b-42d3-a456-426614174012',
  deadlineAt: '2028-01-01T00:00:00.000Z',
};
const terminalVerifier = {
  verify: (candidate: unknown) =>
    candidate === fixture.terminalAuthorizationCandidate ? facts : undefined,
};
const profileVerifier = {
  verify: (candidate: unknown) =>
    candidate === fixture.profileRegistrationCandidate ? fixture.profileRegistration : undefined,
};

const registeredProfile = () =>
  registerExplorerProfile(fixture.profileRegistrationCandidate, profileVerifier);
const buildBoundary = () => {
  const profile = registeredProfile();
  const context = bindLocalContext(fixture.terminalAuthorizationCandidate, terminalVerifier);
  const intent = preauthorize(context, {
    purpose: 'audit',
    action: 'read',
    resource: 'resource-a',
  });
  const narrowed = narrowIntent(intent, profile, {
    ...privacyExplorerNarrowing,
    filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 7 }],
    projectionFields: ['PEF-B', 'PEF-A'],
    page: { limit: 20, cursor: null },
  });
  return {
    profile,
    boundary: createProjectionRequest(narrowed, {
      now: '2027-01-01T00:00:00.000Z',
      deadlineAt: '2027-01-01T00:01:00.000Z',
      occurrenceId: facts.occurrenceId,
      auditCorrelationId: facts.auditCorrelationId,
      cancellationOccurrenceId: facts.occurrenceId,
      reconciliationOccurrenceId: facts.occurrenceId,
    }),
  };
};

describe('Privacy Explorer B2 construction boundary', () => {
  it('constructs one validated, canonical, immutable governed projection boundary', async () => {
    const { boundary, profile } = buildBoundary();
    const reordered = narrowIntent(
      preauthorize(bindLocalContext(fixture.terminalAuthorizationCandidate, terminalVerifier), {
        purpose: 'audit',
        action: 'read',
        resource: facts.resource,
      }),
      profile,
      {
        ...privacyExplorerNarrowing,
        filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 7 }],
        projectionFields: ['PEF-A', 'PEF-B'],
        page: { limit: 20, cursor: 'next-page' },
      },
    );
    expect(boundary.request.projectionFields).toEqual(['PEF-A', 'PEF-B']);
    expect(boundary.context.profileDigest).toBe(profile.digest);
    expect(boundary.context.occurrenceId).toBe(boundary.request.occurrence.requestId);
    expect(boundary.context.idempotencyDigest).toMatch(/^sha256:/);
    expect(boundary.requestDigest).toMatch(/^sha256:/);
    expect(reordered.queryDigest).toBe(boundary.request.queryDigest);
    expect(() => {
      (boundary.request.exportProfile as { id: string }).id = 'changed';
    }).toThrow();
    expect(() => {
      (boundary.context.cancellation as { occurrenceId: string }).occurrenceId = 'changed';
    }).toThrow();
    const port = bindGovernedProjectionConsumer(profile, {
      verifyEvidenceReference: async () => ({}),
      readGovernedProjection: async (
        request: ExplorerProjectionRequestV1,
        context: AdapterCallContextV1,
      ) => ({
        untrusted: true,
        requestId: request.occurrence.requestId,
        contextId: context.occurrenceId,
      }),
    } as never);
    await expect(readGovernedProjection(port, boundary)).resolves.toEqual({
      untrusted: true,
      requestId: facts.occurrenceId,
      contextId: facts.occurrenceId,
    });
  });

  it('requires a registered opaque profile and binds a consumer to its registration', async () => {
    const context = bindLocalContext(fixture.terminalAuthorizationCandidate, terminalVerifier);
    const intent = preauthorize(context, {
      purpose: 'audit',
      action: 'read',
      resource: facts.resource,
    });
    expect(() => registerExplorerProfile('forged-profile', profileVerifier)).toThrow(
      'unqualified Explorer profile',
    );
    expect(() =>
      narrowIntent(
        intent,
        {
          ...fixture.profileRegistration,
          qualified: true,
        } as unknown as RegisteredExplorerProfile,
        {
          ...privacyExplorerNarrowing,
          filters: [],
          projectionFields: ['PEF-A'],
          page: { limit: 1, cursor: null },
        },
      ),
    ).toThrow('unqualified Explorer profile');
    const { boundary } = buildBoundary();
    const otherProfile = registerExplorerProfile('other', {
      verify: (candidate) =>
        candidate === 'other'
          ? {
              ...fixture.profileRegistration,
              registrationId: '123e4567-e89b-42d3-a456-426614174014',
            }
          : undefined,
    });
    const mismatchedPort = bindGovernedProjectionConsumer(otherProfile, {
      verifyEvidenceReference: async () => ({}),
      readGovernedProjection: async () => ({ impossible: true }),
    } as never);
    await expect(readGovernedProjection(mismatchedPort, boundary)).rejects.toThrow(
      'projection consumer registration mismatch',
    );
  });

  it.each([
    [
      'missing operation',
      (profile: Record<string, unknown>) => (profile.operationVersions as unknown[]).splice(8, 1),
    ],
    [
      'duplicate semantic operation',
      (profile: Record<string, unknown>) => {
        const operations = profile.operationVersions as Array<Record<string, unknown>>;
        operations[1] = {
          ...operations[1]!,
          operationId: operations[0]!.operationId,
          version: '2',
        };
      },
    ],
    [
      'noncanonical field profile',
      (profile: Record<string, unknown>) => (profile.allowedFieldIds as unknown[]).reverse(),
    ],
    [
      'retry schedule mismatch',
      (profile: Record<string, unknown>) => (profile.retryBackoffMilliseconds = []),
    ],
    [
      'omitted provenance owner',
      (profile: Record<string, unknown>) => delete profile.provenanceProfileDigest,
    ],
  ] as const)('rejects a self-consistent but unqualified profile with %s', (_name, mutate) => {
    const candidate = structuredClone(fixture.profileRegistration) as unknown as Record<
      string,
      unknown
    >;
    delete candidate.registrationId;
    delete candidate.digest;
    mutate(candidate);
    const forged = {
      registrationId: fixture.profileRegistration.registrationId,
      ...candidate,
      digest: sha256CanonicalJson(candidate),
    };
    expect(() =>
      registerExplorerProfile('forged-profile', {
        verify: (value) => (value === 'forged-profile' ? (forged as never) : undefined),
      }),
    ).toThrow();
  });

  it('rejects each isolated scope-field mutation on an otherwise matching opaque boundary', async () => {
    const { boundary, profile } = buildBoundary();
    let calls = 0;
    const port = bindGovernedProjectionConsumer(profile, {
      readGovernedProjection: async () => {
        calls += 1;
        return undefined;
      },
      verifyEvidenceReference: async () => undefined,
    } as never);
    for (const field of [
      'participantId',
      'privacyDomainId',
      'platformId',
      'workloadId',
      'action',
    ] as const) {
      const forged = {
        ...boundary,
        request: {
          ...boundary.request,
          scope: { ...boundary.request.scope, [field]: `${boundary.request.scope[field]}-other` },
        },
      };
      await expect(readGovernedProjection(port, forged as never)).rejects.toThrow(
        'unvalidated projection boundary',
      );
    }
    expect(calls).toBe(0);
  });

  it('fails closed on forged authority, invalid scalar, field, filter, page, and seed joins', () => {
    expect(() => bindLocalContext('forged', terminalVerifier)).toThrow(
      'terminal authorization denied',
    );
    const context = bindLocalContext(fixture.terminalAuthorizationCandidate, terminalVerifier);
    expect(() =>
      preauthorize(context, { purpose: 'audit', action: 'write', resource: facts.resource }),
    ).toThrow('common terminal denial');
    const intent = preauthorize(context, {
      purpose: 'audit',
      action: 'read',
      resource: facts.resource,
    });
    const profile = registeredProfile();
    expect(() =>
      narrowIntent(intent, profile, {
        ...privacyExplorerNarrowing,
        filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: {} as never }],
        projectionFields: ['PEF-A'],
        page: { limit: 1, cursor: null },
      }),
    ).toThrow('forbidden filter');
    for (const value of [Number.MAX_SAFE_INTEGER + 1, 1.5, Number.POSITIVE_INFINITY])
      expect(() =>
        narrowIntent(intent, profile, {
          ...privacyExplorerNarrowing,
          filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value }],
          projectionFields: ['PEF-A'],
          page: { limit: 1, cursor: null },
        }),
      ).toThrow();
    expect(() =>
      narrowIntent(intent, profile, {
        ...privacyExplorerNarrowing,
        filters: [{ fieldId: 'PEF-X', filterId: 'PEFILTER-A', value: 1 }],
        projectionFields: ['PEF-X'],
        page: { limit: 0, cursor: null },
      }),
    ).toThrow('forbidden projection field');
    expect(() =>
      narrowIntent(intent, profile, {
        ...privacyExplorerNarrowing,
        filters: [
          { fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: '7' },
          { fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 7 },
        ],
        projectionFields: ['PEF-A'],
        page: { limit: 201, cursor: null },
      }),
    ).toThrow();
    const narrowed = narrowIntent(intent, profile, {
      ...privacyExplorerNarrowing,
      filters: [],
      projectionFields: ['PEF-A'],
      page: { limit: 1, cursor: null },
    });
    for (const seed of [
      { now: 'not-a-time', deadlineAt: '2027-01-01T00:01:00.000Z' },
      { now: '2027-01-01T00:00:00.000Z', deadlineAt: '2029-01-01T00:00:00.000Z' },
    ])
      expect(() =>
        createProjectionRequest(narrowed, {
          ...seed,
          occurrenceId: facts.occurrenceId,
          auditCorrelationId: facts.auditCorrelationId,
          cancellationOccurrenceId: facts.occurrenceId,
          reconciliationOccurrenceId: facts.occurrenceId,
        }),
      ).toThrow();
  });

  it('rejects spread and reflected clones at every admitted identity boundary before invocation', async () => {
    const context = bindLocalContext(fixture.terminalAuthorizationCandidate, terminalVerifier);
    const profile = registeredProfile();
    expect(() =>
      preauthorize({ ...context } as typeof context, {
        purpose: 'audit',
        action: 'read',
        resource: facts.resource,
      }),
    ).toThrow('unverified local context');
    const intent = preauthorize(context, {
      purpose: 'audit',
      action: 'read',
      resource: facts.resource,
    });
    expect(() =>
      narrowIntent(intent, { ...profile } as typeof profile, {
        ...privacyExplorerNarrowing,
        filters: [],
        projectionFields: ['PEF-A'],
        page: { limit: 1, cursor: null },
      }),
    ).toThrow('unqualified Explorer profile');
    expect(() =>
      narrowIntent({ ...intent } as typeof intent, profile, {
        ...privacyExplorerNarrowing,
        filters: [],
        projectionFields: ['PEF-A'],
        page: { limit: 1, cursor: null },
      }),
    ).toThrow('unpreauthorized intent');
    const narrowed = narrowIntent(intent, profile, {
      ...privacyExplorerNarrowing,
      filters: [],
      projectionFields: ['PEF-A'],
      page: { limit: 1, cursor: null },
    });
    expect(() =>
      createProjectionRequest({ ...narrowed } as typeof narrowed, {
        now: '2027-01-01T00:00:00.000Z',
        deadlineAt: '2027-01-01T00:01:00.000Z',
        occurrenceId: facts.occurrenceId,
        auditCorrelationId: facts.auditCorrelationId,
        cancellationOccurrenceId: facts.occurrenceId,
        reconciliationOccurrenceId: facts.occurrenceId,
      }),
    ).toThrow('unnarrowed intent');
    const { boundary } = buildBoundary();
    let calls = 0;
    const port = bindGovernedProjectionConsumer(profile, {
      verifyEvidenceReference: async () => ({}),
      readGovernedProjection: async () => {
        calls += 1;
        return {};
      },
    } as never);
    await expect(readGovernedProjection(port, { ...boundary } as typeof boundary)).rejects.toThrow(
      'unvalidated projection boundary',
    );
    await expect(readGovernedProjection({ ...port }, boundary)).rejects.toThrow(
      'projection consumer registration mismatch',
    );
    expect(calls).toBe(0);
  });

  it('derives every declared condition, transition, and non-authoritative outcome', () => {
    expect(() => {
      (executionRegistry.conditionDefinitions[0] as { code: string }).code = 'PC-FORGED-0000';
    }).toThrow();
    for (const condition of executionRegistry.conditionDefinitions)
      expect(safeProblemForCondition(condition.id)).toMatchObject({ code: condition.code });
    const transition = reducePrivacyExplorerTransition({
      state: initialPrivacyExplorerState,
      operationId: 'PXI-BIND-LOCAL-CONTEXT/v1',
      eventId: 'BIND_LOCAL_CONTEXT',
      guardId: 'EXACT_SOURCE_STATE',
    });
    expect(transition.state).toBe('CONTEXT_BOUND');
    expect(() =>
      reducePrivacyExplorerTransition({
        state: initialPrivacyExplorerState,
        operationId: 'PXI-BIND-LOCAL-CONTEXT/v1',
        eventId: 'BIND_LOCAL-CONTEXT',
        guardId: 'CALLER_SELECTED',
      }),
    ).toThrow('undeclared or ambiguous');
    for (const outcome of ['COMPLETE', 'PARTIAL', 'UNKNOWN', 'UNAVAILABLE'] as const)
      expect(classifyOutcome(outcome).outcome).toBe(outcome);
    expect(classifyOutcome('UNKNOWN')).toMatchObject({ recordsAllowed: false });
    expect(() => rejectEmptySuccess('COMPLETE', 0)).toThrow(
      'absence cannot be represented as COMPLETE',
    );
    expect(isSafeProblem({ ...safeProblemForCondition('EXP-COND-003'), rawDetail: 'leak' })).toBe(
      false,
    );
  });

  it.each([
    ['authorization digest', { authorizationDigest: 'sha256:bad' }],
    ['access identifier', { accessClassIds: ['ACCESS-lower'] }],
    ['field identifier', { allowedFieldIds: ['PEF-lower'] }],
    ['packed purpose action', { allowedPurposeActions: ['audit\u0000read'] }],
    [
      'duplicate purpose action',
      {
        allowedPurposeActions: [
          { purpose: 'audit', action: 'read' },
          { purpose: 'audit', action: 'read' },
        ],
      },
    ],
  ])('rejects isolated malformed terminal %s relations', (_name, replacement) => {
    expect(() =>
      bindLocalContext(fixture.terminalAuthorizationCandidate, {
        verify: () => ({ ...facts, ...replacement }) as TerminalAuthorizationFacts,
      }),
    ).toThrow();
  });

  it('keeps public exports and B2 composition code free of transport escape hatches', async () => {
    const sources = await Promise.all(
      [
        './index.ts',
        './context.ts',
        './preauthorization.ts',
        './profile-registration.ts',
        './narrowing.ts',
        './request.ts',
        './consumer-port.ts',
      ].map((path) => readFile(new URL(path, import.meta.url), 'utf8')),
    );
    expect(sources[0]).not.toContain('QualifiedExplorerProfile');
    for (const source of sources)
      for (const forbidden of ['endpoint', 'provider', 'fallback', 'browser'])
        expect(source.toLowerCase()).not.toContain(forbidden);
  });
});
