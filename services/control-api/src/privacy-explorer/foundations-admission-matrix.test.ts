import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { executionRegistry } from '../contracts/privacy-explorer-adapter.js';
import { bindGovernedProjectionConsumer, readGovernedProjection } from './consumer-port.js';
import { bindLocalContext, type TerminalAuthorizationFacts } from './context.js';
import { canonicalJson, narrowIntent, sha256CanonicalJson } from './narrowing.js';
import { classifyOutcome, rejectEmptySuccess } from './outcomes.js';
import { preauthorize } from './preauthorization.js';
import {
  registerExplorerProfile,
  type ExplorerProfileRegistrationFacts,
} from './profile-registration.js';
import { isSafeProblem, safeProblemForCondition } from './problems.js';
import { createProjectionRequest, type CallContextSeed } from './request.js';
import { initialPrivacyExplorerState, reducePrivacyExplorerTransition } from './reducer.js';
import {
  privacyExplorerNarrowing,
  privacyExplorerProfileFacts,
  privacyExplorerScope,
} from '../../../../tests/privacy/i07-gate2-contract-fixture.js';

const digest = (character: string) => `sha256:${character.repeat(64)}`;
const alternateOccurrence = '123e4567-e89b-42d3-a456-426614174099';
const facts: TerminalAuthorizationFacts = {
  authorizationDigest: digest('a'),
  authorizationContextId: '123e4567-e89b-42d3-a456-426614174010',
  authorizationContextEpoch: 1,
  subject: 'subject',
  resource: 'resource',
  ...privacyExplorerScope,
  accessClassIds: ['ACCESS-PRIVATE'],
  allowedPurposeActions: [{ purpose: 'audit', action: 'read' }],
  allowedFieldIds: ['PEF-A', 'PEF-B'],
  auditCorrelationId: '123e4567-e89b-42d3-a456-426614174011',
  occurrenceId: '123e4567-e89b-42d3-a456-426614174012',
  deadlineAt: '2028-01-01T00:00:00Z',
};
const profileFacts: ExplorerProfileRegistrationFacts = privacyExplorerProfileFacts(
  '123e4567-e89b-42d3-a456-426614174013',
);
const seed: CallContextSeed = {
  now: '2027-01-01T00:00:00Z',
  deadlineAt: '2027-01-01T00:01:00Z',
  occurrenceId: facts.occurrenceId,
  auditCorrelationId: facts.auditCorrelationId,
  cancellationOccurrenceId: facts.occurrenceId,
  reconciliationOccurrenceId: facts.occurrenceId,
};

const build = () => {
  const context = bindLocalContext('terminal', {
    verify: (candidate) => (candidate === 'terminal' ? facts : undefined),
  });
  const profile = registerExplorerProfile('profile', {
    verify: (candidate) => (candidate === 'profile' ? profileFacts : undefined),
  });
  const intent = preauthorize(context, { purpose: 'audit', action: 'read', resource: 'resource' });
  const narrowed = narrowIntent(intent, profile, {
    ...privacyExplorerNarrowing,
    filters: [],
    projectionFields: ['PEF-A'],
    page: { limit: 1, cursor: null },
  });
  const boundary = createProjectionRequest(narrowed, seed);
  return { context, profile, intent, narrowed, boundary };
};

const reflectedClone = <T extends object>(value: T): T =>
  Object.defineProperties({}, Object.getOwnPropertyDescriptors(value)) as T;

type AdmissionRow = Readonly<{
  relationId: string;
  authoritySource: string;
  authorityOwner: string;
  admittedEntryPoint: string;
  validator: string;
  consumer: string;
  retainedFact: string;
  positiveProof: string;
  falseButConsistentCounterexample: string;
  mutatedRelation: string;
  expectedRejectingBranch: string;
  noEffectResult: string;
  run: () => number | Promise<number>;
}>;

type RowDefaults = Pick<
  AdmissionRow,
  | 'authoritySource'
  | 'authorityOwner'
  | 'admittedEntryPoint'
  | 'validator'
  | 'consumer'
  | 'retainedFact'
  | 'positiveProof'
  | 'expectedRejectingBranch'
  | 'noEffectResult'
>;

const row = (
  defaults: RowDefaults,
  relationId: string,
  mutatedRelation: string,
  falseButConsistentCounterexample: string,
  run: AdmissionRow['run'],
): AdmissionRow => ({
  ...defaults,
  relationId,
  mutatedRelation,
  falseButConsistentCounterexample,
  run,
});

const assertInventory = (rows: readonly AdmissionRow[]) => {
  expect(new Set(rows.map((entry) => entry.relationId)).size).toBe(rows.length);
  for (const entry of rows)
    for (const value of [
      entry.authoritySource,
      entry.authorityOwner,
      entry.admittedEntryPoint,
      entry.validator,
      entry.consumer,
      entry.retainedFact,
      entry.positiveProof,
      entry.falseButConsistentCounterexample,
      entry.mutatedRelation,
      entry.expectedRejectingBranch,
      entry.noEffectResult,
    ])
      expect(value).not.toBe('');
};

const terminalDefaults: RowDefaults = {
  authoritySource: 'B2 packet 5.4 + AF-22 sections 1 and 4',
  authorityOwner: 'terminal authorization verifier and bindLocalContext',
  admittedEntryPoint: 'bindLocalContext(candidate, verifier)',
  validator: 'terminal verifier plus local context field validation',
  consumer: 'preauthorize',
  retainedFact: 'opaque immutable PrivacyExplorerLocalContext identity',
  positiveProof: 'valid verifier-issued terminal facts bind one local context',
  expectedRejectingBranch: 'terminal authorization denied or authorization context invalid',
  noEffectResult: 'zero Explorer consumer calls and zero authority widening',
};

const terminalMutations: readonly (readonly [string, Readonly<Record<string, unknown>>])[] = [
  ['TERM-DIGEST', { authorizationDigest: 'sha256:bad' }],
  ['TERM-CONTEXT-UUID', { authorizationContextId: 'bad' }],
  ['TERM-EPOCH-NEGATIVE', { authorizationContextEpoch: -1 }],
  ['TERM-EPOCH-NONINTEGER', { authorizationContextEpoch: 1.5 }],
  ['TERM-EPOCH-UNSAFE', { authorizationContextEpoch: Number.MAX_SAFE_INTEGER + 1 }],
  ['TERM-SUBJECT-NONSTRING', { subject: 1 }],
  ['TERM-SUBJECT-EMPTY', { subject: '' }],
  ['TERM-SUBJECT-NUL', { subject: 'a\u0000b' }],
  ['TERM-SUBJECT-LONG', { subject: 'a'.repeat(257) }],
  ['TERM-RESOURCE-NONSTRING', { resource: 1 }],
  ['TERM-RESOURCE-EMPTY', { resource: '' }],
  ['TERM-RESOURCE-NUL', { resource: 'a\u0000b' }],
  ['TERM-RESOURCE-LONG', { resource: 'a'.repeat(257) }],
  ['TERM-ACCESS-NONARRAY', { accessClassIds: 'ACCESS-PRIVATE' }],
  ['TERM-ACCESS-EMPTY', { accessClassIds: [] }],
  ['TERM-ACCESS-33', { accessClassIds: Array.from({ length: 33 }, (_, i) => `ACCESS-${i}`) }],
  ['TERM-ACCESS-DUPLICATE', { accessClassIds: ['ACCESS-A', 'ACCESS-A'] }],
  ['TERM-ACCESS-PATTERN', { accessClassIds: ['access-a'] }],
  ['TERM-PURPOSE-NONARRAY', { allowedPurposeActions: 'audit' }],
  ['TERM-PURPOSE-EMPTY', { allowedPurposeActions: [] }],
  [
    'TERM-PURPOSE-33',
    {
      allowedPurposeActions: Array.from({ length: 33 }, (_, i) => ({
        purpose: `purpose-${i}`,
        action: 'read',
      })),
    },
  ],
  ['TERM-PURPOSE-SHAPE', { allowedPurposeActions: [{ purpose: 'audit' }] }],
  [
    'TERM-PURPOSE-EXTRA',
    { allowedPurposeActions: [{ purpose: 'audit', action: 'read', extra: true }] },
  ],
  [
    'TERM-PURPOSE-DUPLICATE',
    {
      allowedPurposeActions: [
        { purpose: 'audit', action: 'read' },
        { purpose: 'audit', action: 'read' },
      ],
    },
  ],
  ['TERM-PURPOSE-NONSTRING', { allowedPurposeActions: [{ purpose: 1, action: 'read' }] }],
  ['TERM-PURPOSE-NUL', { allowedPurposeActions: [{ purpose: 'a\u0000b', action: 'read' }] }],
  ['TERM-ACTION-LONG', { allowedPurposeActions: [{ purpose: 'audit', action: 'a'.repeat(257) }] }],
  ['TERM-FIELDS-NONARRAY', { allowedFieldIds: 'PEF-A' }],
  ['TERM-FIELDS-EMPTY', { allowedFieldIds: [] }],
  ['TERM-FIELDS-65', { allowedFieldIds: Array.from({ length: 65 }, (_, i) => `PEF-${i}`) }],
  ['TERM-FIELDS-DUPLICATE', { allowedFieldIds: ['PEF-A', 'PEF-A'] }],
  ['TERM-FIELDS-PATTERN', { allowedFieldIds: ['pef-a'] }],
  ['TERM-CORRELATION-UUID', { auditCorrelationId: 'bad' }],
  ['TERM-OCCURRENCE-UUID', { occurrenceId: 'bad' }],
  ['TERM-DEADLINE-SYNTAX', { deadlineAt: 'not-a-date' }],
  ['TERM-DEADLINE-CALENDAR', { deadlineAt: '2028-02-30T00:00:00Z' }],
];

const terminalRows = terminalMutations.map(([relationId, mutation]) =>
  row(
    terminalDefaults,
    relationId,
    relationId,
    'verifier returns a structurally plausible terminal record with exactly one isolated invalid field',
    () => {
      expect(() =>
        bindLocalContext('terminal', {
          verify: () => ({ ...facts, ...mutation }) as TerminalAuthorizationFacts,
        }),
      ).toThrow();
      return 0;
    },
  ),
);
terminalRows.unshift(
  row(
    terminalDefaults,
    'TERM-FORGED-CANDIDATE',
    'terminal witness identity',
    'caller supplies an otherwise well-shaped but verifier-unrecognized witness',
    () => {
      expect(() => bindLocalContext('forged', { verify: () => undefined })).toThrow(
        'terminal authorization denied',
      );
      return 0;
    },
  ),
);

const identityDefaults: RowDefaults = {
  authoritySource: 'B2 packet 5.4-5.8 and ledger records 243-245',
  authorityOwner: 'module-private WeakSet or WeakMap construction provenance',
  admittedEntryPoint: 'next owner in the B2 construction chain',
  validator: 'exact object-identity admission',
  consumer: 'next owner or governed projection consumer',
  retainedFact: 'private provenance identity only',
  positiveProof: 'the original opaque value reaches exactly its named next owner',
  expectedRejectingBranch:
    'unverified, unregistered, unpreauthorized, unnarrowed, or unvalidated identity',
  noEffectResult: 'zero adapter calls from every cloned identity',
};

const identityRows = (
  [
    ['CONTEXT', 'context', 'unverified local context'],
    ['PROFILE', 'profile', 'unqualified Explorer profile'],
    ['INTENT', 'intent', 'unpreauthorized intent'],
    ['NARROWED', 'narrowed', 'unnarrowed intent'],
    ['BOUNDARY', 'boundary', 'unvalidated projection boundary'],
    ['PORT', 'port', 'projection consumer registration mismatch'],
  ] as const
).flatMap(([relationPrefix, valueName, message]) =>
  (['SPREAD', 'REFLECT'] as const).map((cloneKind) =>
    row(
      identityDefaults,
      `${relationPrefix}-${cloneKind}-CLONE`,
      `${valueName} construction provenance`,
      `a field-identical ${cloneKind.toLowerCase()} clone is substituted for the original opaque ${valueName}`,
      async () => {
        const { context, profile, intent, narrowed, boundary } = build();
        let adapterCalls = 0;
        const port = bindGovernedProjectionConsumer(profile, {
          verifyEvidenceReference: async () => ({}),
          readGovernedProjection: async () => {
            adapterCalls += 1;
            return {};
          },
        } as never);
        const clone = <T extends object>(value: T) =>
          cloneKind === 'SPREAD' ? ({ ...value } as T) : reflectedClone(value);
        if (valueName === 'context')
          expect(() =>
            preauthorize(clone(context), {
              purpose: 'audit',
              action: 'read',
              resource: 'resource',
            }),
          ).toThrow(message);
        if (valueName === 'profile')
          expect(() =>
            narrowIntent(intent, clone(profile), {
              ...privacyExplorerNarrowing,
              filters: [],
              projectionFields: ['PEF-A'],
              page: { limit: 1, cursor: null },
            }),
          ).toThrow(message);
        if (valueName === 'intent')
          expect(() =>
            narrowIntent(clone(intent), profile, {
              ...privacyExplorerNarrowing,
              filters: [],
              projectionFields: ['PEF-A'],
              page: { limit: 1, cursor: null },
            }),
          ).toThrow(message);
        if (valueName === 'narrowed')
          expect(() => createProjectionRequest(clone(narrowed), seed)).toThrow(message);
        if (valueName === 'boundary')
          await expect(readGovernedProjection(port, clone(boundary))).rejects.toThrow(message);
        if (valueName === 'port')
          await expect(readGovernedProjection(clone(port), boundary)).rejects.toThrow(message);
        return adapterCalls;
      },
    ),
  ),
);

const preauthorizationDefaults: RowDefaults = {
  authoritySource: 'B2 packet 5.5 + AF-22 sections 1 and 4',
  authorityOwner: 'preauthorize',
  admittedEntryPoint: 'preauthorize(opaqueContext, registeredPurposeAction)',
  validator: 'bounded structured purpose/action/resource plus exact terminal allowlist',
  consumer: 'narrowIntent',
  retainedFact: 'opaque preauthorized intent with exact context identity',
  positiveProof: 'registered audit/read/resource tuple is admitted',
  expectedRejectingBranch: 'common terminal denial or bounded string rejection',
  noEffectResult: 'zero Explorer consumer calls and no widened local authority',
};
const preauthorizationMutations: readonly (readonly [string, Readonly<Record<string, unknown>>])[] =
  [
    ['PRE-EXTRA-FIELD', { provider: 'forbidden' }],
    ['PRE-PURPOSE-WRONG', { purpose: 'write' }],
    ['PRE-PURPOSE-NONSTRING', { purpose: 1 }],
    ['PRE-PURPOSE-EMPTY', { purpose: '' }],
    ['PRE-PURPOSE-NUL', { purpose: 'a\u0000b' }],
    ['PRE-PURPOSE-LONG', { purpose: 'a'.repeat(257) }],
    ['PRE-ACTION-WRONG', { action: 'write' }],
    ['PRE-ACTION-NONSTRING', { action: 1 }],
    ['PRE-ACTION-EMPTY', { action: '' }],
    ['PRE-ACTION-NUL', { action: 'a\u0000b' }],
    ['PRE-ACTION-LONG', { action: 'a'.repeat(257) }],
    ['PRE-RESOURCE-MISMATCH', { resource: 'other' }],
    ['PRE-RESOURCE-NONSTRING', { resource: 1 }],
    ['PRE-RESOURCE-EMPTY', { resource: '' }],
    ['PRE-RESOURCE-NUL', { resource: 'a\u0000b' }],
    ['PRE-RESOURCE-LONG', { resource: 'a'.repeat(257) }],
  ];
const preauthorizationRows = preauthorizationMutations.map(([relationId, mutation]) =>
  row(
    preauthorizationDefaults,
    relationId,
    relationId,
    'the request remains well-shaped while one purpose/action/resource relation is changed',
    () => {
      const { context } = build();
      expect(() =>
        preauthorize(context, {
          purpose: 'audit',
          action: 'read',
          resource: 'resource',
          ...mutation,
        } as never),
      ).toThrow();
      return 0;
    },
  ),
);
preauthorizationRows.push(
  row(
    preauthorizationDefaults,
    'PRE-ACCESSOR-FIELD',
    'plain immutable data-property admission',
    'a registered-looking purpose is supplied through an accessor with executable behavior',
    () => {
      const { context } = build();
      const input = { purpose: 'audit', action: 'read', resource: 'resource' };
      Object.defineProperty(input, 'purpose', { get: () => 'audit', enumerable: true });
      expect(() => preauthorize(context, input)).toThrow('non-JSON object property');
      return 0;
    },
  ),
);

const profileDefaults: RowDefaults = {
  authoritySource: 'B2 packet 5.7 + AF-22 sections 1, 2, and 5',
  authorityOwner: 'registerExplorerProfile',
  admittedEntryPoint: 'registerExplorerProfile(candidate, qualificationVerifier)',
  validator: 'verifier identity plus exact profile identity/allowlist/deadline validation',
  consumer: 'narrowIntent and bindGovernedProjectionConsumer',
  retainedFact: 'opaque registered profile plus private registration identity',
  positiveProof: 'one deterministic non-production verifier-issued profile is admitted',
  expectedRejectingBranch: 'unqualified Explorer profile or exact field validator',
  noEffectResult: 'zero Explorer calls and no implicit active/default profile',
};
const profileMutations: readonly (readonly [string, unknown, Readonly<Record<string, unknown>>])[] =
  [
    ['PROF-DENIED', 'bad', {}],
    ['PROF-REGISTRATION-UUID', 'profile', { registrationId: 'bad' }],
    ['PROF-ID-NONSTRING', 'profile', { id: 1 }],
    ['PROF-ID-EMPTY', 'profile', { id: '' }],
    ['PROF-ID-NUL', 'profile', { id: 'a\u0000b' }],
    ['PROF-ID-LONG', 'profile', { id: 'a'.repeat(257) }],
    ['PROF-VERSION-NONSTRING', 'profile', { version: 1 }],
    ['PROF-VERSION-EMPTY', 'profile', { version: '' }],
    ['PROF-VERSION-NUL', 'profile', { version: 'a\u0000b' }],
    ['PROF-VERSION-LONG', 'profile', { version: 'a'.repeat(257) }],
    ['PROF-DIGEST', 'profile', { digest: 'bad' }],
    ['PROF-FIELDS-NONARRAY', 'profile', { allowedFieldIds: 'PEF-A' }],
    ['PROF-FIELDS-EMPTY', 'profile', { allowedFieldIds: [] }],
    [
      'PROF-FIELDS-65',
      'profile',
      { allowedFieldIds: Array.from({ length: 65 }, (_, i) => `PEF-${i}`) },
    ],
    ['PROF-FIELDS-DUPLICATE', 'profile', { allowedFieldIds: ['PEF-A', 'PEF-A'] }],
    ['PROF-FIELDS-PATTERN', 'profile', { allowedFieldIds: ['pef-a'] }],
    ['PROF-FILTERS-NONARRAY', 'profile', { allowedFilterIds: 'PEFILTER-A' }],
    ['PROF-FILTERS-EMPTY', 'profile', { allowedFilterIds: [] }],
    [
      'PROF-FILTERS-33',
      'profile',
      { allowedFilterIds: Array.from({ length: 33 }, (_, i) => `PEFILTER-${i}`) },
    ],
    ['PROF-FILTERS-DUPLICATE', 'profile', { allowedFilterIds: ['PEFILTER-A', 'PEFILTER-A'] }],
    ['PROF-FILTERS-PATTERN', 'profile', { allowedFilterIds: ['pefilter-a'] }],
    ['PROF-DEADLINE-SYNTAX', 'profile', { maximumDeadlineAt: 'not-a-date' }],
    ['PROF-DEADLINE-CALENDAR', 'profile', { maximumDeadlineAt: '2028-02-30T00:00:00Z' }],
  ];
const profileRows = profileMutations.map(([relationId, candidate, mutation]) =>
  row(
    profileDefaults,
    relationId,
    relationId,
    'the qualification verifier returns a plausible profile with one isolated invalid relation',
    () => {
      expect(() =>
        registerExplorerProfile(candidate, {
          verify: (value) =>
            value === 'profile'
              ? ({ ...profileFacts, ...mutation } as ExplorerProfileRegistrationFacts)
              : undefined,
        }),
      ).toThrow();
      return 0;
    },
  ),
);

const narrowingDefaults: RowDefaults = {
  authoritySource: 'B2 packet 5.6 + AF-22 sections 3 and 4',
  authorityOwner: 'narrowIntent',
  admittedEntryPoint: 'narrowIntent(opaqueIntent, registeredProfile, input)',
  validator:
    'field/filter/page shape, bounds, allowlist intersection, uniqueness, and canonical order',
  consumer: 'createProjectionRequest',
  retainedFact: 'opaque narrowed intent and canonical query digest',
  positiveProof: 'allowed filters/fields/page are canonicalized and admitted',
  expectedRejectingBranch: 'narrowing validation before request construction',
  noEffectResult: 'zero adapter calls and no provider coordinate or widened field retained',
};
const filter = { fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 1 } as const;
const narrowingMutations: readonly (readonly [string, Readonly<Record<string, unknown>>])[] = [
  ['NARROW-TOPLEVEL-EXTRA', { provider: 'forbidden' }],
  ['NARROW-PROJECTION-NONARRAY', { projectionFields: 'PEF-A' }],
  ['NARROW-PROJECTION-UNKNOWN', { projectionFields: ['PEF-X'] }],
  ['NARROW-PROJECTION-FORBIDDEN', { projectionFields: ['PEF-C'] }],
  ['NARROW-PROJECTION-PATTERN', { projectionFields: ['pef-a'] }],
  ['NARROW-PROJECTION-EMPTY', { projectionFields: [] }],
  ['NARROW-PROJECTION-DUPLICATE', { projectionFields: ['PEF-A', 'PEF-A'] }],
  ['NARROW-PROJECTION-65', { projectionFields: Array.from({ length: 65 }, (_, i) => `PEF-${i}`) }],
  ['NARROW-FILTER-NONARRAY', { filters: 'filter' }],
  ['NARROW-FILTER-NULL', { filters: [null] }],
  ['NARROW-FILTER-SHAPE', { filters: [{ ...filter, extra: true }] }],
  ['NARROW-FILTER-FIELD-PATTERN', { filters: [{ ...filter, fieldId: 'pef-a' }] }],
  ['NARROW-FILTER-FIELD-NOT-PROJECTED', { filters: [{ ...filter, fieldId: 'PEF-B' }] }],
  ['NARROW-FILTER-ID-PATTERN', { filters: [{ ...filter, filterId: 'pefilter-a' }] }],
  ['NARROW-FILTER-FORBIDDEN', { filters: [{ ...filter, filterId: 'PEFILTER-X' }] }],
  [
    'NARROW-FILTER-33',
    {
      filters: Array.from({ length: 33 }, (_, i) => ({
        fieldId: 'PEF-A',
        filterId: 'PEFILTER-A',
        value: i,
      })),
    },
  ],
  ['NARROW-FILTER-DUPLICATE', { filters: [filter, { ...filter }] }],
  ['NARROW-FILTER-OBJECT', { filters: [{ ...filter, value: {} }] }],
  ['NARROW-FILTER-ARRAY', { filters: [{ ...filter, value: [] }] }],
  ['NARROW-FILTER-NAN', { filters: [{ ...filter, value: Number.NaN }] }],
  ['NARROW-FILTER-INFINITY', { filters: [{ ...filter, value: Number.POSITIVE_INFINITY }] }],
  ['NARROW-FILTER-STRING-257', { filters: [{ ...filter, value: 'a'.repeat(257) }] }],
  ['NARROW-PAGE-NULL', { page: null }],
  ['NARROW-PAGE-EXTRA', { page: { limit: 1, cursor: null, provider: 'forbidden' } }],
  ['NARROW-PAGE-0', { page: { limit: 0, cursor: null } }],
  ['NARROW-PAGE-201', { page: { limit: 201, cursor: null } }],
  ['NARROW-PAGE-NONINTEGER', { page: { limit: 1.5, cursor: null } }],
  ['NARROW-CURSOR-EMPTY', { page: { limit: 1, cursor: '' } }],
  ['NARROW-CURSOR-LONG', { page: { limit: 1, cursor: 'a'.repeat(1025) } }],
  ['NARROW-CURSOR-NONSTRING', { page: { limit: 1, cursor: 1 } }],
];
const narrowingRows = narrowingMutations.map(([relationId, mutation]) =>
  row(
    narrowingDefaults,
    relationId,
    relationId,
    'an otherwise admitted narrowing input changes exactly one field/filter/page relation',
    () => {
      const { intent, profile } = build();
      expect(() =>
        narrowIntent(intent, profile, {
          ...privacyExplorerNarrowing,
          filters: [],
          projectionFields: ['PEF-A'],
          page: { limit: 1, cursor: null },
          ...mutation,
        } as never),
      ).toThrow();
      return 0;
    },
  ),
);
narrowingRows.push(
  row(
    narrowingDefaults,
    'NARROW-HIDDEN-ARRAY-PROPERTY',
    'filters array exact own data-property grammar',
    'an otherwise empty filter array carries a hidden provider selector',
    () => {
      const { intent, profile } = build();
      const filters: unknown[] = [];
      Object.defineProperty(filters, 'provider', { value: 'forbidden', enumerable: false });
      expect(() =>
        narrowIntent(intent, profile, {
          ...privacyExplorerNarrowing,
          filters: filters as never,
          projectionFields: ['PEF-A'],
          page: { limit: 1, cursor: null },
        }),
      ).toThrow('non-JSON array property');
      return 0;
    },
  ),
);

const requestDefaults: RowDefaults = {
  authoritySource: 'B2 packet 5.6-5.7 + adapter registry readGovernedProjection contract',
  authorityOwner: 'createProjectionRequest',
  admittedEntryPoint: 'createProjectionRequest(opaqueNarrowedIntent, trustedSeed)',
  validator: 'date-time/deadline/occurrence joins plus generated request/context validators',
  consumer: 'readGovernedProjection',
  retainedFact:
    'opaque immutable request/context pair plus private request and registration digests',
  positiveProof: 'one exact request/context pair is derived and generated-schema valid',
  expectedRejectingBranch: 'invalid call context seed before consumer invocation',
  noEffectResult: 'zero adapter calls and zero request emission',
};
const seedMutations: readonly (readonly [string, Readonly<Record<string, unknown>>])[] = [
  ['SEED-EXTRA-PROVIDER', { provider: 'forbidden' }],
  ['SEED-OCCURRENCE-MISMATCH', { occurrenceId: alternateOccurrence }],
  ['SEED-CORRELATION-MISMATCH', { auditCorrelationId: alternateOccurrence }],
  ['SEED-CANCELLATION-MISMATCH', { cancellationOccurrenceId: alternateOccurrence }],
  ['SEED-RECONCILIATION-MISMATCH', { reconciliationOccurrenceId: alternateOccurrence }],
  ['SEED-NOW-SYNTAX', { now: 'bad' }],
  ['SEED-NOW-CALENDAR', { now: '2027-02-30T00:00:00Z' }],
  ['SEED-DEADLINE-SYNTAX', { deadlineAt: 'bad' }],
  ['SEED-DEADLINE-CALENDAR', { deadlineAt: '2027-02-30T00:00:00Z' }],
  ['SEED-DEADLINE-NOT-AFTER-NOW', { deadlineAt: seed.now }],
  ['SEED-DEADLINE-PROFILE-WIDENED', { deadlineAt: '2029-01-01T00:00:00Z' }],
];
const requestRows = seedMutations.map(([relationId, mutation]) =>
  row(
    requestDefaults,
    relationId,
    relationId,
    'the trusted seed remains structurally valid while one occurrence/deadline relation is substituted',
    () => {
      const { narrowed } = build();
      expect(() => createProjectionRequest(narrowed, { ...seed, ...mutation })).toThrow();
      return 0;
    },
  ),
);

const digestDefaults: RowDefaults = {
  authoritySource: 'B2 packet 5.6 digest preimage contract',
  authorityOwner: 'narrowIntent and createProjectionRequest',
  admittedEntryPoint: 'canonical narrowing then generated request construction',
  validator: 'independent SHA-256 canonical JSON recomputation and opaque boundary identity',
  consumer: 'request context and B3 response binding',
  retainedFact: 'queryDigest, requestDigest, and idempotencyDigest with distinct closed preimages',
  positiveProof: 'each digest recomputes from its exact authoritative bytes',
  expectedRejectingBranch:
    'digest inequality or opaque-boundary rejection before adapter invocation',
  noEffectResult: 'zero adapter calls for every false digest/substitution candidate',
};

const digestRows: AdmissionRow[] = [
  row(
    digestDefaults,
    'DIGEST-QUERY-EXACT-PREIMAGE',
    'queryDigest complete semantic preimage',
    'a digest over a preimage that adds the cursor or omits export profile identity is mutually shaped but false',
    () => {
      const { narrowed } = build();
      const expected = sha256CanonicalJson({
        purpose: narrowed.intent.purpose,
        subject: narrowed.intent.context.subject,
        resource: narrowed.intent.resource,
        action: narrowed.intent.action,
        scope: {
          participantId: narrowed.intent.context.participantId,
          privacyDomainId: narrowed.intent.context.privacyDomainId,
          platformId: narrowed.intent.context.platformId,
          workloadId: narrowed.intent.context.workloadId,
          action: narrowed.intent.action,
        },
        operationId: narrowed.operationId,
        semanticOperationVersion: narrowed.semanticOperationVersion,
        dataClassId: narrowed.dataClassId,
        filters: narrowed.filters,
        page: { limit: narrowed.page.limit },
        projectionFields: narrowed.projectionFields,
        exportProfileDigest: narrowed.profile.digest,
      });
      expect(narrowed.queryDigest).toBe(expected);
      expect(sha256CanonicalJson({ expected, cursor: narrowed.page.cursor })).not.toBe(expected);
      return 0;
    },
  ),
  row(
    digestDefaults,
    'DIGEST-CANONICAL-EQUIVALENCE',
    'authority-defined set and filter ordering',
    'two requests differ only in caller-provided order and must not produce distinct query identities',
    () => {
      const { intent, profile } = build();
      const left = narrowIntent(intent, profile, {
        ...privacyExplorerNarrowing,
        filters: [
          { fieldId: 'PEF-B', filterId: 'PEFILTER-B', value: true },
          { fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 1 },
        ],
        projectionFields: ['PEF-B', 'PEF-A'],
        page: { limit: 20, cursor: null },
      });
      const right = narrowIntent(intent, profile, {
        ...privacyExplorerNarrowing,
        filters: [
          { fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 1 },
          { fieldId: 'PEF-B', filterId: 'PEFILTER-B', value: true },
        ],
        projectionFields: ['PEF-A', 'PEF-B'],
        page: { limit: 20, cursor: 'next' },
      });
      expect(left.queryDigest).toBe(right.queryDigest);
      return 0;
    },
  ),
  row(
    digestDefaults,
    'DIGEST-SCALAR-TYPE-SEPARATION',
    'JSON scalar type preservation',
    'the string "1" and number 1 are lexically similar but semantically different filter values',
    () => {
      const { intent, profile } = build();
      const make = (value: string | number) =>
        narrowIntent(intent, profile, {
          ...privacyExplorerNarrowing,
          filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value }],
          projectionFields: ['PEF-A'],
          page: { limit: 1, cursor: null },
        }).queryDigest;
      expect(make('1')).not.toBe(make(1));
      return 0;
    },
  ),
  row(
    digestDefaults,
    'DIGEST-REQUEST-EXACT-BYTES',
    'requestDigest complete generated request',
    'queryDigest is substituted as an undocumented requestDigest alias',
    () => {
      const { boundary } = build();
      expect(boundary.requestDigest).toBe(sha256CanonicalJson(boundary.request));
      expect(boundary.requestDigest).not.toBe(boundary.request.queryDigest);
      return 0;
    },
  ),
  row(
    digestDefaults,
    'DIGEST-IDEMPOTENCY-QUERY-CURSOR',
    'idempotencyDigest exact queryDigest plus cursor preimage',
    'requestDigest or queryDigest alone is substituted for cursor-bound idempotency',
    () => {
      const { boundary } = build();
      expect(boundary.context.idempotencyDigest).toBe(
        sha256CanonicalJson({
          queryDigest: boundary.request.queryDigest,
          cursor: boundary.request.page.cursor ?? null,
        }),
      );
      expect(boundary.context.idempotencyDigest).not.toBe(boundary.requestDigest);
      return 0;
    },
  ),
  row(
    digestDefaults,
    'DIGEST-CANONICAL-JSON-CODE-UNIT',
    'recursive object-key code-unit order',
    'locale collation supplies a different host-dependent key order',
    () => {
      expect(canonicalJson({ z: 1, A: 2, a: 3 })).toBe('{"A":2,"a":3,"z":1}');
      expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow('non-finite scalar');
      return 0;
    },
  ),
];

const consumerDefaults: RowDefaults = {
  authoritySource: 'B2 packet 5.8 + ExplorerConsumerAdapterV1 readGovernedProjection',
  authorityOwner: 'bindGovernedProjectionConsumer/readGovernedProjection',
  admittedEntryPoint: 'readGovernedProjection(opaquePort, opaqueBoundary)',
  validator: 'private profile registration join and exact opaque identities',
  consumer: 'captured adapter implementation callable',
  retainedFact: 'private bound registration identity; no endpoint/source selector',
  positiveProof:
    'captured implementation receives exactly generated request, context and frozen admitted execution control',
  expectedRejectingBranch: 'consumer registration or boundary identity mismatch',
  noEffectResult: 'replacement/mismatched/forged consumer receives zero calls',
};
const consumerRows: AdmissionRow[] = [
  row(
    consumerDefaults,
    'CONSUMER-INVALID-IMPLEMENTATION',
    'implementation callable',
    'a composition object lacks a callable readGovernedProjection member',
    () => {
      const { profile } = build();
      expect(() => bindGovernedProjectionConsumer(profile, {} as never)).toThrow(
        'invalid governed projection consumer',
      );
      return 0;
    },
  ),
  row(
    consumerDefaults,
    'CONSUMER-REGISTRATION-MISMATCH',
    'profile registration identity',
    'two profiles have identical public fields but distinct verifier-issued registration identities',
    async () => {
      const { boundary } = build();
      const otherProfile = registerExplorerProfile('other', {
        verify: (candidate) =>
          candidate === 'other'
            ? { ...profileFacts, registrationId: alternateOccurrence }
            : undefined,
      });
      let calls = 0;
      const port = bindGovernedProjectionConsumer(otherProfile, {
        verifyEvidenceReference: async () => ({}),
        readGovernedProjection: async () => {
          calls += 1;
          return {};
        },
      } as never);
      await expect(readGovernedProjection(port, boundary)).rejects.toThrow(
        'projection consumer registration mismatch',
      );
      return calls;
    },
  ),
  row(
    consumerDefaults,
    'CONSUMER-CAPTURED-CALLABLE-EXACT-ARGS',
    'callable identity and three-argument request/context/frozen-control interface',
    'the mutable composition object replaces its method after binding',
    async () => {
      const { profile, boundary } = build();
      let originalCalls = 0;
      let replacementCalls = 0;
      let received: unknown[] = [];
      const implementation = {
        verifyEvidenceReference: async () => ({}),
        readGovernedProjection: async (...args: unknown[]) => {
          originalCalls += 1;
          received = args;
          return { value: 'original' };
        },
      };
      const port = bindGovernedProjectionConsumer(profile, implementation as never);
      implementation.readGovernedProjection = async () => {
        replacementCalls += 1;
        return { value: 'replacement' };
      };
      await expect(readGovernedProjection(port, boundary)).resolves.toEqual({ value: 'original' });
      expect(originalCalls).toBe(1);
      expect(received).toHaveLength(3);
      expect(received[0]).toBe(boundary.request);
      expect(received[1]).toBe(boundary.context);
      expect(received[2]).toEqual({});
      expect(Object.getPrototypeOf(received[2])).toBe(Object.prototype);
      expect(Object.isFrozen(received[2])).toBe(true);
      expect(Reflect.ownKeys(received[2] as object)).toEqual([]);
      return replacementCalls;
    },
  ),
  row(
    consumerDefaults,
    'CONSUMER-CALLABLE-READ-ONCE',
    'composition callable is read and captured exactly once',
    'an accessor returns a second callable after the validation read',
    async () => {
      const { profile, boundary } = build();
      let getterReads = 0;
      let firstCalls = 0;
      let secondCalls = 0;
      const implementation = {
        verifyEvidenceReference: async () => ({}),
        get readGovernedProjection() {
          getterReads += 1;
          return getterReads === 1
            ? async () => {
                firstCalls += 1;
                return {};
              }
            : async () => {
                secondCalls += 1;
                return {};
              };
        },
      };
      const port = bindGovernedProjectionConsumer(profile, implementation as never);
      await readGovernedProjection(port, boundary);
      expect([getterReads, firstCalls]).toEqual([1, 1]);
      return secondCalls;
    },
  ),
  row(
    consumerDefaults,
    'CONSUMER-REQUEST-CONTEXT-JOINS',
    'profile/query/occurrence/authorization/context joins',
    'one well-shaped public field is compared against a different owner instead of the constructed pair',
    () => {
      const { boundary } = build();
      expect(boundary.request.exportProfile.digest).toBe(boundary.context.profileDigest);
      expect(boundary.request.occurrence.requestId).toBe(boundary.context.occurrenceId);
      expect(boundary.request.occurrence.correlationId).toBe(boundary.context.auditCorrelationId);
      expect(boundary.context.cancellation.occurrenceId).toBe(boundary.context.occurrenceId);
      expect(boundary.context.reconciliation.occurrenceId).toBe(boundary.context.occurrenceId);
      expect(boundary.context.authorizationDigest).toBe(facts.authorizationDigest);
      expect(boundary.context.authorizationContextId).toBe(facts.authorizationContextId);
      expect(boundary.context.authorizationContextEpoch).toBe(facts.authorizationContextEpoch);
      return 0;
    },
  ),
  row(
    consumerDefaults,
    'CONSUMER-DEEP-IMMUTABLE-PAIR',
    'post-construction request/context immutability',
    'caller mutates a nested profile or cancellation occurrence after generated validation',
    () => {
      const { boundary } = build();
      expect(() => {
        (boundary.request.exportProfile as { id: string }).id = 'changed';
      }).toThrow();
      expect(() => {
        (boundary.context.cancellation as { occurrenceId: string }).occurrenceId = 'changed';
      }).toThrow();
      return 0;
    },
  ),
  row(
    consumerDefaults,
    'CONSUMER-CANONICAL-SAFE-PROBLEM',
    'safe problem canonical generated bytes',
    'an adapter returns a mutable but value-equal plain problem or a frozen class with prototype serialization behavior',
    async () => {
      const { profile, boundary } = build();
      const condition = executionRegistry.conditionDefinitions[0]!;
      const supplied = { ...safeProblemForCondition(condition.id) };
      const port = bindGovernedProjectionConsumer(profile, {
        verifyEvidenceReference: async () => ({}),
        readGovernedProjection: async () => supplied,
      } as never);
      const result = await readGovernedProjection(port, boundary);
      expect(result).toEqual(safeProblemForCondition(condition.id));
      expect(result).not.toBe(supplied);
      expect(Object.isFrozen(result)).toBe(true);
      class ForgedProblem {
        toJSON() {
          return { rawDetail: 'secret' };
        }
      }
      const forged = Object.assign(new ForgedProblem(), supplied);
      Object.freeze(forged);
      expect(isSafeProblem(forged)).toBe(false);
      return 0;
    },
  ),
];

const reducerDefaults: RowDefaults = {
  authoritySource: 'B1 generated execution registry derived from authenticated C17 anchors',
  authorityOwner: 'reducePrivacyExplorerTransition',
  admittedEntryPoint:
    'reducePrivacyExplorerTransition(current state, operation, event, guard, condition)',
  validator: 'exactly-one generated registry row match',
  consumer: 'B4 atomic lifecycle owner',
  retainedFact: 'generated next state/effects/retained fact/disposition',
  positiveProof: 'every generated application reduces to its own declared output exactly once',
  expectedRejectingBranch: 'undeclared or ambiguous Privacy Explorer transition',
  noEffectResult:
    'pure reducer performs zero external effects and caller-selected output is ignored',
};
const applications = [
  ...executionRegistry.lifecycleApplications,
  ...executionRegistry.conditionApplications,
  ...executionRegistry.cancellationApplications,
  ...executionRegistry.contributionApplications,
] as const;
const reducerRows: AdmissionRow[] = [
  ...applications.map((application, index) =>
    row(
      reducerDefaults,
      `REDUCER-GENERATED-${String(index + 1).padStart(3, '0')}`,
      'generated transition tuple and derived effects',
      'a caller cannot name a row or select a different next state/effect',
      () => {
        const disposition = application.disposition as Record<string, unknown>;
        const reduced = reducePrivacyExplorerTransition({
          state: application.fromStateId,
          operationId: application.operationId,
          eventId: application.eventId,
          guardId: application.guardId,
          ...(disposition.kind === 'CONDITION'
            ? { conditionDefinitionId: disposition.conditionDefinitionId as string }
            : {}),
        });
        expect(reduced).toMatchObject({
          state: application.toStateId,
          rawStateEffectId: application.rawStateEffectId,
          deliveryEffectId: application.deliveryEffectId,
          adapterEffectId: application.adapterEffectId,
          retainedFactId: application.retainedFactId,
          disposition: application.disposition,
        });
        return 0;
      },
    ),
  ),
  ...(
    [
      ['REDUCER-UNKNOWN-STATE', { state: 'UNKNOWN_STATE' }],
      ['REDUCER-UNKNOWN-OPERATION', { operationId: 'UNKNOWN_OPERATION' }],
      ['REDUCER-UNKNOWN-EVENT', { eventId: 'UNKNOWN_EVENT' }],
      ['REDUCER-UNKNOWN-GUARD', { guardId: 'UNKNOWN_GUARD' }],
      ['REDUCER-WRONG-CONDITION', { conditionDefinitionId: 'EXP-COND-999' }],
    ] as const
  ).map(([relationId, mutation]) =>
    row(
      reducerDefaults,
      relationId,
      relationId,
      'the remaining transition tuple is valid while one selector is substituted',
      () => {
        const application = applications[0]!;
        expect(() =>
          reducePrivacyExplorerTransition({
            state: application.fromStateId,
            operationId: application.operationId,
            eventId: application.eventId,
            guardId: application.guardId,
            ...mutation,
          }),
        ).toThrow('undeclared or ambiguous');
        return 0;
      },
    ),
  ),
  row(
    reducerDefaults,
    'REDUCER-CALLER-SELECTED-EFFECT-IGNORED',
    'caller-supplied output/effect fields',
    'an excess toStateId and adapterEffectId agree with a desired but undeclared transition',
    () => {
      const application = applications[0]!;
      const reduced = reducePrivacyExplorerTransition({
        state: application.fromStateId,
        operationId: application.operationId,
        eventId: application.eventId,
        guardId: application.guardId,
        toStateId: 'RELEASED',
        adapterEffectId: 'CALLER_SELECTED',
      } as never);
      expect(reduced.state).toBe(application.toStateId);
      expect(reduced.adapterEffectId).toBe(application.adapterEffectId);
      return 0;
    },
  ),
];

const outcomeDefaults: RowDefaults = {
  authoritySource: 'AF-22 sections 3 and 5 via B1 generated result/condition definitions',
  authorityOwner: 'classifyOutcome, rejectEmptySuccess, and safeProblemForCondition',
  admittedEntryPoint: 'closed generated outcome or condition identifier',
  validator: 'generated exact mapping with NO_AUTHORITY and safe public fields only',
  consumer: 'B3 validation/result mapping',
  retainedFact: 'closed truth/record/cursor classification or exact safe problem',
  positiveProof:
    'all generated outcomes and conditions map exactly to their authoritative definitions',
  expectedRejectingBranch:
    'unknown outcome/condition, unsafe problem, or invalid empty/record cardinality',
  noEffectResult: 'no authority grant, fallback, raw detail, or fabricated empty COMPLETE',
};
const outcomeRows: AdmissionRow[] = [
  ...executionRegistry.resultDefinitions.map((definition) =>
    row(
      outcomeDefaults,
      `OUTCOME-${definition.outcome}`,
      `${definition.outcome} truth/record/cursor/authority relation`,
      `the ${definition.outcome} label is paired with a different truth or record law`,
      () => {
        const classified = classifyOutcome(definition.outcome);
        expect(classified).toEqual({
          outcome: definition.outcome,
          truthState: definition.truthState,
          recordsAllowed: definition.recordLawId === 'RECORDS_ALLOWED',
          cursorLawId: definition.cursorLawId,
        });
        expect(definition.authorityEffectId).toBe('NO_AUTHORITY');
        return 0;
      },
    ),
  ),
  ...executionRegistry.conditionDefinitions.map((condition) =>
    row(
      outcomeDefaults,
      `PROBLEM-${condition.id}`,
      `${condition.id} exact safe public mapping`,
      'the registered code is paired with raw or cross-condition public fields',
      () => {
        const problem = safeProblemForCondition(condition.id);
        expect(problem).toEqual({
          code: condition.code,
          httpStatus: condition.httpStatus,
          jsonRpcCode: condition.jsonRpcCode,
          grpcStatus: condition.grpcStatus,
          truthState: condition.truthState,
          retryable: condition.retryable,
          disclosure: condition.disclosure,
          publicTitle: condition.publicTitle,
        });
        expect(isSafeProblem({ ...problem })).toBe(true);
        expect(isSafeProblem({ ...problem, rawDetail: 'secret provider body' })).toBe(false);
        return 0;
      },
    ),
  ),
  row(
    outcomeDefaults,
    'OUTCOME-COMPLETE-EMPTY-REJECTED',
    'absence requires explicit gap-free completeness proof',
    'zero records are labeled COMPLETE before B3 can prove gap-free completeness',
    () => {
      expect(() => rejectEmptySuccess('COMPLETE', 0)).toThrow(
        'absence cannot be represented as COMPLETE',
      );
      return 0;
    },
  ),
  row(
    outcomeDefaults,
    'OUTCOME-UNKNOWN-RECORDS-REJECTED',
    'UNKNOWN records must be empty',
    'records are returned while completeness remains UNKNOWN',
    () => {
      expect(() => rejectEmptySuccess('UNKNOWN', 1)).toThrow(
        'non-complete outcome cannot expose records',
      );
      return 0;
    },
  ),
  row(
    outcomeDefaults,
    'OUTCOME-UNAVAILABLE-RECORDS-REJECTED',
    'UNAVAILABLE records must be empty',
    'cached records are returned as a fallback while the source is UNAVAILABLE',
    () => {
      expect(() => rejectEmptySuccess('UNAVAILABLE', 1)).toThrow(
        'non-complete outcome cannot expose records',
      );
      return 0;
    },
  ),
  row(
    outcomeDefaults,
    'OUTCOME-INVALID-COUNT-REJECTED',
    'record count is a non-negative integer',
    'a negative or fractional count bypasses the empty/record laws',
    () => {
      expect(() => rejectEmptySuccess('PARTIAL', -1)).toThrow('invalid record count');
      expect(() => rejectEmptySuccess('PARTIAL', 1.5)).toThrow('invalid record count');
      return 0;
    },
  ),
  row(
    outcomeDefaults,
    'OUTCOME-UNKNOWN-LABEL-REJECTED',
    'closed outcome enum',
    'STALE is supplied as a result outcome rather than its registered condition',
    () => {
      expect(() => classifyOutcome('STALE' as never)).toThrow('unknown non-authoritative outcome');
      return 0;
    },
  ),
  row(
    outcomeDefaults,
    'PROBLEM-UNKNOWN-CONDITION-REJECTED',
    'closed generated condition identifier',
    'a caller invents a new condition with an otherwise safe-looking public code',
    () => {
      expect(() => safeProblemForCondition('EXP-COND-999')).toThrow(
        'unknown Privacy Explorer condition',
      );
      return 0;
    },
  ),
  row(
    outcomeDefaults,
    'PROBLEM-HIDDEN-OR-SYMBOL-DETAIL-REJECTED',
    'exact own data-property safe-problem shape',
    'raw detail is hidden as a non-enumerable or symbol property',
    () => {
      const problem = { ...safeProblemForCondition(executionRegistry.conditionDefinitions[0]!.id) };
      Object.defineProperty(problem, 'rawDetail', { value: 'secret', enumerable: false });
      expect(isSafeProblem(problem)).toBe(false);
      const symbolProblem = {
        ...safeProblemForCondition(executionRegistry.conditionDefinitions[0]!.id),
      };
      Object.defineProperty(symbolProblem, Symbol('raw'), { value: 'secret', enumerable: true });
      expect(isSafeProblem(symbolProblem)).toBe(false);
      return 0;
    },
  ),
];

const negativeSpaceDefaults: RowDefaults = {
  authoritySource: 'AF-22 sections 1, 4, and 5 + B2 packet negative-space contract',
  authorityOwner: 'control-api Privacy Explorer package boundary',
  admittedEntryPoint: 'server-only package export and source dependency graph',
  validator: 'bounded source scan over all B2 production modules',
  consumer: 'later server composition only',
  retainedFact:
    'no transport/provider/raw/fallback/browser path and one generated registry adapter',
  positiveProof: 'the narrow index exports only server composition contracts',
  expectedRejectingBranch: 'forbidden token/export/import count assertion',
  noEffectResult: 'no network I/O, fallback, browser path, raw export, or copied registry',
};
const productionSources = [
  '../contracts/privacy-explorer-adapter.ts',
  './consumer-port.ts',
  './context.ts',
  './immutable.ts',
  './index.ts',
  './narrowing.ts',
  './outcomes.ts',
  './preauthorization.ts',
  './problems.ts',
  './profile-registration.ts',
  './reducer.ts',
  './request.ts',
] as const;
const negativeSpaceRows: AdmissionRow[] = [
  row(
    negativeSpaceDefaults,
    'NEGATIVE-SPACE-NO-TRANSPORT-OR-FALLBACK',
    'server package contains no transport/source selector',
    'a direct fetch, URL, endpoint, provider selector, browser call, or fallback path is added',
    async () => {
      const sources = await Promise.all(
        productionSources.map(async (path) => ({
          path,
          source: await readFile(new URL(path, import.meta.url), 'utf8'),
        })),
      );
      for (const { path, source } of sources)
        for (const forbidden of [
          /\bfetch\s*\(/i,
          /https?:\/\//i,
          /\bendpoint\b/i,
          /\bprovider(?:Id|Url|Selector)?\b/i,
          /\bfallback\b/i,
          /\bbrowser\b/i,
        ])
          expect(source, `${path} contains ${forbidden}`).not.toMatch(forbidden);
      return 0;
    },
  ),
  row(
    negativeSpaceDefaults,
    'NEGATIVE-SPACE-SOLE-GENERATED-ADAPTER',
    'generated layout dependency and execution registry authority',
    'a production module imports generated files directly or copies registry literals',
    async () => {
      const sources = await Promise.all(
        productionSources.map((path) => readFile(new URL(path, import.meta.url), 'utf8')),
      );
      const directGeneratedImports = sources.filter((source, index) =>
        index === 0 ? false : source.includes('generated/typescript'),
      );
      expect(directGeneratedImports).toHaveLength(0);
      expect(
        sources.filter((source) => source.includes('privacyExplorerExecutionRegistry')),
      ).toHaveLength(1);
      expect(sources.slice(1).join('\n')).not.toContain('EXP-COND-001');
      return 0;
    },
  ),
  row(
    negativeSpaceDefaults,
    'NEGATIVE-SPACE-NARROW-PUBLIC-EXPORT',
    'public index excludes generated validators/raw result and internal constructors',
    'the package index exports raw adapter validators/results, registry, digests, or opacity checks',
    async () => {
      const source = await readFile(new URL('./index.ts', import.meta.url), 'utf8');
      for (const forbidden of [
        'executionRegistry',
        'assertExplorerProjectionResult',
        'ExplorerProjectionResultV1',
        'requestDigest',
        'requireLocalContext',
        'requirePreauthorizedIntent',
        'requireNarrowedIntent',
        'requireGovernedProjectionBoundary',
        'registeredProfileId',
      ])
        expect(source).not.toContain(forbidden);
      return 0;
    },
  ),
];

const admissionInventory = [
  ...terminalRows,
  ...identityRows,
  ...preauthorizationRows,
  ...profileRows,
  ...narrowingRows,
  ...requestRows,
  ...digestRows,
  ...consumerRows,
  ...reducerRows,
  ...outcomeRows,
  ...negativeSpaceRows,
] as const;

describe('B2 declarative admission matrix', () => {
  it('has a unique, field-complete authority-to-no-effect row for every admitted relation', () => {
    assertInventory(admissionInventory);
    expect(initialPrivacyExplorerState).toBe('OPEN');
  });

  it('has exactly one generated reducer tuple for every reachable selector key', () => {
    const keys = applications.map((application) => {
      const disposition = application.disposition as Record<string, unknown>;
      return canonicalJson({
        state: application.fromStateId,
        operationId: application.operationId,
        eventId: application.eventId,
        guardId: application.guardId,
        conditionDefinitionId:
          disposition.kind === 'CONDITION' ? disposition.conditionDefinitionId : null,
      });
    });
    expect(new Set(keys).size).toBe(keys.length);
  });

  it.each(admissionInventory)(
    '$relationId executes its positive/rejecting branch and proves the named no-effect result',
    async (entry) => {
      expect(await entry.run()).toBe(0);
    },
  );
});
