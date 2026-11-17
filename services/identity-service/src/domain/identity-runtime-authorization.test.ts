import { describe, expect, it } from 'vitest';

import {
  createIdentityRuntimeAuthorizationAssertion,
  verifyIdentityRuntimeAuthorizationAssertion,
  type IdentityRuntimeAuthorizationContext,
} from './identity-runtime-authorization.js';

const issuedAt = new Date('2026-09-11T02:00:00.000Z');
const context: IdentityRuntimeAuthorizationContext = {
  participantId: '018f0000-0000-7000-8000-000000000101',
  principalId: '018f0000-0000-7000-8000-000000000111',
  sessionId: '018f0000-0000-7000-8000-000000000117',
  sessionEpoch: '4',
  sessionIssuedAt: new Date('2026-09-11T01:00:00.000Z'),
  sessionIdleExpiresAt: new Date('2026-09-11T02:30:00.000Z'),
  sessionAbsoluteExpiresAt: new Date('2026-09-11T12:00:00.000Z'),
  participantEpoch: '5',
  principalEpoch: '7',
  assignmentId: '018f0000-0000-7000-8000-000000000301',
  assignmentRowVersion: '8',
  authorityEnvelopeId: '018f0000-0000-7000-8000-000000000401',
  authorityEpoch: '9',
  delegationEpoch: '10',
  actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
  catalogOperationId: 'ID-OP-SESSION-REFRESH',
  resourceId: '018f0000-0000-7000-8000-000000000117',
  candidateDigest: `sha256:${'a'.repeat(64)}`,
  sessionToken: '018f0000-0000-7000-8000-000000000101.018f0000-0000-7000-8000-000000000117',
};

describe('identity runtime authorization assertion binding', () => {
  it.each(['ID-OP-PLATFORM-SCOPE-PREPARE', 'ID-OP-PLATFORM-SCOPE-COMMIT'])(
    'binds a shared action to the exact supplied catalogue operation: %s',
    (catalogOperationId) => {
      const replacement = {
        ...context,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        catalogOperationId,
        configurationBinding: {
          privacyDomainId: '018f0000-0000-7000-8000-000000000201',
          actionIntentDigest: `sha256:${'b'.repeat(64)}`,
          expectedRevision: '1',
        },
      };
      const assertion = createIdentityRuntimeAuthorizationAssertion(
        'root-replacement',
        replacement,
        issuedAt,
      );
      expect(
        verifyIdentityRuntimeAuthorizationAssertion(assertion, replacement, issuedAt),
      ).toBeDefined();
      expect(
        verifyIdentityRuntimeAuthorizationAssertion(
          assertion,
          {
            ...replacement,
            catalogOperationId:
              catalogOperationId === 'ID-OP-PLATFORM-SCOPE-PREPARE'
                ? 'ID-OP-PLATFORM-SCOPE-COMMIT'
                : 'ID-OP-PLATFORM-SCOPE-PREPARE',
          },
          issuedAt,
        ),
      ).toBeUndefined();
    },
  );
  it('binds configuration context and revision under its exact registered operation', () => {
    const configuration = {
      ...context,
      actionIntentId: 'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1',
      catalogOperationId: 'CFG-OP-CREATE-INDEXER-PROFILE',
      configurationBinding: {
        privacyDomainId: '018f0000-0000-7000-8000-000000000201',
        actionIntentDigest: `sha256:${'b'.repeat(64)}`,
        expectedRevision: '0',
      },
    };
    const evidence = createIdentityRuntimeAuthorizationAssertion(
      'assertion-config',
      configuration,
      issuedAt,
    );
    expect(
      verifyIdentityRuntimeAuthorizationAssertion(evidence, configuration, issuedAt)?.assertionId,
    ).toBe('assertion-config');
    for (const changed of [
      { ...configuration, configurationBinding: undefined },
      { ...configuration, catalogOperationId: 'CFG-OP-UPDATE-INDEXER-PROFILE' },
      { ...configuration, actionIntentId: 'ACT-INDEXER_PROFILES_UPDATE_RESOURCE-V1' },
      {
        ...configuration,
        configurationBinding: {
          ...configuration.configurationBinding,
          privacyDomainId: '018f0000-0000-7000-8000-000000000202',
        },
      },
      {
        ...configuration,
        configurationBinding: {
          ...configuration.configurationBinding,
          actionIntentDigest: `sha256:${'c'.repeat(64)}`,
        },
      },
      {
        ...configuration,
        configurationBinding: { ...configuration.configurationBinding, expectedRevision: '1' },
      },
    ])
      expect(
        verifyIdentityRuntimeAuthorizationAssertion(evidence, changed, issuedAt),
      ).toBeUndefined();
    expect(() =>
      createIdentityRuntimeAuthorizationAssertion(
        'missing-scope',
        {
          ...configuration,
          configurationBinding: undefined,
        },
        issuedAt,
      ),
    ).toThrow();
  });

  it('binds signing advance/recover assertions to their exact catalog, privacy, input and revision', () => {
    for (const operation of ['ADVANCE', 'RECOVER']) {
      const signing = {
        ...context,
        actionIntentId: `ACT-SIGNING_KEY_ROTATIONS_${operation}_RESOURCE-V1`,
        catalogOperationId: `OPS-OP-${operation}-SIGNING-KEY-ROTATION`,
        configurationBinding: {
          privacyDomainId: '018f0000-0000-7000-8000-000000000201',
          actionIntentDigest: `sha256:${'b'.repeat(64)}`,
          expectedRevision: '3',
        },
      };
      const evidence = createIdentityRuntimeAuthorizationAssertion(
        'signing-assertion',
        signing,
        issuedAt,
      );
      expect(
        verifyIdentityRuntimeAuthorizationAssertion(evidence, signing, issuedAt),
      ).toBeDefined();
      for (const changed of [
        { ...signing, configurationBinding: undefined },
        { ...signing, catalogOperationId: 'OPS-OP-UNREGISTERED' },
        { ...signing, candidateDigest: `sha256:${'f'.repeat(64)}` },
        {
          ...signing,
          configurationBinding: { ...signing.configurationBinding, expectedRevision: '4' },
        },
        {
          ...signing,
          configurationBinding: {
            ...signing.configurationBinding,
            privacyDomainId: '018f0000-0000-7000-8000-000000000202',
          },
        },
      ])
        expect(
          verifyIdentityRuntimeAuthorizationAssertion(evidence, changed, issuedAt),
        ).toBeUndefined();
    }
    expect(() =>
      createIdentityRuntimeAuthorizationAssertion(
        'unknown-operation',
        { ...context, catalogOperationId: 'OPS-OP-UNREGISTERED' },
        issuedAt,
      ),
    ).toThrow();
  });

  it('accepts a short-lived assertion bound to current actor, session, authority and mutation', () => {
    const evidence = createIdentityRuntimeAuthorizationAssertion('assertion-1', context, issuedAt);
    const verified = verifyIdentityRuntimeAuthorizationAssertion(
      evidence,
      context,
      new Date(issuedAt.getTime() + 30_000),
    );
    expect(verified?.assertionId).toBe('assertion-1');
    if (verified === undefined) throw new Error('expected verified assertion');
    expect(verified.expiresAtNs - verified.issuedAtNs).toBe(60_000_000_000n);
  });

  it('rejects stale assertions and changes to candidate, audience, session or authority state', () => {
    const evidence = createIdentityRuntimeAuthorizationAssertion('assertion-2', context, issuedAt);
    expect(
      verifyIdentityRuntimeAuthorizationAssertion(
        evidence,
        context,
        new Date(issuedAt.getTime() + 60_000),
      ),
    ).toBeUndefined();
    for (const changed of [
      { candidateDigest: `sha256:${'b'.repeat(64)}` },
      { catalogOperationId: 'ID-OP-SESSION-REVOKE' },
      { sessionEpoch: '5' },
      { authorityEpoch: '10' },
      { assignmentRowVersion: '9' },
    ]) {
      expect(
        verifyIdentityRuntimeAuthorizationAssertion(
          evidence,
          { ...context, ...changed },
          new Date(issuedAt.getTime() + 30_000),
        ),
      ).toBeUndefined();
    }
  });

  it('caps assertion validity at the authoritative session expiry', () => {
    const nearExpiry = {
      ...context,
      sessionIdleExpiresAt: new Date(issuedAt.getTime() + 10_000),
    };
    const evidence = createIdentityRuntimeAuthorizationAssertion(
      'assertion-3',
      nearExpiry,
      issuedAt,
    );
    const verified = verifyIdentityRuntimeAuthorizationAssertion(
      evidence,
      nearExpiry,
      new Date(issuedAt.getTime() + 5_000),
    );
    if (verified === undefined) throw new Error('expected verified assertion');
    expect(verified.expiresAtNs - verified.issuedAtNs).toBe(10_000_000_000n);
  });

  it('expires cached authority exactly at a grant or directory freshness deadline', () => {
    const bounded = { ...context, authorityValidUntil: new Date(issuedAt.getTime() + 10_000) };
    const evidence = createIdentityRuntimeAuthorizationAssertion('group-expiry', bounded, issuedAt);
    expect(
      verifyIdentityRuntimeAuthorizationAssertion(
        evidence,
        bounded,
        new Date(issuedAt.getTime() + 9_999),
      ),
    ).toBeDefined();
    // A receiver without the optional SQL context must still honor the signed deadline.
    expect(
      verifyIdentityRuntimeAuthorizationAssertion(evidence, context, bounded.authorityValidUntil),
    ).toBeUndefined();
    const overlong = createIdentityRuntimeAuthorizationAssertion('overlong', context, issuedAt);
    expect(
      verifyIdentityRuntimeAuthorizationAssertion(overlong, bounded, issuedAt),
    ).toBeUndefined();
  });
});
