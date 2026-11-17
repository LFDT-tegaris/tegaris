import { describe, expect, it } from 'vitest';

import {
  authorityEvaluationSchema,
  recoveryCaseSchema,
  sessionCookieProfile,
  sessionSchema,
} from '../../../services/identity-service/src/contracts/index.js';
import {
  authorityEnvelopeSchema,
  delegationSchema,
  walletBindingSchema,
} from '../../../services/participant-service/src/contracts/index.js';

const uuidA = '018f6d4a-1234-7abc-8def-0123456789ab';
const uuidB = '018f6d4a-1234-7abc-9def-0123456789ac';
const participantId = `urn:openpc:participant:${uuidA}`;
const principalA = `urn:openpc:principal:${uuidA}`;
const principalB = `urn:openpc:principal:${uuidB}`;
const digest = `sha256:${'a'.repeat(64)}`;
const timestamp = '2026-08-28T00:00:00.000000Z';

const metadata = {
  schemaVersion: '1.0.0',
  recordId: `urn:openpc:record:${uuidA}`,
  createdAt: timestamp,
  updatedAt: timestamp,
  traceSetId: 'TS-ID-AUTHORIZATION',
};

describe('I02 security contract boundaries', () => {
  it('rejects unknown fields instead of silently widening input', () => {
    const result = sessionSchema.safeParse({
      contractType: 'Session',
      ...metadata,
      status: 'ACTIVE',
      sessionId: `urn:openpc:session:${uuidA}`,
      principalId: principalA,
      participantId,
      participantEpoch: '1',
      sessionEpoch: '1',
      idleExpiresAt: timestamp,
      absoluteExpiresAt: timestamp,
      stepUpValidUntil: null,
      refreshFamilyId: `urn:openpc:refresh-family:${uuidA}`,
      cookieProfile: sessionCookieProfile,
      ambientAuthority: true,
    });

    expect(result.success).toBe(false);
  });

  it('requires every non-ALLOW evaluation to be terminal and non-leaking', () => {
    const result = authorityEvaluationSchema.safeParse({
      decision: 'UNKNOWN',
      authorized: false,
      terminal: false,
      existenceVisible: true,
      payloadVisible: false,
      authorityContext: {
        principalId: principalA,
        participantId,
        privacyDomainId: `urn:openpc:privacy-domain:${uuidA}`,
        sessionId: `urn:openpc:session:${uuidA}`,
        authorityEnvelopeId: `urn:openpc:authority-envelope:${uuidA}`,
        authorityEpoch: '1',
        delegationEpoch: '1',
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        policyGenerationDigest: digest,
        factGenerationDigest: digest,
      },
      inputsDigest: digest,
      evaluatedAt: timestamp,
      explanationCodes: ['AUTHORITY_INPUT_UNKNOWN'],
      traceSetId: 'TS-ID-AUTHORIZATION',
    });

    expect(result.success).toBe(false);
  });

  it('rejects maker-checker collapse and repeated recovery custodians', () => {
    expect(
      authorityEnvelopeSchema.safeParse({
        contractType: 'AuthorityEnvelope',
        ...metadata,
        status: 'DRAFT',
        participantId,
        authorityEpoch: '1',
        envelopeDigest: digest,
        scopeIds: ['scope:a'],
        capabilityIds: ['capability:a'],
        makerPrincipalId: principalA,
        checkerPrincipalId: principalA,
      }).success,
    ).toBe(false);

    expect(
      recoveryCaseSchema.safeParse({
        contractType: 'RecoveryCase',
        ...metadata,
        status: 'REQUESTED',
        recoveryPrincipalId: principalA,
        subjectId: principalB,
        purposeDigest: digest,
        custodianPrincipalIds: [principalA, principalA],
        leaseExpiresAt: timestamp,
        postReviewRequired: true,
      }).success,
    ).toBe(false);
  });

  it('rejects self-delegation and authority-bearing wallet bindings', () => {
    expect(
      delegationSchema.safeParse({
        contractType: 'Delegation',
        ...metadata,
        status: 'PROPOSED',
        participantId,
        delegationEpoch: '1',
        grantorId: principalA,
        granteeId: principalA,
        parentDelegationId: null,
        grantableDigest: digest,
        usableDigest: digest,
        downwardProofDigest: digest,
        notAfter: timestamp,
      }).success,
    ).toBe(false);

    expect(
      walletBindingSchema.safeParse({
        contractType: 'WalletBinding',
        ...metadata,
        status: 'ACTIVE',
        participantId,
        subjectId: principalA,
        chainId: '1',
        walletAddress: '0x0000000000000000000000000000000000000000',
        bindingEpoch: '1',
        permissionEffect: 'GRANTS_AUTHORITY',
      }).success,
    ).toBe(false);
  });

  it('pins the hardened host-only session cookie profile', () => {
    expect(sessionCookieProfile).toBe(
      '__Host-openpc_session; Secure; HttpOnly; SameSite=Strict; Path=/',
    );
  });
});
