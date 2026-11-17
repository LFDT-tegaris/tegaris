import { createHash, generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createGovernedInitialEnrollmentAssertion,
  governedInitialEnrollmentEvidenceSchema,
  governedInitialEnrollmentProfileSchema,
  selectGovernedInitialEnrollmentAccount,
  verifyGovernedInitialEnrollmentReceipt,
  type GovernedInitialEnrollmentEvidence,
} from './governed-initial-enrollment.js';
import { createLocalIdentityRuntimeCryptoAdapter } from './identity-runtime-crypto.js';
import {
  verifyIdentityRuntimeAuthorizationAssertion,
  type IdentityRuntimeAuthorizationContext,
} from './identity-runtime-authorization.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (text: string) => `sha256:${createHash('sha256').update(text).digest('hex')}`;
const now = new Date('2026-11-13T08:00:00.000Z');
function fixture() {
  const accounts = [0, 1, 2].map((n) => ({
    participantId: id(101),
    privacyDomainId: id(201),
    principalId: id(301 + n),
    identitySubjectId: id(401 + n),
    principalEpoch: '1',
    participantEpoch: '1',
    issuer: 'https://login.example.test',
    subject: `approved-person-${n}`,
    audience: 'console',
    invitationId: id(501 + n),
    invitationVersion: '1',
    acceptanceOperationId: id(601 + n),
    activationOperationId: id(701 + n),
    activationDigest: digest(`activation-${n}`),
    activationEvidenceDigest: digest('activation-receipt'),
    acceptanceEvidenceDigest: digest('acceptance-receipt'),
    makerVerificationEvidenceDigest: digest('maker-verification'),
    kind: n === 0 ? ('EXECUTOR' as const) : ('CUSTODIAN' as const),
  }));
  const profile = governedInitialEnrollmentProfileSchema.parse({
    schema: 'pc.identity.governed-initial-enrollment-profile',
    schemaVersion: 1,
    purpose: 'FIRST_AUTHENTICATOR_ONLY',
    profile: 'LOCAL_QA',
    origin: 'https://console.example.test',
    validFrom: now.toISOString(),
    validUntil: '2026-11-14T08:00:00.000Z',
    accounts,
  });
  const evidence: GovernedInitialEnrollmentEvidence = {
    schema: 'pc.identity.governed-initial-enrollment-result',
    schemaVersion: 1,
    purpose: 'FIRST_AUTHENTICATOR_ONLY',
    permissionEffect: 'NONE',
    operationId: id(801),
    account: accounts[0]!,
    profileDigest: digest('profile'),
    sessionId: id(802),
    sessionEpoch: '1',
    sessionIssuedAt: '2026-11-13T07:59:00.000Z',
    sessionValidUntil: '2026-11-13T08:10:00.000Z',
    authenticationOccurrenceId: id(803),
    authenticationReceiptDigest: digest('authentication-receipt'),
    oidcCredentialId: id(804),
    oidcCredentialEpoch: '1',
    activationEvidenceDigest: digest('activation-receipt'),
    acceptanceEvidenceDigest: digest('acceptance-receipt'),
    makerVerificationEvidenceDigest: digest('maker-verification'),
    enrollmentId: id(805),
    enrollmentCreatedAt: now.toISOString(),
    enrollmentValidUntil: '2026-11-13T08:05:00.000Z',
    rpId: 'console.example.test',
    origin: 'https://console.example.test',
    authenticatorCredentialId: id(806),
    authenticatorPublicKeyDigest: digest('public-key'),
    attestationDigest: digest('attestation'),
    hardwareAttestation: 'VERIFIED',
    committedAt: now.toISOString(),
    validUntil: '2026-11-13T08:01:00.000Z',
  };
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const publicDer = publicKey.export({ type: 'spki', format: 'der' });
  const crypto = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: privateKey.export({ type: 'pkcs8', format: 'der' }),
    activePublicKeySpkiDer: publicDer,
    trustedPublicKeysSpkiDer: [publicDer],
  });
  const selection = {
    profile,
    localQaEnabled: true,
    participantId: id(101),
    principalId: id(301),
    origin: profile.origin,
    now,
  };
  return { profile, evidence, crypto, selection };
}

describe('temporary governed first-enrollment selection', () => {
  it('selects only the exact approved principal and scope', () => {
    const f = fixture();
    expect(selectGovernedInitialEnrollmentAccount(f.selection)).toEqual(f.profile.accounts[0]);
    expect(
      selectGovernedInitialEnrollmentAccount({ ...f.selection, principalId: id(999) }),
    ).toBeUndefined();
    expect(
      selectGovernedInitialEnrollmentAccount({ ...f.selection, participantId: id(102) }),
    ).toBeUndefined();
  });
  it.each([
    { localQaEnabled: false },
    { origin: 'https://foreign.example.test' },
    { now: new Date('2026-11-13T07:59:59.999Z') },
    { now: new Date('2026-11-14T08:00:00.000Z') },
    { now: new Date(Number.NaN) },
  ])('rejects inactive or foreign selection %j', (change) => {
    const f = fixture();
    expect(selectGovernedInitialEnrollmentAccount({ ...f.selection, ...change })).toBeUndefined();
  });
  it.each([
    (p: ReturnType<typeof fixture>['profile']) => ({ ...p, accounts: p.accounts.slice(0, 2) }),
    (p: ReturnType<typeof fixture>['profile']) => ({
      ...p,
      accounts: [...p.accounts, p.accounts[0]],
    }),
    (p: ReturnType<typeof fixture>['profile']) => ({
      ...p,
      accounts: [p.accounts[0], p.accounts[0], p.accounts[2]],
    }),
    (p: ReturnType<typeof fixture>['profile']) => ({
      ...p,
      accounts: p.accounts.map((a) => ({ ...a, kind: 'CUSTODIAN' })),
    }),
    (p: ReturnType<typeof fixture>['profile']) => ({
      ...p,
      validUntil: '2026-11-14T08:00:00.001Z',
    }),
    (p: ReturnType<typeof fixture>['profile']) => ({
      ...p,
      origin: 'https://console.example.test/path',
    }),
    (p: ReturnType<typeof fixture>['profile']) => ({ ...p, permissionEffect: 'GRANT' }),
  ])('rejects broadened or ambiguous profiles', (change) => {
    expect(
      governedInitialEnrollmentProfileSchema.safeParse(change(fixture().profile)).success,
    ).toBe(false);
  });
});

describe('factual first-enrollment receipt', () => {
  it('authenticates the complete result with the actual Identity key ring', async () => {
    const f = fixture();
    const bytes = createGovernedInitialEnrollmentAssertion(f.evidence);
    const signed = await f.crypto.signCanonicalAssertion(bytes);
    expect(
      await verifyGovernedInitialEnrollmentReceipt(f.crypto, f.evidence, bytes, signed.coseSign1),
    ).toBe(true);
  });
  it.each([
    (e: GovernedInitialEnrollmentEvidence) => ({ ...e, permissionEffect: 'GRANT' }),
    (e: GovernedInitialEnrollmentEvidence) => ({ ...e, assignmentId: id(900) }),
    (e: GovernedInitialEnrollmentEvidence) => ({ ...e, hardwareAttestation: 'NOT_REQUIRED' }),
    (e: GovernedInitialEnrollmentEvidence) => ({ ...e, validUntil: e.committedAt }),
    (e: GovernedInitialEnrollmentEvidence) => ({ ...e, validUntil: '2026-11-13T08:01:00.001Z' }),
    (e: GovernedInitialEnrollmentEvidence) => ({
      ...e,
      enrollmentValidUntil: '2026-11-13T08:00:30.000Z',
    }),
    (e: GovernedInitialEnrollmentEvidence) => ({
      ...e,
      sessionValidUntil: '2026-11-13T08:00:30.000Z',
    }),
    (e: GovernedInitialEnrollmentEvidence) => ({ ...e, rpId: 'foreign.example.test' }),
    (e: GovernedInitialEnrollmentEvidence) => ({
      ...e,
      authenticatorCredentialId: e.oidcCredentialId,
    }),
  ])('rejects permissions, invalid attestation, windows or bindings', (change) => {
    expect(
      governedInitialEnrollmentEvidenceSchema.safeParse(change(fixture().evidence)).success,
    ).toBe(false);
  });
  it('rejects substituted provenance and result fields even with an authentic signature', async () => {
    const f = fixture();
    const bytes = createGovernedInitialEnrollmentAssertion(f.evidence);
    const signed = await f.crypto.signCanonicalAssertion(bytes);
    const changes = [
      { profileDigest: digest('other') },
      { activationEvidenceDigest: digest('other') },
      { acceptanceEvidenceDigest: digest('other') },
      { makerVerificationEvidenceDigest: digest('other') },
      { authenticationReceiptDigest: digest('other') },
      { sessionId: id(910) },
      { enrollmentId: id(911) },
      { authenticatorCredentialId: id(912) },
      { account: { ...f.evidence.account, subject: 'other-person' } },
      { account: { ...f.evidence.account, activationDigest: digest('other') } },
    ];
    for (const change of changes)
      expect(
        await verifyGovernedInitialEnrollmentReceipt(
          f.crypto,
          { ...f.evidence, ...change },
          bytes,
          signed.coseSign1,
        ),
      ).toBe(false);
    const wrongRing = fixture().crypto;
    expect(
      await verifyGovernedInitialEnrollmentReceipt(wrongRing, f.evidence, bytes, signed.coseSign1),
    ).toBe(false);
    const corrupt = Buffer.from(signed.coseSign1);
    corrupt[corrupt.length - 1]! ^= 1;
    expect(await verifyGovernedInitialEnrollmentReceipt(f.crypto, f.evidence, bytes, corrupt)).toBe(
      false,
    );
  });
  it('cannot be consumed as assignment-backed runtime authorization', async () => {
    const f = fixture();
    const bytes = createGovernedInitialEnrollmentAssertion(f.evidence);
    const signed = await f.crypto.signCanonicalAssertion(bytes);
    const runtime: IdentityRuntimeAuthorizationContext = {
      participantId: id(101),
      principalId: id(301),
      sessionId: id(802),
      sessionEpoch: '1',
      sessionIssuedAt: new Date(f.evidence.sessionIssuedAt),
      sessionIdleExpiresAt: new Date(f.evidence.sessionValidUntil),
      sessionAbsoluteExpiresAt: new Date(f.evidence.sessionValidUntil),
      participantEpoch: '1',
      principalEpoch: '1',
      assignmentId: id(920),
      assignmentRowVersion: '1',
      authorityEnvelopeId: id(921),
      authorityEpoch: '1',
      delegationEpoch: '1',
      actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      catalogOperationId: 'ID-OP-WEBAUTHN-REGISTER',
      resourceId: id(806),
      candidateDigest: digest('candidate'),
      sessionToken: `${id(101)}.${id(802)}`,
    };
    expect(
      await verifyGovernedInitialEnrollmentReceipt(f.crypto, f.evidence, bytes, signed.coseSign1),
    ).toBe(true);
    expect(verifyIdentityRuntimeAuthorizationAssertion(bytes, runtime, now)).toBeUndefined();
  });
});
