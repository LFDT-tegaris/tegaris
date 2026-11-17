import { timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { encodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import { identityActorKeyDigest } from './identity-runtime-authorization.js';
import type { IdentityRuntimeAssertionVerifier } from './identity-kernel.js';

const id = z.uuid();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18_446_744_073_709_551_615n);
const instant = z.iso.datetime({ offset: true });

/** An operator-reviewed, temporary account selection. It is not an authority
 * envelope, a directory, or permission to create/activate a principal. */
export const governedInitialEnrollmentAccountSchema = z.strictObject({
  participantId: id,
  privacyDomainId: id,
  principalId: id,
  identitySubjectId: id,
  principalEpoch: revision,
  participantEpoch: revision,
  issuer: z.url(),
  subject: z.string().min(1).max(255),
  audience: z.string().min(1).max(512),
  invitationId: id,
  invitationVersion: revision,
  acceptanceOperationId: id,
  activationOperationId: id,
  activationDigest: digest,
  activationEvidenceDigest: digest,
  acceptanceEvidenceDigest: digest,
  makerVerificationEvidenceDigest: digest,
  kind: z.enum(['EXECUTOR', 'CUSTODIAN']),
});
export type GovernedInitialEnrollmentAccount = z.infer<
  typeof governedInitialEnrollmentAccountSchema
>;

export const governedInitialEnrollmentProfileSchema = z
  .strictObject({
    schema: z.literal('pc.identity.governed-initial-enrollment-profile'),
    schemaVersion: z.literal(1),
    purpose: z.literal('FIRST_AUTHENTICATOR_ONLY'),
    profile: z.literal('LOCAL_QA'),
    origin: z.url(),
    validFrom: instant,
    validUntil: instant,
    accounts: z.array(governedInitialEnrollmentAccountSchema).length(3),
  })
  .superRefine((value, context) => {
    const start = Date.parse(value.validFrom);
    const end = Date.parse(value.validUntil);
    if (end <= start || end - start > 86_400_000)
      context.addIssue({ code: 'custom', message: 'Invalid enrollment profile window' });
    const origin = new URL(value.origin);
    if (origin.protocol !== 'https:' || origin.origin !== value.origin)
      context.addIssue({ code: 'custom', message: 'A canonical HTTPS origin is required' });
    if (
      new Set(value.accounts.map((account) => account.principalId)).size !== 3 ||
      new Set(value.accounts.map((account) => account.identitySubjectId)).size !== 3 ||
      new Set(
        value.accounts.map((account) =>
          JSON.stringify([account.issuer, account.subject, account.audience]),
        ),
      ).size !== 3 ||
      new Set(value.accounts.map((account) => account.activationOperationId)).size !== 3 ||
      new Set(value.accounts.map((account) => account.participantId)).size !== 1 ||
      new Set(value.accounts.map((account) => account.privacyDomainId)).size !== 1 ||
      value.accounts.filter((account) => account.kind === 'EXECUTOR').length !== 1
    )
      context.addIssue({
        code: 'custom',
        message: 'Three distinct, scope-bound accounts are required',
      });
  });
export type GovernedInitialEnrollmentProfile = z.infer<
  typeof governedInitialEnrollmentProfileSchema
>;

/** Select only an already approved exact identity. Database owners must still
 * fence and authenticate every source fact; this selection proves no effect. */
export function selectGovernedInitialEnrollmentAccount(input: {
  readonly profile: GovernedInitialEnrollmentProfile;
  readonly localQaEnabled: boolean;
  readonly participantId: string;
  readonly principalId: string;
  readonly origin: string;
  readonly now: Date;
}): GovernedInitialEnrollmentAccount | undefined {
  const profile = governedInitialEnrollmentProfileSchema.parse(input.profile);
  const now = input.now.getTime();
  if (
    !input.localQaEnabled ||
    !Number.isSafeInteger(now) ||
    now < Date.parse(profile.validFrom) ||
    now >= Date.parse(profile.validUntil) ||
    input.origin !== profile.origin
  )
    return undefined;
  return profile.accounts.find(
    (account) =>
      account.participantId === input.participantId && account.principalId === input.principalId,
  );
}

/** Factual receipt for first enrollment. Its source is the approved membership
 * activation and verified login, never an invented assignment/envelope. */
export const governedInitialEnrollmentEvidenceSchema = z
  .strictObject({
    schema: z.literal('pc.identity.governed-initial-enrollment-result'),
    schemaVersion: z.literal(1),
    purpose: z.literal('FIRST_AUTHENTICATOR_ONLY'),
    permissionEffect: z.literal('NONE'),
    operationId: id,
    account: governedInitialEnrollmentAccountSchema,
    profileDigest: digest,
    sessionId: id,
    sessionEpoch: revision,
    sessionIssuedAt: instant,
    sessionValidUntil: instant,
    authenticationOccurrenceId: id,
    authenticationReceiptDigest: digest,
    oidcCredentialId: id,
    oidcCredentialEpoch: revision,
    activationEvidenceDigest: digest,
    acceptanceEvidenceDigest: digest,
    makerVerificationEvidenceDigest: digest,
    enrollmentId: id,
    enrollmentCreatedAt: instant,
    enrollmentValidUntil: instant,
    rpId: z.string().min(1).max(255),
    origin: z.url(),
    authenticatorCredentialId: id,
    authenticatorPublicKeyDigest: digest,
    attestationDigest: digest,
    hardwareAttestation: z.enum(['VERIFIED', 'NOT_REQUIRED']),
    committedAt: instant,
    validUntil: instant,
  })
  .superRefine((value, context) => {
    const committed = Date.parse(value.committedAt);
    const expiry = Date.parse(value.validUntil);
    if (
      committed < Date.parse(value.enrollmentCreatedAt) ||
      Date.parse(value.enrollmentValidUntil) - Date.parse(value.enrollmentCreatedAt) > 300_000 ||
      committed < Date.parse(value.sessionIssuedAt) ||
      expiry <= committed ||
      expiry - committed > 60_000 ||
      expiry > Date.parse(value.enrollmentValidUntil) ||
      expiry > Date.parse(value.sessionValidUntil) ||
      new URL(value.origin).protocol !== 'https:' ||
      new URL(value.origin).origin !== value.origin ||
      new URL(value.origin).hostname !== value.rpId ||
      value.oidcCredentialId === value.authenticatorCredentialId ||
      value.activationEvidenceDigest !== value.account.activationEvidenceDigest ||
      value.acceptanceEvidenceDigest !== value.account.acceptanceEvidenceDigest ||
      value.makerVerificationEvidenceDigest !== value.account.makerVerificationEvidenceDigest ||
      (value.account.kind === 'EXECUTOR' && value.hardwareAttestation !== 'VERIFIED')
    )
      context.addIssue({ code: 'custom', message: 'Invalid first-enrollment evidence binding' });
  });
export type GovernedInitialEnrollmentEvidence = z.infer<
  typeof governedInitialEnrollmentEvidenceSchema
>;

const commitment = (field: string, value: unknown) =>
  canonicalAuthorizationDigestBytes({
    purpose: `pc.identity.governed-initial-enrollment.${field}.v1`,
    value,
  });

export function createGovernedInitialEnrollmentAssertion(
  input: GovernedInitialEnrollmentEvidence,
): Buffer {
  const value = governedInitialEnrollmentEvidenceSchema.parse(input);
  return encodeIdentityAuthContextAssertionPayload({
    assertionId: value.operationId,
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(value.account.participantId, value.account.principalId),
    participantContextDigest: commitment('membership', value.account),
    audienceDigest: commitment('result', value),
    senderBindingKind: 1,
    senderCredentialBindingDigest: commitment('session', [
      value.sessionId,
      value.sessionEpoch,
      value.sessionIssuedAt,
    ]),
    assuranceProfileDigest: commitment('assurance', [
      'verified-oidc-code-pkce-s256',
      'governed-activation',
      'first-authenticator-only',
      'no-ordinary-permission',
      value.hardwareAttestation,
    ]),
    authorityVectorDigest: commitment('activation-provenance', [
      value.account.activationOperationId,
      value.account.activationDigest,
      value.activationEvidenceDigest,
      value.acceptanceEvidenceDigest,
      value.makerVerificationEvidenceDigest,
      value.profileDigest,
    ]),
    authenticationEvidenceDigest: commitment('authentication', [
      value.authenticationOccurrenceId,
      value.authenticationReceiptDigest,
      value.oidcCredentialId,
      value.oidcCredentialEpoch,
      value.authenticatorCredentialId,
      value.authenticatorPublicKeyDigest,
      value.attestationDigest,
    ]),
    issuedAtNs: BigInt(Date.parse(value.committedAt)) * 1_000_000n,
    expiresAtNs: BigInt(Date.parse(value.validUntil)) * 1_000_000n,
  });
}

/** Historical factual readback compares the complete authenticated result.
 * It neither refreshes this receipt nor accepts it as runtime authorization. */
export async function verifyGovernedInitialEnrollmentReceipt(
  verifier: IdentityRuntimeAssertionVerifier,
  input: GovernedInitialEnrollmentEvidence,
  evidenceCbor: Buffer,
  coseSign1: Buffer,
): Promise<boolean> {
  let expected: Buffer;
  try {
    expected = createGovernedInitialEnrollmentAssertion(input);
  } catch {
    return false;
  }
  if (expected.length !== evidenceCbor.length || !timingSafeEqual(expected, evidenceCbor))
    return false;
  return (await verifier.verifyCanonicalAssertion(evidenceCbor, coseSign1)) !== undefined;
}
