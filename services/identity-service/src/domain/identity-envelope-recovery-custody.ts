import { createPublicKey, verify } from 'node:crypto';
import {
  identityEnvelopeRecoveryReceivingTrust,
  signedIdentityEnvelopeRecoveryEnrollment,
  identityEnvelopeRecoveryCustodyPurpose,
  type IdentityEnvelopeRecoveryEnrollment,
} from '../contracts/identity-envelope-recovery.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../contracts/authorization.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';

/** Canonical bytes include the exact purpose and protocol domain. A site, COSE,
 * ordinary role or unsigned installation record cannot substitute for this. */
export function identityEnvelopeRecoveryCustodyPreimage(
  document: IdentityEnvelopeRecoveryEnrollment,
): Buffer {
  return Buffer.from(
    `${identityEnvelopeRecoveryCustodyPurpose}\0${canonicalAuthorizationJson(document)}`,
    'utf8',
  );
}

/** Original signature evidence only, independent of today's clock. This cannot
 * admit a proof, lease or issuer: currentness must use the fresh verifier below. */
export function authenticateHistoricalIdentityEnvelopeRecoveryCustody(
  installedTrust: unknown,
  input: unknown,
): IdentityEnvelopeRecoveryEnrollment {
  return authenticateOriginalCustody(installedTrust, input).document;
}

function authenticateOriginalCustody(installedTrust: unknown, input: unknown) {
  const deny = () => {
    throw new PlatformRecoveryError();
  };
  try {
    const trust = identityEnvelopeRecoveryReceivingTrust.parse(installedTrust);
    const signed = signedIdentityEnvelopeRecoveryEnrollment.parse(input);
    const document = signed.document;
    if (
      trust.participantId !== document.participantId ||
      trust.privacyDomainId !== document.privacyDomainId ||
      trust.platformContextId !== document.platformContextId ||
      trust.installationDigest !== document.installationDigest ||
      trust.installationEnvironmentId !== document.installationEnvironmentId ||
      trust.profile !== document.profile ||
      trust.custodyTrustId !== document.custodyTrustId ||
      canonicalAuthorizationDigest(trust) !== document.custodyTrustDigest ||
      trust.issuerKeyId !== document.custodyIssuerKeyId ||
      trust.issuerEpoch !== document.custodyIssuerEpoch ||
      Date.parse(document.validUntil) <= Date.parse(document.validFrom) ||
      Date.parse(document.validFrom) < Date.parse(trust.validFrom) ||
      Date.parse(document.validUntil) > Date.parse(trust.validUntil)
    )
      deny();
    const signature = Buffer.from(signed.signature, 'base64url');
    if (
      signature.length !== 64 ||
      signature.toString('base64url') !== signed.signature ||
      !verify(
        'sha256',
        identityEnvelopeRecoveryCustodyPreimage(document),
        {
          key: createPublicKey({
            key: Buffer.from(trust.issuerPublicKeySpkiDer, 'base64'),
            format: 'der',
            type: 'spki',
          }),
          dsaEncoding: 'ieee-p1363',
        },
        signature,
      )
    )
      deny();
    return { trust, document };
  } catch {
    return deny();
  }
}

/** Authenticates current custody using independent installed receiving trust.
 * The caller must also fence revocation, installation/Root and live credentials.
 * Neither signature verification nor this clock check grants any authority. */
export function verifyIdentityEnvelopeRecoveryCustody(
  installedTrust: unknown,
  input: unknown,
  now: Date,
  localQaEnabled: boolean,
): IdentityEnvelopeRecoveryEnrollment {
  const { trust, document } = authenticateOriginalCustody(installedTrust, input);
  const nowMs = now.getTime();
  if (
    !Number.isFinite(nowMs) ||
    Date.parse(trust.validFrom) > nowMs ||
    Date.parse(trust.validUntil) <= nowMs ||
    Date.parse(document.validFrom) > nowMs ||
    Date.parse(document.validUntil) <= nowMs ||
    (!localQaEnabled && document.profile === 'LOCAL_QA') ||
    (document.assurance === 'LOCAL_QA_VIRTUAL_AUTHENTICATOR' &&
      (!localQaEnabled || trust.profile !== 'LOCAL_QA'))
  )
    throw new PlatformRecoveryError();
  return document;
}
