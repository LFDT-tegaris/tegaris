import { createPublicKey, verify } from 'node:crypto';
import {
  encodeEnvelopeScope,
  type PlatformEnvelopeScopeAdmission,
} from '../../../../packages/security-kernel/src/index.js';
import {
  localRootExpiryRecoveryReceivingTrust,
  signedLocalRootExpiryRecoveryEnrollment,
  type LocalRootExpiryRecoveryEnrollment,
} from '../contracts/local-root-expiry-recovery.js';
import {
  canonicalAuthorizationJson,
  canonicalAuthorizationDigest,
} from '../contracts/authorization.js';
import { PlatformRecoveryError } from './platform-recovery-policy.js';

export function localRootExpiryRecoveryCustodyPreimage(
  document: LocalRootExpiryRecoveryEnrollment,
): Buffer {
  return Buffer.from(`${document.purpose}\0${canonicalAuthorizationJson(document)}`, 'utf8');
}
/** Historical authentication does not establish current recovery authority. */
export function authenticateLocalRootExpiryRecoveryCustody(
  installedTrust: unknown,
  input: unknown,
) {
  try {
    const trust = localRootExpiryRecoveryReceivingTrust.parse(installedTrust);
    const signed = signedLocalRootExpiryRecoveryEnrollment.parse(input);
    const d = signed.document;
    if (
      trust.schemaVersion !== d.schemaVersion ||
      trust.purpose !== d.purpose ||
      (d.schemaVersion === 2 &&
        (trust.schemaVersion !== 2 ||
          canonicalAuthorizationJson(trust.pending) !== canonicalAuthorizationJson(d.pending))) ||
      (d.schemaVersion === 3 &&
        (trust.schemaVersion !== 3 ||
          canonicalAuthorizationJson(trust.pending) !== canonicalAuthorizationJson(d.pending) ||
          canonicalAuthorizationJson(trust.rootAncestry) !==
            canonicalAuthorizationJson(d.rootAncestry))) ||
      trust.qaDurationProfile !== d.qaDurationProfile ||
      trust.participantId !== d.participantId ||
      trust.privacyDomainId !== d.privacyDomainId ||
      trust.platformContextId !== d.platformContextId ||
      trust.installationDigest !== d.installationDigest ||
      trust.installationEnvironmentId !== d.installationEnvironmentId ||
      trust.custodyTrustId !== d.custodyTrustId ||
      canonicalAuthorizationDigest(trust) !== d.custodyTrustDigest ||
      trust.issuerKeyId !== d.custodyIssuerKeyId ||
      trust.issuerEpoch !== d.custodyIssuerEpoch ||
      Date.parse(d.validFrom) < Date.parse(trust.validFrom) ||
      Date.parse(d.validUntil) > Date.parse(trust.validUntil)
    )
      throw new PlatformRecoveryError();
    const signature = Buffer.from(signed.signature, 'base64url');
    if (
      signature.length !== 64 ||
      signature.toString('base64url') !== signed.signature ||
      !verify(
        'sha256',
        localRootExpiryRecoveryCustodyPreimage(d),
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
      throw new PlatformRecoveryError();
    return { trust, enrollment: d };
  } catch {
    throw new PlatformRecoveryError();
  }
}

/** Only validity changes. All permission dimensions, mandatory governance,
 * custody metadata and delegation constraints remain byte-equivalent. */
export function localRootExpirySuccessorScope(
  root: PlatformEnvelopeScopeAdmission & { readonly platformAuthorityDigest: string },
  enrollment: LocalRootExpiryRecoveryEnrollment,
  rootRevision: string,
  now: Date,
  localQaEnabled: boolean,
  temporaryQaEnabled = false,
) {
  const nowNs = BigInt(now.getTime()) * 1000000n;
  const from = BigInt(Date.parse(enrollment.successorValidFrom)) * 1000000n;
  const until = BigInt(Date.parse(enrollment.successorValidUntil)) * 1000000n;
  if (
    !localQaEnabled ||
    (enrollment.qaDurationProfile === 'LOCAL_QA_10X' && !temporaryQaEnabled) ||
    enrollment.profile !== 'LOCAL_QA' ||
    !Number.isFinite(now.getTime()) ||
    root.ownerParticipantId !== enrollment.participantId ||
    root.installationPrivacyDomainId !== enrollment.privacyDomainId ||
    root.platformContextId !== enrollment.platformContextId ||
    root.installationDigest !== enrollment.installationDigest ||
    root.environmentId !== enrollment.installationEnvironmentId ||
    root.platformAuthorityEpoch !== enrollment.rootEpoch ||
    root.platformAuthorityDigest !== enrollment.rootDigest ||
    rootRevision !== enrollment.rootRevision ||
    BigInt(root.grantable.validUntilNs) > nowNs ||
    BigInt(root.grantable.validFromNs) > nowNs ||
    Date.parse(enrollment.validFrom) > now.getTime() ||
    Date.parse(enrollment.validUntil) <= now.getTime() ||
    from > nowNs ||
    from < BigInt(root.grantable.validUntilNs) ||
    until <= nowNs ||
    until - from > (enrollment.qaDurationProfile ? 864000000000000n : 86400000000000n) ||
    until - from >
      (BigInt(root.grantable.validUntilNs) - BigInt(root.grantable.validFromNs)) *
        (enrollment.qaDurationProfile ? 10n : 1n)
  )
    throw new PlatformRecoveryError();
  const scope = structuredClone(root.grantable);
  scope.validFromNs = from.toString();
  scope.validUntilNs = until.toString();
  // The canonical codec validates the entire scope, including uint64 bounds.
  encodeEnvelopeScope(scope);
  return scope;
}

/** Custody may tolerate thirty seconds of installation transport/clock skew.
 * Later ceremonies use these immutable installation timestamps, never a new
 * commit-time clock that would invalidate correctly installed custody. */
export function assertLocalRootExpiryRecoveryInstallationTime(
  enrollment: LocalRootExpiryRecoveryEnrollment,
  installedAt: Date,
  receivingTrustInstalledAt: Date,
) {
  const from = Date.parse(enrollment.successorValidFrom);
  const boundary = Math.max(installedAt.getTime(), receivingTrustInstalledAt.getTime());
  if (!Number.isFinite(from) || !Number.isFinite(boundary) || from < boundary - 30000)
    throw new PlatformRecoveryError();
}
