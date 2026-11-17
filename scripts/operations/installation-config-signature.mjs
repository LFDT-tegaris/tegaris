import { verifyInstalledOperationsSiteDocument } from '../../packages/security-kernel/src/operations-configuration/site-document.ts';
import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';
import {
  invalid,
  parseConfigurationJson,
  parseNamedProfile,
} from './installation-config-inputs.mjs';
import { prepareInstallationCandidate } from './installation-config-validation.mjs';

function boundedCopy(value, maximum) {
  if (!(value instanceof Uint8Array) || value.length === 0 || value.length > maximum)
    invalid('SIGNED_SITE_INPUT_SIZE');
  return Buffer.from(value);
}

/** Authenticates the actual SITE_FILE bytes using independent installation pins.
 * The existing resolver still owns schema/precedence/closed-value validation.
 * Source authentication, qualification, secret resolution and complete generation
 * effectiveness remain separate requirements. This cannot return startup authority.
 * Callers must hold/recheck current issuer and generation fences when admitting
 * the resulting candidate; a saved result is historical input integrity only. */
export function prepareSignedInstallationCandidate(sources, pins, signed, nowMs, options = {}) {
  try {
    const schemaBytes = boundedCopy(sources.schemaBytes, 131072);
    const profileBytes = boundedCopy(sources.profileBytes, 65536);
    const siteBytes = boundedCopy(sources.siteBytes, 131072);
    const payload = boundedCopy(signed.payload, 65536);
    const cose = boundedCopy(signed.cose, 66560);
    const schema = parseConfigurationJson(schemaBytes);
    const namedProfile = parseNamedProfile(profileBytes);
    const site = parseConfigurationJson(siteBytes);
    // Reject parsed-object substitution instead of authenticating unrelated bytes.
    if (
      canonicalJson(schema) !== canonicalJson(sources.schema) ||
      canonicalJson(namedProfile) !== canonicalJson(sources.namedProfile) ||
      canonicalJson(site) !== canonicalJson(sources.site) ||
      sha256(schemaBytes) !== pins.configurationSchemaDigest ||
      sha256(profileBytes) !== pins.namedProfileDigest ||
      sources.profile !== pins.profile
    )
      invalid('SIGNED_SITE_SOURCE_BINDING');
    const candidate = prepareInstallationCandidate(
      { ...sources, schema, namedProfile, site, schemaBytes, profileBytes },
      options,
    );
    if (
      candidate.configuration.environmentId !== pins.environmentId ||
      (site.environmentId !== undefined && site.environmentId !== pins.environmentId)
    )
      invalid('SIGNED_SITE_ENVIRONMENT_BINDING');
    const verified = verifyInstalledOperationsSiteDocument(
      pins,
      {
        generationId: candidate.configuration.generation.generationId,
        baseGenerationId: candidate.configuration.generation.baseGenerationId,
        siteDigest: sha256(site),
        declaredContentDigest: candidate.configuration.generation.contentDigest,
      },
      payload,
      cose,
      nowMs,
    );
    return {
      ...candidate,
      blockers: candidate.blockers.filter((value) => value !== 'SIGNED_SITE_VERIFICATION_UNBOUND'),
      // This projection is deliberately not an effective digest or a capability.
      siteSignature: {
        signedDocumentDigest: verified.signedDocumentDigest,
        siteDigest: verified.siteDigest,
        issuerKeyId: verified.issuerKeyId,
        issuerEpoch: verified.issuerEpoch,
        validFromMs: verified.validFromMs,
        validUntilMs: verified.validUntilMs,
      },
    };
  } catch {
    invalid('SIGNED_SITE_VERIFICATION_FAILED');
  }
}
