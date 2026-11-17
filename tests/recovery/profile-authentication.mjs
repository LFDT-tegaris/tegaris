import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonicalize = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
};

const exactKeys = (value, keys, label) => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} has unknown or missing fields`);
  }
};

// Test-profile receipts establish local technical proof only; they are not deployment trust roots.
export function createLocalProfileAuthenticator(definition) {
  const { allowed, registries, stage, receiptAuthority, recovery, collections } =
    structuredClone(definition);
  return async function authenticateProfile({ repositoryRoot, profilePath, expectedPurpose }) {
    const normalized = relative(repositoryRoot, resolve(repositoryRoot, profilePath));
    if (normalized.startsWith('..') || normalized !== profilePath) {
      throw new Error('Profile path escapes or is not canonical');
    }
    const admission = allowed[profilePath];
    if (!admission || admission[0] !== expectedPurpose) {
      throw new Error('Profile path or purpose is not allowlisted');
    }
    const version = admission[1];
    const registryPath = resolve(repositoryRoot, registries[version].path);
    const [registryBytes, profileBytes] = await Promise.all([
      readFile(registryPath),
      readFile(resolve(repositoryRoot, profilePath)),
    ]);
    const registry = JSON.parse(registryBytes);
    exactKeys(
      registry,
      [
        'schemaVersion',
        'profileId',
        'stage',
        'algorithm',
        'publicKeyJwk',
        'receipts',
        'claimCeiling',
      ],
      'profile signature registry',
    );
    if (
      registry.schemaVersion !== '1.0' ||
      registry.profileId !== registries[version].profileId ||
      registry.stage !== stage ||
      registry.algorithm !== 'ES256' ||
      registry.claimCeiling !== 'LOCAL_NON_PRODUCTION_TECHNICAL_PROOF_ONLY'
    ) {
      throw new Error('Profile signature registry authority mismatch');
    }
    const expectedPaths = Object.entries(allowed)
      .filter(([, [, signerVersion]]) => signerVersion === version)
      .map(([path]) => path)
      .sort();
    if (
      !Array.isArray(registry.receipts) ||
      JSON.stringify(registry.receipts.map(({ path }) => path).sort()) !==
        JSON.stringify(expectedPaths)
    ) {
      throw new Error('Profile signature registry allowlist mismatch');
    }
    const receipt = registry.receipts.find(({ path }) => path === profilePath);
    if (!receipt) throw new Error('Profile is not allowlisted');
    exactKeys(
      receipt,
      ['path', 'sha256', 'stage', 'purpose', 'authority', 'claimCeiling', 'signatureBase64'],
      'profile receipt',
    );
    if (
      receipt.stage !== stage ||
      receipt.purpose !== expectedPurpose ||
      receipt.authority !== receiptAuthority ||
      receipt.claimCeiling !== 'LOCAL_NON_PRODUCTION_TECHNICAL_PROOF_ONLY' ||
      receipt.sha256 !== sha256(profileBytes)
    ) {
      throw new Error('Profile receipt identity, purpose, or digest mismatch');
    }
    const signed = { ...receipt };
    delete signed.signatureBase64;
    const accepted = verify(
      'sha256',
      Buffer.from(canonicalize(signed)),
      createPublicKey({ key: registry.publicKeyJwk, format: 'jwk' }),
      Buffer.from(receipt.signatureBase64, 'base64'),
    );
    if (!accepted) throw new Error('Profile signature is invalid');
    const profile = JSON.parse(profileBytes);
    if (expectedPurpose === recovery.purpose) {
      const valkey = profile.stores?.filter(({ id }) => id === 'valkey-optional');
      if (
        profile.profileId !== recovery.profiles[version].profileId ||
        valkey?.length !== 1 ||
        valkey[0].mechanism !== recovery.profiles[version].mechanism ||
        valkey[0].authority !== 'NON_AUTHORITATIVE_DISABLED_BY_DEFAULT'
      ) {
        throw new Error('Recovery profile version or Valkey mechanism mismatch');
      }
    }
    const requiredCollections = collections[expectedPurpose];
    if (!requiredCollections) throw new Error('Unknown profile purpose');
    for (const field of requiredCollections) {
      const values = profile[field];
      if (
        !Array.isArray(values) ||
        values.length === 0 ||
        new Set(values.map(canonicalize)).size !== values.length
      ) {
        throw new Error(`Profile ${field} collection is empty or duplicated`);
      }
    }
    return { profile, receipt, registrySha256: sha256(registryBytes) };
  };
}

export { canonicalize, sha256 };
