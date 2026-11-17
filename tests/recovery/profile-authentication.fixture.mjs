import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { canonicalize, sha256 } from './profile-authentication.mjs';

export const definition = {
  allowed: {
    'profiles/recovery-v1.json': ['RECOVERY', 1],
    'profiles/recovery-v2.json': ['RECOVERY', 2],
    'profiles/capacity.json': ['CAPACITY', 1],
    'profiles/supply-chain.json': ['SUPPLY_CHAIN', 1],
  },
  registries: {
    1: { path: 'profiles/signatures-v1.json', profileId: 'TEST-PROFILE-SIGNER-1' },
    2: { path: 'profiles/signatures-v2.json', profileId: 'TEST-PROFILE-SIGNER-2' },
  },
  stage: 'SYNTHETIC_TEST',
  receiptAuthority: 'SYNTHETIC_TEST_FIXTURE',
  recovery: {
    purpose: 'RECOVERY',
    profiles: {
      1: {
        profileId: 'TEST-RECOVERY-V1',
        mechanism: 'RECREATE_EMPTY_WITH_AUTH_NOEVICTION_AND_NO_PERSISTENCE',
      },
      2: {
        profileId: 'TEST-RECOVERY-V2',
        mechanism: 'RECREATE_EMPTY_WITH_AUTH_ALLKEYS_LFU_AND_NO_PERSISTENCE',
      },
    },
  },
  collections: {
    RECOVERY: ['restoreInvariants', 'stores', 'prohibited'],
    CAPACITY: ['resourceEnvelopes', 'workloads'],
    SUPPLY_CHAIN: ['inputs', 'requiredGates'],
  },
};

const claimCeiling = 'LOCAL_NON_PRODUCTION_TECHNICAL_PROOF_ONLY';

function recovery(version) {
  return {
    profileId: definition.recovery.profiles[version].profileId,
    restoreInvariants: ['SINGLE_WRITER', 'PRESERVE_SIGNED_BYTES'],
    stores: [
      { id: 'control', authority: 'SYNTHETIC_TEST_FIXTURE' },
      {
        id: 'valkey-optional',
        mechanism: definition.recovery.profiles[version].mechanism,
        authority: 'NON_AUTHORITATIVE_DISABLED_BY_DEFAULT',
      },
    ],
    prohibited: ['PRODUCTION_DEPLOYMENT', 'CUSTOMER_DATA'],
  };
}

export async function createProfileFixture(root) {
  const profiles = new Map([
    ['profiles/recovery-v1.json', recovery(1)],
    ['profiles/recovery-v2.json', recovery(2)],
    [
      'profiles/capacity.json',
      { resourceEnvelopes: [{ cpu: 1, memoryMiB: 1024 }], workloads: ['FIXTURE_ONLY'] },
    ],
    [
      'profiles/supply-chain.json',
      { inputs: ['LOCAL_FIXTURE_BYTES'], requiredGates: ['SIGNATURE', 'DIGEST'] },
    ],
  ]);
  const registries = new Map();
  const keys = new Map();
  for (const version of [1, 2]) {
    // Keys exist only in this test process and are never written to disk.
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    keys.set(version, privateKey);
    registries.set(version, {
      schemaVersion: '1.0',
      profileId: definition.registries[version].profileId,
      stage: definition.stage,
      algorithm: 'ES256',
      publicKeyJwk: publicKey.export({ format: 'jwk' }),
      receipts: [],
      claimCeiling,
    });
  }
  async function writeRegistry(version, value = registries.get(version)) {
    const path = resolve(root, definition.registries[version].path);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(value)}\n`);
  }
  async function writeProfile(path, value) {
    const [purpose, version] = definition.allowed[path];
    const bytes = Buffer.from(`${JSON.stringify(value)}\n`);
    const receipt = {
      path,
      sha256: sha256(bytes),
      stage: definition.stage,
      purpose,
      authority: definition.receiptAuthority,
      claimCeiling,
    };
    receipt.signatureBase64 = sign(
      'sha256',
      Buffer.from(canonicalize(receipt)),
      keys.get(version),
    ).toString('base64');
    const registry = registries.get(version);
    const index = registry.receipts.findIndex((entry) => entry.path === path);
    if (index < 0) registry.receipts.push(receipt);
    else registry.receipts[index] = receipt;
    await mkdir(dirname(resolve(root, path)), { recursive: true });
    await writeFile(resolve(root, path), bytes);
    await writeRegistry(version);
  }
  for (const [path, profile] of profiles) await writeProfile(path, profile);
  return { profiles, registries, writeRegistry, writeProfile };
}
