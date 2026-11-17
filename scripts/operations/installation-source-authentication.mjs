import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';
import {
  InstallationConfigError,
  parseConfigurationJson,
  parseNamedProfile,
} from './installation-config-inputs.mjs';

// Independent receiving trust, NOT a caller-supplied digest or public-key
// signature. The manifest member was read from the delivered ZIP after checking
// its complete bytes against this accepted archive anchor. A historical I05
// manifest constant differs; it is deliberately not a source of authority.
export const operationsSourceAnchor = Object.freeze({
  receiptId: 'OPENPC-C17-FINAL-DELIVERY-20260827-01',
  packageId: 'OPENPC-C17-RECEIVING-AUTHORITY-COHERENCE-20260827-01',
  archiveDigest: 'sha256:36242402f8ace4b1cff124385b0be45e8e2a2c1fed9ceb980be2644052309ed5',
  archiveBytes: 115157004,
  manifestDigest: 'sha256:39800a6f39f3b989f9230844404099d44908c3bfa31d442964c9d947f7885609',
  manifestBytes: 148274,
  schemaPath: 'SPECIFICATIONS/OPERATIONS/configuration.schema.json',
  schemaDigest: 'sha256:350280220fae0d2fb0c360cb1c5a9011e8c46218e7b10b9a269fba78078496cd',
  schemaBytes: 46898,
});

// Exact raw YAML membership comes from the pinned manifest. The canonical
// profile digests additionally let PostgreSQL bind stored JSON to that YAML
// without introducing a second YAML parser or accepting a caller projection.
export const operationsSourceProfiles = Object.freeze(
  Object.fromEntries(
    [
      [
        'local',
        'aad2b9f62d1659cec987be45b5e2e7c8d504a706f8583819675118bef14eaa0c',
        3014,
        'deaa78277144b603295fb75bc2aaf21e8400504aa67680e83981c01822ca2d9a',
      ],
      [
        'development',
        'e20a644061a759c38d2c09d29a74adb43c8cc683da852a33ade726b4ae5f989f',
        3122,
        '50bdcd6777e07c9a6cc688c54bf5d14962fbec68f7ccb2fe94854d7b978e94f5',
      ],
      [
        'test',
        'fc48ee6b68c13821f0fd5b88222629851ad30a21027c69c9cd4a968a301f3c37',
        3121,
        'e7bf9922e9141cd358f28d79b0cbc70e553e0998c296f610e09a3e846a613997',
      ],
      [
        'staging',
        '386955e70c3eb1af05f926fb6385ef523cb96a2b1ac4624f3b8cbbb8a09d252b',
        3026,
        '8c8c997bd3a2292713973595fbdefedfef01c9a38292da366be7caa48d859d95',
      ],
      [
        'production',
        '53bd65338e2e8d1334d4ecb3519769ce32a8e706e683f731a0d27263a9d2902a',
        3134,
        '493d8802e490ce0d088f5c4c119f434a7267c15075dc777e48937c4503649f71',
      ],
    ].map(([profile, hash, bytes, canonical]) => [
      profile,
      Object.freeze({
        path: `SPECIFICATIONS/OPERATIONS/profiles/${profile}.yaml`,
        digest: `sha256:${hash}`,
        bytes,
        canonicalDigest: `sha256:${canonical}`,
      }),
    ]),
  ),
);

/** Fixed receiving authority for the initial public configuration inputs. This
 * provenance authenticates the published inputs; it makes no archive claim. */
export const publicOperationsSourceAnchor = Object.freeze({
  sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
  inventoryDigest: 'sha256:e467be325380375f53f5ae7a91cb56c24c2dbe02c383156aed97ffa8350547e6',
  inventoryBytes: 1189,
  schemaPath: 'config/schema/effective-configuration.schema.json',
  schemaDigest: operationsSourceAnchor.schemaDigest,
  schemaBytes: operationsSourceAnchor.schemaBytes,
});
export const publicOperationsSourceProfiles = Object.freeze(
  Object.fromEntries(
    Object.entries(operationsSourceProfiles).map(([profile, entry]) => [
      profile,
      Object.freeze({ ...entry, path: `config/profiles/${profile}.yaml` }),
    ]),
  ),
);

const legacyReceiptCanonicalDigest =
  'sha256:86b68d4355b2305590c80fb2ab4adeb0f521bc61f63ce635f2e64948475be490';

const fail = () => {
  throw new InstallationConfigError('C17_SOURCE_AUTHENTICATION_FAILED');
};
function bounded(value, max) {
  if (!(value instanceof Uint8Array) || value.length === 0 || value.length > max) fail();
  return Buffer.from(value);
}
function exact(value, keys) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).length !== keys.length ||
    keys.some((key) => !descriptors[key]?.enumerable || !Object.hasOwn(descriptors[key], 'value'))
  )
    fail();
}

/** Pure source authentication only. No archive code is executed, no full archive
 * is rehashed per generation, and no readiness/qualification is manufactured.
 * The caller MUST keep custody private; identity is the only disclosure shape.
 * Custody alone is not an admission token: SQL independently verifies its bytes
 * and binds the real immutable installation and selected generation. */
export function authenticateOperationsSources(input) {
  try {
    if (input && Object.hasOwn(input, 'sourceProfile'))
      return authenticatePublicOperationsSources(input);
    exact(input, ['receiptBytes', 'manifestBytes', 'schemaBytes', 'profileBytes', 'profile']);
    const selected =
      typeof input.profile === 'string' && Object.hasOwn(operationsSourceProfiles, input.profile)
        ? operationsSourceProfiles[input.profile]
        : undefined;
    if (!selected) fail();
    const receiptBytes = bounded(input.receiptBytes, 4096),
      manifestBytes = bounded(input.manifestBytes, operationsSourceAnchor.manifestBytes),
      schemaBytes = bounded(input.schemaBytes, operationsSourceAnchor.schemaBytes),
      profileBytes = bounded(input.profileBytes, 65536);
    if (
      sha256(Buffer.from(canonicalJson(parseConfigurationJson(receiptBytes)))) !==
        legacyReceiptCanonicalDigest ||
      sha256(manifestBytes) !== operationsSourceAnchor.manifestDigest ||
      sha256(schemaBytes) !== operationsSourceAnchor.schemaDigest ||
      schemaBytes.length !== operationsSourceAnchor.schemaBytes ||
      sha256(profileBytes) !== selected.digest ||
      profileBytes.length !== selected.bytes
    )
      fail();
    const manifest = parseConfigurationJson(manifestBytes, operationsSourceAnchor.manifestBytes);
    if (manifest.packageId !== operationsSourceAnchor.packageId || !Array.isArray(manifest.files))
      fail();
    // Verify all five profile mappings, not a caller-chosen path or prefix.
    for (const expected of [
      {
        path: operationsSourceAnchor.schemaPath,
        digest: operationsSourceAnchor.schemaDigest,
        bytes: operationsSourceAnchor.schemaBytes,
      },
      ...Object.values(operationsSourceProfiles),
    ]) {
      const entries = manifest.files.filter((entry) => entry.path === expected.path);
      if (
        entries.length !== 1 ||
        entries[0].class !== 'NORMATIVE_MACHINE_CONTRACT' ||
        entries[0].sha256 !== expected.digest.slice(7) ||
        entries[0].bytes !== expected.bytes
      )
        fail();
    }
    const profile = parseNamedProfile(profileBytes),
      schema = parseConfigurationJson(schemaBytes);
    if (
      profile.profile !== input.profile ||
      schema.$id !== 'urn:openpc:schema:effective-configuration:1.0' ||
      sha256(Buffer.from(canonicalJson(profile))) !== selected.canonicalDigest
    )
      fail();
    return Object.freeze({
      identity: Object.freeze({
        receiptId: operationsSourceAnchor.receiptId,
        archiveDigest: operationsSourceAnchor.archiveDigest,
        manifestDigest: operationsSourceAnchor.manifestDigest,
        profile: input.profile,
        configurationSchemaDigest: operationsSourceAnchor.schemaDigest,
        namedProfileDigest: selected.digest,
      }),
      custody: Object.freeze({
        version: 1,
        receiptId: operationsSourceAnchor.receiptId,
        archiveDigest: operationsSourceAnchor.archiveDigest,
        manifestHex: manifestBytes.toString('hex'),
        schemaHex: schemaBytes.toString('hex'),
        profileHex: profileBytes.toString('hex'),
      }),
    });
  } catch {
    fail();
  }
}

/** Explicit public source selection. Unknown/mixed profiles fail without a
 * fallback to another trust source. Caller-provided anchors are never accepted. */
function authenticatePublicOperationsSources(input) {
  exact(input, ['sourceProfile', 'inventoryBytes', 'schemaBytes', 'profileBytes', 'profile']);
  if (input.sourceProfile !== publicOperationsSourceAnchor.sourceProfile) fail();
  const selected =
    typeof input.profile === 'string' &&
    Object.hasOwn(publicOperationsSourceProfiles, input.profile)
      ? publicOperationsSourceProfiles[input.profile]
      : undefined;
  if (!selected) fail();
  const inventoryBytes = bounded(input.inventoryBytes, publicOperationsSourceAnchor.inventoryBytes);
  const schemaBytes = bounded(input.schemaBytes, publicOperationsSourceAnchor.schemaBytes);
  const profileBytes = bounded(input.profileBytes, selected.bytes);
  if (
    inventoryBytes.length !== publicOperationsSourceAnchor.inventoryBytes ||
    sha256(inventoryBytes) !== publicOperationsSourceAnchor.inventoryDigest ||
    schemaBytes.length !== publicOperationsSourceAnchor.schemaBytes ||
    sha256(schemaBytes) !== publicOperationsSourceAnchor.schemaDigest ||
    profileBytes.length !== selected.bytes ||
    sha256(profileBytes) !== selected.digest
  )
    fail();
  const inventory = parseConfigurationJson(
    inventoryBytes,
    publicOperationsSourceAnchor.inventoryBytes,
  );
  exact(inventory, ['schema', 'schemaVersion', 'sourceProfile', 'files']);
  if (
    inventory.schema !== 'pc.operations.public-source-inventory' ||
    inventory.schemaVersion !== 1 ||
    inventory.sourceProfile !== publicOperationsSourceAnchor.sourceProfile ||
    !Array.isArray(inventory.files) ||
    inventory.files.length !== 6
  )
    fail();
  const members = [
    {
      path: publicOperationsSourceAnchor.schemaPath,
      digest: publicOperationsSourceAnchor.schemaDigest,
      bytes: publicOperationsSourceAnchor.schemaBytes,
    },
    ...Object.values(publicOperationsSourceProfiles),
  ];
  for (const expected of members) {
    const matches = inventory.files.filter((entry) => entry.path === expected.path);
    if (matches.length !== 1) fail();
    exact(matches[0], ['path', 'digest', 'bytes']);
    if (matches[0].digest !== expected.digest || matches[0].bytes !== expected.bytes) fail();
  }
  const profile = parseNamedProfile(profileBytes),
    schema = parseConfigurationJson(schemaBytes);
  if (
    profile.profile !== input.profile ||
    schema.$id !== 'urn:openpc:schema:effective-configuration:1.0' ||
    sha256(Buffer.from(canonicalJson(profile))) !== selected.canonicalDigest
  )
    fail();
  return Object.freeze({
    identity: Object.freeze({
      sourceProfile: publicOperationsSourceAnchor.sourceProfile,
      inventoryDigest: publicOperationsSourceAnchor.inventoryDigest,
      profile: input.profile,
      configurationSchemaDigest: publicOperationsSourceAnchor.schemaDigest,
      namedProfileDigest: selected.digest,
    }),
    custody: Object.freeze({
      version: 2,
      sourceProfile: publicOperationsSourceAnchor.sourceProfile,
      inventoryHex: inventoryBytes.toString('hex'),
      schemaHex: schemaBytes.toString('hex'),
      profileHex: profileBytes.toString('hex'),
    }),
  });
}
