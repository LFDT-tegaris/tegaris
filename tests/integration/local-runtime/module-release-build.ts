/** Local release-pipeline fixture over the executable in the verified policy-service image. */
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { chmod, copyFile, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { canonicalJson, sha256 } from '../../../services/module-registry/src/domain/digest.js';
import {
  moduleReleaseCoseContext,
  moduleReleasePayload,
} from '../../../services/module-registry/src/domain/module-release.js';

const [rootValue, keyPath, artifactPath, sourceImageId, additionalModuleId, inheritedRoot] =
  process.argv.slice(2);
if (!rootValue || !keyPath || !artifactPath || !/^sha256:[0-9a-f]{64}$/u.test(sourceImageId ?? ''))
  throw new Error('verified module release build inputs missing');
if ((additionalModuleId === undefined) !== (inheritedRoot === undefined))
  throw new Error('extension requires both a module and an existing release catalog');
if (additionalModuleId !== undefined && !/^pc\.[a-z][a-z0-9.-]+$/u.test(additionalModuleId))
  throw new Error('invalid additional module');
const qaTrustLifetimeMs =
  process.env.OPENPC_LOCAL_RUNTIME_QA_FIXTURE === '1'
    ? Number(process.env.OPENPC_QA_AUTHORITY_TTL_MS ?? '86400000')
    : 86400000;
if (
  !Number.isSafeInteger(qaTrustLifetimeMs) ||
  qaTrustLifetimeMs < 3600000 ||
  qaTrustLifetimeMs > 86400000
)
  throw new Error('Unsupported QA module trust lifetime');
const root = resolve(rootValue);
// An extension must fail before copying the executable into an existing owner.
// Non-recursive creation also rejects an existing directory or symlink atomically.
await mkdir(root, { recursive: inheritedRoot === undefined });
// Public immutable bundles must remain readable by the service UID under QA umask 077.
await chmod(root, 0o755);
const privateKey = createPrivateKey(await readFile(keyPath));
const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
const artifact = await readFile(artifactPath);
if (artifact.length < 4 || !artifact.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])))
  throw new Error('compiled ELF artifact required');
await copyFile(artifactPath, resolve(root, 'policy-core-artifact'));
await chmod(resolve(root, 'policy-core-artifact'), 0o444);
const encode = (value: unknown) => Buffer.from(canonicalJson(value));
const tagged = (value: Buffer) => `sha256:${sha256(value)}`;
function length(major: number, value: number): Buffer {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value <= 255) return Buffer.from([(major << 5) | 24, value]);
  const result = Buffer.alloc(3);
  result[0] = (major << 5) | 25;
  result.writeUInt16BE(value, 1);
  return result;
}
const bstr = (value: Buffer) => Buffer.concat([length(2, value.length), value]);
const text = (value: string) =>
  Buffer.concat([length(3, Buffer.byteLength(value)), Buffer.from(value)]);
function cose(payload: Buffer) {
  const protectedHeader = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x26, 0x03]),
    text('application/openpc+cbor'),
    Buffer.from([0x04]),
    bstr(createHash('sha256').update(publicKey).digest()),
    Buffer.from([0x19, 0x03, 0xe9]),
    length(0, moduleReleaseCoseContext.schemaId),
    Buffer.from([0x19, 0x03, 0xea]),
    text(moduleReleaseCoseContext.purpose),
  ]);
  const structure = Buffer.concat([
    Buffer.from([0x84]),
    text('Signature1'),
    bstr(protectedHeader),
    Buffer.from([0x40]),
    bstr(payload),
  ]);
  const signature = sign('sha256', structure, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    bstr(protectedHeader),
    Buffer.from([0xa0]),
    bstr(payload),
    bstr(signature),
  ]);
}
const releases: Record<string, string>[] = [];
const built = new Map<string, string>();
const hosts = new Set<string>();
let compatibility: { manifestSchemaDigest: string; stackLockDigest: string } | undefined;
if (inheritedRoot !== undefined) {
  const inherited = await realpath(inheritedRoot);
  const previous = JSON.parse(await readFile(resolve(inherited, 'catalog.json'), 'utf8')) as {
    schemaVersion: string;
    releases: Record<string, string>[];
  };
  if (previous.schemaVersion !== '1.0.0' || previous.releases.length > 32)
    throw new Error('invalid inherited catalog');
  const copied = new Set<string>();
  for (const release of previous.releases) {
    const retained: Record<string, string> = { manifestDigest: release.manifestDigest! };
    for (const [field, path] of Object.entries(release)) {
      if (field === 'manifestDigest') continue;
      const source = await realpath(resolve(inherited, path));
      if (!source.startsWith(`${inherited}${sep}`))
        throw new Error('inherited release escaped its owner');
      const destination = `inherited/${relative(inherited, source)}`;
      if (!copied.has(source)) {
        await mkdir(dirname(resolve(root, destination)), { recursive: true });
        await copyFile(source, resolve(root, destination));
        copied.add(source);
      }
      retained[field] = destination;
    }
    const bytes = await readFile(resolve(root, retained.manifestBytes!));
    if (tagged(bytes) !== retained.manifestDigest)
      throw new Error('inherited manifest identity changed');
    const manifest = JSON.parse(bytes.toString('utf8'));
    if (built.has(manifest.metadata.id)) throw new Error('duplicate inherited module');
    built.set(manifest.metadata.id, retained.manifestDigest!);
    for (const host of manifest.deployment.r1AdmittedExecutionHostIds) hosts.add(host);
    releases.push(retained);
  }
  if (built.has(additionalModuleId!)) throw new Error('additional module is already inherited');
}
async function build(id: string) {
  if (built.has(id)) return;
  const manifest = JSON.parse(
    await readFile(
      new URL(`../../../policies/modules/generated/manifests/${id}.json`, import.meta.url),
      'utf8',
    ),
  );
  for (const dependency of manifest.dependencies) {
    await build(dependency.moduleId);
    dependency.manifestDigest = built.get(dependency.moduleId);
  }
  compatibility = manifest.compatibility;
  for (const host of manifest.deployment.r1AdmittedExecutionHostIds) hosts.add(host);
  const sbomBytes = encode({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    components: [{ name: 'openpc-policy-compiler', version: '2.0.0' }],
  });
  const provenanceBytes = encode({
    subject: [{ name: id, digest: { sha256: sha256(artifact) } }],
    predicate: {
      buildCommand:
        'cargo build --release -p openpc-policy-compiler --bin openpc-policy-evaluator --locked',
      sourceImageId,
      fixtureAuthority: 'LOCAL_EXTERNAL_RELEASE_PIPELINE_ONLY',
    },
  });
  const sequence = (releases.length + 1).toString(16).padStart(12, '0');
  const receiptId = `urn:openpc:build-receipt:018f0000-0000-7000-8000-${sequence}`;
  manifest.supplyChain = {
    ...manifest.supplyChain,
    releaseEvidenceState: 'RELEASE_CANDIDATE',
    artifactDigest: tagged(artifact),
    sbomDigest: tagged(sbomBytes),
    provenanceDigest: tagged(provenanceBytes),
    buildReceiptId: receiptId,
    signature: tagged(publicKey),
  };
  const buildReceiptBytes = encode({
    receiptId,
    moduleId: id,
    moduleVersion: manifest.metadata.version,
    artifactDigest: tagged(artifact),
    sbomDigest: tagged(sbomBytes),
    provenanceDigest: tagged(provenanceBytes),
    stackLockDigest: manifest.compatibility.stackLockDigest,
    result: 'SUCCEEDED',
  });
  const bundle = {
    manifestBytes: encode(manifest),
    artifactBytes: artifact,
    sbomBytes,
    provenanceBytes,
    buildReceiptBytes,
    configurationBytes: encode({}),
  };
  const payloadCbor = moduleReleasePayload(bundle);
  const outputs = { ...bundle, payloadCbor, coseSign1: cose(payloadCbor) };
  const entry: Record<string, string> = { manifestDigest: tagged(bundle.manifestBytes) };
  for (const [field, value] of Object.entries(outputs)) {
    const filename = field === 'artifactBytes' ? 'policy-core-artifact' : `${id}-${field}`;
    if (field !== 'artifactBytes') {
      await writeFile(resolve(root, filename), value, { mode: 0o444 });
      await chmod(resolve(root, filename), 0o444);
    }
    entry[field] = filename;
  }
  releases.push(entry);
  built.set(id, entry.manifestDigest!);
}
for (const id of additionalModuleId === undefined
  ? [
      'pc.policy.rpc-surface',
      'pc.policy.contract-method',
      'pc.policy.invocation-capability',
      'pc.policy.runtime-guard',
      'pc.policy.argument-guard',
      'pc.policy.deployment',
      'pc.deployment.governance',
      'pc.multi-rpc',
      'pc.transaction.delivery',
      'pc.policy.state-read',
      'pc.policy.ptv',
      'pc.policy.event-visibility',
      'pc.policy.dynamic-event-visibility',
      'pc.policy.dynamic-event-ordering',
      'pc.policy.selective-disclosure',
      'pc.policy.relationship-facts',
      'pc.indexing.dedicated-policy',
    ]
  : [additionalModuleId])
  await build(id);
const manifestSchema = JSON.parse(
  await readFile(
    new URL(
      '../../../policies/modules/generated/module-manifest.compat.schema.json',
      import.meta.url,
    ),
    'utf8',
  ),
);
await writeFile(resolve(root, 'catalog.json'), encode({ schemaVersion: '1.0.0', releases }), {
  mode: 0o444,
});
await writeFile(
  resolve(root, 'trust.json'),
  encode({
    manifestSchema,
    manifestSchemaDigest: compatibility!.manifestSchemaDigest,
    stackLockDigest: compatibility!.stackLockDigest,
    targetProfile: 'local',
    executionHostIds: [...hosts],
    signers: [
      {
        publicKeySpkiDer: publicKey.toString('base64'),
        state: 'ACTIVE',
        validFromMs: Date.now() - 60000,
        validUntilMs: Date.now() + qaTrustLifetimeMs,
      },
    ],
  }),
  { mode: 0o444 },
);

await chmod(resolve(root, 'catalog.json'), 0o444);
await chmod(resolve(root, 'trust.json'), 0o444);
