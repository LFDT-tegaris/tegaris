import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadModuleReleaseCatalog } from '../../../services/module-registry/src/module-release-catalog.js';
import {
  assertModuleUiReleaseSignature,
  moduleUiCoseContext,
  moduleUiRegisteredSchemaDigest,
  moduleUiSemanticPayload,
} from '../../../services/module-registry/src/domain/module-ui-signing.js';

import {
  canonicalJson,
  pcCbor1,
  sha256,
} from '../../../services/module-registry/src/domain/digest.js';
import {
  createModuleReleaseVerifier,
  moduleReleaseCoseContext,
  moduleReleaseSchemaDigest,
  moduleReleasePayload,
  type ModuleReleaseBundle,
  type ModuleReleaseTrust,
} from '../../../services/module-registry/src/domain/module-release.js';

const manifestSchema = JSON.parse(
  readFileSync(
    new URL(
      '../../../policies/modules/generated/module-manifest.compat.schema.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as object;
const specification = JSON.parse(
  readFileSync(
    new URL(
      '../../../policies/modules/generated/manifests/pc.foundation.kernel.json',
      import.meta.url,
    ),
    'utf8',
  ),
);
const bytes = (value: unknown) => Buffer.from(canonicalJson(value));
const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const publicKey = key.publicKey.export({ format: 'der', type: 'spki' });

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
function signedPayload(payloadCbor: Buffer, context = moduleReleaseCoseContext): Buffer {
  const protectedHeader = Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x26, 0x03]),
    text('application/openpc+cbor'),
    Buffer.from([0x04]),
    bstr(createHash('sha256').update(publicKey).digest()),
    Buffer.from([0x19, 0x03, 0xe9]),
    length(0, context.schemaId),
    Buffer.from([0x19, 0x03, 0xea]),
    text(context.purpose),
  ]);
  const structure = Buffer.concat([
    Buffer.from([0x84]),
    text('Signature1'),
    bstr(protectedHeader),
    Buffer.from([0x40]),
    bstr(payloadCbor),
  ]);
  const signature = sign('sha256', structure, { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
  return Buffer.concat([
    Buffer.from([0xd2, 0x84]),
    bstr(protectedHeader),
    Buffer.from([0xa0]),
    bstr(payloadCbor),
    bstr(signature),
  ]);
}
function signed(
  bundle: Omit<ModuleReleaseBundle, 'payloadCbor' | 'coseSign1'>,
): ModuleReleaseBundle {
  const payloadCbor = moduleReleasePayload(bundle);
  return { ...bundle, payloadCbor, coseSign1: signedPayload(payloadCbor) };
}

function release(source = specification) {
  const artifactBytes = Buffer.from('external local release pipeline artifact');
  const sbomBytes = bytes({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [] });
  const provenanceBytes = bytes({
    subject: `sha256:${sha256(artifactBytes)}`,
    builder: 'local-release-test',
  });
  const manifest = structuredClone(source);
  manifest.supplyChain = {
    ...manifest.supplyChain,
    releaseEvidenceState: 'RELEASE_CANDIDATE',
    artifactDigest: `sha256:${sha256(artifactBytes)}`,
    sbomDigest: `sha256:${sha256(sbomBytes)}`,
    provenanceDigest: `sha256:${sha256(provenanceBytes)}`,
    buildReceiptId: 'urn:openpc:build-receipt:018f0000-0000-7000-8000-000000000001',
    signature: `sha256:${sha256(publicKey)}`,
  };
  const buildReceiptBytes = bytes({
    receiptId: manifest.supplyChain.buildReceiptId,
    moduleId: manifest.metadata.id,
    moduleVersion: manifest.metadata.version,
    artifactDigest: manifest.supplyChain.artifactDigest,
    sbomDigest: manifest.supplyChain.sbomDigest,
    provenanceDigest: manifest.supplyChain.provenanceDigest,
    stackLockDigest: manifest.compatibility.stackLockDigest,
    result: 'SUCCEEDED',
  });
  return signed({
    manifestBytes: bytes(manifest),
    artifactBytes,
    sbomBytes,
    provenanceBytes,
    buildReceiptBytes,
    configurationBytes: bytes({}),
  });
}
function trust(): ModuleReleaseTrust {
  return {
    manifestSchema,
    manifestSchemaDigest: specification.compatibility.manifestSchemaDigest,
    stackLockDigest: specification.compatibility.stackLockDigest,
    targetProfile: 'local',
    moduleIds: [specification.metadata.id],
    capabilityIds: specification.capabilities.provided.map(
      (item: { capabilityId: string }) => item.capabilityId,
    ),
    executionHostIds: specification.deployment.r1AdmittedExecutionHostIds,
    signers: [
      { publicKeySpkiDer: publicKey, state: 'ACTIVE', validFromMs: 100, validUntilMs: 200 },
    ],
  };
}

describe('trusted module release admission (TS-MOD-MANIFEST, TS-MOD-DEPENDENCY)', () => {
  it('resolves publisher trust only through the exact built release and rejects changed bytes or revoked trust', async () => {
    const temporaryRoot = process.env.OPENPC_TEST_TMP_ROOT;
    expect(temporaryRoot).toBeTruthy();
    const root = await mkdtemp(join(temporaryRoot!, 'module-publisher-'));
    try {
      const bundle = release();
      const manifestDigest = `sha256:${sha256(bundle.manifestBytes)}`;
      const entry: Record<string, string> = { manifestDigest };
      for (const [name, value] of Object.entries(bundle)) {
        entry[name] = name;
        await writeFile(join(root, name), value);
      }
      const configured = trust();
      const installedTrust = {
        manifestSchema: configured.manifestSchema,
        manifestSchemaDigest: configured.manifestSchemaDigest,
        stackLockDigest: configured.stackLockDigest,
        targetProfile: configured.targetProfile,
        executionHostIds: configured.executionHostIds,
        signers: [
          {
            publicKeySpkiDer: publicKey.toString('base64'),
            state: 'ACTIVE',
            validFromMs: Date.now() - 1000,
            validUntilMs: Date.now() + 60000,
          },
        ],
      };
      const catalogPath = join(root, 'catalog.json'),
        trustPath = join(root, 'trust.json');
      await writeFile(catalogPath, JSON.stringify({ schemaVersion: '1.0.0', releases: [entry] }));
      await writeFile(trustPath, JSON.stringify(installedTrust));
      const catalog = await loadModuleReleaseCatalog(catalogPath, trustPath);
      const binding = await catalog.lookupPublisherBinding(manifestDigest);
      expect(binding).toMatchObject({
        manifestDigest,
        artifactDigest: `sha256:${sha256(bundle.artifactBytes)}`,
        moduleName: specification.metadata.id,
        moduleVersion: specification.metadata.version,
        publisherKeyId: `sha256:${sha256(publicKey)}`,
        publisherPublicKeySpkiDer: publicKey,
      });
      // Signature-boundary fixture only. Complete schema/slot certification
      // belongs to the manifest owner; these fields cannot admit a UI module.
      const ui = {
        moduleId: binding!.moduleName,
        moduleVersion: binding!.moduleVersion,
        moduleDigest: binding!.manifestDigest,
        publisherKeyId: binding!.publisherKeyId,
        contributions: [{ contributionId: 'UICONTRIB-BOUND-TEST', priority: 100 }],
        signature: {
          encoding: 'PC-CBOR-1',
          algorithm: 'ES256',
          ...moduleUiCoseContext,
          schemaVersion: '1.0.0',
          schemaDigest: moduleUiRegisteredSchemaDigest,
          coseSign1: '',
        },
      };
      const uiPayload = moduleUiSemanticPayload(ui);
      ui.signature.coseSign1 = signedPayload(uiPayload, moduleUiCoseContext).toString('base64');
      expect(() => assertModuleUiReleaseSignature(ui, binding!)).not.toThrow();
      expect(uiPayload[0]).toBe(0xa5);
      expect(uiPayload.includes(Buffer.from(moduleUiRegisteredSchemaDigest.slice(7), 'hex'))).toBe(
        true,
      );
      for (const changed of [
        { ...ui, publisherKeyId: `sha256:${'0'.repeat(64)}` },
        { ...ui, moduleDigest: `sha256:${sha256(bytes(specification))}` },
        { ...ui, moduleVersion: '9.0.0' },
        { ...ui, contributions: [{ contributionId: 'UICONTRIB-BOUND-TEST', priority: 99 }] },
        { ...ui, signature: { ...ui.signature, schemaDigest: `sha256:${sha256('23001@1.0.0')}` } },
        {
          ...ui,
          signature: { ...ui.signature, coseSign1: signedPayload(uiPayload).toString('base64') },
        },
      ])
        expect(() => assertModuleUiReleaseSignature(changed, binding!)).toThrow('PC-MODULE-7008');
      expect(() => assertModuleUiReleaseSignature(ui, { ...binding!, validUntilMs: 0 })).toThrow(
        'PC-MODULE-7008',
      );
      expect(await catalog.lookupPublisherBinding(specification.metadata.id)).toBeUndefined();
      expect(
        await catalog.lookupPublisherBinding(`sha256:${sha256(bytes(specification))}`),
      ).toBeUndefined();
      binding!.publisherPublicKeySpkiDer.fill(0);
      expect(
        (await catalog.lookupPublisherBinding(manifestDigest))?.publisherPublicKeySpkiDer,
      ).toEqual(publicKey);
      await writeFile(join(root, 'artifactBytes'), Buffer.from('changed actual artifact'));
      await expect(catalog.lookupPublisherBinding(manifestDigest)).rejects.toThrow(
        'PC-MODULE-7008',
      );
      await writeFile(join(root, 'artifactBytes'), bundle.artifactBytes);
      installedTrust.signers[0]!.state = 'REVOKED';
      await writeFile(trustPath, JSON.stringify(installedTrust));
      const revoked = await loadModuleReleaseCatalog(catalogPath, trustPath);
      await expect(revoked.lookupPublisherBinding(manifestDigest)).rejects.toThrow(
        'PC-MODULE-7008',
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it('registers the signed release schema and purpose under its owning identity', () => {
    const registry = JSON.parse(
      readFileSync(
        new URL('../../../schemas/json/schema-identity-registry.json', import.meta.url),
        'utf8',
      ),
    );
    const entries = registry.entries.filter(
      (entry: { schemaId: number }) => entry.schemaId === moduleReleaseCoseContext.schemaId,
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]).toMatchObject({
      purpose: moduleReleaseCoseContext.purpose,
      schemaVersion: '1.0.0',
      schemaDigest: `sha256:${moduleReleaseSchemaDigest}`,
      signed: true,
      ownerLane: 'LANE-CONTROL',
    });
  });
  it('verifies the release, bound supply-chain bytes and inert configuration against admitted inputs', () => {
    const bundle = release();
    const result = createModuleReleaseVerifier(trust())(bundle, 150);
    expect(result.manifest.metadata.id).toBe('pc.foundation.kernel');
    expect(result.configurationCbor).toEqual(pcCbor1({}).bytes);
    expect(result.manifestDigest.toString('hex')).toBe(sha256(bundle.manifestBytes));
    expect(specification.supplyChain.releaseEvidenceState).toBe('SPECIFIED_NOT_BUILT');
    expect(specification.supplyChain.signature).toBeNull();
  });
  it('admits the R1 indexer policy while keeping its future execution host excluded', () => {
    const source = JSON.parse(
      readFileSync(
        new URL(
          '../../../policies/modules/generated/manifests/pc.indexing.dedicated-policy.json',
          import.meta.url,
        ),
        'utf8',
      ),
    );
    expect(source.scope.r1Disposition).toBe('R1_WITH_FUTURE_HOST_EXCLUDED');
    const configured = {
      ...trust(),
      moduleIds: [
        source.metadata.id,
        ...source.dependencies.map((item: { moduleId: string }) => item.moduleId),
      ],
      capabilityIds: [...source.capabilities.provided, ...source.dependencies].map(
        (item: { capabilityId: string }) => item.capabilityId,
      ),
      executionHostIds: [...source.deployment.r1AdmittedExecutionHostIds, 'DU-SUBQUERY'],
    };
    const bundle = release(source);
    const verify = createModuleReleaseVerifier(configured);
    expect(verify(bundle, 150).manifest.deployment.r1AdmittedExecutionHostIds).toEqual([
      'DU-PC-COMPILER',
      'DU-PC-CONTROL',
    ]);
    const manifest = JSON.parse(bundle.manifestBytes.toString());
    manifest.deployment.r1AdmittedExecutionHostIds.push('DU-SUBQUERY');
    expect(() => verify(signed({ ...bundle, manifestBytes: bytes(manifest) }), 150)).toThrow(
      'PC-MODULE-7008',
    );
    manifest.deployment.r1AdmittedExecutionHostIds.pop();
    manifest.scope.r1Disposition = 'FUTURE_CONDITIONAL';
    expect(() => verify(signed({ ...bundle, manifestBytes: bytes(manifest) }), 150)).toThrow(
      'PC-MODULE-7008',
    );
  });
  it('rejects specification-only manifests, unknown fields, duplicate members and lossy numbers', () => {
    const verify = createModuleReleaseVerifier(trust());
    const bundle = release();
    const document = JSON.parse(bundle.manifestBytes.toString());
    for (const manifestBytes of [
      bytes(specification),
      bytes({ ...document, signerState: 'ACTIVE' }),
      Buffer.from(
        bundle.manifestBytes.toString().replace('"kind":', '"kind":"OpenPCModule","kind":'),
      ),
      Buffer.from(
        bundle.manifestBytes.toString().replace('"kind":', '"number":9007199254740993,"kind":'),
      ),
    ])
      expect(() => verify(signed({ ...bundle, manifestBytes }), 150)).toThrow('PC-MODULE-7008');
  });
  it('rejects modified artifact, SBOM, provenance, receipt, configuration or signature', () => {
    const verify = createModuleReleaseVerifier(trust());
    const bundle = release();
    for (const field of [
      'artifactBytes',
      'sbomBytes',
      'provenanceBytes',
      'buildReceiptBytes',
      'configurationBytes',
      'payloadCbor',
      'coseSign1',
    ] as const) {
      expect(() => verify({ ...bundle, [field]: Buffer.from('tampered') }, 150)).toThrow();
    }
  });
  it('rejects correctly signed cross-artifact receipts and unsupported or secret configuration', () => {
    const verify = createModuleReleaseVerifier(trust());
    const bundle = release();
    const build = JSON.parse(bundle.buildReceiptBytes.toString());
    expect(() =>
      verify(
        signed({ ...bundle, buildReceiptBytes: bytes({ ...build, moduleId: 'pc.other' }) }),
        150,
      ),
    ).toThrow('PC-MODULE-7008');
    expect(() =>
      verify(signed({ ...bundle, configurationBytes: bytes({ password: 'unaccepted' }) }), 150),
    ).toThrow('PC-MODULE-7000');
  });
  it('rejects untrusted, revoked, not-yet-valid and expired signer identities', () => {
    const bundle = release();
    const configured = trust();
    for (const now of [99, 200, Number.NaN])
      expect(() => createModuleReleaseVerifier(configured)(bundle, now)).toThrow('PC-MODULE-7008');
    expect(() => createModuleReleaseVerifier({ ...configured, signers: [] })(bundle, 150)).toThrow(
      'PC-MODULE-7008',
    );
    expect(() =>
      createModuleReleaseVerifier({
        ...configured,
        signers: [{ ...configured.signers[0]!, state: 'REVOKED' }],
      })(bundle, 150),
    ).toThrow('PC-MODULE-7008');
  });
  it('rejects unregistered capabilities, changed stack identity and unavailable execution hosts', () => {
    const bundle = release();
    for (const changed of [
      { capabilityIds: [] },
      { stackLockDigest: `sha256:${'0'.repeat(64)}` },
      { executionHostIds: [] },
    ]) {
      expect(() => createModuleReleaseVerifier({ ...trust(), ...changed })(bundle, 150)).toThrow(
        'PC-MODULE-7008',
      );
    }
  });
  it('rejects signed required capabilities without a matching dependency edge', () => {
    const bundle = release();
    const manifest = JSON.parse(bundle.manifestBytes.toString('utf8'));
    manifest.capabilities.required = [{ ...manifest.capabilities.provided[0] }];
    expect(() =>
      createModuleReleaseVerifier(trust())(
        signed({ ...bundle, manifestBytes: bytes(manifest) }),
        150,
      ),
    ).toThrow('PC-MODULE-7008');
  });
});
