import { readFile, realpath } from 'node:fs/promises';
import { dirname, resolve, sep } from 'node:path';
import { z } from 'zod';

import { createModuleReleaseVerifier, type ModuleReleaseBundle } from './domain/module-release.js';
import type { ModuleReleaseCatalog } from './public-module-http.js';
import { moduleIds } from './generated/contracts.js';
import { ContractError } from './domain/errors.js';
import { sha256 } from './domain/digest.js';

/** Deployment publisher binding for the exact verified release. This is an
 * input to UI signature verification, never UI admission or user authority.
 * A UI manifest must bind moduleDigest to manifestDigest and publisherKeyId to
 * publisherKeyId below, then verify its FINAL semantic payload with this key.
 * Call for each admission; never resolve by module name/version or accept a
 * browser-supplied key. Active installation/configuration remains a separate
 * current database fence, and compile-time UI bundles need their own binding.
 */
export interface ModuleReleasePublisherBinding {
  readonly manifestDigest: string;
  readonly artifactDigest: string;
  readonly moduleName: string;
  readonly moduleVersion: string;
  readonly publisherKeyId: string;
  readonly publisherPublicKeySpkiDer: Buffer;
  readonly validUntilMs: number;
}
export interface DeploymentModuleReleaseCatalog extends ModuleReleaseCatalog {
  lookupPublisherBinding(
    manifestDigest: string,
  ): Promise<ModuleReleasePublisherBinding | undefined>;
}

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const path = z.string().min(1).max(1024);
const release = z.strictObject({
  manifestDigest: digest,
  manifestBytes: path,
  artifactBytes: path,
  sbomBytes: path,
  provenanceBytes: path,
  buildReceiptBytes: path,
  configurationBytes: path,
  payloadCbor: path,
  coseSign1: path,
});
const catalogSchema = z.strictObject({
  schemaVersion: z.literal('1.0.0'),
  releases: z.array(release).max(33),
});
const trustSchema = z.strictObject({
  manifestSchema: z.record(z.string(), z.unknown()),
  manifestSchemaDigest: digest,
  stackLockDigest: digest,
  targetProfile: z.enum(['local', 'development', 'test', 'staging', 'production']),
  executionHostIds: z.array(z.string().min(1)).min(1).max(33),
  signers: z
    .array(
      z.strictObject({
        publicKeySpkiDer: z.string().min(1).max(2048),
        state: z.enum(['ACTIVE', 'REVOKED']),
        validFromMs: z.number().int().nonnegative(),
        validUntilMs: z.number().int().positive(),
      }),
    )
    .min(1)
    .max(32),
});

/** Deployment-owned, immutable artifact catalog; no request may supply paths or signing trust. */
export async function loadModuleReleaseCatalog(
  catalogPath: string,
  trustPath: string,
): Promise<DeploymentModuleReleaseCatalog> {
  const catalog = catalogSchema.parse(JSON.parse(await readFile(catalogPath, 'utf8')));
  const trust = trustSchema.parse(JSON.parse(await readFile(trustPath, 'utf8')));
  if (
    new Set(catalog.releases.map((item) => item.manifestDigest)).size !== catalog.releases.length
  ) {
    throw new ContractError('PC-MODULE-7009');
  }
  const root = await realpath(dirname(catalogPath));
  const verify = createModuleReleaseVerifier({
    ...trust,
    moduleIds,
    capabilityIds: moduleIds.map((id) => `urn:openpc:module-capability:${id.replaceAll('.', '-')}`),
    signers: trust.signers.map((signer) => ({
      ...signer,
      publicKeySpkiDer: Buffer.from(signer.publicKeySpkiDer, 'base64'),
    })),
  });
  const catalogOwner: DeploymentModuleReleaseCatalog = {
    verify,
    async lookup(manifestDigest) {
      const entry = catalog.releases.find((item) => item.manifestDigest === manifestDigest);
      if (entry === undefined) return undefined;
      const loaded = await Promise.all(
        Object.entries(entry)
          .filter(([field]) => field !== 'manifestDigest')
          .map(async ([field, pathValue]) => {
            const actualPath = await realpath(resolve(root, pathValue));
            if (!actualPath.startsWith(`${root}${sep}`)) throw new ContractError('PC-MODULE-7008');
            return [field, await readFile(actualPath)] as const;
          }),
      );
      const bundle = Object.fromEntries(loaded) as unknown as ModuleReleaseBundle;
      const admitted = verify(bundle, Date.now());
      if (`sha256:${admitted.manifestDigest.toString('hex')}` !== manifestDigest)
        throw new ContractError('PC-MODULE-7008');
      return bundle;
    },
    async lookupPublisherBinding(manifestDigest) {
      const bundle = await catalogOwner.lookup(manifestDigest);
      if (!bundle) return undefined;
      const now = Date.now();
      const admitted = verify(bundle, now);
      const publisherKeyId = `sha256:${admitted.signerKeyDigest.toString('hex')}`;
      const signer = trust.signers.find(
        (candidate) =>
          candidate.state === 'ACTIVE' &&
          candidate.validFromMs <= now &&
          now < candidate.validUntilMs &&
          `sha256:${sha256(Buffer.from(candidate.publicKeySpkiDer, 'base64'))}` === publisherKeyId,
      );
      if (!signer) throw new ContractError('PC-MODULE-7008');
      return Object.freeze({
        manifestDigest,
        artifactDigest: `sha256:${admitted.artifactDigest.toString('hex')}`,
        moduleName: admitted.manifest.metadata.id,
        moduleVersion: admitted.manifest.metadata.version,
        publisherKeyId,
        publisherPublicKeySpkiDer: Buffer.from(signer.publicKeySpkiDer, 'base64'),
        validUntilMs: signer.validUntilMs,
      });
    },
  };
  return catalogOwner;
}
