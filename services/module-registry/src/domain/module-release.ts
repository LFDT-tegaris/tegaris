import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';

import { verifyBoundCoseSign1Es256 } from '@openpc/security-kernel';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { z } from 'zod';

import { canonicalJson, pcCbor1, sha256 } from './digest.js';
import { ContractError } from './errors.js';

/** Runtime release identity; the archived specification manifest remains immutable. */
export const moduleReleaseCoseContext = Object.freeze({
  purpose: 'openpc:module-release:v1',
  schemaId: 22601,
});

export const moduleReleaseSchemaPreimage =
  'ModuleReleaseV1|schemaId:uint|schemaVersion:text|schemaDigest:sha256|purpose:text|manifestDigest:sha256|artifactDigest:sha256|sbomDigest:sha256|provenanceDigest:sha256|buildReceiptDigest:sha256|configurationDigest:sha256';
export const moduleReleaseSchemaDigest = createHash('sha256')
  .update(moduleReleaseSchemaPreimage)
  .digest('hex');

export interface ModuleReleaseBundle {
  readonly manifestBytes: Buffer;
  readonly artifactBytes: Buffer;
  readonly sbomBytes: Buffer;
  readonly provenanceBytes: Buffer;
  readonly buildReceiptBytes: Buffer;
  readonly configurationBytes: Buffer;
  readonly payloadCbor: Buffer;
  readonly coseSign1: Buffer;
}

export interface ModuleReleaseSigner {
  readonly publicKeySpkiDer: Buffer;
  readonly state: 'ACTIVE' | 'REVOKED';
  readonly validFromMs: number;
  readonly validUntilMs: number;
}

export interface ModuleReleaseTrust {
  readonly manifestSchema: object;
  readonly manifestSchemaDigest: string;
  readonly stackLockDigest: string;
  readonly targetProfile: string;
  readonly moduleIds: readonly string[];
  readonly capabilityIds: readonly string[];
  readonly executionHostIds: readonly string[];
  readonly signers: readonly ModuleReleaseSigner[];
}

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const receipt = z.strictObject({
  receiptId: z.string().regex(/^urn:openpc:build-receipt:[0-9a-f-]{36}$/u),
  moduleId: z.string(),
  moduleVersion: z.string(),
  artifactDigest: digest,
  sbomDigest: digest,
  provenanceDigest: digest,
  stackLockDigest: digest,
  result: z.literal('SUCCEEDED'),
});

interface Manifest {
  readonly metadata: {
    readonly id: string;
    readonly version: string;
    readonly displayName: string;
  };
  readonly compatibility: {
    readonly stackLockDigest: string;
    readonly manifestSchemaDigest: string;
  };
  readonly scope: { readonly r1Disposition: string };
  readonly certification: { readonly targetProfiles: readonly string[] };
  readonly deployment: {
    readonly r1AdmittedExecutionHostIds: readonly string[];
    readonly futureOnlyExecutionHostIds: readonly string[];
  };
  readonly capabilities: {
    readonly required: readonly {
      readonly capabilityId: string;
      readonly providerModuleId: string;
      readonly version: string;
    }[];
    readonly provided: readonly {
      readonly capabilityId: string;
      readonly providerModuleId: string;
    }[];
  };
  readonly dependencies: readonly {
    readonly edgeId: string;
    readonly moduleId: string;
    readonly providerModuleId: string;
    readonly capabilityId: string;
    readonly version: string;
    readonly manifestDigest: string;
  }[];
  readonly conflicts: { readonly moduleIds: readonly string[] };
  readonly configuration: { readonly fields: readonly unknown[] };
  readonly supplyChain: {
    readonly releaseEvidenceState: string;
    readonly artifactDigest: string;
    readonly sbomDigest: string;
    readonly provenanceDigest: string;
    readonly buildReceiptId: string;
    readonly signature: string;
  };
}

export interface VerifiedModuleRelease {
  readonly manifest: Manifest;
  readonly manifestCbor: Buffer;
  readonly manifestDigest: Buffer;
  readonly artifactDigest: Buffer;
  readonly sbomDigest: Buffer;
  readonly provenanceDigest: Buffer;
  readonly buildReceiptDigest: Buffer;
  readonly configurationCbor: Buffer;
  readonly configurationDigest: Buffer;
  readonly payloadCbor: Buffer;
  readonly coseSign1: Buffer;
  readonly signerKeyDigest: Buffer;
}

function failure(): never {
  throw new ContractError('PC-MODULE-7008', 'module release verification failed');
}

/** Release JSON has one representation, rejecting duplicate members and lossy numbers. */
function releaseJson(bytes: Buffer): unknown {
  if (bytes.length === 0 || bytes.length > 4 * 1024 * 1024) failure();
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const parsed: unknown = JSON.parse(source);
  if (canonicalJson(parsed) !== source) failure();
  const checkNumbers = (value: unknown): void => {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) failure();
    if (Array.isArray(value)) value.forEach(checkNumbers);
    else if (value !== null && typeof value === 'object')
      Object.values(value).forEach(checkNumbers);
  };
  checkNumbers(parsed);
  return parsed;
}

export function moduleReleasePayload(
  bundle: Omit<ModuleReleaseBundle, 'payloadCbor' | 'coseSign1'>,
) {
  return pcCbor1({
    ...moduleReleaseCoseContext,
    schemaVersion: '1.0.0',
    schemaDigest: moduleReleaseSchemaDigest,
    manifestDigest: sha256(bundle.manifestBytes),
    artifactDigest: sha256(bundle.artifactBytes),
    sbomDigest: sha256(bundle.sbomBytes),
    provenanceDigest: sha256(bundle.provenanceBytes),
    buildReceiptDigest: sha256(bundle.buildReceiptBytes),
    configurationDigest: sha256(bundle.configurationBytes),
  }).bytes;
}

/** Construct only from deployment trust; request bodies never supply this authority. */
export function createModuleReleaseVerifier(trust: ModuleReleaseTrust) {
  const ajv = new Ajv2020({ allErrors: false, strict: true, strictTuples: false });
  const validate = ajv.compile(structuredClone(trust.manifestSchema));
  const accepted = structuredClone({
    ...trust,
    signers: trust.signers.map((signer) => ({ ...signer, publicKeySpkiDer: undefined })),
  });
  const signers = trust.signers.map((signer) => ({
    ...signer,
    publicKeySpkiDer: Buffer.from(signer.publicKeySpkiDer),
  }));
  return (bundle: ModuleReleaseBundle, nowMs: number): VerifiedModuleRelease => {
    try {
      const document = releaseJson(bundle.manifestBytes);
      if (!validate(document)) failure();
      const manifest = document as Manifest;
      const supply = manifest.supplyChain;
      if (
        !Number.isSafeInteger(nowMs) ||
        supply.releaseEvidenceState !== 'RELEASE_CANDIDATE' ||
        !['R1', 'R1_WITH_FUTURE_HOST_EXCLUDED'].includes(manifest.scope.r1Disposition) ||
        !accepted.moduleIds.includes(manifest.metadata.id) ||
        manifest.compatibility.stackLockDigest !== accepted.stackLockDigest ||
        manifest.compatibility.manifestSchemaDigest !== accepted.manifestSchemaDigest ||
        !manifest.certification.targetProfiles.includes(accepted.targetProfile) ||
        manifest.deployment.r1AdmittedExecutionHostIds.some(
          (host) =>
            !accepted.executionHostIds.includes(host) ||
            manifest.deployment.futureOnlyExecutionHostIds.includes(host),
        ) ||
        manifest.capabilities.provided.some(
          (capability) =>
            capability.providerModuleId !== manifest.metadata.id ||
            !accepted.capabilityIds.includes(capability.capabilityId),
        ) ||
        manifest.dependencies.some(
          (dependency) =>
            dependency.moduleId !== dependency.providerModuleId ||
            !accepted.moduleIds.includes(dependency.providerModuleId) ||
            !accepted.capabilityIds.includes(dependency.capabilityId),
        ) ||
        new Set(manifest.dependencies.map((dependency) => dependency.edgeId)).size !==
          manifest.dependencies.length ||
        new Set(manifest.capabilities.provided.map((capability) => capability.capabilityId))
          .size !== manifest.capabilities.provided.length ||
        manifest.capabilities.required.some(
          (required) =>
            !manifest.dependencies.some(
              (dependency) =>
                dependency.capabilityId === required.capabilityId &&
                dependency.providerModuleId === required.providerModuleId &&
                dependency.version === required.version,
            ),
        ) ||
        bundle.artifactBytes.length === 0 ||
        bundle.sbomBytes.length === 0 ||
        bundle.provenanceBytes.length === 0 ||
        supply.artifactDigest !== `sha256:${sha256(bundle.artifactBytes)}` ||
        supply.sbomDigest !== `sha256:${sha256(bundle.sbomBytes)}` ||
        supply.provenanceDigest !== `sha256:${sha256(bundle.provenanceBytes)}`
      )
        failure();
      const build = receipt.parse(releaseJson(bundle.buildReceiptBytes));
      if (
        build.receiptId !== supply.buildReceiptId ||
        build.moduleId !== manifest.metadata.id ||
        build.moduleVersion !== manifest.metadata.version ||
        build.artifactDigest !== supply.artifactDigest ||
        build.sbomDigest !== supply.sbomDigest ||
        build.provenanceDigest !== supply.provenanceDigest ||
        build.stackLockDigest !== accepted.stackLockDigest
      )
        failure();
      // Initial policy modules declare no configuration fields. Other module configuration
      // families remain unavailable until their schema owner is implemented.
      const configuration = releaseJson(bundle.configurationBytes);
      if (manifest.configuration.fields.length !== 0 || canonicalJson(configuration) !== '{}') {
        throw new ContractError('PC-MODULE-7000', 'unsupported module configuration');
      }
      const payload = moduleReleasePayload(bundle);
      if (!payload.equals(bundle.payloadCbor)) failure();
      const signer = signers.find(
        (candidate) =>
          candidate.state === 'ACTIVE' &&
          candidate.validFromMs <= nowMs &&
          nowMs < candidate.validUntilMs &&
          supply.signature === `sha256:${sha256(candidate.publicKeySpkiDer)}` &&
          verifyBoundCoseSign1Es256(
            candidate.publicKeySpkiDer,
            payload,
            bundle.coseSign1,
            moduleReleaseCoseContext,
          ),
      );
      if (signer === undefined) failure();
      const canonical = pcCbor1(document);
      const config = pcCbor1(configuration);
      return {
        manifest,
        manifestCbor: canonical.bytes,
        manifestDigest: createHash('sha256').update(bundle.manifestBytes).digest(),
        artifactDigest: Buffer.from(supply.artifactDigest.slice(7), 'hex'),
        sbomDigest: Buffer.from(supply.sbomDigest.slice(7), 'hex'),
        provenanceDigest: Buffer.from(supply.provenanceDigest.slice(7), 'hex'),
        buildReceiptDigest: Buffer.from(sha256(bundle.buildReceiptBytes), 'hex'),
        configurationCbor: config.bytes,
        configurationDigest: config.digest,
        payloadCbor: Buffer.from(payload),
        coseSign1: Buffer.from(bundle.coseSign1),
        signerKeyDigest: Buffer.from(sha256(signer.publicKeySpkiDer), 'hex'),
      };
    } catch (error) {
      if (error instanceof ContractError) throw error;
      return failure();
    }
  };
}
