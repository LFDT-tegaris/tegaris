import { createHash, generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  compilePolicyArtifact,
  createPolicyArtifactCompilerSigner,
} from './policy-artifact-compiler.js';
import {
  authenticatePolicyDeploymentSource,
  type StoredPolicyDeploymentSource,
} from './policy-deployment-source.js';
import { loadPolicyDeploymentSource } from '../db/policy-deployment-source.js';
import { policyDeploymentSourceReference } from '../policy-deployment-source-contract.js';

const id = (value: number) => '01990000-0000-7000-8000-' + String(value).padStart(12, '0');
const scope = { participantId: id(1), privacyDomainId: id(2) };
const reference = {
  policyId: id(3),
  policyVersionId: id(4),
  policyArtifactId: id(5),
  releaseBundleId: id(6),
  retiredGenerationId: id(7),
};
function fixture() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signer = createPolicyArtifactCompilerSigner(
    pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  );
  const digest = 'sha256:' + '11'.repeat(32);
  const artifact = compilePolicyArtifact(
    {
      ...scope,
      policyId: reference.policyId,
      semanticVersion: '1.0.0',
      semanticDocument: {
        schemaVersion: '1.0.0',
        ...scope,
        moduleBindings: [
          'pc.policy.rpc-surface',
          'pc.policy.contract-method',
          'pc.policy.argument-guard',
        ].map((moduleId) => ({
          moduleId,
          semanticVersion: '1.0.0',
          manifestDigest: digest,
          configurationDigest: digest,
        })),
        rpcPolicies: [
          {
            schemaVersion: '1.0.0',
            ...scope,
            rules: [{ method: 'eth_call', effect: 'DENY', requiredRoles: ['reader'] }],
          },
        ],
        contractPolicies: [{ contractMethodPolicyId: id(8), revision: '1' }],
        requiredFacts: [],
      },
    },
    signer,
  );
  const semanticDigest = createHash('sha256').update(artifact.semanticCbor).digest();
  const payloadDigest = createHash('sha256').update(artifact.payloadCbor).digest();
  const row: StoredPolicyDeploymentSource = {
    ...scope,
    ...reference,
    semanticVersion: '1.0.0',
    versionState: 'IMMUTABLE_VERSION',
    versionSemanticCbor: Buffer.from(artifact.semanticCbor),
    versionSchemaDigest: Buffer.from(artifact.policySchemaDigest),
    versionSemanticDigest: Buffer.from(semanticDigest),
    versionCoseSign1: Buffer.from(artifact.coseSign1),
    semanticCbor: Buffer.from(artifact.semanticCbor),
    semanticDigest,
    semanticBytesDigest: Buffer.from(semanticDigest),
    policySchemaDigest: Buffer.from(artifact.policySchemaDigest),
    dependencyClosureDigest: Buffer.from(artifact.dependencyClosureDigest),
    payloadCbor: Buffer.from(artifact.payloadCbor),
    payloadDigest,
    coseSign1: Buffer.from(artifact.coseSign1),
    signerKeyDigest: createHash('sha256').update(signer.publicKeySpkiDer).digest(),
    releaseManifestDigest: Buffer.from(semanticDigest),
    releaseDependencyClosureDigest: Buffer.from(artifact.dependencyClosureDigest),
    releaseRevision: '3',
    releaseState: 'ROLLED_BACK',
    originalGeneration: '2',
    originalGenerationDigest: Buffer.from(semanticDigest),
    generationArtifactDigest: Buffer.from(payloadDigest),
    generationCompilerManifestDigest: Buffer.from(artifact.policySchemaDigest),
    generationDependencyClosureDigest: Buffer.from(artifact.dependencyClosureDigest),
    generationState: 'RETIRED',
    generationActive: false,
  };
  return { row, artifact, trust: [{ publicKeySpkiDer: signer.publicKeySpkiDer }] };
}

it('authenticates original Rust canonical semantics and compiler COSE without creating a version, release or runtime identity', () => {
  const f = fixture(),
    original = Buffer.from(f.row.coseSign1);
  const result = authenticatePolicyDeploymentSource(scope, reference, f.row, f.trust);
  expect(result.view).toMatchObject({
    ...scope,
    ...reference,
    semanticVersion: '1.0.0',
    releaseState: 'ROLLED_BACK',
    generationState: 'RETIRED',
    sourceFormat: 'LEGACY_ARTIFACT_GENERATION_V1',
    authority: 'NONE',
    runtimePermission: 'REQUIRES_FRESH_DEPLOYMENT_AUTHORITY',
  });
  expect(result.artifact).toEqual({
    semanticCbor: f.artifact.semanticCbor,
    payloadCbor: f.artifact.payloadCbor,
    coseSign1: f.artifact.coseSign1,
  });
  result.artifact.coseSign1.fill(0);
  expect(f.row.coseSign1).toEqual(original);
});

it.each([
  'foreign tenant',
  'foreign privacy',
  'different artifact',
  'relabelled version',
  'changed semantic bytes',
  'changed payload',
  'changed signature',
  'untrusted signer',
  'active generation',
  'prepared generation',
  'changed generation digest',
  'changed artifact digest',
  'changed schema digest',
  'changed dependency closure',
  'unpublished release',
] as const)('denies %s source without rewriting historical inputs', (failure) => {
  const f = fixture();
  let currentScope = scope,
    trust = f.trust;
  if (failure === 'foreign tenant') currentScope = { ...scope, participantId: id(90) };
  if (failure === 'foreign privacy') currentScope = { ...scope, privacyDomainId: id(90) };
  if (failure === 'different artifact') f.row.policyArtifactId = id(90);
  if (failure === 'relabelled version') f.row.semanticVersion = '1.0.1';
  if (failure === 'changed semantic bytes') f.row.semanticCbor = Buffer.from('a0', 'hex');
  if (failure === 'changed payload') f.row.payloadCbor = Buffer.from('a0', 'hex');
  if (failure === 'changed signature') {
    f.row.coseSign1 = Buffer.from(f.row.coseSign1);
    f.row.coseSign1[f.row.coseSign1.length - 1]! ^= 1;
    f.row.versionCoseSign1 = Buffer.from(f.row.coseSign1);
  }
  if (failure === 'untrusted signer') trust = [];
  if (failure === 'active generation') f.row.generationActive = true;
  if (failure === 'prepared generation') f.row.generationState = 'PREPARED';
  if (failure === 'changed generation digest') f.row.originalGenerationDigest = Buffer.alloc(32, 9);
  if (failure === 'changed artifact digest') f.row.generationArtifactDigest = Buffer.alloc(32, 9);
  if (failure === 'changed schema digest')
    f.row.generationCompilerManifestDigest = Buffer.alloc(32, 9);
  if (failure === 'changed dependency closure')
    f.row.generationDependencyClosureDigest = Buffer.alloc(32, 9);
  if (failure === 'unpublished release') f.row.releaseState = 'DRAFT';
  expect(() => authenticatePolicyDeploymentSource(currentScope, reference, f.row, trust)).toThrow(
    'PC-POLICY-2003',
  );
});

it('rejects caller-supplied provenance or a replacement semantic label before a database read', async () => {
  const f = fixture(),
    query = vi.fn();
  expect(
    policyDeploymentSourceReference.safeParse({ ...reference, semanticVersion: '1.0.1' }).success,
  ).toBe(false);
  await expect(
    loadPolicyDeploymentSource(
      { query } as unknown as PoolClient,
      scope,
      { ...reference, semanticDigest: 'sha256:' + '11'.repeat(32) } as typeof reference,
      f.trust,
    ),
  ).rejects.toThrow('PC-POLICY-2000');
  expect(query).not.toHaveBeenCalled();
});

it('reads the exact original scoped database source and rejects absent or ambiguous joins', async () => {
  const f = fixture();
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [f.row] });
  const result = await loadPolicyDeploymentSource(
    { query } as unknown as PoolClient,
    scope,
    reference,
    f.trust,
  );
  expect(result.view.retiredGenerationId).toBe(reference.retiredGenerationId);
  expect(query.mock.calls[0]![1]).toEqual([
    scope.participantId,
    scope.privacyDomainId,
    reference.policyId,
    reference.policyVersionId,
    reference.policyArtifactId,
    reference.releaseBundleId,
    reference.retiredGenerationId,
  ]);
  for (const rows of [[], [f.row, f.row]]) {
    query.mockResolvedValueOnce({ rowCount: rows.length, rows });
    await expect(
      loadPolicyDeploymentSource({ query } as unknown as PoolClient, scope, reference, f.trust),
    ).rejects.toThrow('PC-POLICY-2001');
  }
});
