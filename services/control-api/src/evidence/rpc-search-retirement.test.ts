import { expect, it } from 'vitest';
import { rpcCatalogueRetirementProof } from './rpc-search-retirement.js';

const id = '018f0000-0000-7000-8000-000000000101';
const digest = `sha256:${'a'.repeat(64)}`;
const original = {
  recordId: id,
  recordDigest: digest,
  recordedAtNs: '1',
  sourceFormat: 'COSE_SIGN1_24001_338',
  deletionJobId: id,
  operationId: id,
  sourceEvidenceId: `urn:openpc:resource:${id}`,
  sourceRecordId: `rpc:${'a'.repeat(64)}:1`,
  sourceReceiptDigest: digest,
  retirementDigest: digest,
};
it('keeps denied and admitted RPC retirement proof identities distinct', () => {
  expect(
    rpcCatalogueRetirementProof.parse({
      ...original,
      sourceKind: 'RPC_PRE_ADMISSION_DENIAL',
      identityDigest: null,
    }).identityDigest,
  ).toBeNull();
  expect(
    rpcCatalogueRetirementProof.parse({
      ...original,
      sourceKind: 'RPC_CLOSED_TRANSITION',
      identityDigest: digest,
    }).identityDigest,
  ).toBe(digest);
  for (const changed of [
    { sourceKind: 'RPC_PRE_ADMISSION_DENIAL', identityDigest: digest },
    { sourceKind: 'RPC_PRE_ADMISSION_DENIAL' },
    { sourceKind: 'RPC_CLOSED_TRANSITION', identityDigest: null },
    { sourceKind: 'RPC_CLOSED_TRANSITION', identityDigest: 'unknown' },
    { sourceKind: 'RPC_RELEASED', identityDigest: digest },
    { identityDigest: digest },
    { sourceKind: 'RPC_PRE_ADMISSION_DENIAL', identityDigest: null, eligible: true },
  ])
    expect(rpcCatalogueRetirementProof.safeParse({ ...original, ...changed }).success).toBe(false);
});
