import type { EvidenceProvenance } from '../../../services/control-api/src/evidence/provenance-contracts';
import { expect, it } from 'vitest';
import {
  evidenceOperationQuery,
  evidenceOperationView,
  projectEvidenceOperation,
} from './evidence-operation-correlation';

// Shape and identity-join tests; cryptographic and SQL verification remain with
// the real provenance owner, not these fixtures.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = `sha256:${'a'.repeat(64)}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const time = '2026-09-25T00:00:00.123456Z';
const provenance = () => ({
  evidenceId: ref(5),
  participantId: `urn:openpc:participant:${id(3)}`,
  privacyDomainId: id(4),
  evidenceClass: 'BUSINESS_TRANSITION',
  recordId: id(6),
  recordDigest: hash,
  sourceFormat: 'COSE_SIGN1_24001_1_338',
  status: 'VERIFIED_BUSINESS_TRANSITION',
  deployment: null,
  business: {
    authority: 'NONE',
    currentAuthority: 'NOT_ESTABLISHED',
    chainFinality: 'NOT_APPLICABLE',
    integrity: 'VERIFIED_PROFILE_COSE',
    meaning: 'COMMITTED_BUSINESS_TRANSITION',
    providerEffect: 'NOT_ESTABLISHED',
    currentObjectState: 'NOT_QUERIED',
    receiptId: id(6),
    operationId: `urn:openpc:operation:${id(7)}`,
    idempotencyRecordId: id(8),
    profileId: 'pc.control.work-item.claim',
    profileVersion: '1',
    profileDigest: hash,
    actionIntentId: 'ACT-OPERATIONS_UPDATE_CLAIM-V1',
    catalogOperationId: 'CFG-OP-CLAIM-WORK-ITEM',
    aggregateType: 'work-item',
    aggregateId: id(9),
    candidateDigest: hash,
    requestDigest: hash,
    actorKeyDigest: hash,
    authorityDigest: hash,
    signerId: hash,
    signerTrustDigest: hash,
    payloadDigest: hash,
    recordedAt: time,
    before: { existence: 1, revision: '1', stateDigest: hash },
    after: { existence: 1, revision: '2', stateDigest: hash },
    authorizationReferences: [],
    outboxReferences: [],
  },
  custody: {
    streamId: 'test-stream',
    sequence: '1',
    segmentId: id(10),
    checkpoints: [],
    checkpointState: 'NONE_RECORDED',
    archiveAvailability: 'NOT_RECHECKED',
  },
});
const operation = () => ({
  operationId: id(7),
  resourceRef: ref(9),
  actionIntentId: 'ACT-OPERATIONS_UPDATE_CLAIM-V1',
  intentDigest: hash,
  idempotencyKey: 'synthetic-private-key-canary',
  state: 'SUCCEEDED',
  truthState: 'SUCCESS',
  revision: '2',
  createdAt: time,
  updatedAt: time,
});

const query = { evidenceId: ref(5), actorKey: hash };
// Deliberately malformed values probe the projection's identity checks; the BFF
// tests separately exercise the complete server-side provenance parser.
function project(provenanceInput: unknown, operationInput: unknown) {
  return projectEvidenceOperation(query, provenanceInput as EvidenceProvenance, operationInput);
}

it('projects only registered correlation fields and preserves historical/current distinctions', () => {
  const current = {
    ...operation(),
    revision: '9',
    state: 'WRITE_AMBIGUITY',
    truthState: 'WRITE_AMBIGUITY',
  };
  const result = project(provenance(), current);
  expect(result.historicalRevision).toBe('2');
  expect(result.operation).toMatchObject({
    revision: '9',
    state: 'WRITE_AMBIGUITY',
    truthState: 'WRITE_AMBIGUITY',
  });
  expect(Object.keys(result).sort()).toEqual([
    'actorKey',
    'evidenceId',
    'historicalRevision',
    'operation',
    'receiptId',
    'recordDigest',
    'recordedAt',
  ]);
  expect(JSON.stringify(result)).not.toMatch(
    /idempotency|intentDigest|requestDigest|authorityDigest|synthetic-private/u,
  );
});
it.each([
  { operationId: id(99) },
  { resourceRef: ref(99) },
  { resourceRef: null },
  { actionIntentId: 'ACT-OPERATIONS_UPDATE_COMPLETE-V1' },
])('rejects a substituted or missing operation edge: %j', (change) => {
  expect(() => project(provenance(), { ...operation(), ...change })).toThrow();
});
it('rejects unsupported provenance, mismatched record and missing business binding', () => {
  for (const changed of [
    { ...provenance(), evidenceId: ref(99) },
    { ...provenance(), business: null },
    { ...provenance(), status: 'SOURCE_NOT_SUPPORTED', business: null },
    { ...provenance(), business: { ...provenance().business, aggregateId: null } },
  ])
    expect(() => project(changed, operation())).toThrow();
});
it('rejects caller-selected operations and unregistered fields in the strict response', () => {
  expect(evidenceOperationQuery.safeParse({ ...query, operationId: id(7) }).success).toBe(false);
  for (const evidenceId of [
    ref(5) + ' ',
    'urn:openpc:operation:' + id(5),
    '../operations/' + id(7),
  ])
    expect(evidenceOperationQuery.safeParse({ ...query, evidenceId }).success).toBe(false);
  const result = project(provenance(), operation());
  expect(evidenceOperationView.safeParse({ ...result, rawReceipt: 'canary' }).success).toBe(false);
  expect(
    evidenceOperationView.safeParse({
      ...result,
      operation: { ...result.operation, idempotencyKey: 'canary' },
    }).success,
  ).toBe(false);
});
