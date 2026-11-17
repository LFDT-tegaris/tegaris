import {
  evidenceDeletionBatchSelection,
  evidenceDeletionTarget,
} from './deletion-continuation-contracts.js';
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createEvidenceHold,
  encodeEvidenceHoldSelector,
  evidenceHoldSelector,
} from './hold-contracts.js';
import { retentionDuration } from './retention-contracts.js';
import {
  evidenceDeletionRejections,
  evidenceDeletionRpcRetirements,
  evidenceDeletionSourceCardinality,
  localEvidenceDeletionSelection,
} from './deletion-contracts.js';

describe('SEM-059 exact evidence preservation selector', () => {
  const scope = { participantId: randomUUID(), privacyDomainId: randomUUID() };
  it('binds the tenant, privacy, selector kind, digest and exact u64 range including future matches', () => {
    const input = {
      type: 'SEQUENCE_RANGE' as const,
      streamId: 'real-stream',
      fromSequence: '9007199254740993',
      throughSequence: null,
    };
    const bound = encodeEvidenceHoldSelector(scope, input);
    expect(encodeEvidenceHoldSelector(scope, { ...input })).toEqual(bound);
    for (const other of [
      encodeEvidenceHoldSelector({ ...scope, participantId: randomUUID() }, input),
      encodeEvidenceHoldSelector({ ...scope, privacyDomainId: randomUUID() }, input),
      encodeEvidenceHoldSelector(scope, { ...input, fromSequence: '9007199254740992' }),
      encodeEvidenceHoldSelector(scope, { ...input, throughSequence: '18446744073709551615' }),
      encodeEvidenceHoldSelector(scope, { type: 'PRIVACY_DOMAIN' }),
      encodeEvidenceHoldSelector(scope, {
        type: 'DIGEST',
        recordDigest: `sha256:${'01'.repeat(32)}`,
      }),
    ])
      expect(other.digest).not.toBe(bound.digest);
  });
  it('denies reversed, zero, noncanonical, overflowing, wildcard and caller-supplied scope selectors', () => {
    const range = {
      type: 'SEQUENCE_RANGE',
      streamId: 'test',
      fromSequence: '1',
      throughSequence: null,
    };
    for (const input of [
      { ...range, fromSequence: '0' },
      { ...range, fromSequence: '01' },
      { ...range, fromSequence: '1.5' },
      { ...range, fromSequence: '1e3' },
      { ...range, fromSequence: '' },
      { ...range, throughSequence: 'not-a-number' },
      { ...range, fromSequence: '18446744073709551616' },
      { ...range, fromSequence: '2', throughSequence: '1' },
      { ...range, streamId: '*' },
      { type: 'PRIVACY_DOMAIN', privacyDomainId: randomUUID() },
      { type: 'PARTICIPANT', participantId: randomUUID() },
      { type: 'DIGEST', recordDigest: 'sha256:xyz' },
    ])
      expect(evidenceHoldSelector.safeParse(input).success).toBe(false);
  });
});

it('requires exact ordered rejection proof instead of caller-fabricated no-send readiness', () => {
  const hash = `sha256:${'01'.repeat(32)}`;
  const proof = {
    evidenceId: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000101',
    commandId: '018f0000-0000-7000-8000-000000000102',
    attemptId: '018f0000-0000-7000-8000-000000000103',
    receiptDigest: hash,
    candidateDigest: hash,
    authorizationEvidenceDigest: hash,
    externalAttemptState: 'NOT_STARTED',
    sourceFormat: 'PC-DEPLOYMENT-RESERVATION-REJECTION-1',
  };
  expect(evidenceDeletionRejections.parse([proof])).toEqual([proof]);
  for (const input of [
    [],
    [proof, proof],
    [{ ...proof, externalAttemptState: 'UNKNOWN' }],
    [{ ...proof, sourceFormat: 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1' }],
    [{ ...proof, candidateDigest: undefined }],
    [{ ...proof, noSend: true }],
    [{ ...proof, commandId: '*' }],
    [{ ...proof, privacyDomainId: '018f0000-0000-7000-8000-000000000201' }],
  ])
    expect(evidenceDeletionRejections.safeParse(input).success).toBe(false);
});

it('rejects malformed retention durations without throwing and preserves exact PostgreSQL integers', () => {
  for (const value of [
    '1.5',
    '1e3',
    '',
    'not-a-number',
    '-1',
    '01',
    '9223372036854775808',
    null,
    1,
  ]) {
    expect(retentionDuration.safeParse(value).success, String(value)).toBe(false);
  }
  for (const value of ['0', '1', '9007199254740993', '9223372036854775807']) {
    expect(retentionDuration.parse(value)).toBe(value);
  }
});

it('rejects fabricated deletion readiness, partial objects and malformed exact range inputs before database allocation', () => {
  const resource = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000101';
  const hash = `sha256:${'01'.repeat(32)}`;
  const receipt = {
    sinkId: 'archive-a',
    checkpointDigest: hash,
    receiptDigest: hash,
    acknowledgedAtMicros: '9007199254740993',
  };
  const selection = {
    version: 'OPENPC_LOCAL_EVIDENCE_DELETION_V1',
    evidenceId: resource,
    participantId: resource.replace(':resource:', ':participant:'),
    privacyDomainId: randomUUID(),
    retentionPolicyId: resource,
    policyDigest: hash,
    targetDatabase: 'openpc_control',
    dataClass: 'AUDIT_EVIDENCE',
    deletionMode: 'ROW_DELETE',
    streamId: 'authentication',
    segmentId: randomUUID(),
    firstSequence: '9007199254740993',
    throughSequence: '9007199254740994',
    objectDigest: hash,
    ciphertextBytes: 4096,
    recordCount: 2,
    eligibleAfterMicros: '9223373730000000000000',
    sinkReceipts: [receipt],
    priorCursor: null,
  };
  expect(localEvidenceDeletionSelection.parse(selection)).toEqual(selection);
  const first = { ...selection, segmentId: '00000000-0000-4000-8000-000000000001' };
  const target = {
    evidenceId: first.evidenceId,
    segmentId: first.segmentId,
    firstSequence: first.firstSequence,
    throughSequence: first.throughSequence,
    objectDigest: first.objectDigest,
    ciphertextBytes: first.ciphertextBytes,
    recordCount: first.recordCount,
    beforeDigest: hash,
  };
  const second = {
    ...target,
    evidenceId: resource.replace(/101$/u, '102'),
    segmentId: '00000000-0000-4000-8000-000000000002',
    firstSequence: '9007199254740995',
    throughSequence: '9007199254740996',
  };
  const batch = {
    ...first,
    version: 'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1',
    targets: [target, second],
    batchIndex: 0,
  };
  expect(evidenceDeletionBatchSelection.parse(batch)).toEqual(batch);
  const nextObject = { ...second };
  const continuedTarget = evidenceDeletionTarget.parse(nextObject);
  const continued = {
    ...batch,
    ...Object.fromEntries(
      Object.entries(continuedTarget).filter(([key]) => key !== 'beforeDigest'),
    ),
    batchIndex: 1,
    priorCursor: { deletionJobId: resource, receiptDigest: hash },
  };
  expect(evidenceDeletionBatchSelection.parse(continued)).toEqual(continued);
  for (const change of [
    { targets: [] },
    { targets: [second, target] },
    { targets: [target, target] },
    { targets: [target, { ...second, evidenceId: target.evidenceId }] },
    { targets: [target, { ...second, recordCount: 1 }] },
    { batchIndex: 1 },
    { batchIndex: 16 },
    { priorCursor: { deletionJobId: resource, receiptDigest: hash } },
    { objectDigest: `sha256:${'02'.repeat(32)}` },
    { holdReady: true },
    { sinkReceipts: [receipt, receipt] },
  ])
    expect(evidenceDeletionBatchSelection.safeParse({ ...batch, ...change }).success).toBe(false);
  expect(
    evidenceDeletionBatchSelection.safeParse({ ...continued, priorCursor: null }).success,
  ).toBe(false);
  for (const change of [
    { firstSequence: '1.5' },
    { throughSequence: 'not-a-number' },
    { firstSequence: '0' },
    { firstSequence: '9007199254740995' },
    { recordCount: 1 },
    { recordCount: 129 },
    { ciphertextBytes: 0 },
    { ciphertextBytes: 2097153 },
    { priorCursor: 'invented' },
    { holdReady: true },
    { checkpointCovered: true },
    { dataClass: 'ADMITTED_FACT' },
    { deletionMode: 'CRYPTO_SHRED' },
    { sinkReceipts: [receipt, receipt] },
    { eligibleAfterMicros: '1e3' },
    { eligibleAfterMicros: '-1' },
  ])
    expect(localEvidenceDeletionSelection.safeParse({ ...selection, ...change }).success).toBe(
      false,
    );
});

describe('SEM-059 source selectors and explicit Participant-wide authority', () => {
  const scope = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  };
  const resource = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000301';
  const profile = resource.replace(':resource:', ':fact-profile:');
  const hash = `sha256:${'01'.repeat(32)}`;
  it('requires a distinct Participant action and rejects a privacy grant reused for broader preservation', () => {
    const request = {
      participantId: `urn:openpc:participant:${scope.participantId}`,
      holdKind: 'LEGAL',
      reason: 'Preserve relevant evidence',
      actionIntentDigest: hash,
      actionIntentId: 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
      selector: { type: 'PARTICIPANT' },
    };
    expect(createEvidenceHold.safeParse(request).success).toBe(false);
    expect(
      createEvidenceHold.safeParse({
        ...request,
        actionIntentId: 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
      }).success,
    ).toBe(true);
    expect(
      createEvidenceHold.safeParse({
        ...request,
        actionIntentId: 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
        selector: { type: 'PRIVACY_DOMAIN' },
      }).success,
    ).toBe(false);
  });
  it('separates canonical Fact generations, runtime UUID generations, projections, keys and chain namespaces', () => {
    const selectors = [
      { type: 'PARTICIPANT' },
      { type: 'PRIVACY_DOMAIN' },
      { type: 'PROJECTION', projectionId: resource },
      {
        type: 'FACT_TYPE_KEY',
        factType: 'RELATIONSHIP',
        factProfileId: profile,
        factKeyDigest: null,
      },
      {
        type: 'FACT_TYPE_KEY',
        factType: 'RELATIONSHIP',
        factProfileId: profile,
        factKeyDigest: hash,
      },
      {
        type: 'BLOCK_RANGE',
        chainId: '9007199254740993',
        genesisDigest: hash,
        fromBlock: '0',
        throughBlock: null,
      },
      {
        type: 'BLOCK_RANGE',
        chainId: String(2n ** 256n - 1n),
        genesisDigest: hash,
        fromBlock: '0',
        throughBlock: '18446744073709551615',
      },
      { type: 'GENERATION', generation: { kind: 'RUNTIME_CONFIGURATION', generationId: resource } },
      {
        type: 'GENERATION',
        generation: {
          kind: 'CANONICAL_FACT',
          factProfileId: profile,
          canonicalGeneration: '9007199254740993',
        },
      },
    ].map((selector) => evidenceHoldSelector.parse(selector));
    const digests = selectors.map((selector) => encodeEvidenceHoldSelector(scope, selector).digest);
    expect(new Set(digests).size).toBe(selectors.length);
    for (const selector of selectors) {
      const original = encodeEvidenceHoldSelector(scope, selector);
      expect(
        encodeEvidenceHoldSelector({ ...scope, participantId: randomUUID() }, selector).digest,
      ).not.toBe(original.digest);
      expect(
        encodeEvidenceHoldSelector({ ...scope, privacyDomainId: randomUUID() }, selector).digest,
      ).not.toBe(original.digest);
      expect(evidenceHoldSelector.safeParse({ ...selector, coverage: 'VERIFIED' }).success).toBe(
        false,
      );
    }
  });
  it('rejects ambiguous range/key omissions, namespace substitution, overflow and fabricated source metadata', () => {
    const block = {
      type: 'BLOCK_RANGE',
      chainId: '31337',
      genesisDigest: hash,
      fromBlock: '1',
      throughBlock: null,
    };
    for (const value of [
      { ...block, chainId: '031337' },
      { ...block, chainId: String(2n ** 256n) },
      { ...block, fromBlock: '2', throughBlock: '1' },
      { ...block, fromBlock: '1e3' },
      { ...block, fromBlock: '18446744073709551616' },
      { ...block, throughBlock: undefined },
      { type: 'PROJECTION', projectionId: profile },
      { type: 'FACT_TYPE_KEY', factType: 'RELATIONSHIP', factProfileId: profile },
      {
        type: 'FACT_TYPE_KEY',
        factType: 'RELATIONSHIP',
        factProfileId: resource,
        factKeyDigest: hash,
      },
      {
        type: 'GENERATION',
        generation: {
          kind: 'CANONICAL_FACT',
          factProfileId: profile,
          canonicalGeneration: resource,
        },
      },
      {
        type: 'GENERATION',
        generation: { kind: 'CANONICAL_FACT', factProfileId: profile, canonicalGeneration: '0' },
      },
      { type: 'GENERATION', generation: { kind: 'RUNTIME_CONFIGURATION', generationId: '1' } },
      { type: 'GLOBAL' },
    ])
      expect(evidenceHoldSelector.safeParse(value).success, JSON.stringify(value)).toBe(false);
  });
});

it('binds distinct retired RPC proofs without admitting replay authority or a fabricated rejection', () => {
  const resource = (n: number) =>
    `urn:openpc:resource:018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const hash = `sha256:${'01'.repeat(32)}`;
  const proof = {
    evidenceId: resource(1),
    recordId: `rpc:${'01'.repeat(32)}:17`,
    sourceReceiptDigest: hash,
    retirementJobId: resource(2),
    retirementReceiptDigest: hash,
    retirementDigest: hash,
  };
  const next = {
    ...proof,
    evidenceId: resource(3),
    recordId: proof.recordId.replace(/17$/u, '18'),
  };
  expect(evidenceDeletionRpcRetirements.parse([proof, next])).toEqual([proof, next]);
  for (const input of [
    [],
    [proof, proof],
    [next, proof],
    [{ ...proof, retired: true }],
    [{ ...proof, retirementReceiptDigest: undefined }],
    [{ ...proof, retirementDigest: 'sha256:bad' }],
    [{ ...proof, recordId: 'rpc:invalid:1' }],
    ...['0', '01', '18446744073709551616'].map((sequence) => [
      { ...proof, recordId: `rpc:${'01'.repeat(32)}:${sequence}` },
    ]),
  ])
    expect(evidenceDeletionRpcRetirements.safeParse(input).success).toBe(false);
  expect(
    evidenceDeletionSourceCardinality({ recordCount: 2, sourceRpcRetirements: [proof, next] }),
  ).toBe(true);
  expect(
    evidenceDeletionSourceCardinality({ recordCount: 1, sourceRpcRetirements: [proof, next] }),
  ).toBe(false);
  expect(
    evidenceDeletionSourceCardinality({
      recordCount: 2,
      sourceRpcRetirements: [proof],
      sourceRejections: [proof],
    }),
  ).toBe(false);
});
