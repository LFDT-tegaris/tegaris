import { expect, it } from 'vitest';
import { deploymentLineage, deploymentHoldLineage } from './deployment-lineage.js';
import { sha256 } from '../configuration/digest.js';
import { deploymentProjectionReadbackSchema } from '../configuration/deployment/result-contract.js';
import { deploymentObservation, retainedObservationHistory } from './deployment-provenance.js';
import { recordedCheckpoint } from './provenance.js';
import { canonicalJson } from '../configuration/digest.js';
import { verifyAuthenticationSource } from './authentication-source.js';
import { rpcProvenance } from './rpc-provenance-contract.js';
import { verifyRpcProjection } from './rpc-provenance.js';
import { deploymentProvenanceProjection } from './provenance-contracts.js';

const hash = 'a'.repeat(64),
  digest = `sha256:${hash}`;
const id = '018f0000-0000-7000-8000-000000000101';
it('keeps the removable deployment view separate from live state and protected source bytes', () => {
  const projection = {
    integrity: 'VERIFIED_PURPOSE_SIGNATURE',
    authority: 'OBSERVATION_ONLY',
    operationId: `urn:openpc:operation:${id}`,
    attemptId: id,
    deploymentIntentId: `urn:openpc:resource:${id}`,
    targetRuntimeId: `urn:openpc:resource:${id}`,
    executionPrincipalId: id,
    workloadId: 'test-workload',
    intentDigest: digest,
    preparationDigest: digest,
    chainId: '1',
    genesisDigest: digest,
    transactionHash: `0x${hash}`,
    historical: deploymentObservation(
      verified({ attempt: {}, occurrence: null, invalidation: null }),
    ),
  };
  expect(deploymentProvenanceProjection.parse(projection)).toEqual(projection);
  for (const changed of [
    { signedBytes: 'protected' },
    { latestRetained: projection.historical },
    { currentChainTruth: 'VERIFIED' },
    { authority: 'DEPLOYMENT_AUTHORITY' },
    { historical: { ...projection.historical, rawReceipt: 'protected' } },
  ])
    expect(deploymentProvenanceProjection.safeParse({ ...projection, ...changed }).success).toBe(
      false,
    );
});
it('authenticates canonical Identity occurrence bindings without inventing signed permission', () => {
  const value = {
    version: 'OPENPC_AUTHENTICATION_OCCURRENCE_V1',
    occurrenceId: id,
    participantId: id,
    privacyDomainId: id,
    principalId: id,
    operationId: id,
    sourceId: id,
    credentialDigest: digest,
    proofDigest: digest,
    occurredAt: '2026-09-22T00:00:00.000000Z',
    authorityEffect: 'NONE',
    integrity: 'CONTROL_DATABASE_IMMUTABLE',
    method: 'OIDC_CODE_PKCE_S256',
    contextMode: 'PLATFORM',
    sessionBindingDigest: digest,
  };
  const bytes = Buffer.from(canonicalJson(value));
  const row = { id, receipt: bytes, receiptDigest: Buffer.from(sha256(bytes).slice(7), 'hex') };
  const scope = { participantId: id, privacyDomainId: id };
  expect(verifyAuthenticationSource(row, scope)).toEqual(value);
  for (const mutation of [
    { authorityEffect: 'ALLOW' },
    { integrity: 'VERIFIED_COSE' },
    { version: 'V2' },
    { method: 'TLS13_MTLS' },
    { rawAssertion: 'private' },
    { principalId: 'invalid' },
  ]) {
    const receipt = Buffer.from(canonicalJson({ ...value, ...mutation }));
    expect(() =>
      verifyAuthenticationSource(
        { ...row, receipt, receiptDigest: Buffer.from(sha256(receipt).slice(7), 'hex') },
        scope,
      ),
    ).toThrow();
  }
  expect(() =>
    verifyAuthenticationSource({ ...row, receipt: Buffer.from(JSON.stringify(value)) }, scope),
  ).toThrow();
  expect(() =>
    verifyAuthenticationSource({ ...row, id: id.replace('101', '102') }, scope),
  ).toThrow();
  expect(() =>
    verifyAuthenticationSource(row, { ...scope, privacyDomainId: id.replace('101', '102') }),
  ).toThrow();
  expect(() =>
    verifyAuthenticationSource(row, { ...scope, participantId: id.replace('101', '102') }),
  ).toThrow();
});

it('keeps RPC verified-custody projections exact, minimized and phase-specific', () => {
  const projection = rpcProvenance.parse({
    integrity: 'AEAD_CHAIN_VERIFIED_AT_CUSTODY',
    activationIntegrity: 'ACTIVATION_COSE_VERIFIED_AT_CUSTODY',
    authority: 'NONE',
    currentAuthority: 'NOT_ESTABLISHED',
    providerEffect: 'NOT_ESTABLISHED',
    chainFinality: 'NOT_ESTABLISHED',
    decisionId: id,
    targetRuntimeId: id,
    spoolId: 'rpc',
    sourceSequence: '10',
    sourceDigest: digest,
    capsuleDigest: digest,
    reservedAtNs: '1790035200000000000',
    occurredAtNs: '1790035200000000000',
    transition: {
      phase: 'RESERVED',
      traceId: null,
      requestDigest: digest,
      decisionDigest: null,
      responseDigest: null,
      authorityBindingDigest: null,
      sourceScopeDigest: null,
      operationId: null,
      pcCode: null,
      decisionEffect: null,
      boundary: null,
      sourceSegmentId: 'segment',
      sourceRecordDigest: digest,
      admittedAtNs: '1790035200000000000',
    },
    activation: {
      operationId: id,
      attemptId: id,
      configurationWorkId: id,
      generationId: id,
      generationDigest: digest,
      receiptDigest: digest,
      signerId: 'runtime',
      verificationKeyDigest: digest,
    },
  });
  const record = {
    participantId: id,
    privacyDomainId: id,
    recordId: `rpc:${sha256([id, 'rpc']).slice(7)}:10`,
    recordDigest: digest,
    occurredAt: '2026-09-22T00:00:00.000000Z',
  };
  expect(verifyRpcProjection(record, projection, sha256(projection))).toEqual(projection);
  for (const changed of [
    { ...record, recordId: record.recordId.replace(':10', ':11') },
    { ...record, recordDigest: sha256('other') },
    { ...record, occurredAt: '2026-09-22T00:00:01.000000Z' },
  ])
    expect(() => verifyRpcProjection(changed, projection, sha256(projection))).toThrow();
  for (const mutation of [
    { raw: 'private' },
    { providerEffect: 'SUCCESS' },
    { integrity: 'VERIFIED_SIGNATURE' },
    { transition: { ...projection.transition, phase: 'COMMITTED' } },
    { transition: { ...projection.transition, phase: 'SOURCE_READ_RELEASED' } },
    { transition: { ...projection.transition, phase: 'PRE_ADMISSION_DENIAL' } },
    { transition: { ...projection.transition, responseDigest: digest } },
  ])
    expect(() => rpcProvenance.parse({ ...projection, ...mutation })).toThrow();
  expect(() => verifyRpcProjection(record, projection, sha256('wrong projection'))).toThrow();
});
const verified = (outcome: unknown, state = 'CONFIRMED', truthState = 'SUCCESS') =>
  deploymentProjectionReadbackSchema.parse({
    identity: 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1',
    authority: 'OBSERVATION_ONLY',
    resultDigest: hash,
    sequence: '12',
    observedAt: '2026-09-22T00:00:00Z',
    status: {
      operationId: 'operation',
      signedTransactionHash: `0x${hash}`,
      attemptId: 'attempt',
      evidenceDigest: digest,
      state,
      truthState,
    },
    outcome,
    association: null,
  });
it('keeps finalized historical occurrences separate from exact later invalidation references', () => {
  const old = deploymentObservation(
    verified({
      attempt: {},
      occurrence: {
        occurrenceId: `occurrence:${hash}`,
        semanticDigest: hash,
        blockHash: hash,
        blockNumber: '9007199254740994',
        reorgStatus: 'CANONICAL',
        raw: 'private-raw-field',
      },
      invalidation: null,
    }),
  );
  expect(old.finality).toBe('FINALIZED');
  expect(old.occurrence?.blockNumber).toBe('9007199254740994');
  expect(JSON.stringify(old)).not.toContain('private-raw-field');
  const current = deploymentObservation(
    verified(
      {
        attempt: {},
        occurrence: null,
        invalidation: {
          occurrenceId: `occurrence:${hash}`,
          occurrenceDigest: hash,
          observationDigest: 'b'.repeat(64),
          reason: 'REORG',
        },
      },
      'REORG',
      'REORG',
    ),
  );
  expect(current.finality).toBe('REORG');
  expect(current.invalidation?.occurrenceDigest).toBe(old.occurrence?.occurrenceDigest);
  expect(current.occurrence).toBeNull();
  expect(
    deploymentObservation(
      verified(
        { attempt: {}, occurrence: null, invalidation: null },
        'WRITE_AMBIGUITY',
        'WRITE_AMBIGUITY',
      ),
    ).finality,
  ).toBe('NOT_ESTABLISHED');
});
it('reports coalesced numeric snapshot gaps without claiming complete journal history', () => {
  expect(retainedObservationHistory('2', '12', '3')).toMatchObject({
    missingVersionsBetweenSnapshots: '8',
    journalCompleteness: 'NOT_ESTABLISHED',
  });
  expect(
    retainedObservationHistory('9007199254740992', '9007199254740994', '2')
      .missingVersionsBetweenSnapshots,
  ).toBe('1');
  for (const args of [
    ['0', '1', '1'],
    ['2', '1', '1'],
    ['2', '4', '4'],
    ['1', '18446744073709551616', '1'],
  ])
    expect(() => retainedObservationHistory(args[0]!, args[1]!, args[2]!)).toThrow();
});

it('binds a recorded checkpoint to its exact scoped segment, range, object version and digests', () => {
  const record = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    evidenceId: '018f0000-0000-7000-8000-000000000301',
    segmentId: '018f0000-0000-7000-8000-000000000401',
    streamId: 'effects',
    sequence: '2',
    evidenceClass: 'EFFECT' as const,
    sourceFormat: 'PC-DEPLOYMENT-JOURNAL-PROJECTION-1',
    recordId: 'record',
    recordDigest: digest,
    occurredAt: '2026-09-22T00:00:00.000000Z',
  };
  const object = {
    participantId: record.participantId,
    privacyDomainId: record.privacyDomainId,
    streamId: record.streamId,
    segmentId: record.segmentId,
    sinkId: 'local',
    objectDigest: digest,
    firstSequence: '1',
    throughSequence: '3',
    previousSegmentDigest: null,
    keyId: 'never-public-key-id',
    retentionUntil: record.occurredAt,
  };
  const body = { object, versionId: digest, assurance: 'LOCAL_FSYNC_READBACK' as const };
  const checkpoint = {
    participantId: record.participantId,
    privacyDomainId: record.privacyDomainId,
    streamId: record.streamId,
    segmentId: record.segmentId,
    sinkId: object.sinkId,
    throughSequence: '3',
    objectDigest: digest,
    previousCheckpointDigest: null,
    receiptDigest: sha256(body),
  };
  const row = {
    ...checkpoint,
    checkpointDigest: sha256(checkpoint),
    receipt: { ...body, receiptDigest: sha256(body) },
    acknowledgedAt: record.occurredAt,
  };
  const value = recordedCheckpoint(record, row);
  expect(value.assurance).toBe('LOCAL_FSYNC_READBACK');
  expect(JSON.stringify(value)).not.toContain('never-public-key-id');
  for (const changed of [
    { ...record, participantId: '018f0000-0000-7000-8000-000000000102' },
    { ...record, privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
    { ...record, streamId: 'other' },
    { ...record, sequence: '4' },
  ])
    expect(() => recordedCheckpoint(changed, row)).toThrow();
  for (const changed of [
    { ...row, checkpointDigest: sha256('wrong') },
    { ...row, previousCheckpointDigest: digest },
    { ...row, receipt: { ...row.receipt, versionId: sha256('alias') } },
    { ...row, receipt: { ...row.receipt, assurance: 'REMOTE_WORM' } },
  ])
    expect(() => recordedCheckpoint(record, changed)).toThrow();
});

it('preserves exact deployment anchors without treating invalidation or ambiguity as an empty block set', () => {
  const result = verified({
    attempt: {},
    occurrence: {
      occurrenceId: `occurrence:${hash}`,
      semanticDigest: hash,
      blockHash: hash,
      blockNumber: '18446744073709551615',
      reorgStatus: 'CANONICAL',
      raw: 'private',
    },
    invalidation: null,
  });
  const projection = deploymentLineage(result, {
    chain_id: String(2n ** 256n - 1n),
    genesis_digest: hash,
  });
  expect(projection.historical.occurrence?.blockNumber).toBe('18446744073709551615');
  expect(JSON.stringify(projection)).not.toContain('private');
  expect(projection.chainId).toBe(String(2n ** 256n - 1n));
  for (const changed of [
    { ...projection, chainId: String(2n ** 256n) },
    { ...projection, chainId: '01' },
    { ...projection, ready: true },
    { ...projection, genesisDigest: hash },
  ])
    expect(deploymentHoldLineage.safeParse(changed).success).toBe(false);
  const invalidated = deploymentLineage(
    verified(
      {
        attempt: {},
        occurrence: null,
        invalidation: {
          occurrenceId: `occurrence:${hash}`,
          occurrenceDigest: hash,
          observationDigest: hash,
          reason: 'REORG',
        },
      },
      'REORG',
      'REORG',
    ),
    { chain_id: '31337', genesis_digest: hash },
  );
  expect(invalidated.historical.occurrence).toBeNull();
  expect(invalidated.historical.invalidation?.occurrenceDigest).toBe(
    projection.historical.occurrence?.occurrenceDigest,
  );
});

it('binds minimized canonical Fact provenance to its exact tenant, source cursor and archived receipt', async () => {
  const { factProvenance } = await import('./fact-provenance-contract.js');
  const { verifyFactProjection } = await import('./fact-provenance.js');
  const projection = {
    integrity: 'FACT_COSE_VERIFIED_AT_CUSTODY',
    authority: 'NONE',
    currentReadiness: 'NOT_ESTABLISHED',
    candidateId: id,
    sourceProfileId: id,
    sourceSequence: '1',
    receiptDigest: digest,
    admittedAt: '2026-09-22T00:00:00.000000Z',
    verificationKeyId: digest,
    verificationKeyDigest: digest,
    lineage: {
      factId: `urn:openpc:fact:${id}`,
      factDigest: digest,
      factType: 'CONTRACT_STATE_CALL',
      factProfileId: `urn:openpc:fact-profile:${id}`,
      factKeyDigest: digest,
      canonicalGeneration: '1',
      projectionId: `urn:openpc:resource:${id}`,
      chainId: String(2n ** 256n - 1n),
      genesisDigest: digest,
      blockNumber: '18446744073709551615',
      blockHash: digest,
      predecessorDigest: null,
      relationshipPredecessorDigest: null,
      reorgReplacementOf: null,
    },
  };
  const source = {
    participantId: id,
    privacyDomainId: id,
    sequence: '1',
    recordDigest: digest,
    recordId: `fact:${sha256([id, id, id]).slice(7)}:1`,
    occurredAt: projection.admittedAt,
  };
  expect(verifyFactProjection(source, projection, sha256(projection))).toEqual(projection);
  for (const mutation of [
    { participantId: id.replace(/1$/u, '2') },
    { privacyDomainId: id.replace(/1$/u, '2') },
    { sequence: '2' },
    { recordId: source.recordId + '0' },
    { recordDigest: `sha256:${'b'.repeat(64)}` },
    { occurredAt: '2026-09-22T00:00:01.000000Z' },
  ])
    expect(() =>
      verifyFactProjection({ ...source, ...mutation }, projection, sha256(projection)),
    ).toThrow();
  for (const mutation of [
    { currentReadiness: 'PRESENT' },
    { authority: 'ALLOW' },
    { receiptBase64: 'raw' },
    { lineage: { ...projection.lineage, canonicalGeneration: '0' } },
    { lineage: { ...projection.lineage, chainId: String(2n ** 256n) } },
    { lineage: { ...projection.lineage, rawValue: 'protected' } },
    { lineage: { ...projection.lineage, factKeyDigest: null } },
  ])
    expect(factProvenance.safeParse({ ...projection, ...mutation }).success).toBe(false);

  const { FactRetirementBlocked, verifyFactRetirementBatch } = await import('./fact-retirement.js');
  const bytes = Buffer.from(
    'opaque original receipt; COSE verification belongs to the real Fact owner',
  );
  const expected = factProvenance.parse({ ...projection, receiptDigest: sha256(bytes) });
  const entry = {
    candidateId: expected.candidateId,
    sourceSequence: expected.sourceSequence,
    receiptDigest: expected.receiptDigest,
    admittedAt: expected.admittedAt,
    lineage: expected.lineage,
    receiptBase64: bytes.toString('base64'),
  };
  const batch = {
    identity: 'OPENPC_FACT_EVIDENCE_SOURCE_V1',
    sourceProfileId: id,
    verificationKeyDigest: digest,
    checkpointSequence: '1',
    checkpointState: 'COMPLETE',
    records: [entry],
  };
  const verify = (changed: unknown) =>
    verifyFactRetirementBatch(
      { identity: 'OPENPC-FACT-EVIDENCE-LEASE-1', batch: changed, retirementBlocker: null },
      expected,
      digest,
      digest,
    );
  expect(() => verify(batch)).not.toThrow();
  // Delivery metadata is additive transport identity, never part of the
  // historical signed-source projection or authority to retire it.
  const data = {
    candidateId: `urn:openpc:resource:${id}`,
    factArtifactId: `urn:openpc:resource:${id}`,
    artifactDigest: digest,
    sourceProfileDigest: digest,
    sourceNeutral: true,
  };
  const admissionDelivery = {
    specversion: '1.0',
    id,
    source: 'urn:openpc:service:LS-FACT-BRIDGE',
    type: 'io.openpc.fact.candidate.admitted.v1',
    subject: data.candidateId,
    time: entry.admittedAt,
    datacontenttype: 'application/json',
    dataschema:
      'https://schemas.openpc.local/event-payloads.schema.json#/$defs/FactCandidateAdmitted',
    participantid: `urn:openpc:participant:${id}`,
    privacydomainid: `urn:openpc:privacy-domain:${id}`,
    correlationid: id,
    authoritygeneration: digest,
    sequence: '1',
    datadigest: sha256(data),
    data,
  };
  expect(() => verify({ ...batch, records: [{ ...entry, admissionDelivery }] })).not.toThrow();
  expect(() =>
    verifyFactRetirementBatch(
      {
        identity: 'OPENPC-FACT-EVIDENCE-LEASE-1',
        batch: { ...batch, records: [{ ...entry, admissionDelivery }] },
        retirementBlocker: 'REFERENCES',
      },
      expected,
      digest,
      digest,
    ),
  ).toThrow(FactRetirementBlocked);

  for (const checkpointState of ['GAP_BLOCKED', 'REORG_FENCED', 'QUARANTINED']) {
    expect(() =>
      verifyFactRetirementBatch(
        {
          identity: 'OPENPC-FACT-EVIDENCE-LEASE-1',
          batch: { ...batch, checkpointState },
          retirementBlocker: 'INCOMPLETE_CHECKPOINT',
        },
        expected,
        digest,
        digest,
      ),
    ).toThrow(FactRetirementBlocked);
  }
  expect(() =>
    verifyFactRetirementBatch(
      { identity: 'OPENPC-FACT-EVIDENCE-LEASE-1', batch, retirementBlocker: 'REFERENCES' },
      expected,
      digest,
      digest,
    ),
  ).toThrow(FactRetirementBlocked);
  for (const change of [
    { identity: 'OPENPC_FACT_CALLER_READINESS' },
    { sourceProfileId: id.replace(/1$/u, '2') },
    { verificationKeyDigest: `sha256:${'b'.repeat(64)}` },
    { checkpointSequence: '0' },
    ...['GAP_BLOCKED', 'REORG_FENCED', 'QUARANTINED'].map((checkpointState) => ({
      checkpointState,
    })),
    { records: [] },
    { records: [{ ...entry, receiptBase64: bytes.toString('base64') + '\n' }] },
    { records: [{ ...entry, sourceSequence: '2' }] },
    { records: [{ ...entry, candidateId: id.replace(/1$/u, '2') }] },
    { records: [{ ...entry, lineage: { ...entry.lineage, canonicalGeneration: '2' } }] },
    { records: [{ ...entry, admittedAt: '2026-09-22T00:00:01.000000Z' }] },
  ])
    expect(() => verify({ ...batch, ...change })).toThrow();
  expect(() =>
    verifyFactRetirementBatch(
      { identity: 'OPENPC-FACT-EVIDENCE-LEASE-1', batch, retirementBlocker: null },
      expected,
      digest,
      `sha256:${'b'.repeat(64)}`,
    ),
  ).toThrow();
  const minimum = {
    factLineage: {
      ...expected.lineage,
      predecessorDigest: digest,
      relationshipPredecessorDigest: digest,
      reorgReplacementOf: expected.lineage.factId,
      canonicalGeneration: '9223372036854775807',
    },
  };
  // PostgreSQL jsonb text adds separator spaces. The maximal legal lineage
  // still fits the existing bound without retaining custody or raw values.
  expect(
    Buffer.byteLength(JSON.stringify(minimum).replaceAll(',', ', ').replaceAll(':"', ': "')),
  ).toBeLessThanOrEqual(2048);
});
