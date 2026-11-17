import { expect, it } from 'vitest';
import { sha256 } from '../configuration/digest.js';
import { storeRetirementSourceBinding } from './store-retirement-contracts.js';
import { retirementWireFixture } from './store-retirement-wire-fixture.js';
import { retirementWireBytes } from './store-retirement-wire.js';
import { retirementSourceFailure } from './store-retirement-repository.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';

it('returns a safe precondition denial for declared source eligibility failures only', () => {
  for (const suffix of [
    '',
    '-UNSUPPORTED-SOURCE',
    '-SOURCE',
    '-ACTIVE-HOLD',
    '-CHECKPOINT',
    '-SINK-QUORUM',
    '-RETENTION',
  ]) {
    let caught: unknown;
    try {
      retirementSourceFailure({ code: 'P0001', message: `PC-DATA-6007${suffix}` });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ConfigurationRepositoryError);
    expect(caught).toMatchObject({ code: 'PC-DATA-6007', message: 'PC-DATA-6007' });
  }
  expect(() => retirementSourceFailure({ code: 'P0002' })).toThrow('PC-DATA-6007');
  for (const original of [
    new Error('PC-DATA-6007-ACTIVE-HOLD'),
    { code: '42501', message: 'PC-DATA-6007-ACTIVE-HOLD' },
    { code: 'P0001', message: 'PC-DATA-6007-ACTIVE-HOLD: private SQL detail' },
    { code: 'P0001', message: 'PC-DATA-6007-UNKNOWN' },
    { code: 'P0003', message: 'unexpected cardinality' },
  ]) {
    let caught: unknown;
    try {
      retirementSourceFailure(original);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(original);
  }
});

it('rejects substituted catalogue, original COSE, archive and acknowledgement bindings', () => {
  const { attempt } = retirementWireFixture();
  const evidenceId = '018f0000-0000-7000-8000-000000000101';
  const manifest = [
    {
      candidateId: 'candidate',
      evidenceId,
      streamId: 'original-source',
      recordId: 'original-record',
      sequence: '1',
      recordDigest: 'sha256:' + 'a'.repeat(64),
      segmentId: evidenceId,
      objectDigest: 'sha256:' + 'b'.repeat(64),
    },
  ];
  const acknowledgements = [
    {
      candidateId: 'candidate',
      sinkReceipts: [
        {
          sinkId: 'original-sink',
          checkpointDigest: 'sha256:' + 'c'.repeat(64),
          receiptDigest: 'sha256:' + 'd'.repeat(64),
          acknowledgedAtMicros: '1800000000000000',
        },
      ],
    },
  ];
  const binding = {
    version: 'OPENPC_STORE_RETIREMENT_SOURCE_V1',
    selectionWireHex: retirementWireBytes(attempt.selection).toString('hex'),
    recordRefs: [{ candidateId: 'candidate', evidenceId }],
    manifest,
    acknowledgements,
    archiveManifestDigest: sha256(manifest).slice(7),
    archiveAcknowledgementDigest: sha256(acknowledgements).slice(7),
    retentionNotBeforeMs: '1800000000000',
    lifecycleRevision: '9',
  };
  expect(storeRetirementSourceBinding.parse(binding)).toEqual(binding);
  const alteredOriginal = [{ ...manifest[0]!, recordDigest: 'sha256:' + 'f'.repeat(64) }];
  for (const altered of [
    { ...binding, eligible: true },
    { ...binding, recordRefs: [{ candidateId: 'foreign', evidenceId }] },
    { ...binding, recordRefs: [...binding.recordRefs, ...binding.recordRefs] },
    { ...binding, manifest: [{ ...manifest[0]!, streamId: 'foreign' }] },
    {
      ...binding,
      manifest: alteredOriginal,
      archiveManifestDigest: sha256(alteredOriginal).slice(7),
    },
    { ...binding, acknowledgements: [{ ...acknowledgements[0]!, sinkReceipts: [] }] },
    { ...binding, lifecycleRevision: '9223372036854775808' },
    { ...binding, selectionWireHex: Buffer.from('{}').toString('hex') },
  ])
    expect(storeRetirementSourceBinding.safeParse(altered).success).toBe(false);
});
