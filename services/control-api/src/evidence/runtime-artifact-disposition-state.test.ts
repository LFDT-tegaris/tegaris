import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  businessTransitionProfileForOperation,
  configurationMutationOperation,
  signingRoleProfiles,
} from '@openpc/security-kernel';
import { decodeCbor } from '../../../../packages/security-kernel/src/business-transition/cbor.js';
import { governedReceiptOperationIds } from '../../../identity-service/src/db/governed-receipt-inputs.js';
import type { MutationContext } from '../configuration/persistence/types.js';
import { bindRuntimeArtifactDisposition } from './runtime-artifact-disposition-state.js';
import { runtimeArtifactDispositionSelection } from './runtime-artifact-disposition-contract.js';
import { prepareRuntimeArtifactArchive } from './runtime-artifact-archive-contract.js';
import { sha256 } from '../configuration/digest.js';

const uuid = (suffix: number) => `018f0000-0000-7000-8000-${String(suffix).padStart(12, '0')}`;
const context = {
  catalogOperationId: 'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
  resourceId: uuid(1),
  authorization: { participantId: uuid(2), privacyDomainId: uuid(3), approvalRequestId: uuid(4) },
} as MutationContext;
const state = {
  dispositionId: uuid(1),
  sourceOwnerId: uuid(5),
  inputId: uuid(6),
  configurationDigest: '01'.repeat(32),
  selectionDigest: '02'.repeat(32),
  approvalRequestId: uuid(4),
  operationId: uuid(7),
  admittedAtNs: '1800000000123456000',
  revision: '1' as const,
};

it('binds permanent source admission to independent approval, fresh step-up and seven exact state fields', () => {
  const operation = configurationMutationOperation('CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE');
  const profile = businessTransitionProfileForOperation(operation.catalogOperationId)!;
  const definition = JSON.parse(profile.definitionCanonicalJson);
  expect(operation).toMatchObject({
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1',
    resourceType: 'evidence-deletions',
    aggregateType: 'runtime-artifact-disposition',
    operationClass: 'CREATE',
    makerCheckerRequired: true,
    stepUpRequired: true,
  });
  expect(profile.actionIntentId).toBe(operation.actionIntentId);
  expect(governedReceiptOperationIds).toContain(operation.catalogOperationId);
  expect(signingRoleProfiles.BUSINESS_EFFECT).toContain(profile.profileId);
  expect(signingRoleProfiles.LIFECYCLE_EVIDENCE).not.toContain(profile.profileId);
  expect(definition.authority.evidence.map((value: { kind: number }) => value.kind)).toEqual([
    3, 4,
  ]);
  expect(definition.transition.after).toBe('PRESENT_ADMITTED_REVISION_1');
  expect(definition.state.owner).toBe('control.runtime_artifact_source_disposition');
  expect(Object.keys(definition.state.projection)).toHaveLength(7);
  const binding = bindRuntimeArtifactDisposition(context, uuid(7), undefined, state);
  expect((decodeCbor(binding.before.preimage) as unknown[])[8]).toEqual(new Map());
  const fields = (decodeCbor(binding.after.preimage) as unknown[])[8] as Map<number, unknown>;
  expect(fields.size).toBe(7);
  expect(fields.get(0)).toEqual(Buffer.from(uuid(5).replaceAll('-', ''), 'hex'));
  expect(fields.get(2)).toEqual(Buffer.alloc(32, 1));
  expect(fields.get(6)).toBe(1800000000123456000n);
  expect(binding.after.reference.stateDigest).toEqual(
    createHash('sha256').update(binding.after.preimage).digest(),
  );
});

it('rejects changed authority/identity, duplicate admission, missing state and malformed digests', () => {
  for (const [ctx, operation, before, after] of [
    [
      { ...context, catalogOperationId: 'CFG-OP-ADMIT-STORE-RETIREMENT' },
      uuid(7),
      undefined,
      state,
    ],
    [context, uuid(8), undefined, state],
    [context, uuid(7), state, state],
    [context, uuid(7), undefined, undefined],
    [context, uuid(7), undefined, { ...state, dispositionId: uuid(8) }],
    [context, uuid(7), undefined, { ...state, approvalRequestId: uuid(8) }],
    [context, uuid(7), undefined, { ...state, configurationDigest: '01' }],
    [context, uuid(7), undefined, { ...state, admittedAtNs: '01' }],
  ] as const)
    expect(() =>
      bindRuntimeArtifactDisposition(ctx as MutationContext, operation, before, after),
    ).toThrow();
  const original = bindRuntimeArtifactDisposition(context, uuid(7), undefined, state).after
    .reference.stateDigest;
  for (const change of [
    { sourceOwnerId: uuid(8) },
    { inputId: uuid(8) },
    { configurationDigest: '03'.repeat(32) },
    { selectionDigest: '03'.repeat(32) },
    { admittedAtNs: '1800000000123457000' },
  ])
    expect(
      bindRuntimeArtifactDisposition(context, uuid(7), undefined, { ...state, ...change }).after
        .reference.stateDigest,
    ).not.toEqual(original);
});

it('keeps archive/source observations exact and rejects fabricated clearance and incomplete segment selections', () => {
  const payload = Buffer.from([0xa0]);
  const source = {
    participantId: uuid(2),
    privacyDomainId: uuid(3),
    runtimeConfigurationInputId: uuid(6),
    moduleInstallationId: uuid(9),
    moduleConfigurationGenerationId: uuid(10),
    configurationDigest: sha256(payload),
    configurationBytes: payload.length,
    resourceBindingsDigest: sha256({}),
    createdAt: '2026-09-27T00:00:00.000000Z',
  };
  const archive = prepareRuntimeArtifactArchive(source, payload);
  const selection = {
    version: 'OPENPC_RUNTIME_ARTIFACT_SOURCE_DISPOSITION_V1',
    sourceOwnerId: uuid(5),
    sourceRootDigest: sha256('root'),
    archivePendingDigest: sha256('pending-original'),
    observation: {
      version: 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1',
      participantId: `urn:openpc:participant:${uuid(2)}`,
      privacyDomainId: uuid(3),
      retentionPolicyId: `urn:openpc:resource:${uuid(11)}`,
      policyDigest: sha256('policy'),
      targetDatabase: 'openpc_control',
      dataClass: 'RUNTIME_ARTIFACT',
      deletionMode: 'ROW_DELETE',
      source,
      streamId: 'runtime-archive',
      manifestRecordId: archive.groups.at(-1)![0]!.recordId,
      manifestDigest: sha256(archive.manifest),
      referenceObservationDigest: sha256('reference-snapshot'),
      eligibleAfterMicros: '1800000000000000',
      priorCursor: null,
      archiveSegments: [
        {
          segmentId: uuid(12),
          objectDigest: sha256('encrypted'),
          firstSequence: '1',
          throughSequence: '2',
          sinkReceipts: [
            {
              sinkId: 'archive-one',
              checkpointDigest: sha256('checkpoint'),
              receiptDigest: sha256('receipt'),
              acknowledgedAtMicros: '1800000000000000',
            },
          ],
        },
      ],
    },
  };
  expect(runtimeArtifactDispositionSelection.parse(selection)).toEqual(selection);
  for (const patch of [
    { nativeReady: true },
    { sourceRootDigest: sha256('root').slice(7) },
    { sourceOwnerId: 'legacy' },
  ])
    expect(() => runtimeArtifactDispositionSelection.parse({ ...selection, ...patch })).toThrow();
  for (const patch of [
    { referencesCleared: true },
    { archiveSegments: [] },
    { privacyDomainId: uuid(20) },
    { manifestRecordId: `runtime-artifact:${'00'.repeat(32)}:manifest` },
    {
      archiveSegments: [
        ...selection.observation.archiveSegments,
        ...selection.observation.archiveSegments,
      ],
    },
    {
      archiveSegments: selection.observation.archiveSegments.map((segment) => ({
        ...segment,
        sinkReceipts: [],
      })),
    },
  ])
    expect(() =>
      runtimeArtifactDispositionSelection.parse({
        ...selection,
        observation: { ...selection.observation, ...patch },
      }),
    ).toThrow();
});
