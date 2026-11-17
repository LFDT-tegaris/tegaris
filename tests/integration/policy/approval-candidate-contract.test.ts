import { moduleDisableReplacementDigest } from '../../../services/module-registry/src/module-command-contract.js';
import { resumeApprovalSchema } from '../../../services/module-registry/src/public-approval-http.js';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';
import { projectApprovalCandidate } from '../../../services/module-registry/src/approval-candidate-contract.js';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.js';
import { deleteRawProofBatch } from '../../../services/control-api/src/evidence/raw-deletion-contracts.js';
import { deleteProjectionBatch } from '../../../services/control-api/src/evidence/projection-deletion-contracts.js';
import { retirementWireFixture } from '../../../services/control-api/src/evidence/store-retirement-wire-fixture.js';
import { retirementWireBytes } from '../../../services/control-api/src/evidence/store-retirement-wire.js';

const ref = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000101';
const document = {
  actionIntentId: 'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'a'.repeat(64)}`,
  reason: 'Exact reviewed deployment',
  deploymentIntentId: ref,
  signedTransaction: '0x01020304',
};
const hash = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const input = {
  document,
  candidateDigest: hash(document),
  actionIntentId: document.actionIntentId,
  catalogOperationId: 'CFG-OP-SUBMIT-DEPLOYMENT',
  resourceType: 'deployment-submission',
  operationClass: 'CREATE',
};

describe('public approval candidate disclosure', () => {
  it('reviews only the exact producer-validated typed argument rule candidate', () => {
    const candidate = {
      actionIntentId: 'ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1',
      actionIntentDigest: hash('typed-rule-action'),
      reason: 'Review the exact allowed account.',
      runtimeBindingId: ref,
      abiArtifactId: ref,
      abiDigest: hash('abi'),
      canonicalSignature: 'balanceOf(address)',
      version: '1.0.0',
      namedSetVersions: [],
      rules: [
        {
          parameterPath: 'inputs[0]',
          operandType: 'ADDRESS',
          operator: 'EQ',
          values: ['0x' + '11'.repeat(20)],
        },
      ],
    };
    const binding = {
      document: candidate,
      candidateDigest: hash(candidate),
      actionIntentId: candidate.actionIntentId,
      catalogOperationId: 'CFG-OP-CREATE-ARGUMENT-RULES',
      resourceType: 'typed-argument-rule-version',
      operationClass: 'CREATE',
    };
    expect(projectApprovalCandidate(binding)).toEqual({ candidate, redactedFields: [] });
    for (const changed of [
      { ...candidate, privateKey: 'must-not-be-disclosed' },
      { ...candidate, rules: [{ ...candidate.rules[0], privatePayload: 'hidden' }] },
      {
        ...candidate,
        rules: [
          { ...candidate.rules[0], operandType: 'INTEGER', values: ['0x' + '11'.repeat(20)] },
        ],
      },
      { ...candidate, rules: [] },
      {
        ...candidate,
        namedSetVersions: [
          { ownerId: ref, setId: 'unsupported', version: '1.0.0', digest: hash('set') },
        ],
      },
    ])
      expect(() =>
        projectApprovalCandidate({ ...binding, document: changed, candidateDigest: hash(changed) }),
      ).toThrow('PC-POLICY-2001');
    for (const changed of [
      { candidateDigest: hash('substitution') },
      { actionIntentId: 'ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1' },
      { catalogOperationId: 'CFG-OP-CREATE-METHOD-POLICY' },
      { resourceType: 'contract-method-policy' },
      { operationClass: 'UPDATE' },
      {
        document: {
          ...candidate,
          rules: [{ ...candidate.rules[0], values: ['0x' + '22'.repeat(20)] }],
        },
      },
    ])
      expect(() => projectApprovalCandidate({ ...binding, ...changed })).toThrow('PC-POLICY-2001');
  });

  it('discloses only the exact governed runtime retirement identity and ordered successor', () => {
    const id = (n: number) => `01900000-0000-7000-8000-${String(n).padStart(12, '0')}`;
    const source = {
      participantId: id(1),
      privacyDomainId: id(2),
      runtimeConfigurationInputId: id(3),
      moduleInstallationId: id(4),
      moduleConfigurationGenerationId: id(5),
      configurationDigest: hash('source'),
      configurationBytes: 2426,
      resourceBindingsDigest: hash('bindings'),
      createdAt: '2026-09-27T00:00:00.000000Z',
    };
    const candidate = {
      participantId: `urn:openpc:participant:${id(1)}`,
      actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1',
      actionIntentDigest: hash('action'),
      beforeDigest: hash('before'),
      reason: 'Retire the withdrawn original.',
      selection: {
        version: 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1',
        participantId: `urn:openpc:participant:${id(1)}`,
        privacyDomainId: id(2),
        retentionPolicyId: `urn:openpc:resource:${id(6)}`,
        policyDigest: hash('policy'),
        targetDatabase: 'openpc_control',
        dataClass: 'RUNTIME_ARTIFACT',
        deletionMode: 'ROW_DELETE',
        source,
        streamId: 'archive',
        manifestRecordId: `runtime-artifact:${hash({ domain: 'pc.runtime-artifact.archive-identity.v1', identity: source }).slice(7)}:manifest`,
        manifestDigest: hash('manifest'),
        archiveSegments: [
          {
            segmentId: id(7),
            objectDigest: hash('object'),
            firstSequence: '1',
            throughSequence: '1',
            sinkReceipts: [
              {
                sinkId: 'sink',
                checkpointDigest: hash('checkpoint'),
                receiptDigest: hash('receipt'),
                acknowledgedAtMicros: '1',
              },
            ],
          },
        ],
        referenceObservationDigest: hash('references'),
        eligibleAfterMicros: '1',
        priorCursor: null,
        disposition: {
          dispositionId: id(8),
          operationId: id(9),
          receiptDigest: hash('disposition'),
          nativeDenialDigest: hash('denial'),
          sourceOwnerId: id(10),
          sourceRootDigest: hash('root'),
        },
        nextInput: {
          runtimeConfigurationInputId: id(11),
          configurationDigest: hash('next'),
          beforeDigest: hash('next-before'),
        },
      },
    };
    const binding = {
      document: candidate,
      candidateDigest: hash(candidate),
      actionIntentId: candidate.actionIntentId,
      catalogOperationId: 'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH',
      resourceType: 'evidence-deletions',
      operationClass: 'CREATE',
    };
    expect(projectApprovalCandidate(binding)).toEqual({ candidate, redactedFields: [] });
    for (const selection of [
      { ...candidate.selection, disposition: null },
      { ...candidate.selection, ready: true },
      { ...candidate.selection, source: { ...source, configurationCbor: 'secret-bytes' } },
      {
        ...candidate.selection,
        nextInput: {
          ...candidate.selection.nextInput,
          runtimeConfigurationInputId: source.runtimeConfigurationInputId,
        },
      },
      { ...candidate.selection, privacyDomainId: id(99) },
    ]) {
      const altered = { ...candidate, selection };
      expect(() =>
        projectApprovalCandidate({ ...binding, document: altered, candidateDigest: hash(altered) }),
      ).toThrow('PC-POLICY-2001');
    }
    for (const change of [
      { candidateDigest: hash('substitution') },
      { catalogOperationId: 'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE' },
      { operationClass: 'DELETE' },
    ])
      expect(() => projectApprovalCandidate({ ...binding, ...change })).toThrow('PC-POLICY-2001');
  });
  it('reviews the exact governed store retirement without granting authority or admitting substitutions', () => {
    const { attempt } = retirementWireFixture();
    const evidenceId = ref.slice(-36);
    const manifest = [
      {
        candidateId: 'candidate',
        evidenceId,
        streamId: 'source',
        recordId: 'record',
        sequence: '1',
        recordDigest: `sha256:${'a'.repeat(64)}`,
        segmentId: evidenceId,
        objectDigest: hash('object'),
      },
    ];
    const acknowledgements = [
      {
        candidateId: 'candidate',
        sinkReceipts: [
          {
            sinkId: 'archive',
            checkpointDigest: hash('checkpoint'),
            receiptDigest: hash('receipt'),
            acknowledgedAtMicros: '1800000000000000',
          },
        ],
      },
    ];
    const candidate = {
      participantId: ref.replace(':resource:', ':participant:'),
      hostDigest: hash('host').slice(7),
      retentionPolicyId: ref,
      previousAttemptId: null,
      actionIntentId: 'ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1',
      actionIntentDigest: document.actionIntentDigest,
      reason: 'Review the original signed Fact and archive binding.',
      sourceBinding: {
        version: 'OPENPC_STORE_RETIREMENT_SOURCE_V1',
        selectionWireHex: retirementWireBytes(attempt.selection).toString('hex'),
        recordRefs: [{ candidateId: 'candidate', evidenceId }],
        manifest,
        acknowledgements,
        archiveManifestDigest: hash(manifest).slice(7),
        archiveAcknowledgementDigest: hash(acknowledgements).slice(7),
        retentionNotBeforeMs: '1800000000000',
        lifecycleRevision: '9',
      },
    };
    const binding = {
      document: candidate,
      candidateDigest: hash(candidate),
      actionIntentId: candidate.actionIntentId,
      catalogOperationId: 'CFG-OP-ADMIT-STORE-RETIREMENT',
      resourceType: 'evidence-deletions',
      operationClass: 'CREATE',
    };
    expect(projectApprovalCandidate(binding)).toEqual({ candidate, redactedFields: [] });
    for (const change of [
      { runtimePermission: 'EXECUTE' },
      { hostDigest: 'invalid' },
      {
        sourceBinding: {
          ...candidate.sourceBinding,
          recordRefs: [{ candidateId: 'foreign', evidenceId }],
        },
      },
      {
        sourceBinding: {
          ...candidate.sourceBinding,
          manifest: [{ ...manifest[0], recordDigest: hash('substituted') }],
        },
      },
      { sourceBinding: { ...candidate.sourceBinding, acknowledgements: [] } },
      {
        sourceBinding: {
          ...candidate.sourceBinding,
          selectionWireHex: Buffer.from('{}').toString('hex'),
        },
      },
    ]) {
      const altered = { ...candidate, ...change };
      expect(() =>
        projectApprovalCandidate({ ...binding, document: altered, candidateDigest: hash(altered) }),
      ).toThrow('PC-POLICY-2001');
    }
    for (const change of [
      { candidateDigest: hash('different') },
      { catalogOperationId: 'CFG-OP-DELETE-PROJECTION-BATCH' },
      { resourceType: 'retention-policies' },
      { operationClass: 'UPDATE' },
    ])
      expect(() => projectApprovalCandidate({ ...binding, ...change })).toThrow('PC-POLICY-2001');
  });
  it.each(['SEARCH_PROJECTION', 'NORMALIZED_JSON_PROJECTION'])(
    'binds %s to exact source, physical mode and ordered cursor',
    (dataClass) => {
      const digest = document.actionIntentDigest;
      const target = {
        evidenceId: ref,
        recordId: 'source-1',
        projectionDigest: digest,
        projectionBytes: 128,
        sourceReceiptDigest: digest,
        beforeDigest: digest,
      };
      const candidate = {
        participantId: ref.replace(':resource:', ':participant:'),
        beforeDigest: digest,
        actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1',
        actionIntentDigest: digest,
        reason: 'Retire the exact derived projection.',
        selection: {
          version: 'OPENPC_PROJECTION_DELETION_BATCH_V1',
          ...target,
          beforeDigest: undefined,
          participantId: ref.replace(':resource:', ':participant:'),
          privacyDomainId: ref.slice(-36),
          retentionPolicyId: ref,
          policyDigest: digest,
          targetDatabase: 'openpc_control',
          dataClass,
          deletionMode: 'PROJECTION_DELETE',
          sourceKind:
            dataClass === 'SEARCH_PROJECTION'
              ? 'AUTHENTICATION_CATALOGUE'
              : 'RPC_PRE_ADMISSION_DENIAL',
          streamId: 'projection-source',
          segmentId: ref.slice(-36),
          sequence: '1',
          archiveObjectDigest: digest,
          eligibleAfterMicros: '1',
          sinkReceipts: [],
          priorCursor: null,
          targets: [target],
          batchIndex: 0,
        },
      };
      delete (candidate.selection as Record<string, unknown>).beforeDigest;
      const binding = {
        document: candidate,
        candidateDigest: hash(candidate),
        catalogOperationId: 'CFG-OP-DELETE-PROJECTION-BATCH',
        actionIntentId: candidate.actionIntentId,
        resourceType: 'evidence-deletions',
        operationClass: 'CREATE',
      };
      expect(deleteProjectionBatch.safeParse(candidate).success).toBe(true);
      expect(projectApprovalCandidate(binding)).toEqual({ candidate, redactedFields: [] });
      for (const change of [
        { dataClass: 'AUDIT_EVIDENCE' },
        { sourceKind: 'DEPLOYMENT_UNKNOWN' },
        { deletionMode: 'ROW_DELETE' },
        {
          dataClass:
            dataClass === 'SEARCH_PROJECTION' ? 'NORMALIZED_JSON_PROJECTION' : 'SEARCH_PROJECTION',
        },
        { projectionBytes: 127 },
        { projectionDigest: hash('different') },
        { targets: [target, target] },
        { priorCursor: { deletionJobId: ref, receiptDigest: digest } },
        { batchIndex: 1 },
        { projection: { arbitrary: true } },
      ]) {
        const altered = { ...candidate, selection: { ...candidate.selection, ...change } };
        expect(() =>
          projectApprovalCandidate({
            ...binding,
            document: altered,
            candidateDigest: hash(altered),
          }),
        ).toThrow('PC-POLICY-2001');
      }
    },
  );
  it('reviews an exact raw-proof batch while rejecting class, version, cursor and unsigned target substitutions', () => {
    const digest = document.actionIntentDigest;
    const source = {
      evidenceId: ref,
      occurrenceId: ref.slice(-36),
      operationId: ref.slice(-36),
      sourceReceiptDigest: digest,
      proofDigest: digest,
      assertionDigest: digest,
      signatureDigest: digest,
      signerKeyDigest: digest,
      occurredAt: '2026-09-23T00:00:00.000000Z',
      materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
      evidenceClass: 'AUTHENTICATION',
      sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
      occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
      proofIntegrity: 'IDENTITY_COSE_ED25519',
      finality: 'NOT_APPLICABLE',
      authorityEffect: 'NONE',
    };
    const target = {
      objectRef: ref,
      objectVersion: '1',
      objectDigest: digest,
      payloadDigest: digest,
      ciphertextBytes: 64,
      beforeDigest: digest,
    };
    const candidate = {
      participantId: ref.replace(':resource:', ':participant:'),
      beforeDigest: digest,
      actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1',
      actionIntentDigest: digest,
      reason: 'Delete the exact expired raw copy.',
      selection: {
        version: 'OPENPC_RAW_PROOF_DELETION_BATCH_V1',
        ...target,
        beforeDigest: undefined,
        participantId: ref.replace(':resource:', ':participant:'),
        privacyDomainId: ref.slice(-36),
        retentionPolicyId: ref,
        policyDigest: digest,
        targetDatabase: 'openpc_control',
        dataClass: 'RAW_SOURCE_BODY',
        deletionMode: 'ROW_DELETE',
        source,
        eligibleAfterMicros: '1',
        sinkReceipts: [],
        priorCursor: null,
        targets: [target],
        batchIndex: 0,
      },
    };
    delete (candidate.selection as Record<string, unknown>).beforeDigest;
    const binding = {
      document: candidate,
      candidateDigest: hash(candidate),
      catalogOperationId: 'CFG-OP-DELETE-RAW-PROOF-BATCH',
      actionIntentId: candidate.actionIntentId,
      resourceType: 'evidence-deletions',
      operationClass: 'CREATE',
    };
    expect(deleteRawProofBatch.safeParse(candidate).success).toBe(true);
    expect(projectApprovalCandidate(binding)).toEqual({ candidate, redactedFields: [] });
    for (const change of [
      { dataClass: 'AUDIT_EVIDENCE' },
      { deletionMode: 'CRYPTO_SHRED' },
      { targetDatabase: 'openpc_facts' },
      { objectVersion: '2' },
      { batchIndex: 1 },
      { payloadDigest: hash('changed') },
      { targets: [target, target] },
      { priorCursor: { deletionJobId: ref, receiptDigest: digest } },
      { source: { ...source, materialType: 'PC-DEPLOYMENT-HANDOFF' } },
      { source: { ...source, assertionBase64: 'sensitive' } },
    ]) {
      const altered = { ...candidate, selection: { ...candidate.selection, ...change } };
      expect(() =>
        projectApprovalCandidate({ ...binding, document: altered, candidateDigest: hash(altered) }),
      ).toThrow('PC-POLICY-2001');
    }
  });
  it.each([
    [
      'CFG-OP-CREATE-EVIDENCE-HOLD',
      'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
      'CREATE',
      'PRIVACY_DOMAIN',
    ],
    [
      'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD',
      'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
      'CREATE',
      'PARTICIPANT',
    ],
    [
      'CFG-OP-RELEASE-EVIDENCE-HOLD',
      'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
      'UPDATE',
      'PRIVACY_DOMAIN',
    ],
    [
      'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD',
      'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1',
      'UPDATE',
      'PARTICIPANT',
    ],
  ])(
    'reviews the exact hold authority for %s',
    (catalogOperationId, actionIntentId, operationClass, type) => {
      const candidate = {
        actionIntentId,
        actionIntentDigest: document.actionIntentDigest,
        reason: 'Preserve the reviewed scope until an independently approved release.',
        ...(operationClass === 'CREATE'
          ? {
              participantId: ref.replace(':resource:', ':participant:'),
              holdKind: 'LEGAL',
              selector: { type },
            }
          : { targetRef: ref, expectedRevision: '1' }),
      };
      const binding = {
        document: candidate,
        candidateDigest: hash(candidate),
        catalogOperationId,
        actionIntentId,
        resourceType: 'evidence-holds',
        operationClass,
      };
      expect(projectApprovalCandidate(binding)).toEqual({ candidate, redactedFields: [] });
      for (const change of [
        {
          actionIntentId:
            actionIntentId.replace('_PARTICIPANT', '_RESOURCE') === actionIntentId
              ? actionIntentId.replace('_RESOURCE', '_PARTICIPANT')
              : actionIntentId.replace('_PARTICIPANT', '_RESOURCE'),
        },
        { candidateDigest: hash({}) },
        { operationClass: 'DELETE' },
      ])
        expect(() => projectApprovalCandidate({ ...binding, ...change })).toThrow('PC-POLICY-2001');
      const forged = { ...candidate, selector: { type: 'PARTICIPANT', participantId: ref } };
      expect(() =>
        projectApprovalCandidate({ ...binding, document: forged, candidateDigest: hash(forged) }),
      ).toThrow('PC-POLICY-2001');
    },
  );

  it('reviews only the exact public assignment candidate without disclosing unknown identity fields', () => {
    const assignmentId = '018f0000-0000-7000-8000-000000008151';
    const candidate = {
      id: assignmentId,
      assignmentId,
      participantId: '018f0000-0000-7000-8000-000000000101',
      principalId: '018f0000-0000-7000-8000-000000008190',
      authorityEnvelopeId: '018f0000-0000-7000-8000-000000008381',
      roleId: 'urn:openpc:role:018f0000-0000-7000-8000-000000008351',
      state: 'ACTIVE',
      delegationEpoch: '0',
      scopeDigest: document.actionIntentDigest,
      privacyDomainIds: ['018f0000-0000-7000-8000-000000007201'],
      actionIntentIds: ['ACT-RUNTIME_READ_RPC-V1'],
      capabilityIds: [],
      resourceIds: [ref.slice(-36)],
      riskClasses: ['LOW'],
      validFrom: '2026-09-22T00:00:00.000Z',
      validUntil: '2030-01-01T00:00:00.000Z',
      makerCheckerRequired: false,
      stepUpRequired: false,
      onwardDelegationDepth: 0,
    };
    const binding = {
      catalogOperationId: 'ID-OP-ASSIGNMENT-CREATE',
      actionIntentId: 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
      resourceType: 'principal',
      operationClass: 'CREATE',
    };
    expect(
      projectApprovalCandidate({
        ...binding,
        document: candidate,
        candidateDigest: hash(candidate),
      }),
    ).toEqual({ candidate, redactedFields: [] });
    for (const changed of [
      { ...candidate, privateKey: 'private' },
      { ...candidate, sessionToken: 'private' },
      { ...candidate, id: candidate.principalId },
      { ...candidate, state: 'REVOKED' },
      { ...candidate, delegationEpoch: '1' },
      { ...candidate, validUntil: 'bad' },
    ])
      expect(() =>
        projectApprovalCandidate({ ...binding, document: changed, candidateDigest: hash(changed) }),
      ).toThrow('PC-POLICY-2001');
    for (const changed of [
      { catalogOperationId: 'ID-OP-DELEGATION-ISSUE' },
      { actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
      { resourceType: 'participant' },
      { operationClass: 'UPDATE' },
      { candidateDigest: hash({}) },
    ])
      expect(() =>
        projectApprovalCandidate({
          ...binding,
          document: candidate,
          candidateDigest: hash(candidate),
          ...changed,
        }),
      ).toThrow('PC-POLICY-2001');
  });

  it.each([
    [
      'CFG-OP-UPDATE-PROVIDER-PROFILE',
      'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
      'provider-profiles',
      'UPDATE',
    ],
    [
      'CFG-OP-QUALIFY-PROVIDER-PROFILE',
      'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',
      'provider-profile',
      'APPROVE',
    ],
    [
      'CFG-OP-ADMIT-INDEXER-PROFILE',
      'ACT-INDEXER_APPROVE_PROFILE-V1',
      'indexer-profile',
      'APPROVE',
    ],
  ])(
    'reviews exact source admission inputs for %s',
    (catalogOperationId, actionIntentId, resourceType, operationClass) => {
      const candidate = {
        actionIntentId,
        actionIntentDigest: document.actionIntentDigest,
        reason: 'Review the exact provider or source revision.',
        expectedRevision: '2',
        ...(operationClass === 'UPDATE'
          ? { replacementDigest: document.actionIntentDigest }
          : { targetRef: ref, inputDigest: document.actionIntentDigest }),
      };
      const source = {
        document: candidate,
        candidateDigest: hash(candidate),
        catalogOperationId,
        actionIntentId,
        resourceType,
        operationClass,
      };
      expect(projectApprovalCandidate(source)).toEqual({ candidate, redactedFields: [] });
      for (const change of [
        { document: { ...candidate, expectedRevision: '3' } },
        { catalogOperationId: 'CFG-OP-CREATE-PROVIDER-PROFILE' },
        { resourceType: 'indexer-private-data' },
        { operationClass: 'READ' },
      ])
        expect(() => projectApprovalCandidate({ ...source, ...change })).toThrow('PC-POLICY-2001');
      for (const field of ['qualified', 'sourceSubjects', 'endpointCredential']) {
        const untrusted = { ...candidate, [field]: 'must not enter review' };
        expect(() =>
          projectApprovalCandidate({
            ...source,
            document: untrusted,
            candidateDigest: hash(untrusted),
          }),
        ).toThrow('PC-POLICY-2001');
      }
    },
  );

  it.each([
    ['MOD-OP-REGISTER', 'ACT-MODULES_CREATE_RESOURCE-V1', 'modules', 'CREATE'],
    ['MOD-OP-INSTALL', 'ACT-MODULE_CREATE_INSTALL-V1', 'module', 'CREATE'],
    ['MOD-OP-ENABLE', 'ACT-MODULE_ACTIVATE_RESOURCE-V1', 'module', 'ACTIVATE'],
  ])(
    'reviews the exact module command %s without widening disclosure',
    (catalogOperationId, actionIntentId, resourceType, operationClass) => {
      const candidate = {
        actionIntentId,
        actionIntentDigest: document.actionIntentDigest,
        reason: 'Review the exact signed release and target generation.',
        ...(catalogOperationId === 'MOD-OP-REGISTER'
          ? {
              name: 'pc.indexing.dedicated-policy',
              semanticVersion: '1.0.0',
              manifestDigest: document.actionIntentDigest,
              supportProfile: 'R1',
            }
          : { targetRef: ref, expectedRevision: '2', inputDigest: document.actionIntentDigest }),
      };
      const moduleInput = {
        document: candidate,
        candidateDigest: hash(candidate),
        catalogOperationId,
        actionIntentId,
        resourceType,
        operationClass,
      };
      expect(projectApprovalCandidate(moduleInput)).toEqual({
        candidate,
        redactedFields: [],
      });
      for (const change of [
        { document: { ...candidate, reason: 'changed after approval' } },
        { actionIntentId: document.actionIntentId },
        { catalogOperationId: 'MOD-OP-UNKNOWN' },
        { resourceType: 'signing-key' },
        { operationClass: 'DELETE' },
      ])
        expect(() => projectApprovalCandidate({ ...moduleInput, ...change })).toThrow(
          'PC-POLICY-2001',
        );
      const unknown = { ...candidate, privateKey: 'never disclose extra fields' };
      expect(() =>
        projectApprovalCandidate({
          ...moduleInput,
          document: unknown,
          candidateDigest: hash(unknown),
        }),
      ).toThrow('PC-POLICY-2001');
    },
  );

  it('uses the configuration producer byte ordering for mixed-case program keys', () => {
    const review = {
      actionIntentId: 'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1',
      actionIntentDigest: document.actionIntentDigest,
      reason: 'Review exact program',
      targetRef: ref,
      expectedRevision: '2',
      review: {
        analysisDigest: document.actionIntentDigest,
        actions: [],
        program: { Z: 1, a: 2 },
      },
    };
    expect(
      projectApprovalCandidate({
        document: review,
        candidateDigest: hash(review),
        actionIntentId: review.actionIntentId,
        catalogOperationId: 'CFG-OP-REVIEW-CIGL-ANALYSIS',
        resourceType: 'cigl-analysis',
        operationClass: 'UPDATE',
      }).candidate,
    ).toEqual(review);
  });
  it('retains exact intent references while withholding replayable signed bytes', () => {
    const projected = projectApprovalCandidate(input);
    const { signedTransaction, ...review } = document;
    expect(projected.candidate).toEqual(review);
    expect(projected.redactedFields).toEqual([
      {
        field: 'signedTransaction',
        byteLength: 4,
        digest: `sha256:${createHash('sha256')
          .update(Buffer.from(signedTransaction.slice(2), 'hex'))
          .digest('hex')}`,
      },
    ]);
    expect(document.signedTransaction).toBe('0x01020304');
    // The filtered view's digest cannot replace the exact candidate digest.
    expect(hash(projected.candidate)).not.toBe(input.candidateDigest);
  });

  it('withholds signed CIGL receipts using the same closed producer contract', () => {
    const receipt = {
      actionIntentId: 'ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1',
      actionIntentDigest: document.actionIntentDigest,
      reason: 'Review target observation',
      targetRef: ref,
      expectedRevision: '1',
      signedReceipt: '0xaabbcc',
    };
    const result = projectApprovalCandidate({
      document: receipt,
      candidateDigest: hash(receipt),
      actionIntentId: receipt.actionIntentId,
      catalogOperationId: 'CFG-OP-UPDATE-CIGL-ANALYSIS',
      resourceType: 'cigl-analysis',
      operationClass: 'UPDATE',
    });
    expect(result.candidate).not.toHaveProperty('signedReceipt');
    expect(result.redactedFields[0]).toMatchObject({ field: 'signedReceipt', byteLength: 3 });
  });

  it('fails closed on document tampering, unknown fields, unsupported families and mismatched bindings', () => {
    for (const change of [
      { document: { ...document, reason: 'altered' } },
      { catalogOperationId: 'CFG-OP-CREATE-DEPLOYMENT-INTENT' },
      { resourceType: 'deployment-intent' },
      { operationClass: 'UPDATE' },
      { actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
    ])
      expect(() => projectApprovalCandidate({ ...input, ...change })).toThrow('PC-POLICY-2001');
    const unknown = { ...document, privateKey: 'must never be returned' };
    expect(() =>
      projectApprovalCandidate({ ...input, document: unknown, candidateDigest: hash(unknown) }),
    ).toThrow('PC-POLICY-2001');
  });
});

describe('approval resume input boundary', () => {
  const input = {
    command: 'RESUME',
    actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: `sha256:${'a'.repeat(64)}`,
    expectedRevision: '2',
    predecessorCandidateId: '018f0000-0000-7000-8000-000000000101',
    expectedAttempt: '1',
    candidateDigest: `sha256:${'b'.repeat(64)}`,
    reason: 'Resume the same expired intent.',
  };
  it('requires the explicit immutable predecessor and rejects authority or lifetime supplied by callers', () => {
    expect(resumeApprovalSchema.parse(input)).toEqual(input);
    for (const field of [
      'predecessorCandidateId',
      'expectedAttempt',
      'expectedRevision',
      'candidateDigest',
    ]) {
      const malformed = { ...input } as Record<string, unknown>;
      delete malformed[field];
      expect(resumeApprovalSchema.safeParse(malformed).success).toBe(false);
    }
    for (const extra of [
      { candidate: {} },
      { idempotencyKey: 'another-business-intent' },
      { expiresAt: '2099-01-01T00:00:00Z' },
      { noEffect: true },
      { makerPrincipalId: input.predecessorCandidateId },
      { approvalUsable: true },
    ])
      expect(resumeApprovalSchema.safeParse({ ...input, ...extra }).success).toBe(false);
    for (const expectedAttempt of ['0', '-1', '1.5', '01'])
      expect(resumeApprovalSchema.safeParse({ ...input, expectedAttempt }).success).toBe(false);
  });
  it('publishes the same closed resume input while retaining policy replacement', async () => {
    const readSchema = async (name: string) =>
      JSON.parse(
        await readFile(
          new URL(`../../../schemas/json/${name}.schema.json`, import.meta.url),
          'utf8',
        ),
      );
    const [shared, control] = await Promise.all([
      readSchema('shared-primitives'),
      readSchema('control-api'),
    ]);
    const validator = new Ajv2020({ strict: false });
    addFormats(validator);
    validator.addSchema(shared, 'shared-primitives.schema.json');
    const resume = validator.compile(control.$defs.ResumeApprovalRequestRequest);
    const replace = validator.compile(control.$defs.UpdateApprovalRequestRequest);
    expect(resume(input)).toBe(true);
    for (const change of [
      { expectedAttempt: '0' },
      { expectedAttempt: '01' },
      { command: 'REPLACE' },
      { predecessorCandidateId: 'missing' },
      { expiresAt: '2099-01-01T00:00:00Z' },
      { noEffect: true },
      { candidate: {} },
      { candidateDigest: 'unbound' },
    ]) {
      expect(resume({ ...input, ...change })).toBe(false);
      expect(resumeApprovalSchema.safeParse({ ...input, ...change }).success).toBe(false);
    }
    const replacement = {
      actionIntentId: input.actionIntentId,
      actionIntentDigest: input.actionIntentDigest,
      expectedRevision: '1',
      replacementDigest: input.candidateDigest,
      reason: input.reason,
    };
    expect(replace(replacement)).toBe(true);
    expect(resume(replacement)).toBe(false);
    expect(replace(input)).toBe(false);
  });
});

describe('module DISABLE approval disclosure', () => {
  it('reviews only the exact five-field UPDATE candidate and canonical operation registration', () => {
    const candidate = {
      actionIntentId: 'ACT-MODULES_UPDATE_RESOURCE-V1',
      actionIntentDigest: document.actionIntentDigest,
      expectedRevision: '3',
      replacementDigest: moduleDisableReplacementDigest({
        operation: 'MOD-OP-DISABLE',
        targetRef: ref,
        expectedRevision: '3',
        manifestDigest: document.actionIntentDigest,
      }),
      reason: 'Disable this exact release while preserving retained history.',
    };
    const binding = {
      document: candidate,
      candidateDigest: hash(candidate),
      catalogOperationId: 'MOD-OP-DISABLE',
      actionIntentId: candidate.actionIntentId,
      resourceType: 'modules',
      operationClass: 'UPDATE',
    };
    expect(projectApprovalCandidate(binding)).toEqual({ candidate, redactedFields: [] });
    for (const change of [
      { resourceType: 'module' },
      { operationClass: 'ACTIVATE' },
      { catalogOperationId: 'MOD-OP-UPGRADE' },
      { candidateDigest: hash('other') },
    ])
      expect(() => projectApprovalCandidate({ ...binding, ...change })).toThrow('PC-POLICY-2001');
    for (const extra of [
      { targetRef: ref },
      { ready: true },
      { inputDigest: candidate.replacementDigest },
      { expectedRevision: '03' },
      { expectedRevision: '18446744073709551616' },
    ]) {
      const changed = { ...candidate, ...extra };
      expect(() =>
        projectApprovalCandidate({ ...binding, document: changed, candidateDigest: hash(changed) }),
      ).toThrow('PC-POLICY-2001');
    }
  });
});

it('discloses only exact provider creation and wallet binding creation candidate schemas', () => {
  const wallet = {
    walletBindingId: ref.slice(-36),
    participantId: ref.slice(-36),
    subjectId: ref.slice(-36),
    chainId: '92870',
    walletAddress: `0x${'12'.repeat(20)}`,
  };
  const provider = {
    actionIntentId: 'ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1',
    actionIntentDigest: `sha256:${'a'.repeat(64)}`,
    reason: 'Register provider.',
    participantId: `urn:openpc:participant:${ref.slice(-36)}`,
    chainId: '92870',
    endpointSecretRef: `urn:openpc:secret:${ref.slice(-36)}`,
    behaviorFingerprint: `sha256:${'b'.repeat(64)}`,
  };
  for (const [body, operation, action, resource, operationClass] of [
    [
      wallet,
      'ID-OP-WALLET-BINDING-CREATE',
      'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      'participant',
      'UPDATE',
    ],
    [
      provider,
      'CFG-OP-CREATE-PROVIDER-PROFILE',
      provider.actionIntentId,
      'provider-profiles',
      'CREATE',
    ],
  ] as const) {
    const value = {
      document: body,
      candidateDigest: hash(body),
      catalogOperationId: operation,
      actionIntentId: action,
      resourceType: resource,
      operationClass,
    };
    expect(projectApprovalCandidate(value)).toEqual({ candidate: body, redactedFields: [] });
    for (const changed of [
      { ...value, candidateDigest: hash('wrong') },
      { ...value, resourceType: 'wallet-binding' },
      { ...value, catalogOperationId: 'ID-OP-WALLET-BINDING-REVOKE' },
      {
        ...value,
        document: { ...body, privateKey: 'secret' },
        candidateDigest: hash({ ...body, privateKey: 'secret' }),
      },
    ])
      expect(() => projectApprovalCandidate(changed)).toThrow();
  }
  for (const changed of [
    { ...wallet, actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
    { ...wallet, chainId: '18446744073709551616' },
    { ...wallet, walletAddress: '0x1234' },
  ])
    expect(() =>
      projectApprovalCandidate({
        document: changed,
        candidateDigest: hash(changed),
        catalogOperationId: 'ID-OP-WALLET-BINDING-CREATE',
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceType: 'participant',
        operationClass: 'UPDATE',
      }),
    ).toThrow();
});
