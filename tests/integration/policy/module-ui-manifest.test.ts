import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { encodeCanonicalCbor } from '../../../packages/security-kernel/src/index.js';
import { moduleUiSemanticPayload } from '../../../services/module-registry/src/domain/module-ui-signing.js';
import {
  parseModuleUiManifest,
  moduleUiManifestSchema,
  assertModuleUiEnvelopeSignature,
  moduleUiSignatureContext,
  type ModuleUiManifest,
} from '../../../services/module-registry/src/domain/module-ui-manifest.js';

// Portable fixture for the complete pc.policy.ptv document.
// Its placeholder signature is not runtime trust. All 33 untouched originals
// are checked independently by the contract conformance suite.
const portableDocument = {
  accessibility: {
    keyboardPatternIds: ['A11Y-PC_POLICY_PTV_KEYBOARD'],
    landmarkPolicy: 'LABELLED_REGION',
    manualEvidenceIds: ['EVIDENCE-PC_POLICY_PTV_SCREEN_READER_MANUAL'],
    nameKey: 'openpc.pc.policy.ptv.name',
    responsiveProfiles: ['MOBILE', 'TABLET', 'DESKTOP', 'WIDE'],
    truthStates: [
      'SUCCESS',
      'AUTHORIZED_EMPTY',
      'DENIED',
      'LOADING',
      'UNKNOWN',
      'UNAVAILABLE',
      'STALE',
      'REORG',
      'PARTIAL',
      'CONFLICTING',
      'DEGRADED',
      'FAILED',
      'RETRY_ELIGIBLE',
      'FAILOVER_ELIGIBLE',
      'WRITE_AMBIGUITY',
      'RECOVERY',
      'ROLLBACK',
      'RETIREMENT',
      'UNINSTALL',
      'DECOMMISSION',
    ],
  },
  capabilities: ['CAP-UI_PC_POLICY_PTV'],
  contributions: [
    {
      accessibilityMetadataId: 'A11Y-PC_POLICY_PTV_MODULE_LIFECYCLE_DETAIL',
      actionIntents: [],
      anchor: 'VIEW-MODULE_LIFECYCLE',
      capabilityRequirements: ['CAP-UI_PC_POLICY_PTV'],
      contributionId: 'UICONTRIB-PC_POLICY_PTV_MODULE_LIFECYCLE_DETAIL',
      dataQueries: ['getUiModuleLifecycle'],
      kind: 'DETAIL_PANEL',
      localizationNamespace: 'openpc.pc.policy.ptv',
      phase: 'SECONDARY',
      priority: 500,
      routeBehavior: 'NO_ROUTE',
      slotId: 'UISLOT-DETAIL-PANEL',
      unloadBehavior: 'UNMOUNT_CANCEL_CLEAR_REAUTHORIZE',
      versionRange: '>=1.0.0 <2.0.0',
      viewOrFormId: 'VIEW-MODULE_LIFECYCLE',
    },
  ],
  designSystemRange: '>=1.0.0 <2.0.0',
  failure: {
    budget: 'DISABLE_CONTRIBUTION',
    load: 'OMIT_AND_RECORD',
    mutation: 'NO_AUTO_RETRY',
    query: 'TYPED_NO_FALLBACK',
    render: 'ISOLATE_CONTRIBUTION',
    safetyUi: 'PRESERVE',
  },
  localization: {
    builtInLocale: 'en',
    missingKey: 'FAIL_CONTRIBUTION_CERTIFICATION',
    namespace: 'openpc.pc.policy.ptv',
    resourceDigests: {
      en: 'sha256:ae0769bb5224a004b219715c4c98dbf5aff0444f5b40881eac8068cb1aa740f9',
    },
    richText: 'ALLOWLISTED_STRUCTURED_TOKENS_NO_HTML',
  },
  manifestId: 'urn:openpc:module-ui-manifest:c6a374dc-d1f9-74fa-bb60-2df65bf3f162',
  migration: {
    fromRanges: [],
    migrationIds: [],
    oneActiveVersion: true,
    rollbackId: 'ROLLBACK-PC_POLICY_PTV_UI_STATE',
    stateSchemaVersion: '1.0.0',
  },
  moduleDigest: 'sha256:7877a8c4faca1dbfe26e4e0939b8fbbc179e46df72aca2763bbfc339b65e5e16',
  moduleId: 'pc.policy.ptv',
  moduleVersion: '1.0.0',
  publisherKeyId: 'sha256:7c726ed739e881fe5cec6e765330826e994aebb3e4819ce2f4f0c24c884bfaa0',
  resourceBudget: {
    bundleBytes: 262144,
    initialRenderMs: 2000,
    interactionMs: 200,
    memoryBytes: 33554432,
    networkRequests: 0,
    policy: 'EXACT_QUALIFIED_PROFILE_NO_SLA_CLAIM',
  },
  schemaVersion: '1.0',
  shellRange: '>=1.0.0 <2.0.0',
  signature: {
    algorithm: 'ES256',
    coseSign1: 'UNIT_FIXTURE_NOT_ADMITTED',
    encoding: 'PC-CBOR-1',
    purpose: 'openpc:module-ui-manifest:v1',
    schemaDigest: 'sha256:bf8edcaa7a11c08d6cba257ab02d25bb5196b2e72617e67da99732d1c6ac9233',
    schemaId: 23001,
    schemaVersion: '1.0.0',
  },
  telemetry: {
    allowedDimensions: [
      'moduleId',
      'moduleVersion',
      'contributionId',
      'slotId',
      'routeId',
      'truthState',
      'stableProblemCode',
      'durationBucket',
    ],
    highCardinalityActorLabels: false,
    namespace: 'ui.module.pc.policy.ptv',
    payloadCapture: false,
  },
  tests: [
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_SCHEMA',
      kind: 'SCHEMA',
      testId: 'TEST-PC_POLICY_PTV_SCHEMA',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_ACCESSIBILITY_AUTOMATED',
      kind: 'ACCESSIBILITY_AUTOMATED',
      testId: 'TEST-PC_POLICY_PTV_ACCESSIBILITY_AUTOMATED',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_KEYBOARD_E2E',
      kind: 'KEYBOARD_E2E',
      testId: 'TEST-PC_POLICY_PTV_KEYBOARD_E2E',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_SCREEN_READER_MANUAL',
      kind: 'SCREEN_READER_MANUAL',
      testId: 'TEST-PC_POLICY_PTV_SCREEN_READER_MANUAL',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_RESPONSIVE',
      kind: 'RESPONSIVE',
      testId: 'TEST-PC_POLICY_PTV_RESPONSIVE',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_LOCALIZATION',
      kind: 'LOCALIZATION',
      testId: 'TEST-PC_POLICY_PTV_LOCALIZATION',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_FAILURE_ISOLATION',
      kind: 'FAILURE_ISOLATION',
      testId: 'TEST-PC_POLICY_PTV_FAILURE_ISOLATION',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_BACKEND_REAUTHORIZATION',
      kind: 'BACKEND_REAUTHORIZATION',
      testId: 'TEST-PC_POLICY_PTV_BACKEND_REAUTHORIZATION',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_ANTI_LEAKAGE',
      kind: 'ANTI_LEAKAGE',
      testId: 'TEST-PC_POLICY_PTV_ANTI_LEAKAGE',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_MIGRATION',
      kind: 'MIGRATION',
      testId: 'TEST-PC_POLICY_PTV_MIGRATION',
    },
    {
      evidenceId: 'EVIDENCE-PC_POLICY_PTV_UNINSTALL',
      kind: 'UNINSTALL',
      testId: 'TEST-PC_POLICY_PTV_UNINSTALL',
    },
  ],
  uninstall: {
    clearState: true,
    disableFirst: true,
    evidenceReceipt: 'REQUIRED',
    localization: 'REMOVE_NAMESPACE_AFTER_UNMOUNT',
    removeContributions: true,
    savedViews: 'DROP_MODULE_FIELDS_AND_FILTERS',
  },
};
function document(): ModuleUiManifest {
  return structuredClone(parseModuleUiManifest(portableDocument));
}

describe('ModuleUiManifestV1 document shape', () => {
  it('preserves every field of the portable full-document fixture', () => {
    expect(parseModuleUiManifest(portableDocument)).toEqual(portableDocument);
  });
  it.each([
    (value: ModuleUiManifest) => {
      value.signature.schemaId = 22501 as 23001;
    },
    (value: ModuleUiManifest) => {
      value.signature.purpose = 'openpc:module-release:v1' as typeof value.signature.purpose;
    },
    (value: ModuleUiManifest) => {
      value.signature.schemaDigest =
        `sha256:${'a'.repeat(64)}` as typeof value.signature.schemaDigest;
    },
    (value: ModuleUiManifest) => {
      value.telemetry.payloadCapture = true as false;
    },
    (value: ModuleUiManifest) => {
      value.failure.mutation = 'RETRY' as 'NO_AUTO_RETRY';
    },
    (value: ModuleUiManifest) => {
      value.resourceBudget.bundleBytes = 0;
    },
    (value: ModuleUiManifest) => {
      value.accessibility.truthStates.pop();
    },
    (value: ModuleUiManifest) => {
      value.accessibility.manualEvidenceIds = [];
    },
    (value: ModuleUiManifest) => {
      value.migration.oneActiveVersion = false as true;
    },
    (value: ModuleUiManifest) => {
      value.uninstall.clearState = false as true;
    },
    (value: ModuleUiManifest) => {
      value.localization.richText = 'HTML' as typeof value.localization.richText;
    },
  ])('rejects a changed closed safety/schema condition', (mutate) => {
    const value = document();
    mutate(value);
    expect(() => parseModuleUiManifest(value)).toThrow();
  });
  it('rejects duplicate contributions, undeclared capabilities and foreign localization', () => {
    const value = document();
    value.contributions.push(value.contributions[0]!);
    expect(() => parseModuleUiManifest(value)).toThrow('PC-MODULE-7002');
    const capability = document();
    capability.contributions[0]!.capabilityRequirements.push('CAP-UNDECLARED');
    expect(() => parseModuleUiManifest(capability)).toThrow('PC-MODULE-7002');
    const locale = document();
    locale.contributions[0]!.localizationNamespace = 'foreign.namespace';
    expect(() => parseModuleUiManifest(locale)).toThrow('PC-MODULE-7002');
    expect(moduleUiManifestSchema.safeParse({ ...document(), runtimeEnabled: true }).success).toBe(
      false,
    );
  });
});

/** In-memory publisher fixture over a complete contract document, rebound
 * to a synthetic runtime publisher. This does not admit a compiled UI bundle. */
function envelope(options: { purpose?: string; schemaId?: number; payload?: Buffer } = {}) {
  const key = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicKey = key.publicKey.export({ format: 'der', type: 'spki' });
  const keyId = createHash('sha256').update(publicKey).digest();
  const value = document();
  value.publisherKeyId = `sha256:${keyId.toString('hex')}`;
  const payload = options.payload ?? moduleUiSemanticPayload(value);
  const header = encodeCanonicalCbor(
    new Map<number, string | number | Buffer>([
      [1, -7],
      [3, 'application/openpc+cbor'],
      [4, keyId],
      [1001, options.schemaId ?? 23001],
      [1002, options.purpose ?? moduleUiSignatureContext.purpose],
    ]),
  );
  const signature = sign(
    'sha256',
    encodeCanonicalCbor(['Signature1', header, Buffer.alloc(0), payload]),
    { key: key.privateKey, dsaEncoding: 'ieee-p1363' },
  );
  const cose = Buffer.concat([
    Buffer.from([0xd2]),
    encodeCanonicalCbor([header, new Map(), payload, signature]),
  ]);
  value.signature.coseSign1 = cose.toString('base64');
  const binding = {
    manifestDigest: value.moduleDigest,
    artifactDigest: `sha256:${'a'.repeat(64)}`,
    moduleName: value.moduleId,
    moduleVersion: value.moduleVersion,
    publisherKeyId: value.publisherKeyId,
    publisherPublicKeySpkiDer: publicKey,
    validUntilMs: Date.now() + 60000,
  };
  return { value, binding, payload, cose };
}
describe('UI signature envelope denials; no trust/admission result', () => {
  it('verifies exact bound bytes and returns no admitted state', () => {
    const { value, binding } = envelope();
    expect(assertModuleUiEnvelopeSignature(value, binding)).toBeUndefined();
    const unrelated = envelope({ payload: Buffer.from('unrelated signed buffer') });
    expect(() => assertModuleUiEnvelopeSignature(unrelated.value, unrelated.binding)).toThrow(
      'PC-MODULE-7008',
    );
    expect(() =>
      assertModuleUiEnvelopeSignature({ ...value, shellRange: '>=9.0.0' }, binding),
    ).toThrow('PC-MODULE-7008');
  });
  it.each([{ purpose: 'openpc:module-release:v1' }, { schemaId: 22501 }])(
    'rejects valid signature in wrong context %j',
    (change) => {
      const { value, binding } = envelope(change);
      expect(() => assertModuleUiEnvelopeSignature(value, binding)).toThrow('PC-MODULE-7008');
    },
  );
  it('rejects tampered signature, wrong publisher, trailing bytes and noncanonical base64', () => {
    const { value, binding, cose } = envelope();
    const changed = Buffer.from(cose);
    changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
    for (const encoded of [
      changed.toString('base64'),
      Buffer.concat([cose, Buffer.from([0])]).toString('base64'),
      `${cose.toString('base64')}\n`,
    ])
      expect(() =>
        assertModuleUiEnvelopeSignature(
          { ...value, signature: { ...value.signature, coseSign1: encoded } },
          binding,
        ),
      ).toThrow('PC-MODULE-7008');
    expect(() =>
      assertModuleUiEnvelopeSignature(
        { ...value, publisherKeyId: `sha256:${'0'.repeat(64)}` },
        binding,
      ),
    ).toThrow('PC-MODULE-7008');
  });
});
