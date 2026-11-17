import { describe, expect, it } from 'vitest';
import { bindModuleLifecycleTransition } from '../../../services/module-registry/src/db/module-lifecycle-state.js';
import { moduleLifecycleInputDigest } from '../../../services/module-registry/src/db/module-lifecycle-store.js';
import { controlMutationForAction } from '../../../packages/security-kernel/src/control-mutation-operations.js';
import type { MutationContext } from '../../../services/control-api/src/configuration/persistence/types.js';
import {
  disableModuleSchema,
  moduleDisableReplacementDigest,
} from '../../../services/module-registry/src/module-command-contract.js';

describe('DISABLE transport binding and semantic state', () => {
  const descriptor = {
    operation: 'MOD-OP-DISABLE',
    targetRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000301',
    expectedRevision: '3',
    manifestDigest: `sha256:${'11'.repeat(32)}`,
  };
  it.each([
    ['3', 'sha256:f557fae6cbf03ae12514d9332020e281c8c92a10a04e29572ce78cbea0f7f9a0'],
    ['9007199254740993', 'sha256:add33a081407f4795888d17631965e78bae60fd1f2e7b05a2f7330cc43c7b820'],
    [
      '18446744073709551615',
      'sha256:b4575f0ac6c67e8ea548c1bd8eb656edcfe6746a8a860ef8e67a70ae7075cfc9',
    ],
  ])(
    'preserves the exact decimal revision %s in the framed request',
    (expectedRevision, digest) => {
      expect(moduleDisableReplacementDigest({ ...descriptor, expectedRevision })).toBe(digest);
    },
  );
  it('rejects malformed descriptors instead of coercing identity or claiming readiness', () => {
    for (const change of [
      { operation: 'MOD-OP-UPGRADE' },
      { targetRef: descriptor.targetRef.replace('resource', 'module') },
      { expectedRevision: 3 },
      { expectedRevision: '03' },
      { expectedRevision: '-1' },
      { expectedRevision: '18446744073709551616' },
      { manifestDigest: '11'.repeat(32) },
      { ready: true },
    ])
      expect(() => moduleDisableReplacementDigest({ ...descriptor, ...change })).toThrow();
    const original = moduleDisableReplacementDigest(descriptor);
    for (const change of [
      { targetRef: descriptor.targetRef.replace(/301$/u, '302') },
      { expectedRevision: '4' },
      { manifestDigest: `sha256:${'22'.repeat(32)}` },
    ])
      expect(moduleDisableReplacementDigest({ ...descriptor, ...change })).not.toBe(original);
  });
  it('accepts only the five registered PATCH fields; target and readiness are not body fields', () => {
    const body = {
      actionIntentId: 'ACT-MODULES_UPDATE_RESOURCE-V1',
      actionIntentDigest: descriptor.manifestDigest,
      expectedRevision: descriptor.expectedRevision,
      replacementDigest: moduleDisableReplacementDigest(descriptor),
      reason: 'Disable the exact currently enabled release.',
    };
    expect(disableModuleSchema.parse(body)).toEqual(body);
    for (const extra of [
      { targetRef: descriptor.targetRef },
      { operation: 'MOD-OP-DISABLE' },
      { inputDigest: body.replacementDigest },
      { ready: true },
    ])
      expect(disableModuleSchema.safeParse({ ...body, ...extra }).success).toBe(false);
  });
});

const context = {
  catalogOperationId: 'MOD-OP-INSTALL',
  aggregateType: 'module-registration',
  expectedRevision: '1',
  resourceId: '018f0000-0000-7000-8000-000000000301',
  authorization: {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  },
} as MutationContext;
const admitted = {
  moduleId: 'pc.transaction.delivery',
  semanticVersion: '1.0.0',
  manifestDigest: Buffer.alloc(32, 1),
  dependencyDigest: Buffer.alloc(32, 2),
  configurationDigest: Buffer.alloc(32, 3),
  state: 'ADMITTED',
  activeManifestDigest: null,
  generation: '1',
  active: false,
  revision: '1',
  evaluationDigest: null,
};
const installed = {
  ...admitted,
  state: 'INSTALLED_DISABLED',
  revision: '2',
  evaluationDigest: Buffer.alloc(32, 4),
};
const enabled = {
  ...installed,
  state: 'ENABLED',
  revision: '3',
  active: true,
  activeManifestDigest: admitted.manifestDigest,
  evaluationDigest: Buffer.alloc(32, 5),
};
describe('initial module lifecycle receipts', () => {
  it('binds inert install separately from exact activation', () => {
    const install = bindModuleLifecycleTransition(context, admitted, installed);
    expect(install.before.reference.revision).toBe(1n);
    expect(install.after.reference.revision).toBe(2n);
    const enable = bindModuleLifecycleTransition(
      { ...context, catalogOperationId: 'MOD-OP-ENABLE', expectedRevision: '2' },
      installed,
      enabled,
    );
    expect(enable.after.reference.revision).toBe(3n);
    expect(enable.after.reference.stateDigest).not.toEqual(install.after.reference.stateDigest);
  });
  it('rejects activation during install, missing simulation and substituted configuration', () => {
    for (const change of [
      { state: 'ENABLED' },
      { active: true },
      { evaluationDigest: null },
      { activeManifestDigest: admitted.manifestDigest },
      { configurationDigest: Buffer.alloc(32) },
      { dependencyDigest: Buffer.alloc(32) },
      { generation: '2' },
      { revision: '3' },
    ])
      expect(() =>
        bindModuleLifecycleTransition(context, admitted, { ...installed, ...change }),
      ).toThrow();
    expect(() =>
      bindModuleLifecycleTransition({ ...context, expectedRevision: '2' }, admitted, installed),
    ).toThrow();
    expect(() =>
      bindModuleLifecycleTransition(
        { ...context, aggregateType: 'indexer-profile' },
        admitted,
        installed,
      ),
    ).toThrow();
  });
  it('pins release identity and the frozen singular-resource action bindings', () => {
    const target = `urn:openpc:resource:${context.resourceId}`,
      manifest = `sha256:${admitted.manifestDigest.toString('hex')}`;
    expect(moduleLifecycleInputDigest(target, '1', manifest)).not.toBe(
      moduleLifecycleInputDigest(target, '2', manifest),
    );
    expect(controlMutationForAction('ACT-MODULE_CREATE_INSTALL-V1')).toMatchObject({
      catalogOperationId: 'MOD-OP-INSTALL',
      resourceType: 'module',
      operationClass: 'CREATE',
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
    expect(controlMutationForAction('ACT-MODULE_ACTIVATE_RESOURCE-V1')).toMatchObject({
      catalogOperationId: 'MOD-OP-ENABLE',
      resourceType: 'module',
      operationClass: 'ACTIVATE',
    });
    expect(
      controlMutationForAction('ACT-MODULE_CREATE_INSTALL-V1', 'MOD-OP-ENABLE'),
    ).toBeUndefined();
  });
});

describe('governed module DISABLE state (canonical profile required)', () => {
  const disableContext: MutationContext = {
    ...context,
    catalogOperationId: 'MOD-OP-DISABLE',
    expectedRevision: '3',
    actionIntentId: 'ACT-MODULES_UPDATE_RESOURCE-V1',
    resourceType: 'modules',
    operationClass: 'UPDATE',
  };
  const disabled = { ...installed, revision: '4', evaluationDigest: Buffer.alloc(32, 6) };
  it('binds the unchanged release and inert generation to revision four and permits governed re-enable', () => {
    expect(
      controlMutationForAction(disableContext.actionIntentId, disableContext.catalogOperationId),
    ).toMatchObject({
      catalogOperationId: 'MOD-OP-DISABLE',
      resourceType: 'modules',
      operationClass: 'UPDATE',
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
    const transition = bindModuleLifecycleTransition(disableContext, enabled, disabled);
    expect(transition.before.reference.revision).toBe(3n);
    expect(transition.after.reference.revision).toBe(4n);
    expect(transition.before.reference.stateDigest).not.toEqual(
      transition.after.reference.stateDigest,
    );
    expect(
      bindModuleLifecycleTransition(
        { ...context, catalogOperationId: 'MOD-OP-ENABLE', expectedRevision: '4' },
        disabled,
        { ...enabled, revision: '5', evaluationDigest: Buffer.alloc(32, 7) },
      ).after.reference.revision,
    ).toBe(5n);
  });
  it('rejects stale, substituted or granting disable transitions without changing inputs', () => {
    const original = structuredClone(disabled);
    for (const change of [
      { active: true },
      { activeManifestDigest: admitted.manifestDigest },
      { state: 'ENABLED' },
      { generation: '2' },
      { revision: '3' },
      { revision: '5' },
      { evaluationDigest: null },
      { configurationDigest: Buffer.alloc(32, 90) },
      { dependencyDigest: Buffer.alloc(32, 91) },
      { manifestDigest: Buffer.alloc(32, 92) },
      { semanticVersion: '1.0.1' },
    ])
      expect(() =>
        bindModuleLifecycleTransition(disableContext, enabled, { ...disabled, ...change }),
      ).toThrow();
    for (const before of [
      installed,
      { ...enabled, active: false },
      { ...enabled, activeManifestDigest: null },
      { ...enabled, evaluationDigest: null },
    ])
      expect(() => bindModuleLifecycleTransition(disableContext, before, disabled)).toThrow();
    expect(structuredClone(disabled)).toEqual(original);
  });
  it('preserves full-width revision state and rejects overflow', () => {
    const revision = '9007199254740993';
    expect(
      bindModuleLifecycleTransition(
        { ...disableContext, expectedRevision: revision },
        { ...enabled, revision },
        { ...disabled, revision: '9007199254740994' },
      ).before.reference.revision,
    ).toBe(9007199254740993n);
    expect(() =>
      bindModuleLifecycleTransition(
        { ...disableContext, expectedRevision: '18446744073709551615' },
        { ...enabled, revision: '18446744073709551615' },
        { ...disabled, revision: '18446744073709551616' },
      ),
    ).toThrow();
  });
});
