import { describe, expect, it } from 'vitest';
import { bindModuleAdmissionTransition } from '../../../services/module-registry/src/db/module-admission-state.js';
import type { MutationContext } from '../../../services/control-api/src/configuration/persistence/types.js';

const context = {
  catalogOperationId: 'MOD-OP-REGISTER',
  aggregateType: 'module-registration',
  resourceId: '018f0000-0000-7000-8000-000000000301',
  authorization: {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  },
} as MutationContext;
const after = {
  moduleId: 'pc.foundation.kernel',
  semanticVersion: '1.0.0',
  manifestDigest: Buffer.alloc(32, 1),
  dependencyDigest: Buffer.alloc(32, 2),
  configurationDigest: Buffer.alloc(32, 3),
  state: 'ADMITTED',
  activeManifestDigest: null,
  generation: '1',
  active: false,
  revision: '1',
};
describe('module admission business state', () => {
  it('binds absent to the exact inert admission', () => {
    const bound = bindModuleAdmissionTransition(context, undefined, after, after);
    expect(bound.before.reference.existence).toBe(0);
    expect(bound.after.reference.revision).toBe(1n);
    expect(bound.before.reference.stateDigest).not.toEqual(bound.after.reference.stateDigest);
  });
  it('rejects invented activation or an existing installation', () => {
    for (const change of [
      { state: 'ENABLED' },
      { active: true },
      { activeManifestDigest: Buffer.alloc(32) },
      { generation: '2' },
      { revision: '2' },
    ])
      expect(() =>
        bindModuleAdmissionTransition(context, undefined, { ...after, ...change }, after),
      ).toThrow();
    expect(() => bindModuleAdmissionTransition(context, after, after, after)).toThrow();
  });
  it('rejects release, dependency, configuration and profile substitution', () => {
    for (const field of ['manifestDigest', 'dependencyDigest', 'configurationDigest'])
      expect(() =>
        bindModuleAdmissionTransition(
          context,
          undefined,
          { ...after, [field]: Buffer.alloc(32, 9) },
          after,
        ),
      ).toThrow();
    expect(() =>
      bindModuleAdmissionTransition(
        { ...context, catalogOperationId: 'CFG-OP-CREATE-INDEXER-PROFILE' },
        undefined,
        after,
        after,
      ),
    ).toThrow();
  });
});
