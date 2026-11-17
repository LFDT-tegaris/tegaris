import { describe, expect, it } from 'vitest';

import * as publicPrivacyExplorer from '../../services/control-api/src/privacy-explorer/index.js';
import { buildB5Harness, projectionFor } from './i07-gate2-b5-test-support.js';

describe('I07 Gate 2 B5 public composition conformance', () => {
  it('exposes the service but none of the execution, raw, candidate, or evidence owners', () => {
    expect(publicPrivacyExplorer).toHaveProperty('createPrivacyExplorerService');
    for (const forbidden of [
      'createExecutionRepository',
      'createPrivacyExplorerExecutionOracle',
      'createExecutionOwner',
      'createCompletionOwner',
      'createEvidenceLifecycleOwner',
      'buildProjectionCandidate',
      'requirePublicResponseCandidate',
    ])
      expect(publicPrivacyExplorer).not.toHaveProperty(forbidden);
  });

  it('requires the actual qualified profile and verified context identities', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection(request, context) {
          calls += 1;
          return Promise.resolve(projectionFor(request, context));
        },
      },
    });
    const service = publicPrivacyExplorer.createPrivacyExplorerService(harness.port);
    await expect(
      service.read({ ...harness.input, profile: { ...harness.profile } }),
    ).rejects.toThrow('unqualified Explorer profile');
    await expect(
      service.read({ ...harness.input, context: { ...harness.context } }),
    ).rejects.toThrow('unverified local context');
    expect(calls).toBe(0);
  });

  it('rejects a caller-selected endpoint and emits only result plus digest evidence', async () => {
    let calls = 0;
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection(request, context) {
          calls += 1;
          return Promise.resolve(projectionFor(request, context, 'PARTIAL'));
        },
      },
    });
    const service = publicPrivacyExplorer.createPrivacyExplorerService(harness.port);
    await expect(
      service.read({
        ...harness.input,
        endpoint: 'https://browser-or-fallback.invalid',
      } as typeof harness.input),
    ).rejects.toThrow('invalid Privacy Explorer service input');
    const result = await service.read(harness.input);
    expect(calls).toBe(1);
    expect(Object.keys(result).sort()).toEqual(['disposition', 'evidence', 'response']);
    expect(result.disposition).toBe('RELEASED');
    expect(result.response).toMatchObject({ outcome: 'PARTIAL', truthState: 'PARTIAL' });
    expect(result.response).not.toHaveProperty('source');
    expect(result.response).not.toHaveProperty('endpoint');
    expect(result.response).not.toHaveProperty('authorizationDigest');
    expect(result.evidence).not.toHaveProperty('records');
    expect(result.evidence).toHaveProperty(
      'authorizationDigest',
      expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    );
  });

  it('exposes cancellation only as a suppressed disposition with no public response', async () => {
    let calls = 0;
    const controller = new AbortController();
    controller.abort();
    const harness = buildB5Harness({
      signal: controller.signal,
      implementation: {
        readGovernedProjection(request, context) {
          calls += 1;
          return Promise.resolve(projectionFor(request, context));
        },
      },
    });
    const service = publicPrivacyExplorer.createPrivacyExplorerService(harness.port);
    const result = await service.read(harness.input);

    expect(calls).toBe(0);
    expect(Object.keys(result).sort()).toEqual(['disposition', 'evidence']);
    expect(result.disposition).toBe('SUPPRESSED');
    expect(result).not.toHaveProperty('response');
    expect(result.evidence).toMatchObject({
      outcome: 'CANCELLED_BEFORE_DISPATCH',
      rawState: 'NEVER_CREATED',
    });
    expect(result.evidence).not.toHaveProperty('truthState');
    expect(result.evidence).not.toHaveProperty('delivery');
  });
});
