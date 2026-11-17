import { describe, expect, it } from 'vitest';

import { createPrivacyExplorerService } from '../../../services/control-api/src/privacy-explorer/index.js';
import { buildB5Harness, projectionFor } from '../../privacy/i07-gate2-b5-test-support.js';

describe('I07 Gate 2 B5 occurrence integration', () => {
  it('allows only one in-flight execution for an exact replay', async () => {
    let calls = 0;
    let resolveRead!: (value: unknown) => void;
    let firstRequest!: Parameters<typeof projectionFor>[0];
    let firstContext!: Parameters<typeof projectionFor>[1];
    const pendingConsumer = new Promise<unknown>((resolve) => {
      resolveRead = resolve;
    });
    const harness = buildB5Harness({
      implementation: {
        readGovernedProjection(request, context) {
          calls += 1;
          firstRequest = request;
          firstContext = context;
          return pendingConsumer;
        },
      },
    });
    const service = createPrivacyExplorerService(harness.port);
    const winner = service.read(harness.input);
    await Promise.resolve();
    await expect(service.read(harness.input)).rejects.toThrow('undeclared execution event');
    expect(calls).toBe(1);
    resolveRead(projectionFor(firstRequest, firstContext));
    await expect(winner).resolves.toMatchObject({
      response: { outcome: 'COMPLETE' },
      evidence: { rawState: 'DISPOSED' },
    });
  });
});
