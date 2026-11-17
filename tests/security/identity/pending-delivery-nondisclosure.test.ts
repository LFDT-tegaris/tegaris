import { describe, expect, it } from 'vitest';

import type { AuthorityContext } from '../../../services/identity-service/src/contracts/authorization.js';
import { SafePendingScope } from '../../../services/identity-service/src/contracts/pending-delivery.js';
import {
  PendingDeliveryKernel,
  type PendingDeliveryRepository,
} from '../../../services/identity-service/src/domain/pending-delivery-kernel.js';

const uuidA = '018f6d4a-1234-7abc-8def-0123456789ab';
const uuidB = '018f6d4a-1234-7abc-9def-0123456789ac';
const digest = `sha256:${'a'.repeat(64)}` as const;
const timestamp = '2026-09-05T00:00:00.000000Z';
const scope = SafePendingScope.create({
  participantId: `urn:openpc:participant:${uuidA}`,
  privacyDomainId: `urn:openpc:privacy-domain:${uuidB}`,
  chainId: '1',
  profileId: `urn:openpc:profile:${uuidA}`,
  profileVersion: '1.0.0',
  deliverySurface: 'RECEIPT',
});
const context: AuthorityContext = {
  principalId: `urn:openpc:principal:${uuidA}`,
  participantId: scope.value.participantId,
  privacyDomainId: scope.value.privacyDomainId,
  sessionId: `urn:openpc:session:${uuidA}`,
  authorityEnvelopeId: `urn:openpc:authority-envelope:${uuidA}`,
  authorityEpoch: '1',
  delegationEpoch: '1',
  actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
  policyGenerationDigest: digest,
  factGenerationDigest: digest,
};
const unusedStore: PendingDeliveryRepository = {
  async enqueue() {
    throw new Error('not used');
  },
  async transition() {
    throw new Error('not used');
  },
  async summarize() {
    throw new Error('must not execute');
  },
};

describe('P00 pending-delivery non-disclosure', () => {
  it('makes hidden, nonexistent, denied, and cross-scope authorization indistinguishable', async () => {
    const variants = ['HIDDEN', 'NONEXISTENT', 'DENIED', 'CROSS_SCOPE'];
    const observed: string[] = [];
    for (const explanation of variants) {
      const internal: unknown[] = [];
      const kernel = new PendingDeliveryKernel(
        unusedStore,
        {
          async evaluate(request) {
            return {
              decision: 'DENY',
              authorized: false,
              terminal: true,
              existenceVisible: false,
              payloadVisible: false,
              authorityContext: request.authorityContext,
              inputsDigest: request.inputsDigest,
              evaluatedAt: timestamp,
              explanationCodes: [explanation],
              traceSetId: 'TS-ID-AUTHORIZATION',
            };
          },
        },
        { record: (diagnostic) => internal.push(diagnostic) },
      );
      try {
        await kernel.summary(scope, context);
      } catch (error) {
        observed.push(
          JSON.stringify({
            code: (error as { code: string }).code,
            message: (error as Error).message,
            serialized: JSON.stringify(error),
            enumerableKeys: Object.keys(error as object),
            hasReason: 'reason' in (error as object),
          }),
        );
      }
      expect(internal).toEqual([{ code: 'PC-RUNTIME-3001', reason: 'PENDING_SCOPE_INVALID' }]);
    }
    expect(new Set(observed)).toEqual(
      new Set([
        JSON.stringify({
          code: 'PC-RUNTIME-3001',
          message: 'PC-RUNTIME-3001',
          serialized: '{}',
          enumerableKeys: [],
          hasReason: false,
        }),
      ]),
    );
  });
});
