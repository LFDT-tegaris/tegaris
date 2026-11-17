import { describe, expect, it } from 'vitest';
import { configurationMutationOperation } from '@openpc/security-kernel';
import { createRuntimeTargetProfileBindingSchema } from './contract.js';
import { runtimeTargetProfileBindingDigest } from './digest.js';

const input = {
  actionIntentId: 'ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'1'.repeat(64)}`,
  reason: 'Bind the registered target to its reviewed runtime profile.',
  runtimeTargetRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000902',
  targetRevision: '1',
  targetProfileId: 'devnet-rpc-v1',
};
describe('governed runtime target profile binding', () => {
  it('requires its own maker/checker and step-up operation without changing activation', () => {
    expect(createRuntimeTargetProfileBindingSchema.parse(input)).toEqual(input);
    expect(configurationMutationOperation('CFG-OP-CREATE-RUNTIME-TARGET-PROFILE')).toMatchObject({
      actionIntentId: input.actionIntentId,
      resourceType: 'runtime-target-profile-binding',
      operationClass: 'CREATE',
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
    expect(configurationMutationOperation('CFG-OP-UPDATE-RUNTIME-TARGET')).toMatchObject({
      actionIntentId: 'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
      makerCheckerRequired: false,
      stepUpRequired: false,
    });
  });

  it.each([
    { targetRevision: '0' },
    { targetRevision: '01' },
    { targetRevision: '9223372036854775808' },
    { runtimeTargetRef: 'devnet-rpc-v1' },
    { targetProfileId: '*' },
    { targetProfileId: ' devnet-rpc-v1' },
    { targetProfileId: 'devnet/rpc' },
    { targetProfileId: '' },
    { targetProfileId: 'w'.repeat(129) },
    { makerCheckerRequired: false },
    { capabilityIds: ['CALL_RESULT_DISCLOSURE'] },
    { targetRef: input.runtimeTargetRef },
  ])('rejects untyped, widened or substituted command input %j', (change) => {
    expect(createRuntimeTargetProfileBindingSchema.safeParse({ ...input, ...change }).success).toBe(
      false,
    );
  });

  it('matches the independent canonical tuple vector and binds every context dimension', () => {
    const scope = {
      participantId: '018f0000-0000-7000-8000-000000000101',
      privacyDomainId: '018f0000-0000-7000-8000-000000000201',
      targetRuntimeId: '018f0000-0000-7000-8000-000000000902',
      targetProfileId: 'devnet-rpc-v1',
    };
    const expected = 'sha256:8aa9f53cde6159c76a028c910ac010aaf2ab278d744f306c674c49ec2373f195';
    expect(runtimeTargetProfileBindingDigest(scope)).toBe(expected);
    for (const key of Object.keys(scope)) {
      expect(runtimeTargetProfileBindingDigest({ ...scope, [key]: 'foreign' })).not.toBe(expected);
    }
  });
});
