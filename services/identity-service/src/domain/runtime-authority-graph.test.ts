import { describe, expect, it } from 'vitest';
import {
  authorityEnvelopeDigest,
  decodeEnvelopeProposal,
  encodeEnvelopeProposal,
} from '@openpc/security-kernel';
import { identityEnvelopeFixture } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  currentWorkloadCredentialBinding,
  scopedEnvelopePermission,
  scopedPermission,
} from './runtime-authority-graph.js';

describe('runtime permission projection', () => {
  it.each([null, 'retained-recovery-evidence'])(
    'omits empty recovery provenance while retaining real recovery metadata (%s)',
    (recovery_case_id) => {
      const constraints = {
        authority_envelope_id: 'call-envelope',
        runtime_capability_ids: ['CALL_RESULT_DISCLOSURE'],
        resource_ids: ['runtime-binding'],
        risk_classes: ['LOW'],
        maker_checker_required: false,
        step_up_required: false,
        state: 'ACTIVE',
      };
      expect(
        scopedPermission(
          { ...constraints, recovery_case_id, privacy_domain_ids: ['selected', 'foreign'] },
          'selected',
        ),
      ).toEqual({
        ...constraints,
        privacy_domain_ids: ['selected'],
        ...(recovery_case_id === null ? {} : { recovery_case_id }),
      });
    },
  );
});

function typedEnvelope() {
  const proposal = decodeEnvelopeProposal(identityEnvelopeFixture('test-key').proposalBytes);
  const emptyAdministration = {
    participantIds: [],
    privacyDomainIds: [],
    resourceIds: [],
    dataClasses: [],
    targetProfileIds: [],
    riskClasses: [],
    actionIntentIds: [],
  };
  proposal.usable.administration = emptyAdministration;
  proposal.grantable.administration = emptyAdministration;
  const bytes = encodeEnvelopeProposal(proposal);
  const digest = Buffer.from(authorityEnvelopeDigest(bytes).slice(7), 'hex');
  const runtime = proposal.usable.runtime;
  const source = {
    representation: 'TYPED_V1',
    authority_envelope_id: proposal.envelopeId,
    participant_id: proposal.participantId,
    privacy_domain_ids: runtime.privacyDomainIds,
    resource_ids: runtime.resourceIds,
    risk_classes: runtime.riskClasses,
    action_intent_ids: [],
    runtime_capability_ids: runtime.capabilityIds,
    valid_from_ns: proposal.usable.validFromNs,
    valid_until_ns: proposal.usable.validUntilNs,
    maker_checker_required: proposal.usable.makerCheckerRequired,
    step_up_required: proposal.usable.stepUpRequired,
    onward_delegation_depth: proposal.usable.onwardDelegationDepth,
  };
  return { source, bytes, digest, privacy: runtime.privacyDomainIds[0]! };
}

describe('typed runtime envelope projection', () => {
  it('retains the exact signed target and data-class restrictions without resolving labels', () => {
    const { source, bytes, digest, privacy } = typedEnvelope();
    const originalBytes = Buffer.from(bytes);
    expect(scopedEnvelopePermission(source, bytes, digest, privacy)).toEqual({
      ...source,
      runtime_scope: { data_classes: ['METADATA'], target_profile_ids: ['target-1'] },
    });
    expect(bytes.equals(originalBytes)).toBe(true);
  });

  it.each([
    ['authority_envelope_id', 'foreign-envelope'],
    ['participant_id', 'foreign-participant'],
    ['privacy_domain_ids', ['foreign-privacy']],
    ['runtime_capability_ids', ['SIGNED_TRANSACTION_SUBMISSION']],
    ['resource_ids', ['*']],
    ['risk_classes', ['LOW']],
    ['action_intent_ids', ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1']],
    ['valid_from_ns', '1'],
    ['valid_until_ns', '18446744073709551615'],
    ['maker_checker_required', false],
    ['step_up_required', false],
    ['onward_delegation_depth', 3],
  ])('rejects a flat %s substitution rather than publishing it', (key, value) => {
    const { source, bytes, digest, privacy } = typedEnvelope();
    expect(() =>
      scopedEnvelopePermission({ ...source, [key]: value }, bytes, digest, privacy),
    ).toThrow('Typed envelope permission projection mismatch');
  });

  it('rejects another privacy context, changed bytes, and a mismatched original digest', () => {
    const { source, bytes, digest, privacy } = typedEnvelope();
    expect(() => scopedEnvelopePermission(source, bytes, digest, 'foreign')).toThrow();
    const changed = Buffer.from(bytes);
    changed[0] = changed.readUInt8(0) ^ 1;
    expect(() => scopedEnvelopePermission(source, changed, digest, privacy)).toThrow();
    expect(() => scopedEnvelopePermission(source, bytes, Buffer.alloc(32), privacy)).toThrow();
  });
});

const credential = (workloadId: string, state = 'ACTIVE', valid_now = true) => ({
  principalId: 'principal',
  workloadId,
  source: { state, valid_now },
});

describe('current workload credential identity', () => {
  it('retains same-audience rollover and revoked history in the selected binding', () => {
    const rows = [credential('workload-a'), credential('workload-a', 'REVOKED')];
    expect(currentWorkloadCredentialBinding(rows)).toEqual({
      workloadId: 'workload-a',
      credentials: rows,
    });
  });
  it('preserves a genuine ambiguity between concurrently valid audiences', () => {
    expect(() => currentWorkloadCredentialBinding([credential('a'), credential('b')])).toThrow(
      'Ambiguous workload principal binding',
    );
  });
  it.each([
    ['REVOKED', true],
    ['ACTIVE', false],
    ['PENDING', true],
  ] as const)(
    'does not let %s historical or invalid credentials establish an audience',
    (state, valid) => {
      const live = credential('workload-a');
      expect(
        currentWorkloadCredentialBinding([live, credential('workload-b', state, valid)]),
      ).toEqual({ workloadId: 'workload-a', credentials: [live] });
      expect(
        currentWorkloadCredentialBinding([credential('workload-b', state, valid)]),
      ).toBeUndefined();
    },
  );
});
