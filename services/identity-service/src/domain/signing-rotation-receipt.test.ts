import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  businessTransitionProfileForOperation,
  encodeReceiptStructureV2,
  decodeReceiptStructureV2,
  type BusinessTransitionReceipt,
} from '@openpc/security-kernel';
import {
  decodeCbor,
  encodeCbor,
  type CborValue,
} from '../../../../packages/security-kernel/src/business-transition/cbor.js';
import {
  signingRotationStatePreimage,
  validateSigningRotationReceipt,
  type SigningRotationReceiptState,
} from './signing-rotation-receipt.js';
import type { SigningRotationState } from './signing-rotation.js';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const h = (n: number) => Buffer.alloc(32, n);
const hash = (v: Buffer) => createHash('sha256').update(v).digest();
function fixture(
  from: SigningRotationState = 'APPROVED',
  to: SigningRotationState = 'PREPARED',
  recover = false,
) {
  const p = businessTransitionProfileForOperation(
    recover ? 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION' : 'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION',
  )!;
  const receipt: BusinessTransitionReceipt = {
    receiptId: id(1),
    schemaDefinitionDigest: Buffer.from(p.schemaDefinitionDigest.slice(7), 'hex'),
    transitionProfileId: p.profileId,
    transitionProfileVersion: p.profileVersion,
    transitionProfileDigest: Buffer.from(p.profileDigest.slice(7), 'hex'),
    environmentId: 'local',
    participantId: id(2),
    privacyDomainId: id(3),
    operationId: id(4),
    actionIntentId: p.actionIntentId,
    catalogOperationId: p.catalogOperationId,
    aggregateType: 'signing-key-rotation',
    aggregateId: id(5),
    actorKeyDigest: h(1),
    preCommitAuthorityDigest: h(2),
    actionIntentDigest: h(3),
    candidateDigest: h(4),
    idempotencyRecordId: id(6),
    before: { existence: 1, revision: 2n, stateDigest: h(5) },
    after: { existence: 1, revision: 3n, stateDigest: h(6) },
    authorizationEvidence: [{ kind: 2, evidenceId: id(7), evidenceDigest: h(7) }],
    outboxEvents: [],
    transitionKind: 1,
    recordedAtNs: 1000n,
    signerId: 'sha256:' + h(8).toString('hex'),
    signerTrustSnapshotDigest: h(9),
    requestDigest: h(10),
  };
  const state = (s: SigningRotationState, history: number): SigningRotationReceiptState => ({
    state: s,
    candidateDigest: h(11),
    historyDigest: h(history),
    signerRole: 'LIFECYCLE_EVIDENCE',
    oldFingerprint: h(12),
    ...(s === 'APPROVED' || (recover && from === 'APPROVED') ? {} : { newFingerprint: h(13) }),
  });
  const before = signingRotationStatePreimage(receipt, 2n, state(from, 14));
  const after = signingRotationStatePreimage(receipt, 3n, state(to, 15));
  return {
    receipt: {
      ...receipt,
      before: { ...receipt.before, stateDigest: hash(before) },
      after: { ...receipt.after, stateDigest: hash(after) },
    },
    before,
    after,
  };
}
function event(type: string): BusinessTransitionReceipt['outboxEvents'][number] {
  return {
    eventId: id(8),
    eventType: type,
    dataSchemaUri: 'https://schemas.openpc.local/event-payloads.schema.json#/$defs/SecretRotated',
    source: 'urn:openpc:service:control-api',
    subject: `urn:openpc:signing-key-rotation:${id(5)}`,
    aggregateSequence: 1n,
    occurredAtNs: 1000n,
    correlationId: id(4),
    payloadDigest: h(16),
  };
}
describe('signing lifecycle v2 profile acceptance', () => {
  it('preserves the key across signed post-cutover failure and emits no event for a governed renewal', () => {
    for (const f of [
      fixture('OLD_REVOKED', 'FAILED'),
      fixture('FAILED', 'RECOVERING', true),
      fixture('PREPARED', 'PREPARED', true),
      fixture('CUTOVER_FENCED', 'CUTOVER_FENCED', true),
      fixture('OLD_REVOKED', 'OLD_REVOKED', true),
    ]) {
      expect(() => validateSigningRotationReceipt(f.receipt, f.before, f.after)).not.toThrow();
      expect(() =>
        validateSigningRotationReceipt(
          { ...f.receipt, outboxEvents: [event('io.openpc.ops.secret.revoked.v1')] },
          f.before,
          f.after,
        ),
      ).toThrow(/cardinality/);
    }
  });
  it('accepts no event for a nonterminal advance and a distinct recovery receipt', () => {
    for (const f of [
      fixture(),
      fixture('APPROVED', 'RECOVERING', true),
      fixture('RECOVERING', 'RECOVERING', true),
    ]) {
      expect(() =>
        validateSigningRotationReceipt(
          decodeReceiptStructureV2(encodeReceiptStructureV2(f.receipt)),
          f.before,
          f.after,
        ),
      ).not.toThrow();
    }
  });
  it.each([
    ['OBSERVING', 'OLD_REVOKED', 'io.openpc.ops.secret.revoked.v1'],
    ['OLD_RETIRED', 'COMPLETE', 'io.openpc.ops.secret.rotated.v1'],
  ] as const)('requires exactly the state-owned terminal event for %s -> %s', (from, to, type) => {
    const f = fixture(from, to);
    expect(() => validateSigningRotationReceipt(f.receipt, f.before, f.after)).toThrow(
      /cardinality/,
    );
    const correct = { ...f.receipt, outboxEvents: [event(type)] };
    expect(() => validateSigningRotationReceipt(correct, f.before, f.after)).not.toThrow();
    expect(() =>
      validateSigningRotationReceipt(
        { ...correct, outboxEvents: [event('io.openpc.control.command.committed.v1')] },
        f.before,
        f.after,
      ),
    ).toThrow(/cardinality/);
    expect(() =>
      validateSigningRotationReceipt(
        { ...correct, outboxEvents: [event(type), event(type)] },
        f.before,
        f.after,
      ),
    ).toThrow(/cardinality/);
  });
  it('rejects extra nonterminal events, recovery advancing state, and profile/digest substitution', () => {
    const f = fixture();
    expect(() =>
      validateSigningRotationReceipt(
        { ...f.receipt, outboxEvents: [event('io.openpc.ops.secret.rotated.v1')] },
        f.before,
        f.after,
      ),
    ).toThrow(/cardinality/);
    const r = fixture('RECOVERING', 'COMPLETE', true);
    expect(() => validateSigningRotationReceipt(r.receipt, r.before, r.after)).toThrow(/Recovery/);
    for (const receipt of [
      { ...f.receipt, schemaDefinitionDigest: h(1) },
      { ...f.receipt, transitionProfileDigest: h(1) },
      { ...f.receipt, transitionProfileVersion: 2 },
      { ...f.receipt, actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' },
    ])
      expect(() => validateSigningRotationReceipt(receipt, f.before, f.after)).toThrow(/profile/);
  });
  it('rejects malformed fingerprint presence even with a recomputed state digest', () => {
    const f = fixture();
    const changes: Array<(p: Map<number, CborValue>) => void> = [
      (p) => p.set(5, 0n),
      (p) => p.delete(6),
      (p) => p.set(6, Buffer.alloc(0)),
      (p) => p.set(6, Buffer.alloc(32)),
      (p) => p.set(6, h(12)),
      (p) => p.set(5, 2n),
      (p) => p.set(7, h(1)),
      (p) => p.set(3, 'UNKNOWN_ROLE'),
    ];
    for (const change of changes) {
      const decoded = decodeCbor(f.after) as CborValue[];
      change(decoded[8] as Map<number, CborValue>);
      const altered = encodeCbor(decoded);
      const receipt = { ...f.receipt, after: { ...f.receipt.after, stateDigest: hash(altered) } };
      expect(() => validateSigningRotationReceipt(receipt, f.before, altered)).toThrow();
    }
  });
  it('rejects scope, revision and unchanged-history substitution', () => {
    const f = fixture();
    expect(() =>
      validateSigningRotationReceipt({ ...f.receipt, privacyDomainId: id(20) }, f.before, f.after),
    ).toThrow(/binding/);
    expect(() =>
      validateSigningRotationReceipt(
        { ...f.receipt, after: { ...f.receipt.after, revision: 4n } },
        f.before,
        f.after,
      ),
    ).toThrow(/binding/);
    const v = decodeCbor(f.after) as CborValue[];
    (v[8] as Map<number, CborValue>).set(2, h(14));
    const altered = encodeCbor(v);
    expect(() =>
      validateSigningRotationReceipt(
        { ...f.receipt, after: { ...f.receipt.after, stateDigest: hash(altered) } },
        f.before,
        altered,
      ),
    ).toThrow(/transition/);
  });
});
