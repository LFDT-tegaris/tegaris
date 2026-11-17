import { signingTransitionEffects } from '../../../../packages/security-kernel/src/signing-transitions.js';
import { createHash } from 'node:crypto';
import {
  businessTransitionProfileForOperation,
  type BusinessTransitionReceipt,
} from '@openpc/security-kernel';
import {
  decodeCbor,
  type CborValue,
} from '../../../../packages/security-kernel/src/business-transition/cbor.js';
import { uuidBytes } from '../../../../packages/security-kernel/src/business-transition/payload.js';
import { transitionStatePreimage } from '../../../../packages/security-kernel/src/business-transition/state.js';
import { businessTransitionCoseContextV2 } from '../../../../packages/security-kernel/src/business-transition/generated-v2.js';
import {
  signingRotationActions,
  type SigningRotationState,
  type SigningRotationTargetRole,
} from './signing-rotation.js';

export interface SigningRotationReceiptState {
  readonly state: SigningRotationState;
  readonly candidateDigest: Buffer;
  readonly historyDigest: Buffer;
  readonly signerRole: SigningRotationTargetRole;
  readonly oldFingerprint: Buffer;
  readonly newFingerprint?: Buffer;
}
const states = new Set([
  'REQUESTED',
  'APPROVED',
  'PREPARED',
  'DISTRIBUTED',
  'VERIFIED',
  'CUTOVER_FENCED',
  'OBSERVING',
  'OLD_REVOKED',
  'OLD_RETIRED',
  'COMPLETE',
  'FAILED',
  'RECOVERING',
]);
// Target metadata does not grant the attesting receipt signer purpose 371.
const roles = new Set(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE', 'IDENTITY_ENVELOPE']);
function h32(value: unknown): value is Buffer {
  return Buffer.isBuffer(value) && value.length === 32 && value.some((byte) => byte !== 0);
}
function projection(state: SigningRotationReceiptState): Map<number, CborValue> {
  if (
    !states.has(state.state) ||
    !roles.has(state.signerRole) ||
    !h32(state.candidateDigest) ||
    !h32(state.historyDigest) ||
    !h32(state.oldFingerprint) ||
    (state.newFingerprint !== undefined &&
      (!h32(state.newFingerprint) || state.newFingerprint.equals(state.oldFingerprint)))
  )
    throw new Error('Invalid signing rotation state projection');
  return new Map<number, CborValue>([
    [0, state.state],
    [1, state.candidateDigest],
    [2, state.historyDigest],
    [3, state.signerRole],
    [4, state.oldFingerprint],
    [5, state.newFingerprint === undefined ? 0 : 1],
    ...(state.newFingerprint === undefined
      ? []
      : [[6, state.newFingerprint] as [number, CborValue]]),
  ]);
}
export function signingRotationStatePreimage(
  receipt: Pick<
    BusinessTransitionReceipt,
    'transitionProfileDigest' | 'participantId' | 'privacyDomainId' | 'aggregateId'
  >,
  revision: bigint,
  state: SigningRotationReceiptState,
): Buffer {
  return transitionStatePreimage(
    {
      profileDigest: receipt.transitionProfileDigest,
      participantId: receipt.participantId,
      privacyDomainId: receipt.privacyDomainId,
      aggregateType: 'signing-key-rotation',
      aggregateId: receipt.aggregateId,
    },
    1,
    revision,
    projection(state),
  );
}
function stateFromPreimage(
  receipt: BusinessTransitionReceipt,
  which: 'before' | 'after',
  preimage: Buffer,
): SigningRotationReceiptState {
  const value = decodeCbor(preimage);
  const reference = receipt[which];
  if (
    !Array.isArray(value) ||
    value.length !== 9 ||
    value[0] !== 'pc.control.transition-state.v1' ||
    !Buffer.isBuffer(value[1]) ||
    !value[1].equals(receipt.transitionProfileDigest) ||
    !Buffer.isBuffer(value[2]) ||
    !value[2].equals(uuidBytes(receipt.participantId)) ||
    !Buffer.isBuffer(value[3]) ||
    !value[3].equals(uuidBytes(receipt.privacyDomainId)) ||
    value[4] !== 'signing-key-rotation' ||
    !Buffer.isBuffer(value[5]) ||
    !value[5].equals(uuidBytes(receipt.aggregateId)) ||
    value[6] !== 1n ||
    reference.existence !== 1 ||
    value[7] !== reference.revision ||
    !createHash('sha256').update(preimage).digest().equals(reference.stateDigest)
  )
    throw new Error('Signing rotation state binding mismatch');
  const p = value[8];
  if (
    !(p instanceof Map) ||
    ![6, 7].includes(p.size) ||
    [...p.keys()].some((k) => k < 0 || k > 6) ||
    [0, 1, 2, 3, 4, 5].some((k) => !p.has(k)) ||
    (p.get(5) !== 0n && p.get(5) !== 1n) ||
    (p.get(5) === 1n) !== p.has(6)
  )
    throw new Error('Signing rotation fingerprint presence mismatch');
  const state = {
    state: p.get(0),
    candidateDigest: p.get(1),
    historyDigest: p.get(2),
    signerRole: p.get(3),
    oldFingerprint: p.get(4),
    ...(p.has(6) ? { newFingerprint: p.get(6) } : {}),
  } as SigningRotationReceiptState;
  projection(state);
  return state;
}
/** Profile acceptance in addition to structural v2 decoding. Database history remains authoritative. */
export function validateSigningRotationReceipt(
  receipt: BusinessTransitionReceipt,
  beforePreimage: Buffer,
  afterPreimage: Buffer,
): void {
  const profile = businessTransitionProfileForOperation(receipt.catalogOperationId);
  if (
    profile === undefined ||
    !['pc.control.signing-rotation.advance', 'pc.control.signing-rotation.recover'].includes(
      profile.profileId,
    ) ||
    receipt.transitionProfileId !== profile.profileId ||
    receipt.transitionProfileVersion !== profile.profileVersion ||
    !receipt.transitionProfileDigest.equals(Buffer.from(profile.profileDigest.slice(7), 'hex')) ||
    !receipt.schemaDefinitionDigest.equals(
      Buffer.from(businessTransitionCoseContextV2.definitionDigest.slice(7), 'hex'),
    ) ||
    receipt.actionIntentId !== profile.actionIntentId ||
    receipt.aggregateType !== 'signing-key-rotation' ||
    receipt.transitionKind !== profile.transitionKind
  )
    throw new Error('Signing rotation receipt profile mismatch');
  const before = stateFromPreimage(receipt, 'before', beforePreimage);
  const after = stateFromPreimage(receipt, 'after', afterPreimage);
  if (
    receipt.after.revision !== receipt.before.revision + 1n ||
    !before.candidateDigest.equals(after.candidateDigest) ||
    before.signerRole !== after.signerRole ||
    !before.oldFingerprint.equals(after.oldFingerprint) ||
    before.historyDigest.equals(after.historyDigest) ||
    (before.newFingerprint !== undefined &&
      !before.newFingerprint.equals(after.newFingerprint ?? Buffer.alloc(0)))
  )
    throw new Error('Signing rotation receipt transition mismatch');
  const effects = signingTransitionEffects(receipt.actionIntentId, before.state, after.state);
  if (!effects)
    throw new Error(
      receipt.actionIntentId === signingRotationActions.recover
        ? 'Recovery cannot commit an advance effect'
        : 'Invalid rotation advance transition',
    );
  if (
    !effects.prepare &&
    (before.newFingerprint === undefined
      ? after.newFingerprint !== undefined
      : !before.newFingerprint.equals(after.newFingerprint ?? Buffer.alloc(0)))
  )
    throw new Error('Signing rotation effect cannot change key presence');
  const expected = effects.eventType;
  if (
    expected === null
      ? receipt.outboxEvents.length !== 0
      : receipt.outboxEvents.length !== 1 || receipt.outboxEvents[0]?.eventType !== expected
  )
    throw new Error('Signing rotation receipt event cardinality mismatch');
}
