import { createHash } from 'node:crypto';

import { encodeCbor, MAX_UINT64, type CborValue } from './cbor.js';
import { uuidBytes, type StateRef } from './payload.js';

export type { CborValue } from './cbor.js';
export type { StateRef } from './payload.js';

export interface TransitionStateContext {
  readonly profileDigest: Buffer;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly aggregateType: string;
  readonly aggregateId: string;
}

/**
 * Cryptographic state binding only. The owning admitted profile must construct
 * the closed typed projection and validate its legal business transition.
 */
export function transitionStatePreimage(
  context: TransitionStateContext,
  existence: StateRef['existence'],
  revision: bigint,
  typedProjection: ReadonlyMap<number, CborValue>,
): Buffer {
  if (
    !Buffer.isBuffer(context.profileDigest) ||
    context.profileDigest.length !== 32 ||
    typeof context.aggregateType !== 'string' ||
    !/^[a-z][a-z0-9-]{0,62}$/u.test(context.aggregateType) ||
    ![0, 1, 2].includes(existence) ||
    typeof revision !== 'bigint' ||
    revision < 0n ||
    revision > MAX_UINT64 ||
    (existence === 0 && revision !== 0n) ||
    !(typedProjection instanceof Map)
  )
    throw new Error('Invalid transition state binding');
  return encodeCbor([
    'pc.control.transition-state.v1',
    context.profileDigest,
    uuidBytes(context.participantId),
    uuidBytes(context.privacyDomainId),
    context.aggregateType,
    uuidBytes(context.aggregateId),
    existence,
    revision,
    typedProjection,
  ]);
}

export function transitionStateRef(
  context: TransitionStateContext,
  existence: StateRef['existence'],
  revision: bigint,
  typedProjection: ReadonlyMap<number, CborValue>,
): StateRef {
  return {
    existence,
    revision,
    stateDigest: createHash('sha256')
      .update(transitionStatePreimage(context, existence, revision, typedProjection))
      .digest(),
  };
}
