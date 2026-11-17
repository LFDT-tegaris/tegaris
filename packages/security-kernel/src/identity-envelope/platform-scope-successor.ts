import { encodeCbor } from '../canonical-cbor.js';
import { authorityEnvelopeDigest } from './codec.js';
import {
  platformEnvelopeScopePreimage,
  type PlatformEnvelopeScopeAdmission,
} from './platform-scope.js';

/** A governed successor is distinct from initial installation and delegation.
 * These bytes bind the approved transition; they are never actor permission. */
export interface PlatformEnvelopeScopeSuccessor {
  readonly admission: PlatformEnvelopeScopeAdmission;
  readonly replacementId: string;
  readonly preparationOperationId: string;
  readonly predecessorEpoch: string;
  readonly predecessorDigest: string;
}

export const platformEnvelopeScopeSuccessorDomain =
  'pc.identity.platform-envelope-scope.successor.v1';

export function platformEnvelopeScopeSuccessorPreimage(
  value: PlatformEnvelopeScopeSuccessor,
): Buffer {
  const reject = (): never => {
    throw new Error('Platform envelope scope successor unavailable');
  };
  const fields = [
    'admission',
    'replacementId',
    'preparationOperationId',
    'predecessorEpoch',
    'predecessorDigest',
  ];
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== fields.length ||
    fields.some(
      (key) =>
        !Object.hasOwn(value, key) || !('value' in Object.getOwnPropertyDescriptor(value, key)!),
    )
  )
    return reject();
  // Validate the nested admission before reading it, including executable properties.
  const admission = platformEnvelopeScopePreimage(value.admission);
  const uuid = (id: string) => {
    if (
      typeof id !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(id)
    )
      return reject();
    return Buffer.from(id.replaceAll('-', ''), 'hex');
  };
  if (
    typeof value.predecessorEpoch !== 'string' ||
    !/^[1-9][0-9]{0,19}$/u.test(value.predecessorEpoch) ||
    BigInt(value.predecessorEpoch) >= 18446744073709551615n ||
    BigInt(value.admission.platformAuthorityEpoch) !== BigInt(value.predecessorEpoch) + 1n ||
    typeof value.predecessorDigest !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.predecessorDigest)
  )
    return reject();
  return encodeCbor([
    platformEnvelopeScopeSuccessorDomain,
    1,
    uuid(value.replacementId),
    uuid(value.preparationOperationId),
    BigInt(value.predecessorEpoch),
    Buffer.from(value.predecessorDigest.slice(7), 'hex'),
    admission,
  ]);
}

export function platformEnvelopeScopeSuccessorDigest(
  value: PlatformEnvelopeScopeSuccessor,
): string {
  return authorityEnvelopeDigest(platformEnvelopeScopeSuccessorPreimage(value));
}
