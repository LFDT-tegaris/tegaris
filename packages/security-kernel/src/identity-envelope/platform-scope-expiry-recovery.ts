import { encodeCbor } from '../canonical-cbor.js';
import { authorityEnvelopeDigest } from './codec.js';
import {
  platformEnvelopeScopePreimage,
  type PlatformEnvelopeScopeAdmission,
} from './platform-scope.js';

/** Independently governed local expiry recovery has its own cryptographic
 * domain. It cannot be mistaken for a normal replacement or delegation. */
export interface PlatformEnvelopeScopeExpiryRecovery {
  readonly admission: PlatformEnvelopeScopeAdmission;
  readonly recoveryId: string;
  readonly activationOperationId: string;
  readonly enrollmentDigest: string;
  readonly intentDigest: string;
  readonly predecessorEpoch: string;
  readonly predecessorDigest: string;
}

export const platformEnvelopeScopeExpiryRecoveryDomain =
  'pc.identity.platform-envelope-scope.local-expiry-recovery.v1';

export function platformEnvelopeScopeExpiryRecoveryPreimage(
  value: PlatformEnvelopeScopeExpiryRecovery,
): Buffer {
  const fail = (): never => {
    throw new Error('Platform expiry recovery unavailable');
  };
  const fields = [
    'admission',
    'recoveryId',
    'activationOperationId',
    'enrollmentDigest',
    'intentDigest',
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
    return fail();
  const admission = platformEnvelopeScopePreimage(value.admission);
  const uuid = (id: string) => {
    if (
      typeof id !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(id)
    )
      return fail();
    return Buffer.from(id.replaceAll('-', ''), 'hex');
  };
  const digest = (id: string) => {
    if (typeof id !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(id)) return fail();
    return Buffer.from(id.slice(7), 'hex');
  };
  if (
    typeof value.predecessorEpoch !== 'string' ||
    !/^[1-9][0-9]{0,19}$/u.test(value.predecessorEpoch) ||
    BigInt(value.predecessorEpoch) >= 18446744073709551615n ||
    BigInt(value.admission.platformAuthorityEpoch) !== BigInt(value.predecessorEpoch) + 1n
  )
    return fail();
  return encodeCbor([
    platformEnvelopeScopeExpiryRecoveryDomain,
    1,
    uuid(value.recoveryId),
    uuid(value.activationOperationId),
    digest(value.enrollmentDigest),
    digest(value.intentDigest),
    BigInt(value.predecessorEpoch),
    digest(value.predecessorDigest),
    admission,
  ]);
}

export function platformEnvelopeScopeExpiryRecoveryDigest(
  value: PlatformEnvelopeScopeExpiryRecovery,
): string {
  return authorityEnvelopeDigest(platformEnvelopeScopeExpiryRecoveryPreimage(value));
}
