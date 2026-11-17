import { encodeCbor } from '../canonical-cbor.js';
import { authorityEnvelopeDigest, encodeEnvelopeScope } from './codec.js';
import { identityEnvelopeContext } from './generated.js';
import type { EnvelopeScope } from './types.js';

/** Initial installation metadata, not a new signed artifact or runtime grant.
 * The provenance digest must come from the actual current installation owner. */
export interface PlatformEnvelopeScopeAdmission {
  readonly platformContextId: string;
  readonly ownerParticipantId: string;
  readonly installationPrivacyDomainId: string;
  readonly platformAuthorityEpoch: string;
  readonly environmentId: string;
  readonly installationDigest: string;
  readonly grantable: EnvelopeScope;
}
export const platformEnvelopeScopeDomain = 'pc.identity.platform-envelope-scope.v1';
export function platformEnvelopeScopePreimage(value: PlatformEnvelopeScopeAdmission): Buffer {
  const fields = [
    'platformContextId',
    'ownerParticipantId',
    'installationPrivacyDomainId',
    'platformAuthorityEpoch',
    'environmentId',
    'installationDigest',
    'grantable',
  ];
  const reject = (): never => {
    throw new Error('Platform envelope scope unavailable');
  };
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== fields.length ||
    fields.some(
      (key) =>
        !Object.hasOwn(value, key) || !('value' in Object.getOwnPropertyDescriptor(value, key)!),
    )
  )
    reject();
  const uuid = (input: string) => {
    if (
      typeof input !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(input)
    )
      return reject();
    return Buffer.from(input.replaceAll('-', ''), 'hex');
  };
  if (
    typeof value.platformAuthorityEpoch !== 'string' ||
    typeof value.environmentId !== 'string' ||
    typeof value.installationDigest !== 'string' ||
    !/^[1-9][0-9]{0,19}$/u.test(value.platformAuthorityEpoch) ||
    BigInt(value.platformAuthorityEpoch) > 18446744073709551615n ||
    !/^[a-z][a-z0-9-]{2,31}$/u.test(value.environmentId) ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.installationDigest)
  )
    reject();
  return encodeCbor([
    platformEnvelopeScopeDomain,
    24034,
    1,
    Buffer.from(identityEnvelopeContext.definitionDigest.slice(7), 'hex'),
    uuid(value.platformContextId),
    uuid(value.ownerParticipantId),
    uuid(value.installationPrivacyDomainId),
    BigInt(value.platformAuthorityEpoch),
    value.environmentId,
    Buffer.from(value.installationDigest.slice(7), 'hex'),
    encodeEnvelopeScope(value.grantable),
  ]);
}
export function platformEnvelopeScopeDigest(value: PlatformEnvelopeScopeAdmission): string {
  return authorityEnvelopeDigest(platformEnvelopeScopePreimage(value));
}
