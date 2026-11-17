import { createHash, timingSafeEqual } from 'node:crypto';
import { types as utilityTypes } from 'node:util';

import { z } from 'zod';

import {
  pendingDeliveryActiveStates,
  pendingDeliveryBytes32Schema,
  pendingDeliveryChainIdSchema,
  pendingDeliveryIdentityFields,
  pendingDeliveryInternalActions,
  pendingDeliveryInternalOperations,
  pendingDeliveryLimits,
  pendingDeliveryParticipantIdSchema,
  pendingDeliveryPrivacyDomainIdSchema,
  pendingDeliveryProfileIdSchema,
  pendingDeliveryProfileVersionSchema,
  pendingDeliveryReasonCodes,
  pendingDeliveryStates,
  pendingDeliverySurfaceReferenceRequirements,
  pendingDeliverySurfaces,
  pendingDeliveryUint64Schema,
  pendingDeliveryUuidV7Schema,
  pendingDeliveryUuidFromUrn,
} from '../generated/pending-delivery-projection.js';
import {
  authorityContextSchema,
  canonicalAuthorizationDigest,
  type AuthorityContext,
} from './authorization.js';
import { rfc3339MicrosUtcSchema, sha256DigestSchema } from './primitives.js';

const identityShape = {
  participantId: pendingDeliveryParticipantIdSchema,
  privacyDomainId: pendingDeliveryPrivacyDomainIdSchema,
  chainId: pendingDeliveryChainIdSchema,
  profileId: pendingDeliveryProfileIdSchema,
  profileVersion: pendingDeliveryProfileVersionSchema,
  correlatedLogIdentityHmac: pendingDeliveryBytes32Schema,
  entityHmac: pendingDeliveryBytes32Schema,
  entityScopeDigest: pendingDeliveryBytes32Schema,
  deliverySurface: z.enum(pendingDeliverySurfaces),
  protectedDeliveryReferenceDigest: pendingDeliveryBytes32Schema,
  subscriptionReferenceDigest: pendingDeliveryBytes32Schema.optional(),
  sessionReferenceDigest: pendingDeliveryBytes32Schema.optional(),
} as const;

const identitySchema = z.strictObject(identityShape).superRefine((identity, context) => {
  const subscription = identity.subscriptionReferenceDigest !== undefined;
  const session = identity.sessionReferenceDigest !== undefined;
  const requirements = pendingDeliverySurfaceReferenceRequirements[identity.deliverySurface];
  const valid = subscription === requirements.subscription && session === requirements.session;
  if (!valid) {
    context.addIssue({
      code: 'custom',
      path: ['deliverySurface'],
      message: 'delivery references do not match the delivery surface',
    });
  }
});

function plainOwnDataInput(input: unknown): Record<string, unknown> {
  if (input === null || typeof input !== 'object' || utilityTypes.isProxy(input)) {
    throw new TypeError('pending input must be a plain non-proxy object');
  }
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('pending input must use a plain object prototype');
  }
  const clone: Record<string, unknown> = Object.create(null);
  for (const key of Reflect.ownKeys(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      typeof key === 'symbol' ||
      descriptor === undefined ||
      !('value' in descriptor) ||
      !descriptor.enumerable ||
      descriptor.value === undefined
    ) {
      throw new TypeError('pending input must contain only enumerable string data properties');
    }
    clone[key] = descriptor.value;
  }
  return clone;
}

export type PendingDeliverySurface = (typeof pendingDeliverySurfaces)[number];
export type PendingDeliveryState = (typeof pendingDeliveryStates)[number];
export type PendingDeliveryActiveState = (typeof pendingDeliveryActiveStates)[number];
export type PendingDeliveryReasonCode = (typeof pendingDeliveryReasonCodes)[number];
export type PendingDeliveryIdentityInput = z.input<typeof identitySchema>;
export type PendingDeliveryIdentityValue = z.output<typeof identitySchema>;

function copyIdentity(value: PendingDeliveryIdentityValue): PendingDeliveryIdentityValue {
  return {
    ...value,
    correlatedLogIdentityHmac: Buffer.from(value.correlatedLogIdentityHmac),
    entityHmac: Buffer.from(value.entityHmac),
    entityScopeDigest: Buffer.from(value.entityScopeDigest),
    protectedDeliveryReferenceDigest: Buffer.from(value.protectedDeliveryReferenceDigest),
    ...(value.subscriptionReferenceDigest === undefined
      ? {}
      : { subscriptionReferenceDigest: Buffer.from(value.subscriptionReferenceDigest) }),
    ...(value.sessionReferenceDigest === undefined
      ? {}
      : { sessionReferenceDigest: Buffer.from(value.sessionReferenceDigest) }),
  };
}

function lengthDelimited(value: string | Buffer): Buffer {
  const bytes = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

function identityEncoding(value: PendingDeliveryIdentityValue): Buffer {
  const values: readonly (string | Buffer)[] = pendingDeliveryIdentityFields.map((field) => {
    const candidate = value[field];
    return candidate === undefined ? Buffer.alloc(0) : candidate;
  });
  return Buffer.concat(values.map(lengthDelimited));
}

export class FullyScopedPendingDeliveryIdentity {
  readonly #value: PendingDeliveryIdentityValue;

  private constructor(value: PendingDeliveryIdentityValue) {
    this.#value = copyIdentity(value);
  }

  static create(input: PendingDeliveryIdentityInput): FullyScopedPendingDeliveryIdentity {
    return new FullyScopedPendingDeliveryIdentity(identitySchema.parse(plainOwnDataInput(input)));
  }

  snapshot(): PendingDeliveryIdentityValue {
    return copyIdentity(this.#value);
  }

  persistenceSnapshot(): PendingDeliveryPersistenceIdentity {
    const value = this.snapshot();
    return {
      ...value,
      participantId: pendingDeliveryUuidFromUrn(
        value.participantId,
        pendingDeliveryLimits.participantPrefix,
      ),
      privacyDomainId: pendingDeliveryUuidFromUrn(
        value.privacyDomainId,
        pendingDeliveryLimits.privacyDomainPrefix,
      ),
    };
  }

  equals(other: FullyScopedPendingDeliveryIdentity): boolean {
    const leftEncoding = identityEncoding(this.#value);
    const rightEncoding = identityEncoding(other.#value);
    const left = createHash('sha256').update(leftEncoding).digest();
    const right = createHash('sha256').update(rightEncoding).digest();
    return timingSafeEqual(left, right) && leftEncoding.equals(rightEncoding);
  }
}

export interface PendingDeliveryPersistenceIdentity extends Omit<
  PendingDeliveryIdentityValue,
  'participantId' | 'privacyDomainId'
> {
  readonly participantId: string;
  readonly privacyDomainId: string;
}

const safeScopeSchema = z.strictObject({
  participantId: pendingDeliveryParticipantIdSchema,
  privacyDomainId: pendingDeliveryPrivacyDomainIdSchema,
  chainId: pendingDeliveryChainIdSchema,
  profileId: pendingDeliveryProfileIdSchema,
  profileVersion: pendingDeliveryProfileVersionSchema,
  deliverySurface: z.enum(pendingDeliverySurfaces),
});

export type SafePendingScopeInput = z.input<typeof safeScopeSchema>;
export type SafePendingScopeValue = z.output<typeof safeScopeSchema>;

export class SafePendingScope {
  private constructor(readonly value: SafePendingScopeValue) {}

  static create(input: SafePendingScopeInput): SafePendingScope {
    return new SafePendingScope(Object.freeze(safeScopeSchema.parse(plainOwnDataInput(input))));
  }

  persistenceSnapshot() {
    return {
      ...this.value,
      participantId: pendingDeliveryUuidFromUrn(
        this.value.participantId,
        pendingDeliveryLimits.participantPrefix,
      ),
      privacyDomainId: pendingDeliveryUuidFromUrn(
        this.value.privacyDomainId,
        pendingDeliveryLimits.privacyDomainPrefix,
      ),
    };
  }
}

export const pendingDeliveryReceiptSchema = z.strictObject({
  pendingDeliveryId: pendingDeliveryUuidV7Schema,
  state: z.enum(pendingDeliveryStates),
  replay: z.boolean(),
});
export type PendingDeliveryReceipt = z.infer<typeof pendingDeliveryReceiptSchema>;

export const pendingAgeSummarySchema = z
  .strictObject({
    pendingCount: pendingDeliveryUint64Schema,
    oldestPendingAgeMilliseconds: pendingDeliveryUint64Schema.nullable(),
    asOf: rfc3339MicrosUtcSchema,
  })
  .superRefine((summary, context) => {
    if ((summary.pendingCount === '0') !== (summary.oldestPendingAgeMilliseconds === null)) {
      context.addIssue({
        code: 'custom',
        path: ['oldestPendingAgeMilliseconds'],
        message: 'oldest age is null exactly when the pending count is zero',
      });
    }
  });
export type PendingAgeSummary = z.infer<typeof pendingAgeSummarySchema>;

export const pendingDeliveryAuthorizationInputSchema = z.strictObject({
  operationId: z.literal('ID-OP-AUTH-EVALUATE'),
  actionIntentId: z.literal(pendingDeliveryInternalActions.summary),
  resourceType: z.literal('pending-delivery-scope'),
  participantId: pendingDeliveryParticipantIdSchema,
  privacyDomainId: pendingDeliveryPrivacyDomainIdSchema,
  chainId: pendingDeliveryChainIdSchema,
  profileId: pendingDeliveryProfileIdSchema,
  profileVersion: pendingDeliveryProfileVersionSchema,
  deliverySurface: z.enum(pendingDeliverySurfaces),
});

export function pendingDeliveryAuthorizationInput(scope: SafePendingScope) {
  return Object.freeze(
    pendingDeliveryAuthorizationInputSchema.parse({
      operationId: 'ID-OP-AUTH-EVALUATE',
      actionIntentId: pendingDeliveryInternalActions.summary,
      resourceType: 'pending-delivery-scope',
      ...scope.value,
    }),
  );
}

export function pendingDeliveryAuthorizationInputsDigest(scope: SafePendingScope) {
  return canonicalAuthorizationDigest(pendingDeliveryAuthorizationInput(scope));
}

export interface PendingDeliveryAuthorityRequest {
  readonly authorityContext: AuthorityContext;
  readonly inputsDigest: z.infer<typeof sha256DigestSchema>;
  readonly input: z.infer<typeof pendingDeliveryAuthorizationInputSchema>;
}

export function pendingDeliveryAuthorityRequest(
  scope: SafePendingScope,
  authorityContext: AuthorityContext,
): PendingDeliveryAuthorityRequest {
  const parsedContext = authorityContextSchema.parse(plainOwnDataInput(authorityContext));
  const input = pendingDeliveryAuthorizationInput(scope);
  return Object.freeze({
    authorityContext: Object.freeze(parsedContext),
    inputsDigest: pendingDeliveryAuthorizationInputsDigest(scope),
    input,
  });
}

export { pendingDeliveryInternalActions, pendingDeliveryInternalOperations };
