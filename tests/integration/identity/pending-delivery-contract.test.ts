import { describe, expect, it } from 'vitest';

import { buildIdentityService } from '../../../services/identity-service/src/app.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationJson,
} from '../../../services/identity-service/src/contracts/authorization.js';
import {
  FullyScopedPendingDeliveryIdentity,
  pendingAgeSummarySchema,
  pendingDeliveryAuthorizationInput,
  pendingDeliveryAuthorizationInputsDigest,
  pendingDeliveryReceiptSchema,
  SafePendingScope,
} from '../../../services/identity-service/src/contracts/pending-delivery.js';
import {
  pendingDeliveryAuthority,
  pendingDeliveryBytes32Schema,
  pendingDeliveryIdentityFields,
  pendingDeliveryInternalActions,
  pendingDeliveryInternalOperations,
  pendingDeliveryLimits,
  pendingDeliveryProfileVersionSchema,
} from '../../../services/identity-service/src/generated/pending-delivery-projection.js';

const participantUuid = '018f6d4a-1234-7abc-8def-0123456789ab';
const privacyUuid = '018f6d4a-1234-7abc-9def-0123456789ac';
const recordUuid = '018f6d4a-1234-7abc-adef-0123456789ad';
const participantId = `urn:openpc:participant:${participantUuid}`;
const privacyDomainId = `urn:openpc:privacy-domain:${privacyUuid}`;

function identityInput() {
  return {
    participantId,
    privacyDomainId,
    chainId: pendingDeliveryLimits.uint64Maximum,
    profileId: `urn:openpc:profile:${recordUuid}`,
    profileVersion: '1.2.3-alpha..local+proof',
    correlatedLogIdentityHmac: Buffer.alloc(32, 1),
    entityHmac: Buffer.alloc(32, 2),
    entityScopeDigest: Buffer.alloc(32, 3),
    deliverySurface: 'HTTP' as const,
    protectedDeliveryReferenceDigest: Buffer.alloc(32, 4),
  };
}

describe('pending-delivery generated contract boundary', () => {
  it('pins the immutable source, addendum, ordered tuple, and internal identifiers', () => {
    expect(pendingDeliveryAuthority).toEqual({
      sharedSchemaSha256: 'bc1ed970a22ffcdd2cb7ad39f2ac2fab4fbeb77f18c5612972d078832674769a',
      addendumSha256: 'cc7112b5360d8ceb7cc7a1dce959cd799cfd21943e4edcd580cdc0229206f187',
    });
    expect(pendingDeliveryIdentityFields).toEqual([
      'participantId',
      'privacyDomainId',
      'chainId',
      'profileId',
      'profileVersion',
      'correlatedLogIdentityHmac',
      'entityHmac',
      'entityScopeDigest',
      'deliverySurface',
      'protectedDeliveryReferenceDigest',
      'subscriptionReferenceDigest',
      'sessionReferenceDigest',
    ]);
    expect(pendingDeliveryInternalOperations).toEqual({
      enqueue: 'ID-OP-PENDING-DELIVERY-ENQUEUE',
      transition: 'ID-OP-PENDING-DELIVERY-TRANSITION',
    });
    expect(pendingDeliveryInternalActions).toEqual({
      enqueue: 'ACT-IDENTITY_CREATE_PENDING_DELIVERY-V1',
      transition: 'ACT-IDENTITY_UPDATE_PENDING_DELIVERY-V1',
      summary: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    });
  });

  it('accepts the exact primitive language and rejects isolated boundary mutations', () => {
    expect(FullyScopedPendingDeliveryIdentity.create(identityInput()).snapshot()).toMatchObject({
      chainId: pendingDeliveryLimits.uint64Maximum,
      profileVersion: '1.2.3-alpha..local+proof',
    });
    expect(pendingDeliveryProfileVersionSchema.safeParse('01.2.3').success).toBe(false);
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        chainId: '18446744073709551616',
      }),
    ).toThrow();
  });

  it('canonicalizes supported data without aliases, getters, symbols, or descriptor surprises', () => {
    expect(canonicalAuthorizationJson({ b: 2, a: [true, null] })).toBe('{"a":[true,null],"b":2}');
    expect(canonicalAuthorizationJson(Buffer.from([1, 2]))).toBe('{"0":1,"1":2}');
    expect(canonicalAuthorizationJson(new Date('2026-09-05T00:00:00.000Z'))).toBe(
      '"2026-09-05T00:00:00.000Z"',
    );
    expect(canonicalAuthorizationJson(null)).toBe('null');
    expect(() => canonicalAuthorizationJson(undefined)).toThrow();
    expect(() => canonicalAuthorizationJson(Number.NaN)).toThrow();
    expect(() => canonicalAuthorizationJson(Number.POSITIVE_INFINITY)).toThrow();
    expect(() => canonicalAuthorizationJson(-0)).toThrow();
    expect(() => canonicalAuthorizationJson(Symbol('value'))).toThrow();
    expect(() => canonicalAuthorizationJson(1n)).toThrow();
    expect(() => canonicalAuthorizationJson(() => undefined)).toThrow();
    const sparseArray: unknown[] = [];
    sparseArray[0] = 1;
    sparseArray[2] = 3;
    expect(() => canonicalAuthorizationJson(sparseArray)).toThrow();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalAuthorizationJson(cyclic)).toThrow();
    const accessor = {} as Record<string, unknown>;
    let reads = 0;
    Object.defineProperty(accessor, 'value', {
      enumerable: true,
      get() {
        reads += 1;
        return 'secret';
      },
    });
    expect(() => canonicalAuthorizationJson(accessor)).toThrow();
    expect(reads).toBe(0);
    const symbolBearing = { value: 1, [Symbol('hidden')]: 2 };
    expect(() => canonicalAuthorizationJson(symbolBearing)).toThrow();
    const hidden = { value: 1 };
    Object.defineProperty(hidden, 'surprise', { value: 2, enumerable: false });
    expect(() => canonicalAuthorizationJson(hidden)).toThrow();
    expect(canonicalAuthorizationDigest({ value: null })).not.toBe(
      canonicalAuthorizationDigest({ value: 'null' }),
    );
  });

  it('rejects accessor, symbol, non-enumerable, proxy, and explicit-undefined pending inputs before Zod reads', () => {
    const accessor = identityInput() as Record<string, unknown>;
    let reads = 0;
    Object.defineProperty(accessor, 'chainId', {
      enumerable: true,
      get() {
        reads += 1;
        return '1';
      },
    });
    expect(() => FullyScopedPendingDeliveryIdentity.create(accessor as never)).toThrow();
    expect(reads).toBe(0);
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        [Symbol('hidden')]: true,
      }),
    ).toThrow();
    const hidden = identityInput() as Record<string, unknown>;
    Object.defineProperty(hidden, 'surprise', { value: true, enumerable: false });
    expect(() => FullyScopedPendingDeliveryIdentity.create(hidden as never)).toThrow();
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create(
        new Proxy(identityInput(), {}) as ReturnType<typeof identityInput>,
      ),
    ).toThrow();
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        sessionReferenceDigest: undefined,
      }),
    ).toThrow();
  });

  it('admits only closed own-data bytes32 values and copies inspected descriptor bytes', () => {
    let proxyTraps = 0;
    const proxied = new Proxy(Buffer.alloc(32), {
      get() {
        proxyTraps += 1;
        return undefined;
      },
      getOwnPropertyDescriptor() {
        proxyTraps += 1;
        return undefined;
      },
      getPrototypeOf() {
        proxyTraps += 1;
        return Buffer.prototype;
      },
      ownKeys() {
        proxyTraps += 1;
        return [];
      },
    });
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({ ...identityInput(), entityHmac: proxied }),
    ).toThrow();
    expect(proxyTraps).toBe(0);

    const symbolBearing = Buffer.alloc(32);
    Object.defineProperty(symbolBearing, Symbol('hidden'), { enumerable: true, value: 1 });
    expect(pendingDeliveryBytes32Schema.safeParse(symbolBearing).success).toBe(false);

    const enumerableExtra = Buffer.alloc(32);
    Object.defineProperty(enumerableExtra, 'extra', { enumerable: true, value: 1 });
    expect(pendingDeliveryBytes32Schema.safeParse(enumerableExtra).success).toBe(false);

    const hiddenExtra = Buffer.alloc(32);
    Object.defineProperty(hiddenExtra, 'hidden', { enumerable: false, value: 1 });
    expect(pendingDeliveryBytes32Schema.safeParse(hiddenExtra).success).toBe(false);

    const accessorBearing = Buffer.alloc(32);
    let getterReads = 0;
    Object.defineProperty(accessorBearing, 'secret', {
      enumerable: true,
      get() {
        getterReads += 1;
        return 1;
      },
    });
    expect(pendingDeliveryBytes32Schema.safeParse(accessorBearing).success).toBe(false);
    expect(getterReads).toBe(0);

    const alteredPrototype = Buffer.alloc(32);
    Object.setPrototypeOf(alteredPrototype, Object.create(Buffer.prototype));
    expect(pendingDeliveryBytes32Schema.safeParse(alteredPrototype).success).toBe(false);
    expect(pendingDeliveryBytes32Schema.safeParse(Buffer.alloc(31)).success).toBe(false);

    const original = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
    const admitted = pendingDeliveryBytes32Schema.parse(original);
    expect(admitted).not.toBe(original);
    expect(admitted).toEqual(original);
    original[0] = 255;
    expect(admitted[0]).toBe(0);
  });

  it('enforces each surface reference partition and exact 32-byte digests', () => {
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        deliverySurface: 'EMAIL' as 'HTTP',
      }),
    ).toThrow();
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({ ...identityInput(), unknown: true }),
    ).toThrow();
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        subscriptionReferenceDigest: Buffer.alloc(32),
      }),
    ).toThrow();
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        deliverySurface: 'WEBSOCKET',
        subscriptionReferenceDigest: Buffer.alloc(32),
      }),
    ).toThrow();
    expect(() =>
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        deliverySurface: 'INDEXER',
        sessionReferenceDigest: Buffer.alloc(31),
      }),
    ).toThrow();
    expect(
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        deliverySurface: 'WEBSOCKET',
        subscriptionReferenceDigest: Buffer.alloc(32),
        sessionReferenceDigest: Buffer.alloc(32),
      }).snapshot().deliverySurface,
    ).toBe('WEBSOCKET');
    expect(
      FullyScopedPendingDeliveryIdentity.create({
        ...identityInput(),
        deliverySurface: 'INDEXER',
        sessionReferenceDigest: Buffer.alloc(32),
      }).snapshot().deliverySurface,
    ).toBe('INDEXER');
  });

  it('copies mutable bytes and compares the complete ordered identity', () => {
    const input = identityInput();
    const identity = FullyScopedPendingDeliveryIdentity.create(input);
    input.entityHmac[0] = 99;
    const snapshot = identity.snapshot();
    expect(snapshot.entityHmac[0]).toBe(2);
    snapshot.entityHmac[0] = 88;
    expect(identity.snapshot().entityHmac[0]).toBe(2);
    expect(identity.equals(FullyScopedPendingDeliveryIdentity.create(identityInput()))).toBe(true);
    expect(
      identity.equals(
        FullyScopedPendingDeliveryIdentity.create({ ...identityInput(), chainId: '7' }),
      ),
    ).toBe(false);
  });

  it('binds the exact six-field safe scope to the fixed policy action and digest', () => {
    const scope = SafePendingScope.create({
      participantId,
      privacyDomainId,
      chainId: '1',
      profileId: `urn:openpc:profile:${recordUuid}`,
      profileVersion: '1.0.0',
      deliverySurface: 'LOG',
    });
    expect(pendingDeliveryAuthorizationInput(scope)).toEqual({
      operationId: 'ID-OP-AUTH-EVALUATE',
      actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      resourceType: 'pending-delivery-scope',
      ...scope.value,
    });
    expect(pendingDeliveryAuthorizationInputsDigest(scope)).toMatch(/^sha256:[0-9a-f]{64}$/u);
    expect(() => SafePendingScope.create({ ...scope.value, hidden: true })).toThrow();

    const accessorScope = { ...scope.value } as Record<string, unknown>;
    let reads = 0;
    Object.defineProperty(accessorScope, 'profileId', {
      enumerable: true,
      get() {
        reads += 1;
        return scope.value.profileId;
      },
    });
    expect(() => SafePendingScope.create(accessorScope as never)).toThrow();
    expect(reads).toBe(0);
    expect(() => SafePendingScope.create({ ...scope.value, [Symbol('hidden')]: true })).toThrow();
  });

  it('enforces the count/age relation and keeps internal contracts out of the public catalog', async () => {
    expect(
      pendingAgeSummarySchema.safeParse({
        pendingCount: pendingDeliveryLimits.uint64Maximum,
        oldestPendingAgeMilliseconds: pendingDeliveryLimits.uint64Maximum,
        asOf: '2026-09-05T00:00:00.000000Z',
      }).success,
    ).toBe(true);
    expect(
      pendingAgeSummarySchema.safeParse({
        pendingCount: '0',
        oldestPendingAgeMilliseconds: '1',
        asOf: '2026-09-05T00:00:00.000000Z',
      }).success,
    ).toBe(false);
    expect(
      pendingDeliveryReceiptSchema.safeParse({
        pendingDeliveryId: recordUuid,
        state: 'PENDING',
        replay: false,
        firstObservedAt: '2026-09-05T00:00:00.000000Z',
      }).success,
    ).toBe(false);
    expect(
      pendingAgeSummarySchema.safeParse({
        pendingCount: '99999999999999999999',
        oldestPendingAgeMilliseconds: '1',
        asOf: '2026-09-05T00:00:00.000000Z',
      }).success,
    ).toBe(false);
    expect(
      pendingAgeSummarySchema.safeParse({
        pendingCount: '1',
        oldestPendingAgeMilliseconds: '99999999999999999999',
        asOf: '2026-09-05T00:00:00.000000Z',
      }).success,
    ).toBe(false);
    expect(
      pendingAgeSummarySchema.safeParse({
        pendingCount: '1',
        oldestPendingAgeMilliseconds: null,
        asOf: '2026-09-05T00:00:00.000000Z',
      }).success,
    ).toBe(false);

    const app = buildIdentityService();
    try {
      const response = await app.inject({ method: 'GET', url: '/v1/identity/contracts' });
      const serialized = response.body;
      expect(response.statusCode).toBe(200);
      expect(serialized).not.toContain('PENDING-DELIVERY');
      expect(serialized).not.toContain('PendingDelivery');
    } finally {
      await app.close();
    }
  });
});
