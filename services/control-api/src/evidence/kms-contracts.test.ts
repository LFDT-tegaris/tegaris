import { generateKeyPairSync } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import {
  decodeCbor,
  encodeCbor,
  type CborValue,
} from '../../../../packages/security-kernel/src/canonical-cbor.js';
import { signConsumerCose } from '../../../../packages/security-kernel/src/fact-consumer/cose-framing.js';
import { evidenceKmsCoseProfiles } from '../../../../packages/security-kernel/src/evidence-kms/generated.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import {
  EvidenceKmsError,
  evidenceKmsRecipientRequest,
  parseEvidenceKms,
  validateEvidenceKmsInstallation,
  verifyEvidenceKmsResponse,
  evidenceKmsReceiptBytes,
  verifyStoredEvidenceKmsStatus,
  verifyStoredEvidenceWrappedKey,
  type EvidenceKmsExpectedResponse,
  type EvidenceKmsExpectedDestructionResponse,
} from './kms-contracts.js';
import {
  signEvidenceKmsClaim,
  encodeEvidenceKmsResponse,
  evidenceKmsAbsentDigest,
  type EvidenceKmsProfileClaims,
  type EvidenceWrappedKeyClaims,
  type EvidenceKmsReceiptClaims,
  decodeEvidenceKmsResponse,
} from '../../../../packages/security-kernel/src/evidence-kms/codec.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const digest = (n: string) => `sha256:${n.repeat(64)}`;
const publicKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  .publicKey.export({ type: 'spki', format: 'der' })
  .toString('hex');
const pins = {
  owner: 'LS-EVIDENCE-EXPORT',
  secretClass: 'SECRET-EVIDENCE-VAULT',
  environmentId: 'local-kms',
  participantId: id(1),
  privacyDomainId: id(2),
  installationId: id(3),
  producerTrustDigest: digest('1'),
  reference: 'secret://test-kms/evidence/kek#v1',
  version: 'v1',
  keyEpoch: '1',
  providerId: 'test-kms',
  providerOrigin: 'https://localhost:4433',
  providerTlsSpkiDigest: digest('2'),
  profileIssuerSpkiHex: generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .publicKey.export({ type: 'spki', format: 'der' })
    .toString('hex'),
  providerReceiptSpkiHex: publicKey,
  recoveryAuthoritySpkiHex: generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .publicKey.export({ type: 'spki', format: 'der' })
    .toString('hex'),
  providerKeyId: 'evidence-kek',
  providerKeyVersion: 'v1',
  wrapProfileDigest: digest('3'),
  policyDigest: digest('4'),
  recoveryProfileDigest: digest('5'),
  profileDigest: digest('6'),
  permissions: ['DECRYPT', 'ENCRYPT'],
  validFromMs: 1800000000000,
  validUntilMs: 1800000060000,
};

it('retains the whole purpose-bound public trust tuple without declaring it admitted', () => {
  const result = validateEvidenceKmsInstallation(pins);
  expect(result.pins).toEqual(pins);
  expect(result.bytes).toEqual(Buffer.from(canonicalJson(pins)));
  expect(result.digest).toBe(sha256(result.bytes));
  expect(result).not.toHaveProperty('admitted');
  for (const patch of [
    { participantId: id(9) },
    { privacyDomainId: id(9) },
    { installationId: id(9) },
    { producerTrustDigest: digest('9') },
    { keyEpoch: '2' },
    { reference: 'secret://test-kms/evidence/kek#v2', version: 'v2' },
    { providerKeyVersion: 'v2' },
    { policyDigest: digest('9') },
    { recoveryProfileDigest: digest('9') },
    { providerTlsSpkiDigest: digest('9') },
    { permissions: ['DECRYPT'] },
    { validUntilMs: pins.validUntilMs + 1 },
  ])
    expect(validateEvidenceKmsInstallation({ ...pins, ...patch }).digest).not.toBe(result.digest);
});

it('rejects cross-purpose, alias, transport, key, epoch and unbounded installation inputs', () => {
  const otherKey = generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
    .publicKey.export({ type: 'spki', format: 'der' })
    .toString('hex');
  for (const patch of [
    { owner: 'LS-NOTIFICATION' },
    { owner: 'LS-FACT-BRIDGE' },
    { secretClass: 'SECRET-SIGNING-KEY' },
    { installed: true },
    { admitted: true },
    { status: 'ACTIVE' },
    { privateKey: 'PRIVATE_CANARY' },
    { kekBytes: 'PRIVATE_CANARY' },
    { reference: 'secret://test-kms/evidence#latest', version: 'latest' },
    { reference: 'secret://test-kms/evidence#CURRENT', version: 'CURRENT' },
    { reference: 'secret://test-kms/../evidence#v1' },
    { reference: 'secret://test-kms/evidence//key#v1' },
    { reference: 'secret://test-kms/evidence/..#v1' },
    { reference: 'secret://other-provider/evidence#v1' },
    { version: 'v2' },
    { providerKeyVersion: 'current' },
    { providerKeyVersion: ' latest' },
    { providerOrigin: 'http://localhost:4433' },
    { providerOrigin: 'https://localhost:4433/' },
    { providerOrigin: 'https://user:password@localhost' },
    { providerOrigin: 'https://localhost?x=y' },
    { providerOrigin: 'https://localhost/#fragment' },
    { providerOrigin: 'https://localhost/path' },
    { providerOrigin: 'https://LOCALHOST' },
    { providerReceiptSpkiHex: otherKey },
    { providerReceiptSpkiHex: '00'.repeat(91) },
    { recoveryAuthoritySpkiHex: otherKey },
    { providerTlsSpkiDigest: digest('A') },
    { keyEpoch: '0' },
    { keyEpoch: '01' },
    { keyEpoch: '18446744073709551616' },
    { validFromMs: -0 },
    { validFromMs: -1 },
    { validUntilMs: pins.validFromMs },
    { validUntilMs: Number.MAX_SAFE_INTEGER + 1 },
    { validUntilMs: Infinity },
    { permissions: [] },
    { permissions: ['ENCRYPT', 'ENCRYPT'] },
    { permissions: ['ENCRYPT', 'DECRYPT'] },
    { permissions: ['DESTROY'] },
    { participantId: `${id(1)}\n` },
    { environmentId: 'local\n' },
    { providerKeyId: 'x'.repeat(257) },
    { providerKeyId: 'é'.repeat(129) },
    { providerKeyId: 'e\u0301' },
  ])
    expect(() => validateEvidenceKmsInstallation({ ...pins, ...patch })).toThrow(EvidenceKmsError);
  for (const field of Object.keys(pins)) {
    const missing: Record<string, unknown> = { ...pins };
    delete missing[field];
    expect(() => validateEvidenceKmsInstallation(missing)).toThrow('OPS_SECRET_UNRESOLVED');
  }
});

it('does not invoke accessors or accept inherited/nonenumerable authority', () => {
  let calls = 0;
  const accessor = { ...pins };
  Object.defineProperty(accessor, 'owner', {
    enumerable: true,
    get() {
      calls++;
      return pins.owner;
    },
  });
  expect(() => validateEvidenceKmsInstallation(accessor)).toThrow('OPS_SECRET_UNRESOLVED');
  expect(calls).toBe(0);
  expect(() => validateEvidenceKmsInstallation(Object.create(pins))).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  const hidden = { ...pins };
  Object.defineProperty(hidden, 'admitted', { value: true, enumerable: false });
  expect(() => validateEvidenceKmsInstallation(hidden)).toThrow('OPS_SECRET_UNRESOLVED');
  expect(() => validateEvidenceKmsInstallation({ ...pins, [Symbol('authority')]: true })).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  const permissions = new Array(1);
  Object.setPrototypeOf(
    permissions,
    Object.defineProperty([], '0', {
      get() {
        calls++;
        return 'ENCRYPT';
      },
    }),
  );
  expect(() => validateEvidenceKmsInstallation({ ...pins, permissions })).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  expect(calls).toBe(0);
  expect(() => validateEvidenceKmsInstallation({ ...pins, permissions: new Array(1) })).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  expect(() =>
    validateEvidenceKmsInstallation({
      ...pins,
      permissions: Object.assign(['ENCRYPT'], { admitted: true }),
    }),
  ).toThrow('OPS_SECRET_UNRESOLVED');
  expect(() =>
    validateEvidenceKmsInstallation(
      new Proxy(pins, {
        ownKeys() {
          throw new Error('PRIVATE_CANARY');
        },
      }),
    ),
  ).toThrow('OPS_SECRET_UNRESOLVED');
});

it('request scope cannot smuggle a key, provider descriptor or recipient purpose', () => {
  const request = {
    participantId: id(1),
    privacyDomainId: id(2),
    producerTrustDigest: digest('1'),
    installationDigest: digest('2'),
  };
  expect(parseEvidenceKms(evidenceKmsRecipientRequest, request)).toEqual(request);
  for (const patch of [
    { bytes: 'PRIVATE_CANARY' },
    { provider: pins },
    { use: 'DESTROY' },
    { consumer: 'LS-FACT-BRIDGE' },
    { purpose: 'POSTGRES_CONNECT' },
    { revoked: false },
  ])
    expect(() => parseEvidenceKms(evidenceKmsRecipientRequest, { ...request, ...patch })).toThrow(
      'OPS_SECRET_UNRESOLVED',
    );
});

it('errors carry only the bounded failure classification', () => {
  expect(new EvidenceKmsError('REVOKED').message).toBe('OPS_SECRET_REVOKED');
  for (const code of [
    'INVALID',
    'UNAVAILABLE',
    'SCOPE',
    'STALE',
    'INTEGRITY',
    'CONFLICT',
    'UNKNOWN',
  ] as const) {
    const error = new EvidenceKmsError(code);
    expect(error.message).toBe('OPS_SECRET_UNRESOLVED');
    expect(error).not.toHaveProperty('cause');
    expect(JSON.stringify(error)).not.toContain('PRIVATE_CANARY');
  }
});

function providerResponse(
  patch: {
    status?: boolean;
    destroy?: boolean;
    signedCurrentDestroy?: boolean;
    receipt?: Partial<EvidenceKmsReceiptClaims>;
    recovery?: Partial<EvidenceKmsReceiptClaims>;
    record?: Partial<EvidenceWrappedKeyClaims>;
    wrongProviderSigner?: boolean;
    wrongRecoverySigner?: boolean;
  } = {},
) {
  const key = () => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    return {
      privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
      spki: pair.publicKey.export({ type: 'spki', format: 'der' }),
    };
  };
  const issuer = key(),
    provider = key(),
    recovery = key(),
    outsider = key();
  const installed = validateEvidenceKmsInstallation({
    ...pins,
    profileIssuerSpkiHex: issuer.spki.toString('hex'),
    providerReceiptSpkiHex: provider.spki.toString('hex'),
    recoveryAuthoritySpkiHex: recovery.spki.toString('hex'),
  }).pins;
  const scope = {
    environmentId: installed.environmentId,
    participantId: installed.participantId,
    privacyDomainId: installed.privacyDomainId,
  };
  const descriptor = {
    providerId: installed.providerId,
    reference: installed.reference,
    version: installed.version,
    providerKeyId: installed.providerKeyId,
    providerKeyVersion: installed.providerKeyVersion,
    keyEpoch: installed.keyEpoch,
    wrapProfileDigest: installed.wrapProfileDigest,
    policyDigest: installed.policyDigest,
    recoveryProfileDigest: installed.recoveryProfileDigest,
  };
  const profileClaims: EvidenceKmsProfileClaims = {
    ...scope,
    ...descriptor,
    profileId: installed.installationId,
    revision: '1',
    producerTrustDigest: installed.producerTrustDigest,
    owner: installed.owner,
    secretClass: installed.secretClass,
    providerOrigin: installed.providerOrigin,
    providerTlsSpkiDigest: installed.providerTlsSpkiDigest,
    receiptKeyId: sha256(provider.spki),
    recoveryKeyId: sha256(recovery.spki),
    permissions: 'ENCRYPT_AND_DECRYPT',
    kekExportPolicy: 'NON_EXPORTABLE',
    recoveryMode: 'THRESHOLD_ESCROW',
    validFromMs: installed.validFromMs,
    validUntilMs: installed.validUntilMs,
    issuerKeyId: sha256(issuer.spki),
  };
  const profile = signEvidenceKmsClaim(
    'EvidenceKmsProfileV1',
    issuer.privateKey,
    issuer.spki,
    profileClaims,
  );
  installed.profileDigest = sha256(profile.cose);
  const recordClaims: EvidenceWrappedKeyClaims = {
    ...scope,
    ...descriptor,
    attemptId: id(10),
    originalRequestDigest: digest('a'),
    objectIntentDigest: digest('b'),
    profileDigest: installed.profileDigest,
    wrappedKey: 'a1'.repeat(60),
    createdAtMs: installed.validFromMs + 1000,
    signerKeyId: sha256(provider.spki),
    ...patch.record,
  };
  const record = signEvidenceKmsClaim(
    'EvidenceWrappedKeyRecordV1',
    provider.privateKey,
    provider.spki,
    recordClaims,
  );
  const material = Buffer.alloc(32, 0x5a),
    nowMs = installed.validFromMs + 2000;
  const expected: EvidenceKmsExpectedResponse = {
    operation: patch.destroy ? 'DESTROY' : patch.status ? 'STATUS' : 'UNWRAP',
    attemptId: id(10),
    exchangeId: id(11),
    requestDigest: digest('c'),
    originalRequestDigest: digest('a'),
    objectIntentDigest: digest('b'),
    challenge: 'ab'.repeat(32),
    keyId: sha256(record.payload),
    keyUse: patch.status || patch.destroy ? 'NONE' : 'DECRYPT',
    nowMs,
    minimumSequence: '2',
    minimumRecoveryFloor: '2',
  };
  const common = {
    ...scope,
    ...descriptor,
    profileDigest: installed.profileDigest,
    attemptId: expected.attemptId,
    exchangeId: expected.exchangeId,
    requestDigest: expected.requestDigest,
    challenge: expected.challenge,
    objectIntentDigest: expected.objectIntentDigest,
    keyId: expected.keyId,
    keyState: patch.destroy
      ? ('DESTROYED' as const)
      : patch.status
        ? ('CURRENT' as const)
        : ('RETAINED' as const),
    providerSequence: '2',
    recoveryFloor: '2',
    observedAtMs: nowMs - 1,
    validUntilMs: nowMs + 3000,
  };
  const providerKey = patch.wrongProviderSigner ? outsider : provider,
    recoveryKey = patch.wrongRecoverySigner ? provider : recovery;
  let receipt = signEvidenceKmsClaim(
    'EvidenceKmsReceiptV1',
    providerKey.privateKey,
    providerKey.spki,
    {
      ...common,
      receiptId: id(12),
      operation: patch.destroy ? 'DESTROY' : patch.status ? 'STATUS' : 'UNWRAP',
      keyUse: patch.status || patch.destroy ? 'NONE' : 'DECRYPT',
      outcome: 'PROVED',
      materialDigest: patch.status || patch.destroy ? evidenceKmsAbsentDigest : sha256(material),
      signerKeyId: sha256(providerKey.spki),
      ...patch.receipt,
    },
  );
  if (patch.signedCurrentDestroy) {
    const context = evidenceKmsCoseProfiles.EvidenceKmsReceiptV1;
    const state = context.fields.find((field) => field.name === 'keyState')!;
    const current = state.type
      .split(' ')
      .slice(1)
      .find((entry) => entry.startsWith('CURRENT='))!;
    const map = decodeCbor(receipt.payload) as Map<number, CborValue>;
    map.set(state.key, BigInt(current.split('=')[1]!));
    const payload = encodeCbor(map);
    receipt = {
      payload,
      cose: signConsumerCose(context, providerKey.privateKey, providerKey.spki, payload),
    };
  }
  const recoveryReceipt = signEvidenceKmsClaim(
    'EvidenceKmsReceiptV1',
    recoveryKey.privateKey,
    recoveryKey.spki,
    {
      ...common,
      receiptId: id(13),
      operation: 'RECOVERY_FLOOR',
      keyUse: 'NONE',
      outcome: 'PROVED',
      materialDigest: evidenceKmsAbsentDigest,
      signerKeyId: sha256(recoveryKey.spki),
      ...patch.recovery,
    },
  );
  const wire = encodeEvidenceKmsResponse({
    profile,
    record,
    receipt,
    recovery: recoveryReceipt,
    material: patch.status || patch.destroy ? Buffer.alloc(0) : material,
  });
  material.fill(0);
  issuer.privateKey.fill(0);
  provider.privateKey.fill(0);
  recovery.privateKey.fill(0);
  outsider.privateKey.fill(0);
  return { installed, expected, wire };
}

function retainedStatus(patch: Parameters<typeof providerResponse>[0] = {}) {
  const sample = providerResponse({ ...patch, status: true });
  const response = decodeEvidenceKmsResponse(sample.wire);
  const pair = (p: { payload: Buffer; cose: Buffer }) => ({
    payloadHex: p.payload.toString('hex'),
    coseHex: p.cose.toString('hex'),
  });
  const stored = Buffer.from(
    canonicalJson({
      profile: pair(response.profile),
      receipt: pair(response.receipt),
      record: pair(response.record),
      recovery: pair(response.recovery),
    }),
  );
  return { ...sample, response, stored };
}

it('rechecks original signed STATUS and wrapped-key bindings without returning material', () => {
  const s = retainedStatus();
  expect(verifyStoredEvidenceKmsStatus(s.stored, s.installed, s.expected)).toMatchObject({
    operation: 'STATUS',
    keyState: 'CURRENT',
  });
  expect(
    verifyStoredEvidenceWrappedKey(
      s.response.record.payload,
      s.response.record.cose,
      s.installed,
      s.expected,
    ),
  ).toMatchObject({ attemptId: s.expected.attemptId });
  expect(verifyStoredEvidenceKmsStatus(s.stored, s.installed, s.expected)).not.toHaveProperty(
    'material',
  );
  for (const patch of [
    { nowMs: s.expected.nowMs + 3000 },
    { keyId: digest('d') },
    { attemptId: id(99) },
    { exchangeId: id(99) },
    { challenge: 'cc'.repeat(32) },
    { requestDigest: digest('d') },
    { minimumSequence: '3' },
    { minimumRecoveryFloor: '3' },
  ])
    expect(() =>
      verifyStoredEvidenceKmsStatus(s.stored, s.installed, { ...s.expected, ...patch }),
    ).toThrow(EvidenceKmsError);
  for (const patch of [
    { keyId: digest('d') },
    { attemptId: id(99) },
    { originalRequestDigest: digest('d') },
    { objectIntentDigest: digest('d') },
  ])
    expect(() =>
      verifyStoredEvidenceWrappedKey(
        s.response.record.payload,
        s.response.record.cose,
        s.installed,
        { ...s.expected, ...patch },
      ),
    ).toThrow(EvidenceKmsError);
});

it('denies retained, revoked, destroyed, unknown and wrongly signed status observations', () => {
  for (const keyState of ['RETAINED', 'REVOKED', 'DESTROYED'] as const) {
    const s = retainedStatus({ receipt: { keyState }, recovery: { keyState } });
    expect(() => verifyStoredEvidenceKmsStatus(s.stored, s.installed, s.expected)).toThrow(
      EvidenceKmsError,
    );
  }
  for (const patch of [
    { receipt: { outcome: 'UNKNOWN' as const } },
    { wrongProviderSigner: true },
    { wrongRecoverySigner: true },
  ]) {
    const s = retainedStatus(patch);
    expect(() => verifyStoredEvidenceKmsStatus(s.stored, s.installed, s.expected)).toThrow(
      EvidenceKmsError,
    );
  }
});

it('denies material-bearing, noncanonical and foreign stored status without leaking diagnostics', () => {
  const s = retainedStatus();
  const value = JSON.parse(s.stored.toString('utf8'));
  for (const bytes of [
    Buffer.from(canonicalJson({ ...value, material: 'PRIVATE_CANARY' })),
    Buffer.from(JSON.stringify(value, null, 2)),
    Buffer.from('PRIVATE_CANARY'),
    Buffer.alloc(262145),
  ])
    expect(() => verifyStoredEvidenceKmsStatus(bytes, s.installed, s.expected)).toThrow(
      'OPS_SECRET_UNRESOLVED',
    );
  expect(() =>
    verifyStoredEvidenceKmsStatus(s.stored, { ...s.installed, participantId: id(99) }, s.expected),
  ).toThrow(EvidenceKmsError);
  expect(() =>
    verifyStoredEvidenceKmsStatus(s.stored, s.installed, {
      ...s.expected,
      operation: 'UNWRAP',
      keyUse: 'DECRYPT',
    }),
  ).toThrow(EvidenceKmsError);
});

it('verifies installed roles and fresh exact provider/recovery binding before exposing transient material', () => {
  const sample = providerResponse();
  const verified = verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected);
  try {
    expect(verified.response.material).toEqual(Buffer.alloc(32, 0x5a));
    expect(verified.receipt.keyState).toBe('RETAINED');
    const stored = JSON.parse(evidenceKmsReceiptBytes(verified).toString('utf8'));
    expect(Object.keys(stored).sort()).toEqual(['profile', 'receipt', 'record', 'recovery']);
    expect(stored).not.toHaveProperty('material');
  } finally {
    verified.response.material.fill(0);
    sample.wire.fill(0);
  }
});

it('rejects correctly signed responses for another scope, object, nonce, request, key version or policy', () => {
  const changes: Partial<EvidenceKmsReceiptClaims>[] = [
    { participantId: id(99) },
    { privacyDomainId: id(99) },
    { attemptId: id(99) },
    { exchangeId: id(99) },
    { requestDigest: digest('9') },
    { challenge: 'ff'.repeat(32) },
    { objectIntentDigest: digest('9') },
    { profileDigest: digest('9') },
    { keyId: digest('9') },
    { providerKeyVersion: 'v2' },
    { policyDigest: digest('9') },
    { keyEpoch: '2' },
    { observedAtMs: pins.validFromMs - 10000, validUntilMs: pins.validFromMs - 6000 },
  ];
  for (const receipt of changes) {
    const sample = providerResponse({ receipt });
    try {
      expect(() =>
        verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected),
      ).toThrow('OPS_SECRET_UNRESOLVED');
    } finally {
      sample.wire.fill(0);
    }
  }
});

it('a current signed provider result cannot substitute for an independently signed recovery floor', () => {
  for (const change of [
    { wrongProviderSigner: true },
    { wrongRecoverySigner: true },
    { recovery: { providerSequence: '3', recoveryFloor: '3' } },
    { recovery: { challenge: 'fe'.repeat(32) } },
    { recovery: { keyState: 'REVOKED' as const } },
    { receipt: { providerSequence: '1', recoveryFloor: '1' } },
  ]) {
    const sample = providerResponse(change);
    try {
      expect(() =>
        verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected),
      ).toThrow('OPS_SECRET_UNRESOLVED');
    } finally {
      sample.wire.fill(0);
    }
  }
});

it('historical wrapped-key authenticity cannot hide changed original intent or permit a retained key for encryption', () => {
  for (const record of [
    { originalRequestDigest: digest('9') },
    { objectIntentDigest: digest('9') },
    { attemptId: id(99) },
  ]) {
    const sample = providerResponse({ record });
    try {
      expect(() =>
        verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected),
      ).toThrow('OPS_SECRET_UNRESOLVED');
    } finally {
      sample.wire.fill(0);
    }
  }
  const sample = providerResponse();
  try {
    expect(() =>
      verifyEvidenceKmsResponse(sample.wire, sample.installed, {
        ...sample.expected,
        keyUse: 'ENCRYPT',
      }),
    ).toThrow('OPS_SECRET_UNRESOLVED');
  } finally {
    sample.wire.fill(0);
  }
});

it('rejects expired authority, future or overlong receipts, and tampered material before use', () => {
  for (const receipt of [
    { observedAtMs: pins.validFromMs + 2001 },
    { validUntilMs: pins.validFromMs + 2000 },
    { observedAtMs: pins.validFromMs + 1000, validUntilMs: pins.validFromMs + 7000 },
    { materialDigest: digest('9') },
  ]) {
    const sample = providerResponse({ receipt });
    try {
      expect(() =>
        verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected),
      ).toThrow('OPS_SECRET_UNRESOLVED');
    } finally {
      sample.wire.fill(0);
    }
  }
  const sample = providerResponse();
  try {
    expect(() =>
      verifyEvidenceKmsResponse(sample.wire, sample.installed, {
        ...sample.expected,
        nowMs: sample.installed.validUntilMs,
      }),
    ).toThrow('OPS_SECRET_UNRESOLVED');
  } finally {
    sample.wire.fill(0);
  }
});

it('verifies exact-key destruction observations without changing creation identity or granting authority', () => {
  for (const outcome of ['PROVED', 'UNKNOWN', 'REJECTED'] as const) {
    const states =
      outcome === 'PROVED'
        ? (['DESTROYED'] as const)
        : (['CURRENT', 'RETAINED', 'REVOKED', 'DESTROYED'] as const);
    for (const keyState of states) {
      const sample = providerResponse({
        destroy: true,
        receipt: { outcome, keyState },
        recovery: { keyState },
      });
      const expected: EvidenceKmsExpectedDestructionResponse = {
        ...sample.expected,
        operation: 'DESTROY',
        keyUse: 'NONE',
      };
      const originalExpected = structuredClone(expected);
      const verified = verifyEvidenceKmsResponse(sample.wire, sample.installed, expected);
      expect(verified.receipt).toMatchObject({
        operation: 'DESTROY',
        outcome,
        keyState,
        keyId: expected.keyId,
        keyUse: 'NONE',
        materialDigest: evidenceKmsAbsentDigest,
      });
      expect(verified.record).toMatchObject({
        attemptId: expected.attemptId,
        originalRequestDigest: expected.originalRequestDigest,
        objectIntentDigest: expected.objectIntentDigest,
      });
      expect(verified.response.material.length).toBe(0);
      expect(Object.keys(verified).sort()).toEqual([
        'profile',
        'receipt',
        'record',
        'recovery',
        'response',
      ]);
      expect(expected).toEqual(originalExpected);
      const stored = JSON.parse(evidenceKmsReceiptBytes(verified).toString()) as Record<
        string,
        { payloadHex: string; coseHex: string }
      >;
      expect(stored.receipt).toEqual({
        payloadHex: verified.response.receipt.payload.toString('hex'),
        coseHex: verified.response.receipt.cose.toString('hex'),
      });
      expect(() =>
        verifyStoredEvidenceKmsStatus(
          evidenceKmsReceiptBytes(verified),
          sample.installed,
          expected,
        ),
      ).toThrow('OPS_SECRET_UNRESOLVED');
    }
  }
});

it('binds every destruction signed family to the installed scope, provider and profile', () => {
  const changes = [
    { environmentId: 'other-kms' },
    { participantId: id(99) },
    { privacyDomainId: id(99) },
    { providerId: 'other-kms', reference: 'secret://other-kms/evidence/kek#v1' },
    { reference: 'secret://test-kms/other#v1' },
    { version: 'v2', reference: 'secret://test-kms/evidence/kek#v2' },
    { providerKeyId: 'other-key' },
    { providerKeyVersion: 'v2' },
    { keyEpoch: '2' },
    { wrapProfileDigest: digest('9') },
    { policyDigest: digest('9') },
    { recoveryProfileDigest: digest('9') },
    { profileDigest: digest('9') },
  ];
  for (const family of ['receipt', 'recovery', 'record'] as const) {
    for (const change of changes) {
      const sample = providerResponse({ destroy: true, [family]: change });
      expect(() =>
        verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected),
      ).toThrow('OPS_SECRET_UNRESOLVED');
    }
  }
  const sample = providerResponse({ destroy: true });
  for (const change of [
    { installationId: id(99) },
    { producerTrustDigest: digest('9') },
    { profileDigest: digest('9') },
    { providerOrigin: 'https://other.example' },
    { providerTlsSpkiDigest: digest('9') },
    { permissions: ['ENCRYPT'] as const },
    { profileIssuerSpkiHex: pins.profileIssuerSpkiHex },
    { recoveryAuthoritySpkiHex: sample.installed.providerReceiptSpkiHex },
  ]) {
    expect(() =>
      verifyEvidenceKmsResponse(
        sample.wire,
        { ...sample.installed, ...change } as typeof sample.installed,
        sample.expected,
      ),
    ).toThrow('OPS_SECRET_UNRESOLVED');
  }
});

it('binds destruction observations and recovery to the original creation request and fresh exchange', () => {
  for (const family of ['receipt', 'recovery'] as const) {
    for (const change of [
      { operation: 'STATUS' as const },
      { attemptId: id(99) },
      { exchangeId: id(99) },
      { requestDigest: digest('9') },
      { objectIntentDigest: digest('9') },
      { challenge: 'ff'.repeat(32) },
      { keyId: digest('9') },
      { providerSequence: '1', recoveryFloor: '1' },
      { observedAtMs: pins.validFromMs + 2001 },
      { validUntilMs: pins.validFromMs + 2000 },
      { observedAtMs: pins.validFromMs - 5000, validUntilMs: pins.validFromMs - 1000 },
      { validUntilMs: pins.validFromMs + 8000 },
    ]) {
      const sample = providerResponse({ destroy: true, [family]: change });
      expect(() =>
        verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected),
      ).toThrow('OPS_SECRET_UNRESOLVED');
    }
  }
  for (const record of [
    { attemptId: id(99) },
    { originalRequestDigest: digest('9') },
    { objectIntentDigest: digest('9') },
    { createdAtMs: pins.validFromMs - 1 },
    { createdAtMs: pins.validFromMs + 2001 },
  ]) {
    const sample = providerResponse({ destroy: true, record });
    expect(() => verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected)).toThrow(
      'OPS_SECRET_UNRESOLVED',
    );
  }
  for (const change of [
    { wrongProviderSigner: true },
    { wrongRecoverySigner: true },
    { recovery: { outcome: 'UNKNOWN' as const } },
    { recovery: { outcome: 'REJECTED' as const } },
    { recovery: { keyState: 'CURRENT' as const } },
    { recovery: { providerSequence: '3', recoveryFloor: '3' } },
    { recovery: { recoveryFloor: '1' } },
  ]) {
    const sample = providerResponse({ destroy: true, ...change });
    expect(() => verifyEvidenceKmsResponse(sample.wire, sample.installed, sample.expected)).toThrow(
      'OPS_SECRET_UNRESOLVED',
    );
  }
});

it('rejects missing or malformed destruction expectations before producing a verified result', () => {
  const sample = providerResponse({ destroy: true });
  for (const patch of [
    { keyId: evidenceKmsAbsentDigest },
    { keyId: digest('9') },
    { keyId: undefined },
    { keyId: 'bad' },
    { keyUse: 'ENCRYPT' },
    { keyUse: 'DECRYPT' },
    { attemptId: id(99) },
    { exchangeId: id(99) },
    { requestDigest: digest('9') },
    { originalRequestDigest: digest('9') },
    { objectIntentDigest: digest('9') },
    { challenge: 'ff'.repeat(32) },
    { minimumSequence: '3' },
    { minimumRecoveryFloor: '3' },
    { minimumSequence: '0' },
    { minimumRecoveryFloor: '02' },
    { minimumSequence: '18446744073709551616' },
    { nowMs: -0 },
    { nowMs: NaN },
    { nowMs: sample.installed.validUntilMs },
    { admitted: true },
  ]) {
    expect(() =>
      verifyEvidenceKmsResponse(sample.wire, sample.installed, {
        ...sample.expected,
        ...patch,
      } as EvidenceKmsExpectedResponse),
    ).toThrow('OPS_SECRET_UNRESOLVED');
  }
  let accessed = false;
  const expected = { ...sample.expected };
  Object.defineProperty(expected, 'keyId', {
    enumerable: true,
    get() {
      accessed = true;
      return sample.expected.keyId;
    },
  });
  expect(() => verifyEvidenceKmsResponse(sample.wire, sample.installed, expected)).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  expect(accessed).toBe(false);
});

it('rejects signed CURRENT destruction success, missing retained custody and unsolicited material', () => {
  const current = providerResponse({
    destroy: true,
    signedCurrentDestroy: true,
    recovery: { keyState: 'CURRENT' },
  });
  expect(() =>
    verifyEvidenceKmsResponse(current.wire, current.installed, current.expected),
  ).toThrow('OPS_SECRET_UNRESOLVED');
  for (const outcome of ['PROVED', 'UNKNOWN', 'REJECTED'] as const) {
    const sample = providerResponse({ destroy: true, receipt: { outcome } });
    const response = decodeEvidenceKmsResponse(sample.wire);
    for (const patch of [
      { record: { payload: Buffer.alloc(0), cose: Buffer.alloc(0) } },
      { material: Buffer.alloc(32, 0x5a) },
    ]) {
      const wire = encodeEvidenceKmsResponse({ ...response, ...patch });
      // Observe the real erasure without replacing the verifier, crypto or fill.
      const erased = vi.spyOn(Buffer.prototype, 'fill');
      try {
        expect(() => verifyEvidenceKmsResponse(wire, sample.installed, sample.expected)).toThrow(
          'OPS_SECRET_UNRESOLVED',
        );
        if (patch.material) {
          const owned = erased.mock.contexts.find((buffer) => buffer.length === 32);
          expect(owned).toBeDefined();
          expect(owned).not.toBe(patch.material);
          expect(owned).toEqual(Buffer.alloc(32));
        }
      } finally {
        erased.mockRestore();
        patch.material?.fill(0);
        wire.fill(0);
      }
    }
  }
});
