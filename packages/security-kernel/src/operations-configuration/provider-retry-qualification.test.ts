import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { signConsumerCose } from '../fact-consumer/cose-framing.js';
import { encodeCbor, decodeCbor, type CborValue } from '../canonical-cbor.js';
import {
  assertProviderRetryAuthoritySuccessor,
  requireQualificationIssuerKey,
  qualificationOnlinePurposes,
  decodeProviderRetryQualification,
  encodeProviderRetryQualification,
  qualificationCanonicalJson,
  qualificationDigest,
  verifyProviderRetryAuthority,
  verifyProviderRetryEnvelope,
  verifyProviderRetryReceipt,
  providerRetryQualificationProfiles,
  type QualificationFamily,
  type QualificationRoot,
  type QualificationInputClaims,
  type QualificationReceiptClaims,
  type QualificationKeysetClaims,
  type QualificationRevocationClaims,
  type QualificationAuthorityEnvelope,
} from './provider-retry-qualification.js';

const now = 1800000000000;
const h = (text: string) => qualificationDigest(Buffer.from(text));
const id = (last: number) => `01900000-0000-7000-8000-${String(last).padStart(12, '0')}`;
const bytes = (value: unknown) => Buffer.from(qualificationCanonicalJson(value));
const descriptor = {
  format: 'COSE_Sign1',
  algorithm: 'ES256',
  curve: 'P-256',
  hash: 'SHA-256',
  canonicalization: 'PC-CBOR-1',
};
function pair() {
  const p = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    spki: p.publicKey.export({ type: 'spki', format: 'der' }),
    privateKey: p.privateKey.export({ type: 'pkcs8', format: 'der' }),
  };
}
// Software keys are ONLY a cryptographic adapter corpus. No test fixture here
// establishes non-exportability, independence, execution or product readiness.
function fixture(value = 2) {
  const rootKey = pair(),
    inputKey = pair(),
    receiptKey = pair();
  const root: QualificationRoot = {
    authorityId: 'test-authority',
    rootKeyId: qualificationDigest(rootKey.spki),
    rootEpoch: '1',
    rootSpki: rootKey.spki,
    policySigner: 'OFFLINE_TRUST_ROOT',
    validFromMs: now - 10000,
    validUntilMs: now + 100000,
  };
  const environmentIdentity = {
    environmentId: 'test-env',
    profile: 'test',
    dataClass: 'synthetic',
  };
  const workloadIdentity = { principal: 'external-qualification-corpus' };
  const input: QualificationInputClaims = {
    authorityId: root.authorityId,
    environmentId: 'test-env',
    profile: 'test',
    inputId: id(1),
    slot: 'QINPUT-TEST-PROVIDER-READ-RETRY-V1',
    setting: 'provider.read_retry_limit',
    value,
    method: 'eth_getBalance',
    methodClass: 'RETRY_SAFE_READ',
    methodProfileDigest: h('method'),
    workloadIdentityDigest: qualificationDigest(bytes(workloadIdentity)),
    environmentIdentityDigest: qualificationDigest(bytes(environmentIdentity)),
    subjectArtifactDigest: h('subject'),
    buildDigest: h('build'),
    sourceTreeDigest: h('tree'),
    configurationSchemaDigest: h('schema'),
    namedProfileDigest: h('profile'),
    issuerKeyId: qualificationDigest(inputKey.spki),
    issuerEpoch: '1',
    validFromMs: now - 100,
    validUntilMs: now + 10000,
  };
  function sign<F extends QualificationFamily>(
    family: F,
    claims: Parameters<typeof encodeProviderRetryQualification<F>>[1],
    key: ReturnType<typeof pair>,
    document?: unknown,
  ) {
    const payload = encodeProviderRetryQualification(family, claims);
    return {
      payload,
      cose: signConsumerCose(
        providerRetryQualificationProfiles[family],
        key.privateKey,
        key.spki,
        payload,
      ),
      document: bytes(document ?? {}),
    };
  }
  const revocationDoc = {
    schemaVersion: '1.0',
    authorityId: root.authorityId,
    revocations: [] as Record<string, unknown>[],
  };
  const revocation: QualificationRevocationClaims = {
    authorityId: root.authorityId,
    snapshotId: id(2),
    sequence: '1',
    revocationDocumentDigest: qualificationDigest(bytes(revocationDoc)),
    rootKeyId: root.rootKeyId,
    rootEpoch: '1',
    issuedAtMs: now - 1000,
    validUntilMs: now + 20000,
  };
  const keysetDoc = {
    schemaVersion: '1.0',
    authorityId: root.authorityId,
    policySigner: root.policySigner,
    keys: [
      ['input', inputKey],
      ['executed-receipt', receiptKey],
    ]
      .map(([purpose, key]) => {
        const p = key as ReturnType<typeof pair>;
        return {
          keyId: qualificationDigest(p.spki),
          epoch: 1,
          state: 'ACTIVE',
          purpose: `pc.cose.operations-qualification-${purpose as string}.v1`,
          nonExportable: true,
          backend: 'HSM',
          publicKeySpkiHex: p.spki.toString('hex'),
          validFromMs: now - 5000,
          validUntilMs: now + 40000,
        };
      })
      .sort((a, b) => (a.keyId < b.keyId ? -1 : 1)),
    issuedAt: new Date(now - 1000).toISOString(),
    signatureEnvelope: descriptor,
  };
  const revocations = sign('revocations', revocation, rootKey, revocationDoc);
  const keyset: QualificationKeysetClaims = {
    authorityId: root.authorityId,
    keysetId: id(3),
    sequence: '1',
    keysetDocumentDigest: qualificationDigest(bytes(keysetDoc)),
    revocationPayloadDigest: qualificationDigest(revocations.payload),
    policySigner: root.policySigner,
    rootKeyId: root.rootKeyId,
    rootEpoch: '1',
    issuedAtMs: now - 1000,
    validUntilMs: now + 20000,
  };
  const bundle: QualificationAuthorityEnvelope = {
    keyset: sign('keyset', keyset, rootKey, keysetDoc),
    revocations,
  };
  const inputEnvelope = sign('input', input, inputKey);
  const qualificationRef = `qualification://${root.authorityId}/${input.inputId}@${qualificationDigest(inputEnvelope.payload)}`;
  const doc = {
    schemaVersion: '1.0',
    profileId: 'OPENPC-R1-QUALIFICATION-AUTHORITY-PROFILE-1.0',
    profileVersion: '1.0',
    authorityId: root.authorityId,
    signerKeyId: qualificationDigest(receiptKey.spki),
    keyEpoch: 1,
    qualificationRef,
    subjectArtifactDigest: input.subjectArtifactDigest.slice(7),
    buildDigest: input.buildDigest.slice(7),
    sourceTreeDigest: input.sourceTreeDigest.slice(7),
    environmentIdentity,
    topologyIdentity: { topology: 'test' },
    resourceIdentity: { resources: 'test' },
    workloadIdentity,
    corpusIdentity: { corpus: 'test' },
    harnessDigest: h('harness').slice(7),
    toolchainDigest: h('toolchain').slice(7),
    rawEvidenceDigest: h('raw-corpus').slice(7),
    normalizedResults: { testOnly: 'no-execution-claim' },
    reviewerAttestation: { testOnly: 'no-independence-claim' },
    limitations: ['CRYPTOGRAPHIC_ADAPTER_ONLY'],
    exclusions: ['PRODUCTION_QUALIFICATION'],
    claimCeilingIds: ['LOCAL_ADAPTER_ONLY'],
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 10000).toISOString(),
    trustRegistryRef: 'qualification-trust://test/state-1',
    revocationRef: 'qualification-revocations://test/state-1',
    signatureEnvelope: descriptor,
  };
  const receipt: QualificationReceiptClaims = {
    authorityId: root.authorityId,
    environmentId: input.environmentId,
    profile: input.profile,
    receiptId: id(4),
    inputPayloadDigest: qualificationDigest(inputEnvelope.payload),
    qualificationRef,
    receiptDocumentDigest: qualificationDigest(bytes(doc)),
    keysetPayloadDigest: qualificationDigest(bundle.keyset.payload),
    revocationPayloadDigest: qualificationDigest(revocations.payload),
    result: 'EXECUTED_PASS',
    issuerKeyId: qualificationDigest(receiptKey.spki),
    issuerEpoch: '1',
    issuedAtMs: now,
    expiresAtMs: now + 10000,
  };
  function state() {
    return verifyProviderRetryAuthority(root, bundle, now);
  }
  function verify(receiptEnvelope = sign('receipt', receipt, receiptKey, doc)) {
    return verifyProviderRetryReceipt(inputEnvelope, receiptEnvelope, state(), state(), now);
  }
  function successor(mutator: (k: typeof keysetDoc, r: typeof revocationDoc) => void) {
    const kd = structuredClone(keysetDoc),
      rd = structuredClone(revocationDoc);
    mutator(kd, rd);
    const re = sign(
      'revocations',
      {
        ...revocation,
        snapshotId: id(5),
        sequence: '2',
        revocationDocumentDigest: qualificationDigest(bytes(rd)),
      },
      rootKey,
      rd,
    );
    const ke = sign(
      'keyset',
      {
        ...keyset,
        keysetId: id(6),
        sequence: '2',
        revocationPayloadDigest: qualificationDigest(re.payload),
        keysetDocumentDigest: qualificationDigest(bytes(kd)),
      },
      rootKey,
      kd,
    );
    return verifyProviderRetryAuthority(root, { keyset: ke, revocations: re }, now);
  }
  return {
    root,
    rootKey,
    inputKey,
    receiptKey,
    input,
    inputEnvelope,
    receipt,
    doc,
    keyset,
    keysetDoc,
    revocation,
    revocationDoc,
    bundle,
    sign,
    state,
    verify,
    successor,
  };
}
it('authenticates all four committed profiles without asserting execution, readiness or production qualification', () => {
  const f = fixture(),
    result = f.verify();
  expect(result.input.value).toBe(2);
  expect(result.qualificationRef).toBe(f.doc.qualificationRef);
  expect(result).not.toHaveProperty('ready');
  expect(result).not.toHaveProperty('verified');
});
it.each(['input', 'receipt', 'keyset', 'revocations'] as const)(
  'rejects malformed/noncanonical/wrong-purpose %s envelopes',
  (family) => {
    const f = fixture();
    const e =
      family === 'input'
        ? f.inputEnvelope
        : family === 'receipt'
          ? f.sign('receipt', f.receipt, f.receiptKey, f.doc)
          : f.bundle[family];
    const key = family === 'input' ? f.inputKey : family === 'receipt' ? f.receiptKey : f.rootKey;
    expect(() => verifyProviderRetryEnvelope(family, e, key.spki)).not.toThrow();
    expect(() =>
      verifyProviderRetryEnvelope(
        family,
        { ...e, payload: Buffer.concat([e.payload, Buffer.from([0])]) },
        key.spki,
      ),
    ).toThrow('UNQUALIFIED');
    expect(() =>
      verifyProviderRetryEnvelope(
        family,
        { ...e, cose: Buffer.from(e.cose).fill(0, 20, 21) },
        key.spki,
      ),
    ).toThrow('UNQUALIFIED');
    expect(() => verifyProviderRetryEnvelope(family, e, pair().spki)).toThrow('UNQUALIFIED');
    const map = decodeCbor(e.payload) as Map<number, CborValue>;
    map.set(255, 1);
    expect(() => decodeProviderRetryQualification(family, encodeCbor(map))).toThrow('UNQUALIFIED');
    for (const other of ['input', 'receipt', 'keyset', 'revocations'] as const)
      if (other !== family)
        expect(() => verifyProviderRetryEnvelope(other, e, key.spki)).toThrow('UNQUALIFIED');
  },
);
it.each([
  ['value', true],
  ['value', '2'],
  ['value', 4],
  ['value', -0],
  ['value', 1.5],
  ['methodClass', 'WRITE'],
  ['slot', 'QINPUT-LOCAL-PROVIDER-READ-RETRY-V1'],
  ['method', 'e\u0301'],
  ['method', 'x\n'],
  ['method', 'x'.repeat(129)],
  ['issuerEpoch', '01'],
  ['issuerEpoch', '18446744073709551616'],
  ['inputId', '01900000-0000-4000-8000-000000000001'],
  ['validUntilMs', now - 100],
])('rejects invalid input field %s (%s)', (name, value) => {
  const f = fixture();
  expect(() =>
    encodeProviderRetryQualification('input', { ...f.input, [name as string]: value }),
  ).toThrow('UNQUALIFIED');
});
it('rejects accessors, unknown fields, oversized and shared bytes before interpretation', () => {
  const f = fixture();
  const claims = { ...f.input };
  Object.defineProperty(claims, 'method', {
    get() {
      throw new Error('getter executed');
    },
    enumerable: true,
  });
  expect(() => encodeProviderRetryQualification('input', claims)).toThrow('UNQUALIFIED');
  expect(() =>
    encodeProviderRetryQualification('input', {
      ...f.input,
      ready: true,
    } as QualificationInputClaims),
  ).toThrow('UNQUALIFIED');
  expect(() => decodeProviderRetryQualification('input', Buffer.alloc(65537))).toThrow(
    'UNQUALIFIED',
  );
  expect(() =>
    decodeProviderRetryQualification('input', new Uint8Array(new SharedArrayBuffer(32))),
  ).toThrow('UNQUALIFIED');
});
it.each([
  'duplicate',
  'unknown',
  'descriptor',
  'identity',
  'raw',
  'empty',
  'unsafe',
  'escaped-duplicate',
])('rejects %s receipt document even with a valid matching signature', (kind) => {
  const f = fixture();
  const doc: Record<string, unknown> = structuredClone(f.doc);
  if (kind === 'unknown') doc.extra = true;
  if (kind === 'descriptor') doc.signatureEnvelope = { ...descriptor, algorithm: 'ES384' };
  if (kind === 'identity') doc.environmentIdentity = { environmentId: 'foreign' };
  if (kind === 'raw') doc.rawEvidenceDigest = 'not-evidence';
  if (kind === 'empty') doc.reviewerAttestation = {};
  let raw = bytes(doc);
  if (kind === 'duplicate')
    raw = Buffer.from(
      raw.toString().replace('"authorityId":', '"authorityId":"other","authorityId":'),
    );
  if (kind === 'escaped-duplicate')
    raw = Buffer.from(
      raw.toString().replace('"authorityId":', '"author\\u0069tyId":"other","authorityId":'),
    );
  if (kind === 'unsafe')
    raw = Buffer.from(raw.toString().replace('"keyEpoch":1', '"keyEpoch":9007199254740993'));
  const e = f.sign(
    'receipt',
    { ...f.receipt, receiptDocumentDigest: qualificationDigest(raw) },
    f.receiptKey,
    doc,
  );
  e.document = raw;
  expect(() => f.verify(e)).toThrow('UNQUALIFIED');
});
it.each([
  'expired',
  'future',
  'wrong-root',
  'root-epoch',
  'cross-snapshot',
  'exportable',
  'duplicate-epoch',
  'purpose-reuse',
  'root-online',
  'unknown-key-field',
])('rejects %s root/keyset state', (kind) => {
  const f = fixture();
  const root = { ...f.root };
  let bundle = f.bundle;
  if (kind === 'expired') root.validUntilMs = now;
  if (kind === 'future') root.validFromMs = now + 1;
  if (kind === 'wrong-root') root.rootSpki = pair().spki;
  if (kind === 'root-epoch') root.rootEpoch = '2';
  if (kind === 'cross-snapshot')
    bundle = {
      ...bundle,
      keyset: f.sign(
        'keyset',
        { ...f.keyset, revocationPayloadDigest: h('wrong') },
        f.rootKey,
        f.keysetDoc,
      ),
    };
  if (
    ['exportable', 'duplicate-epoch', 'purpose-reuse', 'root-online', 'unknown-key-field'].includes(
      kind,
    )
  ) {
    const doc = structuredClone(f.keysetDoc);
    if (kind === 'exportable') doc.keys[0]!.nonExportable = false;
    if (kind === 'duplicate-epoch') doc.keys.push(doc.keys[0]!);
    if (kind === 'purpose-reuse') {
      doc.keys = [
        { ...doc.keys[0]!, epoch: 1 },
        { ...doc.keys[0]!, epoch: 2, purpose: 'pc.cose.operations-qualification-else.v1' },
      ];
    }
    if (kind === 'root-online') {
      doc.keys[0]!.keyId = f.root.rootKeyId;
      doc.keys[0]!.publicKeySpkiHex = f.root.rootSpki.toString('hex');
    }
    if (kind === 'unknown-key-field') Object.assign(doc.keys[0]!, { ready: true });
    bundle = {
      ...bundle,
      keyset: f.sign(
        'keyset',
        { ...f.keyset, keysetDocumentDigest: qualificationDigest(bytes(doc)) },
        f.rootKey,
        doc,
      ),
    };
  }
  expect(() => verifyProviderRetryAuthority(root, bundle, now)).toThrow('UNQUALIFIED');
});
it('retains originals across rotation; suspension and epoch revocation deny historical use', () => {
  const f = fixture(),
    issue = f.state(),
    e = f.sign('receipt', f.receipt, f.receiptKey, f.doc);
  const retired = f.successor((k) => {
    k.keys.forEach((key) => {
      key.state = 'RETIRED';
    });
  });
  expect(() => assertProviderRetryAuthoritySuccessor(issue, retired)).not.toThrow();
  expect(() => verifyProviderRetryReceipt(f.inputEnvelope, e, issue, retired, now)).not.toThrow();
  const suspended = f.successor((k) => {
    k.keys[0]!.state = 'SUSPENDED';
  });
  expect(() => verifyProviderRetryReceipt(f.inputEnvelope, e, issue, suspended, now)).toThrow(
    'UNQUALIFIED',
  );
  const revoked = f.successor((k, r) => {
    const key = k.keys[0]!;
    key.state = 'REVOKED';
    r.revocations.push({
      schemaVersion: '1.0',
      authorityId: f.root.authorityId,
      keyId: key.keyId,
      keyEpoch: 1,
      state: 'REVOKED',
      effectiveAt: new Date(now).toISOString(),
      receiptEffect: 'INVALIDATE_RECEIPTS_COVERED_BY_REVOKED_KEY_EPOCH',
      evidenceRetention: 'PRESERVE_NEVER_DELETE_OR_RESIGN',
      signatureEnvelope: descriptor,
    });
  });
  expect(() => assertProviderRetryAuthoritySuccessor(issue, revoked)).not.toThrow();
  expect(() => verifyProviderRetryReceipt(f.inputEnvelope, e, issue, revoked, now)).toThrow(
    'UNQUALIFIED',
  );
  expect(() => assertProviderRetryAuthoritySuccessor(revoked, issue)).toThrow('UNQUALIFIED');
  expect(e.payload.equals(f.sign('receipt', f.receipt, f.receiptKey, f.doc).payload)).toBe(true);
});
it('rejects rollback, deletion, mutation and revival of historical key epochs', () => {
  const f = fixture(),
    old = f.state();
  expect(() => assertProviderRetryAuthoritySuccessor(old, old)).toThrow('UNQUALIFIED');
  expect(() =>
    assertProviderRetryAuthoritySuccessor(
      old,
      f.successor((k) => {
        k.keys.pop();
      }),
    ),
  ).toThrow('UNQUALIFIED');
  expect(() =>
    assertProviderRetryAuthoritySuccessor(
      old,
      f.successor((k) => {
        k.keys[0]!.validUntilMs++;
      }),
    ),
  ).toThrow('UNQUALIFIED');
  const retired = f.successor((k) => {
    k.keys[0]!.state = 'RETIRED';
  });
  const active = f.successor(() => {});
  expect(() =>
    assertProviderRetryAuthoritySuccessor(retired, {
      ...active,
      keyset: { ...active.keyset, sequence: '3' },
      revocations: { ...active.revocations, sequence: '3' },
    }),
  ).toThrow('UNQUALIFIED');
});
it.each(['expiry', 'input-reference', 'issuance-snapshot', 'different-value', 'different-subject'])(
  'rejects %s substitution',
  (kind) => {
    const f = fixture();
    let e = f.sign('receipt', f.receipt, f.receiptKey, f.doc),
      input = f.inputEnvelope;
    if (kind === 'input-reference')
      e = f.sign('receipt', { ...f.receipt, inputPayloadDigest: h('other') }, f.receiptKey, f.doc);
    if (kind === 'issuance-snapshot')
      e = f.sign('receipt', { ...f.receipt, keysetPayloadDigest: h('other') }, f.receiptKey, f.doc);
    if (kind === 'different-value') input = f.sign('input', { ...f.input, value: 3 }, f.inputKey);
    if (kind === 'different-subject')
      input = f.sign('input', { ...f.input, subjectArtifactDigest: h('other') }, f.inputKey);
    expect(() =>
      verifyProviderRetryReceipt(
        input,
        e,
        f.state(),
        f.state(),
        kind === 'expiry' ? now + 10000 : now,
      ),
    ).toThrow('UNQUALIFIED');
  },
);
it('does not accept a document digest as raw execution or custody proof', () => {
  const f = fixture();
  expect(f.verify().receiptDocument.rawEvidenceDigest).toBe(h('raw-corpus').slice(7));
  // This result deliberately has no admission/qualification flag. The durable
  // adapter requires exact same-transaction evidence from the separately owned
  // real execution/reviewer/custody/method reader, which pure signatures cannot provide.
  expect(Object.keys(f.verify()).sort()).toEqual([
    'input',
    'qualificationRef',
    'receipt',
    'receiptDocument',
  ]);
});

it.each([0, 1, 2, 3])(
  'preserves the exact permitted retry value %i without a fallback',
  (value) => {
    expect(fixture(value).verify().input.value).toBe(value);
  },
);
it('accepts a complete maximum snapshot and rejects a partial/oversized substitute', () => {
  const f = fixture();
  const rows = Array.from({ length: 4096 }, (_, i) => ({
    schemaVersion: '1.0',
    authorityId: f.root.authorityId,
    keyId: f.input.issuerKeyId,
    keyEpoch: i + 1,
    state: 'REVOKED',
    effectiveAt: new Date(now).toISOString(),
    receiptEffect: 'INVALIDATE_RECEIPTS_COVERED_BY_REVOKED_KEY_EPOCH',
    evidenceRetention: 'PRESERVE_NEVER_DELETE_OR_RESIGN',
    signatureEnvelope: descriptor,
  }));
  const accepted = f.successor((_k, r) => {
    r.revocations = rows;
  });
  expect(accepted.revoked).toHaveLength(4096);
  expect(() =>
    f.successor((_k, r) => {
      r.revocations = [...rows, { ...rows[0]!, keyEpoch: 4097 }];
    }),
  ).toThrow('UNQUALIFIED');
  const next = f.successor(() => {});
  expect(() =>
    assertProviderRetryAuthoritySuccessor(accepted, {
      ...next,
      keyset: { ...next.keyset, sequence: '3' },
      revocations: { ...next.revocations, sequence: '3' },
    }),
  ).toThrow('UNQUALIFIED');
});
it('observes the exact effective revocation instant while retaining the original receipt', () => {
  const f = fixture(),
    issuance = f.state();
  const current = f.successor((_k, r) => {
    r.revocations.push({
      schemaVersion: '1.0',
      authorityId: f.root.authorityId,
      keyId: f.input.issuerKeyId,
      keyEpoch: 1,
      state: 'REVOKED',
      effectiveAt: new Date(now + 1).toISOString(),
      receiptEffect: 'INVALIDATE_RECEIPTS_COVERED_BY_REVOKED_KEY_EPOCH',
      evidenceRetention: 'PRESERVE_NEVER_DELETE_OR_RESIGN',
      signatureEnvelope: descriptor,
    });
  });
  const receipt = f.sign('receipt', f.receipt, f.receiptKey, f.doc);
  expect(() =>
    verifyProviderRetryReceipt(f.inputEnvelope, receipt, issuance, current, now),
  ).not.toThrow();
  expect(() =>
    verifyProviderRetryReceipt(f.inputEnvelope, receipt, issuance, current, now + 1),
  ).toThrow('UNQUALIFIED');
});

it('registers only the two async purposes without giving them provider receipt authority', () => {
  const f = fixture();
  expect(qualificationOnlinePurposes).toHaveLength(4);
  const substituted = f.successor((keys) => {
    for (const key of keys.keys)
      key.purpose = key.purpose.endsWith('-input.v1')
        ? 'pc.cose.operations-notification-async-input.v1'
        : 'pc.cose.operations-notification-async-capacity-receipt.v1';
  });
  expect(() =>
    verifyProviderRetryReceipt(
      f.inputEnvelope,
      f.sign('receipt', f.receipt, f.receiptKey, f.doc),
      f.state(),
      substituted,
      now,
    ),
  ).toThrow();
  expect(() =>
    requireQualificationIssuerKey(
      substituted,
      f.input.issuerKeyId,
      '1',
      'pc.cose.operations-qualification-input.v1',
      f.input.validFromMs,
      f.input.validUntilMs,
      now,
      true,
    ),
  ).toThrow();
  expect(() =>
    f.successor((keys) => {
      keys.keys.push({
        ...keys.keys[0]!,
        epoch: 2,
        purpose: 'pc.cose.operations-notification-async-input.v1',
      });
      keys.keys.sort((a, b) => a.keyId.localeCompare(b.keyId) || a.epoch - b.epoch);
    }),
  ).toThrow();
  expect(() =>
    f.successor((keys) => {
      keys.keys[0]!.purpose = 'pc.cose.unregistered.v1';
    }),
  ).toThrow();
});
