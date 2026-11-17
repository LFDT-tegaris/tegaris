import { describe, expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import {
  parseProtectedRemoteArchiveSource,
  protectedRemoteArchiveIntentBytes,
  type BoundProtectedRemoteArchiveSource,
} from './protected-remote-archive-source.js';
import type { RemoteArchiveIntent } from './remote-archive-contracts.js';

function sample() {
  const packet = {
    keyId: 'proof-key-version-3',
    nonceBase64: Buffer.alloc(12, 1).toString('base64'),
    ciphertextBase64: Buffer.alloc(43, 2).toString('base64'),
  };
  const facts: BoundProtectedRemoteArchiveSource = {
    state: 'BOUND',
    object: {
      objectRef: `urn:openpc:resource:${uuidv7()}`,
      objectVersion: '1',
      objectDigest: sha256('original plaintext; not the encrypted packet'),
      source: {
        evidenceId: `urn:openpc:resource:${uuidv7()}`,
        occurrenceId: uuidv7(),
        operationId: uuidv7(),
        sourceReceiptDigest: sha256('source receipt'),
        proofDigest: sha256('proof'),
        assertionDigest: sha256('assertion'),
        signatureDigest: sha256('signature'),
        signerKeyDigest: sha256('verification key'),
        occurredAt: '2026-09-20T01:00:00.000000Z',
        materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
        evidenceClass: 'AUTHENTICATION',
        sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
        occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
        proofIntegrity: 'IDENTITY_COSE_ED25519',
        finality: 'NOT_APPLICABLE',
        authorityEffect: 'NONE',
      },
      dataClass: 'RAW_SOURCE_BODY',
      participantId: uuidv7(),
      privacyDomainId: uuidv7(),
      sinkId: 'protected-remote-test',
      payloadDigest: sha256(packet),
      ciphertextBytes: 43,
      retainUntil: '2026-09-24T01:00:00.000001Z',
    },
    packet,
    payloadBytes: Buffer.byteLength(canonicalJson(packet)),
    proofCreatedAt: '2026-09-21T01:00:00.000000Z',
    observedAt: '2026-09-23T01:00:00.000000Z',
    lineage: {
      evidenceId: '',
      streamId: 'authentication-proof-source',
      sequence: '17',
      sourceReceiptDigest: sha256('source receipt'),
    },
    retention: { state: 'UNKNOWN', reason: 'PROFILE_NOT_ADMITTED' },
    rules: [],
  };
  facts.lineage.evidenceId = facts.object.source.evidenceId;
  const intent: RemoteArchiveIntent = {
    intentId: uuidv7(),
    profileDigest: sha256('not signed profile authority'),
    source: { kind: 'PROTECTED_PROOF', object: facts.object },
    payloadDigest: facts.object.payloadDigest,
    payloadBytes: facts.payloadBytes,
    initialProtection: { revision: '1', rules: facts.rules },
  };
  return { facts, intent };
}

describe('protected remote source projection (not SQL or profile admission)', () => {
  it('keeps plaintext identity, exact packet bytes and retention uncertainty distinct', () => {
    const { facts, intent } = sample();
    expect(parseProtectedRemoteArchiveSource(facts)).toEqual(facts);
    const bytes = protectedRemoteArchiveIntentBytes(facts, intent);
    expect(bytes.toString()).toBe(canonicalJson(facts.packet));
    expect(sha256(bytes)).toBe(facts.object.payloadDigest);
    expect(sha256(bytes)).not.toBe(facts.object.objectDigest);
    expect(bytes.length).toBeGreaterThan(facts.object.ciphertextBytes);
    expect(facts.retention.state).toBe('UNKNOWN');
  });

  it.each<[string, (facts: BoundProtectedRemoteArchiveSource) => void]>([
    [
      'packet digest',
      (f: BoundProtectedRemoteArchiveSource) => (f.packet!.keyId = 'different-key'),
    ],
    ['packet length', (f: BoundProtectedRemoteArchiveSource) => f.payloadBytes++],
    ['ciphertext length', (f: BoundProtectedRemoteArchiveSource) => f.object.ciphertextBytes++],
    ['nonce length', (f: BoundProtectedRemoteArchiveSource) => (f.packet!.nonceBase64 = 'AQ==')],
    [
      'source reference',
      (f: BoundProtectedRemoteArchiveSource) =>
        (f.lineage.evidenceId = `urn:openpc:resource:${uuidv7()}`),
    ],
    [
      'source receipt',
      (f: BoundProtectedRemoteArchiveSource) => (f.lineage.sourceReceiptDigest = sha256('wrong')),
    ],
    [
      'creation time',
      (f: BoundProtectedRemoteArchiveSource) => (f.proofCreatedAt = f.object.retainUntil),
    ],
    [
      'expired deadline',
      (f: BoundProtectedRemoteArchiveSource) => (f.observedAt = f.object.retainUntil),
    ],
  ])('rejects malformed %s', (_name, mutate) => {
    const { facts } = sample();
    mutate(facts);
    expect(() => parseProtectedRemoteArchiveSource(facts)).toThrow('Remote archive integrity');
  });

  it('retains metadata after local deletion without inventing packet bytes', () => {
    const { facts, intent } = sample();
    facts.packet = null;
    expect(parseProtectedRemoteArchiveSource(facts)).toEqual(facts);
    expect(() => protectedRemoteArchiveIntentBytes(facts, intent)).toThrow(
      'Remote archive unavailable',
    );
  });

  it('observes expiry at the exact microsecond without extending a held proof deadline', () => {
    const { facts } = sample();
    facts.observedAt = '2026-09-24T01:00:00.000000Z';
    expect(parseProtectedRemoteArchiveSource(facts)).toEqual(facts);
    facts.observedAt = facts.object.retainUntil;
    facts.retention.reason = 'PROOF_DEADLINE_ELAPSED';
    const expired = parseProtectedRemoteArchiveSource(facts);
    expect(expired).toMatchObject({
      retention: { state: 'UNKNOWN', reason: 'PROOF_DEADLINE_ELAPSED' },
    });
    expect(facts.object.retainUntil).toBe('2026-09-24T01:00:00.000001Z');
  });

  it.each([
    'OBJECT_UNAVAILABLE',
    'PAYLOAD_UNAVAILABLE',
    'LINEAGE_UNAVAILABLE',
    'HOLD_LINEAGE_UNAVAILABLE',
    'TOO_MANY_HOLDS',
  ] as const)('never turns %s into empty rules or replacement bytes', (reason) => {
    const { intent } = sample();
    const unavailable = { state: 'UNKNOWN' as const, reason };
    expect(parseProtectedRemoteArchiveSource(unavailable)).toEqual(unavailable);
    expect(() => protectedRemoteArchiveIntentBytes(unavailable, intent)).toThrow(
      'Remote archive unavailable',
    );
  });

  it('rejects substituted intent identity and packet length before any transport owner', () => {
    const { facts, intent } = sample();
    expect(() =>
      protectedRemoteArchiveIntentBytes(facts, {
        ...intent,
        payloadBytes: facts.object.ciphertextBytes,
      }),
    ).toThrow('Remote archive integrity');
    const changed = structuredClone(intent);
    changed.source.object.privacyDomainId = uuidv7();
    expect(() => protectedRemoteArchiveIntentBytes(facts, changed)).toThrow(
      'Remote archive integrity',
    );
  });

  it('rejects duplicate holds and unapproved release shapes', () => {
    const { facts } = sample();
    const rule = {
      holdId: uuidv7(),
      selectorDigest: sha256('selector'),
      creationOperationId: uuidv7(),
      releaseOperationId: null,
      state: 'ACTIVE' as const,
      revision: '1' as const,
    };
    facts.rules = [rule, rule];
    expect(() => parseProtectedRemoteArchiveSource(facts)).toThrow('Remote archive integrity');
    expect(() =>
      parseProtectedRemoteArchiveSource({
        ...facts,
        rules: [{ ...rule, state: 'RELEASED', revision: '2' }],
      }),
    ).toThrow('Remote archive integrity');
  });
});
