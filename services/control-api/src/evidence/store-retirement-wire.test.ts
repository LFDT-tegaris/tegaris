import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  parseRetirementWire,
  retirementAttempt,
  retirementCancellationClaims,
  retirementOutcomeClaims,
  retirementPurposes,
  retirementRequestClaims,
  retirementSelectionDigest,
  retirementWireBytes,
  retirementWireDigest,
  verifyRetirementOutcome,
  verifyRetirementRequest,
  verifyRetirementCancellation,
} from './store-retirement-wire.js';

const digest = 'a'.repeat(64);
import { retirementWireFixture as fixture } from './store-retirement-wire-fixture.js';

describe('Control store retirement wire boundary', () => {
  it('verifies independent Control request/cancellation signatures without allowing target keys or purpose substitution', () => {
    const { request, host, attempt } = fixture();
    const control = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const target = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const cancellation = {
      version: 1n as const,
      host,
      attempt,
      cancellation_id: 'original-cancel',
      lifecycle_revision: 9n,
      committed_cancellation_digest: digest,
      issued_at_ms: request.issued_at_ms,
      expires_at_ms: request.expires_at_ms,
    };
    for (const [purpose, claims, verify] of [
      [retirementPurposes.request, request, verifyRetirementRequest],
      [retirementPurposes.cancel, cancellation, verifyRetirementCancellation],
    ] as const) {
      const claims_digest = retirementWireDigest(claims);
      const signature_p1363_hex = sign('sha256', retirementWireBytes([purpose, claims_digest]), {
        key: control.privateKey,
        dsaEncoding: 'ieee-p1363',
      }).toString('hex');
      const signed = { purpose, claims, claims_digest, signature_p1363_hex };
      const bytes = retirementWireBytes(signed);
      expect(verify(bytes, control.publicKey, host, request.issued_at_ms)).toEqual(claims);
      expect(() => verify(bytes, target.publicKey, host, request.issued_at_ms)).toThrow();
      expect(() => verify(bytes, control.publicKey, host, request.expires_at_ms)).toThrow();
      expect(() =>
        verify(
          retirementWireBytes({ ...signed, purpose: retirementPurposes.outcome }),
          control.publicKey,
          host,
          request.issued_at_ms,
        ),
      ).toThrow();
      expect(() =>
        verify(
          Buffer.concat([bytes, Buffer.from('\n')]),
          control.publicKey,
          host,
          request.issued_at_ms,
        ),
      ).toThrow();
    }
  });
  it('preserves full u64 allocation and distinct feed sequence in typed declaration order', () => {
    const { attempt } = fixture();
    const bytes = retirementWireBytes(attempt);
    expect(bytes.toString()).toContain(
      '"fact_delta_sequence":18446744073709551615,"candidate_feed_sequence":20',
    );
    expect(retirementAttempt.parse(parseRetirementWire(bytes))).toEqual(attempt);
    const changed = structuredClone(attempt);
    if (changed.selection.class !== 'ADMITTED_FACT') throw new Error('fixture class');
    changed.selection.rows[0]!.fact_delta_sequence = 20n;
    expect(() => retirementAttempt.parse(changed)).toThrow();
  });
  it('rejects duplicate keys, unsigned-number aliases, poison keys and malformed UTF8', () => {
    for (const value of [
      '{"x":1,"x":2}',
      '{"x":-0}',
      '{"x":1.0}',
      '{"x":1e3}',
      '{"__proto__":1}',
      '{"x":01}',
      '{"x":184467440737095516150}',
    ])
      expect(() => parseRetirementWire(Buffer.from(value))).toThrow();
    expect(() => parseRetirementWire(Buffer.from([0xff]))).toThrow();
    const { attempt } = fixture();
    expect(() =>
      retirementAttempt.parse(
        parseRetirementWire(
          Buffer.from(
            retirementWireBytes(attempt)
              .toString()
              .replace('"payload_bytes":40', '"payload_bytes":"40"'),
          ),
        ),
      ),
    ).toThrow();
  });
  it('rejects unknown authority flags and false class/store/scope bindings', () => {
    const { attempt, host, request } = fixture();
    for (const flag of ['eligible', 'hold_free', 'references_clear', 'archive_verified'])
      expect(() => retirementAttempt.parse({ ...attempt, [flag]: true })).toThrow();
    expect(() =>
      retirementAttempt.parse({ ...attempt, store: 'openpc_candidate_index' }),
    ).toThrow();
    expect(() =>
      retirementRequestClaims(request, { ...host, target_id: 'other' }, request.issued_at_ms),
    ).toThrow();
    expect(() =>
      retirementRequestClaims(
        { ...request, host: { ...host, scope: { ...host.scope, privacy_domain_id: 'foreign' } } },
        host,
        request.issued_at_ms,
      ),
    ).toThrow();
  });
  it('rejects duplicate identities, unordered rows and overflowing byte accounting', () => {
    const { attempt } = fixture();
    if (attempt.selection.class !== 'ADMITTED_FACT') throw new Error('fixture class');
    const original = attempt.selection.rows[0]!;
    for (const rows of [
      [],
      [original, original],
      [original, { ...original, candidate_id: 'other', fact_id: 'other', fact_delta_sequence: 1n }],
      [
        { ...original, payload_bytes: 9223372036854775807n },
        {
          ...original,
          candidate_id: 'other',
          fact_id: 'other',
          fact_delta_sequence: 1n,
          candidate_feed_sequence: 21n,
          payload_bytes: 9223372036854775807n,
        },
        {
          ...original,
          candidate_id: 'third',
          fact_id: 'third',
          fact_delta_sequence: 2n,
          candidate_feed_sequence: 22n,
        },
      ],
    ])
      expect(() =>
        retirementSelectionDigest(attempt.scope, { ...attempt.selection, rows }),
      ).toThrow();
  });
  it('keeps finite request and cancellation authority separate from historical readback', () => {
    const { request, host, attempt, outcome } = fixture();
    expect(retirementRequestClaims(request, host, request.issued_at_ms)).toEqual(request);
    for (const now of [request.issued_at_ms - 1n, request.expires_at_ms])
      expect(() => retirementRequestClaims(request, host, now)).toThrow();
    expect(() =>
      retirementRequestClaims(
        { ...request, expires_at_ms: request.expires_at_ms + 1n },
        host,
        request.issued_at_ms,
      ),
    ).toThrow();
    const cancellation = {
      version: 1n,
      host,
      attempt,
      cancellation_id: 'cancel',
      lifecycle_revision: 9n,
      committed_cancellation_digest: digest,
      issued_at_ms: request.issued_at_ms,
      expires_at_ms: request.expires_at_ms,
    };
    expect(retirementCancellationClaims(cancellation, host, request.issued_at_ms)).toEqual(
      cancellation,
    );
    expect(() =>
      retirementCancellationClaims(
        { ...cancellation, lifecycle_revision: 8n },
        host,
        request.issued_at_ms,
      ),
    ).toThrow();
    expect(retirementOutcomeClaims(outcome, host, attempt)).toEqual(outcome);
  });
  it('requires exact original attempt and physical counts, rejecting effect fields in no-effect outcomes', () => {
    const { attempt, host, outcome } = fixture();
    expect(() =>
      retirementOutcomeClaims({ ...outcome, attempt_id: 'other' }, host, attempt),
    ).toThrow();
    expect(() =>
      retirementOutcomeClaims(
        {
          ...outcome,
          outcome: {
            ...outcome.outcome,
            effect: { ...outcome.outcome.effect, retired_payload_bytes: 39n },
          },
        },
        host,
        attempt,
      ),
    ).toThrow();
    expect(() =>
      retirementOutcomeClaims(
        {
          ...outcome,
          outcome: {
            ...outcome.outcome,
            effect: { state: 'CANCELLED_NO_EFFECT', retired_rows: 1n },
          },
        },
        host,
        attempt,
      ),
    ).toThrow();
  });
  it('accepts only the configured target P256 signature over purpose and typed claims', () => {
    const { attempt, host, outcome } = fixture();
    const target = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const other = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const claims_digest = retirementWireDigest(outcome),
      purpose = retirementPurposes.outcome;
    const signature_p1363_hex = sign('sha256', retirementWireBytes([purpose, claims_digest]), {
      key: target.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex');
    const signed = { purpose, claims: outcome, claims_digest, signature_p1363_hex };
    for (const alternate of [
      Buffer.concat([retirementWireBytes(signed), Buffer.from('\n')]),
      retirementWireBytes({ ...signed, claims: { ...outcome, version: 1n } })
        .toString()
        .replace('"host":', '"host" :'),
      retirementWireBytes(signed).toString().replace('"local"', '"\\u006cocal"'),
    ])
      expect(() =>
        verifyRetirementOutcome(Buffer.from(alternate), target.publicKey, host, attempt),
      ).toThrow();
    expect(
      verifyRetirementOutcome(retirementWireBytes(signed), target.publicKey, host, attempt),
    ).toEqual(outcome);
    expect(() =>
      verifyRetirementOutcome(retirementWireBytes(signed), other.publicKey, host, attempt),
    ).toThrow();
    expect(() =>
      verifyRetirementOutcome(
        retirementWireBytes({ ...signed, purpose: retirementPurposes.request }),
        target.publicKey,
        host,
        attempt,
      ),
    ).toThrow();
    expect(() =>
      verifyRetirementOutcome(
        retirementWireBytes({
          ...signed,
          claims: { ...outcome, completed_at_ms: outcome.completed_at_ms + 1n },
        }),
        target.publicKey,
        host,
        attempt,
      ),
    ).toThrow();
  });
});
