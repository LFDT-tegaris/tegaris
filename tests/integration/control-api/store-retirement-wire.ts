// Cross-language codec test called by the ordinary Rust workspace test. It has
// no database, transport or admission capability. Keys are ephemeral IPC only.
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { retirementWireFixture } from '../../../services/control-api/src/evidence/store-retirement-wire-fixture.js';
import {
  parseRetirementWire,
  retirementAttempt,
  retirementPurposes,
  retirementRequestClaims,
  retirementSelectionDigest,
  retirementWireBytes,
  retirementWireDigest,
  verifyRetirementOutcome,
  type StoreRetirementHost,
} from '../../../services/control-api/src/evidence/store-retirement-wire.js';

const mode = process.argv[2];
if (mode === 'produce') {
  const { host, request } = retirementWireFixture();
  if (process.argv[3] === 'candidate') {
    const fact = request.attempt.selection;
    if (fact.class !== 'ADMITTED_FACT') throw new Error('fixture');
    const selection = {
      class: 'CANDIDATE_PROJECTION' as const,
      source: fact.source,
      rows: fact.rows.map((row) => ({
        candidate_id: row.candidate_id,
        candidate_feed_sequence: row.candidate_feed_sequence,
        payload_digest: row.payload_digest,
        payload_bytes: row.payload_bytes,
        checkpoint_digest: row.checkpoint_digest,
      })),
    };
    host.store = 'openpc_candidate_index';
    request.attempt = retirementAttempt.parse({
      ...request.attempt,
      store: host.store,
      selection,
      selection_digest: retirementSelectionDigest(host.scope, selection),
    });
  }
  const control = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const target = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const sec1 = (key: KeyObject) => {
    const jwk = key.export({ format: 'jwk' });
    return [
      ...Buffer.concat([
        Buffer.from([4]),
        Buffer.from(jwk.x!, 'base64url'),
        Buffer.from(jwk.y!, 'base64url'),
      ]),
    ];
  };
  const signed = (purpose: string, claims: typeof request | typeof cancellation) => {
    const claims_digest = retirementWireDigest(claims);
    const signature_p1363_hex = sign('sha256', retirementWireBytes([purpose, claims_digest]), {
      key: control.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex');
    return retirementWireBytes({ purpose, claims, claims_digest, signature_p1363_hex }).toString();
  };
  const cancellation = {
    version: 1n,
    host,
    attempt: request.attempt,
    cancellation_id: 'cancel',
    lifecycle_revision: 10n,
    committed_cancellation_digest: 'c'.repeat(64),
    issued_at_ms: request.issued_at_ms,
    expires_at_ms: request.expires_at_ms,
  };
  process.stdout.write(
    JSON.stringify({
      request: signed(retirementPurposes.request, request),
      cancellation: signed(retirementPurposes.cancel, cancellation),
      control_public: sec1(control.publicKey),
      target_public: sec1(target.publicKey),
      target_secret: [...Buffer.from(target.privateKey.export({ format: 'jwk' }).d!, 'base64url')],
    }),
  );
} else if (mode === 'verify') {
  const input = JSON.parse(readFileSync(0, 'utf8')) as {
    request: string;
    target_public: number[];
    outcomes: string[];
  };
  const original = parseRetirementWire(Buffer.from(input.request)) as {
    claims: { host: StoreRetirementHost; issued_at_ms: bigint };
  };
  const request = retirementRequestClaims(
    original.claims,
    original.claims.host,
    original.claims.issued_at_ms,
  );
  const point = Buffer.from(input.target_public);
  assert.equal(point.length, 65);
  assert.equal(point[0], 4);
  const target = createPublicKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: point.subarray(1, 33).toString('base64url'),
      y: point.subarray(33).toString('base64url'),
    },
    format: 'jwk',
  });
  assert.deepEqual(
    input.outcomes.map(
      (outcome) =>
        verifyRetirementOutcome(Buffer.from(outcome), target, request.host, request.attempt).outcome
          .effect.state,
    ),
    ['APPLIED', 'CANCELLED_NO_EFFECT', 'REJECTED_NO_EFFECT'],
  );
  process.stdout.write('OPENPC_STORE_RETIREMENT_WIRE|PASS\n');
} else throw new Error('codec test mode required');
