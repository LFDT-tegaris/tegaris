import { signNotificationClaim } from '../../../../packages/security-kernel/src/notification-gateway/codec.js';
import { decodeCbor } from '../../../../packages/security-kernel/src/canonical-cbor.js';
import { completionDispositionInputFixture } from '../../../../tests/integration/identity/notification-completion-disposition-cases.js';
import { notificationCompletionDispositionClaims } from './completion-disposition-contract.js';
import { buildNotificationCompletionDispositionSigning } from './completion-disposition-state.js';
import { validateNotificationCompletionDispositionObservation } from '../../../identity-service/src/domain/notification-completion-disposition-provider.js';
import { expect, it } from 'vitest';
import { verifyConditionCases } from '../../../identity-service/src/db/function-grants.js';
async function sql() {
  const exports: Record<string, unknown> = await import(
    new URL('./completion-disposition-effect-guards.mjs', import.meta.url).href
  );
  const phase = exports.notificationCompletionDispositionPhaseGuardsSql;
  const structure = exports.notificationCompletionDispositionStructureGuardsSql;
  if (typeof phase !== 'string' || typeof structure !== 'string')
    throw new Error('Missing feature SQL');
  return { phase, structure };
}
it('requires exactly one native event/phase binding and rejects nullable or malformed expected identity', async () => {
  const { phase } = await sql();
  expect(() => verifyConditionCases(phase)).not.toThrow();
  expect(phase).toContain('event IS NULL OR phase IS NULL');
  expect(phase).toContain("(installation ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true");
  expect(phase).toContain("(authority ~ '^sha256:[0-9a-f]{64}$') IS DISTINCT FROM true");
  expect(phase).toContain(
    'SELECT * INTO STRICT admitted FROM openpc.notification_completion_phase_binding(event,phase)',
  );
  expect(phase).toContain(
    'admitted.installation_digest IS DISTINCT FROM installation OR admitted.authority_digest IS DISTINCT FROM authority',
  );
  expect(phase).not.toMatch(
    /LOOP|\bANY\s*\(|SECURITY DEFINER|GRANT\s|current_setting|pg_has_role/u,
  );
});
it('keeps deferred structure independent of expired or cleared live admission and creates no effects', async () => {
  const { structure } = await sql();
  expect(() => verifyConditionCases(structure)).not.toThrow();
  expect(structure).not.toMatch(
    /phase_binding|require_notification_completion_disposition_authority|SECURITY DEFINER|GRANT\s|\b(?:INSERT INTO|UPDATE control|DELETE FROM)\b/u,
  );
  for (const invariant of [
    'SELECT * INTO STRICT d',
    'SELECT * INTO STRICT signing',
    'SELECT * INTO STRICT inbox',
    'signing.observation_digest IS DISTINCT FROM',
    "s.source->'envelope' IS DISTINCT FROM openpc.notification_completion_source_envelope(e)",
    'inbox.admission_operation_id IS DISTINCT FROM d.operation_id',
    'inbox.envelope_digest IS DISTINCT FROM',
    'cursor_row.last_sequence IS DISTINCT FROM inbox.source_sequence',
    'cursor_row.last_event_id IS DISTINCT FROM event',
    "'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1'",
  ])
    expect(structure).toContain(invariant);
});
it('binds HOLD and minimized remediation while preserving original human work history', async () => {
  const { structure } = await sql();
  expect(structure).toContain("r->>'cursorMode' IS DISTINCT FROM 'HOLD'");
  expect(structure).toContain(
    'last_sequence<>0 OR last_event_id IS NOT NULL OR last_data_digest IS NOT NULL OR revision<>1',
  );
  expect(structure).toContain("'3',openpc.business_bytes(sha256(item.receipt_payload))");
  expect(structure).toContain('Notification completion could not be processed.');
  expect(structure).toContain("'2','urn:openpc:resource:'||item.event_id::text");
  expect(structure).toContain('openpc.check_notification_completion_validated_source(event)');
  expect(structure).toContain('SELECT * INTO STRICT history');
  expect(structure).toContain(
    'openpc.business_cbor(history.before_state_preimage)->8 IS DISTINCT FROM expected',
  );
  expect(structure).not.toContain('SET state=');
});
it('does not label structural framing as a cryptographic or publication success API', async () => {
  const { structure } = await sql();
  expect(structure).not.toMatch(
    /CREATE OR REPLACE FUNCTION openpc\.(?:publish_notification_completion_disposition_effects|assert_notification_completion_disposition_shared_owner)\(/u,
  );
});

it('binds successor mutation phases to the original producer trust and environment without reviving producer authority', async () => {
  const { phase } = await sql();
  expect(phase).toContain(
    'SELECT * INTO STRICT binding FROM openpc.notification_completion_phase_binding(event,phase)',
  );
  expect(phase).toContain("installation_digest=binding.installation_digest AND state='ACTIVE'");
  expect(phase).toContain('current_worker.producer_trust_digest,8');
  expect(phase).toContain(
    "original.transition->'receipt'->>'environmentId' IS DISTINCT FROM current_worker.installation->'pins'->>'environmentId'",
  );
  expect(phase).not.toContain("producer.state='ACTIVE'");
});

it('compares the complete native verified receipt to exact stored signing bytes and installed originals', async () => {
  const { phase, structure } = await sql();
  expect(phase).toContain('verified:=openpc.notification_completion_verified_receipt(event,phase)');
  expect(phase).toContain("phase NOT IN ('OBSERVE','PUBLISH')");
  expect(phase).toContain('verified IS NULL');
  expect(phase).toContain('IF verified IS DISTINCT FROM expected');
  for (const key of [
    'schema',
    'purpose',
    'requestDigest',
    'preparationDigest',
    'payloadDigest',
    'coseDigest',
    'observationDigest',
    'signerInstallationDigest',
    'signerKeyId',
    'originalWorkerInstallationDigest',
    'producerTrustDigest',
    'environmentId',
  ])
    expect(phase).toContain("'" + key + "'");
  expect(phase).toContain("'preparationDigest',q->>'dispositionPreparationDigest'");
  expect(phase).toContain("sha256(decode(observation->>'coseHex','hex'))");
  expect(phase).toContain('signing_canonical_json(observation)');
  expect(phase).toContain("s.state='OBSERVED' AND observation IS DISTINCT FROM s.observation");
  expect(structure).toContain(
    'CREATE OR REPLACE FUNCTION openpc.check_notification_completion_disposition_original(event uuid)',
  );
  expect(structure).not.toMatch(/notification_completion_verified_receipt|receipt_admission\(/u);
});

it('rejects a changed ECDSA signature even when every COSE framing field and payload is unchanged', () => {
  const f = completionDispositionInputFixture('QUARANTINED');
  const preparation = buildNotificationCompletionDispositionSigning(f.input);
  const claims = notificationCompletionDispositionClaims(f.input);
  const signed = signNotificationClaim(
    'NotificationCompletionDispositionReceiptV1',
    f.key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    f.key.publicKey.export({ format: 'der', type: 'spki' }),
    claims,
  );
  const observation = {
    schemaVersion: 1,
    providerId: preparation.request.providerId,
    signingAttemptId: preparation.request.signingAttemptId,
    requestDigest: preparation.requestDigest,
    recordedAtMs: claims.recordedAtMs,
    outcome: 'SIGNED',
    reason: null,
    coseHex: signed.cose.toString('hex'),
  };
  const trust = { signer: f.signer, worker: f.worker.input };
  expect(
    validateNotificationCompletionDispositionObservation(preparation.request, observation, trust),
  ).toEqual(observation);
  const damaged = Buffer.from(signed.cose);
  damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1;
  expect(signed.cose[0]).toBe(0xd2);
  expect(damaged[0]).toBe(0xd2);
  const originalFrame = decodeCbor(signed.cose.subarray(1)),
    changedFrame = decodeCbor(damaged.subarray(1));
  if (!Array.isArray(originalFrame) || !Array.isArray(changedFrame))
    throw new Error('Expected closed COSE array');
  expect(changedFrame.slice(0, 3)).toEqual(originalFrame.slice(0, 3));
  expect(Buffer.isBuffer(changedFrame[3]) && changedFrame[3].length).toBe(64);
  expect(() =>
    validateNotificationCompletionDispositionObservation(
      preparation.request,
      { ...observation, coseHex: damaged.toString('hex') },
      trust,
    ),
  ).toThrow();
});
