import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { Pool } from 'pg';

const [secretFile, participantId, privacyDomainId, approvalId, checkerSession, bodyText, etag] =
  process.argv.slice(2);
const body = JSON.parse(bodyText);
const releaseId = body.targetRef.split(':').at(-1);
const origin = 'http://127.0.0.1:8080';
const admin = new Pool({
  host: '127.0.0.1',
  port: 55432,
  user: 'openpc_control',
  database: 'openpc_control',
  password: (await readFile(secretFile, 'utf8')).trim(),
  max: 1,
});

function requestId() {
  const bytes = randomBytes(16);
  bytes.writeUIntBE(Date.now(), 0, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
const csrfResponse = await fetch(`${origin}/api/v1/session/csrf`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    origin,
    'cookie': `__Host-openpc_session=${checkerSession}`,
  },
  body: JSON.stringify({ actionIntentId: body.actionIntentId }),
});
assert.equal(csrfResponse.status, 200);
const { csrfToken } = await csrfResponse.json();

try {
  const bound = (
    await admin.query(
      `select request.maker_principal_id::text as "makerId",
            request.maker_authority->>'sessionId' as "makerSessionId",
            decision.approver_assignment_id::text as "checkerAssignmentId",
            decision.signer_credential_id::text as "checkerCredentialId"
       from control.approval_request request join control.approval_decision_record decision
         on decision.participant_id=request.participant_id and decision.approval_request_id=request.approval_request_id
      where request.participant_id=$1 and request.privacy_domain_id=$2 and request.approval_request_id=$3
        and request.state='APPROVED' and decision.decision='APPROVE'`,
      [participantId, privacyDomainId, approvalId],
    )
  ).rows;
  assert.equal(bound.length, 1);
  const authority = bound[0];
  // Each fault changes authoritative input after real public approval. Restore the
  // original input afterward; no approval, candidate or execution result is seeded.
  const faults = [
    {
      name: 'expired-approval',
      table: 'approval_request',
      key: 'approval_request_id',
      id: approvalId,
      column: 'expires_at',
      change: "clock_timestamp()-interval '1 second'",
      cast: 'timestamptz',
    },
    {
      name: 'stale-maker-principal',
      table: 'principal',
      key: 'principal_id',
      id: authority.makerId,
      column: 'authority_epoch',
      change: 'authority_epoch+1',
      cast: 'bigint',
    },
    {
      name: 'stale-maker-session',
      table: 'session',
      key: 'session_id',
      id: authority.makerSessionId,
      column: 'session_epoch',
      change: 'session_epoch+1',
      cast: 'bigint',
    },
    {
      name: 'stale-checker-assignment',
      table: 'assignment',
      key: 'assignment_id',
      id: authority.checkerAssignmentId,
      column: 'row_version',
      change: 'row_version+1',
      cast: 'bigint',
    },
    {
      name: 'stale-checker-credential',
      table: 'credential',
      key: 'credential_id',
      id: authority.checkerCredentialId,
      column: 'credential_epoch',
      change: 'credential_epoch+1',
      cast: 'bigint',
    },
  ];
  for (const fault of faults) {
    assert.equal(typeof fault.id, 'string');
    const previous = (
      await admin.query(
        `select ${fault.column}::text as value from control.${fault.table} where participant_id=$1 and ${fault.key}=$2`,
        [participantId, fault.id],
      )
    ).rows;
    assert.equal(previous.length, 1);
    try {
      await admin.query(
        `update control.${fault.table} set ${fault.column}=${fault.change} where participant_id=$1 and ${fault.key}=$2`,
        [participantId, fault.id],
      );
      const key = `public-release-denial-${fault.name}`;
      const response = await fetch(`${origin}/api/v1/release-bundles/${body.targetRef}/publish`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          origin,
          'cookie': `__Host-openpc_session=${checkerSession}`,
          'openpc-api-version': '1',
          'openpc-participant-id': `urn:openpc:participant:${participantId}`,
          'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
          'x-request-id': requestId(),
          'x-correlation-id': requestId(),
          'x-openpc-action-intent-digest': body.actionIntentDigest,
          'idempotency-key': key,
          'x-csrf-token': csrfToken,
          'if-match': etag,
        },
        body: bodyText,
      });
      const problem = await response.text();
      assert.equal(response.status, 403, `${fault.name}: ${problem}`);
      const state = (
        await admin.query(
          `select release.state,release.revision::text,
          (select count(*)::int from control.outbox_event where participant_id=$1
            and aggregate_type='policy-release-bundle' and aggregate_id=$2) as events,
          (select count(*)::int from control.idempotency_record where participant_id=$1
            and idempotency_key=$3) as operations,
          (select count(*)::int from control.mfa_challenge where participant_id=$1
            and action_intent_id=$4 and resource_digest=$5 and used_at is not null) as consumed
         from control.policy_release_bundle release where participant_id=$1 and release_bundle_id=$2`,
          [
            participantId,
            releaseId,
            key,
            body.actionIntentId,
            Buffer.from(body.inputDigest.slice(7), 'hex'),
          ],
        )
      ).rows[0];
      assert.deepEqual(
        state,
        { state: 'DRAFT', revision: body.expectedRevision, events: 0, operations: 0, consumed: 0 },
        fault.name,
      );
    } finally {
      await admin.query(
        `update control.${fault.table} set ${fault.column}=$3::${fault.cast} where participant_id=$1 and ${fault.key}=$2`,
        [participantId, fault.id, previous[0].value],
      );
    }
  }
  process.stdout.write(
    'OPENPC_POLICY_APPROVAL_FRESHNESS PASS expired maker-session maker-principal checker-assignment checker-credential forbidden-effects\n',
  );
} finally {
  await admin.end();
}
