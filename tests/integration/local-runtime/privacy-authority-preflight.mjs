import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Pool } from 'pg';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.ts';
import { authorizeLocalPolicyAction } from '../../../services/identity-service/src/domain/policy-authorization.ts';
import { bootstrapPrivacyAuthority } from './privacy-authority-fixture.mjs';
import { checkExplorerCustody } from './privacy-explorer-custody.mjs';

const [host, passwordFile] = process.argv.slice(2);
const password = (await readFile(passwordFile, 'utf8')).trim();
const admin = new Pool({
  host,
  port: 5432,
  database: 'openpc_control',
  user: 'postgres',
  password,
  max: 1,
});
const runtime = new Pool({
  host,
  port: 5432,
  database: 'openpc_control',
  user: 'openpc_identity_runtime',
  password,
  max: 1,
});
const participant = '018f0000-0000-7000-8000-000000000101';
const principal = '018f0000-0000-7000-8000-000000000111';
function uuid() {
  const bytes = randomBytes(16);
  bytes.writeUIntBE(Date.now(), 0, 6);
  bytes[6] = (bytes[6] & 15) | 112;
  bytes[8] = (bytes[8] & 63) | 128;
  const h = bytes.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
try {
  const kernel = new IdentityKernel(new PostgresIdentityRepository(runtime));
  const originalSession = await kernel.issueLocalDevelopmentSession(participant, principal, false);
  const privacy = uuid();
  let request = {
    sessionToken: originalSession.sessionToken,
    privacyDomainId: privacy,
    actionIntentId: 'ACT-OPERATIONS_READ_OPERATION-V1',
    resourceId: uuid(),
    stepUpRequired: false,
  };
  await assert.rejects(authorizeLocalPolicyAction(runtime, kernel, request));
  const envelope = uuid();
  const assignment = uuid();
  await bootstrapPrivacyAuthority(admin, participant, principal, privacy, envelope, assignment);
  await assert.rejects(authorizeLocalPolicyAction(runtime, kernel, request));
  await admin.query(
    `update control.participant set root_privacy_domain_id=$2 where participant_id=$1`,
    [participant, privacy],
  );
  const selectedSession = await kernel.issueLocalDevelopmentSession(participant, principal, false);
  request = { ...request, sessionToken: selectedSession.sessionToken };
  for (const action of [
    'ACT-OPERATIONS_READ_OPERATION-V1',
    'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  ]) {
    const decision = await authorizeLocalPolicyAction(runtime, kernel, {
      ...request,
      actionIntentId: action,
    });
    assert.equal(decision.assignmentId, assignment);
    assert.equal(decision.authorityEnvelopeId, envelope);
    assert.equal(decision.principalId, principal);
    assert.equal(decision.sessionId, selectedSession.sessionId);
  }
  await assert.rejects(
    authorizeLocalPolicyAction(runtime, kernel, {
      ...request,
      sessionToken: originalSession.sessionToken,
    }),
  );
  await assert.rejects(
    authorizeLocalPolicyAction(runtime, kernel, {
      ...request,
      actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
    }),
  );
  // A deployment association definer may lock its Participant only inside the
  // result trigger. Its owner must not gain ordinary Participant reads/writes.
  const owner = await admin.connect();
  try {
    await owner.query('begin');
    await owner.query('set local role openpc_control_owner');
    await owner.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,
       'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',true)`,
      [participant, privacy, uuid()],
    );
    assert.equal(
      (
        await owner.query(
          'select count(*)::int n from control.participant where participant_id=$1',
          [participant],
        )
      ).rows[0].n,
      0,
    );
    assert.equal(
      (
        await owner.query(
          'update control.participant set authority_epoch=authority_epoch+1 where participant_id=$1',
          [participant],
        )
      ).rowCount,
      0,
    );
  } finally {
    await owner.query('rollback');
    owner.release();
  }
  await checkExplorerCustody(
    { host, port: 5432, database: 'openpc_control', password },
    participant,
    privacy,
    principal,
  );
  process.stdout.write(
    'OPENPC_PRIVACY_AUTHORITY_PREFLIGHT|PASS|exact-catalog|selected-context|wrong-context-denied|exact-assignment|ungranted-denied\n',
  );
} finally {
  await runtime.end();
  await admin.end();
}
