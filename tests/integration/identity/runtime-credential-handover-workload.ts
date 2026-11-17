import { type X509Certificate } from 'node:crypto';
import { Pool } from 'pg';
import { expect } from 'vitest';
import { z } from 'zod';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { digest, sha } from './public-governance-client.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  assignmentCreate,
  assignmentCreateCandidate,
} from '../../../services/participant-service/src/contracts/assignment.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import { readWorkloadSigningHandoverProvenance } from '../../../services/identity-service/src/db/workload-signing-handover-provenance.js';
import { signingRotationActions } from '../../../packages/security-kernel/src/signing-operations.js';

type Administration = Awaited<ReturnType<typeof contractAdministrationFixture>>;
type PublicLeaf = { certificate: X509Certificate; publicKey: Buffer };

/** Independent initial workload trust only. No assignment, policy, approval,
 * activation, observation or completed operation is installed here. */
export async function installRuntimeWorkloadInitialTrust(
  admin: Pool,
  fixture: Administration,
  targetId: string,
  leaf: PublicLeaf,
) {
  z.uuidv7().parse(targetId);
  const workloadId = `urn:openpc:workload:${targetId}`;
  const subject = `urn:openpc:participant:${fixture.participantId}:workload:${targetId}`;
  expect(leaf.certificate.subjectAltName).toBe(`URI:${subject}`);
  expect(Buffer.from(leaf.certificate.publicKey.export({ format: 'der', type: 'spki' }))).toEqual(
    leaf.publicKey,
  );
  const now = Date.now(),
    from = new Date(leaf.certificate.validFrom),
    until = new Date(leaf.certificate.validTo);
  expect(from.getTime()).toBeLessThanOrEqual(now);
  expect(until.getTime()).toBeGreaterThan(now);
  const principalId = id(),
    credentialId = id();
  const connection = await admin.connect();
  try {
    await connection.query('begin');
    const existing = await connection.query(
      'select count(*)::int n from control.credential where participant_id=$1 and audience=$2',
      [fixture.participantId, workloadId],
    );
    expect(existing.rows).toEqual([{ n: 0 }]);
    await connection.query(
      "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)values($1,$2,'WORKLOAD','Independent native handover initial trust','ACTIVE',1)",
      [principalId, fixture.participantId],
    );
    await connection.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,secret_fingerprint,certificate_der,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS',$4,$5,$6,$7,$8,$9,$10,'ACTIVE',1,$11,$12)`,
      [
        credentialId,
        fixture.participantId,
        principalId,
        leaf.certificate.issuer,
        subject,
        workloadId,
        sha(leaf.publicKey),
        leaf.publicKey,
        sha(leaf.certificate.raw),
        leaf.certificate.raw,
        from,
        until,
      ],
    );
    await connection.query('commit');
  } catch (error) {
    try {
      await connection.query('rollback');
    } catch (releaseError) {
      throw new AggregateError(
        [error, releaseError],
        'Initial workload trust failed; rollback also failed',
      );
    }
    throw error;
  } finally {
    connection.release();
  }
  return {
    principalId,
    credentialId,
    targetId,
    workloadId,
    certificateDigest: 'sha256:' + sha(leaf.certificate.raw).toString('hex'),
  };
}

/** Real Participant public proposal, checker read/approval, maker step-up,
 * command, exact replay and restart readback. No workload permission is seeded. */
export async function grantRuntimeWorkloadSourceRead(
  admin: Pool,
  fixture: Administration,
  workload: Awaited<ReturnType<typeof installRuntimeWorkloadInitialTrust>>,
  indexerProfileId: string,
) {
  z.uuidv7().parse(indexerProfileId);
  const envelope = z.uuidv7().parse(fixture.initialRuntimeSourceEnvelopeId);
  const role = z
    .string()
    .regex(/^urn:openpc:role:[0-9a-f-]{36}$/u)
    .parse(fixture.initialParticipantRoleId);
  const scope = {
    privacyDomainIds: [fixture.privacyDomainId],
    actionIntentIds: ['ACT-RUNTIME_READ_RPC-V1'],
    capabilityIds: [],
    resourceIds: [indexerProfileId],
    riskClasses: ['LOW'],
    makerCheckerRequired: false,
    stepUpRequired: false,
    onwardDelegationDepth: 0,
  };
  const body = JSON.parse(
    JSON.stringify(
      assignmentCreate.parse({
        assignmentId: id(),
        principalId: workload.principalId,
        roleId: role,
        authorityEnvelopeId: envelope,
        scopeDigest: 'sha256:' + sha(JSON.stringify(scope)).toString('hex'),
        ...scope,
        validFrom: new Date().toISOString(),
        validUntil: new Date(Date.now() + 86400000).toISOString(),
      }),
    ),
  ) as Record<string, unknown>;
  const assignmentId = z.uuidv7().parse(body.assignmentId);
  const candidate = assignmentCreateCandidate.parse({
    id: assignmentId,
    participantId: fixture.participantId,
    state: 'ACTIVE',
    delegationEpoch: '0',
    ...body,
  });
  const candidateDigest = digest(candidate),
    action = 'ACT-PARTICIPANT_CREATE_MEMBER-V1',
    key = `runtime-source-assignment-${id()}`;
  const { client } = fixture.governance;
  const commit = async (approvalId = '018f0000-0000-7000-8000-000000000001') => {
    const maker = fixture.governance.maker,
      origin = fixture.service.participantUrl();
    return client.request(
      `${origin}/v1/participants/${fixture.participantId}/assignments`,
      maker,
      body,
      {
        'Authorization': `Bearer ${maker.sessionToken}`,
        'X-CSRF-Token': await client.csrf(maker, action, origin),
        'Idempotency-Key': key,
        'X-OpenPC-Aggregate-Version': '0',
        'X-OpenPC-Approval-Request-ID': approvalId,
        'OpenPC-Action-Intent-Digest': client.actionDigests.get(action)!,
      },
    );
  };
  const staged = await commit();
  expect(staged.status, JSON.stringify(staged)).toBe(403);
  await client.stepUp(
    fixture.governance.checker,
    'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    assignmentId,
    candidateDigest,
  );
  const proposal = await fixture.service.get(
    fixture.governance.checker.sessionToken,
    candidateDigest,
    fixture.privacyDomainId,
    'grant-proposals',
  );
  expect(proposal, JSON.stringify(proposal)).toMatchObject({
    status: 200,
    cacheControl: 'no-store',
    body: {
      candidateDigest,
      resourceId: assignmentId,
      expectedRevision: '0',
      kind: 'assignment',
      mutation: 'CREATE',
      proposedGrant: {
        id: assignmentId,
        participantId: fixture.participantId,
        principalId: workload.principalId,
        roleId: role,
        privacyDomainIds: [fixture.privacyDomainId],
        actionIntentIds: scope.actionIntentIds,
        resourceIds: scope.resourceIds,
        state: 'ACTIVE',
      },
    },
  });
  expect(
    (
      await admin.query(
        'select count(*)::int n from control.assignment where participant_id=$1 and principal_id=$2',
        [fixture.participantId, workload.principalId],
      )
    ).rows,
  ).toEqual([{ n: 0 }]);
  expect(
    (
      await fixture.service.get(
        fixture.governance.checker.sessionToken,
        candidateDigest,
        id(),
        'grant-proposals',
      )
    ).status,
  ).toBe(404);
  const approvalId = await fixture.approveCandidate(candidateDigest);
  await client.stepUp(fixture.governance.maker, action, assignmentId, candidateDigest);
  const committed = await commit(approvalId);
  expect(committed, JSON.stringify(committed)).toMatchObject({
    status: 201,
    body: { id: assignmentId, principalId: workload.principalId, roleId: role, state: 'ACTIVE' },
  });
  expect(await commit(approvalId)).toEqual(committed);
  // Keep the maker's original consumed create verification intact for replay.
  await client.stepUp(
    fixture.governance.checker,
    'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    assignmentId,
    candidateDigest,
  );
  const readback = () => fixture.service.get(fixture.governance.checker.sessionToken, assignmentId);
  const original = await readback();
  expect(original, JSON.stringify(original)).toMatchObject({
    status: 200,
    body: { effect: committed.body, operationId: expect.any(String) },
  });
  await fixture.service.restartParticipant();
  expect(await readback()).toEqual(original);
  expect(await commit(approvalId)).toEqual(committed);
  // A resource-read assertion cannot replace the original create verification.
  await client.stepUp(
    fixture.governance.maker,
    'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    assignmentId,
    candidateDigest,
  );
  expect(await commit(approvalId)).toMatchObject({ status: 403 });
  const durable = await admin.query(
    `select c.consumed_operation_id::text operation_id,
    (select count(*)::int from control.mutation_evidence e where e.operation_id=c.consumed_operation_id) evidence,
    (select count(*)::int from control.outbox_event e where e.aggregate_id=c.resource_id and e.event_type='openpc.assignment.mutation.committed.v1') outbox
    from control.mutation_candidate c where c.participant_id=$1 and c.privacy_domain_id=$2 and c.resource_id=$3
    and c.catalog_operation_id='ID-OP-ASSIGNMENT-CREATE' and c.state='CONSUMED'`,
    [fixture.participantId, fixture.privacyDomainId, assignmentId],
  );
  const originalOperationId = z
    .object({ operationId: z.uuidv7() })
    .passthrough()
    .parse(original.body).operationId;
  expect(durable.rows).toEqual([{ operation_id: originalOperationId, evidence: 1, outbox: 1 }]);
  return {
    assignmentId,
    candidateDigest,
    approvalId,
    operationId: originalOperationId,
    roleId: role,
  };
}

/** Ordinary approved renewal, with signed provenance read by the actual
 * scoped runtime role. The witness grants no signing or transport authority. */
export async function renewRuntimeHandoverWorkload(
  admin: Pool,
  runtime: Pool,
  fixture: Administration,
  workload: Awaited<ReturnType<typeof installRuntimeWorkloadInitialTrust>>,
  successor: PublicLeaf & { credentialId: string },
) {
  z.uuidv7().parse(successor.credentialId);
  expect(successor.certificate.subjectAltName).toBe(
    `URI:urn:openpc:participant:${fixture.participantId}:workload:${workload.targetId}`,
  );
  expect(new Date(successor.certificate.validTo).getTime()).toBeGreaterThan(Date.now());
  expect(
    Buffer.from(successor.certificate.publicKey.export({ format: 'der', type: 'spki' })),
  ).toEqual(successor.publicKey);
  const historical = async () =>
    (
      await admin.query(
        'select certificate_der,public_key_spki_der,secret_fingerprint,valid_from,valid_until from control.credential where participant_id=$1 and credential_id=$2',
        [fixture.participantId, workload.credentialId],
      )
    ).rows;
  const original = await historical();
  expect(original).toHaveLength(1);
  expect(new Date(original[0]!.valid_until).getTime()).toBeLessThanOrEqual(Date.now());
  const { client } = fixture.governance,
    action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    key = `runtime-credential-continuity-${id()}`;
  const body = {
    credentialId: successor.credentialId,
    publicKeySpkiDer: successor.publicKey.toString('base64'),
  };
  const candidateDigest = digest({ replacedCredentialId: workload.credentialId, ...body });
  const staged = await client.mutation(
    fixture.governance.maker,
    '/v1/identity/workloads/prepare',
    { mutation: 'ROTATE', replacedCredentialId: workload.credentialId, ...body },
    key,
    '1',
  );
  expect(staged, JSON.stringify(staged)).toMatchObject({
    status: 202,
    body: { candidateDigest, expectedRevision: '1' },
  });
  const approvalId = await fixture.approveCandidate(candidateDigest);
  await client.stepUp(fixture.governance.maker, action, workload.credentialId, candidateDigest);
  const commit = () =>
    client.mutation(
      fixture.governance.maker,
      `/v1/identity/workloads/${workload.credentialId}/rotate`,
      body,
      key,
      '1',
      approvalId,
    );
  const result = await commit();
  expect(result, JSON.stringify(result)).toMatchObject({
    status: 200,
    body: {
      credentialId: successor.credentialId,
      replacedCredentialId: workload.credentialId,
      principalId: workload.principalId,
      workloadId: workload.workloadId,
      state: 'ACTIVE',
      workloadEpoch: '2',
    },
  });
  expect(await commit()).toEqual(result);
  expect(await historical()).toEqual(original);
  expect(
    (
      await admin.query(
        'select state,credential_epoch::text from control.credential where participant_id=$1 and credential_id=$2',
        [fixture.participantId, workload.credentialId],
      )
    ).rows,
  ).toEqual([{ state: 'REVOKED', credential_epoch: '2' }]);
  expect(
    (
      await admin.query(
        'select certificate_der,public_key_spki_der,secret_fingerprint,rotated_from_credential_id::text,state,credential_epoch::text from control.credential where participant_id=$1 and credential_id=$2',
        [fixture.participantId, successor.credentialId],
      )
    ).rows,
  ).toEqual([
    {
      certificate_der: successor.certificate.raw,
      public_key_spki_der: successor.publicKey,
      secret_fingerprint: sha(successor.certificate.raw),
      rotated_from_credential_id: workload.credentialId,
      state: 'ACTIVE',
      credential_epoch: '2',
    },
  ]);
  const rows = (
    await admin.query(
      `select consumed_operation_id::text id from control.mutation_candidate
    where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3 and state='CONSUMED'
    and catalog_operation_id='ID-OP-WORKLOAD-ROTATE' and candidate_digest=$4`,
      [
        fixture.participantId,
        fixture.privacyDomainId,
        workload.credentialId,
        Buffer.from(candidateDigest.slice(7), 'hex'),
      ],
    )
  ).rows;
  expect(rows).toHaveLength(1);
  const input = {
    participantId: fixture.participantId,
    privacyDomainId: fixture.privacyDomainId,
    predecessorCredentialId: workload.credentialId,
    predecessorCredentialEpoch: '1',
    successorCredentialId: successor.credentialId,
    successorCredentialEpoch: '2',
    credentialRotationOperationId: z.uuidv7().parse(rows[0]!.id),
  };
  const witness = await runScopedTransaction(
    runtime,
    {
      participantId: fixture.participantId,
      privacyDomainId: fixture.privacyDomainId,
      actionIntentId: signingRotationActions.create,
      isolation: 'SERIALIZABLE',
    },
    id,
    (connection) =>
      readWorkloadSigningHandoverProvenance(connection, input, fixture.identityRuntimeVerifier),
  );
  expect(witness).toMatchObject({
    ...input,
    principalId: workload.principalId,
    makerPrincipalId: fixture.governance.maker.principalId,
    checkerPrincipalId: fixture.governance.checker.principalId,
    candidateDigest,
  });
  await fixture.service.restartIdentity();
  expect(await commit()).toEqual(result);
  expect(await historical()).toEqual(original);
  return {
    rotationOperationId: input.credentialRotationOperationId,
    successorCredentialId: successor.credentialId,
    successorCertificateDigest: 'sha256:' + sha(successor.certificate.raw).toString('hex'),
    witness,
  };
}
