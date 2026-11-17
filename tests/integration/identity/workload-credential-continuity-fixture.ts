import { createServer, request } from 'node:https';
import { createServer as createIssuerServer } from 'node:http';
import { type TLSSocket } from 'node:tls';
import type { Duplex } from 'node:stream';
import { closeFixtureResources } from './close-fixture-resources.js';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { cp, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { Pool } from 'pg';
import { expect } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import {
  workloadRotationAuthority,
  workloadRotationCertificates,
} from './workload-rotation-pki.js';
import { digest, sha } from './public-governance-client.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { createLocalWorkloadIssuerFixture } from '../local-runtime/workload-issuer-runtime.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import {
  readWorkloadSigningHandoverProvenance,
  WorkloadSigningHandoverProvenanceUnavailable,
} from '../../../services/identity-service/src/db/workload-signing-handover-provenance.js';
import { signingRotationActions } from '../../../packages/security-kernel/src/signing-operations.js';

type Pki = Awaited<ReturnType<typeof workloadRotationCertificates>>;

/** Real transport only. This is not the Control handover or an application grant. */
export async function checkCurrentWorkloadTransport(pki: Pki) {
  let accepted = 0;
  const sockets = new Set<Duplex>();
  let failure: { error: unknown } | undefined;
  const server = createServer(
    {
      key: pki.server.privateKey,
      cert: pki.server.pem,
      ca: pki.ca,
      requestCert: true,
      rejectUnauthorized: true,
    },
    (req, res) => {
      const socket = req.socket as TLSSocket;
      if (!socket.authorized) {
        res.writeHead(403).end();
        return;
      }
      accepted++;
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(
        JSON.stringify({
          certificateSha256: sha(socket.getPeerCertificate().raw).toString('hex'),
        }),
      );
    },
  );
  server.on('tlsClientError', () => undefined);
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  const read = (leaf: Pki['successor']) =>
    new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = request(
        {
          hostname: '127.0.0.1',
          port: (server.address() as AddressInfo).port,
          ca: pki.ca,
          cert: leaf.pem,
          key: leaf.privateKey,
          rejectUnauthorized: true,
          agent: false,
        },
        (res) => {
          let body = '';
          res.setEncoding('utf8');
          res.on('data', (part: string) => {
            body += part;
          });
          res.on('end', () => resolve({ status: res.statusCode!, body }));
        },
      );
      req.on('error', reject);
      req.setTimeout(5000, () => req.destroy(new Error('Workload transport timed out')));
      req.end();
    });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const expected = {
      status: 200,
      body: JSON.stringify({
        certificateSha256: sha(pki.successor.certificate.raw).toString('hex'),
      }),
    };
    expect(await read(pki.successor)).toEqual(expected);
    await expect(read(pki.predecessor)).rejects.toThrow();
    expect(accepted).toBe(1);
    expect(await read(pki.successor)).toEqual(expected);
    expect(accepted).toBe(2);
  } catch (error) {
    failure = { error };
  }
  await closeFixtureResources(
    [
      () => {
        for (const socket of sockets) socket.destroy();
      },
      () =>
        server.listening
          ? new Promise<void>((resolve, reject) =>
              server.close((error) => (error ? reject(error) : resolve())),
            )
          : undefined,
    ],
    failure,
  );
  if (failure) throw failure.error;
}

/** Independent initial trust; every rotation candidate, approval, authenticator
 * proof, issuer request and durable result below uses its ordinary API owner. */
export async function ordinaryCredentialContinuity(adminUrl: string, runtimeUrl: string) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent?.startsWith('/')) throw new Error('Absolute isolated test scratch is required');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'credential-continuity-'));
  const admin = new Pool({ connectionString: adminUrl, max: 2 }),
    runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
  const controlUrl = new URL(runtimeUrl);
  controlUrl.username = 'openpc_configuration_runtime';
  const control = new Pool({ connectionString: controlUrl.href, max: 2 });
  const participantId = id(),
    privacyDomainId = id(),
    principalId = id(),
    predecessorId = id(),
    successorId = id();
  let workloadId = '',
    targetId = '';
  let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
  let issuer: ReturnType<typeof createIssuerServer> | undefined;
  let installedIssuer: Awaited<ReturnType<typeof createLocalWorkloadIssuerFixture>> | undefined;
  let complete = false;
  let failure: { error: unknown } | undefined;
  try {
    // Prepare only external CA trust before the real Control target exists.
    // The issuer cannot return a certificate until its exact manifest is installed.
    const authority = await workloadRotationAuthority(root, participantId);
    const token = randomBytes(32).toString('hex');
    issuer = createIssuerServer((req, res) => {
      if (!installedIssuer) {
        res.writeHead(503).end();
        return;
      }
      installedIssuer.emit('request', req, res);
    });
    await new Promise<void>((resolve, reject) => {
      issuer!.once('error', reject);
      issuer!.listen(0, '127.0.0.1', resolve);
    });
    let issuanceRequests = 0;
    issuer.on('request', (req) => {
      if (req.method === 'POST' && req.url === '/v1/certificates') issuanceRequests++;
    });
    fixture = await contractAdministrationFixture(
      admin,
      runtimeUrl,
      participantId,
      privacyDomainId,
      {
        principalKind: 'PLATFORM_OPERATOR',
        configurationRuntime: control,
        workloadIssuer: {
          url: `http://127.0.0.1:${(issuer.address() as AddressInfo).port}/v1/certificates`,
          token,
          trustedCaPem: authority.ca,
        },
      },
    );
    const createdTarget = await fixture
      .ordinaryMutation('runtime-targets', 'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1', {
        participantId: `urn:openpc:participant:${participantId}`,
        desiredGenerationDigest: null,
        activeGenerationDigest: null,
        xdsVersionDigest: null,
        observedAt: new Date().toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z'),
      })
      .call();
    expect(createdTarget.status, JSON.stringify(createdTarget)).toBe(202);
    targetId = String(createdTarget.body.resourceRef).slice(-36);
    workloadId = `urn:openpc:workload:${targetId}`;
    const targetRead = await fixture.read(`runtime-targets/${createdTarget.body.resourceRef}`);
    expect(targetRead.status, JSON.stringify(targetRead)).toBe(200);
    expect(targetRead.headers.get('etag')).toMatch(/^"sha256:[0-9a-f]{64}"$/u);
    expect(issuanceRequests).toBe(0);
    const pki = await authority.bindWorkload(workloadId, { runtimeTargetId: targetId });
    const old = pki.predecessor;
    expect(new Date(old.certificate.validTo).getTime()).toBeLessThan(Date.now());
    // Install the exact independently generated successor as external issuer input.
    installedIssuer = await createLocalWorkloadIssuerFixture({
      token,
      manifest: [
        {
          credentialId: successorId,
          participantId,
          principalId,
          workloadId,
          publicKeySpkiDer: pki.successor.publicKey.toString('base64'),
          certificateDer: pki.successor.certificate.raw.toString('base64'),
        },
      ],
    });
    await admin.query(
      "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)values($1,$2,'WORKLOAD','Independent expired workload initial trust','ACTIVE',1)",
      [principalId, participantId],
    );
    await admin.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,certificate_der,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS',$4,$5,$6,$7,$8,$9,$10,'ACTIVE',1,$11,$12)`,
      [
        predecessorId,
        participantId,
        principalId,
        old.certificate.issuer,
        `urn:openpc:participant:${participantId}:workload:${targetId}`,
        workloadId,
        sha(old.publicKey),
        old.publicKey,
        sha(old.certificate.raw),
        old.certificate.raw,
        new Date(old.certificate.validFrom),
        new Date(old.certificate.validTo),
      ],
    );
    const historical = async () =>
      (
        await admin.query(
          'select certificate_der,public_key_spki_der,secret_fingerprint,valid_from,valid_until from control.credential where participant_id=$1 and credential_id=$2',
          [participantId, predecessorId],
        )
      ).rows[0];
    const original = await historical();
    const { client, maker, checker } = fixture.governance;
    const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      key = `credential-continuity-${id()}`;
    const body = {
      credentialId: successorId,
      publicKeySpkiDer: pki.successor.publicKey.toString('base64'),
    };
    const candidateDigest = digest({ replacedCredentialId: predecessorId, ...body });
    const path = `/v1/identity/workloads/${predecessorId}/rotate`;
    const prepared = await client.mutation(
      maker,
      '/v1/identity/workloads/prepare',
      { mutation: 'ROTATE', replacedCredentialId: predecessorId, ...body },
      key,
      '1',
    );
    expect(prepared).toMatchObject({
      status: 202,
      body: { candidateDigest, expectedRevision: '1' },
    });
    expect((await client.mutation(maker, path, body, key, '1')).status).toBeGreaterThanOrEqual(400);
    expect(issuanceRequests).toBe(0);
    expect(
      (
        await admin.query(
          'select count(*)::int n from control.credential where participant_id=$1 and credential_id=$2',
          [participantId, successorId],
        )
      ).rows,
    ).toEqual([{ n: 0 }]);
    const requested = await client.policyMutation(maker, '/api/v1/approval-requests', {
      actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
      actionIntentDigest: client.actionDigests.get('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'),
      candidateDigest,
      makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
      reason: 'Renew the exact expired workload credential.',
    });
    expect(requested.status, JSON.stringify(requested)).toBe(202);
    const approvalRef = String(requested.body.resourceRef),
      approvalId = approvalRef.slice(-36),
      approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
    const decision = digest({
      actionIntentId: approveAction,
      approvalRequestId: approvalRef,
      candidateDigest,
      expectedRevision: '1',
      decision: 'APPROVE',
    });
    await client.stepUp(checker, approveAction, approvalId, decision);
    const approved = await client.policyMutation(
      checker,
      `/api/v1/approval-requests/${approvalRef}/approve`,
      {
        targetRef: approvalRef,
        actionIntentId: approveAction,
        actionIntentDigest: client.actionDigests.get(approveAction),
        inputDigest: decision,
        expectedRevision: '1',
        reason: 'Approve the stored workload and successor public key.',
      },
      '1',
    );
    expect(approved.status, JSON.stringify(approved)).toBe(202);
    await client.stepUp(maker, action, predecessorId, candidateDigest);
    const commit = () => client.mutation(maker, path, body, key, '1', approvalId);
    const result = await commit();
    expect(result, JSON.stringify(result)).toMatchObject({
      status: 200,
      body: {
        credentialId: successorId,
        replacedCredentialId: predecessorId,
        principalId,
        workloadId,
        state: 'ACTIVE',
        workloadEpoch: '2',
      },
    });
    expect(await commit()).toEqual(result);
    expect(issuanceRequests).toBe(1);
    expect(await historical()).toEqual(original);
    expect(
      (
        await admin.query(
          'select state,credential_epoch::text,rotated_from_credential_id::text from control.credential where participant_id=$1 and credential_id=$2',
          [participantId, predecessorId],
        )
      ).rows,
    ).toEqual([{ state: 'REVOKED', credential_epoch: '2', rotated_from_credential_id: null }]);
    const issued = (
      await admin.query(
        'select certificate_der,secret_fingerprint,rotated_from_credential_id::text,state,credential_epoch::text from control.credential where participant_id=$1 and credential_id=$2',
        [participantId, successorId],
      )
    ).rows[0];
    expect(issued).toEqual({
      certificate_der: pki.successor.certificate.raw,
      secret_fingerprint: sha(pki.successor.certificate.raw),
      rotated_from_credential_id: predecessorId,
      state: 'ACTIVE',
      credential_epoch: '2',
    });
    const operation = (
      await admin.query<{ id: string }>(
        `select consumed_operation_id::text id from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3 and state='CONSUMED'and catalog_operation_id='ID-OP-WORKLOAD-ROTATE'and candidate_digest=$4`,
        [
          participantId,
          privacyDomainId,
          predecessorId,
          Buffer.from(candidateDigest.slice(7), 'hex'),
        ],
      )
    ).rows;
    expect(operation).toHaveLength(1);
    const input = {
      participantId,
      privacyDomainId,
      predecessorCredentialId: predecessorId,
      predecessorCredentialEpoch: '1',
      successorCredentialId: successorId,
      successorCredentialEpoch: '2',
      credentialRotationOperationId: operation[0]!.id,
    };
    const provenance = (overrides: Partial<typeof input> = {}) =>
      runScopedTransaction(
        runtime,
        {
          participantId,
          privacyDomainId,
          actionIntentId: signingRotationActions.create,
          isolation: 'SERIALIZABLE',
        },
        id,
        (connection) =>
          readWorkloadSigningHandoverProvenance(
            connection,
            { ...input, ...overrides },
            fixture!.identityRuntimeVerifier,
          ),
      );
    const witness = await provenance();
    expect(witness).toMatchObject({
      ...input,
      principalId,
      makerPrincipalId: maker.principalId,
      checkerPrincipalId: checker.principalId,
      candidateDigest,
    });
    await expect(provenance({ credentialRotationOperationId: id() })).rejects.toThrow(
      WorkloadSigningHandoverProvenanceUnavailable,
    );
    await expect(provenance({ predecessorCredentialEpoch: '2' })).rejects.toThrow(
      WorkloadSigningHandoverProvenanceUnavailable,
    );
    await expect(provenance({ privacyDomainId: id() })).rejects.toThrow();
    await expect(provenance({ successorCredentialId: predecessorId })).rejects.toThrow(
      WorkloadSigningHandoverProvenanceUnavailable,
    );
    expect(
      (await client.mutation(maker, path, { ...body, credentialId: id() }, key, '1', approvalId))
        .status,
    ).toBeGreaterThanOrEqual(400);
    expect(issuanceRequests).toBe(1);
    const read = async () => {
      const res = await fetch(
        `${fixture!.service.identityUrl}/v1/identity/workloads/${successorId}/certificate`,
        {
          headers: {
            'Cookie': `__Host-openpc_session=${maker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
          },
        },
      );
      return { status: res.status, body: await res.json() };
    };
    const beforeRestart = await read();
    expect(beforeRestart.status).toBe(200);
    await fixture.service.restartIdentity();
    expect(await read()).toEqual(beforeRestart);
    expect(await commit()).toEqual(result);
    expect(await provenance()).toEqual(witness);
    expect(issuanceRequests).toBe(1);
    expect(await historical()).toEqual(original);
    const targetAfterRestart = await fixture.read(
      `runtime-targets/${createdTarget.body.resourceRef}`,
    );
    console.info(
      'OPENPC_CREDENTIAL_TARGET_READBACK|' +
        JSON.stringify({
          targetId,
          beforeStatus: targetRead.status,
          afterStatus: targetAfterRestart.status,
          beforeBodyDigest: digest(targetRead.body),
          afterBodyDigest: digest(targetAfterRestart.body),
          beforeEtag: targetRead.headers.get('etag'),
          afterEtag: targetAfterRestart.headers.get('etag'),
          requestReferencesDiffer:
            targetRead.headers.get('x-request-id') !==
            targetAfterRestart.headers.get('x-request-id'),
        }),
    );
    expect(targetAfterRestart.status).toBe(targetRead.status);
    expect(targetAfterRestart.body).toEqual(targetRead.body);
    expect(targetAfterRestart.headers.get('etag')).toBe(targetRead.headers.get('etag'));
    await checkCurrentWorkloadTransport(pki);
    complete = true;
    console.info(
      'OPENPC_CREDENTIAL_CONTINUITY|' +
        JSON.stringify({
          schema: 'pc.test.ordinary-credential-continuity.v1',
          ...witness,
          targetId,
          workloadId,
          publicTargetCreatedBeforeCertificateBinding: true,
          unchangedPublicTargetReadbackVerified: true,
          originalCertificateSha256: 'sha256:' + sha(old.certificate.raw).toString('hex'),
          successorCertificateSha256:
            'sha256:' + sha(pki.successor.certificate.raw).toString('hex'),
          issuerRequests: issuanceRequests,
          ordinaryRotationWitnessQualified: true,
          currentAndExpiredTransportQualified: true,
          controlHandoverAccepted: false,
          retainedDemoDataReused: false,
        }),
    );
  } catch (error) {
    failure = { error };
    const secondary: unknown[] = [];
    const retained = join(parent, 'secrets', `credential-continuity-failure-${basename(root)}`);
    const save: (() => Promise<unknown>)[] = [
      () => mkdir(retained, { recursive: true, mode: 0o700 }),
      () =>
        cp(root, join(retained, 'workload-material'), {
          recursive: true,
          errorOnExist: true,
          force: false,
        }),
      async () => {
        if (fixture)
          await cp(fixture.service.directory, join(retained, 'identity-runtime'), {
            recursive: true,
            errorOnExist: true,
            force: false,
          });
      },
      async () => {
        if (fixture)
          await writeFile(
            join(retained, 'synthetic-actors.private.json'),
            JSON.stringify({
              maker: fixture.governance.maker,
              checker: fixture.governance.checker,
              devices: [...fixture.governance.devices].map(([principalId, device]) => ({
                principalId,
                credentialId: device.credentialId,
                count: device.count,
                privateKeyPkcs8Base64: device.privateKey
                  .export({ format: 'der', type: 'pkcs8' })
                  .toString('base64'),
              })),
            }),
            { mode: 0o600, flag: 'wx' },
          );
      },
      () =>
        writeFile(
          join(retained, 'failure.private.json'),
          JSON.stringify({
            name: error instanceof Error ? error.name : typeof error,
            message: error instanceof Error ? error.message : 'Unknown failure',
            participantId,
            privacyDomainId,
            principalId,
            predecessorId,
            successorId,
          }),
          { mode: 0o600, flag: 'wx' },
        ),
    ];
    for (const step of save) {
      try {
        await step();
      } catch (retentionError) {
        secondary.push(retentionError);
      }
    }
    if (secondary.length)
      failure = {
        error: new AggregateError(
          [error, ...secondary],
          'Continuity failure evidence retention was incomplete',
        ),
      };
  }
  await closeFixtureResources(
    [
      () => fixture?.close(),
      () =>
        issuer?.listening
          ? new Promise<void>((resolve, reject) =>
              issuer!.close((e) => (e ? reject(e) : resolve())),
            )
          : undefined,
      () => runtime.end(),
      () => control.end(),
      () => admin.end(),
    ],
    failure,
  );
  if (failure) throw failure.error;
  if (complete) await rm(root, { recursive: true, force: true });
}
