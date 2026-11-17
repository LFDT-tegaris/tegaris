import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes, X509Certificate } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { Pool } from 'pg';
import { expect, it, vi } from 'vitest';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { digest, sha } from './public-governance-client.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { createLocalWorkloadIssuerFixture } from '../local-runtime/workload-issuer-runtime.js';
import {
  readWorkloadSigningHandoverProvenance,
  WorkloadSigningHandoverProvenanceUnavailable,
} from '../../../services/identity-service/src/db/workload-signing-handover-provenance.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';
import {
  workloadSigningHandoverFixture,
  workloadHandoverSigningFamilies,
} from './workload-signing-handover-fixture.js';
import {
  captureWorkloadSigningHandoverSource,
  WorkloadSigningHandoverSourceUnavailable,
} from '../../../services/identity-service/src/db/workload-signing-handover-source.js';
import { createLocalConfigurationAuthorizer } from '../../../services/control-api/src/configuration/local-authorizer.js';
import type { WorkloadSigningHandoverRequest } from '../../../services/identity-service/src/contracts/workload-signing-handover.js';
import {
  createWorkloadSigningHandover,
  readWorkloadSigningHandover,
  recordWorkloadSigningHandoverAttempt,
  claimWorkloadSigningHandoverDispatch,
  WorkloadSigningHandoverStoreError,
  loadWorkloadSigningHandoverAttempt,
  type WorkloadSigningHandoverScope,
} from '../../../services/identity-service/src/db/workload-signing-handover-store.js';
import { signingRotationActions } from '../../../packages/security-kernel/src/signing-operations.js';
import {
  identityEnvelopeContext,
  evidenceKeyId,
} from '../../../packages/security-kernel/src/index.js';
import {
  prepareHandoverProviderAttempt,
  type HandoverPreparationAttempt,
  handoverProviderBindingSchema,
} from '../../../services/identity-service/src/domain/workload-signing-handover-provider.js';
import type { IdentityEnvelopeRotationObservation } from '../../../services/identity-service/src/domain/identity-envelope-rotation-provider.js';
import { workloadHandoverProviderFixture } from './workload-handover-provider-fixture.js';
import {
  dispatchWorkloadSigningHandoverPreparation,
  reconcileWorkloadSigningHandoverPreparation,
} from '../../../services/identity-service/src/domain/workload-signing-handover-dispatch.js';
import {
  readWorkloadSigningHandoverObservations,
  readWorkloadSigningHandoverObservationsInTransaction,
  recordWorkloadSigningHandoverObservation,
} from '../../../services/identity-service/src/db/workload-signing-handover-observations.js';
import {
  createWorkloadSigningHandoverPossessionGeneration,
  readWorkloadSigningHandoverPossessionGeneration,
} from '../../../services/identity-service/src/db/workload-signing-handover-possession-store.js';
import { loadWorkloadSigningHandoverGeneration } from '../../../services/identity-service/src/db/workload-signing-handover-generation-reader.js';
import {
  snapshot as captureHandoverSnapshot,
  canonical as handoverCanonical,
  hash as handoverHash,
} from '../../../services/identity-service/src/db/workload-signing-handover-custody.js';
import {
  handoverPossessionMaximumLifetimeNs,
  handoverPossessionGenerationSchema,
  handoverPossessionGenerationDigest,
  verifyHandoverPossessionObservation,
} from '../../../services/identity-service/src/domain/workload-signing-handover-possession.js';
import { workloadSigningHandoverAdmissionOperation as admissionOperation } from '../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import { stageWorkloadSigningHandoverAdmissionCandidate } from '../../../services/identity-service/src/db/workload-signing-handover-admission-store.js';
import { assertCurrentHandoverAdmissionCandidate } from '../../../services/identity-service/src/db/workload-signing-handover-admission-reader.js';
import { canonicalAuthorizationDigest } from '../../../services/identity-service/src/contracts/authorization.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

/** Independent PKI with real expired/current leaves, never retained credentials or clock changes. */
async function certificates(
  root: string,
  participantId: string,
  workloadId: string,
  initiallyCurrent = false,
) {
  const file = (name: string) => join(root, name);
  const openssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'ignore' });
  const time = (value: number) =>
    new Date(value)
      .toISOString()
      .replace(/[-:T]/gu, '')
      .replace(/\.\d{3}Z$/u, 'Z');
  const now = Date.now();
  await writeFile(file('index'), '');
  await writeFile(file('serial'), '10\n');
  await writeFile(
    file('authority.cnf'),
    '[authority]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n',
  );
  await writeFile(
    file('issuer.cnf'),
    `[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=${file('index')}\nserial=${file('serial')}\nnew_certs_dir=${root}\ncertificate=${file('seed-ca.pem')}\nprivate_key=${file('ca.key')}\ndefault_md=sha256\npolicy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n`,
  );
  openssl(
    'req',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-nodes',
    '-days',
    '2',
    '-subj',
    '/CN=Workload rotation fixture CA',
    '-keyout',
    file('ca.key'),
    '-out',
    file('seed-ca.pem'),
  );
  openssl(
    'req',
    '-new',
    '-key',
    file('ca.key'),
    '-subj',
    '/CN=Workload rotation fixture CA',
    '-out',
    file('ca.csr'),
  );
  openssl(
    'ca',
    '-batch',
    '-selfsign',
    '-notext',
    '-config',
    file('issuer.cnf'),
    '-in',
    file('ca.csr'),
    '-out',
    file('ca.pem'),
    '-startdate',
    time(now - 86400000),
    '-enddate',
    time(now + 172800000),
    '-extfile',
    file('authority.cnf'),
    '-extensions',
    'authority',
  );
  await writeFile(
    file('client.cnf'),
    `[client]\nsubjectAltName=URI:urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}\nextendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n`,
  );
  const leaf = async (name: string, start: number, end: number, server = false) => {
    openssl(
      'req',
      '-new',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-subj',
      `/CN=Workload rotation ${name}`,
      '-keyout',
      file(`${name}.key`),
      '-out',
      file(`${name}.csr`),
    );
    openssl(
      'ca',
      '-batch',
      '-notext',
      '-config',
      file('issuer.cnf'),
      '-cert',
      file('ca.pem'),
      '-in',
      file(`${name}.csr`),
      '-out',
      file(`${name}.pem`),
      '-startdate',
      time(start),
      '-enddate',
      time(end),
      '-extfile',
      file(server ? 'server.cnf' : 'client.cnf'),
      '-extensions',
      server ? 'server' : 'client',
    );
    const certificate = new X509Certificate(await readFile(file(`${name}.pem`)));
    return {
      certificate,
      publicKey: Buffer.from(certificate.publicKey.export({ format: 'der', type: 'spki' })),
      pem: await readFile(file(`${name}.pem`)),
      privateKey: await readFile(file(`${name}.key`)),
    };
  };
  await writeFile(
    file('server.cnf'),
    '[server]\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n',
  );
  return {
    ca: await readFile(file('ca.pem')),
    predecessor: await leaf(
      'predecessor',
      now - 1800000,
      initiallyCurrent ? now + 10000 : now - 60000,
    ),
    successor: await leaf('successor', now - 10000, now + 3600000),
    server: await leaf('provider-server', now - 10000, now + 3600000, true),
  };
}

it('authenticates independent expired and current workload fixture certificates before database allocation', async () => {
  const parent = process.env.OPENPC_TEST_TMP_ROOT ?? process.env.OPENPC_TEST_ROOT;
  if (!parent?.startsWith('/')) throw new Error('Absolute isolated test scratch is required');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'workload-pki-preflight-'));
  try {
    const participantId = id(),
      workloadId = `urn:openpc:workload:${id()}`;
    const families = workloadHandoverSigningFamilies();
    expect(families).toHaveLength(7);
    expect(families.flatMap((family) => family.profiles)).toHaveLength(18);
    const configuration = families.find((family) => family.name === 'configuration')!;
    expect(
      configuration.profiles.filter((p) => p.profileId.startsWith('pc.control.module.')),
    ).toHaveLength(4);
    expect(
      configuration.profiles
        .filter((p) => p.profileId === 'pc.control.indexer-profile.create')
        .map((p) => p.profileVersion),
    ).toEqual([1, 2]);
    const pki = await certificates(root, participantId, workloadId);
    const ca = new X509Certificate(pki.ca),
      now = Date.now();
    expect(ca.ca).toBe(true);
    expect(ca.verify(ca.publicKey)).toBe(true);
    expect(new Date(ca.validFrom).getTime()).toBeLessThan(now - 1800000);
    expect(new Date(ca.validTo).getTime()).toBeGreaterThan(now + 3600000);
    for (const leaf of [pki.predecessor, pki.successor]) {
      expect(leaf.certificate.checkIssued(ca)).toBe(true);
      expect(leaf.certificate.verify(ca.publicKey)).toBe(true);
      expect(leaf.certificate.subjectAltName).toBe(
        `URI:urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`,
      );
      expect(leaf.publicKey).toEqual(
        leaf.certificate.publicKey.export({ format: 'der', type: 'spki' }),
      );
      expect(
        new Date(leaf.certificate.validTo).getTime() -
          new Date(leaf.certificate.validFrom).getTime(),
      ).toBeLessThanOrEqual(86400000);
    }
    expect(new Date(pki.predecessor.certificate.validTo).getTime()).toBeLessThan(now);
    expect(new Date(pki.successor.certificate.validFrom).getTime()).toBeLessThan(now);
    expect(new Date(pki.successor.certificate.validTo).getTime()).toBeGreaterThan(now);
    expect(pki.server.certificate.checkIP('127.0.0.1')).toBe('127.0.0.1');
    expect(pki.server.certificate.verify(ca.publicKey)).toBe(true);
    // Transport-only external readback. No database, command dispatch, Identity
    // state or admission is installed by this pre-allocation check.
    const providerIds = {
      receipt: 'synthetic-receipt-custody',
      envelope: 'synthetic-envelope-custody',
    };
    const binding = handoverProviderBindingSchema.parse({
      participantId,
      privacyDomainId: id(),
      environmentId: 'transport-preflight',
      handoverId: id(),
      sourceDigest: `sha256:${'01'.repeat(32)}`,
      successorCredentialId: id(),
      successorCredentialEpoch: '2',
      participantEpoch: '1',
      principalEpoch: '1',
      providerId: providerIds.envelope,
      replacement: {
        oldFingerprint: `sha256:${'02'.repeat(32)}`,
        oldTrustDigest: `sha256:${'03'.repeat(32)}`,
        expectedKeyEpoch: '1',
        oldReference: 'secret://local/old#1',
        newReference: 'secret://local/new#2',
        purpose: identityEnvelopeContext.purpose,
        signerRole: 'IDENTITY_ENVELOPE',
      },
    });
    const attempt = prepareHandoverProviderAttempt(binding, { operationId: id(), attemptId: id() });
    if (attempt.purpose !== identityEnvelopeContext.purpose)
      throw new Error('Expected envelope transport fixture');
    const at = BigInt(Date.now()) * 1000000n,
      r = attempt.request;
    const observed: IdentityEnvelopeRotationObservation = {
      schemaVersion: 1,
      providerId: providerIds.envelope,
      attemptId: r.attemptId,
      operationId: r.operationId,
      requestDigest: attempt.requestDigest,
      method: 'PREPARE',
      recordedAtNs: at.toString(),
      outcome: 'SUCCEEDED',
      reason: null,
      resultHex: null,
      descriptor: {
        participantId,
        privacyDomainId: r.privacyDomainId,
        environmentId: r.environmentId,
        workloadCredentialId: r.workloadCredentialId,
        workloadCredentialEpoch: r.workloadCredentialEpoch,
        secretClass: r.secretClass,
        purpose: r.purpose,
        purposeCode: r.purposeCode,
        schemaId: r.schemaId,
        schemaVersion: r.schemaVersion,
        schemaDefinitionDigest: r.schemaDefinitionDigest,
        profileId: r.profileId,
        profileVersion: r.profileVersion,
        profileDigest: r.profileDigest,
        reference: r.reference,
        version: r.version,
        algorithm: 'ES256',
        publicKeySpkiHex: pki.server.publicKey.toString('hex'),
        fingerprint: evidenceKeyId(pki.server.publicKey),
        validFromNs: (at - 1000000000n).toString(),
        validUntilNs: (at + 3600000000000n).toString(),
        state: 'ACTIVE',
        revokedAtNs: null,
        retiredAtNs: null,
      },
    };
    const provider = await workloadHandoverProviderFixture(undefined, pki, [attempt], providerIds);
    try {
      provider.observations.set(r.attemptId, observed);
      provider.lookupFaults.set(r.attemptId, 'NONCANONICAL');
      await expect(provider.providers.envelope.lookup(r)).rejects.toThrow();
      provider.lookupFaults.delete(r.attemptId);
      expect(await provider.providers.envelope.lookup(r)).toEqual({
        state: 'OBSERVED',
        observation: observed,
      });
      expect(provider.performs.size).toBe(0);
      provider.assertHealthy();
    } finally {
      await provider.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

function privateNativeFailure(error: unknown, depth = 0): unknown {
  if (!(error instanceof Error)) return { type: typeof error, value: String(error) };
  const detail = error as Error & { code?: unknown; cause?: unknown };
  return {
    name: error.name,
    message: error.message,
    stack: error.stack,
    code: detail.code,
    ...(depth < 5 && error instanceof AggregateError
      ? { errors: error.errors.map((value) => privateNativeFailure(value, depth + 1)) }
      : {}),
    ...(depth < 5 && detail.cause !== undefined
      ? { cause: privateNativeFailure(detail.cause, depth + 1) }
      : {}),
  };
}
interface HandoverProofJourneyContext {
  admin: Pool;
  runtime: Pool;
  scope: WorkloadSigningHandoverScope;
  foreignScope: WorkloadSigningHandoverScope;
  handoverId: string;
  handoverRequest: WorkloadSigningHandoverRequest;
  successorId: string;
  workloadId: string;
  fixture: Awaited<ReturnType<typeof contractAdministrationFixture>>;
  attempts: HandoverPreparationAttempt[];
  provider: Awaited<ReturnType<typeof workloadHandoverProviderFixture>>;
  restartIdentity: () => Promise<unknown>;
  reauthorize: (candidate: Record<string, unknown>) => Promise<WorkloadSigningHandoverScope>;
  authorizeAdmission: (
    candidate: Record<string, unknown>,
    foreign?: boolean,
  ) => Promise<WorkloadSigningHandoverScope>;
}
async function workloadRotationHandoverRehearsal(
  proofJourney?: (context: HandoverProofJourneyContext) => Promise<void>,
) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent?.startsWith('/')) throw new Error('Absolute isolated test scratch is required');
  await mkdir(parent, { recursive: true });
  const root = await mkdtemp(join(parent, 'workload-rotation-'));
  const admin = new Pool({ connectionString: adminUrl });
  const nativeRuntime = new Pool({ connectionString: runtimeUrl });
  const participantId = id(),
    privacyDomainId = id(),
    principalId = id();
  const workloadId = `urn:openpc:workload:${id()}`,
    predecessorId = id(),
    successorId = id();
  let retainedAuthority: WorkloadSigningHandoverScope['authority'] | undefined;
  let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
  let issuer: Awaited<ReturnType<typeof createLocalWorkloadIssuerFixture>> | undefined;
  let externalProvider: Awaited<ReturnType<typeof workloadHandoverProviderFixture>> | undefined;
  let foreignFixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
  let signingTrust: Awaited<ReturnType<typeof workloadSigningHandoverFixture>> | undefined;
  try {
    const pki = await certificates(root, participantId, workloadId, true);
    const token = randomBytes(32).toString('hex');
    issuer = await createLocalWorkloadIssuerFixture({
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
    await new Promise<void>((resolve, reject) => {
      issuer!.once('error', reject);
      issuer!.listen(0, '127.0.0.1', resolve);
    });
    const address = issuer.address() as AddressInfo;
    let issuanceRequests = 0;
    issuer.on('request', (request) => {
      if (request.method === 'POST' && request.url === '/v1/certificates') issuanceRequests++;
    });
    fixture = await contractAdministrationFixture(
      admin,
      runtimeUrl!,
      participantId,
      privacyDomainId,
      {
        principalKind: 'PLATFORM_OPERATOR',
        workloadIssuer: {
          url: `http://127.0.0.1:${address.port}/v1/certificates`,
          token,
          trustedCaPem: pki.ca,
        },
      },
    );
    await admin.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Certificate rotation initial trust','ACTIVE',1)`,
      [principalId, participantId],
    );
    const old = pki.predecessor;
    await admin.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,certificate_der,state,credential_epoch,valid_from,valid_until)
      values($1,$2,$3,'WORKLOAD_MTLS',$4,$5,$6,$7,$8,$9,$10,'ACTIVE',1,$11,$12)`,
      [
        predecessorId,
        participantId,
        principalId,
        old.certificate.issuer,
        old.certificate.subjectAltName!.slice(4),
        workloadId,
        sha(old.publicKey),
        old.publicKey,
        sha(old.certificate.raw),
        old.certificate.raw,
        new Date(old.certificate.validFrom),
        new Date(old.certificate.validTo),
      ],
    );
    signingTrust = await workloadSigningHandoverFixture(admin, {
      participantId,
      privacyDomainId,
      predecessorCredentialId: predecessorId,
      validUntilNs: BigInt(new Date(old.certificate.validTo).getTime()) * 1000000n,
    });
    const original = (
      await admin.query(
        'select certificate_der,public_key_spki_der,secret_fingerprint,valid_from,valid_until from control.credential where participant_id=$1 and credential_id=$2',
        [participantId, predecessorId],
      )
    ).rows[0];
    await vi.waitFor(() => expect(original.valid_until.getTime()).toBeLessThan(Date.now()), {
      timeout: 12000,
      interval: 25,
    });
    const { client, maker, checker } = fixture.governance;
    const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
    const key = `workload-rotation-${id()}`;
    const body = {
      credentialId: successorId,
      publicKeySpkiDer: pki.successor.publicKey.toString('base64'),
    };
    const candidate = { replacedCredentialId: predecessorId, ...body };
    const candidateDigest = digest(candidate);
    const path = `/v1/identity/workloads/${predecessorId}/rotate`;
    const prepared = await client.mutation(
      maker,
      '/v1/identity/workloads/prepare',
      { mutation: 'ROTATE', ...candidate },
      key,
      '1',
    );
    expect(prepared).toMatchObject({
      status: 202,
      body: { candidateDigest, expectedRevision: '1' },
    });
    const beforeApproval = await client.mutation(maker, path, body, key, '1');
    expect(beforeApproval.status).toBeGreaterThanOrEqual(400);
    expect(issuanceRequests).toBe(0);
    expect(
      (
        await admin.query(
          'select credential_id from control.credential where participant_id=$1 and credential_id=$2',
          [participantId, successorId],
        )
      ).rowCount,
    ).toBe(0);
    const requested = await client.policyMutation(maker, '/api/v1/approval-requests', {
      actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
      actionIntentDigest: client.actionDigests.get('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'),
      candidateDigest,
      makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
      reason: 'Rotate the exact expired workload credential.',
    });
    expect(requested.status, JSON.stringify(requested)).toBe(202);
    const approvalRef = String(requested.body.resourceRef),
      approvalId = approvalRef.slice(-36);
    const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
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
        reason: 'Approve the stored workload and public key.',
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
    expect(issuanceRequests).toBe(1);
    expect(await commit()).toEqual(result);
    expect(issuanceRequests).toBe(1);
    const read = async (credentialId: string, privacy = privacyDomainId, certificate = false) => {
      const response = await fetch(
        `${fixture!.service.identityUrl}/v1/identity/workloads/${credentialId}${certificate ? '/certificate' : ''}`,
        {
          headers: {
            'Cookie': `__Host-openpc_session=${maker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        },
      );
      return { status: response.status, body: await response.json() };
    };
    expect(await read(predecessorId)).toMatchObject({
      status: 200,
      body: { state: 'REVOKED', workloadEpoch: '2' },
    });
    expect(await read(successorId)).toMatchObject({
      status: 200,
      body: { state: 'ACTIVE', workloadEpoch: '2', rotatedFromCredentialId: predecessorId },
    });
    expect(await read(successorId, id(), true)).toMatchObject({
      status: 404,
      body: { error: { code: 'PC-IDENTITY-1008' } },
    });
    const foreignParticipantId = id(),
      foreignPrivacyDomainId = id();
    foreignFixture = await contractAdministrationFixture(
      admin,
      runtimeUrl!,
      foreignParticipantId,
      foreignPrivacyDomainId,
    );
    for (const suffix of ['', '/certificate']) {
      const response = await fetch(
        `${foreignFixture.service.identityUrl}/v1/identity/workloads/${successorId}${suffix}`,
        {
          headers: {
            'Cookie': `__Host-openpc_session=${foreignFixture.governance.maker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${foreignPrivacyDomainId}`,
          },
        },
      );
      const expected = suffix
        ? { status: 404, code: 'PC-IDENTITY-1008' }
        : { status: 401, code: 'PC-IDENTITY-1006' };
      expect(response.status).toBe(expected.status);
      expect(await response.json()).toMatchObject({ error: { code: expected.code } });
    }

    const substitution = await client.mutation(
      maker,
      path,
      { ...body, credentialId: id() },
      key,
      '1',
      approvalId,
    );
    expect(substitution.status).toBeGreaterThanOrEqual(400);
    expect(issuanceRequests).toBe(1);
    const committedRotation = await admin.query<{ operation_id: string }>(
      `select consumed_operation_id::text as operation_id from control.mutation_candidate
         where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3
           and candidate_digest=$4 and state='CONSUMED' and catalog_operation_id='ID-OP-WORKLOAD-ROTATE'`,
      [participantId, privacyDomainId, predecessorId, Buffer.from(candidateDigest.slice(7), 'hex')],
    );
    expect(committedRotation.rowCount).toBe(1);
    const provenanceInput = {
      participantId,
      privacyDomainId,
      predecessorCredentialId: predecessorId,
      predecessorCredentialEpoch: '1',
      successorCredentialId: successorId,
      successorCredentialEpoch: '2',
      credentialRotationOperationId: committedRotation.rows[0]!.operation_id,
    };
    const provenance = (
      overrides: Partial<typeof provenanceInput> = {},
      privacy = privacyDomainId,
      verifier = fixture!.identityRuntimeVerifier,
    ) =>
      runScopedTransaction(
        nativeRuntime,
        {
          participantId,
          privacyDomainId: privacy,
          actionIntentId: signingRotationActions.create,
          isolation: 'SERIALIZABLE',
        },
        id,
        (connection) =>
          readWorkloadSigningHandoverProvenance(
            connection,
            { ...provenanceInput, ...overrides },
            verifier,
          ),
      );
    const beforeRestartProvenance = await provenance();
    expect(beforeRestartProvenance).toMatchObject({
      ...provenanceInput,
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
    await expect(provenance({}, foreignPrivacyDomainId)).rejects.toThrow();
    await expect(provenance({ successorCredentialId: predecessorId })).rejects.toThrow(
      WorkloadSigningHandoverProvenanceUnavailable,
    );
    const wrongRuntimeTrust = createLocalIdentityRuntimeVerifier([
      generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }),
    ]);
    await expect(provenance({}, privacyDomainId, wrongRuntimeTrust)).rejects.toThrow(
      WorkloadSigningHandoverProvenanceUnavailable,
    );
    const handoverRequest: WorkloadSigningHandoverRequest = {
      schemaVersion: 1,
      actionIntentId: signingRotationActions.create,
      actionIntentDigest: client.actionDigests.get(signingRotationActions.create)!,
      environmentId: signingTrust.environmentId,
      predecessorCredentialId: predecessorId,
      successorCredentialId: successorId,
      credentialRotationOperationId: provenanceInput.credentialRotationOperationId,
      replacements: signingTrust.replacements,
      reason: 'Replace the complete expired initial signing bundle.',
    };
    const authorizer = createLocalConfigurationAuthorizer(
      fixture.service.identityUrl,
      fixture.service.identityInternalToken,
      privacyDomainId,
    );
    const authorized = await authorizer.propose!({
      sessionToken: maker.sessionToken,
      participantId,
      privacyDomainId,
      actionIntentId: signingRotationActions.create,
      resourceId: '*',
      candidateDigest: digest(handoverRequest),
      makerCheckerRequired: true,
      stepUpRequired: true,
      csrfToken: await client.csrf(
        maker,
        signingRotationActions.create,
        fixture.service.identityUrl,
      ),
      origin: fixture.service.identityUrl,
      host: new URL(fixture.service.identityUrl).host,
    });
    const capture = (overrides: Partial<WorkloadSigningHandoverRequest> = {}) =>
      runScopedTransaction(
        nativeRuntime,
        {
          participantId,
          privacyDomainId,
          actionIntentId: signingRotationActions.create,
          isolation: 'SERIALIZABLE',
        },
        id,
        (connection) =>
          captureWorkloadSigningHandoverSource(
            connection,
            {
              participantId,
              privacyDomainId,
              authority: {
                ...authorized,
                actionIntentId: signingRotationActions.create,
                resourceId: '*',
              },
              environmentId: signingTrust!.environmentId,
              verifier: fixture!.identityRuntimeVerifier,
            },
            { ...handoverRequest, ...overrides },
          ),
      );
    await expect(
      runScopedTransaction(
        nativeRuntime,
        {
          participantId,
          privacyDomainId,
          actionIntentId: signingRotationActions.create,
          isolation: 'SERIALIZABLE',
        },
        id,
        (connection) =>
          connection.query(
            `update control.identity_envelope_signing_selection set admission_version=admission_version+1
          where participant_id=$1 and privacy_domain_id=$2`,
            [participantId, privacyDomainId],
          ),
      ),
    ).rejects.toThrow('PC-AUTH-0005-ENVELOPE-SIGNING-CUTOVER');
    const captured = await capture();
    expect(captured.document.keys).toHaveLength(7);
    expect(captured.document.receiptSelections).toHaveLength(18);
    expect(captured.document.envelopeSelections).toHaveLength(1);
    expect(captured.document.issuer.workloadCredentialId).toBe(successorId);
    expect(
      captured.document.keys.every((key) => BigInt(key.oldKeyValidUntilNs) < captured.recordedAtNs),
    ).toBe(true);
    await expect(capture({ replacements: handoverRequest.replacements.slice(1) })).rejects.toThrow(
      WorkloadSigningHandoverSourceUnavailable,
    );
    await expect(capture({ environmentId: 'foreign-environment' })).rejects.toThrow(
      WorkloadSigningHandoverSourceUnavailable,
    );
    await expect(capture({ actionIntentDigest: `sha256:${'00'.repeat(32)}` })).rejects.toThrow(
      WorkloadSigningHandoverSourceUnavailable,
    );
    await expect(
      capture({
        replacements: handoverRequest.replacements.map((key) =>
          key.signerRole === 'BUSINESS_EFFECT' ? { ...key, signerRole: 'LIFECYCLE_EVIDENCE' } : key,
        ),
      }),
    ).rejects.toThrow(WorkloadSigningHandoverSourceUnavailable);
    await expect(
      capture({
        replacements: handoverRequest.replacements.map((key, index) =>
          index === 0 ? { ...key, oldTrustDigest: `sha256:${'00'.repeat(32)}` } : key,
        ),
      }),
    ).rejects.toThrow(WorkloadSigningHandoverSourceUnavailable);
    const handoverScope = {
      participantId,
      privacyDomainId,
      authority: {
        ...authorized,
        actionIntentId: signingRotationActions.create,
        resourceId: '*',
      },
      environmentId: signingTrust.environmentId,
      verifier: fixture.identityRuntimeVerifier,
    };
    retainedAuthority = handoverScope.authority;
    const handoverIdempotencyKey = `handover-${id()}`;
    const preparations = await Promise.allSettled([
      createWorkloadSigningHandover(
        nativeRuntime,
        handoverScope,
        handoverRequest,
        handoverIdempotencyKey,
      ),
      createWorkloadSigningHandover(
        nativeRuntime,
        handoverScope,
        handoverRequest,
        handoverIdempotencyKey,
      ),
    ]);
    const completed = preparations.filter((result) => result.status === 'fulfilled');
    if (completed.length === 0)
      throw new AggregateError(
        preparations.flatMap((result) => (result.status === 'rejected' ? [result.reason] : [])),
        'Concurrent handover preparation did not commit',
      );
    expect(completed.length).toBeGreaterThanOrEqual(1);
    const preparedHandover = completed[0]!.value;
    for (const result of preparations) {
      if (result.status === 'fulfilled') expect(result.value).toEqual(preparedHandover);
      else expect(result.reason).toMatchObject({ code: expect.stringMatching(/^(40001|23505)$/u) });
    }
    expect(preparedHandover).toMatchObject({
      state: 'PREPARING',
      keyCount: 7,
      receiptSelectionCount: 18,
      envelopeSelectionCount: 1,
    });
    expect(
      await createWorkloadSigningHandover(
        nativeRuntime,
        handoverScope,
        handoverRequest,
        handoverIdempotencyKey,
      ),
    ).toEqual(preparedHandover);
    await expect(
      createWorkloadSigningHandover(
        nativeRuntime,
        handoverScope,
        { ...handoverRequest, reason: 'A substituted intent.' },
        handoverIdempotencyKey,
      ),
    ).rejects.toThrow(WorkloadSigningHandoverStoreError);
    const foreignAuthorizer = createLocalConfigurationAuthorizer(
      foreignFixture.service.identityUrl,
      foreignFixture.service.identityInternalToken,
      foreignPrivacyDomainId,
    );
    const foreignMaker = foreignFixture.governance.maker;
    const foreignAuthorized = await foreignAuthorizer.propose!({
      sessionToken: foreignMaker.sessionToken,
      participantId: foreignParticipantId,
      privacyDomainId: foreignPrivacyDomainId,
      actionIntentId: signingRotationActions.create,
      resourceId: '*',
      candidateDigest: digest(handoverRequest),
      makerCheckerRequired: true,
      stepUpRequired: true,
      csrfToken: await foreignFixture.governance.client.csrf(
        foreignMaker,
        signingRotationActions.create,
        foreignFixture.service.identityUrl,
      ),
      origin: foreignFixture.service.identityUrl,
      host: new URL(foreignFixture.service.identityUrl).host,
    });
    await expect(
      readWorkloadSigningHandover(
        nativeRuntime,
        {
          ...handoverScope,
          participantId: foreignParticipantId,
          privacyDomainId: foreignPrivacyDomainId,
          authority: {
            ...foreignAuthorized,
            actionIntentId: signingRotationActions.create,
            resourceId: '*',
          },
          verifier: foreignFixture.identityRuntimeVerifier,
        },
        preparedHandover.handoverId,
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const providers = {
      receipt: 'synthetic-receipt-custody',
      envelope: 'synthetic-envelope-custody',
    };
    const savedAttempts = [];
    for (const replacement of handoverRequest.replacements) {
      const saved = await recordWorkloadSigningHandoverAttempt(
        nativeRuntime,
        handoverScope,
        preparedHandover.handoverId,
        replacement.oldFingerprint,
        providers,
      );
      expect(saved.request.workloadCredentialId).toBe(successorId);
      expect(
        await recordWorkloadSigningHandoverAttempt(
          nativeRuntime,
          handoverScope,
          preparedHandover.handoverId,
          replacement.oldFingerprint,
          providers,
        ),
      ).toEqual(saved);
      savedAttempts.push(saved);
    }
    expect(savedAttempts).toHaveLength(7);
    expect(new Set(savedAttempts.map((attempt) => attempt.request.attemptId)).size).toBe(7);
    expect(new Set(savedAttempts.map((attempt) => attempt.request.reference)).size).toBe(7);
    await expect(
      recordWorkloadSigningHandoverAttempt(
        nativeRuntime,
        handoverScope,
        preparedHandover.handoverId,
        handoverRequest.replacements[0]!.oldFingerprint,
        { ...providers, receipt: 'changed-provider', envelope: 'changed-provider' },
      ),
    ).rejects.toThrow(WorkloadSigningHandoverStoreError);
    externalProvider = await workloadHandoverProviderFixture(admin, pki, savedAttempts, providers);
    if (proofJourney) {
      await proofJourney({
        admin,
        runtime: nativeRuntime,
        scope: handoverScope,
        handoverId: preparedHandover.handoverId,
        handoverRequest,
        successorId,
        workloadId,
        fixture,
        attempts: savedAttempts,
        provider: externalProvider,
        foreignScope: {
          ...handoverScope,
          participantId: foreignParticipantId,
          privacyDomainId: foreignPrivacyDomainId,
          authority: {
            ...foreignAuthorized,
            actionIntentId: signingRotationActions.create,
            resourceId: '*',
          },
          verifier: foreignFixture.identityRuntimeVerifier,
        },
        restartIdentity: () => fixture!.service.restartIdentity(),
        reauthorize: async (candidate) => {
          const next = await authorizer.propose!({
            sessionToken: maker.sessionToken,
            participantId,
            privacyDomainId,
            actionIntentId: signingRotationActions.create,
            resourceId: '*',
            candidateDigest: digest(candidate),
            makerCheckerRequired: true,
            stepUpRequired: true,
            csrfToken: await client.csrf(
              maker,
              signingRotationActions.create,
              fixture!.service.identityUrl,
            ),
            origin: fixture!.service.identityUrl,
            host: new URL(fixture!.service.identityUrl).host,
          });
          return {
            ...handoverScope,
            authority: { ...next, actionIntentId: signingRotationActions.create, resourceId: '*' },
          };
        },
        authorizeAdmission: async (candidate, foreign = false) => {
          const target = foreign ? foreignFixture! : fixture!;
          const human = target.governance.maker,
            nativeClient = target.governance.client;
          const current = await createLocalConfigurationAuthorizer(
            target.service.identityUrl,
            target.service.identityInternalToken,
            target.privacyDomainId,
          ).propose!({
            sessionToken: human.sessionToken,
            participantId: target.participantId,
            privacyDomainId: target.privacyDomainId,
            actionIntentId: admissionOperation.actionIntentId,
            resourceId: preparedHandover.handoverId,
            candidateDigest: digest(candidate),
            makerCheckerRequired: true,
            stepUpRequired: true,
            csrfToken: await nativeClient.csrf(
              human,
              admissionOperation.actionIntentId,
              target.service.identityUrl,
            ),
            origin: target.service.identityUrl,
            host: new URL(target.service.identityUrl).host,
          });
          return {
            participantId: target.participantId,
            privacyDomainId: target.privacyDomainId,
            environmentId: handoverScope.environmentId,
            verifier: target.identityRuntimeVerifier,
            authority: {
              ...current,
              actionIntentId: admissionOperation.actionIntentId,
              catalogOperationId: admissionOperation.catalogOperationId,
              resourceId: preparedHandover.handoverId,
            },
          };
        },
      });
      return;
    }
    const receiptAttempts = savedAttempts.filter(
      (attempt) => attempt.signerRole !== 'IDENTITY_ENVELOPE',
    );
    const envelopeAttempt = savedAttempts.find(
      (attempt) => attempt.signerRole === 'IDENTITY_ENVELOPE',
    )!;
    const lostReceipt = receiptAttempts[0]!,
      rejectedReceipt = receiptAttempts[1]!,
      unissuedReceipt = receiptAttempts[2]!,
      conflictingReceipt = receiptAttempts[3]!,
      concurrentReceipt = receiptAttempts[4]!,
      lateReceipt = receiptAttempts[5]!;
    for (const attempt of [lostReceipt, envelopeAttempt, lateReceipt])
      externalProvider.dispatchFaults.set(attempt.request.attemptId, 'DROP_RESPONSE');
    externalProvider.dispatchFaults.set(rejectedReceipt.request.attemptId, 'REJECT');
    const dispatches = new Map<string, string>();
    for (const attempt of savedAttempts) {
      if (attempt === unissuedReceipt || attempt === concurrentReceipt) continue;
      const response = await dispatchWorkloadSigningHandoverPreparation(
        nativeRuntime,
        handoverScope,
        attempt.request.attemptId,
        externalProvider.providers,
      );
      dispatches.set(attempt.request.attemptId, response.dispatchId);
      expect(response.state).toBe(
        externalProvider.dispatchFaults.get(attempt.request.attemptId) === 'DROP_RESPONSE'
          ? 'UNKNOWN'
          : 'OBSERVED',
      );
    }
    const concurrent = await Promise.allSettled(
      [0, 1].map(() =>
        dispatchWorkloadSigningHandoverPreparation(
          nativeRuntime,
          handoverScope,
          concurrentReceipt.request.attemptId,
          externalProvider!.providers,
        ),
      ),
    );
    expect(concurrent.some((result) => result.status === 'fulfilled')).toBe(true);
    for (const result of concurrent) {
      if (result.status === 'rejected') expect(result.reason).toMatchObject({ code: '40001' });
      else dispatches.set(concurrentReceipt.request.attemptId, result.value.dispatchId);
    }
    const unissued = await claimWorkloadSigningHandoverDispatch(
      nativeRuntime,
      handoverScope,
      unissuedReceipt.request.attemptId,
      providers,
    );
    expect(unissued.dispatch).toBe(true);
    dispatches.set(unissuedReceipt.request.attemptId, unissued.dispatchId);
    const resumedUnissued = await dispatchWorkloadSigningHandoverPreparation(
      nativeRuntime,
      handoverScope,
      unissuedReceipt.request.attemptId,
      externalProvider.providers,
    );
    expect(resumedUnissued).toMatchObject({
      dispatchId: unissued.dispatchId,
      state: 'UNKNOWN',
      firstObservation: null,
    });
    expect(externalProvider.performs.get(unissuedReceipt.request.attemptId)).toBeUndefined();
    for (const attempt of [lostReceipt, envelopeAttempt, concurrentReceipt]) {
      const recovered = await reconcileWorkloadSigningHandoverPreparation(
        nativeRuntime,
        handoverScope,
        attempt.request.attemptId,
        dispatches.get(attempt.request.attemptId)!,
        externalProvider.providers,
      );
      expect(recovered).toMatchObject({
        state: 'OBSERVED',
        firstObservation: externalProvider.observations.get(attempt.request.attemptId),
      });
    }
    const rejected = await dispatchWorkloadSigningHandoverPreparation(
      nativeRuntime,
      handoverScope,
      rejectedReceipt.request.attemptId,
      externalProvider.providers,
    );
    expect(rejected).toMatchObject({
      state: 'OBSERVED',
      firstObservation: { outcome: 'REJECTED', reason: 'KEY_NOT_FOUND' },
    });
    for (const fault of ['UNKNOWN', 'ABSENT', 'MALFORMED'] as const) {
      externalProvider.lookupFaults.set(lostReceipt.request.attemptId, fault);
      const uncertain = await reconcileWorkloadSigningHandoverPreparation(
        nativeRuntime,
        handoverScope,
        lostReceipt.request.attemptId,
        dispatches.get(lostReceipt.request.attemptId)!,
        externalProvider.providers,
      );
      expect(uncertain).toMatchObject({
        state: 'OBSERVED',
        firstObservation: externalProvider.observations.get(lostReceipt.request.attemptId),
      });
    }
    externalProvider.lookupFaults.set(conflictingReceipt.request.attemptId, 'CONFLICT');
    expect(
      await reconcileWorkloadSigningHandoverPreparation(
        nativeRuntime,
        handoverScope,
        conflictingReceipt.request.attemptId,
        dispatches.get(conflictingReceipt.request.attemptId)!,
        externalProvider.providers,
      ),
    ).toMatchObject({
      state: 'CONFLICTING',
      firstObservation: externalProvider.observations.get(conflictingReceipt.request.attemptId),
    });
    externalProvider.lookupFaults.delete(conflictingReceipt.request.attemptId);
    expect(
      await reconcileWorkloadSigningHandoverPreparation(
        nativeRuntime,
        handoverScope,
        conflictingReceipt.request.attemptId,
        dispatches.get(conflictingReceipt.request.attemptId)!,
        externalProvider.providers,
      ),
    ).toMatchObject({ state: 'CONFLICTING' });
    await expect(
      dispatchWorkloadSigningHandoverPreparation(
        nativeRuntime,
        handoverScope,
        lostReceipt.request.attemptId,
        {
          ...externalProvider.providers,
          ids: { receipt: 'unrelated-provider', envelope: providers.envelope },
        },
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      reconcileWorkloadSigningHandoverPreparation(
        nativeRuntime,
        { participantId: foreignParticipantId, privacyDomainId: foreignPrivacyDomainId },
        lostReceipt.request.attemptId,
        dispatches.get(lostReceipt.request.attemptId)!,
        externalProvider.providers,
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    externalProvider.assertHealthy();
    expect([...externalProvider.performs.values()]).toEqual([1, 1, 1, 1, 1, 1]);
    const providerBeforeRestart = new Map<
      string,
      Awaited<ReturnType<typeof readWorkloadSigningHandoverObservations>>
    >();
    for (const attempt of savedAttempts)
      providerBeforeRestart.set(
        attempt.request.attemptId,
        await readWorkloadSigningHandoverObservations(
          nativeRuntime,
          handoverScope,
          attempt.request.attemptId,
          dispatches.get(attempt.request.attemptId)!,
        ),
      );
    await expect(
      recordWorkloadSigningHandoverObservation(
        nativeRuntime,
        handoverScope,
        lostReceipt.request.attemptId,
        dispatches.get(lostReceipt.request.attemptId)!,
        {
          state: 'OBSERVED',
          via: 'LOOKUP',
          observation: externalProvider.observations.get(envelopeAttempt.request.attemptId)!,
        },
      ),
    ).rejects.toThrow();
    await expect(
      runScopedTransaction(
        nativeRuntime,
        { participantId, privacyDomainId, actionIntentId: signingRotationActions.create },
        id,
        (connection, operationId) =>
          connection.query(
            `insert into control.workload_signing_handover_observation
          (participant_id,privacy_domain_id,handover_id,attempt_id,dispatch_id,observation_id,operation_id,sequence,result,result_canonical,result_digest,previous_digest,entry_canonical,entry_digest,recorded_at_ns)
          select participant_id,privacy_domain_id,handover_id,attempt_id,dispatch_id,$3,$4,sequence+1,result,result_canonical,result_digest,entry_digest,entry_canonical,entry_digest,recorded_at_ns
          from control.workload_signing_handover_observation where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$5 order by sequence desc limit 1`,
            [participantId, privacyDomainId, id(), operationId, lostReceipt.request.attemptId],
          ),
      ),
    ).rejects.toThrow('DATA-6021-HANDOVER-OBSERVATION-CUSTODY');
    for (const table of [
      'workload_signing_handover',
      'workload_signing_handover_attempt',
      'workload_signing_handover_dispatch',
      'workload_signing_handover_observation',
    ]) {
      await expect(
        runScopedTransaction(
          nativeRuntime,
          {
            participantId,
            privacyDomainId,
            actionIntentId: signingRotationActions.create,
            isolation: 'SERIALIZABLE',
          },
          id,
          (connection) =>
            connection.query(
              `update control.${table} set recorded_at_ns=recorded_at_ns where participant_id=$1 and privacy_domain_id=$2`,
              [participantId, privacyDomainId],
            ),
        ),
      ).rejects.toThrow();
    }
    const retainedCounts = await admin.query<{
      requests: number;
      attempts: number;
      successor_keys: number;
    }>(
      `select
        (select count(*)::integer from control.workload_signing_handover where participant_id=$1 and privacy_domain_id=$2) requests,
        (select count(*)::integer from control.workload_signing_handover_attempt where participant_id=$1 and privacy_domain_id=$2) attempts,
        (select count(*)::integer from control.business_signing_key where participant_id=$1 and privacy_domain_id=$2 and workload_credential_id=$3) successor_keys`,
      [participantId, privacyDomainId, successorId],
    );
    expect(retainedCounts.rows).toEqual([{ requests: 1, attempts: 7, successor_keys: 0 }]);
    const historical = (
      await admin.query(
        'select certificate_der,public_key_spki_der,secret_fingerprint,valid_from,valid_until from control.credential where participant_id=$1 and credential_id=$2',
        [participantId, predecessorId],
      )
    ).rows[0];
    expect(historical).toEqual(original);
    const issued = (
      await admin.query(
        'select certificate_der,secret_fingerprint,rotated_from_credential_id from control.credential where participant_id=$1 and credential_id=$2',
        [participantId, successorId],
      )
    ).rows[0];
    expect(issued).toMatchObject({
      certificate_der: pki.successor.certificate.raw,
      secret_fingerprint: sha(pki.successor.certificate.raw),
      rotated_from_credential_id: predecessorId,
    });
    const beforeRestart = await read(successorId, privacyDomainId, true);
    expect(beforeRestart.status).toBe(200);
    await fixture.service.restartIdentity();
    expect(await read(successorId, privacyDomainId, true)).toEqual(beforeRestart);
    expect(await provenance()).toEqual(beforeRestartProvenance);
    expect((await capture()).document).toEqual(captured.document);
    expect(
      await readWorkloadSigningHandover(nativeRuntime, handoverScope, preparedHandover.handoverId),
    ).toEqual(preparedHandover);
    for (const saved of savedAttempts)
      expect(
        await recordWorkloadSigningHandoverAttempt(
          nativeRuntime,
          handoverScope,
          preparedHandover.handoverId,
          saved.predecessorFingerprint,
          providers,
        ),
      ).toEqual(saved);
    expect(await commit()).toEqual(result);
    expect(issuanceRequests).toBe(1);
    for (const attempt of savedAttempts)
      expect(
        await readWorkloadSigningHandoverObservations(
          nativeRuntime,
          handoverScope,
          attempt.request.attemptId,
          dispatches.get(attempt.request.attemptId)!,
        ),
      ).toEqual(providerBeforeRestart.get(attempt.request.attemptId));
    const logoutAction = 'ACT-IDENTITY_DELETE_SESSION-V1',
      logoutReason = 'End preparation authority before collecting the delayed provider response.';
    const revision = (
      await admin.query('select row_version::text from control.session where session_id=$1', [
        maker.sessionId,
      ])
    ).rows[0].row_version;
    const loggedOut = await client.request(
      fixture.service.identityUrl + '/api/v1/session/logout',
      maker,
      {
        targetRef: `urn:openpc:resource:${maker.sessionId}`,
        actionIntentId: logoutAction,
        actionIntentDigest: client.actionDigests.get(logoutAction),
        inputDigest: digest({ sessionId: maker.sessionId, reason: logoutReason }),
        expectedRevision: revision,
        reason: logoutReason,
      },
      {
        'OpenPC-API-Version': '1',
        'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
        'X-Request-ID': id(),
        'X-Correlation-ID': id(),
        'Idempotency-Key': `logout-${id()}`,
        'OpenPC-Action-Intent-Digest': client.actionDigests.get(logoutAction)!,
        'If-Match': `"${digest({ resourceType: 'session', sessionId: maker.sessionId, revision })}"`,
        'X-CSRF-Token': await client.csrf(maker, logoutAction, fixture.service.identityUrl),
      },
    );
    expect(loggedOut.status, JSON.stringify(loggedOut.body)).toBe(202);
    await expect(
      dispatchWorkloadSigningHandoverPreparation(
        nativeRuntime,
        handoverScope,
        lateReceipt.request.attemptId,
        externalProvider.providers,
      ),
    ).rejects.toThrow();
    const late = await reconcileWorkloadSigningHandoverPreparation(
      nativeRuntime,
      handoverScope,
      lateReceipt.request.attemptId,
      dispatches.get(lateReceipt.request.attemptId)!,
      externalProvider.providers,
    );
    expect(late).toMatchObject({
      state: 'OBSERVED',
      firstObservation: externalProvider.observations.get(lateReceipt.request.attemptId),
    });
    externalProvider.assertHealthy();
    expect([...externalProvider.performs.values()]).toEqual([1, 1, 1, 1, 1, 1]);
    expect(
      (
        await admin.query(
          'select count(*)::int as count from control.business_signing_key where participant_id=$1 and privacy_domain_id=$2 and workload_credential_id=$3',
          [participantId, privacyDomainId, successorId],
        )
      ).rows,
    ).toEqual([{ count: 0 }]);
  } catch (error) {
    try {
      const retained = join(parent, 'secrets', `handover-failure-${basename(root)}`);
      await mkdir(retained, { recursive: true, mode: 0o700 });
      await writeFile(
        join(retained, 'failure.private.json'),
        JSON.stringify(privateNativeFailure(error)),
        { mode: 0o600, flag: 'wx' },
      );
      await cp(root, join(retained, 'workload-material'), {
        recursive: true,
        errorOnExist: true,
        force: false,
      });
      if (fixture) {
        await cp(fixture.service.directory, join(retained, 'identity-runtime'), {
          recursive: true,
          errorOnExist: true,
          force: false,
        });
        await writeFile(
          join(retained, 'human-credentials.private.json'),
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
      }
      await externalProvider?.savePrivateState(join(retained, 'provider.private.json'));
      await signingTrust?.savePrivateState(join(retained, 'predecessor-keys.private.json'));
      await writeFile(
        join(retained, 'scope.private.json'),
        JSON.stringify({
          participantId,
          privacyDomainId,
          principalId,
          workloadId,
          predecessorId,
          successorId,
          authority: retainedAuthority,
        }),
        { mode: 0o600, flag: 'wx' },
      );
    } catch (retentionError) {
      throw new AggregateError(
        [error, retentionError],
        'Native handover failure; private diagnostic retention was incomplete',
      );
    }
    throw error;
  } finally {
    await externalProvider?.close();
    await foreignFixture?.close();
    await fixture?.close();
    if (issuer?.listening)
      await new Promise<void>((resolve, reject) =>
        issuer!.close((error) => (error ? reject(error) : resolve())),
      );
    signingTrust?.close();
    await nativeRuntime.end();
    await admin.end();
    await rm(root, { recursive: true, force: true });
  }
}

integration(
  'rotates an expired workload through real approval and issuer owners, preserves history and rejects unapproved substitution',
  () => workloadRotationHandoverRehearsal(),
  60000,
);

integration(
  'retains seven successor proofs and governs admission after settled expired-challenge refresh',
  () =>
    workloadRotationHandoverRehearsal(async (context) => {
      const { admin, runtime, provider, handoverId, attempts } = context;
      let scope = context.scope;
      const input = {
        schemaVersion: 1 as const,
        supersedesGenerationId: null,
        reason: 'Prove possession of the complete prepared successor signing bundle.',
      };
      const idempotencyKey = `possession-${id()}`;
      const create = (request = input, key = idempotencyKey) =>
        createWorkloadSigningHandoverPossessionGeneration(
          runtime,
          scope,
          handoverId,
          request,
          key,
          provider.providers.ids,
        );
      const counts = async () =>
        (
          await admin.query(
            `select
    (select count(*)::int from control.workload_signing_handover_generation where participant_id=$1 and privacy_domain_id=$2) generations,
    (select count(*)::int from control.workload_signing_handover_attempt where participant_id=$1 and privacy_domain_id=$2 and stage='PREPARATION') preparations,
    (select count(*)::int from control.workload_signing_handover_attempt where participant_id=$1 and privacy_domain_id=$2 and stage='POSSESSION') proofs,
    (select count(*)::int from control.business_signing_key where participant_id=$1 and privacy_domain_id=$2 and workload_credential_id=$3) successor_keys`,
            [scope.participantId, scope.privacyDomainId, context.successorId],
          )
        ).rows[0];
      await expect(create()).rejects.toMatchObject({ code: 'CONFLICT' });
      expect(await counts()).toEqual({
        generations: 0,
        preparations: 7,
        proofs: 0,
        successor_keys: 0,
      });
      for (const attempt of attempts) {
        expect(
          await dispatchWorkloadSigningHandoverPreparation(
            runtime,
            scope,
            attempt.request.attemptId,
            provider.providers,
          ),
        ).toMatchObject({ state: 'OBSERVED', firstObservation: { outcome: 'SUCCEEDED' } });
        provider.assertHealthy();
      }
      for (const attempt of attempts) {
        const dispatch = await admin.query<{ dispatchId: string }>(
          `select dispatch_id::text as "dispatchId" from control.workload_signing_handover_dispatch where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
          [scope.participantId, scope.privacyDomainId, attempt.request.attemptId],
        );
        expect(dispatch.rowCount).toBe(1);
        const dispatchId = dispatch.rows[0]!.dispatchId;
        const narrow = await readWorkloadSigningHandoverObservations(
          runtime,
          { participantId: scope.participantId, privacyDomainId: scope.privacyDomainId },
          attempt.request.attemptId,
          dispatchId,
        );
        const authorized = await runScopedTransaction(
          runtime,
          { ...scope, actionIntentId: signingRotationActions.create },
          id,
          (client) =>
            readWorkloadSigningHandoverObservationsInTransaction(
              client,
              scope,
              attempt.request.attemptId,
              dispatchId,
            ),
        );
        expect(authorized).toEqual(narrow);
        expect(authorized).not.toHaveProperty('authority');
        expect(authorized).not.toHaveProperty('verifier');
      }
      scope = await context.reauthorize(input);
      const concurrent = await Promise.allSettled([create(), create()]);
      const successful = concurrent.filter((result) => result.status === 'fulfilled');
      if (successful.length === 0)
        throw new AggregateError(
          concurrent.flatMap((result) => (result.status === 'rejected' ? [result.reason] : [])),
          'Possession generation creation did not commit',
        );
      expect(successful.length).toBeGreaterThan(0);
      const generation = successful[0]!.value;
      for (const result of concurrent) {
        if (result.status === 'rejected')
          expect(result.reason).toMatchObject({ code: expect.stringMatching(/^(40001|23505)$/u) });
        else expect(result.value).toEqual(generation);
      }
      expect(generation).toMatchObject({
        state: 'PROVING',
        keyCount: 7,
        supersedesGenerationId: null,
      });
      expect(await create()).toEqual(generation);
      await expect(
        create({
          ...input,
          reason: 'A different request cannot replace the retained proof generation.',
        }),
      ).rejects.toMatchObject({ code: 'CONFLICT' });
      await expect(create(input, `new-initial-${id()}`)).rejects.toMatchObject({
        code: 'CONFLICT',
      });
      await expect(
        readWorkloadSigningHandoverPossessionGeneration(
          runtime,
          context.foreignScope,
          generation.generationId,
        ),
      ).rejects.toMatchObject({ code: 'NOT_FOUND' });
      expect(await counts()).toEqual({
        generations: 1,
        preparations: 7,
        proofs: 7,
        successor_keys: 0,
      });
      const document = await runScopedTransaction(
        runtime,
        {
          participantId: scope.participantId,
          privacyDomainId: scope.privacyDomainId,
          actionIntentId: signingRotationActions.create,
        },
        id,
        (client) => loadWorkloadSigningHandoverGeneration(client, scope, generation.generationId),
      );
      const originalGenerationBytes = Buffer.from(document.documentCanonical),
        originalCommands = generation.attempts.map((attempt) => handoverCanonical(attempt));
      provider.registerAttempts(generation.attempts);
      const receipt = generation.attempts.filter(
          (attempt) => attempt.signerRole !== 'IDENTITY_ENVELOPE',
        ),
        envelope = generation.attempts.find(
          (attempt) => attempt.signerRole === 'IDENTITY_ENVELOPE',
        )!;
      provider.dispatchFaults.set(receipt[0]!.request.attemptId, 'DROP_RESPONSE');
      provider.dispatchFaults.set(receipt[1]!.request.attemptId, 'CORRUPT_RESPONSE_SIGNATURE');
      provider.dispatchFaults.set(envelope.request.attemptId, 'DROP_RESPONSE');
      const dispatches = new Map<string, string>();
      for (const attempt of generation.attempts) {
        const result = await dispatchWorkloadSigningHandoverPreparation(
          runtime,
          scope,
          attempt.request.attemptId,
          provider.providers,
        );
        provider.assertHealthy();
        dispatches.set(attempt.request.attemptId, result.dispatchId);
        expect(result.state).toBe(
          provider.dispatchFaults.has(attempt.request.attemptId) ? 'UNKNOWN' : 'OBSERVED',
        );
        if (attempt === envelope) continue;
        const recovered = await reconcileWorkloadSigningHandoverPreparation(
          runtime,
          scope,
          attempt.request.attemptId,
          result.dispatchId,
          provider.providers,
        );
        provider.assertHealthy();
        expect(recovered).toMatchObject({
          state: 'OBSERVED',
          firstObservation: { outcome: 'SUCCEEDED', method: 'PROVE' },
        });
        const clock = (
          await admin.query(
            'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::numeric(20,0)::text as now',
          )
        ).rows[0].now;
        expect(
          verifyHandoverPossessionObservation(
            document.document,
            attempt,
            recovered.firstObservation,
            clock,
          ),
        ).toMatchObject({ state: 'PROVEN' });
      }
      const beforeRestart = [];
      for (const attempt of generation.attempts)
        beforeRestart.push(
          await readWorkloadSigningHandoverObservations(
            runtime,
            scope,
            attempt.request.attemptId,
            dispatches.get(attempt.request.attemptId)!,
          ),
        );
      await context.restartIdentity();
      expect(
        await readWorkloadSigningHandoverPossessionGeneration(
          runtime,
          scope,
          generation.generationId,
        ),
      ).toEqual(generation);
      for (const [index, attempt] of generation.attempts.entries())
        expect(
          await readWorkloadSigningHandoverObservations(
            runtime,
            scope,
            attempt.request.attemptId,
            dispatches.get(attempt.request.attemptId)!,
          ),
        ).toEqual(beforeRestart[index]);
      const refreshInput = {
        ...input,
        supersedesGenerationId: generation.generationId,
        reason: 'Refresh the same complete bundle after its original proof challenge expires.',
      };
      await expect(
        createWorkloadSigningHandoverPossessionGeneration(
          runtime,
          scope,
          handoverId,
          refreshInput,
          `early-refresh-${id()}`,
          provider.providers.ids,
        ),
      ).rejects.toMatchObject({ code: 'CONFLICT' });
      // Wait for the real server deadline. No clock, certificate, key or recorded
      // lifetime is changed to manufacture expiry or preserve stale authority.
      for (;;) {
        const now = BigInt(
          (
            await admin.query(
              'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::numeric(20,0)::text as now',
            )
          ).rows[0].now,
        );
        const remaining = BigInt(generation.expiresAtNs) - now;
        if (remaining <= 0n) break;
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(1000, Math.ceil(Number(remaining) / 1000000))),
        );
      }
      scope = await context.reauthorize(refreshInput);
      expect(
        await readWorkloadSigningHandoverPossessionGeneration(
          runtime,
          scope,
          generation.generationId,
        ),
      ).toMatchObject({ state: 'EXPIRED' });
      await expect(
        createWorkloadSigningHandoverPossessionGeneration(
          runtime,
          scope,
          handoverId,
          refreshInput,
          `unsettled-refresh-${id()}`,
          provider.providers.ids,
        ),
      ).rejects.toMatchObject({ code: 'CONFLICT' });
      expect(await counts()).toEqual({
        generations: 1,
        preparations: 7,
        proofs: 7,
        successor_keys: 0,
      });
      const late = await reconcileWorkloadSigningHandoverPreparation(
        runtime,
        scope,
        envelope.request.attemptId,
        dispatches.get(envelope.request.attemptId)!,
        provider.providers,
      );
      provider.assertHealthy();
      expect(late).toMatchObject({
        state: 'OBSERVED',
        firstObservation: { method: 'PROVE', outcome: 'SUCCEEDED' },
      });
      expect(() =>
        verifyHandoverPossessionObservation(
          document.document,
          envelope,
          late.firstObservation,
          generation.expiresAtNs,
        ),
      ).toThrow();
      await expect(
        runScopedTransaction(
          runtime,
          {
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            actionIntentId: signingRotationActions.create,
            isolation: 'SERIALIZABLE',
          },
          id,
          async (client, operationId) => {
            const current = await captureWorkloadSigningHandoverSource(
                client,
                scope,
                context.handoverRequest,
              ),
              authority = await captureHandoverSnapshot(
                client,
                scope,
                operationId,
                current.document,
              );
            const original = await loadWorkloadSigningHandoverAttempt(
              client,
              scope,
              envelope.request.attemptId,
            );
            await client.query(
              `insert into control.workload_signing_handover_dispatch(participant_id,privacy_domain_id,handover_id,attempt_id,dispatch_id,operation_id,maker_principal_id,attempt_digest,source_digest,authority_snapshot,authority_snapshot_digest,recorded_at_ns)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,floor(extract(epoch from clock_timestamp())*1000000)*1000)`,
              [
                scope.participantId,
                scope.privacyDomainId,
                handoverId,
                envelope.request.attemptId,
                id(),
                operationId,
                scope.authority.principalId,
                original.attemptDigest,
                Buffer.from(document.document.sourceDigest.slice(7), 'hex'),
                authority.bytes,
                authority.digest,
              ],
            );
          },
        ),
      ).rejects.toThrow('DATA-6021-HANDOVER-POSSESSION-DISPATCH-EXPIRED');
      await expect(
        runScopedTransaction(
          runtime,
          {
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            actionIntentId: signingRotationActions.create,
            isolation: 'SERIALIZABLE',
          },
          id,
          async (client, operationId) => {
            const current = await captureWorkloadSigningHandoverSource(
                client,
                scope,
                context.handoverRequest,
              ),
              authority = await captureHandoverSnapshot(
                client,
                scope,
                operationId,
                current.document,
              );
            const generationId = id(),
              issuedAtNs = current.recordedAtNs.toString();
            const next = handoverPossessionGenerationSchema.parse({
              ...document.document,
              generationId,
              operationId,
              supersedesGenerationId: generation.generationId,
              issuedAtNs,
              expiresAtNs: (BigInt(issuedAtNs) + handoverPossessionMaximumLifetimeNs).toString(),
            });
            await client.query(
              `insert into control.workload_signing_handover_generation(participant_id,privacy_domain_id,handover_id,generation_id,operation_id,maker_principal_id,idempotency_key,supersedes_generation_id,request,request_canonical,request_digest,document,document_canonical,document_digest,authority_snapshot,authority_snapshot_digest,recorded_at_ns)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,floor(extract(epoch from clock_timestamp())*1000000)*1000)`,
              [
                scope.participantId,
                scope.privacyDomainId,
                handoverId,
                generationId,
                operationId,
                scope.authority.principalId,
                `incomplete-${id()}`,
                generation.generationId,
                refreshInput,
                handoverCanonical(refreshInput),
                handoverHash(
                  'pc.identity.workload-signing-handover.possession-generation-request.v1',
                  handoverCanonical(refreshInput),
                ),
                next,
                handoverCanonical(next),
                Buffer.from(handoverPossessionGenerationDigest(next).slice(7), 'hex'),
                authority.bytes,
                authority.digest,
              ],
            );
          },
        ),
      ).rejects.toThrow('DATA-6021-HANDOVER-GENERATION-INCOMPLETE');
      expect(await counts()).toEqual({
        generations: 1,
        preparations: 7,
        proofs: 7,
        successor_keys: 0,
      });
      const refreshed = await createWorkloadSigningHandoverPossessionGeneration(
        runtime,
        scope,
        handoverId,
        refreshInput,
        `settled-refresh-${id()}`,
        provider.providers.ids,
      );
      expect(refreshed).toMatchObject({
        state: 'PROVING',
        keyCount: 7,
        supersedesGenerationId: generation.generationId,
      });
      expect(refreshed.generationId).not.toBe(generation.generationId);
      expect(
        new Set(
          [...generation.attempts, ...refreshed.attempts].map(
            (attempt) => attempt.request.attemptId,
          ),
        ).size,
      ).toBe(14);
      provider.registerAttempts(refreshed.attempts);
      for (const attempt of refreshed.attempts) {
        expect(
          await dispatchWorkloadSigningHandoverPreparation(
            runtime,
            scope,
            attempt.request.attemptId,
            provider.providers,
          ),
        ).toMatchObject({
          state: 'OBSERVED',
          firstObservation: { method: 'PROVE', outcome: 'SUCCEEDED' },
        });
        provider.assertHealthy();
      }
      expect(
        await readWorkloadSigningHandoverPossessionGeneration(
          runtime,
          scope,
          generation.generationId,
        ),
      ).toMatchObject({ state: 'SUPERSEDED' });
      const old = await runScopedTransaction(
        runtime,
        {
          participantId: scope.participantId,
          privacyDomainId: scope.privacyDomainId,
          actionIntentId: signingRotationActions.create,
        },
        id,
        (client) => loadWorkloadSigningHandoverGeneration(client, scope, generation.generationId),
      );
      expect(old.documentCanonical).toEqual(originalGenerationBytes);
      expect(
        (
          await readWorkloadSigningHandoverPossessionGeneration(
            runtime,
            scope,
            generation.generationId,
          )
        ).attempts.map((attempt) => handoverCanonical(attempt)),
      ).toEqual(originalCommands);
      expect(await counts()).toEqual({
        generations: 2,
        preparations: 7,
        proofs: 14,
        successor_keys: 0,
      });
      expect(provider.performs.size).toBe(21);
      expect([...provider.performs.values()].every((count) => count === 1)).toBe(true);
      await qualifyHandoverAdmissionCandidate(context, refreshed);
    }),
  600000,
);

async function qualifyHandoverAdmissionCandidate(
  context: HandoverProofJourneyContext,
  generation: Awaited<ReturnType<typeof createWorkloadSigningHandoverPossessionGeneration>>,
) {
  const { admin, runtime, handoverId, fixture, provider } = context;
  const { client, maker, checker } = fixture.governance;
  const request = {
    schemaVersion: 1 as const,
    actionIntentId: admissionOperation.actionIntentId,
    actionIntentDigest: client.actionDigests.get(admissionOperation.actionIntentId)!,
    generationId: generation.generationId,
    generationDigest: generation.generationDigest,
    reason: 'Review the complete successor keys and preserve every original signing profile.',
  };
  const scope = await context.authorizeAdmission(request),
    key = 'admission-candidate-' + id();
  const stage = (input = request, idem = key, actor = scope) =>
    stageWorkloadSigningHandoverAdmissionCandidate(runtime, actor, handoverId, input, idem);
  const snapshot = async () =>
    (
      await admin.query<{ snapshot: unknown }>(
        `select jsonb_build_object(
     'receipts',(select jsonb_agg(to_jsonb(s) order by profile_digest) from control.business_signing_selection s where participant_id=$1 and privacy_domain_id=$2),
     'envelopes',(select jsonb_agg(to_jsonb(s) order by profile_digest) from control.identity_envelope_signing_selection s where participant_id=$1 and privacy_domain_id=$2)) snapshot`,
        [scope.participantId, scope.privacyDomainId],
      )
    ).rows[0]!.snapshot;
  const before = await snapshot();
  await expect(stage(request, 'legacy-permission-' + id(), context.scope)).rejects.toMatchObject({
    code: 'DENIED',
  });
  const concurrent = await Promise.allSettled([stage(), stage()]);
  const successes = concurrent.filter((result) => result.status === 'fulfilled');
  if (!successes.length)
    throw new AggregateError(
      concurrent.flatMap((result) => (result.status === 'rejected' ? [result.reason] : [])),
      'Handover admission candidate did not commit',
    );
  for (const result of concurrent)
    if (result.status === 'rejected')
      expect(['40001', '23505', 'PC-DATA-6007', 'CONFLICT']).toContain(result.reason?.code);
  const staged = await stage();
  expect(staged).toMatchObject({
    state: 'PROPOSED',
    keyCount: 7,
    receiptSelectionCount: 18,
    envelopeSelectionCount: 1,
  });
  expect(staged.document.workloadId).toBe(context.workloadId);
  expect(staged.candidateDigest).toBe(canonicalAuthorizationDigest(staged.document));
  const storedCandidate = await admin.query<{
    digest: string;
    sqlDigest: string;
    originalDocument: boolean;
  }>(
    `select 'sha256:'||encode(candidate_digest,'hex') digest,
      'sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(candidate_document),'UTF8')),'hex') as "sqlDigest",
      candidate_document=$4::jsonb as "originalDocument"
     from control.mutation_candidate where mutation_candidate_id=$1 and participant_id=$2 and privacy_domain_id=$3`,
    [
      staged.candidateId,
      scope.participantId,
      scope.privacyDomainId,
      JSON.stringify(staged.document),
    ],
  );
  expect(storedCandidate.rowCount).toBe(1);
  expect(storedCandidate.rows[0]).toEqual({
    digest: staged.candidateDigest,
    sqlDigest: staged.candidateDigest,
    originalDocument: true,
  });
  expect(staged.expiresAtNs).toBe(generation.expiresAtNs);
  expect((await stage()).document).toEqual(staged.document);
  await expect(
    stage({ ...request, reason: 'A changed explanation cannot replace the original candidate.' }),
  ).rejects.toMatchObject({ code: 'CONFLICT' });
  const foreign = await context.authorizeAdmission(request, true);
  await expect(stage(request, 'foreign-admission-' + id(), foreign)).rejects.toMatchObject({
    code: 'NOT_FOUND',
  });
  const candidateCount = async () =>
    Number(
      (
        await admin.query(
          `select count(*)::int count from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and resource_id=$3 and catalog_operation_id=$4`,
          [
            scope.participantId,
            scope.privacyDomainId,
            handoverId,
            admissionOperation.catalogOperationId,
          ],
        )
      ).rows[0]!.count,
    );
  expect(await candidateCount()).toBe(1);
  const incomplete = { ...staged.document, proofs: staged.document.proofs.slice(1) };
  await expect(
    runScopedTransaction(
      runtime,
      {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        actionIntentId: admissionOperation.actionIntentId,
        isolation: 'SERIALIZABLE',
      },
      id,
      (connection) =>
        connection.query(
          `insert into control.mutation_candidate(participant_id,privacy_domain_id,action_intent_id,catalog_operation_id,resource_type,operation_class,
       resource_id,candidate_digest,candidate_document,expected_revision,idempotency_key,maker_principal_id,maker_session_id,maker_session_epoch,
       maker_participant_epoch,maker_principal_epoch,maker_assignment_id,maker_assignment_row_version,maker_authority_envelope_id,maker_authority_epoch,
       maker_delegation_epoch,state,expires_at)
       select participant_id,privacy_domain_id,action_intent_id,catalog_operation_id,resource_type,operation_class,
       resource_id,$5,$4::jsonb,expected_revision,$6,maker_principal_id,maker_session_id,maker_session_epoch,maker_participant_epoch,maker_principal_epoch,
       maker_assignment_id,maker_assignment_row_version,maker_authority_envelope_id,maker_authority_epoch,maker_delegation_epoch,'PROPOSED',expires_at
       from control.mutation_candidate where participant_id=$1 and privacy_domain_id=$2 and mutation_candidate_id=$3`,
          [
            scope.participantId,
            scope.privacyDomainId,
            staged.candidateId,
            incomplete,
            Buffer.from(canonicalAuthorizationDigest(incomplete).slice(7), 'hex'),
            'raw-incomplete-admission-' + id(),
          ],
        ),
    ),
  ).rejects.toThrow('DATA-6021-HANDOVER-ADMISSION-CURRENT');
  expect(await candidateCount()).toBe(1);

  const createApprovalAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
    approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
  const createApproval = (candidateDigest: string, checkerId = checker.principalId) =>
    client.policyMutation(maker, '/api/v1/approval-requests', {
      actionIntentId: createApprovalAction,
      actionIntentDigest: client.actionDigests.get(createApprovalAction),
      candidateDigest,
      makerSubjectRef: 'urn:openpc:resource:' + maker.principalId,
      checkerSubjectRef: 'urn:openpc:resource:' + checkerId,
      reason: 'Review this complete signing handover under the explicit admission permission.',
    });
  expect(
    (await createApproval(staged.candidateDigest, maker.principalId)).status,
  ).toBeGreaterThanOrEqual(400);
  await client.stepUp(maker, admissionOperation.actionIntentId, handoverId, staged.candidateDigest);
  const created = await createApproval(staged.candidateDigest);
  expect(created.status, JSON.stringify(created.body)).toBe(202);
  const approvalRef = String(created.body.resourceRef),
    approvalId = approvalRef.slice(-36);
  const decisionDigest = digest({
    actionIntentId: approveAction,
    approvalRequestId: approvalRef,
    candidateDigest: staged.candidateDigest,
    expectedRevision: '1',
    decision: 'APPROVE',
  });
  const decisionBody = {
    targetRef: approvalRef,
    actionIntentId: approveAction,
    actionIntentDigest: client.actionDigests.get(approveAction),
    inputDigest: decisionDigest,
    expectedRevision: '1',
    reason: 'Independent checker approves the exact complete handover candidate.',
  };
  expect(
    (
      await client.policyMutation(
        maker,
        '/api/v1/approval-requests/' + approvalRef + '/approve',
        decisionBody,
        '1',
      )
    ).status,
  ).toBeGreaterThanOrEqual(400);
  await client.stepUp(checker, approveAction, approvalId, decisionDigest);
  const approved = await client.policyMutation(
    checker,
    '/api/v1/approval-requests/' + approvalRef + '/approve',
    decisionBody,
    '1',
  );
  expect(approved.status, JSON.stringify(approved.body)).toBe(202);
  const retained = await admin.query<{
    checkerId: string;
    digest: Buffer;
    evidence: Buffer;
    cose: Buffer;
    candidateState: string;
    deadlineNs: string;
  }>(
    `select decision.approver_principal_id::text as "checkerId",decision.candidate_digest as digest,
     decision.evidence_cbor as evidence,decision.cose_sign1 as cose,candidate.state::text as "candidateState",
     (extract(epoch from approval.expires_at)*1000000000)::numeric(20,0)::text as "deadlineNs"
     from control.approval_request approval join control.approval_decision_record decision using(participant_id,privacy_domain_id,approval_request_id)
     join control.mutation_candidate candidate on candidate.participant_id=approval.participant_id and candidate.privacy_domain_id=approval.privacy_domain_id
      and candidate.mutation_candidate_id=approval.subject_id
     where approval.participant_id=$1 and approval.privacy_domain_id=$2 and approval.approval_request_id=$3
      and approval.state='APPROVED' and decision.decision='APPROVE'`,
    [scope.participantId, scope.privacyDomainId, approvalId],
  );
  expect(retained.rowCount).toBe(1);
  expect(retained.rows[0]!.checkerId).toBe(checker.principalId);
  expect(retained.rows[0]!.digest).toEqual(Buffer.from(staged.candidateDigest.slice(7), 'hex'));
  expect(retained.rows[0]!.candidateState).toBe('APPROVED');
  expect(BigInt(retained.rows[0]!.deadlineNs)).toBeLessThanOrEqual(BigInt(generation.expiresAtNs));
  expect(
    await fixture.identityRuntimeVerifier.verifyCanonicalAssertion(
      retained.rows[0]!.evidence,
      retained.rows[0]!.cose,
    ),
  ).toBeDefined();
  expect(await stage()).toMatchObject({
    state: 'APPROVED',
    candidateDigest: staged.candidateDigest,
    document: staged.document,
  });
  await context.restartIdentity();
  const restartedScope = await context.authorizeAdmission(request);
  expect(await stage(request, key, restartedScope)).toMatchObject({
    state: 'APPROVED',
    candidateDigest: staged.candidateDigest,
    document: staged.document,
  });

  const secondRequest = {
    ...request,
    reason: 'Review a separate explicit candidate before testing a later provider conflict.',
  };
  const second = await stage(secondRequest, 'second-admission-review-' + id(), restartedScope);
  const secondCreated = await createApproval(second.candidateDigest);
  expect(secondCreated.status, JSON.stringify(secondCreated.body)).toBe(202);
  const secondRef = String(secondCreated.body.resourceRef),
    secondId = secondRef.slice(-36);
  const proof = generation.attempts.find((attempt) => attempt.signerRole !== 'IDENTITY_ENVELOPE')!;
  const originalDispatch = await admin.query<{ dispatchId: string }>(
    `select dispatch_id::text as "dispatchId" from control.workload_signing_handover_dispatch where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
    [scope.participantId, scope.privacyDomainId, proof.request.attemptId],
  );
  expect(originalDispatch.rowCount).toBe(1);
  provider.lookupFaults.set(proof.request.attemptId, 'CONFLICT');
  expect(
    await reconcileWorkloadSigningHandoverPreparation(
      runtime,
      context.scope,
      proof.request.attemptId,
      originalDispatch.rows[0]!.dispatchId,
      provider.providers,
    ),
  ).toMatchObject({
    state: 'CONFLICTING',
  } satisfies Pick<
    Awaited<ReturnType<typeof reconcileWorkloadSigningHandoverPreparation>>,
    'state'
  >);
  provider.lookupFaults.delete(proof.request.attemptId);
  await expect(
    runScopedTransaction(
      runtime,
      {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        actionIntentId: admissionOperation.actionIntentId,
        isolation: 'SERIALIZABLE',
      },
      id,
      (connection) =>
        assertCurrentHandoverAdmissionCandidate(connection, restartedScope, staged.document),
    ),
  ).rejects.toMatchObject({ code: 'CONFLICT' });
  const secondDigest = digest({
    actionIntentId: approveAction,
    approvalRequestId: secondRef,
    candidateDigest: second.candidateDigest,
    expectedRevision: '1',
    decision: 'APPROVE',
  });
  await client.stepUp(checker, approveAction, secondId, secondDigest);
  const blocked = await client.policyMutation(
    checker,
    '/api/v1/approval-requests/' + secondRef + '/approve',
    {
      targetRef: secondRef,
      actionIntentId: approveAction,
      actionIntentDigest: client.actionDigests.get(approveAction),
      inputDigest: secondDigest,
      expectedRevision: '1',
      reason: 'A later conflicting proof must block this otherwise valid checker decision.',
    },
    '1',
  );
  // Approval admission failures retain the endpoint's flat public problem response.
  expect(blocked.status).toBe(403);
  expect(blocked.body).toEqual({
    type: 'https://errors.openpc.local/pc-policy-2005',
    title: 'Policy authorization denied',
    status: 403,
    code: 'PC-POLICY-2005',
    retryable: false,
    truthState: 'FAILED',
    traceId: expect.stringMatching(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    ),
  });
  expect(
    (
      await admin.query(
        `select count(*)::int count from control.approval_decision_record where participant_id=$1 and privacy_domain_id=$2 and approval_request_id=$3`,
        [scope.participantId, scope.privacyDomainId, secondId],
      )
    ).rows[0]!.count,
  ).toBe(0);
  expect(
    (
      await admin.query(
        `select count(*)::int count from control.business_signing_key where participant_id=$1 and privacy_domain_id=$2 and workload_credential_id=$3`,
        [scope.participantId, scope.privacyDomainId, context.successorId],
      )
    ).rows[0]!.count,
  ).toBe(0);
  expect(await snapshot()).toEqual(before);
  expect(provider.performs.size).toBe(21);
  expect([...provider.performs.values()].every((count) => count === 1)).toBe(true);
  provider.assertHealthy();
  const database = new URL(adminUrl!);
  const catalogue = execFileSync(
    'node',
    [
      '--import',
      'tsx',
      'tests/integration/local-runtime/signing-candidate-catalog.mjs',
      database.hostname,
      join(process.env.OPENPC_TEST_TMP_ROOT!, 'secrets/control_pg_password'),
      database.port,
    ],
    { encoding: 'utf8', timeout: 120000, maxBuffer: 65536 },
  );
  expect(catalogue).toMatch(/OPENPC_SIGNING_CANDIDATE_CATALOG\|PASS\|/u);
}
