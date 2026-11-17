import { generateKeyPairSync } from 'node:crypto';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { evidenceKeyId } from '../../../packages/security-kernel/src/business-transition/cose.js';
import {
  signSecretRecipientProfile,
  verifyInstalledSecretRecipient,
  type SecretRecipientProfile,
} from '../../../packages/security-kernel/src/secret-recipient/profile.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  inspectOperationsSecretProbe,
  operationsSecretProbeQuery,
  parseOperationsSecretObservationRequest,
} from '../../../services/identity-service/src/domain/operations-secret-resolution.js';
// @ts-expect-error The released JavaScript owner has no declaration-generation seam yet.
import * as installation from '../../../scripts/operations/installation-secret-binding.mjs';
const {
  parseOperationsSecretAssociation,
  readOperationsProcessIdentity,
  assertOperationsProcessIdentity,
  operationsSecretRecipientPins,
} = installation;

const h = (value: string) => `sha256:${value.repeat(64)}`;
function structuralAssociation() {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = key.publicKey.export({ format: 'der', type: 'spki' });
  const reference = 'secret://test-memory-resolver/fact/candidate#v1';
  const process = {
    pid: 1,
    startTicks: '100',
    bootId: '00000000-0000-4000-8000-000000000001',
    startedAtMs: 1000,
    executable: '/usr/local/bin/openpc-fact-local-runtime',
    uid: 65532,
  };
  return {
    profile: 'test',
    associationId: id(),
    environmentId: 'secret-test',
    participantId: id(),
    privacyDomainId: id(),
    generationId: id(),
    operationsInstallationDigest: h('a'),
    candidateDigest: h('b'),
    recipientBindingDigest: h('c'),
    recipientInstallationDigest: h('d'),
    recipientGeneration: '7',
    recipientIssuerSpkiHex: spki.toString('hex'),
    recipientPayloadHex: '00',
    recipientCoseHex: '00'.repeat(65),
    field: 'postgres.candidateIndexDsnSecretRef',
    consumerId: 'LS-FACT-BRIDGE',
    storeId: 'STORE-CANDIDATE-INDEX-PG',
    reference,
    version: 'v1',
    referenceFingerprint: sha256(Buffer.from(reference)),
    fingerprint: sha256({ providerId: 'test-memory-resolver', reference, version: 'v1' }),
    principalId: id(),
    workloadCredentialId: id(),
    workloadCredentialEpoch: '1',
    consumerInstanceId: id(),
    consumerStartedAtMs: 1000,
    consumerProcess: {
      ...process,
      container: {
        id: '1'.repeat(64),
        imageId: h('a'),
        owner: 'fixture-owner',
        startedAt: '2026-09-25T00:00:00.000000000Z',
        engineEndpoint: 'unix:///var/run/docker.sock',
        networkId: '2'.repeat(64),
        address: '172.18.0.10',
      },
    },
    observerInstanceId: id(),
    observerStartedAtMs: 1000,
    observerProcess: { ...process, executable: '/usr/local/bin/node', uid: 1000 },
    observerBackendPid: 100,
    observerBackendStart: '2026-09-25 00:00:00+00',
    issuerSpkiHex: spki.toString('hex'),
    issuerKeyId: evidenceKeyId(spki),
    issuerEpoch: '1',
    issuerValidFromMs: 1000,
    issuerValidUntilMs: 5000,
  };
}
it('typed association keeps independently installed source identities without granting authority', () => {
  const a = structuralAssociation();
  expect(parseOperationsSecretAssociation(a).generationId).not.toBe(a.recipientGeneration);
  for (const change of [
    { profile: 'production' },
    { field: 'postgres.controlDsnSecretRef' },
    { consumerId: 'LS-NOTIFICATION' },
    { recipientGeneration: a.generationId },
    { generationId: '7' },
    { referenceFingerprint: h('f') },
    { fingerprint: 'not-a-version-fingerprint' },
    { consumerStartedAtMs: 2000 },
    { consumerProcess: { ...a.consumerProcess, uid: 0 } },
    { consumerProcess: { ...a.consumerProcess, executable: '/tmp/openpc-fact-local-runtime' } },
    { reference: 'secret://test-memory-resolver/fact/candidate#latest', version: 'latest' },
    { reference: a.reference, version: 'different' },
    { checked: true },
    { issuerKeyId: h('0') },
  ])
    expect(() => parseOperationsSecretAssociation({ ...a, ...change })).toThrow();
  // These structural fixture bytes are never installed/signed/admitted.
});
it('prepared association verifies exact original signed recipient bytes across independent generations', () => {
  const a = structuralAssociation();
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = issuer.publicKey.export({ type: 'spki', format: 'der' });
  const claims: SecretRecipientProfile = {
    environmentId: a.environmentId,
    participantId: a.participantId,
    privacyDomainId: a.privacyDomainId,
    installationDigest: a.recipientInstallationDigest,
    generation: a.recipientGeneration,
    consumerId: 'LS-FACT-BRIDGE',
    secretClass: 'SECRET-DB-CREDENTIAL',
    purpose: 'POSTGRES_CONNECT',
    store: 'STORE-CANDIDATE-INDEX-PG',
    reference: a.reference,
    version: a.version,
    principalId: a.principalId,
    workloadCredentialId: a.workloadCredentialId,
    workloadCredentialEpoch: a.workloadCredentialEpoch,
    validFromMs: 1000,
    validUntilMs: 5000,
    issuerKeyId: evidenceKeyId(spki),
  };
  const original = signSecretRecipientProfile(
    issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
    spki,
    claims,
  );
  const prepared = parseOperationsSecretAssociation({
    ...a,
    recipientIssuerSpkiHex: spki.toString('hex'),
    recipientPayloadHex: original.payload.toString('hex'),
    recipientCoseHex: original.cose.toString('hex'),
    recipientBindingDigest: sha256(original.cose),
  });
  const verify = (
    association: unknown,
    payload = original.payload,
    cose = original.cose,
    now = 2000,
  ) =>
    verifyInstalledSecretRecipient(operationsSecretRecipientPins(association), payload, cose, now);
  expect(verify(prepared)).toEqual(claims);
  expect(prepared.generationId).not.toBe(claims.generation);
  // An ops UUID or its installation digest can never replace the recipient's
  // independently installed u64 / installation identity.
  for (const change of [
    { recipientGeneration: '8' },
    { recipientGeneration: a.generationId },
    { recipientInstallationDigest: a.operationsInstallationDigest },
    { participantId: id() },
    { privacyDomainId: id() },
    { workloadCredentialEpoch: '2' },
    { workloadCredentialId: id() },
    { recipientBindingDigest: h('0') },
  ])
    expect(() => verify({ ...prepared, ...change })).toThrow();
  const changed = Buffer.from(original.cose);
  changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
  expect(() =>
    verify({ ...prepared, recipientBindingDigest: sha256(changed) }, original.payload, changed),
  ).toThrow();
  expect(() => verify(prepared, original.payload, original.cose, 5000)).toThrow();
});
it('observation transport rejects caller success/start assertions and malformed backend identity', () => {
  const challenge = { phase: 'CHALLENGE', associationId: id(), consumerInstanceId: id() };
  expect(parseOperationsSecretObservationRequest(challenge)).toEqual(challenge);
  const observation = {
    ...challenge,
    phase: 'OBSERVE',
    challengeId: id(),
    backendPid: 23,
    backendStart: '1790000000.123456',
  };
  expect(parseOperationsSecretObservationRequest(observation)).toEqual(observation);
  for (const input of [
    { ...challenge, checked: true },
    { ...challenge, consumerStartedAtMs: 1 },
    { ...challenge, phase: 'PUBLISH' },
    { ...challenge, associationId: '7' },
    { ...observation, backendPid: 2147483648 },
    { ...observation, backendPid: NaN },
    { ...observation, backendStart: '' },
    { ...observation, backendStart: 'now()' },
    { ...observation, backendStart: '1790000000.1234567' },
    { ...observation, sourceDigest: h('a') },
  ])
    expect(() => parseOperationsSecretObservationRequest(input)).toThrow();
  let calls = 0;
  const accessor = Object.defineProperty({ ...challenge }, 'checked', {
    enumerable: true,
    get() {
      calls++;
      return true;
    },
  });
  expect(() => parseOperationsSecretObservationRequest(accessor)).toThrow();
  expect(calls).toBe(0);
});
it('actual Linux process identity is read and stale start/boot identity is rejected', async () => {
  const actual = await readOperationsProcessIdentity(process.pid);
  await assertOperationsProcessIdentity(actual);
  await expect(
    assertOperationsProcessIdentity({
      ...actual,
      startTicks: String(BigInt(actual.startTicks) + 1n),
    }),
  ).rejects.toThrow();
  await expect(
    assertOperationsProcessIdentity({ ...actual, bootId: '00000000-0000-4000-8000-000000000001' }),
  ).rejects.toThrow();
});
it('probe query is a bounded exact scoped read; invalid scope/lock keys cannot become SQL', () => {
  // Shared byte-level protocol vector with the native consumer test. The
  // independent PostgreSQL query comparison requires exactly these bytes.
  expect(
    sha256(
      Buffer.from(
        operationsSecretProbeQuery(
          '018f0000-0000-7000-8000-000000000001',
          '018f0000-0000-7000-8000-000000000002',
          12,
          34,
        ),
      ),
    ),
  ).toBe('sha256:59936925501ac93bd98e1f45d01a45856597644816481e2ee9386014d8f9dde0');
  const participant = id(),
    privacy = id();
  const query = operationsSecretProbeQuery(participant, privacy, 12, 34);
  expect(Buffer.byteLength(query)).toBeLessThan(1024);
  expect(query).toContain('candidate.fact_bridge_admission_v1');
  expect(query).toContain("current_setting('transaction_read_only')='on'");
  expect(query).toContain('openpc.assert_request_context(true)');
  for (const key of [-1, 2147483648, 1.5, NaN, Infinity])
    expect(() => operationsSecretProbeQuery(participant, privacy, key, 34)).toThrow();
  expect(() => operationsSecretProbeQuery("';select true", privacy, 12, 34)).toThrow();
});

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
(adminUrl ? it : it.skip)(
  'observer identity retains actual self backend start across owner role switch without statistics access',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 2 });
    const first = await pool.connect(),
      second = await pool.connect();
    try {
      const original = await first.query(
        'select pg_backend_pid() pid,backend_start::text started from pg_stat_activity where pid=pg_backend_pid()',
      );
      const other = await second.query('select pg_backend_pid() pid');
      await first.query('begin');
      await first.query('set local role openpc_control_owner');
      const switched = await first.query(`select current_user,
        pg_backend_pid() pid,openpc.operations_observer_backend_start() started,
        (select backend_start from pg_stat_activity where pid=pg_backend_pid()) hidden,
        pg_has_role(current_user,'pg_read_all_stats','USAGE') broad`);
      expect(switched.rows[0]).toEqual({
        current_user: 'openpc_control_owner',
        ...original.rows[0],
        hidden: null,
        broad: false,
      });
      expect(original.rows[0].started).toEqual(expect.any(String));
      expect(original.rows[0].pid).not.toBe(other.rows[0].pid);
      const metadata = await first.query(`select p.prosecdef,p.pronargs,p.proconfig,
        pg_has_role(current_user,p.proowner,'USAGE') owns
        from pg_proc p where p.oid='openpc.operations_observer_backend_start()'::regprocedure`);
      expect(metadata.rows[0]).toEqual({
        prosecdef: true,
        pronargs: 0,
        proconfig: ['search_path=pg_catalog'],
        owns: false,
      });
      // The caller cannot choose another backend, replace the privileged owner,
      // or keep the original identity when moving to a second connection.
      await first.query('rollback');
      await second.query('begin');
      await second.query('set local role openpc_control_owner');
      const next = await second.query(
        'select pg_backend_pid() pid,openpc.operations_observer_backend_start() started',
      );
      expect(next.rows[0].pid).not.toBe(original.rows[0].pid);
      expect(next.rows[0].started).toEqual(expect.any(String));
      await second.query('rollback');
      for (const role of [
        'openpc_control_runtime',
        'openpc_control_worker',
        'openpc_control_reader',
      ]) {
        await first.query('begin');
        await first.query(`set local role ${role}`);
        await expect(
          first.query('select openpc.operations_observer_backend_start()'),
        ).rejects.toThrow(/permission denied/u);
        await first.query('rollback');
      }
    } finally {
      await Promise.allSettled([first.query('rollback'), second.query('rollback')]);
      first.release(true);
      second.release(true);
      await pool.end();
    }
  },
);

(adminUrl ? it : it.skip)(
  'observer identity fences permit scoped locks while rejecting foreign scope, wrong action and mutations',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 1 });
    const client = await pool.connect();
    const participant = id(),
      privacy = id(),
      principal = id(),
      credential = id();
    const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
      type: 'spki',
      format: 'der',
    });
    try {
      await client.query('begin');
      // Initial workload trust only; no association, observation or successful
      // business state is seeded. All rows disappear with this transaction.
      await client.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Observer trust','ACTIVE',1)",
        [participant],
      );
      await client.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Observer domain','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [privacy, participant],
      );
      await client.query(
        "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Observer workload','ACTIVE',1)",
        [principal, participant],
      );
      await client.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,state,credential_epoch,valid_from,valid_until,secret_fingerprint)
        values($1,$2,$3,'WORKLOAD_MTLS','urn:openpc:observer-test-ca',$1::uuid::text,'observer-test',$4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',$4)`,
        [
          credential,
          participant,
          principal,
          Buffer.from(evidenceKeyId(spki).slice(7), 'hex'),
          spki,
        ],
      );
      await client.query('set local role openpc_control_owner');
      const context = (
        tenant = participant,
        domain = privacy,
        action = 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      ) =>
        client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
          tenant,
          domain,
          id(),
          action,
        ]);
      const rows = async () =>
        (
          await client.query(
            `select c.credential_id from control.participant p
        join control.privacy_domain d using(participant_id)
        join control.principal principal using(participant_id)
        join control.credential c on c.participant_id=p.participant_id and c.principal_id=principal.principal_id
        where c.credential_id=$1 and d.privacy_domain_id=$2 FOR SHARE OF p,d,principal,c`,
            [credential, privacy],
          )
        ).rowCount;
      await context();
      expect(await rows()).toBe(1);
      await context(id());
      expect(await rows()).toBe(0);
      await context(participant, id());
      expect(await rows()).toBe(0);
      await context(participant, privacy, 'ACT-RUNTIME_READ_RPC-V1');
      expect(await rows()).toBe(0);
      await context();
      for (const table of ['participant', 'privacy_domain', 'principal', 'credential']) {
        await client.query('savepoint rejected_mutation');
        await expect(
          client.query(`update control.${table} set state='ACTIVE' where participant_id=$1`, [
            participant,
          ]),
        ).rejects.toThrow(/row-level security/u);
        await client.query('rollback to savepoint rejected_mutation');
        await client.query('release savepoint rejected_mutation');
        expect(
          (
            await client.query(`delete from control.${table} where participant_id=$1`, [
              participant,
            ])
          ).rowCount,
        ).toBe(0);
      }
      expect(await rows()).toBe(1);
    } finally {
      await client.query('rollback');
      client.release(true);
      await pool.end();
    }
  },
);

const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
(runtimeUrl ? it : it.skip)(
  'real runtime role cannot insert fabricated association or observation rows',
  async () => {
    const pool = new Pool({ connectionString: runtimeUrl, max: 1 });
    try {
      for (const table of ['operations_secret_association', 'operations_secret_observation'])
        await expect(pool.query(`insert into control.${table} default values`)).rejects.toThrow(
          /permission denied/u,
        );
    } finally {
      await pool.end();
    }
  },
);

// Reuses the existing admitted C1 TEST reader lease; never enables LOGIN, seeds
// a successful receipt, supplies a fabricated mTLS result or takes live stores.
// The canonical runtime owner must explicitly bind this isolated fixture phase.
const candidateAdminUrl = process.env.OPENPC_OPERATIONS_SECRET_CANDIDATE_ADMIN_URL;
const candidateReaderUrl = process.env.OPENPC_FACT_CANDIDATE_SESSION_TEST_URL;
const probeEnabled =
  process.env.OPENPC_OPERATIONS_SECRET_PROBE_TEST === '1' &&
  candidateAdminUrl &&
  candidateReaderUrl;
(probeEnabled ? it : it.skip)(
  'real PostgreSQL probe segment observes the credential read and denies closed/replayed/wrong sessions',
  async () => {
    const admin = new Pool({ connectionString: candidateAdminUrl, max: 1 });
    const reader = new Pool({ connectionString: candidateReaderUrl, max: 1 });
    let session: PoolClient | undefined;
    let primary: { cause: unknown } | undefined;
    let cleanupUnknown = false;
    const scope = { participantId: id(), privacyDomainId: id(), clientAddress: '' };
    try {
      const time = await admin.query(
        'select floor(extract(epoch from clock_timestamp())*1000)::text now',
      );
      const now = Number(time.rows[0].now);
      const challenge = {
        challengeId: id(),
        key1: 123456789,
        key2: 987654321,
        issuedAtMs: now,
        validUntilMs: now + 30000,
      };
      session = await reader.connect();
      const address = await session.query('select inet_client_addr()::text address');
      scope.clientAddress = address.rows[0].address;
      await session.query('begin isolation level repeatable read read only');
      await session.query('set local row_security=on');
      await session.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',true)",
        [scope.participantId, scope.privacyDomainId, challenge.challengeId],
      );
      const identity = await session.query(
        'select pg_backend_pid() pid,extract(epoch from backend_start)::text started from pg_stat_activity where pid=pg_backend_pid()',
      );
      const request = { backendPid: identity.rows[0].pid, backendStart: identity.rows[0].started };
      await expect(
        inspectOperationsSecretProbe(admin, scope, challenge, request),
      ).rejects.toThrow();
      const result = await session.query(
        operationsSecretProbeQuery(
          scope.participantId,
          scope.privacyDomainId,
          challenge.key1,
          challenge.key2,
        ),
      );
      expect(result.rowCount).toBe(1);
      const observed = await inspectOperationsSecretProbe(admin, scope, challenge, request);
      expect(observed.backendPid).toBe(request.backendPid);
      await expect(
        inspectOperationsSecretProbe(
          admin,
          { ...scope, privacyDomainId: id() },
          challenge,
          request,
        ),
      ).rejects.toThrow();
      await expect(
        inspectOperationsSecretProbe(admin, scope, { ...challenge, key2: 1 }, request),
      ).rejects.toThrow();
      await expect(
        inspectOperationsSecretProbe(
          admin,
          { ...scope, clientAddress: '192.0.2.1' },
          challenge,
          request,
        ),
      ).rejects.toThrow();
      await expect(
        inspectOperationsSecretProbe(admin, scope, { ...challenge, validUntilMs: now }, request),
      ).rejects.toThrow();
      await session.query('rollback');
      await expect(
        inspectOperationsSecretProbe(admin, scope, challenge, request),
      ).rejects.toThrow();
    } catch (cause) {
      primary = { cause };
    } finally {
      const cleanup = await Promise.allSettled([
        (async () => {
          if (!session) return;
          try {
            await session.query('rollback');
          } finally {
            session.release(true);
          }
        })(),
      ]);
      cleanup.push(...(await Promise.allSettled([admin.end(), reader.end()])));
      cleanupUnknown = cleanup.some((result) => result.status === 'rejected');
      if (cleanupUnknown) process.stderr.write('OPS_SECRET_PROBE_TEST_CLEANUP|UNKNOWN\n');
    }
    if (primary !== undefined) throw primary.cause;
    if (cleanupUnknown) throw new Error('OPS_SECRET_PROBE_TEST_CLEANUP_UNKNOWN');
  },
);

// Framework-neutral assertions are shared with the actual Node host launcher.
// @ts-expect-error This feature-local JavaScript owner has no declaration-generation seam.
import * as runtimeAssertions from '../local-runtime/fact-secret-operations.mjs';
export const assertOperationsSecretBindingRuntime =
  runtimeAssertions.assertOperationsSecretBindingRuntime;
export const assertOperationsSecretBindingUnavailable =
  runtimeAssertions.assertOperationsSecretBindingUnavailable;
