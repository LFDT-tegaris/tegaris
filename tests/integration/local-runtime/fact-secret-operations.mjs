import assert from 'node:assert/strict';
import { createPrivateKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import { join } from 'node:path';
import { Transform } from 'node:stream';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import {
  encodeOperationsSiteDocument,
  signOperationsSiteDocument,
  evidenceKeyId,
} from '../../../packages/security-kernel/src/index.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import {
  IdentityKernel,
  PostgresIdentityRepository,
} from '../../../services/identity-service/src/domain/identity-kernel.ts';
import { buildOperationsSecretResolutionService } from '../../../services/identity-service/src/domain/operations-secret-resolution.ts';
import {
  installOperationsSecretAssociation,
  readOperationsProcessIdentity,
} from '../../../scripts/operations/installation-secret-binding.mjs';
import {
  installInitialOperationsEnvironment,
  stageInitialOperationsGeneration,
  commitOperationsGenerationInTransaction,
} from '../../../scripts/operations/installation-generation-store.mjs';
import {
  parseConfigurationJson,
  parseNamedProfile,
} from '../../../scripts/operations/installation-config-inputs.mjs';
import { prepareSignedInstallationCandidate } from '../../../scripts/operations/installation-config-signature.mjs';
import { effectiveProjectionCanonicalJson } from '../../../scripts/operations/installation-effective-projection.mjs';
import { isExactSigningSecretReference } from '../../../packages/security-kernel/src/business-transition/secret-reference.ts';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z.uuidv7();
const scopeSchema = z.strictObject({ participantId: uuid, privacyDomainId: uuid });
const descriptorSchema = z.strictObject({
  referenceFingerprint: digest,
  version: z.literal('v1'),
  fingerprint: digest,
});
const failure = () => new Error('OPS_HOST_OBSERVATION_REJECTED');
const ownedHosts = new WeakSet();
export function assertFactSecretOperationsOwner(value) {
  assert.ok(value && ownedHosts.has(value), 'Actual installation operations owner required');
}
export function parseFactSecretResolutionDescriptor(value, reference) {
  const result = descriptorSchema.parse(JSON.parse(effectiveProjectionCanonicalJson(value)));
  assert.equal(result.referenceFingerprint, sha256(Buffer.from(reference)));
  return Object.freeze(result);
}
export function parseFactSecretPublisherCommand(value) {
  if (value === 'close') return { operation: 'close' };
  assert.ok(typeof value === 'string' && value.length < 128);
  const match = /^(arm|release|abort) ([0-9a-f-]+)$/u.exec(value);
  assert.ok(match);
  return Object.freeze({ operation: match[1], associationId: uuid.parse(match[2]) });
}

// Bound bytes BEFORE readline buffers a complete private frame. The only
// frames are installation input plus at most arm, release, abort and close.
// Command phase/identity checks remain with the gate.
export function createFactSecretPublisherInput() {
  let line = 0,
    bytes = 0;
  return new Transform({
    transform(chunk, _encoding, done) {
      for (const byte of chunk) {
        if (byte === 10) {
          line++;
          bytes = 0;
          if (line > 5) return done(failure());
        } else if (++bytes > (line === 0 ? 65536 : 127)) return done(failure());
      }
      done(null, chunk);
    },
  });
}

/** A local startup barrier, never peer authentication or readiness. Only the
 * existing installer's private stdin owner can arm/release it. Abort is terminal. */
export function createFactSecretPublishGate(associationId) {
  uuid.parse(associationId);
  let state = 'PREPARING',
    resolve,
    reject;
  const pending = new Promise((ok, no) => {
    resolve = ok;
    reject = no;
  });
  pending.catch(() => undefined);
  return Object.freeze({
    arm(value) {
      assert.equal(value, associationId);
      assert.equal(state, 'PREPARING');
      state = 'ARMED';
    },
    release(value) {
      assert.equal(value, associationId);
      assert.equal(state, 'ARMED');
      state = 'RELEASED';
      resolve();
    },
    abort() {
      if (state === 'ABORTED') return;
      state = 'ABORTED';
      reject(failure());
    },
    async wait() {
      if (state === 'ABORTED') throw failure();
      if (state !== 'ARMED') return;
      let timer;
      try {
        await Promise.race([
          pending,
          new Promise((_, no) => {
            timer = setTimeout(() => {
              state = 'ABORTED';
              reject(failure());
              no(failure());
            }, 4500);
            timer.unref();
          }),
        ]);
        if (state !== 'RELEASED') throw failure();
      } finally {
        clearTimeout(timer);
      }
    },
  });
}

// Shared with PostgreSQL tests. This is an assertion of an actual live owner,
// not an alternate source adapter or intermediate-state fixture.
export async function assertOperationsSecretBindingRuntime(observer) {
  return observer.withCurrent(async (client, source) => {
    const result = await client.query(
      `select o.state,o.claims,o.probe,a.environment_id,a.generation_id,a.participant_id,a.privacy_domain_id,
      openpc.operations_generation_missing(a.environment_id,a.generation_id) missing
      from control.operations_secret_observation o join control.operations_secret_association a using(association_id)
      where o.observation_id=$1 and o.source_digest=$2`,
      [source.observationId, source.sourceDigest],
    );
    assert.equal(result.rowCount, 1);
    const row = result.rows[0];
    assert.equal(row.state, 'OBSERVED');
    assert.equal(row.claims.consumerId, 'LS-FACT-BRIDGE');
    assert.ok(row.missing.includes('SOURCE:C17_AUTHENTICATION'));
    assert.ok(row.missing.includes('CONSUMER_EFFECTIVE:LS-FACT-BRIDGE'));
    assert.ok(row.missing.some((requirement) => requirement.startsWith('QUALIFICATION:')));
    // Consume the canonical guarded commit body on this SAME live observer
    // client. The remaining missing owners must deny it without ending this
    // transaction; withCurrent still performs its source recheck afterward.
    await assert.rejects(
      commitOperationsGenerationInTransaction(
        client,
        { participantId: row.participant_id, privacyDomainId: row.privacy_domain_id },
        row.environment_id,
        row.generation_id,
      ),
      {
        name: 'InstallationConfigError',
        code: 'OPS_CONFIG_INVALID',
        reason: 'GENERATION_BINDINGS_UNAVAILABLE',
      },
    );
    assert.equal(
      (
        await client.query(
          'select 1 from control.operations_generation_commit where environment_id=$1 and generation_id=$2',
          [row.environment_id, row.generation_id],
        )
      ).rowCount,
      0,
    );
    assert.ok(!JSON.stringify(row.claims).includes('secret://'));
    assert.ok(!JSON.stringify(row.claims).includes('postgresql://'));
    return Object.freeze({ ...source, validUntilMs: row.claims.validUntilMs, probe: row.probe });
  });
}
export async function assertOperationsSecretBindingUnavailable(observer) {
  let invoked = false;
  await assert.rejects(
    observer.withCurrent(async () => {
      invoked = true;
    }),
    /OPS_SECRET_OBSERVATION_REJECTED/u,
  );
  assert.equal(invoked, false);
}

/** Pure prepared TEST site; all qualification references remain unverified.
 * Exact source/schema/profile validation precedes any installation DB write. */
export async function prepareFactSecretOperationsSite(
  repository,
  scope,
  reference,
  environmentId,
  now = Date.now(),
) {
  scope = scopeSchema.parse(JSON.parse(effectiveProjectionCanonicalJson(scope)));
  assert.ok(
    isExactSigningSecretReference(reference, 'v1') &&
      reference.startsWith('secret://test-memory-resolver/'),
  );
  const schemaBytes = await readFile(
    join(repository, 'config/schema/effective-configuration.schema.json'),
  );
  const profileBytes = await readFile(join(repository, 'config/profiles/test.yaml'));
  const schema = parseConfigurationJson(schemaBytes),
    namedProfile = parseNamedProfile(profileBytes);
  assert.equal(namedProfile.profile, 'test');
  const generationId = id(),
    baseGenerationId = id();
  const ref = (name) => `secret://test-memory-resolver/${name}#v1`;
  const site = {
    environmentId,
    publicBaseUrl: 'https://localhost:8443',
    generation: {
      generationId: `urn:openpc:generation:${generationId}`,
      baseGenerationId: `urn:openpc:generation:${baseGenerationId}`,
      // A signed declaration only; not the unresolved effective projection.
      contentDigest: sha256({
        environmentId,
        generationId,
        baseGenerationId,
        claim: 'UNVERIFIED_TEST_SITE',
      }),
    },
    postgres: {
      controlDsnSecretRef: ref('control'),
      factsDsnSecretRef: ref('facts'),
      candidateIndexDsnSecretRef: reference,
    },
    identity: {
      oidcIssuer: 'https://localhost:8443/oidc',
      clientId: 'synthetic-test-client',
      clientSecretRef: ref('oidc'),
      scimEnabled: false,
    },
    pki: { trustBundleSecretRef: ref('trust'), signingKeySecretRef: ref('signing') },
    telemetry: { otlpEndpoint: 'grpc://localhost:4317' },
    qualificationInputBindings: Object.fromEntries(
      Object.entries(namedProfile.requiredSettingInputs).map(([key, slot]) => [
        key,
        `qualification://test/${key}@${sha256({ slot, claim: 'UNVERIFIED' })}`,
      ]),
    ),
    settings: {
      'ui.export_row_limit': 1,
      'runtime.local_artifact_capacity': 1,
      'runtime.decision_deadline': '1ms',
      'evidence.local_spool_capacity': 1,
      'evidence.retention_profile': `profile://test/retention@${sha256({ environmentId })}`,
      'provider.read_retry_limit': 0,
      'facts.maximum_staleness': '1ms',
      'facts.reorg_retained_tail': 1,
      'module.allowed_publishers': `publisher-set://test/modules@${sha256(scope)}`,
      'module.ui_slot_budget': 0,
      'operations.notification_delivery_limit': 0,
    },
  };
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = key.publicKey.export({ format: 'der', type: 'spki' }),
    privateKey = key.privateKey.export({ format: 'der', type: 'pkcs8' });
  const pins = {
    issuerSpkiHex: spki.toString('hex'),
    issuerEpoch: '1',
    issuerValidFromMs: now - 1000,
    issuerValidUntilMs: now + 600000,
    environmentId,
    profile: 'test',
    configurationSchemaDigest: sha256(schemaBytes),
    namedProfileDigest: sha256(profileBytes),
  };
  const payload = encodeOperationsSiteDocument({
    generationId: site.generation.generationId,
    baseGenerationId: site.generation.baseGenerationId,
    environmentId,
    profile: 'test',
    siteDigest: sha256(site),
    configurationSchemaDigest: pins.configurationSchemaDigest,
    namedProfileDigest: pins.namedProfileDigest,
    declaredContentDigest: site.generation.contentDigest,
    issuerKeyId: evidenceKeyId(spki),
    issuerEpoch: '1',
    validFromMs: now - 1000,
    validUntilMs: pins.issuerValidUntilMs,
  });
  let cose;
  try {
    cose = signOperationsSiteDocument(privateKey, spki, payload);
  } finally {
    privateKey.fill(0);
  }
  const sources = {
    schema,
    schemaBytes,
    namedProfile,
    profileBytes,
    profile: 'test',
    site,
    siteBytes: Buffer.from(JSON.stringify(site)),
    environment: {},
  };
  const signed = { payload, cose };
  const publicPins = { ...pins };
  delete publicPins.issuerSpkiHex;
  const checked = prepareSignedInstallationCandidate(
    sources,
    { ...publicPins, issuerSpki: spki },
    signed,
    now,
  );
  assert.equal(checked.startupAllowed, false);
  assert.ok(checked.blockers.includes('QUALIFICATION_VERIFICATION_UNBOUND'));
  return { pins, sources, signed, baseGenerationId, generationId };
}

/** Host only: one owned association/observer for one actual native instance.
 * Its pools are the existing real installation pools. No callback grants proof. */
export async function prepareFactSecretOperations(options) {
  const {
    repository,
    scope: scopeInput,
    reference,
    controlPool,
    runtimePool,
    candidateAdminPool,
    gateway,
    networkId,
    imageId,
    ownerToken,
    tls,
    serverName,
    workloadId,
  } = options;
  const scope = Object.freeze(
    scopeSchema.parse(JSON.parse(effectiveProjectionCanonicalJson(scopeInput))),
  );
  uuid.parse(workloadId);
  z.ipv4().parse(gateway);
  z.string()
    .regex(/^[0-9a-f]{64}$/u)
    .parse(networkId);
  digest.parse(imageId);
  z.string().min(1).max(128).parse(ownerToken);
  z.hostname().parse(serverName);
  const certificate = new X509Certificate(tls.certificate);
  assert.ok(certificate.checkHost(serverName));
  assert.ok(certificate.checkPrivateKey(createPrivateKey(tls.privateKey)));
  assert.ok(Date.parse(certificate.validFrom) <= Date.now());
  assert.ok(Date.parse(certificate.validTo) - Date.now() >= 60000);
  const associationId = id(),
    consumerInstanceId = id(),
    observerInstanceId = id();
  const environmentId = `ops-${associationId.slice(-12)}`;
  const prepared = await prepareFactSecretOperationsSite(
    repository,
    scope,
    reference,
    environmentId,
  );
  const installationDigest = await installInitialOperationsEnvironment(controlPool, scope, {
    pins: prepared.pins,
    initialBaseGenerationId: prepared.baseGenerationId,
    schemaBytes: prepared.sources.schemaBytes,
    profileBytes: prepared.sources.profileBytes,
  });
  const staged = await stageInitialOperationsGeneration(
    controlPool,
    scope,
    prepared.sources,
    prepared.signed,
  );
  assert.equal(staged.effective, false);
  const observerProcess = await readOperationsProcessIdentity(process.pid);
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = issuer.publicKey.export({ format: 'der', type: 'spki' }),
    key = issuer.privateKey.export({ format: 'der', type: 'pkcs8' });
  let owner,
    app,
    serviceOwnsConnection = false,
    cleanupUnknown = false,
    closed = false,
    installed = false,
    descriptor,
    original,
    peerTls;
  const now = Date.now(),
    validUntil = Math.min(now + 600000, Date.parse(certificate.validTo));
  const native = Object.freeze({
    endpoint: Object.freeze({
      endpoint_id: 'operations-secret-observer',
      normalized_uri: `https://${serverName}:3444/internal/v1/operations/secret-resolution`,
      reference_identity: serverName,
      port: 3444,
      path: '/internal/v1/operations/secret-resolution',
      dns_policy_ref: 'local-exact-address-v1',
      tls_policy_ref: 'local-mtls-v1',
      credential_ref: `urn:openpc:workload:${workloadId}`,
      egress_policy_ref: 'local-exact-private-address-v1',
      endpoint_generation: 1,
    }),
    addresses: Object.freeze([gateway]),
    allowed_ranges: Object.freeze([`${gateway}/32`]),
    private_network_ranges: Object.freeze([`${gateway}/32`]),
    server_certificate_digest: sha256(certificate.raw).slice(7),
    association_id: associationId,
    consumer_instance_id: consumerInstanceId,
  });
  const observer = {
    withCurrent: (use) => {
      assert.ok(app && installed && !closed);
      return app.withCurrentOperationsSecretResolution(use);
    },
  };
  let closing;
  const close = () =>
    (closing ??= (async () => {
      closed = true;
      try {
        if (app) await app.close();
        else if (owner && !serviceOwnsConnection) owner.release(true);
      } finally {
        key.fill(0);
        peerTls?.cert.fill(0);
        peerTls?.key.fill(0);
      }
      if (cleanupUnknown) throw new Error('OPS_HOST_OBSERVATION_CLEANUP_UNKNOWN');
    })());
  const handle = Object.freeze({
    environmentId,
    native,
    associationId,
    async attachPublisher(value) {
      assert.ok(!app && !closed);
      descriptor = parseFactSecretResolutionDescriptor(value, reference);
      owner = await controlPool.connect();
      serviceOwnsConnection = true;
      app = buildOperationsSecretResolutionService({
        owner,
        pool: runtimePool,
        candidateAdminPool,
        kernel: new IdentityKernel(new PostgresIdentityRepository(runtimePool)),
        associationId,
        installationScope: scope,
        resolvedVersion: descriptor,
        issuerPrivateKey: key,
        tls,
      });
      await app.listen({ host: gateway, port: 3444 });
    },
    async installStarted(container, recipient) {
      assert.ok(app && !installed && !closed);
      const networks = Object.values(container.NetworkSettings.Networks);
      assert.equal(networks.length, 1);
      const consumerProcess = await readOperationsProcessIdentity(container.State.Pid, {
        id: container.Id,
        imageId,
        owner: ownerToken,
        startedAt: container.State.StartedAt,
        engineEndpoint: 'unix:///var/run/docker.sock',
        networkId,
        address: networks[0].IPAddress,
      });
      const backend = await owner.query(
        'select pg_backend_pid() pid,(select backend_start::text from pg_stat_activity where pid=pg_backend_pid()) started',
      );
      const pins = recipient.pins;
      peerTls = {
        cert: Buffer.from(recipient.tls.certificate, 'base64'),
        key: Buffer.from(recipient.tls.privateKey, 'base64'),
      };
      await owner.query('begin isolation level read committed');
      try {
        await owner.query('set local role openpc_control_owner');
        await owner.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          [scope.participantId, scope.privacyDomainId, id()],
        );
        const signed = await owner.query(
          'select payload,cose from control.installed_secret_recipient where participant_id=$1 and privacy_domain_id=$2 and binding_digest=$3',
          [scope.participantId, scope.privacyDomainId, pins.signedBindingDigest],
        );
        assert.equal(signed.rowCount, 1);
        await installOperationsSecretAssociation(owner, {
          profile: 'test',
          associationId,
          environmentId,
          ...scope,
          generationId: staged.generationId,
          operationsInstallationDigest: installationDigest,
          candidateDigest: staged.candidateDigest,
          recipientBindingDigest: pins.signedBindingDigest,
          recipientInstallationDigest: pins.installationDigest,
          recipientGeneration: pins.generation,
          recipientIssuerSpkiHex: Buffer.from(pins.issuerSpkiDer, 'base64').toString('hex'),
          recipientPayloadHex: signed.rows[0].payload.toString('hex'),
          recipientCoseHex: signed.rows[0].cose.toString('hex'),
          field: 'postgres.candidateIndexDsnSecretRef',
          consumerId: 'LS-FACT-BRIDGE',
          storeId: 'STORE-CANDIDATE-INDEX-PG',
          reference,
          ...descriptor,
          principalId: pins.principalId,
          workloadCredentialId: pins.workloadCredentialId,
          workloadCredentialEpoch: pins.workloadCredentialEpoch,
          consumerInstanceId,
          consumerStartedAtMs: consumerProcess.startedAtMs,
          consumerProcess,
          observerInstanceId,
          observerStartedAtMs: observerProcess.startedAtMs,
          observerProcess,
          observerBackendPid: backend.rows[0].pid,
          observerBackendStart: backend.rows[0].started,
          issuerSpkiHex: spki.toString('hex'),
          issuerKeyId: evidenceKeyId(spki),
          issuerEpoch: '1',
          issuerValidFromMs: now,
          issuerValidUntilMs: validUntil,
        });
        await owner.query('commit');
      } catch (error) {
        await owner.query('rollback').catch(() => {
          cleanupUnknown = true;
        });
        throw error;
      }
      await app.startOperationsSecretResolution();
      installed = true;
    },
    async positive() {
      original = await assertOperationsSecretBindingRuntime(observer);
      // The host presents the actual workload certificate over real TLS, but
      // is not the installed native network origin. Its denial must leave the
      // live source intact. A missing client certificate must fail transport.
      const probe = (credentials) =>
        new Promise((resolve, reject) => {
          const body = JSON.stringify({ phase: 'CHALLENGE', associationId, consumerInstanceId });
          const request = httpsRequest(
            {
              host: gateway,
              port: 3444,
              servername: serverName,
              path: native.endpoint.path,
              method: 'POST',
              ca: tls.ca,
              minVersion: 'TLSv1.3',
              maxVersion: 'TLSv1.3',
              ...credentials,
              headers: {
                'content-type': 'application/json',
                'content-length': Buffer.byteLength(body),
              },
            },
            (response) => {
              let bytes = 0,
                text = '';
              response.on('data', (chunk) => {
                bytes += chunk.length;
                if (bytes > 4096) request.destroy(failure());
                else text += chunk;
              });
              response.on('end', () => {
                try {
                  resolve({ status: response.statusCode, body: JSON.parse(text) });
                } catch {
                  reject(failure());
                }
              });
              response.on('error', reject);
            },
          );
          request.setTimeout(2000, () => request.destroy(failure()));
          request.on('error', reject);
          request.end(body);
        });
      await assert.rejects(probe({}));
      assert.deepEqual(await probe(peerTls), {
        status: 403,
        body: { code: 'OPS_SECRET_OBSERVATION_REJECTED' },
      });
      const after = await assertOperationsSecretBindingRuntime(observer);
      assert.equal(after.observationId, original.observationId);
      assert.equal(after.sourceDigest, original.sourceDigest);
      return original;
    },
    async unavailable({ beforeExpiry = false } = {}) {
      await assertOperationsSecretBindingUnavailable(observer);
      if (beforeExpiry) assert.ok(original && Date.now() < original.validUntilMs);
    },
    async terminateProof() {
      assert.ok(original && original.validUntilMs > Date.now());
      const result = await candidateAdminPool.query(
        `select pg_terminate_backend(pid) stopped from pg_stat_activity
        where pid=$1 and extract(epoch from backend_start)::text=$2 and usename='openpc_fact_bridge_reader' and host(client_addr)=$3`,
        [original.probe.backendPid, original.probe.backendStart, original.probe.clientAddress],
      );
      assert.deepEqual(result.rows, [{ stopped: true }]);
    },
    async waitForExpiry() {
      assert.ok(original);
      await delay(Math.max(0, original.validUntilMs - Date.now() + 25));
    },
    close,
  });
  ownedHosts.add(handle);
  return handle;
}
