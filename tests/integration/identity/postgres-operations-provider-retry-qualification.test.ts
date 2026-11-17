import { generateKeyPairSync } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { parseStrictJsonBytes } from '../../../services/control-api/src/privacy-explorer/strict-json.js';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { commitOperationsGenerationInTransaction } from '../../../scripts/operations/installation-generation-store.mjs';
import {
  ProviderRetryQualificationStore,
  withInstalledNotificationAsyncAuthority,
  withCurrentProviderRetryQualification,
  installProviderRetryQualificationRoot,
  type ProviderRetryQualificationScope,
  type ProviderRetryQualificationBundle,
} from '../../../services/control-api/src/configuration/operations/provider-retry-qualification.js';
import {
  decodeProviderRetryQualification,
  encodeProviderRetryQualification,
  providerRetryQualificationProfiles,
  type QualificationKeysetClaims,
  type QualificationRevocationClaims,
  qualificationDigest,
  qualificationCanonicalJson,
  verifyProviderRetryAuthority,
  verifyProviderRetryReceipt,
  type QualificationRoot,
  type QualificationAuthorityEnvelope,
  type QualificationDocumentEnvelope,
} from '../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';

import {
  encodeOperationsSiteDocument,
  signOperationsSiteDocument,
  evidenceKeyId,
} from '../../../packages/security-kernel/src/index.js';
import { signConsumerCose } from '../../../packages/security-kernel/src/fact-consumer/cose-framing.js';
import {
  encodeNotificationAsync,
  notificationAsyncProfiles,
  type NotificationAsyncInputClaims,
  type NotificationAsyncCapacityClaims,
} from '../../../packages/security-kernel/src/operations-configuration/notification-async.js';
import {
  parseConfigurationJson,
  parseNamedProfile,
} from '../../../scripts/operations/installation-config-inputs.mjs';
import {
  installInitialOperationsEnvironment,
  stageInitialOperationsGeneration,
} from '../../../scripts/operations/installation-generation-store.mjs';
import { readPublicOperationsSources } from '../../../scripts/operations/read-public-installation-sources.mjs';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
const id = localOperationId;
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const ownerUrl = process.env.OPENPC_OPERATIONS_QUALIFICATION_OWNER_DATABASE_URL;
const bootstrapUrl = process.env.OPENPC_OPERATIONS_QUALIFICATION_BOOTSTRAP_DATABASE_URL;
const fixturePath = process.env.OPENPC_OPERATIONS_QUALIFICATION_FIXTURE;
// Existing identity/runtime driver supplies a REAL supported staged generation
// and external authority corpus. No approval, execution, method safety, reviewer
// result or readiness rows may be seeded here. Missing inputs never imply a pass.
const integration = adminUrl ? it : it.skip;
let admissionPrerequisitePassed = false;
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('QUALIFICATION_FIXTURE_INVALID');
  return value as Record<string, unknown>;
}
function hex(value: unknown, max: number): Buffer {
  if (typeof value !== 'string' || value.length > max * 2 || !/^(?:[0-9a-f]{2})+$/u.test(value))
    throw new Error('QUALIFICATION_FIXTURE_INVALID');
  return Buffer.from(value, 'hex');
}
function envelope(value: unknown, max?: number): QualificationDocumentEnvelope {
  const o = object(value);
  return {
    payload: hex(o.payloadHex, 65536),
    cose: hex(o.coseHex, 66560),
    document: max ? hex(o.documentHex, max) : Buffer.alloc(0),
  };
}
function authority(value: unknown): QualificationAuthorityEnvelope {
  const o = object(value);
  return { keyset: envelope(o.keyset, 131072), revocations: envelope(o.revocations, 4194304) };
}
function fixture(bytes: Uint8Array) {
  const data = object(parseStrictJsonBytes(bytes, { maximumDepth: 16 }));
  if (
    Object.keys(data).sort().join() !==
    'authorityStates,bundle,environmentId,generationId,root,scope'
  )
    throw new Error('QUALIFICATION_FIXTURE_INVALID');
  const pins = object(data.root),
    scope = object(data.scope),
    b = object(data.bundle),
    states = object(data.authorityStates);
  const root = { ...pins, rootSpki: hex(pins.rootSpkiHex, 256) } as unknown as QualificationRoot;
  const bundle: ProviderRetryQualificationBundle = {
    input: envelope(b.input),
    receipt: envelope(b.receipt, 524288),
  };
  const input = decodeProviderRetryQualification('input', bundle.input.payload),
    receipt = decodeProviderRetryQualification('receipt', bundle.receipt.payload);
  if (
    !['test', 'local'].includes(input.profile) ||
    input.environmentId !== data.environmentId ||
    input.authorityId !== root.authorityId
  )
    throw new Error('QUALIFICATION_FIXTURE_INVALID');
  for (const key of ['participantId', 'privacyDomainId', 'requestId'])
    if (typeof scope[key] !== 'string') throw new Error('QUALIFICATION_FIXTURE_INVALID');
  if (
    typeof data.generationId !== 'string' ||
    !/^\w{8}-\w{4}-7\w{3}-[89ab]\w{3}-\w{12}$/u.test(data.generationId)
  )
    throw new Error('QUALIFICATION_FIXTURE_INVALID');
  const initial = authority(states.initial),
    successor = authority(states.successor),
    revoked = authority(states.revoked);
  const verified = verifyProviderRetryAuthority(root, initial, receipt.issuedAtMs);
  verifyProviderRetryReceipt(bundle.input, bundle.receipt, verified, verified, receipt.issuedAtMs);
  return {
    scope: scope as unknown as ProviderRetryQualificationScope,
    root,
    bundle,
    initial,
    successor,
    revoked,
    environment: String(data.environmentId),
    generation: data.generationId,
  };
}
it('rejects missing authority/executed-input fixture before allocating PostgreSQL', () => {
  expect(() => fixture(Buffer.from('{}'))).toThrow('QUALIFICATION_FIXTURE_INVALID');
  expect(() => fixture(Buffer.from('{"root":{},"root":{}}'))).toThrow();
});
async function inputs() {
  if (!ownerUrl || !bootstrapUrl || !fixturePath)
    throw new Error(
      'Real qualification owner/bootstrap pools and executed external authority fixture are required',
    );
  const size = (await stat(fixturePath)).size;
  if (size < 1 || size > 30000000) throw new Error('QUALIFICATION_FIXTURE_INVALID');
  return fixture(await readFile(fixturePath));
}
async function preflight(admin: Pool) {
  const rows = (
    await admin.query<{
      name: string;
      present: boolean;
    }>(`select name,to_regprocedure(name) is not null present from unnest(array[
 'openpc.operations_provider_retry_evidence_current(text,uuid,text,text)',
 'openpc.operations_provider_retry_qualification_bound(text,uuid)',
 'openpc.operations_generation_source_authenticated(text,uuid)']) name`)
  ).rows;
  expect(
    rows.every((r) => r.present),
    `required actual owners missing: ${rows
      .filter((r) => !r.present)
      .map((r) => r.name)
      .join(',')}`,
  ).toBe(true);
  const memberships = await admin.query<{ separate: boolean }>(
    `select not pg_has_role('openpc_operations_qualification_owner','openpc_operations_qualification_bootstrap','USAGE') and not pg_has_role('openpc_operations_qualification_bootstrap','openpc_operations_qualification_owner','USAGE') as separate`,
  );
  expect(memberships.rows[0]?.separate).toBe(true);
}
async function controlTransaction<T>(
  pool: Pool,
  scope: ProviderRetryQualificationScope,
  consume: (client: PoolClient) => Promise<T>,
  isolation: 'read committed' | 'repeatable read' = 'read committed',
): Promise<T> {
  const client = await pool.connect();
  let value!: T;
  let failed = false;
  let primary: unknown;
  try {
    await client.query(`begin isolation level ${isolation}`);
    await client.query('set local role openpc_control_owner');
    await client.query('set local row_security=on');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
      [scope.participantId, scope.privacyDomainId, scope.requestId],
    );
    value = await consume(client);
  } catch (error) {
    failed = true;
    primary = error;
  }
  const cleanupFailure = (error: unknown) => {
    process.stderr.write('OPS_QUALIFICATION_TEST_CLEANUP|UNKNOWN\n');
    if (!failed) primary = error;
    failed = true;
  };
  try {
    await client.query('rollback');
  } catch (error) {
    cleanupFailure(error);
  }
  try {
    client.release();
  } catch (error) {
    cleanupFailure(error);
  }
  if (failed) throw primary;
  return value;
}
integration(
  'real owner admits one exact qualification, preserves replay/originals, rejects foreign scope and rolls back denied consumption',
  async () => {
    const f = await inputs();
    const admin = new Pool({ connectionString: adminUrl, max: 1 }),
      owner = new Pool({ connectionString: ownerUrl, max: 2 }),
      bootstrap = new Pool({ connectionString: bootstrapUrl, max: 1 });
    try {
      await preflight(admin);
      const store = new ProviderRetryQualificationStore(owner);
      const originalGenerations = await admin.query(
        'select count(*)::text count from control.operations_generation_commit where environment_id=$1',
        [f.environment],
      );
      const originalMissing = await controlTransaction(admin, f.scope, async (client) => {
        const result = await client.query<{ missing: string[] }>(
          'select openpc.operations_generation_missing($1,$2) missing',
          [f.environment, f.generation],
        );
        return result.rows[0]!.missing;
      });
      expect(originalMissing.filter((s) => s.startsWith('QUALIFICATION:'))).toHaveLength(10);
      await expect(
        store.installAuthorityState(f.scope, f.environment, f.root.authorityId, f.initial),
      ).rejects.toThrow('ROOT_UNBOUND');
      await installProviderRetryQualificationRoot(bootstrap, f.scope, f.environment, f.root);
      await installProviderRetryQualificationRoot(bootstrap, f.scope, f.environment, f.root);
      await expect(
        installProviderRetryQualificationRoot(owner, f.scope, f.environment, f.root),
      ).rejects.toThrow();
      const accepted = await store.installAuthorityState(
        f.scope,
        f.environment,
        f.root.authorityId,
        f.initial,
      );
      expect(
        await store.installAuthorityState(f.scope, f.environment, f.root.authorityId, f.initial),
      ).toEqual(accepted);
      const receipt = await store.admit(f.scope, f.environment, f.generation, f.bundle);
      expect(receipt.inputDigest).toBe(qualificationDigest(f.bundle.input.payload));
      expect(await store.admit(f.scope, f.environment, f.generation, f.bundle)).toEqual(receipt);
      const wrong = {
        ...f.bundle,
        receipt: { ...f.bundle.receipt, cose: Buffer.from(f.bundle.receipt.cose) },
      };
      wrong.receipt.cose[wrong.receipt.cose.length - 1] =
        wrong.receipt.cose[wrong.receipt.cose.length - 1]! ^ 1;
      await expect(store.admit(f.scope, f.environment, f.generation, wrong)).rejects.toThrow(
        'UNQUALIFIED',
      );
      const foreign = { ...f.scope, privacyDomainId: '01900000-0000-7000-8000-000000000299' };
      await expect(
        store.withCurrent(foreign, f.environment, f.generation, async () => true),
      ).rejects.toThrow();
      await expect(
        controlTransaction(admin, f.scope, (client) =>
          commitOperationsGenerationInTransaction(
            client,
            { participantId: f.scope.participantId, privacyDomainId: f.scope.privacyDomainId },
            f.environment,
            f.generation,
          ),
        ),
      ).rejects.toThrow('GENERATION_BINDINGS_UNAVAILABLE');
      // Generation readback belongs to the control owner; qualification custody
      // does not gain generic binding-table access to make this test pass.
      await controlTransaction(admin, f.scope, (controlClient) =>
        store.withCurrentInTransaction(
          controlClient,
          f.scope,
          f.environment,
          f.generation,
          async (client, verified) => {
            expect(client).toBe(controlClient);
            expect(verified.qualificationRef).toBe(
              decodeProviderRetryQualification('receipt', f.bundle.receipt.payload)
                .qualificationRef,
            );
            const missing = (
              await client.query<{ missing: string[] }>(
                'select openpc.operations_generation_missing($1,$2) missing',
                [f.environment, f.generation],
              )
            ).rows[0]!.missing;
            expect(missing).not.toContain('QUALIFICATION:provider.read_retry_limit');
            expect(missing.filter((s) => s.startsWith('QUALIFICATION:'))).toHaveLength(9);
            expect(missing).toEqual(
              originalMissing.filter((s) => s !== 'QUALIFICATION:provider.read_retry_limit'),
            );
            expect(missing.length).toBeGreaterThan(9);
            await expect(
              client.query(
                `insert into control.operations_generation_binding(participant_id,privacy_domain_id,environment_id,generation_id,requirement_id,source_digest,effective_digest,valid_until_ms,state) values($1,$2,$3,$4,'QUALIFICATION:ui.export_row_limit',$5,$5,9007199254740991,'CURRENT')`,
                [
                  f.scope.participantId,
                  f.scope.privacyDomainId,
                  f.environment,
                  f.generation,
                  receipt.receiptDigest,
                ],
              ),
            ).rejects.toThrow();
            // Permission failure aborts this transaction; outer wrapper must roll back.
            throw new Error('EXPECTED_ROLLBACK');
          },
        ),
      ).then(
        () => {
          throw new Error('rollback was lost');
        },
        (error) => expect(String(error)).toContain('EXPECTED_ROLLBACK'),
      );
      const after = await admin.query(
        'select count(*)::text count from control.operations_generation_commit where environment_id=$1',
        [f.environment],
      );
      expect(after.rows).toEqual(originalGenerations.rows);
      await store.installAuthorityState(f.scope, f.environment, f.root.authorityId, f.successor);
      await expect(
        store.installAuthorityState(f.scope, f.environment, f.root.authorityId, f.initial),
      ).rejects.toThrow('UNQUALIFIED');
      const restarted = new ProviderRetryQualificationStore(owner);
      expect(
        await restarted.withCurrent(f.scope, f.environment, f.generation, async () => receipt),
      ).toEqual(receipt);
      expect(
        await controlTransaction(admin, f.scope, (client) =>
          withCurrentProviderRetryQualification(
            client,
            f.scope,
            f.environment,
            f.generation,
            async (sameClient, verified) => {
              expect(sameClient).toBe(client);
              return verified.qualificationRef;
            },
          ),
        ),
      ).toBe(
        decodeProviderRetryQualification('receipt', f.bundle.receipt.payload).qualificationRef,
      );
      let wrongRequestConsumed = false;
      await expect(
        controlTransaction(admin, f.scope, (client) =>
          withCurrentProviderRetryQualification(
            client,
            { ...f.scope, requestId: localOperationId() },
            f.environment,
            f.generation,
            async () => {
              wrongRequestConsumed = true;
            },
          ),
        ),
      ).rejects.toThrow('UNQUALIFIED');
      expect(wrongRequestConsumed).toBe(false);
      await expect(
        controlTransaction(admin, f.scope, (client) =>
          withCurrentProviderRetryQualification(
            client,
            f.scope,
            f.environment,
            f.generation,
            async (sameClient) => {
              await sameClient.query("select set_config('openpc.operation_id',$1,true)", [
                localOperationId(),
              ]);
            },
          ),
        ),
      ).rejects.toThrow('UNQUALIFIED');
      const controlClient = await admin.connect();
      try {
        await controlClient.query('begin isolation level read committed');
        await controlClient.query('set local role openpc_control_owner');
        await controlClient.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          [f.scope.participantId, f.scope.privacyDomainId, f.scope.requestId],
        );
        await restarted.withCurrentInTransaction(
          controlClient,
          f.scope,
          f.environment,
          f.generation,
          async (sameClient) => {
            expect(sameClient).toBe(controlClient);
            expect(
              (await sameClient.query<{ role: string }>('select current_user::text role')).rows[0]
                ?.role,
            ).toBe('openpc_control_owner');
          },
        );
      } finally {
        await controlClient.query('rollback');
        controlClient.release();
      }
      const raw = await admin.query<{ custody: unknown }>(
        'select custody from control.operations_provider_retry_qualification where environment_id=$1 and generation_id=$2',
        [f.environment, f.generation],
      );
      const stored = object(raw.rows[0]!.custody);
      expect(object(stored.receipt).payloadHex).toBe(f.bundle.receipt.payload.toString('hex'));
      expect(object(stored.receipt).coseHex).toBe(f.bundle.receipt.cose.toString('hex'));
      admissionPrerequisitePassed = true;
    } finally {
      await Promise.all([admin.end(), owner.end(), bootstrap.end()]);
    }
  },
  30000,
);

integration(
  'concurrent current consumption fences revocation; the next use denies without replacing historical custody',
  async () => {
    if (!admissionPrerequisitePassed)
      throw new Error('BLOCKED: provider retry admission prerequisite did not pass');
    const f = await inputs();
    const admin = new Pool({ connectionString: adminUrl, max: 1 }),
      owner = new Pool({
        connectionString: ownerUrl,
        max: 2,
        application_name: 'openpc-provider-retry-revocation-test',
      });
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: () => void = () => {};
    const started = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let live: Promise<unknown> | undefined, revocation: Promise<unknown> | undefined;
    try {
      await preflight(admin);
      const store = new ProviderRetryQualificationStore(owner);
      const original = (
        await admin.query<{ custody_digest: string }>(
          'select custody_digest from control.operations_provider_retry_qualification where environment_id=$1 and generation_id=$2',
          [f.environment, f.generation],
        )
      ).rows;
      expect(original).toHaveLength(1);
      live = store.withCurrent(f.scope, f.environment, f.generation, async () => {
        entered();
        await gate;
        return 'ORIGINAL_USE';
      });
      await Promise.race([
        started,
        live.then(() => {
          throw new Error('consumption did not enter');
        }),
      ]);
      revocation = store.installAuthorityState(
        f.scope,
        f.environment,
        f.root.authorityId,
        f.revoked,
      );
      // Observe the actual database lock wait, not a timing assertion or fake flag.
      let blocked = false;
      for (let attempt = 0; attempt < 100 && !blocked; attempt++) {
        blocked = (
          await admin.query<{ blocked: boolean }>(
            `select exists(select 1 from pg_stat_activity a join pg_locks l on l.pid=a.pid where a.application_name='openpc-provider-retry-revocation-test' and l.locktype='advisory' and not l.granted) blocked`,
          )
        ).rows[0]!.blocked;
        if (!blocked) await new Promise((resolve) => setTimeout(resolve, 10));
      }
      expect(blocked).toBe(true);
      release();
      expect(await live).toBe('ORIGINAL_USE');
      await revocation;
      await expect(
        store.withCurrent(f.scope, f.environment, f.generation, async () => true),
      ).rejects.toThrow('UNQUALIFIED');
      expect(
        await new ProviderRetryQualificationStore(owner).readOriginal(
          f.scope,
          f.environment,
          f.generation,
        ),
      ).toEqual({
        inputDigest: qualificationDigest(f.bundle.input.payload),
        receiptDigest: qualificationDigest(f.bundle.receipt.payload),
        qualificationRef: decodeProviderRetryQualification('receipt', f.bundle.receipt.payload)
          .qualificationRef,
      });
      const retained = (
        await admin.query<{ custody_digest: string }>(
          'select custody_digest from control.operations_provider_retry_qualification where environment_id=$1 and generation_id=$2',
          [f.environment, f.generation],
        )
      ).rows;
      expect(qualificationCanonicalJson(retained)).toBe(qualificationCanonicalJson(original));
    } finally {
      release();
      await Promise.allSettled([live, revocation]);
      await Promise.all([admin.end(), owner.end()]);
    }
  },
  30000,
);

async function initialTrustGenerationFixture() {
  const schemaBytes = await readFile('config/schema/effective-configuration.schema.json'),
    profileBytes = await readFile('config/profiles/local.yaml');
  const schema = parseConfigurationJson(schemaBytes),
    namedProfile = parseNamedProfile(profileBytes);
  const environmentId = `ops-${id().slice(-12)}`,
    generationId = id(),
    baseGenerationId = id(),
    now = Date.now();
  const secret = (name: string) => `secret://local-os-keystore/${name}#v1`;
  const provider = (namedProfile.secretProvider as { providerId: string }).providerId;
  const reference = (name: string) => secret(name).replace('local-os-keystore', provider);
  const generation = {
    generationId: `urn:openpc:generation:${generationId}`,
    baseGenerationId: `urn:openpc:generation:${baseGenerationId}`,
    contentDigest: `sha256:${'a'.repeat(64)}`,
  };
  const site = {
    environmentId,
    publicBaseUrl: 'https://localhost:8443',
    generation,
    postgres: {
      controlDsnSecretRef: reference('control'),
      factsDsnSecretRef: reference('facts'),
      candidateIndexDsnSecretRef: reference('candidate'),
    },
    identity: {
      oidcIssuer: 'https://localhost:8443/oidc',
      clientId: 'synthetic-client',
      clientSecretRef: reference('oidc'),
      scimEnabled: false,
    },
    pki: { trustBundleSecretRef: reference('trust'), signingKeySecretRef: reference('signing') },
    telemetry: { otlpEndpoint: 'grpc://localhost:4317' },
    qualificationInputBindings: Object.fromEntries(
      Object.keys(namedProfile.requiredSettingInputs as object).map((key) => [
        key,
        `qualification://local/${key}@sha256:${'b'.repeat(64)}`,
      ]),
    ),
    settings: {
      'ui.export_row_limit': 1,
      'runtime.local_artifact_capacity': 1,
      'runtime.decision_deadline': '1ms',
      'evidence.local_spool_capacity': 1,
      'evidence.retention_profile': `profile://local/retention@sha256:${'c'.repeat(64)}`,
      'provider.read_retry_limit': 0,
      'facts.maximum_staleness': '1ms',
      'facts.reorg_retained_tail': 1,
      'module.allowed_publishers': `publisher-set://local/modules@sha256:${'d'.repeat(64)}`,
      'module.ui_slot_budget': 0,
      'operations.notification_delivery_limit': 0,
    },
  };
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    spki = key.publicKey.export({ format: 'der', type: 'spki' });
  const pins = {
    issuerSpkiHex: spki.toString('hex'),
    issuerEpoch: '1',
    issuerValidFromMs: now - 1000,
    issuerValidUntilMs: now + 300000,
    environmentId,
    profile: 'local' as const,
    configurationSchemaDigest: sha256(schemaBytes),
    namedProfileDigest: sha256(profileBytes),
  };
  const payload = encodeOperationsSiteDocument({
    generationId: generation.generationId,
    baseGenerationId: generation.baseGenerationId,
    environmentId,
    profile: 'local',
    siteDigest: sha256(site),
    configurationSchemaDigest: pins.configurationSchemaDigest,
    namedProfileDigest: pins.namedProfileDigest,
    declaredContentDigest: generation.contentDigest,
    issuerKeyId: evidenceKeyId(spki),
    issuerEpoch: '1',
    validFromMs: now - 1000,
    validUntilMs: now + 300000,
  });
  const signed = {
    payload,
    cose: signOperationsSiteDocument(
      key.privateKey.export({ format: 'der', type: 'pkcs8' }),
      spki,
      payload,
    ),
  };
  return {
    environmentId,
    generationId,
    baseGenerationId,
    pins,
    signed,
    sources: {
      schema,
      schemaBytes,
      namedProfile,
      profileBytes,
      profile: 'local',
      site,
      siteBytes: Buffer.from(JSON.stringify(site)),
      environment: {},
    },
  };
}

// This corpus installs INITIAL trust and stages a real signed configuration.
// Synthetic signed run claims test trust verification only: no execution,
// independent reviewer, admitted capacity or EFFECTIVE generation is seeded.
integration(
  'verifies installed async trust on the actual scoped transaction without granting qualification',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 });
    const staged = await initialTrustGenerationFixture();
    const scope = { participantId: id(), privacyDomainId: id(), requestId: id() };
    const pair = () => {
      const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      return {
        spki: keys.publicKey.export({ format: 'der', type: 'spki' }),
        privateKey: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
      };
    };
    const rootKey = pair(),
      inputKey = pair(),
      capacityKey = pair(),
      instant = Date.now();
    const root: QualificationRoot = {
      authorityId: 'async-test-authority',
      rootKeyId: evidenceKeyId(rootKey.spki),
      rootEpoch: '1',
      rootSpki: rootKey.spki,
      policySigner: 'OFFLINE_TRUST_ROOT',
      validFromMs: instant - 10000,
      validUntilMs: instant + 600000,
    };
    const descriptor = {
      format: 'COSE_Sign1',
      algorithm: 'ES256',
      curve: 'P-256',
      hash: 'SHA-256',
      canonicalization: 'PC-CBOR-1',
    };
    const keys = [
      { material: inputKey, purpose: 'pc.cose.operations-notification-async-input.v1' },
      {
        material: capacityKey,
        purpose: 'pc.cose.operations-notification-async-capacity-receipt.v1',
      },
    ]
      .map(({ material, purpose }) => ({
        keyId: evidenceKeyId(material.spki),
        epoch: 1,
        state: 'ACTIVE',
        purpose,
        nonExportable: true,
        backend: 'HSM',
        publicKeySpkiHex: material.spki.toString('hex'),
        validFromMs: instant - 5000,
        validUntilMs: instant + 300000,
      }))
      .sort((a, b) => a.keyId.localeCompare(b.keyId));
    const signedState = (
      sequence: number,
      state = 'ACTIVE',
      duplicatePurpose = false,
    ): QualificationAuthorityEnvelope => {
      const documentKeys = keys.map((k) => ({ ...k, state }));
      if (duplicatePurpose)
        documentKeys.push({
          ...documentKeys[0]!,
          epoch: 2,
          purpose: 'pc.cose.operations-qualification-input.v1',
        });
      documentKeys.sort((a, b) => a.keyId.localeCompare(b.keyId) || a.epoch - b.epoch);
      const rd = Buffer.from(
        qualificationCanonicalJson({
          schemaVersion: '1.0',
          authorityId: root.authorityId,
          revocations: [],
        }),
      );
      const r: QualificationRevocationClaims = {
        authorityId: root.authorityId,
        snapshotId: id(),
        sequence: String(sequence),
        revocationDocumentDigest: qualificationDigest(rd),
        rootKeyId: root.rootKeyId,
        rootEpoch: '1',
        issuedAtMs: instant - 1000,
        validUntilMs: instant + 300000,
      };
      const sign = (
        family: 'keyset' | 'revocations',
        claims: QualificationKeysetClaims | QualificationRevocationClaims,
        document: Buffer,
      ) => {
        const payload = encodeProviderRetryQualification(family, claims);
        return {
          payload,
          cose: signConsumerCose(
            providerRetryQualificationProfiles[family],
            rootKey.privateKey,
            rootKey.spki,
            payload,
          ),
          document,
        };
      };
      const revocations = sign('revocations', r, rd);
      const kd = Buffer.from(
        qualificationCanonicalJson({
          schemaVersion: '1.0',
          authorityId: root.authorityId,
          policySigner: root.policySigner,
          keys: documentKeys,
          issuedAt: new Date(instant - 1000).toISOString(),
          signatureEnvelope: descriptor,
        }),
      );
      const k: QualificationKeysetClaims = {
        authorityId: root.authorityId,
        keysetId: id(),
        sequence: String(sequence),
        keysetDocumentDigest: qualificationDigest(kd),
        revocationPayloadDigest: qualificationDigest(revocations.payload),
        policySigner: root.policySigner,
        rootKeyId: root.rootKeyId,
        rootEpoch: '1',
        issuedAtMs: instant - 1000,
        validUntilMs: instant + 300000,
      };
      return { keyset: sign('keyset', k, kd), revocations };
    };
    try {
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Async initial trust','ACTIVE',1)",
        [scope.participantId],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Async trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [scope.privacyDomainId, scope.participantId],
      );
      const sourceAuthentication = (
        await readPublicOperationsSources({
          sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
          profile: 'local',
        })
      ).custody;
      const installationScope = {
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
      };
      await installInitialOperationsEnvironment(admin, installationScope, {
        pins: staged.pins,
        initialBaseGenerationId: staged.baseGenerationId,
        schemaBytes: staged.sources.schemaBytes,
        profileBytes: staged.sources.profileBytes,
        sourceAuthentication,
      });
      const generation = await stageInitialOperationsGeneration(
        admin,
        installationScope,
        staged.sources,
        staged.signed,
      );
      expect(generation.effective).toBe(false);
      expect(generation.missingBindings).toContain('CONSUMER_EFFECTIVE:LS-NOTIFICATION');
      await installProviderRetryQualificationRoot(admin, scope, staged.environmentId, root);
      const store = new ProviderRetryQualificationStore(admin),
        initial = signedState(1);
      expect(
        (await store.installAuthorityState(scope, staged.environmentId, root.authorityId, initial))
          .sequence,
      ).toBe('1');
      const candidate = (
        await admin.query(
          'select candidate from control.operations_generation where environment_id=$1 and generation_id=$2',
          [staged.environmentId, staged.generationId],
        )
      ).rows[0]!.candidate.configuration;
      const h = (name: string) => qualificationDigest(Buffer.from(name));
      const input: NotificationAsyncInputClaims = {
        authorityId: root.authorityId,
        environmentId: staged.environmentId,
        profile: 'local',
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        task: 'ASYNC-NOTIFICATION',
        generationId: staged.generationId,
        configurationDigest: candidate.generation.contentDigest,
        configurationSchemaDigest: staged.pins.configurationSchemaDigest,
        namedProfileDigest: staged.pins.namedProfileDigest,
        buildDigest: h('test-build'),
        sourceTreeDigest: h('test-source'),
        workloadIdentityDigest: h('test-workload'),
        environmentIdentityDigest: h('test-environment'),
        storeProfileDigest: h('test-store'),
        gatewayProfileDigest: h('test-gateway'),
        ratePolicyDigest: h('test-rate'),
        inputId: id(),
        slot: 'QINPUT-ASYNC-NOTIFICATION',
        concurrency: 1,
        batchSize: 1,
        leaseMs: 1000,
        heartbeatMs: 200,
        attemptTimeoutMs: 100,
        retryDelaysMs: [1, 2, 3, 4, 5],
        domainDeadlineMs: 2000,
        queueItems: 1,
        queueBytes: 1000,
        maximumQueueAgeMs: 2000,
        maximumPayloadBytes: 500,
        dispatchRatePerSecond: 1,
        issuerKeyId: evidenceKeyId(inputKey.spki),
        issuerEpoch: '1',
        validFromMs: instant - 500,
        validUntilMs: instant + 120000,
      };
      const inputPayload = encodeNotificationAsync('input', input);
      const capacity: NotificationAsyncCapacityClaims = {
        authorityId: input.authorityId,
        environmentId: input.environmentId,
        profile: input.profile,
        participantId: input.participantId,
        privacyDomainId: input.privacyDomainId,
        task: input.task,
        generationId: input.generationId,
        configurationDigest: input.configurationDigest,
        configurationSchemaDigest: input.configurationSchemaDigest,
        namedProfileDigest: input.namedProfileDigest,
        buildDigest: input.buildDigest,
        sourceTreeDigest: input.sourceTreeDigest,
        workloadIdentityDigest: input.workloadIdentityDigest,
        environmentIdentityDigest: input.environmentIdentityDigest,
        storeProfileDigest: input.storeProfileDigest,
        gatewayProfileDigest: input.gatewayProfileDigest,
        ratePolicyDigest: input.ratePolicyDigest,
        receiptId: id(),
        inputPayloadDigest: qualificationDigest(inputPayload),
        runId: id(),
        harnessDigest: h('test-harness'),
        rawEvidenceDigest: h('NOT-EXECUTED'),
        originalSignedOutcomesDigest: h('NOT-EXECUTED-OUTCOMES'),
        normalizedResultsDigest: h('NOT-EXECUTED-RESULTS'),
        reviewerAttestationDigest: h('NOT-REVIEWED'),
        subjectAuthorPrincipalId: id(),
        harnessAuthorPrincipalId: id(),
        reviewerPrincipalId: id(),
        signerPrincipalId: id(),
        measuredConcurrency: 1,
        measuredBatchSize: 1,
        measuredQueueItems: 1,
        measuredQueueBytes: 1000,
        measuredMaximumPayloadBytes: 500,
        measuredDispatchRatePerSecond: 1,
        observedMaximumQueueAgeMs: 1000,
        observedMaximumAttemptDurationMs: 100,
        runStartedAtMs: instant - 400,
        runCompletedAtMs: instant - 200,
        keysetPayloadDigest: qualificationDigest(initial.keyset.payload),
        revocationPayloadDigest: qualificationDigest(initial.revocations.payload),
        issuerKeyId: evidenceKeyId(capacityKey.spki),
        issuerEpoch: '1',
        issuedAtMs: instant - 100,
        expiresAtMs: instant + 120000,
      };
      const capacityPayload = encodeNotificationAsync('capacity', capacity);
      const originals = {
        input: {
          payload: inputPayload,
          cose: signConsumerCose(
            notificationAsyncProfiles.input,
            inputKey.privateKey,
            inputKey.spki,
            inputPayload,
          ),
        },
        capacity: {
          payload: capacityPayload,
          cose: signConsumerCose(
            notificationAsyncProfiles.capacity,
            capacityKey.privateKey,
            capacityKey.spki,
            capacityPayload,
          ),
        },
      };
      let consumed = 0;
      const verify = (
        client: PoolClient,
        selected = scope,
        environment = staged.environmentId,
        generationId = staged.generationId,
      ) =>
        withInstalledNotificationAsyncAuthority(
          client,
          selected,
          environment,
          generationId,
          originals,
          async (same, claims) => {
            expect(same).toBe(client);
            expect(claims).toEqual({ input, capacity });
            consumed++;
            return claims;
          },
        );
      await controlTransaction(admin, scope, async (client) => {
        await verify(client);
        const other = await admin.connect();
        try {
          await other.query('begin');
          for (const name of [
            `operations-generation:${staged.environmentId}`,
            `operations-qualification:${staged.environmentId}:${root.authorityId}`,
          ])
            expect(
              (
                await other.query(
                  'select pg_try_advisory_xact_lock(hashtextextended($1,0)) locked',
                  [name],
                )
              ).rows[0].locked,
            ).toBe(false);
        } finally {
          await other.query('rollback');
          other.release();
        }
      });
      expect(consumed).toBe(1);
      for (const selected of [
        { ...scope, requestId: id() },
        { ...scope, privacyDomainId: id() },
        { ...scope, participantId: id() },
      ])
        await expect(
          controlTransaction(admin, scope, (client) => verify(client, selected)),
        ).rejects.toThrow();
      await expect(
        controlTransaction(admin, scope, (client) => verify(client, scope, 'foreign-environment')),
      ).rejects.toThrow();
      await expect(
        controlTransaction(admin, scope, (client) =>
          verify(client, scope, staged.environmentId, id()),
        ),
      ).rejects.toThrow();
      await expect(
        controlTransaction(admin, scope, (client) => verify(client), 'repeatable read'),
      ).rejects.toThrow();
      expect(consumed).toBe(1);
      const autocommit = await admin.connect();
      try {
        await autocommit.query('set role openpc_control_owner');
        for (const [name, value] of Object.entries({
          'openpc.context_mode': 'PARTICIPANT',
          'openpc.context_scope': 'TRANSACTION_LOCAL',
          'openpc.participant_id': scope.participantId,
          'openpc.privacy_domain_id': scope.privacyDomainId,
          'openpc.operation_id': scope.requestId,
          'openpc.action_intent_id': 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        }))
          await autocommit.query('select set_config($1,$2,false)', [name, value]);
        await expect(verify(autocommit)).rejects.toThrow();
      } finally {
        await autocommit.query('reset role');
        await autocommit.query('reset all');
        autocommit.release();
      }
      expect(consumed).toBe(1);
      await expect(
        controlTransaction(admin, scope, (client) =>
          withInstalledNotificationAsyncAuthority(
            client,
            scope,
            staged.environmentId,
            staged.generationId,
            originals,
            async (same) => {
              await same.query("select set_config('openpc.operation_id',$1,true)", [id()]);
            },
          ),
        ),
      ).rejects.toThrow();
      // A deliberately hostile trusted callback can COMMIT; the seam detects it
      // and returns no authority. It does not claim to undo that COMMIT.
      await expect(
        controlTransaction(admin, scope, (client) =>
          withInstalledNotificationAsyncAuthority(
            client,
            scope,
            staged.environmentId,
            staged.generationId,
            originals,
            async (same) => {
              await same.query('commit');
            },
          ),
        ),
      ).rejects.toThrow();
      // Real SQL rejects an async envelope under either original provider purpose.
      for (const [family, envelope] of [
        ['input', originals.input],
        ['receipt', originals.capacity],
      ] as const)
        await expect(
          controlTransaction(admin, scope, (client) =>
            client.query('select openpc.provider_retry_claims($1,$2,$3,$4)', [
              family,
              envelope.payload,
              envelope.cose,
              family === 'input' ? input.issuerKeyId : capacity.issuerKeyId,
            ]),
          ),
        ).rejects.toThrow();
      // Bypass the TypeScript state installer solely to exercise the installed SQL
      // prohibition on reusing one SPKI for another purpose in a retained epoch.
      const invalid = signedState(2, 'ACTIVE', true),
        custody = {
          keyset: {
            payloadHex: invalid.keyset.payload.toString('hex'),
            coseHex: invalid.keyset.cose.toString('hex'),
            documentHex: invalid.keyset.document.toString('hex'),
          },
          revocations: {
            payloadHex: invalid.revocations.payload.toString('hex'),
            coseHex: invalid.revocations.cose.toString('hex'),
            documentHex: invalid.revocations.document.toString('hex'),
          },
        };
      const custodyBytes = Buffer.from(qualificationCanonicalJson(custody));
      await expect(
        controlTransaction(admin, scope, async (client) => {
          await client.query('set local role openpc_operations_qualification_owner');
          return client.query(
            'insert into control.operations_qualification_state(participant_id,privacy_domain_id,environment_id,authority_id,sequence,snapshot_sequence,root_epoch,custody,custody_bytes,custody_digest,keyset_digest,revocations_digest,valid_until_ms) values($1,$2,$3,$4,2,2,1,$5,$6,$7,$8,$9,$10)',
            [
              scope.participantId,
              scope.privacyDomainId,
              staged.environmentId,
              root.authorityId,
              custody,
              custodyBytes,
              qualificationDigest(custodyBytes),
              qualificationDigest(invalid.keyset.payload),
              qualificationDigest(invalid.revocations.payload),
              instant + 300000,
            ],
          );
        }),
      ).rejects.toThrow();
      await store.installAuthorityState(
        scope,
        staged.environmentId,
        root.authorityId,
        signedState(2, 'RETIRED'),
      );
      await controlTransaction(admin, scope, (client) => verify(client));
      expect(consumed).toBe(2);
      await store.installAuthorityState(
        scope,
        staged.environmentId,
        root.authorityId,
        signedState(3, 'REVOKED'),
      );
      await expect(controlTransaction(admin, scope, (client) => verify(client))).rejects.toThrow();
      expect(consumed).toBe(2);
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.operations_qualification_state where environment_id=$1',
            [staged.environmentId],
          )
        ).rows[0].count,
      ).toBe(3);
      for (const table of [
        'operations_provider_retry_qualification',
        'operations_generation_commit',
      ])
        expect(
          (
            await admin.query(
              `select count(*)::int count from control.${table} where environment_id=$1`,
              [staged.environmentId],
            )
          ).rows[0].count,
        ).toBe(0);
    } finally {
      rootKey.privateKey.fill(0);
      inputKey.privateKey.fill(0);
      capacityKey.privateKey.fill(0);
      await admin.end();
    }
  },
  30000,
);
