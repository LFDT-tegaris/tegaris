import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  ProviderRetryQualificationStore,
  installProviderRetryQualificationRoot,
  withInstalledProviderRetryInput,
  type ProviderRetryQualificationScope,
} from '../../../services/control-api/src/configuration/operations/provider-retry-qualification.js';
import {
  decodeProviderRetryQualification,
  encodeProviderRetryQualification,
  providerRetryQualificationProfiles,
  qualificationDigest,
  qualificationCanonicalJson,
  type QualificationRoot,
  type QualificationEnvelope,
  type QualificationAuthorityEnvelope,
  type QualificationFamily,
  type QualificationInputClaims,
} from '../../../packages/security-kernel/src/operations-configuration/provider-retry-qualification.js';
import { signConsumerCose } from '../../../packages/security-kernel/src/fact-consumer/cose-framing.js';
import {
  encodeOperationsSiteDocument,
  signOperationsSiteDocument,
  evidenceKeyId,
} from '../../../packages/security-kernel/src/index.js';
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

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const integration = adminUrl ? it : it.skip;
const descriptor = {
  format: 'COSE_Sign1',
  algorithm: 'ES256',
  curve: 'P-256',
  hash: 'SHA-256',
  canonicalization: 'PC-CBOR-1',
};
const h = (text: string) => qualificationDigest(Buffer.from(text));
const pair = () => {
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    spki: key.publicKey.export({ format: 'der', type: 'spki' }),
  };
};

// Existing installed-trust fixture recipe: authentic source files and supported
// installation/staging owners. Only INITIAL trust/identities are bootstrapped.
async function initialTrustGenerationFixture(
  inputFactory: (pins: {
    environmentId: string;
    configurationSchemaDigest: string;
    namedProfileDigest: string;
  }) => QualificationEnvelope,
) {
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
  const original = inputFactory(pins);
  const input = decodeProviderRetryQualification('input', original.payload);
  site.qualificationInputBindings['provider.read_retry_limit'] =
    `qualification://${input.authorityId}/${input.inputId}@${qualificationDigest(original.payload)}`;
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
    original,
    input,
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

async function setup(
  pool: Pool,
  options: { authenticated?: boolean; purpose?: string; lifetimeMs?: number } = {},
) {
  const instant = Date.now(),
    rootKey = pair(),
    inputKey = pair();
  const root: QualificationRoot = {
    authorityId: 'provider-input-authority',
    rootKeyId: evidenceKeyId(rootKey.spki),
    rootEpoch: '1',
    rootSpki: rootKey.spki,
    policySigner: 'OFFLINE_TRUST_ROOT',
    validFromMs: instant - 10000,
    validUntilMs: instant + 600000,
  };
  const scope = { participantId: id(), privacyDomainId: id(), requestId: id() };
  const sign = <F extends QualificationFamily>(
    family: F,
    claims: Parameters<typeof encodeProviderRetryQualification<F>>[1],
    key = rootKey,
  ) => {
    const payload = encodeProviderRetryQualification(family, claims);
    return {
      payload,
      cose: signConsumerCose(
        providerRetryQualificationProfiles[family],
        key.privateKey,
        key.spki,
        payload,
      ),
    };
  };
  const state = (
    sequence: number,
    revoked = false,
    keyState = 'ACTIVE',
  ): QualificationAuthorityEnvelope => {
    const issued = instant - 500 + sequence;
    const rd = Buffer.from(
      qualificationCanonicalJson({
        schemaVersion: '1.0',
        authorityId: root.authorityId,
        revocations: revoked
          ? [
              {
                schemaVersion: '1.0',
                authorityId: root.authorityId,
                keyId: evidenceKeyId(inputKey.spki),
                keyEpoch: 1,
                state: 'REVOKED',
                effectiveAt: new Date(issued).toISOString(),
                receiptEffect: 'INVALIDATE_RECEIPTS_COVERED_BY_REVOKED_KEY_EPOCH',
                evidenceRetention: 'PRESERVE_NEVER_DELETE_OR_RESIGN',
                signatureEnvelope: descriptor,
              },
            ]
          : [],
      }),
    );
    const revocations = {
      ...sign('revocations', {
        authorityId: root.authorityId,
        snapshotId: id(),
        sequence: String(sequence),
        revocationDocumentDigest: qualificationDigest(rd),
        rootKeyId: root.rootKeyId,
        rootEpoch: '1',
        issuedAtMs: issued,
        validUntilMs: instant + 300000,
      }),
      document: rd,
    };
    const kd = Buffer.from(
      qualificationCanonicalJson({
        schemaVersion: '1.0',
        authorityId: root.authorityId,
        policySigner: root.policySigner,
        issuedAt: new Date(issued).toISOString(),
        signatureEnvelope: descriptor,
        keys: [
          {
            keyId: evidenceKeyId(inputKey.spki),
            epoch: 1,
            state: keyState,
            purpose: options.purpose ?? 'pc.cose.operations-qualification-input.v1',
            nonExportable: true,
            backend: 'HSM',
            publicKeySpkiHex: inputKey.spki.toString('hex'),
            validFromMs: instant - 5000,
            validUntilMs: instant + 300000,
          },
        ],
      }),
    );
    return {
      revocations,
      keyset: {
        ...sign('keyset', {
          authorityId: root.authorityId,
          keysetId: id(),
          sequence: String(sequence),
          keysetDocumentDigest: qualificationDigest(kd),
          revocationPayloadDigest: qualificationDigest(revocations.payload),
          policySigner: root.policySigner,
          rootKeyId: root.rootKeyId,
          rootEpoch: '1',
          issuedAtMs: issued,
          validUntilMs: instant + 300000,
        }),
        document: kd,
      },
    };
  };
  const staged = await initialTrustGenerationFixture((pins) =>
    sign(
      'input',
      {
        authorityId: root.authorityId,
        environmentId: pins.environmentId,
        profile: 'local',
        inputId: id(),
        slot: 'QINPUT-LOCAL-PROVIDER-READ-RETRY-V1',
        setting: 'provider.read_retry_limit',
        value: 0,
        method: 'eth_call',
        methodClass: 'RETRY_SAFE_READ',
        methodProfileDigest: h('unexecuted-method-claim'),
        workloadIdentityDigest: h('unexecuted-workload-claim'),
        environmentIdentityDigest: h('unexecuted-environment-claim'),
        subjectArtifactDigest: h('unexecuted-subject-claim'),
        buildDigest: h('unexecuted-build-claim'),
        sourceTreeDigest: h('unexecuted-source-claim'),
        configurationSchemaDigest: pins.configurationSchemaDigest,
        namedProfileDigest: pins.namedProfileDigest,
        issuerKeyId: evidenceKeyId(inputKey.spki),
        issuerEpoch: '1',
        validFromMs: instant - 1000,
        validUntilMs: instant + (options.lifetimeMs ?? 120000),
      },
      inputKey,
    ),
  );
  await pool.query(
    "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Input initial trust','ACTIVE',1)",
    [scope.participantId],
  );
  await pool.query(
    "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Input trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
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
  await installInitialOperationsEnvironment(pool, installationScope, {
    pins: staged.pins,
    initialBaseGenerationId: staged.baseGenerationId,
    schemaBytes: staged.sources.schemaBytes,
    profileBytes: staged.sources.profileBytes,
    ...(options.authenticated === false ? {} : { sourceAuthentication }),
  });
  const generation = await stageInitialOperationsGeneration(
    pool,
    installationScope,
    staged.sources,
    staged.signed,
  );
  expect(generation.effective).toBe(false);
  await installProviderRetryQualificationRoot(pool, scope, staged.environmentId, root);
  const store = new ProviderRetryQualificationStore(pool);
  await store.installAuthorityState(scope, staged.environmentId, root.authorityId, state(1));
  return {
    ...staged,
    scope,
    root,
    store,
    state,
    signInput: (changes: Partial<QualificationInputClaims>) =>
      sign('input', { ...staged.input, ...changes }, inputKey),
  };
}
type Fixture = Awaited<ReturnType<typeof setup>>;
async function scoped<T>(
  pool: Pool,
  scope: ProviderRetryQualificationScope,
  work: (client: PoolClient) => Promise<T>,
  role = 'openpc_operations_qualification_owner',
  reservationTable?: string,
): Promise<T> {
  if (
    ![
      'openpc_operations_qualification_owner',
      'openpc_control_owner',
      'openpc_control_runtime',
    ].includes(role)
  )
    throw new Error('TEST_ROLE');
  const client = await pool.connect();
  let failed = false,
    first: unknown,
    result!: T;
  try {
    // Only the test administrator creates this session-local scratch table.
    // Ordinary qualification roles retain their real lack of CREATE privileges.
    if (reservationTable) {
      if (!/^provider_input_[a-z_]+$/u.test(reservationTable)) throw new Error('TEST_TABLE');
      await client.query(`create temporary table ${reservationTable}(value text)`);
      await client.query(
        `grant select,insert on ${reservationTable} to openpc_operations_qualification_owner,openpc_control_owner`,
      );
    }
    await client.query('begin isolation level read committed');
    await client.query(`set local role ${role}`);
    await client.query('set local row_security=on');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
      [scope.participantId, scope.privacyDomainId, scope.requestId],
    );
    result = await work(client);
  } catch (error) {
    failed = true;
    first = error;
  }
  const cleanup = (error: unknown) => {
    process.stderr.write('PROVIDER_INPUT_TEST_CLEANUP|UNKNOWN\n');
    if (!failed) first = error;
    failed = true;
  };
  await client.query('rollback').catch(cleanup);
  try {
    client.release();
  } catch (error) {
    cleanup(error);
  }
  if (failed) throw first;
  return result;
}
async function unchanged(pool: Pool, f: Fixture) {
  const result = await pool.query(
    `select g.state,
    (select count(*)::integer from control.operations_provider_retry_qualification q where q.environment_id=g.environment_id) qualifications
    from control.operations_generation g where g.environment_id=$1 and g.generation_id=$2`,
    [f.environmentId, f.generationId],
  );
  // Missing bindings is context-dependent: inspect it with the actual scoped owner.
  const missing = await scoped(
    pool,
    f.scope,
    (client) =>
      client.query<{ missing: string[] }>(
        'select openpc.operations_generation_missing($1,$2) missing',
        [f.environmentId, f.generationId],
      ),
    'openpc_control_owner',
  );
  expect(result.rows[0]?.state).toBe('STAGED');
  expect(result.rows[0]?.qualifications).toBe(0);
  expect(missing.rows[0]?.missing).toContain('QUALIFICATION:provider.read_retry_limit');
}
// Real PG trust/input tests ONLY: generated external keys and declared native
// identities never establish KMS custody, executed qualification or review.
integration(
  'verifies receipt-free installed provider input on both scoped owners without granting qualification',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 2 });
    try {
      const f = await setup(pool);
      for (const role of ['openpc_operations_qualification_owner', 'openpc_control_owner']) {
        const table = `provider_input_reservation_${role}`;
        await scoped(
          pool,
          f.scope,
          (client) =>
            withInstalledProviderRetryInput(
              client,
              f.scope,
              f.environmentId,
              f.generationId,
              f.original,
              async (same, verified) => {
                expect(same).toBe(client);
                expect(verified.input).toEqual(f.input);
                expect(Object.isFrozen(verified.input)).toBe(true);
                expect(verified.inputPayloadDigest).toBe(qualificationDigest(f.original.payload));
                await same.query(`insert into ${table} values($1)`, [verified.inputPayloadDigest]);
                expect((await same.query(`select value from ${table}`)).rows).toEqual([
                  { value: verified.inputPayloadDigest },
                ]);
              },
            ),
          role,
          table,
        );
      }
      await unchanged(pool, f);
    } finally {
      await pool.end();
    }
  },
  30000,
);
integration(
  'denies substituted signed bindings, wrong scope/generation/purpose and unauthenticated source before its callback',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 2 });
    try {
      const f = await setup(pool);
      let consumed = 0;
      const consume = async () => {
        consumed++;
      };
      for (const changes of [
        { value: 1 },
        { issuerEpoch: '2' },
        { profile: 'test' as const },
        { slot: 'QINPUT-TEST-PROVIDER-READ-RETRY-V1' },
        { configurationSchemaDigest: h('other-schema') },
        { namedProfileDigest: h('other-profile') },
        { method: 'eth_getLogs' },
        { methodProfileDigest: h('other-method') },
        { workloadIdentityDigest: h('other-workload') },
        { subjectArtifactDigest: h('other-subject') },
      ])
        await expect(
          scoped(pool, f.scope, (client) =>
            withInstalledProviderRetryInput(
              client,
              f.scope,
              f.environmentId,
              f.generationId,
              f.signInput(changes),
              consume,
            ),
          ),
        ).rejects.toThrow();
      await expect(
        scoped(pool, f.scope, (client) =>
          withInstalledProviderRetryInput(
            client,
            f.scope,
            f.environmentId,
            id(),
            f.original,
            consume,
          ),
        ),
      ).rejects.toThrow();
      for (const field of ['participantId', 'privacyDomainId'] as const) {
        const foreign = { ...f.scope, [field]: id() };
        await expect(
          scoped(pool, foreign, (client) =>
            withInstalledProviderRetryInput(
              client,
              foreign,
              f.environmentId,
              f.generationId,
              f.original,
              consume,
            ),
          ),
        ).rejects.toThrow();
      }
      for (const options of [
        { authenticated: false },
        { purpose: 'pc.cose.operations-notification-async-input.v1' },
      ]) {
        const other = await setup(pool, options);
        await expect(
          scoped(pool, other.scope, (client) =>
            withInstalledProviderRetryInput(
              client,
              other.scope,
              other.environmentId,
              other.generationId,
              other.original,
              consume,
            ),
          ),
        ).rejects.toThrow();
        await unchanged(pool, other);
      }
      expect(consumed).toBe(0);
      await unchanged(pool, f);
    } finally {
      await pool.end();
    }
  },
  30000,
);
integration(
  'denies autocommit, changed request/action/role/transaction/client and retains callback failure with rollback',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 1 });
    try {
      const f = await setup(pool);
      let consumed = false;
      const invoke = (
        client: PoolClient,
        scope = f.scope,
        callback = async (_same: PoolClient) => {
          consumed = true;
        },
      ) =>
        withInstalledProviderRetryInput(
          client,
          scope,
          f.environmentId,
          f.generationId,
          f.original,
          callback,
        );
      await expect(
        scoped(pool, f.scope, (client) => invoke(client, { ...f.scope, requestId: id() })),
      ).rejects.toThrow();
      await expect(
        scoped(pool, f.scope, (client) => invoke(client), 'openpc_control_runtime'),
      ).rejects.toThrow();
      await expect(
        scoped(pool, f.scope, async (client) => {
          await client.query('commit');
          return invoke(client);
        }),
      ).rejects.toThrow();
      await expect(
        scoped(pool, f.scope, async (client) => {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)",
          );
          return invoke(client);
        }),
      ).rejects.toThrow();
      expect(consumed).toBe(false);
      await expect(
        scoped(pool, f.scope, async (client) => {
          await client.query('rollback');
          await client.query('begin isolation level serializable');
          await client.query('set local role openpc_operations_qualification_owner');
          await client.query('set local row_security=on');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
            [f.scope.participantId, f.scope.privacyDomainId, f.scope.requestId],
          );
          return invoke(client);
        }),
      ).rejects.toThrow();
      expect(consumed).toBe(false);
      await expect(
        scoped(pool, f.scope, (client) =>
          invoke(client, f.scope, async (same) => {
            await same.query("select set_config('openpc.operation_id',$1,true)", [id()]);
          }),
        ),
      ).rejects.toThrow();
      await expect(
        scoped(pool, f.scope, (client) =>
          invoke(client, f.scope, async (same) => {
            same.release();
          }),
        ),
      ).rejects.toThrow();
      await expect(
        scoped(pool, f.scope, (client) =>
          invoke(client, f.scope, async (same) => {
            same.query = same.query.bind(same);
          }),
        ),
      ).rejects.toThrow();
      await expect(
        scoped(pool, f.scope, (client) =>
          invoke(client, f.scope, async (same) => {
            await same.query('rollback');
            await same.query('begin isolation level read committed');
            await same.query('set local role openpc_operations_qualification_owner');
            await same.query('set local row_security=on');
            await same.query(
              "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
              [f.scope.participantId, f.scope.privacyDomainId, f.scope.requestId],
            );
          }),
        ),
      ).rejects.toThrow();
      const failure = new Error('ORIGINAL_CALLBACK_FAILURE');
      await expect(
        scoped(
          pool,
          f.scope,
          (client) =>
            invoke(client, f.scope, async (same) => {
              await same.query(
                "insert into provider_input_failed_reservation values('uncommitted')",
              );
              throw failure;
            }),
          'openpc_operations_qualification_owner',
          'provider_input_failed_reservation',
        ),
      ).rejects.toBe(failure);
      expect(
        (await pool.query('select count(*)::integer count from provider_input_failed_reservation'))
          .rows[0]?.count,
      ).toBe(0);
      await unchanged(pool, f);
    } finally {
      await pool.end();
    }
  },
  30000,
);
integration(
  'holds actual generation/root fences and rejects the unchanged original after installed revocation',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 2 });
    try {
      const f = await setup(pool);
      const before = {
        payload: Buffer.from(f.original.payload),
        cose: Buffer.from(f.original.cose),
      };
      await scoped(pool, f.scope, (held) =>
        withInstalledProviderRetryInput(
          held,
          f.scope,
          f.environmentId,
          f.generationId,
          f.original,
          async () => {
            for (const key of [
              `operations-generation:${f.environmentId}`,
              `operations-qualification:${f.environmentId}:${f.root.authorityId}`,
            ]) {
              const result = await scoped(pool, { ...f.scope, requestId: id() }, (other) =>
                other.query<{ acquired: boolean }>(
                  'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
                  [key],
                ),
              );
              expect(result.rows).toEqual([{ acquired: false }]);
            }
            for (const table of [
              'operations_installation',
              'operations_generation',
              'operations_qualification_root',
            ]) {
              await expect(
                scoped(pool, { ...f.scope, requestId: id() }, (other) =>
                  other.query(
                    `select 1 from control.${table} where environment_id=$1 for update nowait`,
                    [f.environmentId],
                  ),
                ),
              ).rejects.toMatchObject({ code: '55P03' });
            }
          },
        ),
      );
      await f.store.installAuthorityState(
        f.scope,
        f.environmentId,
        f.root.authorityId,
        f.state(2, true),
      );
      let consumed = false;
      await expect(
        scoped(pool, f.scope, (client) =>
          withInstalledProviderRetryInput(
            client,
            f.scope,
            f.environmentId,
            f.generationId,
            f.original,
            async () => {
              consumed = true;
            },
          ),
        ),
      ).rejects.toThrow();
      expect(consumed).toBe(false);
      expect(f.original).toEqual(before);
      await unchanged(pool, f);
    } finally {
      await pool.end();
    }
  },
  30000,
);
integration(
  'fails after original input expires during a database callback without renewing or replacing it',
  async () => {
    const pool = new Pool({ connectionString: adminUrl, max: 1 });
    try {
      const f = await setup(pool, { lifetimeMs: 10000 });
      let consumed = false;
      await expect(
        scoped(pool, f.scope, (client) =>
          withInstalledProviderRetryInput(
            client,
            f.scope,
            f.environmentId,
            f.generationId,
            f.original,
            async (same, verified) => {
              const row = (
                await same.query<{ remaining: string }>(
                  'select $1::numeric-extract(epoch from clock_timestamp())*1000 remaining',
                  [verified.input.validUntilMs],
                )
              ).rows[0];
              const remaining = Number(row?.remaining);
              if (!(remaining >= 100 && remaining <= 10000))
                throw new Error(
                  'BLOCKED: fresh original input did not reach its intended expiry phase',
                );
              consumed = true;
              await same.query('select pg_sleep($1)', [(remaining + 100) / 1000]);
            },
          ),
        ),
      ).rejects.toThrow('OPS_PROVIDER_RETRY_UNQUALIFIED');
      expect(consumed).toBe(true);
      await unchanged(pool, f);
    } finally {
      await pool.end();
    }
  },
  30000,
);
