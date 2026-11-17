import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { mkdtemp, readFile, writeFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import {
  encodeOperationsSiteDocument,
  signOperationsSiteDocument,
  evidenceKeyId,
} from '../../../packages/security-kernel/src/index.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  parseConfigurationJson,
  parseNamedProfile,
} from '../../../scripts/operations/installation-config-inputs.mjs';
import { prepareSignedInstallationCandidate } from '../../../scripts/operations/installation-config-signature.mjs';
import { readPublicOperationsSources } from '../../../scripts/operations/read-public-installation-sources.mjs';
import {
  installInitialOperationsEnvironment,
  stageInitialOperationsGeneration,
  readOperationsGeneration,
} from '../../../scripts/operations/installation-generation-store.mjs';
import { closeFixtureResources } from './close-fixture-resources.js';
const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const material = process.env.OPENPC_PUBLIC_OPERATIONS_TEST_MATERIAL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
async function fixture() {
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
    initialKeyPkcs8Der: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
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
it('authenticates public source bytes and a real signed installation before database allocation', async () => {
  const input = await fixture();
  const source = await readPublicOperationsSources({
    sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
    profile: 'local',
  });
  expect(source.custody.version).toBe(2);
  const { issuerSpkiHex, ...pins } = input.pins;
  const candidate = prepareSignedInstallationCandidate(
    input.sources,
    { ...pins, issuerSpki: Buffer.from(issuerSpkiHex, 'hex') },
    input.signed,
    Date.now(),
  );
  expect(candidate.startupAllowed).toBe(false);
  expect(candidate.blockers).toContain('QUALIFICATION_VERIFICATION_UNBOUND');
});

integration(
  'installs public sources using a restricted installer and binds their real signed generation across reconnect',
  async () => {
    let endpoint: URL, runtimeEndpoint: URL;
    try {
      endpoint = new URL(adminUrl!);
      runtimeEndpoint = new URL(runtimeUrl!);
    } catch {
      throw Error('Invalid isolated test database configuration');
    }
    if (
      !['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname) ||
      endpoint.pathname !== '/openpc_control' ||
      runtimeEndpoint.hostname !== endpoint.hostname ||
      runtimeEndpoint.port !== endpoint.port ||
      runtimeEndpoint.pathname !== endpoint.pathname
    )
      throw Error('Same isolated loopback test database required');
    const parent = material ?? process.env.OPENPC_TEST_TMP_ROOT ?? tmpdir();
    if (!parent.startsWith('/') || (await realpath(parent)) !== parent)
      throw Error('Canonical private test material root required');
    const input = await fixture(),
      scope = { participantId: id(), privacyDomainId: id() },
      foreign = { participantId: id(), privacyDomainId: id() };
    const directory = await mkdtemp(join(parent, 'public-operations-source-'));
    await writeFile(join(directory, 'initial-signer.pkcs8.der'), input.initialKeyPkcs8Der, {
      mode: 0o600,
      flag: 'wx',
    });
    const roleName = 'openpc_public_source_' + id().replaceAll('-', '').slice(-12);
    if (!/^[a-z0-9_]{1,63}$/u.test(roleName)) throw Error('Invalid isolated role name');
    const installerLocation = new URL(adminUrl!);
    installerLocation.username = roleName;
    installerLocation.password = randomBytes(32).toString('hex');
    const installerUrl = installerLocation.href;
    await writeFile(
      join(directory, 'installer-login.private.json'),
      JSON.stringify({ databaseUrl: installerUrl }),
      { mode: 0o600, flag: 'wx' },
    );
    const authentication = await readPublicOperationsSources({
      sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
      profile: 'local',
    });
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    let installer = new Pool({ connectionString: installerUrl, max: 1 });
    const closed = new Set<Pool>();
    const end = async (pool: Pool) => {
      if (!closed.has(pool)) {
        closed.add(pool);
        await pool.end();
      }
    };
    let failure: { error: unknown } | undefined;
    async function scoped<T>(
      selected: typeof scope,
      run: (client: PoolClient) => Promise<T>,
    ): Promise<T> {
      const c = await installer.connect();
      let primary: { error: unknown } | undefined;
      let result!: T;
      try {
        await c.query('discard all');
        await c.query('begin');
        await c.query('set local role openpc_control_owner');
        await c.query('set local row_security=on');
        await c.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true),openpc.assert_request_context(true)`,
          [selected.participantId, selected.privacyDomainId, id()],
        );
        result = await run(c);
      } catch (error) {
        primary = { error };
      }
      let rollbackFailure: { error: unknown } | undefined;
      await closeFixtureResources(
        [
          async () => {
            try {
              await c.query('rollback');
            } catch (error) {
              rollbackFailure = { error };
              throw error;
            }
          },
          async () => {
            c.release(
              rollbackFailure
                ? new Error('Isolated source check rollback failed', {
                    cause: rollbackFailure.error,
                  })
                : undefined,
            );
          },
        ],
        primary,
      );
      if (primary) throw primary.error;
      return result;
    }
    const authenticated = (selected = scope, generation = input.generationId) =>
      scoped(
        selected,
        async (c) =>
          (
            await c.query(
              'select openpc.operations_generation_source_authenticated($1,$2) result',
              [input.environmentId, generation],
            )
          ).rows[0].result,
      );
    try {
      // Bootstrap only a restricted installation login in this isolated database.
      // Its generated password is durable before any role or installation is admitted.
      await admin.query(
        `create role ${roleName} login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '${new URL(installerUrl).password}'`,
      );
      await admin.query(`grant openpc_control_owner to ${roleName}`);
      await admin.query(`grant connect on database openpc_control to ${roleName}`);
      const role = await installer.query(
        'select current_user name,rolsuper,rolbypassrls,rolinherit from pg_roles where rolname=current_user',
      );
      expect(role.rows[0]).toMatchObject({
        rolsuper: false,
        rolbypassrls: false,
        rolinherit: false,
      });
      expect(role.rows[0].name).toBe(new URL(installerUrl!).username);
      for (const value of [scope, foreign]) {
        await admin.query(
          "insert into control.participant(participant_id,display_name,state,authority_epoch)values($1,'Public installation source test','ACTIVE',1)",
          [value.participantId],
        );
        await admin.query(
          "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)values($1,$2,'Public installation source','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
          [value.privacyDomainId, value.participantId],
        );
      }
      const installation = {
        pins: input.pins,
        initialBaseGenerationId: input.baseGenerationId,
        schemaBytes: input.sources.schemaBytes,
        profileBytes: input.sources.profileBytes,
        sourceAuthentication: authentication.custody,
      };
      for (const sourceAuthentication of [
        null,
        { verified: true },
        { ...authentication.custody, version: 1 },
        { ...authentication.custody, sourceProfile: 'UNKNOWN' },
        { ...authentication.custody, inventoryHex: '00' },
      ]) {
        await expect(
          installInitialOperationsEnvironment(installer, scope, {
            ...installation,
            sourceAuthentication,
          } as typeof installation),
        ).rejects.toThrow('C17_SOURCE_AUTHENTICATION_FAILED');
        expect(
          (
            await admin.query(
              'select count(*)::int count from control.operations_installation where environment_id=$1',
              [input.environmentId],
            )
          ).rows[0].count,
        ).toBe(0);
      }
      const digest = await installInitialOperationsEnvironment(installer, scope, installation);
      expect(await installInitialOperationsEnvironment(installer, scope, installation)).toBe(
        digest,
      );
      const broken = Buffer.from(input.signed.cose);
      broken[broken.length - 1]! ^= 1;
      await expect(
        stageInitialOperationsGeneration(installer, scope, input.sources, {
          ...input.signed,
          cose: broken,
        }),
      ).rejects.toThrow();
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.operations_generation where environment_id=$1',
            [input.environmentId],
          )
        ).rows[0].count,
      ).toBe(0);
      const staged = await stageInitialOperationsGeneration(
        installer,
        scope,
        input.sources,
        input.signed,
      );
      expect(staged.state).toBe('STAGED');
      expect(staged.effective).toBe(false);
      expect(staged.missingBindings).not.toContain('SOURCE:C17_AUTHENTICATION');
      expect(staged.missingBindings.some((value) => value.startsWith('QUALIFICATION:'))).toBe(true);
      expect(await authenticated()).toBe(true);
      expect(await authenticated(foreign)).toBe(false);
      expect(await authenticated(scope, id())).toBe(false);
      await scoped(scope, async (client) => {
        const stored = (
          await client.query(
            'select installation from control.operations_installation where environment_id=$1',
            [input.environmentId],
          )
        ).rows[0].installation;
        for (const change of [
          {
            ...stored,
            sourceAuthentication: { ...stored.sourceAuthentication, sourceProfile: 'UNKNOWN' },
          },
          { ...stored, sourceAuthentication: { ...stored.sourceAuthentication, version: 1 } },
          {
            ...stored,
            sourceAuthentication: { ...stored.sourceAuthentication, inventoryHex: '00' },
          },
          {
            ...stored,
            sourceAuthentication: { ...stored.sourceAuthentication, receiptId: 'mixed' },
          },
          { ...stored, pins: { ...stored.pins, profile: 'production' } },
          { ...stored, schema: {} },
          { ...stored, namedProfile: {} },
        ])
          expect(
            (
              await client.query(
                'select openpc.operations_source_authentication_valid($1::jsonb) result',
                [JSON.stringify(change)],
              )
            ).rows[0].result,
          ).toBe(false);
      });
      const before = (
        await admin.query(
          `select encode(installation_bytes,'hex') bytes,installation_digest from control.operations_installation where environment_id=$1`,
          [input.environmentId],
        )
      ).rows[0];
      await end(installer);
      installer = new Pool({ connectionString: installerUrl, max: 1 });
      expect(await authenticated()).toBe(true);
      expect(
        (await readOperationsGeneration(installer, scope, input.environmentId, input.generationId))
          .state,
      ).toBe('STAGED');
      expect(
        (
          await admin.query(
            `select encode(installation_bytes,'hex') bytes,installation_digest from control.operations_installation where environment_id=$1`,
            [input.environmentId],
          )
        ).rows[0],
      ).toEqual(before);
      await writeFile(
        join(directory, 'bindings.private.json'),
        JSON.stringify({
          scope,
          foreign,
          environmentId: input.environmentId,
          generationId: input.generationId,
          installationDigest: digest,
          installerRole: role.rows[0].name,
        }),
        { mode: 0o600, flag: 'wx' },
      );
    } catch (error) {
      failure = { error };
      throw error;
    } finally {
      await closeFixtureResources([() => end(installer), () => end(admin)], failure);
    }
  },
  60000,
);
