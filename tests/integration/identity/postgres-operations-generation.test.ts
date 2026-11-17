import {
  installProviderRetryQualificationRoot,
  withCurrentProviderRetryQualification,
} from '../../../services/control-api/src/configuration/operations/provider-retry-qualification.js';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync } from 'node:crypto';
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
import {
  installInitialOperationsEnvironment,
  stageInitialOperationsGeneration,
  commitOperationsGeneration,
  commitOperationsGenerationInTransaction,
  readOperationsGeneration,
} from '../../../scripts/operations/installation-generation-store.mjs';
import { prepareSignedInstallationCandidate } from '../../../scripts/operations/installation-config-signature.mjs';
import { authenticateOperationsSources } from '../../../scripts/operations/installation-source-authentication.mjs';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;

// Keep SQL numeric scales and Unicode intact through the source verifier.
const operationsSourceValueCorpusSql = String.raw`
WITH seed AS MATERIALIZED (
 SELECT installation AS input FROM control.operations_installation WHERE environment_id=$1
), fields(field) AS (
 SELECT unnest(ARRAY['inventoryHex','schemaHex','profileHex'])
), bad(label,value) AS (
 VALUES ('uppercase','A'),('space',' '),('tab',chr(9)),('lf',chr(10)),('cr',chr(13)),
 ('crlf',chr(13)||chr(10)),('vtab',chr(11)),('formfeed',chr(12)),('del',chr(127)),
 ('fullwidth','Ａ'),('cjk','中'),('emoji','😀'),('combining','a'||chr(769)),
 ('invalid','g'),('punctuation','-')
), corpus(label,input,expected) AS (
 SELECT 'authentic',input,true FROM seed
 UNION ALL VALUES ('sql_null',NULL,false),('json_null','null'::jsonb,false),
 ('array','[]'::jsonb,false),('boolean','true'::jsonb,false),('number','1'::jsonb,false),
 ('string','"text"'::jsonb,false),('empty_object','{}'::jsonb,false)
 UNION ALL
 SELECT field||':'||bad.label||':'||position.label,
  jsonb_set(seed.input,ARRAY['sourceAuthentication',field],
   to_jsonb(overlay(seed.input#>>ARRAY['sourceAuthentication',field]
    placing bad.value FROM position.start_at FOR char_length(bad.value)))),false
 FROM seed CROSS JOIN fields CROSS JOIN bad
 CROSS JOIN LATERAL (VALUES ('first',1),
  ('middle',greatest(1,length(seed.input#>>ARRAY['sourceAuthentication',field])/2)),
  ('last',length(seed.input#>>ARRAY['sourceAuthentication',field])-char_length(bad.value)+1)
 )position(label,start_at)
 UNION ALL
 SELECT field||':length:'||variant.label,
  jsonb_set(seed.input,ARRAY['sourceAuthentication',field],variant.value),false
 FROM seed CROSS JOIN fields CROSS JOIN LATERAL (VALUES
  ('empty','""'::jsonb),
  ('short',to_jsonb(left(seed.input#>>ARRAY['sourceAuthentication',field],
   length(seed.input#>>ARRAY['sourceAuthentication',field])-1))),
  ('long',to_jsonb((seed.input#>>ARRAY['sourceAuthentication',field])||'0')),
  ('null','null'::jsonb),('number','12'::jsonb),('array','[]'::jsonb)
 )variant(label,value)
 UNION ALL
 SELECT field||':missing',seed.input#-ARRAY['sourceAuthentication',field],false
 FROM seed CROSS JOIN fields
 UNION ALL
 SELECT field||':changed_lowercase',jsonb_set(seed.input,ARRAY['sourceAuthentication',field],
  to_jsonb((CASE left(seed.input#>>ARRAY['sourceAuthentication',field],1)
   WHEN '0' THEN '1' ELSE '0' END)||substr(seed.input#>>ARRAY['sourceAuthentication',field],2))),false
 FROM seed CROSS JOIN fields
 UNION ALL SELECT 'unknown_profile',jsonb_set(input,'{pins,profile}','"unknown"'::jsonb),false FROM seed
 UNION ALL SELECT 'extra_custody_key',jsonb_set(input,'{sourceAuthentication,extra}','true'::jsonb),false FROM seed
 UNION ALL SELECT 'wrong_version',jsonb_set(input,'{sourceAuthentication,version}','1'::jsonb),false FROM seed
 UNION ALL SELECT 'changed_receipt',jsonb_set(input,'{sourceAuthentication,sourceProfile}','"untrusted"'::jsonb),false FROM seed
 UNION ALL SELECT 'changed_schema',jsonb_set(input,'{schema}','{}'::jsonb),false FROM seed
 UNION ALL SELECT 'changed_profile',jsonb_set(input,'{namedProfile}','{}'::jsonb),false FROM seed
 UNION ALL SELECT 'extra_root_large_number',jsonb_set(input,'{copyProbe}',
  '{"v":9007199254740993}'::jsonb),true FROM seed
 UNION ALL SELECT 'extra_root_scaled_number',jsonb_set(input,'{copyProbe}',
  '{"v":1.00000000000000000001}'::jsonb),true FROM seed
 UNION ALL SELECT 'extra_root_unicode',jsonb_set(input,'{copyProbe}',
  jsonb_build_object('v','中😀é'||'e'||chr(769))),true FROM seed
 UNION ALL SELECT 'extra_root_control_chars',jsonb_set(input,'{copyProbe}',
  jsonb_build_object('v',chr(9)||chr(10)||chr(13))),true FROM seed
), prepared AS MATERIALIZED (
 SELECT *,jsonb_send(input) AS bytes,input::text AS encoded FROM corpus
), verified AS MATERIALIZED (
 SELECT *,openpc.operations_source_authentication_valid(input) AS actual FROM prepared
)
SELECT current_user AS caller,count(*)::integer AS cases,
 coalesce(jsonb_agg(label ORDER BY label) FILTER (WHERE actual IS DISTINCT FROM expected),'[]'::jsonb) AS mismatches,
 bool_and(CASE WHEN jsonb_typeof(input)='object' THEN
  jsonb_send(input#>'{}'::text[]) IS NOT DISTINCT FROM bytes
  AND (input#>'{}'::text[])::text IS NOT DISTINCT FROM encoded
  ELSE true END) AS root_identity_preserved,
 bool_and(jsonb_send(input) IS NOT DISTINCT FROM bytes
  AND input::text IS NOT DISTINCT FROM encoded) AS input_unchanged
FROM verified;
`;

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
it('validates actual signed operations generation inputs before PostgreSQL allocation', async () => {
  const input = await fixture();
  const { issuerSpkiHex, ...pins } = input.pins;
  const candidate = prepareSignedInstallationCandidate(
    input.sources,
    { ...pins, issuerSpki: Buffer.from(issuerSpkiHex, 'hex') },
    input.signed,
    Date.now(),
  );
  expect(candidate.startupAllowed).toBe(false);
  expect(candidate.blockers).toContain('QUALIFICATION_VERIFICATION_UNBOUND');
  expect(candidate.blockers).toContain('SECRET_PROVIDER_RESOLUTION_UNBOUND');
  expect(candidate.blockers).toContain('ENTRYPOINT_CONSUMER_BINDING_UNBOUND');
});
async function context(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  role = 'openpc_control_owner',
) {
  if (
    ![
      'openpc_control_owner',
      'openpc_control_runtime',
      'openpc_operations_qualification_owner',
      'openpc_operations_qualification_bootstrap',
    ].includes(role)
  )
    throw new Error('Invalid fixture role');
  await client.query('begin');
  await client.query(`set local role ${role}`);
  await client.query(
    `select set_config('openpc.context_mode','PARTICIPANT',true),set_config('openpc.context_scope','TRANSACTION_LOCAL',true),
    set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true),set_config('openpc.operation_id',$3,true),
    set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)`,
    [scope.participantId, scope.privacyDomainId, id()],
  );
}
integration(
  'keeps real signed operations candidates immutable and ineffective without independent bindings',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 }),
      runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const scope = { participantId: id(), privacyDomainId: id() },
      input = await fixture();
    try {
      // Initial installation/tenant trust only. No effective generation, proof,
      // consumer observation or accepted business state is seeded.
      await admin.query(
        `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Operations generation initial trust','ACTIVE',1)`,
        [scope.participantId],
      );
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Operations installation','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [scope.privacyDomainId, scope.participantId],
      );
      const installation = {
        pins: input.pins,
        initialBaseGenerationId: input.baseGenerationId,
        schemaBytes: input.sources.schemaBytes,
        profileBytes: input.sources.profileBytes,
      };
      const first = await installInitialOperationsEnvironment(admin, scope, installation);
      expect(await installInitialOperationsEnvironment(admin, scope, installation)).toBe(first);
      await expect(
        installInitialOperationsEnvironment(admin, scope, {
          ...installation,
          pins: { ...input.pins, issuerEpoch: '2' },
        }),
      ).rejects.toThrow('INSTALLATION_IMMUTABLE');
      const staged = await stageInitialOperationsGeneration(
        admin,
        scope,
        input.sources,
        input.signed,
      );
      expect(staged.effective).toBe(false);
      expect(staged.missingBindings).toContain('SOURCE:C17_AUTHENTICATION');
      expect(staged.missingBindings).toContain('CONSUMER_EFFECTIVE:LS-NOTIFICATION');
      expect(staged.missingBindings).toContain('CONSUMER_STAGED:LS-NOTIFICATION');
      expect(staged.missingBindings.filter((v) => v.startsWith('QUALIFICATION:'))).toHaveLength(10);
      expect(staged.missingBindings).toContain('QUALIFICATION:provider.read_retry_limit');
      expect(staged.missingBindings.filter((v) => v.startsWith('UNIT_EFFECTIVE:'))).toHaveLength(8);
      expect(
        staged.missingBindings.filter((v) => v.startsWith('SECRET:')).length,
      ).toBeGreaterThanOrEqual(6);
      expect(
        await stageInitialOperationsGeneration(admin, scope, input.sources, input.signed),
      ).toEqual(staged);
      await expect(
        commitOperationsGeneration(admin, scope, input.environmentId, input.generationId),
      ).rejects.toThrow('GENERATION_BINDINGS_UNAVAILABLE');
      // The observer seam must reuse the same scoped connection, preserve the
      // caller transaction and retain missing-evidence and context denials.
      const observed = await admin.connect();
      try {
        await context(observed, scope);
        expect(
          (
            await observed.query<{ volatility: string }>(
              "select provolatile::text volatility from pg_proc where oid='openpc.operations_generation_missing(text,uuid)'::regprocedure",
            )
          ).rows[0]?.volatility,
        ).toBe('v');
        // No admission row is not a qualified zero-retry value. The real
        // predicate leaves exactly the original complete missing vector intact.
        expect(
          (
            await observed.query<{ bound: boolean }>(
              'select openpc.operations_provider_retry_qualification_bound($1,$2) bound',
              [input.environmentId, input.generationId],
            )
          ).rows[0]?.bound,
        ).toBe(false);
        expect(
          (
            await observed.query<{ missing: string[] }>(
              'select openpc.operations_generation_missing($1,$2) missing',
              [input.environmentId, input.generationId],
            )
          ).rows[0]?.missing,
        ).toEqual(staged.missingBindings);
        await observed.query(
          "select set_config('openpc.test_generation_transaction','retained',true)",
        );
        const before = (await observed.query('select txid_current()::text id')).rows[0].id;
        const request = (
          await observed.query<{ request: string }>(
            "select current_setting('openpc.operation_id') request",
          )
        ).rows[0]!.request;
        let consumed = false;
        for (const requestId of [id(), request]) {
          await expect(
            withCurrentProviderRetryQualification(
              observed,
              { ...scope, requestId },
              input.environmentId,
              input.generationId,
              async () => {
                consumed = true;
              },
            ),
          ).rejects.toThrow('UNQUALIFIED');
        }
        expect(consumed).toBe(false);
        expect((await observed.query('select txid_current()::text id')).rows[0].id).toBe(before);
        await expect(
          commitOperationsGenerationInTransaction(
            observed,
            { ...scope, privacyDomainId: id() },
            input.environmentId,
            input.generationId,
          ),
        ).rejects.toThrow('GENERATION_TRANSACTION_CONTEXT');
        await expect(
          commitOperationsGenerationInTransaction(
            observed,
            scope,
            input.environmentId,
            input.generationId,
          ),
        ).rejects.toThrow('GENERATION_BINDINGS_UNAVAILABLE');
        expect((await observed.query('select txid_current()::text id')).rows[0].id).toBe(before);
        expect(
          (
            await observed.query(
              "select current_setting('openpc.test_generation_transaction') marker",
            )
          ).rows[0].marker,
        ).toBe('retained');
        await observed.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        await expect(
          commitOperationsGenerationInTransaction(
            observed,
            scope,
            input.environmentId,
            input.generationId,
          ),
        ).rejects.toThrow('GENERATION_TRANSACTION_CONTEXT');
      } finally {
        await observed.query('rollback');
        observed.release();
      }
      const unprivileged = await runtime.connect();
      try {
        await context(unprivileged, scope, 'openpc_control_runtime');
        await expect(
          commitOperationsGenerationInTransaction(
            unprivileged,
            scope,
            input.environmentId,
            input.generationId,
          ),
        ).rejects.toThrow('GENERATION_TRANSACTION_CONTEXT');
        expect((await unprivileged.query('select 1 as alive')).rows[0].alive).toBe(1);
      } finally {
        await unprivileged.query('rollback');
        unprivileged.release();
      }
      const status = await readOperationsGeneration(
        admin,
        scope,
        input.environmentId,
        input.generationId,
      );
      expect(status.effective_digest).toBeNull();
      expect(status.missing).toEqual(staged.missingBindings);
      expect(JSON.stringify(status)).not.toMatch(/secret:\/\/|siteHex|coseHex|synthetic-client/u);
      await expect(
        readOperationsGeneration(
          admin,
          { ...scope, privacyDomainId: id() },
          input.environmentId,
          input.generationId,
        ),
      ).rejects.toThrow('GENERATION_UNAVAILABLE');
      const denied = async (
        sql: string,
        values: unknown[],
        expected: string,
        role = 'openpc_control_owner',
      ) => {
        const client = await (role === 'openpc_control_runtime' ? runtime : admin).connect();
        try {
          await context(client, scope, role);
          await expect(client.query(sql, values)).rejects.toThrow(expected);
        } finally {
          await client.query('rollback');
          client.release();
        }
      };
      await denied(
        `insert into control.operations_generation_commit(participant_id,privacy_domain_id,environment_id,generation_id,sequence,effective_digest) values($1,$2,$3,$4,1,$5)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          input.environmentId,
          input.generationId,
          input.sources.site.generation.contentDigest,
        ],
        'OPS_CONFIG_BINDINGS_UNAVAILABLE',
      );
      await denied(
        `insert into control.operations_generation_binding(participant_id,privacy_domain_id,environment_id,generation_id,requirement_id,source_digest,effective_digest,valid_until_ms,state) values($1,$2,$3,$4,$5,$6,$6,9007199254740991,'CURRENT')`,
        [
          scope.participantId,
          scope.privacyDomainId,
          input.environmentId,
          input.generationId,
          staged.missingBindings[0],
          input.sources.site.generation.contentDigest,
        ],
        'permission denied',
      );
      await denied(
        `update control.operations_generation set requirements='[]'::jsonb where environment_id=$1`,
        [input.environmentId],
        'OPS_CONFIG_IMMUTABLE',
      );
      await denied(
        `select * from openpc.current_notification_delivery_limit($1)`,
        [input.environmentId],
        'OPS_CONFIG_UNREADY',
        'openpc_control_runtime',
      );
      await denied(
        `select * from control.operations_generation where environment_id=$1`,
        [input.environmentId],
        'permission denied',
        'openpc_control_runtime',
      );
      const held = await admin.connect();
      try {
        await context(held, scope);
        expect(
          (
            await held.query('select openpc.operations_generation_missing($1,$2) missing', [
              input.environmentId,
              id(),
            ])
          ).rows[0].missing,
        ).toEqual(['GENERATION:MISSING']);
        await held.query(
          `select pg_advisory_xact_lock(hashtextextended('operations-generation:'||$1,0))`,
          [input.environmentId],
        );
        await expect(
          stageInitialOperationsGeneration(admin, scope, input.sources, input.signed),
        ).rejects.toThrow('GENERATION_BUSY');
      } finally {
        await held.query('rollback');
        held.release();
      }
      const reopened = new Pool({ connectionString: adminUrl, max: 1 });
      try {
        expect(
          await readOperationsGeneration(reopened, scope, input.environmentId, input.generationId),
        ).toEqual(status);
      } finally {
        await reopened.end();
      }
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.operations_generation_commit where environment_id=$1',
            [input.environmentId],
          )
        ).rows[0].n,
      ).toBe(0);
      const fence = await admin.connect();
      try {
        await context(fence, scope);
        await fence.query(
          "update control.operations_generation set state='FENCED' where environment_id=$1 and generation_id=$2",
          [input.environmentId, input.generationId],
        );
        await fence.query('commit');
      } finally {
        await fence.query('rollback');
        fence.release();
      }
      await expect(
        stageInitialOperationsGeneration(admin, scope, input.sources, input.signed),
      ).rejects.toThrow('GENERATION_FENCED');
      await expect(
        commitOperationsGeneration(admin, scope, input.environmentId, input.generationId),
      ).rejects.toThrow('GENERATION_UNAVAILABLE');
      expect(
        await readOperationsGeneration(admin, scope, input.environmentId, input.generationId),
      ).toMatchObject({ state: 'FENCED', effective_digest: null });
    } finally {
      await runtime.end();
      await admin.end();
    }
  },
  30000,
);

integration(
  'authenticates public generation sources, preserves other blockers and rejects tampering across reconnect',
  async () => {
    const input = await fixture();
    const inventoryBytes = await readFile(
      'config/source-authentication/public-operations-source-v1.json',
    );
    const authentication = authenticateOperationsSources({
      sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
      inventoryBytes,
      schemaBytes: input.sources.schemaBytes,
      profileBytes: input.sources.profileBytes,
      profile: 'local',
    });
    const scope = { participantId: id(), privacyDomainId: id() },
      foreign = { participantId: id(), privacyDomainId: id() };
    const admin = new Pool({ connectionString: adminUrl, max: 2 }),
      reopened = new Pool({ connectionString: adminUrl, max: 1 });
    let primary: unknown;
    let failed = false;
    async function scoped<T>(
      pool: Pool,
      selected: typeof scope,
      run: (client: PoolClient) => Promise<T>,
      commit = false,
    ) {
      const client = await pool.connect();
      let original: unknown,
        rejected = false;
      let result!: T;
      try {
        await context(client, selected);
        result = await run(client);
        if (commit) await client.query('commit');
      } catch (error) {
        original = error;
        rejected = true;
      }
      const cleanupFailure = (error: unknown) => {
        process.stderr.write('OPS_SOURCE_TEST_CLEANUP|UNKNOWN\n');
        if (!rejected) original = error;
        rejected = true;
      };
      await client.query('rollback').catch(cleanupFailure);
      try {
        client.release();
      } catch (error) {
        cleanupFailure(error);
      }
      if (rejected) throw original;
      return result;
    }
    const current = (pool = admin, selected = scope, generation = input.generationId) =>
      scoped(
        pool,
        selected,
        async (client) =>
          (
            await client.query(
              'select openpc.operations_generation_source_authenticated($1,$2) authenticated',
              [input.environmentId, generation],
            )
          ).rows[0].authenticated,
      );
    try {
      for (const selected of [scope, foreign]) {
        await admin.query(
          "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Operations source trust','ACTIVE',1)",
          [selected.participantId],
        );
        await admin.query(
          "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Operations source','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
          [selected.privacyDomainId, selected.participantId],
        );
      }
      // Canonical splice: the existing installation owner retains this PRIVATE
      // closed custody, validates it, and permits no subsequent source rewrite.
      // An old owner ignoring the field makes this test FAIL, never a fake pass.
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
        { ...authentication.custody, inventoryHex: '00' },
      ]) {
        await expect(
          installInitialOperationsEnvironment(admin, scope, {
            ...installation,
            sourceAuthentication,
          } as typeof installation),
        ).rejects.toThrow('C17_SOURCE_AUTHENTICATION_FAILED');
      }
      await installInitialOperationsEnvironment(admin, scope, installation);
      const staged = await stageInitialOperationsGeneration(
        admin,
        scope,
        input.sources,
        input.signed,
      );
      expect(staged.missingBindings).not.toContain('SOURCE:C17_AUTHENTICATION');
      expect(staged.missingBindings).toContain('CONSUMER_EFFECTIVE:LS-NOTIFICATION');
      expect(staged.missingBindings).toContain('CONSUMER_STAGED:LS-NOTIFICATION');
      expect(staged.missingBindings.filter((r) => r.startsWith('QUALIFICATION:'))).toHaveLength(10);
      expect(staged.missingBindings.filter((r) => r.startsWith('UNIT_EFFECTIVE:'))).toHaveLength(8);
      expect(
        staged.missingBindings.filter((r) => r.startsWith('SECRET:')).length,
      ).toBeGreaterThanOrEqual(6);
      expect(await current()).toBe(true);
      expect(await current(admin, foreign)).toBe(false);
      expect(await current(admin, scope, id())).toBe(false);
      await scoped(admin, scope, async (client) => {
        const stored = (
          await client.query(
            'select installation from control.operations_installation where environment_id=$1',
            [input.environmentId],
          )
        ).rows[0].installation;
        const valueCorpus = (
          await client.query(operationsSourceValueCorpusSql, [input.environmentId])
        ).rows[0];
        expect(valueCorpus).toEqual({
          caller: 'openpc_control_owner',
          cases: 177,
          mismatches: [],
          root_identity_preserved: true,
          input_unchanged: true,
        });
        for (const profile of ['local', 'development', 'test', 'staging', 'production'] as const) {
          const profileBytes = await readFile(`config/profiles/${profile}.yaml`);
          const actual = authenticateOperationsSources({
            sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
            inventoryBytes,
            schemaBytes: input.sources.schemaBytes,
            profileBytes,
            profile,
          });
          // Exact source-data check only; this does not install or admit a
          // candidate for another profile or claim a complete generation.
          expect(
            (
              await client.query(
                'select openpc.operations_source_authentication_valid($1::jsonb) authenticated',
                [
                  JSON.stringify({
                    ...stored,
                    pins: {
                      ...stored.pins,
                      profile,
                      namedProfileDigest: actual.identity.namedProfileDigest,
                    },
                    namedProfile: parseNamedProfile(profileBytes),
                    sourceAuthentication: actual.custody,
                  }),
                ],
              )
            ).rows[0].authenticated,
          ).toBe(true);
        }
        const changedSchema = structuredClone(stored);
        changedSchema.schema.properties.settings.properties[
          'security.audit_reason_required'
        ].default = false;
        const changedProfile = structuredClone(stored);
        changedProfile.namedProfile.immutableAfterStart = false;
        const changedCustody = structuredClone(stored);
        changedCustody.sourceAuthentication.sourceProfile = 'UNTRUSTED';
        const forged = structuredClone(stored);
        forged.sourceAuthentication.inventoryHex = Buffer.from('{"files":[]}').toString('hex');
        for (const changed of [
          changedSchema,
          changedProfile,
          changedCustody,
          forged,
          { ...stored, pins: { ...stored.pins, profile: 'test' } },
          { ...stored, sourceAuthentication: { verified: true } },
          { ...stored, sourceAuthentication: null },
        ])
          expect(
            (
              await client.query(
                'select openpc.operations_source_authentication_valid($1::jsonb) authenticated',
                [JSON.stringify(changed)],
              )
            ).rows[0].authenticated,
          ).toBe(false);
        const transaction = (await client.query('select txid_current()::text id')).rows[0].id;
        await expect(
          commitOperationsGenerationInTransaction(
            client,
            scope,
            input.environmentId,
            input.generationId,
          ),
        ).rejects.toThrow('GENERATION_BINDINGS_UNAVAILABLE');
        expect((await client.query('select txid_current()::text id')).rows[0].id).toBe(transaction);
        expect(
          (
            await client.query(
              'select 1 from control.operations_generation_commit where environment_id=$1',
              [input.environmentId],
            )
          ).rowCount,
        ).toBe(0);
      });
      await expect(
        scoped(admin, scope, async (client) => {
          await client.query(
            `insert into control.operations_generation_binding(participant_id,privacy_domain_id,environment_id,generation_id,requirement_id,source_digest,effective_digest,valid_until_ms,state)
          values($1,$2,$3,$4,'SOURCE:C17_AUTHENTICATION',$5,$5,9007199254740991,'CURRENT')`,
            [
              scope.participantId,
              scope.privacyDomainId,
              input.environmentId,
              input.generationId,
              input.sources.site.generation.contentDigest,
            ],
          );
        }),
      ).rejects.toThrow('permission denied');
      await expect(
        scoped(admin, scope, async (client) => {
          await client.query('set local role openpc_control_runtime');
          await client.query('select openpc.operations_generation_source_authenticated($1,$2)', [
            input.environmentId,
            input.generationId,
          ]);
        }),
      ).rejects.toThrow('permission denied');
      await scoped(admin, scope, async (client) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        // Data provenance does not disappear under another read owner's
        // action, and it cannot authorize that action to commit a generation.
        expect(
          (
            await client.query(
              'select openpc.operations_generation_source_authenticated($1,$2) authenticated',
              [input.environmentId, input.generationId],
            )
          ).rows[0].authenticated,
        ).toBe(true);
        await expect(
          commitOperationsGenerationInTransaction(
            client,
            scope,
            input.environmentId,
            input.generationId,
          ),
        ).rejects.toThrow('GENERATION_TRANSACTION_CONTEXT');
      });
      expect(await current(reopened)).toBe(true);
      const status = await readOperationsGeneration(
        reopened,
        scope,
        input.environmentId,
        input.generationId,
      );
      expect(status.missing).toEqual(staged.missingBindings);
      expect(status.effective_digest).toBeNull();
      expect(JSON.stringify(status)).not.toMatch(
        /manifestHex|schemaHex|profileHex|sourceAuthentication/u,
      );
      await scoped(
        admin,
        scope,
        async (client) => {
          await client.query(
            "update control.operations_generation set state='FENCED' where environment_id=$1 and generation_id=$2",
            [input.environmentId, input.generationId],
          );
        },
        true,
      );
      expect(await current(reopened)).toBe(false);
      // Reuse the same authentic source for a fresh initial generation, not a
      // resurrected fenced candidate or a fabricated effective business state.
      const second = await fixture();
      await installInitialOperationsEnvironment(admin, scope, {
        ...installation,
        pins: second.pins,
        initialBaseGenerationId: second.baseGenerationId,
      });
      await stageInitialOperationsGeneration(admin, scope, second.sources, second.signed);
      await scoped(
        admin,
        scope,
        async (client) => {
          expect(
            (
              await client.query(
                'select openpc.operations_generation_source_authenticated($1,$2) authenticated',
                [second.environmentId, second.generationId],
              )
            ).rows[0].authenticated,
          ).toBe(true);
          await client.query(
            "update control.operations_installation set state='REVOKED' where environment_id=$1",
            [second.environmentId],
          );
        },
        true,
      );
      await scoped(reopened, scope, async (client) => {
        expect(
          (
            await client.query(
              'select openpc.operations_generation_source_authenticated($1,$2) authenticated',
              [second.environmentId, second.generationId],
            )
          ).rows[0].authenticated,
        ).toBe(false);
      });
    } catch (error) {
      failed = true;
      primary = error;
    } finally {
      const results = await Promise.allSettled([admin.end(), reopened.end()]);
      if (results.some((r) => r.status === 'rejected')) {
        process.stderr.write('OPS_SOURCE_TEST_CLEANUP|UNKNOWN\n');
        if (!failed) {
          failed = true;
          primary = new Error('OPS_SOURCE_TEST_CLEANUP_UNKNOWN');
        }
      }
    }
    if (failed) throw primary;
  },
  30000,
);

integration(
  'qualification bootstrap roles remain separated and executed-evidence authority stays unbound',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const scope = { participantId: id(), privacyDomainId: id(), requestId: id() };
    const input = await fixture();
    try {
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Qualification initial trust','ACTIVE',1)",
        [scope.participantId],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Qualification initial trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [scope.privacyDomainId, scope.participantId],
      );
      await installInitialOperationsEnvironment(
        admin,
        { participantId: scope.participantId, privacyDomainId: scope.privacyDomainId },
        {
          pins: input.pins,
          initialBaseGenerationId: input.baseGenerationId,
          schemaBytes: input.sources.schemaBytes,
          profileBytes: input.sources.profileBytes,
        },
      );
      const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
        type: 'spki',
        format: 'der',
      });
      const root = {
        authorityId: 'local-root',
        rootEpoch: '1',
        rootKeyId: evidenceKeyId(spki),
        rootSpki: spki,
        policySigner: 'OFFLINE_TRUST_ROOT' as const,
        validFromMs: Date.now() - 1000,
        validUntilMs: Date.now() + 60000,
      };
      // Initial public root trust is allowed here; no qualification, executed
      // receipt or successful generation is seeded or manufactured.
      await installProviderRetryQualificationRoot(admin, scope, input.pins.environmentId, root);
      await installProviderRetryQualificationRoot(admin, scope, input.pins.environmentId, root);
      const client = await admin.connect();
      try {
        for (const role of [
          'openpc_operations_qualification_owner',
          'openpc_operations_qualification_bootstrap',
        ]) {
          await context(client, scope, role);
          const flags = (
            await client.query(
              `select rolcanlogin,rolinherit,rolsuper,rolbypassrls,rolcreaterole from pg_roles where rolname=current_user`,
            )
          ).rows[0];
          expect(flags).toEqual({
            rolcanlogin: false,
            rolinherit: false,
            rolsuper: false,
            rolbypassrls: false,
            rolcreaterole: false,
          });
          const other = role.endsWith('_owner')
            ? 'openpc_operations_qualification_bootstrap'
            : 'openpc_operations_qualification_owner';
          expect(
            (await client.query("select pg_has_role(current_user,$1,'MEMBER') member", [other]))
              .rows[0].member,
          ).toBe(false);
          expect(
            (
              await client.query(
                'select environment_id from control.operations_installation where environment_id=$1 for share',
                [input.pins.environmentId],
              )
            ).rowCount,
          ).toBe(1);
          await client.query('savepoint forbidden');
          await expect(
            client.query(
              "update control.operations_installation set state='ACTIVE' where environment_id=$1",
              [input.pins.environmentId],
            ),
          ).rejects.toThrow();
          await client.query('rollback to savepoint forbidden');
          if (role.endsWith('_owner')) {
            await expect(
              client.query(
                "update control.operations_qualification_root set state='REVOKED' where environment_id=$1",
                [input.pins.environmentId],
              ),
            ).rejects.toThrow();
          }
          await client.query('rollback');
        }
        await context(client, scope, 'openpc_operations_qualification_owner');
        await expect(
          client.query('select openpc.require_provider_retry_evidence($1,$2,$3,$4)', [
            input.pins.environmentId,
            input.generationId,
            sha256('input'),
            sha256('receipt'),
          ]),
        ).rejects.toThrow('OPS_PROVIDER_RETRY_EVIDENCE_OWNER_UNBOUND');
        await client.query('rollback');
        for (const role of [
          'openpc_control_runtime',
          'openpc_control_worker',
          'openpc_control_owner',
        ]) {
          expect(
            (
              await client.query(
                "select pg_has_role($1,'openpc_operations_qualification_owner','MEMBER') ordinary,pg_has_role($1,'openpc_operations_qualification_bootstrap','MEMBER') bootstrap",
                [role],
              )
            ).rows[0],
          ).toEqual({ ordinary: false, bootstrap: false });
        }
      } finally {
        await client.query('rollback');
        client.release(true);
      }
    } finally {
      await admin.end();
    }
  },
);
