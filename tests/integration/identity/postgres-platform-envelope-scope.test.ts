import { execFile } from 'node:child_process';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import {
  decodeCbor,
  encodeCbor,
  type CborValue,
} from '../../../packages/security-kernel/src/canonical-cbor.js';
import { envelopeFixtureScope } from '../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  encodeEnvelopeScope,
  platformEnvelopeScopeDigest,
  platformEnvelopeScopePreimage,
  type PlatformEnvelopeScopeAdmission,
} from '../../../packages/security-kernel/src/index.js';
import { installInitialPlatformEnvelopeScope } from '../../../scripts/operations/installation-platform-authority.mjs';
import {
  installInitialOperationsEnvironment,
  withInstallationTransaction,
} from '../../../scripts/operations/installation-generation-store.mjs';
import { readPublicOperationsSources } from '../../../scripts/operations/read-public-installation-sources.mjs';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { fenceEnvelopePlatformScope } from '../../../services/identity-service/src/db/platform-envelope-scope.js';
import { runScopedTransaction } from '../../../services/identity-service/src/db/scoped-transaction.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL,
  runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const container = process.env.OPENPC_PLATFORM_SCOPE_CONTAINER;
const integration = adminUrl && runtimeUrl && container ? it : it.skip;
const execute = promisify(execFile);
const hash = (bytes: Buffer | string) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
async function initialInput(environmentId: string) {
  const schemaBytes = await readFile('config/schema/effective-configuration.schema.json'),
    profileBytes = await readFile('config/profiles/local.yaml');
  const sourceAuthentication = (
    await readPublicOperationsSources({
      sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
      profile: 'local',
    })
  ).custody;
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    schemaBytes,
    profileBytes,
    sourceAuthentication,
    initialBaseGenerationId: id(),
    pins: {
      issuerSpkiHex: key.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
      issuerEpoch: '1',
      issuerValidFromMs: Date.now() - 1000,
      issuerValidUntilMs: Date.now() + 300000,
      environmentId,
      profile: 'local',
      configurationSchemaDigest: hash(schemaBytes),
      namedProfileDigest: hash(profileBytes),
    },
  };
}
it('authenticates Platform installation sources before allocating PostgreSQL', async () => {
  expect((await initialInput('platform-scope-preflight')).sourceAuthentication.version).toBe(1);
});

integration(
  'admits immutable typed Platform bounds through the real installer and fences current custody',
  async () => {
    expect(container).toMatch(/^openpc-participant-readback-[0-9]+$/u);
    let admin = new Pool({ connectionString: adminUrl, max: 3 });
    const installerUrl = new URL(adminUrl!);
    installerUrl.username = 'openpc_scope_installer';
    installerUrl.password = randomBytes(24).toString('hex');
    let installer = new Pool({ connectionString: installerUrl.href, max: 2 });
    const actualRuntimeUrl = new URL(runtimeUrl!);
    actualRuntimeUrl.username = 'openpc_participant_runtime';
    let runtime = new Pool({ connectionString: actualRuntimeUrl.href, max: 2 });
    const closedPools = new Set<Pool>();
    const endPool = async (pool: Pool) => {
      if (!closedPools.has(pool)) {
        closedPools.add(pool);
        await pool.end();
      }
    };
    const scope = { participantId: id(), privacyDomainId: id() },
      foreign = { participantId: id(), privacyDomainId: id() };
    const environmentId = `platform-${id().slice(-12)}`;
    const input = await initialInput(environmentId);
    const platformContextId = id(),
      principalId = id(),
      selectedEnvelopeId = id(),
      legacyEnvelopeId = id(),
      legacyRoot = id();
    let admission: PlatformEnvelopeScopeAdmission;
    const scoped = <T>(work: (c: PoolClient) => Promise<T>, participantId = scope.participantId) =>
      runScopedTransaction(
        runtime,
        {
          participantId,
          privacyDomainId:
            participantId === scope.participantId ? scope.privacyDomainId : foreign.privacyDomainId,
          actionIntentId: 'ACT-PARTICIPANT_CREATE_CONTEXT-V1',
        },
        id,
        work,
      );
    const current = () =>
      scoped(async (c) => {
        await c.query('select 1 from control.participant where participant_id=$1 for share', [
          scope.participantId,
        ]);
        return fenceEnvelopePlatformScope(c, scope.participantId, selectedEnvelopeId);
      });
    const roots = async () =>
      Number(
        (
          await admin.query(
            'select count(*) from control.platform_context where owner_participant_id=$1',
            [scope.participantId],
          )
        ).rows[0].count,
      );
    async function rawAdmission(
      c: PoolClient,
      value: PlatformEnvelopeScopeAdmission,
      preimage = platformEnvelopeScopePreimage(value),
      bytes = encodeEnvelopeScope(value.grantable),
      createRoot = true,
    ) {
      if (createRoot)
        await c.query(
          `insert into control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version)
      values($1,$2,'ACTIVE',1,1)`,
          [value.platformContextId, value.ownerParticipantId],
        );
      return c.query(
        `insert into control.platform_envelope_scope(platform_context_id,owner_participant_id,installation_privacy_domain_id,
      platform_authority_epoch,environment_id,installation_digest,scope_cbor,admission_preimage,admission_digest)
      values($1,$2,$3,1,$4,$5,$6,$7,$8)`,
        [
          value.platformContextId,
          value.ownerParticipantId,
          value.installationPrivacyDomainId,
          value.environmentId,
          value.installationDigest,
          bytes,
          preimage,
          Buffer.from(hash(preimage).slice(7), 'hex'),
        ],
      );
    }
    try {
      await admin.query(
        `create role openpc_scope_installer login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '${installerUrl.password}'`,
      );
      await admin.query('grant openpc_control_owner to openpc_scope_installer');
      await admin.query('grant connect on database openpc_control to openpc_scope_installer');
      for (const tenant of [scope, foreign]) {
        await admin.query(
          `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Independent initial Platform trust','ACTIVE',1)`,
          [tenant.participantId],
        );
        await admin.query(
          `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
        values($1,$2,'Initial Platform installation','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
          [tenant.privacyDomainId, tenant.participantId],
        );
      }
      const installationDigest = await installInitialOperationsEnvironment(installer, scope, input);
      expect(
        (await admin.query("select to_regclass('control.platform_envelope_scope') name")).rows[0]
          .name,
      ).toBeNull();
      await admin.query(
        `insert into control.platform_context(platform_context_id,owner_participant_id,state,authority_epoch,row_version)
        values($1,$2,'ACTIVE',1,1)`,
        [legacyRoot, scope.participantId],
      );
      const originalRoot = await admin.query(
        'select * from control.platform_context where platform_context_id=$1',
        [legacyRoot],
      );
      const originalInstallation = await admin.query(
        'select installation_bytes,installation_digest from control.operations_installation where environment_id=$1',
        [environmentId],
      );
      await execute(
        'docker',
        [
          'exec',
          '-e',
          'PGHOST=127.0.0.1',
          '-e',
          'PGUSER=postgres',
          '-e',
          'PGDATABASE=openpc_control',
          container!,
          'sh',
          '/local/migrate.sh',
          'control',
        ],
        { timeout: 120000, maxBuffer: 1024 * 1024 },
      );
      expect(
        (
          await admin.query('select * from control.platform_context where platform_context_id=$1', [
            legacyRoot,
          ])
        ).rows,
      ).toEqual(originalRoot.rows);
      expect(
        (
          await admin.query(
            'select installation_bytes,installation_digest from control.operations_installation where environment_id=$1',
            [environmentId],
          )
        ).rows,
      ).toEqual(originalInstallation.rows);
      expect(
        (await admin.query('select count(*) from control.platform_envelope_scope')).rows[0].count,
      ).toBe('0');
      admission = {
        platformContextId,
        ownerParticipantId: scope.participantId,
        installationPrivacyDomainId: scope.privacyDomainId,
        platformAuthorityEpoch: '1',
        environmentId,
        installationDigest,
        grantable: envelopeFixtureScope(),
      };
      const admitted = await installInitialPlatformEnvelopeScope(installer, admission);
      expect(admitted).toEqual({
        platformContextId,
        platformAuthorityEpoch: '1',
        platformAuthorityDigest: platformEnvelopeScopeDigest(admission),
      });
      expect(await installInitialPlatformEnvelopeScope(installer, admission)).toEqual(admitted);
      const stored = await admin.query(
        `select admission_preimage,admission_digest,installed_by from control.platform_envelope_scope where platform_context_id=$1`,
        [platformContextId],
      );
      expect(stored.rows[0]).toEqual({
        admission_preimage: platformEnvelopeScopePreimage(admission),
        admission_digest: Buffer.from(admitted.platformAuthorityDigest.slice(7), 'hex'),
        installed_by: 'openpc_scope_installer',
      });
      expect(
        (
          await admin.query(
            'select count(*) from control.authority_envelope where participant_id=$1',
            [scope.participantId],
          )
        ).rows[0].count,
      ).toBe('0');
      await expect(
        installInitialPlatformEnvelopeScope(admin, { ...admission, platformContextId: id() }),
      ).rejects.toThrow('PLATFORM_SCOPE_UNAVAILABLE');
      await expect(
        installInitialPlatformEnvelopeScope(runtime, { ...admission, platformContextId: id() }),
      ).rejects.toThrow();
      for (const patch of [
        { platformAuthorityEpoch: '2' },
        { installationDigest: hash('forged') },
        { environmentId: 'missing-installation' },
        {
          ownerParticipantId: foreign.participantId,
          installationPrivacyDomainId: foreign.privacyDomainId,
        },
        { grantable: { ...admission.grantable, onwardDelegationDepth: 1 } },
      ])
        await expect(
          installInitialPlatformEnvelopeScope(installer, { ...admission, ...patch }),
        ).rejects.toThrow();
      expect(await roots()).toBe(2);

      const unverifiedEnvironment = `unverified-${id().slice(-12)}`;
      const unverifiedDigest = await installInitialOperationsEnvironment(installer, scope, {
        pins: { ...input.pins, environmentId: unverifiedEnvironment },
        initialBaseGenerationId: id(),
        schemaBytes: input.schemaBytes,
        profileBytes: input.profileBytes,
      });
      await expect(
        installInitialPlatformEnvelopeScope(installer, {
          ...admission,
          platformContextId: id(),
          environmentId: unverifiedEnvironment,
          installationDigest: unverifiedDigest,
        }),
      ).rejects.toThrow();
      expect(await roots()).toBe(2);

      // This is an existing, independently installed untyped root. The adapter
      // cannot retrofit it or infer grantability from ACTIVE/owner labels.
      await expect(
        installInitialPlatformEnvelopeScope(installer, {
          ...admission,
          platformContextId: legacyRoot,
        }),
      ).rejects.toThrow();
      await expect(
        withInstallationTransaction(installer, scope, (c) =>
          rawAdmission(
            c,
            { ...admission, platformContextId: legacyRoot },
            undefined,
            undefined,
            false,
          ),
        ),
      ).rejects.toThrow();
      expect(
        (await admin.query('select count(*) from control.platform_envelope_scope')).rows[0].count,
      ).toBe('1');

      // Direct negative invocation of the SQL owner, not a replacement installer.
      // A self-consistent forged preimage/digest and root/body substitution must
      // fail independently of the TypeScript adapter and roll back their roots.
      for (const forged of [encodeCbor([]), platformEnvelopeScopePreimage(admission)]) {
        await expect(
          withInstallationTransaction(installer, scope, (c) =>
            rawAdmission(c, { ...admission, platformContextId: id() }, forged),
          ),
        ).rejects.toThrow();
        expect(await roots()).toBe(2);
      }
      const invalid = decodeCbor(encodeEnvelopeScope(admission.grantable)) as Map<
        number,
        CborValue
      >;
      (invalid.get(1) as Map<number, CborValue>).set(3, ['*']);
      await expect(
        withInstallationTransaction(installer, scope, (c) =>
          rawAdmission(
            c,
            { ...admission, platformContextId: id() },
            undefined,
            encodeCbor(invalid),
          ),
        ),
      ).rejects.toThrow();
      expect(await roots()).toBe(2);
      await withInstallationTransaction(installer, scope, async (c) => {
        expect(
          (
            await c.query('select openpc.identity_envelope_scope_valid($1) valid', [
              encodeEnvelopeScope(admission.grantable),
            ])
          ).rows[0].valid,
        ).toBe(true);
        const cases: CborValue[] = [new Map(), invalid];
        for (const [key, value] of [
          [3, 1n],
          [4, 0n],
          [5, 2n],
          [6, 2n],
          [7, 33n],
        ] as const) {
          const bad = decodeCbor(encodeEnvelopeScope(admission.grantable)) as Map<
            number,
            CborValue
          >;
          bad.set(key, value);
          cases.push(bad);
        }
        for (const [dimension, value] of [
          [1, [Buffer.alloc(16)]],
          [2, [new Map<number, CborValue>()]],
          [3, ['same', 'same']],
          [4, ['B', 'A']],
          [5, ['*']],
          [6, ['UNKNOWN']],
          [7, ['UNKNOWN']],
        ] as [number, CborValue][]) {
          const bad = decodeCbor(encodeEnvelopeScope(admission.grantable)) as Map<
            number,
            CborValue
          >;
          (bad.get(1) as Map<number, CborValue>).set(dimension, value);
          cases.push(bad);
        }
        for (const bad of cases)
          expect(
            (
              await c.query('select openpc.identity_envelope_scope_valid($1) valid', [
                encodeCbor(bad),
              ])
            ).rows[0].valid,
          ).toBe(false);
      });
      for (const sql of [
        'update control.platform_envelope_scope set admission_version=1',
        'delete from control.platform_envelope_scope',
      ]) {
        await expect(
          withInstallationTransaction(installer, scope, (c) => c.query(sql)),
        ).rejects.toThrow();
        await expect(scoped((c) => c.query(sql))).rejects.toMatchObject({ code: '42501' });
      }
      await expect(
        scoped((c) =>
          c.query(
            'insert into control.platform_envelope_scope select * from control.platform_envelope_scope',
          ),
        ),
      ).rejects.toMatchObject({ code: '42501' });
      expect(
        (
          await admin.query(
            `select has_table_privilege('openpc_control_key_governor','control.platform_envelope_scope','INSERT') allowed`,
          )
        ).rows[0].allowed,
      ).toBe(false);
      expect(
        (
          await scoped(
            (c) => c.query('select * from control.platform_envelope_scope'),
            foreign.participantId,
          )
        ).rowCount,
      ).toBe(0);

      // Downstream custody fixture only, analogous to the existing Platform test.
      // No issuance, approval, activation or assignment journey is established.
      await admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'PLATFORM_OPERATOR','Initial custody fixture','ACTIVE',1)`,
        [principalId, scope.participantId],
      );
      for (const [envelopeId, rootId] of [
        [selectedEnvelopeId, platformContextId],
        [legacyEnvelopeId, legacyRoot],
      ])
        await admin.query(
          `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,
      authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,
      resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
      values($1,$2,$3,$3,1,1,'ACTIVE',clock_timestamp(),$4,$5,$4,ARRAY[]::text[],ARRAY[]::text[],ARRAY[]::text[],ARRAY[]::text[],true,true,0,$6,1)`,
          [
            envelopeId,
            scope.participantId,
            principalId,
            Buffer.from([0x80]),
            Buffer.from(hash(envelopeId!).slice(7), 'hex'),
            rootId,
          ],
        );
      expect(await current()).toEqual({
        ...admission,
        platformAuthorityDigest: admitted.platformAuthorityDigest,
      });
      await expect(
        scoped((c) => fenceEnvelopePlatformScope(c, scope.participantId, legacyEnvelopeId)),
      ).rejects.toThrow('authority dependency');
      await expect(
        scoped(
          (c) => fenceEnvelopePlatformScope(c, foreign.participantId, selectedEnvelopeId),
          foreign.participantId,
        ),
      ).rejects.toThrow('authority dependency');
      await expect(
        scoped((c) => fenceEnvelopePlatformScope(c, scope.participantId, id())),
      ).rejects.toThrow('authority dependency');

      const held = await runtime.connect(),
        updater = await admin.connect();
      try {
        await held.query('begin');
        await held.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-PARTICIPANT_CREATE_CONTEXT-V1',true)`,
          [scope.participantId, scope.privacyDomainId, id()],
        );
        await held.query('select 1 from control.participant where participant_id=$1 for share', [
          scope.participantId,
        ]);
        await fenceEnvelopePlatformScope(held, scope.participantId, selectedEnvelopeId);
        await updater.query('begin');
        await updater.query("set local lock_timeout='200ms'");
        await expect(
          updater.query(
            `update control.platform_context set state='SUSPENDED',authority_epoch=2,row_version=2,updated_at=clock_timestamp()
        where platform_context_id=$1`,
            [platformContextId],
          ),
        ).rejects.toMatchObject({ code: '55P03' });
        await updater.query('rollback');
        await held.query('rollback');
      } finally {
        await held.query('rollback');
        await updater.query('rollback');
        held.release();
        updater.release();
      }
      const beforeRestart = await current();
      await Promise.all([endPool(admin), endPool(installer), endPool(runtime)]);
      await execute('docker', ['restart', container!], { timeout: 60000, maxBuffer: 4096 });
      await execute(
        'docker',
        [
          'exec',
          container!,
          'sh',
          '-c',
          'for n in $(seq 1 60); do pg_isready -h 127.0.0.1 -U postgres -d openpc_control >/dev/null 2>&1 && exit 0; sleep 0.1; done; exit 1',
        ],
        { timeout: 10000, maxBuffer: 4096 },
      );
      // Docker may allocate a new ephemeral host port at restart. Resolve the
      // actual endpoint, then wait only for connection readiness before reading
      // the original durable bound. Never retry an admission or business effect.
      const published = await execute('docker', ['port', container!, '5432/tcp'], {
        timeout: 10000,
        maxBuffer: 4096,
      });
      const match = /^127\.0\.0\.1:([0-9]+)$/u.exec(published.stdout.trim());
      expect(match).not.toBeNull();
      const restartedAdminUrl = new URL(adminUrl!);
      restartedAdminUrl.port = match![1]!;
      installerUrl.port = match![1]!;
      actualRuntimeUrl.port = match![1]!;
      admin = new Pool({ connectionString: restartedAdminUrl.href, max: 2 });
      installer = new Pool({ connectionString: installerUrl.href, max: 2 });
      runtime = new Pool({ connectionString: actualRuntimeUrl.href, max: 2 });
      const deadline = Date.now() + 10000;
      for (;;) {
        try {
          await admin.query('select 1');
          break;
        } catch (error) {
          if (
            !['ECONNREFUSED', '57P03'].includes((error as { code: string }).code) ||
            Date.now() >= deadline
          )
            throw error;
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
      expect(await current()).toEqual(beforeRestart);
      expect(await installInitialPlatformEnvelopeScope(installer, admission)).toEqual(admitted);
      for (const [state, epoch] of [
        ['SUSPENDED', 2],
        ['ACTIVE', 3],
        ['RETIRED', 4],
      ] as const) {
        await admin.query(
          `update control.platform_context set state=$2,authority_epoch=$3,row_version=$3,updated_at=clock_timestamp()
        where platform_context_id=$1`,
          [platformContextId, state, epoch],
        );
        await expect(current()).rejects.toThrow('authority dependency');
        await expect(installInitialPlatformEnvelopeScope(installer, admission)).rejects.toThrow();
      }
      const final = await admin.query(
        `select admission_preimage,admission_digest,installed_by from control.platform_envelope_scope where platform_context_id=$1`,
        [platformContextId],
      );
      expect(final.rows).toEqual(stored.rows);
    } finally {
      await Promise.all([endPool(admin), endPool(installer), endPool(runtime)]);
    }
  },
  120000,
);
