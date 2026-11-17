import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect } from 'vitest';
import { z } from 'zod';
import { encodeCbor } from '../../../packages/security-kernel/src/canonical-cbor.js';
import { envelopeFixtureScope } from '../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  platformEnvelopeScopeDigest,
  type PlatformEnvelopeScopeAdmission,
} from '../../../packages/security-kernel/src/index.js';
import { installInitialPlatformEnvelopeScope } from '../../../scripts/operations/installation-platform-authority.mjs';
import { installInitialOperationsEnvironment } from '../../../scripts/operations/installation-generation-store.mjs';
import {
  installPlatformRecoveryEnrollment,
  provisionPlatformRecoveryInstallationLogin,
} from '../../../scripts/operations/installation-platform-recovery.mjs';
import { localRootExpiryRecoveryReceivingTrust } from '../../../services/identity-service/src/contracts/local-root-expiry-recovery.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { sha } from './public-governance-client.js';
import { readPublicOperationsSources } from '../../../scripts/operations/read-public-installation-sources.mjs';

const isolatedRecoveryDatabase = z.object({
  Id: z.string().regex(/^[a-f0-9]{64}$/u),
  Name: z.string(),
  State: z.object({ Running: z.literal(true) }),
  Config: z.object({ Labels: z.record(z.string(), z.string()) }),
  NetworkSettings: z.object({
    Ports: z.object({
      '5432/tcp': z
        .array(
          z.object({
            HostIp: z.literal('127.0.0.1'),
            HostPort: z.string().regex(/^[1-9][0-9]{0,4}$/u),
          }),
        )
        .length(1),
    }),
  }),
});

export function assertNativeRootExpiryDatabaseTarget(input: {
  container: string;
  scratch: string;
  adminUrl: string;
  runtimeUrl: string;
  inspection: unknown;
}) {
  if (
    !/^openpc-participant-readback-[0-9]+$/u.test(input.container) ||
    !input.scratch.startsWith('/')
  )
    throw new Error('An owned isolated recovery database is required');
  const database = isolatedRecoveryDatabase.parse(input.inspection);
  if (
    database.Name !== '/' + input.container ||
    database.Config.Labels['io.openpc.test-owner'] !== input.scratch
  )
    throw new Error('Isolated recovery database ownership mismatch');
  const binding = database.NetworkSettings.Ports['5432/tcp'][0]!;
  if (Number(binding.HostPort) > 65535) throw new Error('Invalid isolated database port');
  for (const [value, username] of [
    [input.adminUrl, 'postgres'],
    [input.runtimeUrl, 'openpc_identity_runtime'],
  ]) {
    const url = new URL(value!);
    if (
      url.protocol !== 'postgresql:' ||
      url.hostname !== binding.HostIp ||
      url.port !== binding.HostPort ||
      url.pathname !== '/openpc_control' ||
      url.username !== username ||
      url.search ||
      url.hash
    )
      throw new Error('Recovery database URL does not match the owned loopback target');
  }
  return { id: database.Id, port: binding.HostPort };
}

export async function nativeRootExpiryInstallationInput(environmentId: string) {
  const schemaBytes = await readFile('config/schema/effective-configuration.schema.json');
  const profileBytes = await readFile('config/profiles/local.yaml');
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
      configurationSchemaDigest: 'sha256:' + sha(schemaBytes).toString('hex'),
      namedProfileDigest: 'sha256:' + sha(profileBytes).toString('hex'),
    },
  };
}

/** Real installation owner and genuine expiry only. This checks the receiving-
 * trust prerequisite, not human enrollment, recovery authority or root activation. */
export async function verifyNativeRootExpiryReceivingTrust(input: {
  admin: Pool;
  initialInstaller: Pool;
  runtime: Pool;
  adminUrl: string;
  operationsInput: Parameters<typeof installInitialOperationsEnvironment>[2] & {
    pins: { environmentId: string };
  };
}) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent?.startsWith('/')) throw new Error('Absolute isolated fixture scratch is required');
  const directory = await mkdtemp(join(parent, 'root-expiry-installation-'));
  await mkdir(join(directory, 'private'), { mode: 0o700 });
  const scope = { participantId: id(), privacyDomainId: id() };
  const otherPrivacyDomainId = id();
  const environmentId = input.operationsInput.pins.environmentId;
  const contextId = id();
  const loginUrl = new URL(input.adminUrl);
  loginUrl.username = 'openpc_recovery_installation';
  loginUrl.password = randomBytes(32).toString('hex');
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const spki = issuer.publicKey.export({ format: 'der', type: 'spki' });
  await writeFile(
    join(directory, 'private', 'custody-issuer.pkcs8.der'),
    issuer.privateKey.export({ format: 'der', type: 'pkcs8' }),
    { mode: 0o600, flag: 'wx' },
  );
  await writeFile(
    join(directory, 'private', 'installation-login.json'),
    JSON.stringify({ databaseUrl: loginUrl.href }) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
  await input.admin.query(
    "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Native expired-root installation fixture','ACTIVE',1)",
    [scope.participantId],
  );
  await input.admin.query(
    "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Native expired-root installation','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
    [scope.privacyDomainId, scope.participantId],
  );
  await input.admin.query(
    "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Alternate recovery scope','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
    [otherPrivacyDomainId, scope.participantId],
  );
  const installationDigest = await installInitialOperationsEnvironment(
    input.initialInstaller,
    scope,
    input.operationsInput,
  );
  const grantable = envelopeFixtureScope();
  for (const key of Object.keys(
    grantable.administration,
  ) as (keyof typeof grantable.administration)[])
    grantable.administration[key] = [];
  grantable.onwardDelegationDepth = 0;
  grantable.runtime.participantIds = [scope.participantId];
  grantable.runtime.privacyDomainIds = [scope.privacyDomainId];
  const now = Date.now();
  grantable.validFromNs = (BigInt(now) * 1_000_000n).toString();
  grantable.validUntilNs = (BigInt(now + 5_000) * 1_000_000n).toString();
  const admission: PlatformEnvelopeScopeAdmission = {
    platformContextId: contextId,
    ownerParticipantId: scope.participantId,
    installationPrivacyDomainId: scope.privacyDomainId,
    platformAuthorityEpoch: '1',
    environmentId,
    installationDigest,
    grantable,
  };
  const initial = await installInitialPlatformEnvelopeScope(input.initialInstaller, admission);
  expect(initial.platformAuthorityDigest).toBe(platformEnvelopeScopeDigest(admission));
  // Synthetic initial custody only, matching the LEGACY setup representation.
  // This is not governed issuance, an authenticated operator or a signing proof.
  const principalId = id(),
    envelopeId = id();
  const semantic = encodeCbor([
    'SYNTHETIC_LOCAL_QA_CUSTODY',
    scope.participantId,
    scope.privacyDomainId,
    principalId,
    [],
  ]);
  await input.admin.query(
    "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'PLATFORM_OPERATOR','Synthetic initial Root custody','ACTIVE',1)",
    [principalId, scope.participantId],
  );
  await input.admin.query(
    `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,representation,
    authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,runtime_capability_ids,
    resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
    values($1,$2,$3,$3,'LEGACY',1,1,'ACTIVE',clock_timestamp(),$4,$5,$6,ARRAY[]::text[],ARRAY[]::text[],ARRAY[]::text[],ARRAY[]::text[],ARRAY[]::text[],true,true,0,$7,1)`,
    [
      envelopeId,
      scope.participantId,
      principalId,
      semantic,
      sha(semantic),
      Buffer.from('d28440a04040', 'hex'),
      contextId,
    ],
  );
  const sourceRows = async (pool: Pool) => {
    const installation = await pool.query(
      'select installation_bytes,installation_digest from control.operations_installation where participant_id=$1 and environment_id=$2',
      [scope.participantId, environmentId],
    );
    const root = await pool.query(
      'select * from control.platform_envelope_scope where platform_context_id=$1',
      [contextId],
    );
    const context = await pool.query(
      'select * from control.platform_context where platform_context_id=$1',
      [contextId],
    );
    const principals = await pool.query(
      'select * from control.principal where participant_id=$1 order by principal_id',
      [scope.participantId],
    );
    const envelopes = await pool.query(
      'select * from control.authority_envelope where participant_id=$1 order by authority_envelope_id',
      [scope.participantId],
    );
    return {
      installation: installation.rows,
      root: root.rows,
      context: context.rows,
      principals: principals.rows,
      envelopes: envelopes.rows,
    };
  };
  const original = await sourceRows(input.admin);
  const trust = localRootExpiryRecoveryReceivingTrust.parse({
    schema: 'pc.installation.local-root-expiry-recovery-receiving-trust',
    schemaVersion: 1,
    purpose: 'pc.installation.local-root-expiry-recovery-custody.v1',
    custodyTrustId: id(),
    ...scope,
    platformContextId: contextId,
    installationDigest,
    installationEnvironmentId: environmentId,
    profile: 'LOCAL_QA',
    algorithm: 'ES256',
    issuerKeyId: 'sha256:' + sha(spki).toString('hex'),
    issuerPublicKeySpkiDer: spki.toString('base64'),
    issuerEpoch: '1',
    validFrom: new Date(now).toISOString(),
    validUntil: new Date(now + 120_000).toISOString(),
  });
  await writeFile(join(directory, 'trust.json'), JSON.stringify(trust, null, 2) + '\n', {
    mode: 0o600,
    flag: 'wx',
  });
  await writeFile(
    join(directory, 'source.json'),
    JSON.stringify({ admission, original, initial }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
  const login = await provisionPlatformRecoveryInstallationLogin(input.admin, loginUrl.href);
  expect(login).toMatchObject({
    login: 'openpc_recovery_installation',
    created: true,
    authority: 'INSTALLATION_ONLY',
  });
  let installer = new Pool({ connectionString: loginUrl.href, max: 1 });
  const install = (body: unknown, localQaEnabled = true, pool = installer) =>
    installPlatformRecoveryEnrollment(pool, body, { localQaEnabled });
  const count = async (pool = input.admin) =>
    Number(
      (
        await pool.query(
          'select count(*) from control.root_expiry_recovery_trust where participant_id=$1',
          [scope.participantId],
        )
      ).rows[0].count,
    );
  const authorityEffects = async (pool: Pool) =>
    (
      await pool.query(
        `select
      (select count(*)::integer from control.root_expiry_recovery_enrollment where participant_id=$1) enrollments,
      (select count(*)::integer from control.root_expiry_recovery_case where participant_id=$1) recoveries,
      (select count(*)::integer from control.root_expiry_recovery_scope where owner_participant_id=$1) successor_scopes,
      (select count(*)::integer from control.authority_envelope where participant_id=$1) envelopes,
      (select count(*)::integer from control.assignment where participant_id=$1) assignments,
      (select count(*)::integer from control.authority_role where participant_id=$1) roles,
      (select count(*)::integer from control.credential where participant_id=$1) credentials,
      (select count(*)::integer from control.session where participant_id=$1) sessions`,
        [scope.participantId],
      )
    ).rows;
  const expectedEffects = [
    {
      enrollments: 0,
      recoveries: 0,
      successor_scopes: 0,
      envelopes: 1,
      assignments: 0,
      roles: 0,
      credentials: 0,
      sessions: 0,
    },
  ];
  let installed: Awaited<ReturnType<typeof installPlatformRecoveryEnrollment>>;
  let stored: unknown[];
  try {
    const nativeClock = async () =>
      BigInt(
        (
          await input.admin.query(
            'select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text now',
          )
        ).rows[0].now,
      );
    expect(await nativeClock()).toBeLessThan(BigInt(grantable.validUntilNs));
    await expect(install(trust)).rejects.toThrow();
    expect(await count()).toBe(0);
    for (;;) {
      const clock = await nativeClock();
      if (clock >= BigInt(grantable.validUntilNs)) break;
      const remaining = Number((BigInt(grantable.validUntilNs) - clock) / 1_000_000n);
      await new Promise((resolve) => setTimeout(resolve, Math.min(250, remaining + 1)));
    }
    await expect(install(trust, false)).rejects.toThrow();
    await expect(install(trust, true, input.runtime)).rejects.toThrow();
    expect(await count()).toBe(0);
    const clockMs = Number((await nativeClock()) / 1_000_000n);
    for (const [validFrom, validUntil] of [
      [clockMs + 30_000, clockMs + 60_000],
      [clockMs - 60_000, clockMs - 1_000],
    ]) {
      await expect(
        install({
          ...trust,
          custodyTrustId: id(),
          validFrom: new Date(validFrom!).toISOString(),
          validUntil: new Date(validUntil!).toISOString(),
        }),
      ).rejects.toThrow();
      expect(await count()).toBe(0);
    }
    await expect(
      install({ ...trust, custodyTrustId: id(), privacyDomainId: otherPrivacyDomainId }),
    ).rejects.toThrow();
    expect(await count()).toBe(0);
    installed = await install(trust);
    expect(installed).toMatchObject({
      custodyTrustId: trust.custodyTrustId,
      state: 'INSTALLED',
      authority: 'NONE',
    });
    expect(await install(trust)).toEqual(installed);
    expect(await count()).toBe(1);
    await expect(
      install({ ...trust, validUntil: new Date(now + 121_000).toISOString() }),
    ).rejects.toThrow();
    await expect(
      install({ ...trust, custodyTrustId: id(), installationDigest: 'sha256:' + '00'.repeat(32) }),
    ).rejects.toThrow();
    await expect(
      install({ ...trust, custodyTrustId: id(), privacyDomainId: otherPrivacyDomainId }),
    ).rejects.toThrow();
    expect(await count()).toBe(1);
    const observed = await input.admin.query(
      'select document,document_digest,state,row_version::text,created_at from control.root_expiry_recovery_trust where custody_trust_id=$1',
      [trust.custodyTrustId],
    );
    expect(observed.rows).toHaveLength(1);
    stored = observed.rows;
    expect(await sourceRows(input.admin)).toEqual(original);
    const effects = await authorityEffects(input.admin);
    expect(effects).toEqual(expectedEffects);
    await writeFile(
      join(directory, 'installed.json'),
      JSON.stringify({ installed, stored, effects }, null, 2) + '\n',
      { mode: 0o600, flag: 'wx' },
    );
  } finally {
    await installer.end();
  }
  return {
    async afterRestart(admin: Pool, port: string) {
      loginUrl.port = port;
      installer = new Pool({ connectionString: loginUrl.href, max: 1 });
      try {
        expect(await install(trust)).toEqual(installed);
        expect(await count(admin)).toBe(1);
        const observed = await admin.query(
          'select document,document_digest,state,row_version::text,created_at from control.root_expiry_recovery_trust where custody_trust_id=$1',
          [trust.custodyTrustId],
        );
        expect(observed.rows).toEqual(stored);
        expect(await sourceRows(admin)).toEqual(original);
        expect(await authorityEffects(admin)).toEqual(expectedEffects);
      } finally {
        await installer.end();
      }
    },
  };
}
