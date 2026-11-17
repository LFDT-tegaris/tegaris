import {
  installRootExpiryRecoveryTrust,
  enrollRootExpiryRecovery,
} from '../../services/identity-service/src/db/root-expiry-recovery-installation.ts';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';
import manifest from '../../package.json' with { type: 'json' };
import { discoveryCertificateRecoveryEnrollment } from '../../services/identity-service/src/contracts/discovery-certificate-recovery.ts';
import { platformAdministrationRecoveryEnrollment } from '../../services/identity-service/src/contracts/platform-recovery.ts';
import { enrollPlatformRecovery } from '../../services/identity-service/src/db/platform-recovery-enrollment.ts';
import {
  identityEnvelopeRecoveryReceivingTrust,
  signedIdentityEnvelopeRecoveryEnrollment,
} from '../../services/identity-service/src/contracts/identity-envelope-recovery.ts';
import {
  installIdentityEnvelopeRecoveryReceivingTrust as installEnvelopeReceivingTrust,
  enrollIdentityEnvelopeRecovery,
} from '../../services/identity-service/src/db/identity-envelope-recovery-enrollment.ts';
import {
  InstallationConfigError,
  parseConfigurationJson,
  readConfigurationBytes,
} from './installation-config-inputs.mjs';
import { withInstallationTransaction } from './installation-generation-store.mjs';
import { createLocalIdentityRuntimeVerifier } from '../../services/identity-service/src/domain/identity-runtime-crypto.ts';

const unavailable = () => {
  throw new InstallationConfigError('PLATFORM_RECOVERY_ENROLLMENT_UNAVAILABLE');
};

/** Host initial-trust owner only. No lease, assignment, approval or business effect is installed. */
export async function installPlatformRecoveryEnrollment(
  pool,
  input,
  { localQaEnabled = false, identityRuntimeVerifier } = {},
) {
  if (input?.schema === 'pc.installation.local-root-expiry-recovery-receiving-trust') {
    if (input.schemaVersion === 3 && (!localQaEnabled || !identityRuntimeVerifier)) unavailable();
    return withInstallationRecoveryOwner(pool, input, (client) =>
      installRootExpiryRecoveryTrust(client, input, localQaEnabled, identityRuntimeVerifier),
    );
  }
  if (input?.document?.schema === 'pc.identity.local-root-expiry-recovery-enrollment') {
    if (input.document.schemaVersion === 3 && (!localQaEnabled || !identityRuntimeVerifier))
      unavailable();
    return withInstallationRecoveryOwner(pool, input.document, (client) =>
      enrollRootExpiryRecovery(client, input, localQaEnabled, identityRuntimeVerifier),
    );
  }
  if (input?.schema === 'pc.installation.identity-envelope-recovery-receiving-trust')
    return installIdentityEnvelopeRecoveryReceivingTrust(pool, input, { localQaEnabled });
  if (input?.document?.schema === 'pc.identity.identity-envelope-recovery-enrollment')
    return installIdentityEnvelopeRecoveryEnrollment(pool, input, {
      localQaEnabled,
      identityRuntimeVerifier,
    });
  const enrollment = platformAdministrationRecoveryEnrollment.parse(input);
  if (enrollment.schemaVersion !== 1 && (!localQaEnabled || !identityRuntimeVerifier))
    unavailable();
  return installRecoveryEnrollment(pool, enrollment, localQaEnabled, identityRuntimeVerifier);
}

/** Separate public receiving trust and signed custody input through the existing
 * host initial-trust entrypoint. Neither function can activate a RecoveryCase. */
export async function installIdentityEnvelopeRecoveryReceivingTrust(
  pool,
  input,
  { localQaEnabled = false } = {},
) {
  const trust = identityEnvelopeRecoveryReceivingTrust.parse(input);
  return withInstallationRecoveryOwner(pool, trust, (client) =>
    installEnvelopeReceivingTrust(client, trust, { localQaEnabled }),
  );
}

export async function installIdentityEnvelopeRecoveryEnrollment(
  pool,
  input,
  { localQaEnabled = false, identityRuntimeVerifier } = {},
) {
  const signed = signedIdentityEnvelopeRecoveryEnrollment.parse(input);
  return withInstallationRecoveryOwner(pool, signed.document, (client) =>
    enrollIdentityEnvelopeRecovery(client, signed, {
      localQaEnabled,
      ...(identityRuntimeVerifier === undefined ? {} : { identityRuntimeVerifier }),
    }),
  );
}

export async function installDiscoveryCertificateRecoveryEnrollment(
  pool,
  input,
  { localQaEnabled = false, identityRuntimeVerifier } = {},
) {
  const enrollment = discoveryCertificateRecoveryEnrollment.parse(input);
  if (enrollment.schemaVersion === 2 && (!localQaEnabled || !identityRuntimeVerifier))
    unavailable();
  return installRecoveryEnrollment(pool, enrollment, localQaEnabled, identityRuntimeVerifier);
}

async function installRecoveryEnrollment(
  pool,
  enrollment,
  localQaEnabled,
  identityRuntimeVerifier,
) {
  return withInstallationRecoveryOwner(pool, enrollment, async (client) => {
    if (enrollment.schemaVersion !== 1) {
      if (!localQaEnabled) unavailable();
      await client.query("select set_config('openpc.local_qa_runtime','1',true)");
    }
    return enrollPlatformRecovery(client, enrollment, {
      localQaEnabled,
      ...(enrollment.schemaVersion !== 1 ? { verifier: identityRuntimeVerifier } : {}),
    });
  });
}

async function withInstallationRecoveryOwner(pool, source, admit) {
  return withInstallationTransaction(
    pool,
    { participantId: source.participantId, privacyDomainId: source.privacyDomainId },
    async (client, scope) => {
      const admission = await client.query(`select current_user='openpc_control_owner'
        and pg_has_role(session_user,'openpc_control_owner','MEMBER')
        and exists(select 1 from pg_roles where rolname=session_user and rolcanlogin and not rolsuper and not rolbypassrls) allowed`);
      if (admission.rows[0]?.allowed !== true) unavailable();
      if (
        source.schema === 'pc.installation.local-root-expiry-recovery-receiving-trust' ||
        source.schema === 'pc.identity.local-root-expiry-recovery-enrollment'
      ) {
        if (source.profile !== 'LOCAL_QA') unavailable();
        await client.query("select set_config('openpc.local_qa_runtime','1',true)");
      }
      await client.query(
        `select set_config('openpc.action_intent_id','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',true)`,
      );
      // Serialize with recovery activation and Root/source changes before descendant locks.
      const participant = await client.query(
        `select 1 from control.participant where participant_id=$1 and state='ACTIVE' for update`,
        [scope.participantId],
      );
      if (participant.rowCount !== 1) unavailable();
      const privacy = await client.query(
        `select 1 from control.privacy_domain where participant_id=$1 and privacy_domain_id=$2 and state='ACTIVE' for share`,
        [scope.participantId, scope.privacyDomainId],
      );
      if (privacy.rowCount !== 1) unavailable();
      return admit(client);
    },
  );
}

const installationLogin = 'openpc_recovery_installation';
const installationLoginMarker = 'openpc:installation-recovery-login:v1';
/** Explicit host bootstrap only. Existing unknown or changed logins stay
 * untouched; an existing password is never reset to make enrollment succeed. */
export async function provisionPlatformRecoveryInstallationLogin(bootstrapPool, connectionString) {
  let target;
  try {
    target = new URL(connectionString);
    if (
      !['postgres:', 'postgresql:'].includes(target.protocol) ||
      decodeURIComponent(target.username) !== installationLogin ||
      !target.hostname ||
      !target.pathname ||
      !target.password ||
      /[\r\n\0]/u.test(connectionString)
    )
      unavailable();
  } catch {
    unavailable();
  }
  let password;
  try {
    password = decodeURIComponent(target.password);
  } catch {
    unavailable();
  }
  if (password.length < 32 || password.length > 512 || /[\r\n\0]/u.test(password)) unavailable();
  const client = await bootstrapPool.connect();
  try {
    await client.query('begin');
    const authority = await client.query(
      `select current_database()=$1 and exists(select 1 from pg_roles owner where owner.rolname='openpc_control_owner' and not owner.rolsuper and not owner.rolbypassrls and not owner.rolcanlogin)
      and exists(select 1 from pg_roles actor where actor.rolname=session_user and (actor.rolsuper or (actor.rolcreaterole and exists(select 1 from pg_auth_members membership join pg_roles owner on owner.oid=membership.roleid where owner.rolname='openpc_control_owner' and membership.member=actor.oid and membership.admin_option)))) allowed`,
      [decodeURIComponent(target.pathname.slice(1))],
    );
    if (authority.rowCount !== 1 || authority.rows[0]?.allowed !== true) unavailable();
    await client.query(
      "select pg_advisory_xact_lock(hashtextextended('openpc:installation-recovery-login:v1',0))",
    );
    await client.query("select set_config('openpc.installation_recovery_login_secret',$1,true)", [
      password,
    ]);
    const result = await client.query(`do $$
    declare installed pg_roles; exists_already boolean;
    begin
      select * into installed from pg_roles where rolname='openpc_recovery_installation';
      exists_already:=found;
      if exists_already then
        if not installed.rolcanlogin or installed.rolsuper or installed.rolbypassrls or installed.rolcreatedb or installed.rolcreaterole or installed.rolreplication or installed.rolinherit or installed.rolconnlimit<>2 or installed.rolvaliduntil is not null
          or shobj_description(installed.oid,'pg_authid') is distinct from 'openpc:installation-recovery-login:v1'
          or not exists(select 1 from pg_auth_members member join pg_roles owner on owner.oid=member.roleid where member.member=installed.oid and owner.rolname='openpc_control_owner' and not member.admin_option and not member.inherit_option and member.set_option)
          or exists(select 1 from pg_auth_members member join pg_roles owner on owner.oid=member.roleid where member.member=installed.oid and owner.rolname<>'openpc_control_owner')
        then raise exception 'OPS_CONFIG_INVALID-INSTALLATION-LOGIN'; end if;
      else
        execute format('CREATE ROLE openpc_recovery_installation LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD %L',current_setting('openpc.installation_recovery_login_secret'));
        grant openpc_control_owner to openpc_recovery_installation with admin false,inherit false,set true;
        comment on role openpc_recovery_installation is 'openpc:installation-recovery-login:v1';
      end if;
      -- NOINHERIT cannot consume the owner's CONNECT grant. Grant only this
      -- database connection after the existing role provenance checks pass.
      execute format('GRANT CONNECT ON DATABASE %I TO openpc_recovery_installation',current_database());
      perform set_config('openpc.installation_recovery_login_created',case when exists_already then 'false' else 'true' end,true);
    end $$`);
    void result;
    const created = await client.query(
      "select current_setting('openpc.installation_recovery_login_created')='true' as created",
    );
    if (created.rowCount !== 1 || typeof created.rows[0]?.created !== 'boolean') unavailable();
    await client.query('commit');
    return {
      login: installationLogin,
      created: created.rows[0].created,
      authority: 'INSTALLATION_ONLY',
      ownership: installationLoginMarker,
    };
  } catch {
    await client.query('rollback');
    unavailable();
  } finally {
    client.release();
  }
}

export function validatePlatformRecoveryInstallationPeer(
  bootstrapConnectionString,
  installationConnectionString,
) {
  try {
    const initial = new URL(bootstrapConnectionString),
      target = new URL(installationConnectionString);
    if (
      !['postgres:', 'postgresql:'].includes(initial.protocol) ||
      !['postgres:', 'postgresql:'].includes(target.protocol) ||
      !initial.username ||
      !initial.password ||
      !initial.hostname ||
      initial.hostname !== target.hostname ||
      (initial.port || '5432') !== (target.port || '5432') ||
      initial.pathname !== target.pathname ||
      initial.search !== target.search ||
      decodeURIComponent(target.username) !== installationLogin ||
      /[\r\n\0]/u.test(bootstrapConnectionString + installationConnectionString)
    )
      unavailable();
  } catch {
    unavailable();
  }
}

export function parsePlatformRecoveryEnrollmentArguments(args) {
  const options = { localQaEnabled: false };
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--local-qa-virtual-authenticator' && !options.localQaEnabled) {
      options.localQaEnabled = true;
    } else if (
      argument === '--provision-installation-login' &&
      !options.provisionInstallationLogin
    ) {
      options.provisionInstallationLogin = true;
    } else if (
      [
        '--enrollment',
        '--database-url-file',
        '--bootstrap-database-url-file',
        '--identity-runtime-trust-file',
      ].includes(argument) &&
      !Object.hasOwn(options, argument)
    ) {
      const value = args[++index];
      if (!value || !isAbsolute(value)) unavailable();
      options[argument] = value;
    } else unavailable();
  }
  if (
    !options['--enrollment'] ||
    !options['--database-url-file'] ||
    !!options.provisionInstallationLogin !== !!options['--bootstrap-database-url-file']
  )
    unavailable();
  return options;
}

/** Do not accept credentials on argv or follow links to unrelated secret material. */
export async function readPlatformRecoveryDatabaseUrl(path) {
  if (!isAbsolute(path)) unavailable();
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const stat = await file.stat();
    if (
      !stat.isFile() ||
      stat.uid !== process.getuid() ||
      (stat.mode & 0o077) !== 0 ||
      stat.size < 1 ||
      stat.size > 8192
    )
      unavailable();
    const bytes = Buffer.alloc(8193);
    const { bytesRead } = await file.read(bytes, 0, bytes.length, 0);
    if (bytesRead < 1 || bytesRead > 8192) unavailable();
    const value = new TextDecoder('utf-8', { fatal: true })
      .decode(bytes.subarray(0, bytesRead))
      .trim();
    const url = new URL(value);
    if (
      !['postgres:', 'postgresql:'].includes(url.protocol) ||
      !url.hostname ||
      !url.username ||
      !url.pathname ||
      /[\r\n\0]/u.test(value)
    )
      unavailable();
    return value;
  } catch {
    unavailable();
  } finally {
    await file?.close();
  }
}

export async function runRecoveryEnrollmentInstallation(
  install,
  reason = 'PLATFORM_RECOVERY_ENROLLMENT_UNAVAILABLE',
) {
  let pool;
  try {
    if (process.versions.node !== manifest.engines.node) unavailable();
    const options = parsePlatformRecoveryEnrollmentArguments(process.argv.slice(2));
    const input = parseConfigurationJson(await readConfigurationBytes(options['--enrollment']));
    // Independent operator-installed public trust, never a key embedded in custody.
    if (options['--identity-runtime-trust-file']) {
      if (
        input?.document?.schema !== 'pc.identity.identity-envelope-recovery-enrollment' &&
        !(
          input?.schema === 'pc.installation.local-root-expiry-recovery-receiving-trust' &&
          input?.schemaVersion === 3
        ) &&
        !(
          input?.document?.schema === 'pc.identity.local-root-expiry-recovery-enrollment' &&
          input?.document?.schemaVersion === 3
        ) &&
        !(
          input?.schema === 'pc.identity.platform-recovery-enrollment' &&
          [2, 3, 4].includes(input?.schemaVersion)
        ) &&
        !(
          input?.schema === 'pc.identity.discovery-certificate-recovery-enrollment' &&
          input?.schemaVersion === 2
        )
      )
        unavailable();
      options.identityRuntimeVerifier = createLocalIdentityRuntimeVerifier([
        await readConfigurationBytes(options['--identity-runtime-trust-file'], 8192),
      ]);
    }
    const connectionString = await readPlatformRecoveryDatabaseUrl(options['--database-url-file']);
    if (options.provisionInstallationLogin) {
      const bootstrapConnectionString = await readPlatformRecoveryDatabaseUrl(
        options['--bootstrap-database-url-file'],
      );
      validatePlatformRecoveryInstallationPeer(bootstrapConnectionString, connectionString);
      const bootstrapPool = new Pool({
        connectionString: bootstrapConnectionString,
        max: 1,
        connectionTimeoutMillis: 10000,
        query_timeout: 30000,
      });
      try {
        await provisionPlatformRecoveryInstallationLogin(bootstrapPool, connectionString);
      } finally {
        await bootstrapPool.end();
      }
    }
    pool = new Pool({
      connectionString,
      max: 1,
      connectionTimeoutMillis: 10000,
      query_timeout: 30000,
    });
    const result = await install(pool, input, options);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write(`${JSON.stringify({ code: 'OPS_CONFIG_INVALID', reason })}\n`);
    process.exitCode = 2;
  } finally {
    await pool?.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await runRecoveryEnrollmentInstallation(installPlatformRecoveryEnrollment);
