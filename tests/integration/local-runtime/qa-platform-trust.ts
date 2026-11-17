import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';

import { installInitialPlatformEnvelopeScope } from '../../../scripts/operations/installation-platform-authority.mjs';
import { installInitialOperationsEnvironment } from '../../../scripts/operations/installation-generation-store.mjs';
import { localQaRpcAuthority } from '../../../scripts/operations/local-qa-rpc-authority.mjs';
import { envelopeBrowserInstallationInputs } from './envelope-recovery-browser-fixture.ts';
import { qaParticipants, qaRpcPlatformTrust } from './qa-sandbox.mjs';

const rootInput = process.argv[2];
if (!rootInput || (await realpath(rootInput)) !== rootInput)
  throw new Error('Canonical QA root required');

const participantId = qaParticipants[0]!.participantId;
const privacyDomainId = qaParticipants[0]!.privacyDomainId;
const grantable = localQaRpcAuthority(process.env, {
  participantId,
  privacyDomainId,
  runtimeBindingId: qaRpcPlatformTrust.runtimeBindingId,
  targetProfileId: qaRpcPlatformTrust.targetProfileId,
});
const controlPassword = (
  await readFile(join(rootInput, 'secrets/control_pg_password.txt'), 'utf8')
).trim();
const admin = new Pool({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: controlPassword,
  max: 1,
});
const password = randomBytes(24).toString('hex');
let roleCreated = false;
let installer: Pool | undefined;
try {
  await admin.query(
    `create role openpc_qa_platform_installer login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '${password}'`,
  );
  roleCreated = true;
  await admin.query('grant openpc_control_owner to openpc_qa_platform_installer');
  await admin.query('grant connect on database openpc_control to openpc_qa_platform_installer');
  installer = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_qa_platform_installer',
    password,
    max: 1,
  });
  const { schemaBytes, profileBytes, sourceAuthentication } =
    await envelopeBrowserInstallationInputs();
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const sha = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  const installationDigest = await installInitialOperationsEnvironment(
    installer,
    { participantId, privacyDomainId },
    {
      schemaBytes,
      profileBytes,
      sourceAuthentication,
      initialBaseGenerationId: qaRpcPlatformTrust.initialBaseGenerationId,
      pins: {
        issuerSpkiHex: key.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
        issuerEpoch: '1',
        issuerValidFromMs: Date.now() - 60_000,
        issuerValidUntilMs: Number(BigInt(grantable.validUntilNs) / 1_000_000n),
        environmentId: qaRpcPlatformTrust.environmentId,
        profile: 'local',
        configurationSchemaDigest: sha(schemaBytes),
        namedProfileDigest: sha(profileBytes),
      },
    },
  );
  const installed = await installInitialPlatformEnvelopeScope(installer, {
    platformContextId: qaRpcPlatformTrust.platformContextId,
    ownerParticipantId: participantId,
    installationPrivacyDomainId: privacyDomainId,
    platformAuthorityEpoch: '1',
    environmentId: qaRpcPlatformTrust.environmentId,
    installationDigest,
    grantable,
  });
  process.stdout.write(`${JSON.stringify(installed)}\n`);
} finally {
  await installer?.end();
  if (roleCreated) await admin.query('alter role openpc_qa_platform_installer nologin');
  await admin.end();
}
