import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';
import type { EnvelopeScope } from '../../../packages/security-kernel/src/index.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { installInitialPlatformEnvelopeScope } from '../../../scripts/operations/installation-platform-authority.mjs';
import { installInitialOperationsEnvironment } from '../../../scripts/operations/installation-generation-store.mjs';
import { readPublicOperationsSources } from '../../../scripts/operations/read-public-installation-sources.mjs';

export async function envelopeBrowserInstallationInputs() {
  const schemaBytes = await readFile('config/schema/effective-configuration.schema.json');
  const profileBytes = await readFile('config/profiles/local.yaml');
  const sourceAuthentication = (
    await readPublicOperationsSources({
      sourceProfile: 'PUBLIC_OPERATIONS_SOURCE_V1',
      profile: 'local',
    })
  ).custody;
  return { schemaBytes, profileBytes, sourceAuthentication };
}

/** Fresh installation trust only. No proposal, candidate, approval or effect is seeded. */
export async function installEnvelopeBrowserTrust(admin: Pool, dataRoot: string) {
  const { schemaBytes, profileBytes, sourceAuthentication } =
    await envelopeBrowserInstallationInputs();
  const participantId = '018f0000-0000-7000-8000-000000000101';
  const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
  const platformContextId = id(),
    targetParticipantId = id(),
    targetPrivacyDomainId = id();
  const envelopeId = id(),
    crossEnvelopeId = id();
  const environmentId = `browser-envelope-${platformContextId.slice(-12)}`;
  const scope: EnvelopeScope = {
    administration: {
      participantIds: [participantId, targetParticipantId].sort(),
      privacyDomainIds: [privacyDomainId, targetPrivacyDomainId].sort(),
      resourceIds: [envelopeId, crossEnvelopeId].sort(),
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: ['HIGH'],
    },
    runtime: {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      capabilityIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [],
    },
    validFromNs: String(BigInt(Date.now() - 60_000) * 1_000_000n),
    validUntilNs: String(BigInt(Date.now() + 3_600_000) * 1_000_000n),
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
  await admin.query(
    `insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Envelope browser target initial trust','ACTIVE',1)`,
    [targetParticipantId],
  );
  await admin.query(
    `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Envelope browser target','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
    [targetPrivacyDomainId, targetParticipantId],
  );
  await admin.query(
    'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
    [targetParticipantId, targetPrivacyDomainId],
  );
  const password = randomBytes(24).toString('hex');
  await admin.query(
    `create role openpc_envelope_browser_installer login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls password '${password}'`,
  );
  await admin.query('grant openpc_control_owner to openpc_envelope_browser_installer');
  await admin.query(
    'grant connect on database openpc_control to openpc_envelope_browser_installer',
  );
  const installer = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_envelope_browser_installer',
    password,
    max: 1,
  });
  try {
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const sha = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    const installationDigest = await installInitialOperationsEnvironment(
      installer,
      { participantId, privacyDomainId },
      {
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
          configurationSchemaDigest: sha(schemaBytes),
          namedProfileDigest: sha(profileBytes),
        },
      },
    );
    await installInitialPlatformEnvelopeScope(installer, {
      platformContextId,
      ownerParticipantId: participantId,
      installationPrivacyDomainId: privacyDomainId,
      platformAuthorityEpoch: '1',
      environmentId,
      installationDigest,
      grantable: scope,
    });
    await writeFile(
      join(dataRoot, 'recovery-browser/envelope-selection.json'),
      JSON.stringify({
        participantId,
        privacyDomainId,
        targetParticipantId,
        targetPrivacyDomainId,
        platformContextId,
        envelopeId,
        crossEnvelopeId,
        scope,
      }),
      { mode: 0o444, flag: 'wx' },
    );
    // The password is not retained and the installer cannot be used by runtime services.
    await admin.query('alter role openpc_envelope_browser_installer nologin');
  } finally {
    await installer.end();
  }
  return platformContextId;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 3 || process.argv[2] !== 'preflight')
    throw new Error('Unsupported envelope browser fixture invocation');
  await envelopeBrowserInstallationInputs();
  process.stdout.write('OPENPC_ENVELOPE_BROWSER_INPUTS|PASS|source_authenticated\n');
}
