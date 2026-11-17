import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import { registerEvidenceArchiveProfiles } from './evidence-archive-profiles.mjs';
import { registerNotificationProfiles } from './notification-profiles.mjs';
import { registerOperationsConfigurationProfiles } from './operations-configuration-profiles.mjs';
import { registerEvidenceExportProfile } from './evidence-export-profile.mjs';
import { registerEvidenceKmsProfiles } from './generate-evidence-kms.mjs';
import { registerIdentityEnvelopeProfile } from './identity-envelope-profile.mjs';
import { registerWorkloadRenewalProfiles } from './workload-renewal-profile.mjs';
import { registerWorkloadRenewalSigningProfile } from './workload-renewal-signing-profile.mjs';
import { registerHandoverAdmissionProfile } from './handover-admission-profile.mjs';
import {
  registerConsumerProfile,
  registerConsumerFailure,
  registerSecretRecipientProfile,
} from './consumer-profile.mjs';

import {
  canonicalDefinitionJson,
  definitionDigest,
} from '../src/business-transition/definition.ts';

const root = new URL('../../../', import.meta.url);
const registryPath = new URL('schemas/json/schema-identity-registry.json', root);
const registry = JSON.parse(await readFile(registryPath, 'utf8'));
const definitions = new Map();
async function emit(path, bytes) {
  if (process.argv.includes('--check')) {
    if ((await readFile(path, 'utf8').catch(() => '')) !== bytes)
      throw new Error(`Stale control receipt projection: ${fileURLToPath(path)}`);
  } else await writeFile(path, bytes);
}
for (const version of [1, 2]) {
  const projection = `schemas/canonical/control-business-transition-receipt-v${version}.json`;
  const definition = JSON.parse(await readFile(new URL(projection, root), 'utf8'));
  if (
    definition.name !== 'pc.control.business-transition-receipt' ||
    definition.schemaId !== 24001 ||
    definition.schemaVersion !== version ||
    definition.semanticVersion !== `${version}.0.0` ||
    definition.purpose.code !== 338 ||
    definition.purpose.name !== 'pc.cose.control-business-transition.v1' ||
    definition.ownerLane !== 'LANE-CONTROL' ||
    definition.cose.protected['101'] !== version
  )
    throw new Error('Receipt allocation changed; a new admitted version is required');
  if (version === 2) {
    const v1 = structuredClone(definitions.get(1).definition);
    v1.schemaVersion = 2;
    v1.semanticVersion = '2.0.0';
    v1.types.OutboxRefs.minItems = 0;
    v1.cose.protected['101'] = 2;
    if (canonicalDefinitionJson(v1) !== canonicalDefinitionJson(definition))
      throw new Error('Receipt v2 changes more than its adopted zero-event cardinality');
  }
  const digest = `sha256:${definitionDigest(definition).toString('hex')}`;
  const entry = {
    ownerLane: definition.ownerLane,
    projectionRefs: [projection],
    purpose: definition.purpose.name,
    purposeCode: definition.purpose.code,
    schemaDigest: digest,
    schemaId: definition.schemaId,
    schemaVersion: definition.semanticVersion,
    signatureContextRule:
      'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_TAGGED_PAYLOAD_DEFINITION_PROFILE_AAD_AND_ADMITTED_CONTROL_KEY',
    signed: true,
    typeName: `ControlBusinessTransitionReceiptV${version}`,
  };
  for (const item of registry.entries) {
    if (
      item.schemaId === entry.schemaId ||
      item.purpose === entry.purpose ||
      item.purposeCode === entry.purposeCode ||
      item.typeName === entry.typeName
    ) {
      const admittedVersion = [1, 2].find(
        (v) =>
          item.schemaVersion === `${v}.0.0` &&
          item.typeName === `ControlBusinessTransitionReceiptV${v}`,
      );
      if (
        item.schemaId !== entry.schemaId ||
        item.purpose !== entry.purpose ||
        item.purposeCode !== entry.purposeCode ||
        item.ownerLane !== entry.ownerLane ||
        admittedVersion === undefined
      )
        throw new Error('Control receipt registry allocation collision');
    }
  }
  const existing = registry.entries.findIndex(
    (item) => item.schemaId === entry.schemaId && item.schemaVersion === entry.schemaVersion,
  );
  if (existing === -1) registry.entries.push(entry);
  else {
    if (registry.entries[existing].schemaDigest !== digest)
      throw new Error('Frozen control receipt definition changed without a new schema version');
    registry.entries[existing] = entry;
  }
  const cose = definition.cose;
  const context = {
    contentType: cose.protected['3'],
    externalAadHex: cose.externalAadHex,
    purpose: definition.purpose.name,
    purposeCode: definition.purpose.code,
    schemaId: definition.schemaId,
    schemaVersion: definition.schemaVersion,
    signatureProfileVersion: cose.protected['103'],
    definitionDigest: digest,
  };
  const outputPath = new URL(
    `../src/business-transition/generated${version === 1 ? '' : '-v2'}.ts`,
    import.meta.url,
  );
  const source = `// Generated from ${projection}. Do not edit.\nexport const businessTransitionCoseContext${version === 1 ? '' : 'V2'} = Object.freeze(${JSON.stringify(context, null, 2)} as const);\n`;
  await emit(
    outputPath,
    await format(source, {
      ...(await resolveConfig(fileURLToPath(outputPath))),
      parser: 'typescript',
    }),
  );
  definitions.set(version, { definition, digest });
}
await registerEvidenceArchiveProfiles(registry, root, emit);
await registerConsumerProfile(registry, root, emit);
await registerConsumerFailure(registry, root, emit);
await registerSecretRecipientProfile(registry, root, emit);
await registerNotificationProfiles(registry, root, emit);
await registerOperationsConfigurationProfiles(registry, root, emit);
await registerEvidenceExportProfile(registry, root, emit);
await registerEvidenceKmsProfiles(registry, root, emit);
await registerIdentityEnvelopeProfile(registry, root, emit);
await registerWorkloadRenewalProfiles(registry, root, emit);
await registerWorkloadRenewalSigningProfile(root, emit);
await registerHandoverAdmissionProfile(registry, root, emit);
await emit(registryPath, JSON.stringify(registry, null, 2) + '\n');

// Explicit admission list: adding a file alone never enrolls a transition profile.
const admittedProfileFiles = [
  'notification-endpoint-create-v1.json',
  'notification-endpoint-update-v1.json',
  'notification-endpoint-verify-v1.json',
  'notification-create-v1.json',
  'notification-acknowledge-v1.json',
  'work-item-create-v1.json',
  'work-item-update-v1.json',
  'work-item-claim-v1.json',
  'work-item-complete-v1.json',
  'indexer-profile-create-v1.json',
  'indexer-profile-update-v1.json',
  'indexer-profile-create-v2.json',
  'indexer-profile-update-v2.json',
  'evidence-hold-create-v1.json',
  'evidence-hold-release-v1.json',
  'evidence-participant-hold-create-v1.json',
  'evidence-participant-hold-release-v1.json',
  'evidence-deletion-local-v1.json',
  'evidence-deletion-batch-v1.json',
  'evidence-deletion-local-v2.json',
  'evidence-deletion-batch-v2.json',
  'evidence-deletion-raw-proof-v1.json',
  'evidence-deletion-projection-v1.json',
  'store-retirement-admit-v1.json',
  'runtime-artifact-disposition-v1.json',
  'evidence-deletion-runtime-artifact-v1.json',
  'retention-policy-activate-v1.json',
  'evidence-deletion-projection-v2.json',
  'evidence-deletion-projection-v3.json',
  'retention-policy-retire-v1.json',
  'workload-renewal-policy-create-v1.json',
  'workload-renewal-policy-revise-v1.json',
  'workload-renewal-policy-suspend-v1.json',
  'workload-renewal-policy-revoke-v1.json',
  'module-register-v1.json',
  'module-install-v1.json',
  'module-enable-v1.json',
  'module-disable-v1.json',
  'signing-rotation-advance-v1.json',
  'signing-rotation-recover-v1.json',
];
// Source contracts without an installed receipt/input/attempt owner are passive.
// Never merge this list into namespace selection, signer admission or SQL grants.
const preparedProfileFiles = ['workload-instance-admit-v1.json'];
if (preparedProfileFiles.some((name) => admittedProfileFiles.includes(name)))
  throw new Error('Prepared business profile also appears in the admitted catalogue');
async function projectProfiles(names) {
  const profiles = [];
  for (const name of names) {
    const profile = JSON.parse(
      await readFile(
        new URL(`schemas/canonical/business-transition-profiles/${name}`, root),
        'utf8',
      ),
    );
    const { digest } = definitions.get(name.startsWith('signing-rotation-') ? 2 : 1);
    const profileDigest = `sha256:${definitionDigest(profile).toString('hex')}`;
    if (
      profile.definitionDigest !== profileDigest ||
      profile.schemaDefinitionDigest !== digest ||
      profile.sequenceNamespace !== 'CONTROL_BUSINESS_TRANSITION_V1'
    )
      throw new Error(`Unpinned business profile ${name}`);
    const preimage = Object.fromEntries(
      Object.entries(profile).filter(([key]) => key !== 'definitionDigest' && key !== 'signature'),
    );
    profiles.push({
      profileId: profile.profileId,
      profileVersion: profile.profileVersion,
      profileDigest,
      schemaDefinitionDigest: digest,
      actionIntentId: profile.actionIntentId,
      catalogOperationId: profile.catalogOperationId,
      resourceType: profile.resourceType,
      aggregateType: profile.aggregateType,
      sequenceNamespace: profile.sequenceNamespace,
      transitionKind: profile.transitionKind,
      definitionCanonicalJson: canonicalDefinitionJson(preimage),
    });
  }
  return profiles;
}
for (const [filename, exportName, names, classification] of [
  ['profiles.generated.ts', 'businessTransitionProfiles', admittedProfileFiles, 'admission'],
  [
    'profiles.prepared.generated.ts',
    'preparedBusinessTransitionProfiles',
    preparedProfileFiles,
    'PASSIVE preparation; not admission',
  ],
]) {
  const profiles = await projectProfiles(names);
  const profilesPath = new URL('../src/business-transition/' + filename, import.meta.url);
  const profileSource = await format(
    `// Generated from the explicit canonical business-transition profile ${classification} list. Do not edit.\nexport const ${exportName} = ${JSON.stringify(profiles, null, 2)} as const;\n`,
    { ...(await resolveConfig(fileURLToPath(profilesPath))), parser: 'typescript' },
  );
  if (process.argv.includes('--check')) {
    if ((await readFile(profilesPath, 'utf8').catch(() => '')) !== profileSource)
      throw new Error('Stale business profile projection');
  } else await writeFile(profilesPath, profileSource);
}
