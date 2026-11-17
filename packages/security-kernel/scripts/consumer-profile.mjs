import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import { definitionDigest } from '../src/business-transition/definition.ts';

export async function registerConsumerProfile(registry, root, emit) {
  const projection = 'schemas/canonical/fact-consumer-profile-v1.json';
  const definition = JSON.parse(await readFile(new URL(projection, root), 'utf8'));
  if (
    definition.schemaId !== 24006 ||
    definition.purpose.code !== 343 ||
    definition.schemaVersion !== 1 ||
    definition.semanticVersion !== '1.0.0' ||
    definition.typeName !== 'FactConsumerProfileV1'
  )
    throw new Error('Fact consumer profile allocation mismatch');
  const entry = {
    ownerLane: 'LANE-CONTROL',
    projectionRefs: [projection],
    purpose: definition.purpose.name,
    purposeCode: definition.purpose.code,
    schemaDigest: `sha256:${definitionDigest(definition).toString('hex')}`,
    schemaId: definition.schemaId,
    schemaVersion: definition.semanticVersion,
    signatureContextRule:
      'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_TAGGED_PAYLOAD_DEFINITION_AAD_AND_HOST_ADMITTED_CONSUMER_KEY',
    signed: true,
    typeName: definition.typeName,
  };
  for (const item of registry.entries) {
    if (
      item.schemaId === entry.schemaId ||
      item.purpose === entry.purpose ||
      item.purposeCode === entry.purposeCode ||
      item.typeName === entry.typeName
    ) {
      if (
        item.schemaId !== entry.schemaId ||
        item.purpose !== entry.purpose ||
        item.purposeCode !== entry.purposeCode ||
        item.typeName !== entry.typeName ||
        item.schemaVersion !== entry.schemaVersion ||
        item.schemaDigest !== entry.schemaDigest
      )
        throw new Error('Fact consumer profile allocation collision or definition drift');
    }
  }
  const index = registry.entries.findIndex((item) => item.schemaId === entry.schemaId);
  if (index < 0) registry.entries.push(entry);
  else registry.entries[index] = entry;
  const path = new URL('../src/fact-consumer/generated.ts', import.meta.url);
  const context = {
    ...definition.cose,
    schemaId: definition.schemaId,
    schemaVersion: definition.schemaVersion,
    purposeCode: definition.purpose.code,
    definitionDigest: entry.schemaDigest,
    fields: definition.fields,
  };
  await emit(
    path,
    await format(
      `// Generated from ${projection}. Do not edit.\nexport const factConsumerProfileContext = ${JSON.stringify(context)} as const;\n`,
      { ...(await resolveConfig(fileURLToPath(path))), parser: 'typescript' },
    ),
  );
  await emit(
    new URL('services/fact-service/src/consumer_profile/generated.rs', root),
    '// Generated from schemas/canonical/fact-consumer-profile-v1.json. Do not edit.\n' +
      `pub(super) const DEFINITION_DIGEST: &str =\n    "${entry.schemaDigest.slice(7)}";\n` +
      `pub(super) const SCHEMA_ID: u64 = ${entry.schemaId};\n` +
      `pub(super) const PURPOSE_CODE: u64 = ${entry.purposeCode};\n`,
  );
}

/** Source-owned exhausted-delivery evidence; separate from installation policy. */
export async function registerConsumerFailure(registry, root, emit) {
  const projection = 'schemas/canonical/fact-consumer-failure-v1.json';
  const definition = JSON.parse(await readFile(new URL(projection, root), 'utf8'));
  if (
    definition.schemaId !== 24007 ||
    definition.purpose.code !== 344 ||
    definition.schemaVersion !== 1 ||
    definition.semanticVersion !== '1.0.0' ||
    definition.typeName !== 'FactConsumerFailureV1'
  )
    throw new Error('Fact consumer failure allocation mismatch');
  const entry = {
    ownerLane: 'LANE-CONTROL',
    projectionRefs: [projection],
    purpose: definition.purpose.name,
    purposeCode: definition.purpose.code,
    schemaDigest: `sha256:${definitionDigest(definition).toString('hex')}`,
    schemaId: definition.schemaId,
    schemaVersion: definition.semanticVersion,
    signatureContextRule:
      'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_TAGGED_PAYLOAD_DEFINITION_AAD_AND_ADMITTED_SCOPED_FAILURE_SIGNER',
    signed: true,
    typeName: definition.typeName,
  };
  for (const item of registry.entries) {
    if (
      item.schemaId === entry.schemaId ||
      item.purpose === entry.purpose ||
      item.purposeCode === entry.purposeCode ||
      item.typeName === entry.typeName
    ) {
      for (const key of [
        'schemaId',
        'purpose',
        'purposeCode',
        'typeName',
        'schemaVersion',
        'schemaDigest',
      ])
        if (item[key] !== entry[key])
          throw new Error('Fact consumer failure allocation collision or definition drift');
    }
  }
  const index = registry.entries.findIndex((item) => item.schemaId === entry.schemaId);
  if (index < 0) registry.entries.push(entry);
  else registry.entries[index] = entry;
  const context = {
    ...definition.cose,
    schemaId: definition.schemaId,
    schemaVersion: definition.schemaVersion,
    purposeCode: definition.purpose.code,
    definitionDigest: entry.schemaDigest,
    fields: definition.fields,
  };
  await emit(
    new URL('services/fact-service/src/consumer_profile/failure_generated.rs', root),
    '// Generated from schemas/canonical/fact-consumer-failure-v1.json. Do not edit.\n' +
      `pub(super) const DEFINITION_DIGEST: &str =\n    "${entry.schemaDigest.slice(7)}";\n` +
      `pub(super) const SCHEMA_ID: u64 = ${entry.schemaId};\n` +
      `pub(super) const PURPOSE_CODE: u64 = ${entry.purposeCode};\n`,
  );
  const path = new URL('../src/fact-consumer/failure-generated.ts', import.meta.url);
  await emit(
    path,
    await format(
      `// Generated from ${projection}. Do not edit.\nexport const factConsumerFailureContext = ${JSON.stringify(context)} as const;\n`,
      { ...(await resolveConfig(fileURLToPath(path))), parser: 'typescript' },
    ),
  );
}

/** Installed workload recipient binding, independent from evidence consumers. */
export async function registerSecretRecipientProfile(registry, root, emit) {
  const projection = 'schemas/canonical/secret-recipient-profile-v1.json';
  const definition = JSON.parse(await readFile(new URL(projection, root), 'utf8'));
  if (
    definition.schemaId !== 24008 ||
    definition.purpose.code !== 345 ||
    definition.schemaVersion !== 1 ||
    definition.semanticVersion !== '1.0.0' ||
    definition.typeName !== 'SecretRecipientProfileV1'
  )
    throw new Error('Secret recipient profile allocation mismatch');
  const entry = {
    ownerLane: 'LANE-CONTROL',
    projectionRefs: [projection],
    purpose: definition.purpose.name,
    purposeCode: definition.purpose.code,
    schemaDigest: `sha256:${definitionDigest(definition).toString('hex')}`,
    schemaId: definition.schemaId,
    schemaVersion: definition.semanticVersion,
    signatureContextRule:
      'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_TAGGED_PAYLOAD_DEFINITION_AAD_AND_ADMITTED_INSTALLATION_ISSUER',
    signed: true,
    typeName: definition.typeName,
  };
  for (const item of registry.entries) {
    if (
      item.schemaId === entry.schemaId ||
      item.purpose === entry.purpose ||
      item.purposeCode === entry.purposeCode ||
      item.typeName === entry.typeName
    ) {
      for (const key of [
        'schemaId',
        'purpose',
        'purposeCode',
        'typeName',
        'schemaVersion',
        'schemaDigest',
      ])
        if (item[key] !== entry[key])
          throw new Error('Secret recipient profile allocation collision or definition drift');
    }
  }
  const index = registry.entries.findIndex((item) => item.schemaId === entry.schemaId);
  if (index < 0) registry.entries.push(entry);
  else registry.entries[index] = entry;
  const context = {
    ...definition.cose,
    schemaId: definition.schemaId,
    schemaVersion: definition.schemaVersion,
    purposeCode: definition.purpose.code,
    definitionDigest: entry.schemaDigest,
    fields: definition.fields,
  };
  const path = new URL('../src/secret-recipient/generated.ts', import.meta.url);
  await emit(
    path,
    await format(
      `// Generated from ${projection}. Do not edit.\nexport const secretRecipientContext = ${JSON.stringify(context)} as const;\n`,
      { ...(await resolveConfig(fileURLToPath(path))), parser: 'typescript' },
    ),
  );
}
