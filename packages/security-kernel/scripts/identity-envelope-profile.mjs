import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import {
  canonicalDefinitionJson,
  definitionDigest,
} from '../src/business-transition/definition.ts';

const projection = 'schemas/canonical/identity-authority-envelope-v1.json';
const signingProjection =
  'schemas/canonical/identity-envelope-signing-profiles/authority-envelope-v1.json';

export function identityEnvelopeProfileRegistration(profile, context) {
  const expected = {
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    schemaId: 24034,
    schemaVersion: 1,
    schemaDefinitionDigest: context.definitionDigest,
    purpose: 'pc.cose.identity-authority-envelope.v1',
    purposeCode: 371,
    actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
    catalogOperationId: 'ID-OP-ENVELOPE-ACTIVATE',
    aggregateType: 'authority-envelope',
  };
  if (canonicalDefinitionJson(profile) !== canonicalDefinitionJson(expected))
    throw new Error('Identity envelope signing profile allocation mismatch');
  return {
    profile,
    canonical: canonicalDefinitionJson(profile),
    digest: `sha256:${definitionDigest(profile).toString('hex')}`,
  };
}

/** Explicit coordinator adoption, not allocation by scanning for an unused ID.
 * Called by the existing canonical generator; a file alone cannot enroll. */
export function identityEnvelopeRegistration(definition, entries, otherCanonicalDefinitions = []) {
  if (
    definition.name !== 'pc.identity.authority-envelope' ||
    definition.typeName !== 'IdentityAuthorityEnvelopeV1' ||
    definition.schemaId !== 24034 ||
    definition.schemaVersion !== 1 ||
    definition.semanticVersion !== '1.0.0' ||
    definition.ownerLane !== 'LANE-IDENTITY' ||
    definition.extensionAuthority !== 'POST_C17_R1_COORDINATOR_ADOPTION' ||
    definition.purpose?.name !== 'pc.cose.identity-authority-envelope.v1' ||
    definition.purpose?.code !== 371 ||
    definition.cose?.signatureProfileVersion !== 2 ||
    definition.cose?.algorithm !== 'ES256' ||
    definition.cose?.contentType !== 'application/pc+cbor' ||
    definition.cose?.externalAadHex !== '7063706c616e653a636f73652d7369676e313a763200'
  )
    throw new Error('Identity envelope allocation mismatch');
  if (otherCanonicalDefinitions.some((other) => other.name === definition.name))
    throw new Error('Identity envelope canonical name collision');
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
      'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_TYPED_ENVELOPE_DEFINITION_AAD_AND_ADMITTED_IDENTITY_KEY',
    signed: true,
    typeName: definition.typeName,
  };
  const matches = entries.filter(
    (item) =>
      item.schemaId === entry.schemaId ||
      item.purpose === entry.purpose ||
      item.purposeCode === entry.purposeCode ||
      item.typeName === entry.typeName ||
      item.projectionRefs?.includes(projection),
  );
  if (
    matches.length > 1 ||
    matches.some((item) => canonicalDefinitionJson(item) !== canonicalDefinitionJson(entry))
  )
    throw new Error('Identity envelope allocation collision or frozen definition drift');
  return {
    entry,
    context: {
      schemaId: definition.schemaId,
      schemaVersion: definition.schemaVersion,
      purpose: entry.purpose,
      purposeCode: entry.purposeCode,
      definitionDigest: digest,
      contentType: definition.cose.contentType,
      externalAadHex: definition.cose.externalAadHex,
      signatureProfileVersion: definition.cose.signatureProfileVersion,
      types: definition.types,
    },
  };
}

export async function registerIdentityEnvelopeProfile(registry, root, emit) {
  const definition = JSON.parse(await readFile(new URL(projection, root), 'utf8'));
  const references = new Set(registry.entries.flatMap((entry) => entry.projectionRefs ?? []));
  const otherCanonicalDefinitions = [];
  for (const reference of references) {
    if (
      reference !== projection &&
      reference.startsWith('schemas/canonical/') &&
      reference.endsWith('.json')
    )
      otherCanonicalDefinitions.push(JSON.parse(await readFile(new URL(reference, root), 'utf8')));
  }
  const { entry, context } = identityEnvelopeRegistration(
    definition,
    registry.entries,
    otherCanonicalDefinitions,
  );
  if (!registry.entries.some((item) => item.schemaId === entry.schemaId))
    registry.entries.push(entry);
  const path = new URL('../src/identity-envelope/generated.ts', import.meta.url);
  const signing = identityEnvelopeProfileRegistration(
    JSON.parse(await readFile(new URL(signingProjection, root), 'utf8')),
    context,
  );
  const source = `// Generated from ${projection} and ${signingProjection}. Do not edit.\nexport const identityEnvelopeContext = ${JSON.stringify(context, null, 2)} as const;\nexport const identityEnvelopeSigningProfile = Object.freeze(${JSON.stringify(signing.profile, null, 2)} as const);\nexport const identityEnvelopeSigningProfileJson = ${JSON.stringify(signing.canonical)};\nexport const identityEnvelopeSigningProfileDigest = ${JSON.stringify(signing.digest)};\n`;
  await emit(
    path,
    await format(source, {
      ...(await resolveConfig(fileURLToPath(path))),
      parser: 'typescript',
    }),
  );
  await emit(
    new URL('crates/pc-policy-core/src/identity_envelope/generated.rs', root),
    `// Generated from ${projection}. Do not edit.\npub const DEFINITION_DIGEST: &str =\n    "${context.definitionDigest}";\npub const SCHEMA_ID: u64 = ${context.schemaId};\npub const PURPOSE_CODE: u64 = ${context.purposeCode};\n`,
  );
}
