import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import {
  canonicalDefinitionJson,
  definitionDigest,
} from '../src/business-transition/definition.ts';
import { preservedIdentityAllocations } from './workload-renewal-profile.mjs';

export const handoverAdmissionProjection =
  'schemas/canonical/workload-signing-handover-admission-authorization-v1.json';

/** Preserve ownership even when the implementation is absent from this checkout. */
export const handoverPreservedAllocations = Object.freeze([
  ...preservedIdentityAllocations,
  {
    schemaId: 24040,
    purposeCode: 377,
    purpose: 'pc.cose.identity-platform-scope-source-admission.v1',
    typeName: 'PlatformScopeSourceAdmissionV1',
    schemaDigest: 'sha256:b7945f2bfee9e5368a7c528432712bf56aa951d56d7d969d3bbeaa901b3a804e',
  },
  {
    schemaId: 24041,
    purposeCode: 378,
    purpose: 'pc.cose.event-record-fact-consumer-failure.v1',
    typeName: 'EventRecordFactConsumerFailureV1',
    schemaDigest: 'sha256:8bb03148a45367374d2a11629c6fff7c807584df1f4e407fceb6fb6f069ebe9f',
  },
]);

/** Exact authoritative entries retained from the canonical source. Other absent
 * producers retain reservations only and cannot be registered by tuple alone. */
export const handoverPreservedRegistryEntries = Object.freeze([
  {
    ownerLane: 'LANE-IDENTITY',
    projectionRefs: ['schemas/canonical/identity-platform-scope-source-admission-v1.json'],
    purpose: 'pc.cose.identity-platform-scope-source-admission.v1',
    purposeCode: 377,
    schemaDigest: 'sha256:b7945f2bfee9e5368a7c528432712bf56aa951d56d7d969d3bbeaa901b3a804e',
    schemaId: 24040,
    schemaVersion: '1.0.0',
    signatureContextRule:
      'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_SOURCE_SCOPE_AND_INDEPENDENT_EXACT_RECEIVING_TRUST',
    signed: true,
    typeName: 'PlatformScopeSourceAdmissionV1',
  },
  {
    ownerLane: 'LANE-CONTROL',
    projectionRefs: ['schemas/canonical/event-record-fact-consumer-failure-v1.json'],
    purpose: 'pc.cose.event-record-fact-consumer-failure.v1',
    purposeCode: 378,
    schemaDigest: 'sha256:8bb03148a45367374d2a11629c6fff7c807584df1f4e407fceb6fb6f069ebe9f',
    schemaId: 24041,
    schemaVersion: '1.0.0',
    signatureContextRule:
      'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_TAGGED_PAYLOAD_DEFINITION_AAD_AND_ADMITTED_SCOPED_FAILURE_SIGNER',
    signed: true,
    typeName: 'EventRecordFactConsumerFailureV1',
  },
]);

const overlaps = (left, right) =>
  ['schemaId', 'purposeCode', 'purpose', 'typeName'].some((key) => left[key] === right[key]);
const allocation = (definition) => ({
  schemaId: definition.schemaId,
  purposeCode: definition.purpose?.code,
  purpose: definition.purpose?.name,
  typeName: definition.typeName,
  schemaDigest: `sha256:${definitionDigest(definition).toString('hex')}`,
});

/** Exact controller-adopted tuple, not allocation by scanning for an unused ID. */
export function handoverAdmissionRegistration(definition, entries, otherDefinitions = []) {
  for (const reserved of handoverPreservedAllocations) {
    for (const other of entries) {
      if (!overlaps(other, reserved)) continue;
      const expected = handoverPreservedRegistryEntries.find(
        (item) => item.schemaId === reserved.schemaId,
      );
      if (!expected || canonicalDefinitionJson(other) !== canonicalDefinitionJson(expected))
        throw new Error('Preserved handover protocol ownership drift');
    }
    for (const other of otherDefinitions.map(allocation)) {
      if (
        overlaps(other, reserved) &&
        (!reserved.schemaDigest ||
          Object.entries(reserved).some(([key, value]) => other[key] !== value))
      )
        throw new Error('Preserved handover canonical ownership drift');
    }
    if (overlaps(allocation(definition), reserved))
      throw new Error('Preserved handover protocol allocation is reserved');
  }
  if (
    definition.name !== 'pc.identity.workload-signing-handover.admission-authorization' ||
    definition.typeName !== 'WorkloadSigningHandoverAdmissionAuthorizationV1' ||
    definition.schemaId !== 24042 ||
    definition.schemaVersion !== 1 ||
    definition.semanticVersion !== '1.0.0' ||
    definition.ownerLane !== 'LANE-IDENTITY' ||
    definition.extensionAuthority !== 'POST_C17_R1_COORDINATOR_ADOPTION' ||
    definition.purpose?.name !==
      'pc.cose.identity.workload-signing-handover-admission-authorization.v1' ||
    definition.purpose?.code !== 379 ||
    definition.cose?.algorithm !== 'Ed25519' ||
    definition.cose?.algorithmCode !== -8 ||
    definition.cose?.signatureProfileVersion !== 2 ||
    definition.cose?.contentType !== 'application/pc+cbor' ||
    definition.cose?.externalAadHex !== '7063706c616e653a636f73652d7369676e313a763200'
  )
    throw new Error('Handover admission allocation mismatch');
  if (
    otherDefinitions.some(
      (other) =>
        other.name === definition.name || overlaps(allocation(other), allocation(definition)),
    )
  )
    throw new Error('Handover admission canonical allocation collision');
  const entry = {
    ownerLane: definition.ownerLane,
    projectionRefs: [handoverAdmissionProjection],
    purpose: definition.purpose.name,
    purposeCode: definition.purpose.code,
    schemaDigest: `sha256:${definitionDigest(definition).toString('hex')}`,
    schemaId: definition.schemaId,
    schemaVersion: definition.semanticVersion,
    signatureContextRule:
      'PC_COSE_SIGN1_PROFILE_2_ED25519_EXACT_ADMISSION_AUTHORIZATION_AND_EXPLICIT_SCOPED_IDENTITY_TRUST',
    signed: true,
    typeName: definition.typeName,
  };
  const matches = entries.filter(
    (item) => overlaps(item, entry) || item.projectionRefs?.includes(handoverAdmissionProjection),
  );
  if (
    matches.length > 1 ||
    matches.some((item) => canonicalDefinitionJson(item) !== canonicalDefinitionJson(entry))
  )
    throw new Error('Handover admission allocation collision or frozen definition drift');
  return {
    entry,
    context: {
      schemaId: definition.schemaId,
      schemaVersion: 1,
      purpose: entry.purpose,
      purposeCode: entry.purposeCode,
      definitionDigest: entry.schemaDigest,
      contentType: definition.cose.contentType,
      externalAadHex: definition.cose.externalAadHex,
      signatureProfileVersion: 2,
      fields: definition.fields,
    },
  };
}

export async function registerHandoverAdmissionProfile(registry, root, emit) {
  const definition = JSON.parse(await readFile(new URL(handoverAdmissionProjection, root), 'utf8'));
  const others = [];
  for (const reference of new Set(
    registry.entries.flatMap((entry) => entry.projectionRefs ?? []),
  )) {
    if (
      reference !== handoverAdmissionProjection &&
      reference.startsWith('schemas/canonical/') &&
      reference.endsWith('.json')
    )
      others.push(JSON.parse(await readFile(new URL(reference, root), 'utf8')));
  }
  const { entry, context } = handoverAdmissionRegistration(definition, registry.entries, others);
  if (!registry.entries.some((item) => item.schemaId === entry.schemaId))
    registry.entries.push(entry);
  const path = new URL('../src/workload-signing-handover/generated.ts', import.meta.url);
  const fields = definition.fields
    .map(
      (field) =>
        `readonly ${field.name}: ${field.type === 'literal' ? JSON.stringify(field.value) : 'string'};`,
    )
    .join('\n');
  const source = `// Generated from ${handoverAdmissionProjection}. Do not edit.\nexport const handoverAdmissionAuthorizationContext = ${JSON.stringify(context, null, 2)} as const;\nexport interface HandoverAdmissionAuthorization {\n${fields}\n}\n`;
  await emit(
    path,
    await format(source, { ...(await resolveConfig(fileURLToPath(path))), parser: 'typescript' }),
  );
}
