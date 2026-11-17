import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import {
  canonicalDefinitionJson,
  definitionDigest,
} from '../src/business-transition/definition.ts';

/** Preserved protocol ownership survives a checkout missing the producer's
 * implementation. These are reservations, not a claim of current admission. */
export const preservedIdentityAllocations = Object.freeze([
  {
    schemaId: 24035,
    purposeCode: 372,
    purpose: 'pc.cose.control.database-recipient.v1',
    typeName: 'ControlDatabaseRecipientV1',
    schemaDigest: 'sha256:366594f98c257c7c209fc8f47fb3a370ce0d91d45dec69dda9056afc727de4ab',
  },
  {
    schemaId: 24036,
    purposeCode: 373,
    purpose: 'pc.cose.control.database-recipient.v2',
    typeName: 'ControlDatabaseRecipientV2',
    schemaDigest: 'sha256:452109b14c8114d3558efdf4175d26859ec50fdfc85b8beb863247127455d4f2',
  },
  {
    schemaId: 24037,
    purposeCode: 374,
    purpose: 'pc.cose.identity-platform-genesis-manifest.v1',
    typeName: 'PlatformGenesisManifestV1',
  },
]);

const allocations = Object.freeze([
  {
    kind: 'request',
    name: 'pc.identity.workload-renewal.request',
    typeName: 'WorkloadRenewalRequestV1',
    schemaId: 24038,
    purposeCode: 375,
    purpose: 'pc.cose.identity.workload-renewal-request.v1',
    projection: 'schemas/canonical/workload-renewal-request-v1.json',
  },
  {
    kind: 'authorization',
    name: 'pc.identity.workload-renewal.policy-authorization',
    typeName: 'WorkloadRenewalPolicyAuthorizationV1',
    schemaId: 24039,
    purposeCode: 376,
    purpose: 'pc.cose.identity.workload-renewal-policy-authorization.v1',
    projection: 'schemas/canonical/workload-renewal-policy-authorization-v1.json',
  },
]);

/** The controller must adopt this exact mapping before the owning generator
 * invokes registration. Missing branch ancestry is never free allocation. */
export function workloadRenewalRegistration(definition, entries, otherDefinitions = []) {
  for (const reserved of preservedIdentityAllocations) {
    if (
      definition.schemaId === reserved.schemaId ||
      definition.purpose?.code === reserved.purposeCode ||
      definition.purpose?.name === reserved.purpose ||
      definition.typeName === reserved.typeName
    )
      throw new Error('Preserved protocol allocation is reserved');
    for (const entry of entries) {
      if (
        entry.schemaId === reserved.schemaId ||
        entry.purposeCode === reserved.purposeCode ||
        entry.typeName === reserved.typeName
      ) {
        if (
          entry.schemaId !== reserved.schemaId ||
          entry.purposeCode !== reserved.purposeCode ||
          entry.purpose !== reserved.purpose ||
          entry.typeName !== reserved.typeName ||
          (reserved.schemaDigest && entry.schemaDigest !== reserved.schemaDigest)
        )
          throw new Error('Preserved protocol registry ownership drift');
      }
    }
    for (const other of otherDefinitions) {
      if (
        other.schemaId === reserved.schemaId ||
        other.purpose?.code === reserved.purposeCode ||
        other.typeName === reserved.typeName
      ) {
        if (
          other.schemaId !== reserved.schemaId ||
          other.purpose?.code !== reserved.purposeCode ||
          other.purpose?.name !== reserved.purpose ||
          other.typeName !== reserved.typeName ||
          (reserved.schemaDigest &&
            `sha256:${definitionDigest(other).toString('hex')}` !== reserved.schemaDigest)
        )
          throw new Error('Preserved canonical definition ownership drift');
      }
    }
  }
  const allocation = allocations.find((item) => item.name === definition.name);
  if (
    !allocation ||
    definition.schemaId !== allocation.schemaId ||
    definition.typeName !== allocation.typeName ||
    definition.purpose?.name !== allocation.purpose ||
    definition.purpose?.code !== allocation.purposeCode ||
    definition.ownerLane !== 'LANE-IDENTITY' ||
    definition.extensionAuthority !== 'POST_C17_R1_COORDINATOR_ADOPTION' ||
    definition.schemaVersion !== 1 ||
    definition.semanticVersion !== '1.0.0' ||
    definition.cose?.algorithm !== 'ES256' ||
    definition.cose?.signatureProfileVersion !== 2 ||
    definition.cose?.contentType !== 'application/pc+cbor' ||
    definition.cose?.externalAadHex !== '7063706c616e653a636f73652d7369676e313a763200'
  )
    throw new Error('Renewal protocol allocation mismatch');
  if (
    otherDefinitions.some(
      (other) =>
        other.name === definition.name ||
        other.typeName === definition.typeName ||
        other.schemaId === definition.schemaId ||
        other.purpose?.name === allocation.purpose ||
        other.purpose?.code === allocation.purposeCode,
    )
  )
    throw new Error('Renewal canonical definition allocation collision');
  const digest = `sha256:${definitionDigest(definition).toString('hex')}`;
  const entry = {
    ownerLane: 'LANE-IDENTITY',
    projectionRefs: [allocation.projection],
    purpose: allocation.purpose,
    purposeCode: allocation.purposeCode,
    schemaDigest: digest,
    schemaId: allocation.schemaId,
    schemaVersion: '1.0.0',
    signed: true,
    typeName: allocation.typeName,
    signatureContextRule:
      allocation.kind === 'request'
        ? 'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_RENEWAL_REQUEST_SUCCESSOR_KEY_PROOF_ONLY'
        : 'PC_COSE_SIGN1_PROFILE_2_ES256_EXACT_POLICY_AUTHORIZATION_AND_ADMITTED_CURRENT_IDENTITY_KEY',
  };
  const matches = entries.filter(
    (item) =>
      item.schemaId === entry.schemaId ||
      item.purposeCode === entry.purposeCode ||
      item.purpose === entry.purpose ||
      item.typeName === entry.typeName ||
      item.projectionRefs?.includes(allocation.projection),
  );
  if (
    matches.length > 1 ||
    matches.some((item) => canonicalDefinitionJson(item) !== canonicalDefinitionJson(entry))
  )
    throw new Error('Renewal allocation collision or frozen definition drift');
  return {
    allocation,
    entry,
    context: {
      schemaId: allocation.schemaId,
      schemaVersion: 1,
      purpose: allocation.purpose,
      purposeCode: allocation.purposeCode,
      definitionDigest: digest,
      contentType: definition.cose.contentType,
      externalAadHex: definition.cose.externalAadHex,
      signatureProfileVersion: 2,
      types: definition.types,
    },
  };
}

export async function registerWorkloadRenewalProfiles(registry, root, emit) {
  const registered = [];
  for (const allocation of allocations) {
    const definition = JSON.parse(await readFile(new URL(allocation.projection, root), 'utf8'));
    const others = [];
    for (const reference of new Set(
      registry.entries.flatMap((entry) => entry.projectionRefs ?? []),
    )) {
      if (
        reference !== allocation.projection &&
        reference.startsWith('schemas/canonical/') &&
        reference.endsWith('.json')
      )
        others.push(JSON.parse(await readFile(new URL(reference, root), 'utf8')));
    }
    const { entry, context } = workloadRenewalRegistration(definition, registry.entries, others);
    registered.push({ allocation, context });
    if (!registry.entries.some((item) => item.schemaId === entry.schemaId))
      registry.entries.push(entry);
    const path = new URL(
      `../src/workload-renewal/generated-${allocation.kind}.ts`,
      import.meta.url,
    );
    await emit(
      path,
      await format(
        `// Generated from ${allocation.projection}. Do not edit.\nexport const workloadRenewal${allocation.kind === 'request' ? 'Request' : 'Authorization'}Context = ${JSON.stringify(context, null, 2)} as const;\n`,
        {
          ...(await resolveConfig(fileURLToPath(path))),
          parser: 'typescript',
        },
      ),
    );
  }
  const scalar = {
    uuid: 'DomainUuid',
    H32: 'Hash32',
    u64: 'Unsigned',
    u64p: 'Positive',
    nanos: 'Nanos',
    id: 'Identifier',
    workload: 'Workload',
    requestProfile: 'RequestProfile',
    authorizationProfile: 'AuthorizationProfile',
    policyAuthorized: 'PolicyAuthorized',
    version1: 'VersionOne',
    requestBytes: 'RequestBytes',
    Signer: 'Signer',
  };
  let rust =
    '// Generated from the adopted canonical workload renewal definitions. Do not edit.\nuse super::*;\n\n';
  for (const { allocation, context } of registered) {
    const name = allocation.kind.toUpperCase();
    rust += `pub const ${name}_DEFINITION_DIGEST: &str =\n    "${context.definitionDigest}";\npub const ${name}_SCHEMA_ID: u64 = ${context.schemaId};\npub const ${name}_PURPOSE_CODE: u64 = ${context.purposeCode};\n\n`;
    for (const [type, fields] of Object.entries(context.types)) {
      const digest = type === 'Signer' ? 'None::<&str>' : `Some(${name}_DEFINITION_DIGEST)`;
      rust += `renewal_record!(${type}, ${digest},\n`;
      for (const field of fields.filter((field) => field.type !== 'definitionDigest')) {
        const fieldName = field.name.replace(/[A-Z]/gu, (letter) => `_${letter.toLowerCase()}`);
        if (!scalar[field.type]) throw new Error('Unadmitted renewal native scalar');
        rust += `    ${fieldName}: ${scalar[field.type]} => ${field.key},\n`;
      }
      rust += ');\n\n';
    }
  }
  await emit(
    new URL('crates/pc-policy-core/src/workload_renewal/generated.rs', root),
    rust.trimEnd() + '\n',
  );
}
