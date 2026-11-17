import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import {
  canonicalDefinitionJson,
  definitionDigest,
} from '../src/business-transition/definition.ts';
import { workloadRenewalAuthorizationContext } from '../src/workload-renewal/generated-authorization.ts';

const projection =
  'schemas/canonical/workload-renewal-signing-profiles/policy-authorization-v2.json';
export const workloadRenewalTrustFields = Object.freeze([
  ['participantId', 'uuid'],
  ['privacyDomainId', 'uuid'],
  ['environmentId', 'identifier'],
  ['principalId', 'uuid'],
  ['workloadId', 'workload'],
  ['familyId', 'uuid'],
  ['familySecurityEpoch', 'unsigned'],
  ['participantSecurityInvalidationEpoch', 'unsigned'],
  ['keySecurityGeneration', 'positive'],
  ['signerId', 'hash'],
  ['publicKeySpkiDer', 'p256spki'],
  ['keyEpoch', 'positive'],
  ['validFromNs', 'nanos'],
  ['validUntilNs', 'nanos'],
  ['providerQualificationDigest', 'hash'],
  ['admissionKind', 'admissionKind'],
  ['admissionReference', 'admissionReference'],
  ['admissionDigest', 'hash'],
  ['secretClass', 'secretClass'],
  ['secretReference', 'secretReference'],
  ['secretVersion', 'secretVersion'],
]);
export function workloadRenewalSigningProfileRegistration(input) {
  const expected = {
    profileId: 'pc.identity.workload-renewal.policy-authorization.v1',
    profileVersion: 2,
    schemaId: workloadRenewalAuthorizationContext.schemaId,
    schemaVersion: 1,
    schemaDefinitionDigest: workloadRenewalAuthorizationContext.definitionDigest,
    purpose: workloadRenewalAuthorizationContext.purpose,
    purposeCode: 376,
    authorizationMode: 'POLICY_AUTHORIZED',
    actionIntentId: 'ACT-IDENTITY_RENEW_WORKLOAD_CREDENTIAL-V1',
    catalogOperationId: 'ID-OP-WORKLOAD-RENEWAL-ADMIT',
    signedArtifactProfileVersion: 1,
    trustDomain: 'pc.identity.workload-renewal-signing-trust.v2',
    trustFields: workloadRenewalTrustFields,
    securityOwners: {
      familySecurityEpoch: 'control.workload_credential_family.security_epoch',
      participantSecurityInvalidationEpoch:
        'latest control.participant_lifecycle_transition.new_epoch where mutation=ARCHIVE; zero only for authoritative absence',
      keySecurityGeneration:
        'control.business_signing_key_state.row_version under its closed key lifecycle',
      keyEpoch: 'control.business_signing_key.key_epoch',
    },
    currentUse:
      'Exact admitted selection and current key lifecycle, provider qualification, family/current verified transport credential, Participant/principal state and current policy/instance/runtime permission are separate mandatory fences; historical original transport credential grants no current permission.',
    consumerAdmission:
      'TS, SQL and native readers must prove this exact profile and canonical trust before selection; mixed or missing capability denies.',
  };
  if (canonicalDefinitionJson(input) !== canonicalDefinitionJson(expected))
    throw new Error('Unadmitted renewal signing trust profile');
  return {
    profile: input,
    canonical: canonicalDefinitionJson(input),
    digest: `sha256:${definitionDigest(input).toString('hex')}`,
  };
}
/** Unsigned generated descriptor, not an authorization or registry allocation. */
export async function registerWorkloadRenewalSigningProfile(root, emit) {
  const selected = workloadRenewalSigningProfileRegistration(
    JSON.parse(await readFile(new URL(projection, root), 'utf8')),
  );
  const path = new URL('../src/workload-renewal/generated-signing.ts', import.meta.url);
  await emit(
    path,
    await format(
      `// Generated from ${projection}. Do not edit.\nexport const workloadRenewalSigningProfile = ${JSON.stringify(selected.profile, null, 2)} as const;\nexport const workloadRenewalSigningProfileCanonicalJson = ${JSON.stringify(selected.canonical)};\nexport const workloadRenewalSigningProfileDigest = ${JSON.stringify(selected.digest)};\n`,
      { ...(await resolveConfig(fileURLToPath(path))), parser: 'typescript' },
    ),
  );
  const rust = `// Generated from ${projection}. Do not edit.\npub const SIGNING_PROFILE_DIGEST: &str =\n    "${selected.digest}";\npub const SIGNING_PROFILE_VERSION: u64 = 2;\npub const SIGNING_TRUST_DOMAIN: &str = "${selected.profile.trustDomain}";\npub const SIGNING_TRUST_FIELDS: &[(&str, &str)] = &[\n${workloadRenewalTrustFields.map(([name, type]) => `    ("${name}", "${type}"),`).join('\n')}\n];\n`;
  await emit(
    new URL('crates/pc-policy-core/src/workload_renewal/generated_signing.rs', root),
    rust,
  );
}
