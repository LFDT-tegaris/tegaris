import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { canonicalJson, sha256 } from '../../services/control-api/src/configuration/digest.ts';

const fail = () => {
  throw new Error('OPS_EFFECTIVE_PROJECTION_INVALID');
};
const digest = /^sha256:[0-9a-f]{64}$/u;
const version = /^[A-Za-z0-9._-]{1,96}$/u;

/** Validate the I-JSON domain BEFORE using the accepted Control RFC8785
 * primitive (ECMAScript number/string serialization and UTF-16 key ordering).
 * No getters, toJSON, sparse arrays, implicit coercion, non-finite numbers,
 * lone surrogates, non-NFC text, inherited members or cycles can enter it. */
export function effectiveProjectionCanonicalJson(value) {
  const active = new Set();
  let nodes = 0;
  function visit(item, depth) {
    if (++nodes > 20000 || depth > 32) fail();
    if (item === null || typeof item === 'boolean') return;
    if (typeof item === 'number') {
      if (!Number.isFinite(item)) fail();
      return;
    }
    if (typeof item === 'string') {
      if (!item.isWellFormed() || item !== item.normalize('NFC')) fail();
      return;
    }
    if (!item || typeof item !== 'object' || active.has(item)) fail();
    active.add(item);
    const array = Array.isArray(item);
    if (Object.getPrototypeOf(item) !== (array ? Array.prototype : Object.prototype)) fail();
    const descriptors = Object.getOwnPropertyDescriptors(item);
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== 'string')) fail();
    if (array && keys.length !== item.length + 1) fail();
    for (const key of keys) {
      if (array && key === 'length') continue;
      const descriptor = descriptors[key];
      if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail();
      if (array && (!/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= item.length)) fail();
      visit(key, depth + 1);
      visit(descriptor.value, depth + 1);
    }
    active.delete(item);
  }
  visit(value, 0);
  const text = canonicalJson(value);
  if (Buffer.byteLength(text) > 1048576) fail();
  return text;
}

function exact(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  if (Object.keys(value).sort().join('\0') !== [...names].sort().join('\0')) fail();
}

/** Pure preimage calculation, NOT verification or generation admission.
 * Inputs must eventually come from the canonical live source-specific readers.
 * This function deliberately returns no effectiveDigest, COMPLETE, ready or
 * verified flag: even a structurally complete collection is not authenticated.
 *
 * Preimage = the exact closed configuration with generation.contentDigest
 * removed, preserving generation/base IDs and every other semantic member.
 * Each SecretRef is replaced IN PLACE with {referenceFingerprint,version,
 * fingerprint}. Reference fingerprints hash the exact UTF-8 opaque reference;
 * fingerprints are resolver-issued opaque version identities, never hashes of
 * secret material. Qualification values must equal the configured setting and
 * bind the named profile's exact slot and qualification reference. Signature
 * envelopes and source documents are not configuration members and are rejected
 * by the closed schema, rather than silently stripped.
 */
export function prepareEffectiveProjection(input) {
  // Snapshot once, after rejecting observable/coercing object behavior.
  const value = JSON.parse(effectiveProjectionCanonicalJson(input));
  exact(value, ['schema', 'namedProfile', 'configuration', 'secretResolutions', 'qualifications']);
  const { schema, namedProfile, configuration, secretResolutions, qualifications } = value;
  if (schema.$id !== 'urn:openpc:schema:effective-configuration:1.0') fail();
  if (namedProfile.profile !== configuration.profile) fail();
  const ajv = new Ajv2020({ strict: false, allErrors: false });
  addFormats(ajv);
  if (!ajv.compile(schema)(configuration)) fail();
  const secretFields = Object.entries(schema.properties).flatMap(([section, node]) =>
    Object.entries(node.properties ?? {})
      .filter(([, field]) => field.$ref === '#/$defs/SecretRef')
      .map(([field]) => `${section}.${field}`),
  );
  const slots = schema.properties.qualificationInputBindings.required;
  exact(namedProfile.requiredSettingInputs, slots);
  if (!Array.isArray(secretResolutions) || !Array.isArray(qualifications)) fail();
  const preimage = structuredClone(configuration);
  delete preimage.generation.contentDigest;
  const seenSecrets = new Set();
  const seenQualifications = new Set();
  const missing = [];
  for (const item of secretResolutions) {
    exact(item, ['field', 'referenceFingerprint', 'version', 'fingerprint']);
    if (!secretFields.includes(item.field) || seenSecrets.has(item.field)) fail();
    seenSecrets.add(item.field);
    const [section, field] = item.field.split('.');
    const reference = configuration[section][field];
    if (
      !digest.test(item.referenceFingerprint) ||
      !digest.test(item.fingerprint) ||
      typeof item.version !== 'string' ||
      !version.test(item.version) ||
      ['latest', 'current'].includes(item.version.toLowerCase()) ||
      item.referenceFingerprint !== sha256(Buffer.from(reference, 'utf8')) ||
      reference.slice(reference.lastIndexOf('#') + 1) !== item.version
    )
      fail();
    preimage[section][field] = {
      referenceFingerprint: item.referenceFingerprint,
      version: item.version,
      fingerprint: item.fingerprint,
    };
  }
  for (const item of qualifications) {
    exact(item, ['setting', 'slot', 'reference', 'value']);
    if (!slots.includes(item.setting) || seenQualifications.has(item.setting)) fail();
    seenQualifications.add(item.setting);
    if (
      item.slot !== namedProfile.requiredSettingInputs[item.setting] ||
      item.reference !== configuration.qualificationInputBindings[item.setting] ||
      effectiveProjectionCanonicalJson(item.value) !==
        effectiveProjectionCanonicalJson(configuration.settings[item.setting])
    )
      fail();
  }
  for (const field of secretFields) {
    if (!seenSecrets.has(field)) {
      missing.push(`SECRET:${field}`);
      // Even diagnostics never disclose the source's sensitive reference name.
      const [section, member] = field.split('.');
      preimage[section][member] = {
        referenceFingerprint: sha256(Buffer.from(configuration[section][member], 'utf8')),
        resolution: 'UNRESOLVED',
      };
    }
  }
  for (const slot of slots)
    if (!seenQualifications.has(slot)) missing.push(`QUALIFICATION:${slot}`);
  const bytes = Buffer.from(effectiveProjectionCanonicalJson(preimage));
  return Object.freeze({
    state: 'UNVERIFIED',
    missing: Object.freeze(missing.sort()),
    // Distinct by API/name/domain from candidateDigest and site contentDigest.
    diagnosticProjectionDigest: sha256(bytes),
    preimageBytes: bytes,
  });
}
