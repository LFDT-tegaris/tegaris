import {
  bindTestFactCandidateDatabaseReference,
  testFactCandidateDatabaseConsumer,
} from './installation-consumer-bindings.mjs';
import { InstallationConfigError } from './installation-config-inputs.mjs';

const fail = (reason) => {
  throw new InstallationConfigError(reason, 'OPS_TEST_SECRET_PROVIDER_INVALID');
};

function dataMembers(value) {
  if (
    value === null ||
    typeof value !== 'object' ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    fail('BINDING_INVALID');
  const members = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(members).some(
      (key) => typeof key !== 'string' || !Object.hasOwn(members[key], 'value'),
    )
  )
    fail('BINDING_INVALID');
  return members;
}

/** Descriptor equality restricts the fixture; it does NOT authenticate a caller. */
function exactBinding(input) {
  try {
    const members = dataMembers(input);
    const binding = bindTestFactCandidateDatabaseReference(
      members.reference?.value,
      members.version?.value,
    );
    if (
      Reflect.ownKeys(members).length !== Object.keys(binding).length ||
      Object.entries(binding).some(([key, value]) => members[key]?.value !== value)
    )
      fail('BINDING_INVALID');
    return binding;
  } catch {
    // Includes malformed JS descriptors; never forward an input object's error.
    fail('BINDING_INVALID');
  }
}

/** Accept only a direct URI for the committed consumer. Query options could
 * override the endpoint, role or connection behavior, so this fixture has none. */
function validateMaterial(bytes, binding) {
  let text;
  let url;
  let password;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    url = new URL(text);
    password = decodeURIComponent(url.password);
  } catch {
    fail('MATERIAL_INVALID');
  }
  if (
    !['postgres:', 'postgresql:'].includes(url.protocol) ||
    url.username !== binding.databaseRole ||
    url.hostname !== binding.databaseHost ||
    url.port !== String(binding.databasePort) ||
    url.pathname !== `/${binding.databaseName}` ||
    url.search !== '' ||
    url.hash !== '' ||
    password.length === 0 ||
    Buffer.byteLength(password, 'utf8') > 1024 ||
    /[\s\p{Cc}\p{Cf}]/u.test(password) ||
    text !==
      `${url.protocol}//${binding.databaseRole}:${url.password}@${binding.databaseHost}:${binding.databasePort}/${binding.databaseName}`
  )
    fail('MATERIAL_INVALID');
}

/**
 * A single-version external TEST fixture, never a network service or production
 * adapter. The caller supplies synthetic DSN bytes in memory, owns that input
 * buffer and must erase it. This provider copies it and never persists material.
 *
 * withMaterial is an internal handoff for the integrator-owned authenticated
 * workload delivery path. Neither its request descriptor nor its callback is
 * identity evidence. That owner must authenticate LS-FACT-BRIDGE and enforce the
 * committed read-only EPHEMERAL_MEMORY mount, UID/GID and actual consumed value.
 * Do not expose this function directly to an unauthenticated workload.
 *
 * revoke/reset are terminal for this instance and immediately erase owned byte
 * buffers, including an in-flight handoff. New fixtures need a new instance;
 * there is no re-enable, replacement, stale-version fallback or persistence.
 * Buffer erasure does not promise erasure of JavaScript VM or consumer copies.
 */
export function createTestSecretProvider(bindingInput, syntheticMaterial) {
  const binding = exactBinding(bindingInput);
  let material;
  if (syntheticMaterial !== undefined) {
    try {
      if (
        !(syntheticMaterial instanceof Uint8Array) ||
        syntheticMaterial.byteLength === 0 ||
        syntheticMaterial.byteLength > 4096
      )
        fail('MATERIAL_INVALID');
      material = Buffer.from(syntheticMaterial);
      validateMaterial(material, binding);
    } catch {
      material?.fill(0);
      fail('MATERIAL_INVALID');
    }
  }
  let lifecycle = material === undefined ? 'MISSING' : 'ACTIVE';
  let handoff;

  function requireMaterial() {
    if (lifecycle !== 'ACTIVE') fail(`MATERIAL_${lifecycle}`);
  }

  function erase(next) {
    material?.fill(0);
    material = undefined;
    handoff?.fill(0);
    // Terminal state survives repeated cleanup; reset cannot undo revocation.
    if (lifecycle !== 'REVOKED' && lifecycle !== 'RESET') lifecycle = next;
  }

  return Object.freeze({
    describe() {
      return Object.freeze({
        profile: testFactCandidateDatabaseConsumer.profile,
        providerId: testFactCandidateDatabaseConsumer.providerId,
        synthetic: true,
        providerState: lifecycle,
        state: 'BLOCKED',
        startupAllowed: false,
        workloadAuthentication: 'UNVERIFIED',
        mountDelivery: 'UNVERIFIED',
      });
    },
    async withMaterial(request, consume) {
      const requested = exactBinding(request);
      if (requested.reference !== binding.reference || requested.version !== binding.version)
        fail('REFERENCE_MISMATCH');
      requireMaterial();
      if (typeof consume !== 'function') fail('HANDOFF_INVALID');
      if (handoff !== undefined) fail('HANDOFF_BUSY');
      // Recheck the actual owned bytes immediately before handing them off.
      validateMaterial(material, binding);
      const bytes = Buffer.from(material);
      handoff = bytes;
      try {
        // No callback result or exception is allowed into public metadata.
        await consume(bytes);
        requireMaterial();
      } catch {
        requireMaterial();
        fail('HANDOFF_FAILED');
      } finally {
        bytes.fill(0);
        handoff = undefined;
      }
    },
    revoke() {
      erase('REVOKED');
    },
    reset() {
      erase('RESET');
    },
  });
}
