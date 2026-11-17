import { withInstalledSecretRecipient } from '../../services/identity-service/src/domain/secret-recipient.ts';
import { bindTestFactCandidateDatabaseReference } from './installation-consumer-bindings.mjs';
import { InstallationConfigError } from './installation-config-inputs.mjs';
import { createTestFactSecretMount } from './test-fact-secret-mount.mjs';
import { createTestSecretProvider } from './test-secret-provider.mjs';

const CODE = 'OPS_TEST_FACT_SECRET_DELIVERY_INVALID';
const pinFields = [
  'signedBindingDigest',
  'installationDigest',
  'environmentId',
  'generation',
  'participantId',
  'privacyDomainId',
  'principalId',
  'workloadCredentialId',
  'workloadCredentialEpoch',
];
const optionFields = [
  'pool',
  'kernel',
  'installed',
  'rootPath',
  'reference',
  'version',
  'syntheticMaterial',
];
const failureCodes = new Set([
  'PC-IDENTITY-1006',
  'OPS_SECRET_UNRESOLVED',
  'OPS_TEST_SECRET_PROVIDER_INVALID',
  'OPS_TEST_FACT_SECRET_MOUNT_INVALID',
  CODE,
]);
const error = (reason) => new InstallationConfigError(reason, CODE);

function members(value) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    throw error('INPUT_INVALID');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(descriptors).some(
      (key) => typeof key !== 'string' || !Object.hasOwn(descriptors[key], 'value'),
    )
  )
    throw error('INPUT_INVALID');
  return Object.fromEntries(Object.entries(descriptors).map(([key, entry]) => [key, entry.value]));
}

function requestSnapshot(value) {
  try {
    const request = members(value);
    if (
      Object.keys(request).length !== 2 ||
      typeof request.reference !== 'string' ||
      typeof request.version !== 'string'
    )
      throw error('REQUEST_INVALID');
    return Object.freeze({ reference: request.reference, version: request.version });
  } catch {
    throw error('REQUEST_INVALID');
  }
}

function failureCode(value) {
  try {
    // Never read getters or forward raw error text, paths, SQL or causes.
    const code = Object.getOwnPropertyDescriptor(value, 'code')?.value;
    if (failureCodes.has(code)) return code;
    const message = Object.getOwnPropertyDescriptor(value, 'message')?.value;
    if (message === 'OPS_SECRET_UNRESOLVED') return message;
  } catch {
    /* An arbitrary thrown value is not a diagnostic contract. */
  }
  return 'UNCLASSIFIED';
}

/** Trusted TEST composition, loaded with the repository's `node --import tsx`.
 * Owns one provider copy and one exclusively reserved UID/GID-65532 tmpfs root.
 * The caller owns/erases its input buffer. Pins and database/kernel objects come
 * from the installation owner, never resolver request fields. There is no caller
 * authentication callback, provider injection, alternate mount or disk fallback.
 *
 * publish needs the actual TLS socket. The sole material publication is inside
 * withInstalledSecretRecipient; its post-use freshness/transaction rejection
 * also destroys this adapter's publication and provider. Failed/expired/disposed
 * instances are terminal. Cleanup uncertainty stays UNKNOWN and needs the root's
 * original runtime owner; this module never unlinks or takes over named paths.
 *
 * Expiry cleanup is an additional local timer, not an authority lease. Success
 * remains BLOCKED for consumer startup: no DB login/session lifecycle is supplied
 * here, and erasing bytes cannot revoke open files, VM copies or SQLx sessions.
 * Do not mount/start the consumer using this result before that owner is integrated.
 */
export function createTestFactSecretDelivery(input) {
  let options;
  let pins;
  let binding;
  try {
    options = members(input);
    if (
      Object.keys(options).length !== optionFields.length ||
      optionFields.some((key) => !Object.hasOwn(options, key))
    )
      throw error('INPUT_INVALID');
    const original = members(options.installed);
    if (
      Object.keys(original).length !== pinFields.length + 1 ||
      !Buffer.isBuffer(original.issuerSpkiDer) ||
      pinFields.some((key) => typeof original[key] !== 'string')
    )
      throw error('INPUT_INVALID');
    pins = Object.freeze({
      ...Object.fromEntries(pinFields.map((key) => [key, original[key]])),
      issuerSpkiDer: Buffer.from(original.issuerSpkiDer),
    });
    binding = bindTestFactCandidateDatabaseReference(options.reference, options.version);
  } catch {
    throw error('INPUT_INVALID');
  }

  let provider;
  let mount;
  let pending;
  let materialPublication;
  let timer;
  let deadline;
  let closed = false;
  let cleanupAttempted = false;
  let cleanupState = 'NOT_RUN';
  let publicationState = 'EMPTY';
  let recipientCheck = 'UNVERIFIED';
  // Keep the first original error privately, including a transaction failure.
  // Public diagnostics expose only its fixed phase/code and cleanup outcome.
  let firstFailure;
  let cleanupFailure;
  const remember = (cause, phase) => {
    firstFailure ??= { cause, phase, code: failureCode(cause) };
  };
  const uncertain = (cause, phase) => {
    cleanupFailure ??= { cause, phase, code: failureCode(cause) };
    cleanupState = 'UNKNOWN';
  };
  const rejection = (fallback) => {
    const result = error(firstFailure?.phase ?? fallback);
    result.failureCode = firstFailure?.code ?? CODE;
    result.cleanupState = cleanupState;
    result.cleanupFailure = cleanupFailure?.phase ?? null;
    result.cleanupFailureCode = cleanupFailure?.code ?? null;
    result.state = cleanupState === 'UNKNOWN' ? 'UNKNOWN' : 'BLOCKED';
    result.startupAllowed = false;
    return result;
  };
  const describe = () =>
    Object.freeze({
      profile: 'test',
      synthetic: true,
      state: cleanupState === 'UNKNOWN' ? 'UNKNOWN' : 'BLOCKED',
      startupAllowed: false,
      publicationState,
      recipientCheck,
      databaseSession: 'UNVERIFIED',
      providerState: provider?.describe().providerState ?? 'ABSENT',
      cleanupState,
      failure: firstFailure?.phase ?? null,
      failureCode: firstFailure?.code ?? null,
      cleanupFailure: cleanupFailure?.phase ?? null,
      cleanupFailureCode: cleanupFailure?.code ?? null,
    });

  function revokeProvider() {
    try {
      provider?.revoke();
    } catch (cause) {
      remember(cause, 'PROVIDER_CLEANUP_FAILED');
      uncertain(cause, 'PROVIDER_CLEANUP_FAILED');
    }
  }
  function cleanup() {
    if (cleanupAttempted) return;
    cleanupAttempted = true;
    closed = true;
    clearTimeout(timer);
    revokeProvider();
    try {
      mount?.dispose();
    } catch (cause) {
      remember(cause, 'MOUNT_CLEANUP_FAILED');
      uncertain(cause, 'MOUNT_CLEANUP_FAILED');
    }
    if (cleanupState !== 'UNKNOWN') cleanupState = 'ERASED';
    publicationState = cleanupState === 'UNKNOWN' ? 'UNKNOWN' : 'REVOKED';
  }
  function cleanupAfterPublication() {
    // Only the mount's active descriptor use can delay erasure. A stalled
    // post-use query/COMMIT must not retain already published bytes past expiry.
    if (materialPublication) void materialPublication.then(cleanup, cleanup);
    else cleanup();
  }
  function scheduleExpiry() {
    clearTimeout(timer);
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      remember(error('RECIPIENT_EXPIRED'), 'RECIPIENT_EXPIRED');
      closed = true;
      revokeProvider();
      cleanupAfterPublication();
      return;
    }
    timer = setTimeout(scheduleExpiry, Math.min(remaining, 2_147_483_647));
    timer.unref();
  }

  let phase = 'PROVIDER_CREATION_FAILED';
  try {
    provider = createTestSecretProvider(binding, options.syntheticMaterial);
    phase = 'MOUNT_CREATION_FAILED';
    mount = createTestFactSecretMount(options.rootPath, binding.reference, binding.version);
  } catch (cause) {
    remember(cause, phase);
    // A failed mount constructor may have reserved an inert claim before it
    // closed its descriptors. No returned handle grants us ownership to erase it.
    if (phase === 'MOUNT_CREATION_FAILED') uncertain(cause, 'MOUNT_CREATION_UNCERTAIN');
    cleanup();
    throw rejection(phase);
  }
  // Do not retain the caller's synthetic material through the options object.
  const pool = options.pool,
    kernel = options.kernel;
  options = undefined;

  async function publish(socket, request) {
    let phase = 'REQUEST_INVALID';
    try {
      const requested = requestSnapshot(request);
      phase = 'RECIPIENT_REJECTED';
      await withInstalledSecretRecipient(pool, kernel, socket, pins, requested, async (profile) => {
        phase = 'PUBLICATION_FAILED';
        if (closed) throw error('DELIVERY_CLOSED');
        if (profile.reference !== binding.reference || profile.version !== binding.version)
          throw error('PROVIDER_BINDING_MISMATCH');
        deadline = profile.validUntilMs;
        scheduleExpiry();
        if (closed) throw error('RECIPIENT_EXPIRED');
        publicationState = 'PUBLISHING';
        materialPublication = mount.publish(provider);
        try {
          await materialPublication;
        } finally {
          materialPublication = undefined;
        }
        if (closed) throw error('DELIVERY_CLOSED');
        // Keep the classification on the actual outer fence until both
        // freshness rechecks, COMMIT and connection reset have succeeded.
        phase = 'RECIPIENT_REJECTED';
      });
      phase = 'PUBLICATION_FINALIZATION_FAILED';
      if (closed || Date.now() >= deadline) throw error('DELIVERY_CLOSED');
      recipientCheck = 'PASSED_AT_PUBLICATION';
      publicationState = 'PUBLISHED';
      return describe();
    } catch (cause) {
      remember(cause, phase);
      recipientCheck = 'REJECTED';
      cleanup();
      throw rejection(phase);
    }
  }

  return Object.freeze({
    describe,
    publish(socket, request) {
      if (pending) return Promise.reject(error('DELIVERY_BUSY'));
      if (closed) return Promise.reject(rejection('DELIVERY_CLOSED'));
      pending = publish(socket, request);
      const current = pending;
      void current.then(
        () => {
          pending = undefined;
        },
        () => {
          pending = undefined;
        },
      );
      return current;
    },
    async dispose() {
      closed = true;
      clearTimeout(timer);
      // Erase provider handoff immediately; only active mount publication can
      // delay mount disposal. Await the outer result to retain its first failure.
      revokeProvider();
      cleanupAfterPublication();
      if (pending) {
        try {
          await pending;
        } catch {
          /* The first failure is already retained. */
        }
      }
      cleanup();
      if (cleanupState === 'UNKNOWN') throw rejection('CLEANUP_UNCERTAIN');
      return describe();
    },
  });
}
