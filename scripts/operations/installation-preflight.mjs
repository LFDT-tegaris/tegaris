import { parseStrictJsonBytes } from '../../services/control-api/src/privacy-explorer/strict-json.ts';
import { canonicalJson } from '../../services/control-api/src/configuration/digest.ts';
import { InstallationConfigError } from './installation-config-inputs.mjs';
import { prepareInstallationCandidate } from './installation-config-validation.mjs';
import {
  checkConsumedConfiguration,
  checkContainerBindings,
  checkImageBindings,
  checkRenderedCompose,
  compareRenderedBindings,
  object,
  rejectPreflight,
} from './installation-preflight-checks.mjs';

const pendingOwners = Object.freeze([
  'RUNNER_SOURCE_AND_OBSERVATION_FRESHNESS_UNBOUND',
  'LIVE_RESOURCE_ADMISSION_UNVERIFIED',
  'FILESYSTEM_MOUNT_IDENTITY_UNVERIFIED',
  'DATABASE_ROLE_AND_MIGRATION_READBACK_UNVERIFIED',
  'SIGNING_TRUST_EPOCH_AND_REVOCATION_UNVERIFIED',
  'GENERATION_AND_EFFECTIVE_STATE_READBACK_UNVERIFIED',
  'SECRET_REFERENCE_TO_MOUNT_OWNER_UNBOUND',
  'EVIDENCE_DURABILITY_AND_CAPACITY_UNVERIFIED',
  'REQUIRED_EXTERNAL_DEPENDENCIES_UNQUALIFIED',
]);

function nativeDocument(bytes, array) {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.length === 0 ||
    bytes.length > 4 * 1024 * 1024 ||
    (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
  )
    rejectPreflight('PREFLIGHT_DOCUMENT_INVALID');
  let result;
  try {
    result = parseStrictJsonBytes(bytes, { maximumDepth: 32 });
  } catch {
    rejectPreflight('PREFLIGHT_DOCUMENT_INVALID');
  }
  if (array ? !Array.isArray(result) : !object(result))
    rejectPreflight('PREFLIGHT_DOCUMENT_INVALID');
  return result;
}

/**
 * Called by the existing installation/runtime owner, with its prepared and immediately
 * current `docker compose config --format json` output and native Docker inspect arrays.
 * No subprocess, filesystem/secret read, service start, migration, or scheduling occurs here.
 * Snapshots cannot prove their own freshness, cryptographic eligibility or capability readiness.
 */
export function prepareInstallationPreflight(input) {
  try {
    const fields = [
      'preparedConfigurationSources',
      'configurationSources',
      'preparedComposeBytes',
      'currentComposeBytes',
      'imageInspectBytes',
      'selectedServices',
      'externalMemoryKiB',
      'containerInspectBytes',
    ];
    if (!object(input) || Object.keys(input).some((key) => !fields.includes(key)))
      rejectPreflight('PREFLIGHT_INPUT_INVALID');
    const preparedCandidate = prepareInstallationCandidate(input.preparedConfigurationSources);
    const currentCandidate = prepareInstallationCandidate(input.configurationSources);
    if (
      canonicalJson(preparedCandidate.configuration.generation) !==
      canonicalJson(currentCandidate.configuration.generation)
    )
      rejectPreflight('PREFLIGHT_GENERATION_CHANGED');
    if (canonicalJson(preparedCandidate) !== canonicalJson(currentCandidate))
      rejectPreflight('PREFLIGHT_CONFIGURATION_CHANGED');
    const prepared = nativeDocument(input.preparedComposeBytes, false);
    const current = nativeDocument(input.currentComposeBytes, false);
    checkRenderedCompose(prepared, input.selectedServices);
    const selectedMemoryBytes = checkRenderedCompose(current, input.selectedServices);
    compareRenderedBindings(prepared, current, input.selectedServices);
    if (
      !/^[1-9][0-9]*$/u.test(String(input.externalMemoryKiB)) ||
      !Number.isSafeInteger(Number(input.externalMemoryKiB) * 1024)
    )
      rejectPreflight('PREFLIGHT_RESOURCE_BINDING_MISSING');
    // This is the supplied inherited envelope, not a new admission. Full phase/transient and
    // host/disk admission stays in openpc_target_service_order/run-bounded.sh.
    if (selectedMemoryBytes > Number(input.externalMemoryKiB) * 1024)
      rejectPreflight('PREFLIGHT_RESOURCE_ENVELOPE_EXCEEDED');
    const imageInspections = nativeDocument(input.imageInspectBytes, true);
    const images = checkImageBindings(current, input.selectedServices, imageInspections);
    const comparedConfigurationFields = checkConsumedConfiguration(
      current,
      input.selectedServices,
      currentCandidate.configuration,
    );
    const containerObserved = input.containerInspectBytes !== undefined;
    if (containerObserved)
      checkContainerBindings(
        current,
        input.selectedServices,
        images,
        nativeDocument(input.containerInspectBytes, true),
        imageInspections,
      );
    return {
      state: 'BLOCKED',
      startupAllowed: false,
      structuralState: 'CONSISTENT',
      capabilityReadiness: 'UNKNOWN',
      // Counts and fixed reason identifiers only: never emit raw environment/mount/inspection data.
      selectedServiceCount: input.selectedServices.length,
      selectedMemoryBytes,
      comparedConfigurationFields,
      containerBindings: containerObserved ? 'CONSISTENT_SNAPSHOT' : 'UNOBSERVED',
      blockers: [
        ...new Set([
          ...currentCandidate.blockers,
          ...pendingOwners,
          ...(!containerObserved ? ['CONSUMED_CONTAINER_CONFIGURATION_UNOBSERVED'] : []),
        ]),
      ],
    };
  } catch (error) {
    if (error instanceof InstallationConfigError) throw error;
    // Native Docker data and schema errors may include secrets in their error messages.
    rejectPreflight('PREFLIGHT_INPUT_INVALID');
  }
}
