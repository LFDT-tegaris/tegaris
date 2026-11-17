import {
  assertPrivacyExplorerExportProfile,
  executionRegistry,
  type PrivacyExplorerExportProfileV1,
} from '../contracts/privacy-explorer-adapter.js';
import { sha256CanonicalJson } from './canonical.js';
import { immutableJsonCopy } from './immutable.js';

export type ExplorerProfileRegistrationFacts = Readonly<
  PrivacyExplorerExportProfileV1 & { registrationId: string }
>;
export interface ExplorerProfileRegistrationVerifier {
  verify(candidate: unknown): ExplorerProfileRegistrationFacts | undefined;
}
export type RegisteredExplorerProfile = Readonly<PrivacyExplorerExportProfileV1>;

const registrations = new WeakMap<RegisteredExplorerProfile, string>();
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const dateTime =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const compare = (left: string, right: string) => (left < right ? -1 : left > right ? 1 : 0);

export const boundedString = (value: unknown, label: string): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 256 ||
    value.includes('\u0000')
  )
    throw new Error(`${label}: invalid string`);
  return value;
};

export const validDateTime = (value: unknown, label: string): string => {
  const input = typeof value === 'string' ? value : '';
  const match = dateTime.exec(input);
  const year = Number(match?.[1]);
  const month = Number(match?.[2]);
  const day = Number(match?.[3]);
  const hour = Number(match?.[4]);
  const minute = Number(match?.[5]);
  const second = Number(match?.[6]);
  const days = month >= 1 && month <= 12 ? new Date(Date.UTC(year, month, 0)).getUTCDate() : 0;
  if (
    !match ||
    day < 1 ||
    day > days ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    !Number.isFinite(Date.parse(input))
  )
    throw new Error(`${label}: invalid date-time`);
  return input;
};

export const canonicalSet = (
  values: unknown,
  label: string,
  maximum: number,
  expression: RegExp,
) => {
  if (!Array.isArray(values) || values.length === 0 || values.length > maximum)
    throw new Error(`${label}: invalid bounds`);
  const result = values.map((value) => {
    const admitted = boundedString(value, label);
    if (!expression.test(admitted)) throw new Error(`${label}: invalid value`);
    return admitted;
  });
  if (result.some((value, index) => index > 0 && compare(result[index - 1]!, value) >= 0))
    throw new Error(`${label}: noncanonical or duplicate value`);
  return Object.freeze(result);
};

const assertProfileRelations = (profile: PrivacyExplorerExportProfileV1) => {
  canonicalSet(profile.allowedFieldIds, 'profile field allowlist', 64, /^PEF-[A-Z0-9-]{1,64}$/);
  canonicalSet(
    profile.allowedFilterIds,
    'profile filter allowlist',
    32,
    /^PEFILTER-[A-Z0-9-]{1,64}$/,
  );
  if (
    profile.operationVersions.length !== 9 ||
    profile.operationVersions.some((operation, index) => {
      canonicalSet(operation.acceptedDataClassIds, 'accepted data classes', 64, /^.{1,256}$/u);
      if (index === 0) return false;
      const prior = profile.operationVersions[index - 1]!;
      return compare(prior.operationId, operation.operationId) >= 0;
    }) ||
    profile.retryBackoffMilliseconds.length !== profile.maximumReadAttempts - 1 ||
    profile.retryBackoffMilliseconds.some(
      (delay, index) => index > 0 && profile.retryBackoffMilliseconds[index - 1]! > delay,
    )
  )
    throw new Error('unqualified Explorer profile');
  validDateTime(profile.maximumDeadlineAt, 'profile deadline');
  const { digest, ...preimage } = profile;
  if (digest !== sha256CanonicalJson(preimage)) throw new Error('profile digest mismatch');
};

export const validateExplorerProfile = (candidate: unknown): PrivacyExplorerExportProfileV1 => {
  const profile = assertPrivacyExplorerExportProfile(candidate);
  assertProfileRelations(profile);
  return profile;
};

/** Legacy kernel fixtures remain readable; only an exact governed source can serve live data. */
export const requireLiveExplorerProfile = (profile: RegisteredExplorerProfile) => {
  const admitted = requireRegisteredExplorerProfile(profile);
  const source = admitted.sourceBinding;
  if (!source) throw new Error('Explorer source binding unavailable');
  canonicalSet(source.accessClassIds, 'source access classes', 32, /^ACCESS-[A-Z0-9-]{1,64}$/);
  const operations = executionRegistry.operationDefinitions.map((operation) => operation.id).sort();
  if (
    admitted.operationVersions.some(
      (operation, index) =>
        operation.operationId !== operations[index] || operation.version !== '1.0.0',
    )
  )
    throw new Error('Explorer semantic operations unavailable');
  return source;
};

export const registerExplorerProfile = (
  candidate: unknown,
  verifier: ExplorerProfileRegistrationVerifier,
): RegisteredExplorerProfile => {
  const verified = verifier.verify(candidate);
  if (!verified || !uuid.test(verified.registrationId))
    throw new Error('unqualified Explorer profile');
  const { registrationId, ...profileFacts } = immutableJsonCopy(verified);
  const profile = validateExplorerProfile(profileFacts);
  registrations.set(profile, registrationId);
  return profile;
};

export const requireRegisteredExplorerProfile = (value: unknown): RegisteredExplorerProfile => {
  if (!value || typeof value !== 'object' || !registrations.has(value as RegisteredExplorerProfile))
    throw new Error('unqualified Explorer profile');
  return value as RegisteredExplorerProfile;
};

export const registeredProfileId = (value: RegisteredExplorerProfile) => {
  const registrationId = registrations.get(requireRegisteredExplorerProfile(value));
  if (!registrationId) throw new Error('unqualified Explorer profile');
  return registrationId;
};
