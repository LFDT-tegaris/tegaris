import {
  type PrivacyExplorerPreauthorizedIntent,
  requirePreauthorizedIntent,
} from './preauthorization.js';
import {
  boundedString,
  canonicalSet as canonicalValidatedSet,
  type RegisteredExplorerProfile,
  requireRegisteredExplorerProfile,
} from './profile-registration.js';
import { immutableJsonCopy } from './immutable.js';
import { canonicalJson, sha256CanonicalJson } from './canonical.js';

export type ScalarValue = string | number | boolean | null;
export type ProjectionFilter = Readonly<{ fieldId: string; filterId: string; value: ScalarValue }>;
export type NarrowingInput = Readonly<{
  operationId: string;
  semanticOperationVersion: string;
  dataClassId: string;
  filters: readonly ProjectionFilter[];
  projectionFields: readonly string[];
  page: Readonly<{ limit: number; cursor: string | null }>;
}>;

export type PrivacyExplorerNarrowedIntent = Readonly<{
  intent: PrivacyExplorerPreauthorizedIntent;
  profile: RegisteredExplorerProfile;
  operationId: string;
  semanticOperationVersion: string;
  dataClassId: string;
  filters: readonly ProjectionFilter[];
  projectionFields: readonly string[];
  page: Readonly<{ limit: number; cursor: string | null }>;
  queryDigest: string;
}>;
const narrowedIntents = new WeakSet<PrivacyExplorerNarrowedIntent>();

const compare = (left: string, right: string) => (left < right ? -1 : left > right ? 1 : 0);
const compareFilter = (left: ProjectionFilter, right: ProjectionFilter) => {
  const fieldOrder = compare(left.fieldId, right.fieldId);
  if (fieldOrder !== 0) return fieldOrder;
  const filterOrder = compare(left.filterId, right.filterId);
  return filterOrder !== 0
    ? filterOrder
    : compare(canonicalJson(left.value), canonicalJson(right.value));
};
export const narrowIntent = (
  intent: PrivacyExplorerPreauthorizedIntent,
  profile: RegisteredExplorerProfile,
  input: NarrowingInput,
): PrivacyExplorerNarrowedIntent => {
  const admitted = requirePreauthorizedIntent(intent);
  const registeredProfile = requireRegisteredExplorerProfile(profile);
  const candidate = immutableJsonCopy(input);
  if (
    Reflect.ownKeys(candidate).length !== 6 ||
    !Object.hasOwn(candidate, 'operationId') ||
    !Object.hasOwn(candidate, 'semanticOperationVersion') ||
    !Object.hasOwn(candidate, 'dataClassId') ||
    !Object.hasOwn(candidate, 'filters') ||
    !Object.hasOwn(candidate, 'projectionFields') ||
    !Object.hasOwn(candidate, 'page')
  )
    throw new Error('invalid narrowing input');
  const operationId = boundedString(candidate.operationId, 'operation');
  const semanticOperationVersion = boundedString(
    candidate.semanticOperationVersion,
    'operation version',
  );
  const dataClassId = boundedString(candidate.dataClassId, 'data class');
  const operation = registeredProfile.operationVersions.find(
    (entry) => entry.operationId === operationId && entry.version === semanticOperationVersion,
  );
  if (!operation) throw new Error('unsupported operation');
  if (!operation.acceptedDataClassIds.includes(dataClassId))
    throw new Error('unsupported data class');
  if (!Array.isArray(candidate.projectionFields))
    throw new Error('projection fields: invalid bounds');
  const projectionFields = canonicalValidatedSet(
    [...candidate.projectionFields].sort(compare),
    'projection fields',
    64,
    /^PEF-[A-Z0-9-]{1,64}$/,
  );
  if (
    projectionFields.some(
      (fieldId) =>
        !registeredProfile.allowedFieldIds.includes(fieldId) ||
        !admitted.context.allowedFieldIds.includes(fieldId),
    )
  )
    throw new Error('forbidden projection field');
  if (!Array.isArray(candidate.filters) || candidate.filters.length > 32)
    throw new Error('filter count');
  const filters = [...candidate.filters].map((filter) => {
    if (
      !filter ||
      typeof filter !== 'object' ||
      Array.isArray(filter) ||
      Reflect.ownKeys(filter).length !== 3 ||
      !Object.hasOwn(filter, 'fieldId') ||
      !Object.hasOwn(filter, 'filterId') ||
      !Object.hasOwn(filter, 'value')
    )
      throw new Error('forbidden filter');
    if (
      !/^PEF-[A-Z0-9-]{1,64}$/.test(filter.fieldId) ||
      !/^PEFILTER-[A-Z0-9-]{1,64}$/.test(filter.filterId) ||
      !projectionFields.includes(filter.fieldId) ||
      !registeredProfile.allowedFilterIds.includes(filter.filterId) ||
      !(
        filter.value === null ||
        (typeof filter.value === 'string' && filter.value.length <= 256) ||
        typeof filter.value === 'boolean' ||
        (typeof filter.value === 'number' && Number.isSafeInteger(filter.value))
      )
    )
      throw new Error('forbidden filter');
    return Object.freeze({
      fieldId: boundedString(filter.fieldId, 'filter field'),
      filterId: boundedString(filter.filterId, 'filter id'),
      value: filter.value,
    });
  });
  filters.sort(compareFilter);
  if (
    filters.some((filter, index) => index > 0 && compareFilter(filter, filters[index - 1]!) === 0)
  )
    throw new Error('duplicate filter');
  if (
    !candidate.page ||
    typeof candidate.page !== 'object' ||
    Array.isArray(candidate.page) ||
    Reflect.ownKeys(candidate.page).length !== 2 ||
    !Object.hasOwn(candidate.page, 'limit') ||
    !Object.hasOwn(candidate.page, 'cursor') ||
    !Number.isInteger(candidate.page.limit) ||
    candidate.page.limit < 1 ||
    candidate.page.limit > registeredProfile.maximumPageSize ||
    (candidate.page.cursor !== null &&
      (typeof candidate.page.cursor !== 'string' ||
        candidate.page.cursor.length === 0 ||
        candidate.page.cursor.length > 1024))
  )
    throw new Error('invalid page');
  const page = Object.freeze({ limit: candidate.page.limit, cursor: candidate.page.cursor });
  const queryDigest = sha256CanonicalJson({
    purpose: admitted.purpose,
    subject: admitted.context.subject,
    resource: admitted.resource,
    action: admitted.action,
    scope: {
      participantId: admitted.context.participantId,
      privacyDomainId: admitted.context.privacyDomainId,
      platformId: admitted.context.platformId,
      workloadId: admitted.context.workloadId,
      action: admitted.action,
    },
    operationId,
    semanticOperationVersion,
    dataClassId,
    filters,
    page: { limit: page.limit },
    projectionFields,
    exportProfileDigest: registeredProfile.digest,
  });
  const narrowed = Object.freeze({
    intent: admitted,
    profile: registeredProfile,
    operationId,
    semanticOperationVersion,
    dataClassId,
    filters: Object.freeze(filters),
    projectionFields,
    page,
    queryDigest,
  });
  narrowedIntents.add(narrowed);
  return narrowed;
};

export const requireNarrowedIntent = (value: unknown): PrivacyExplorerNarrowedIntent => {
  if (
    !value ||
    typeof value !== 'object' ||
    !narrowedIntents.has(value as PrivacyExplorerNarrowedIntent)
  )
    throw new Error('unnarrowed intent');
  return value as PrivacyExplorerNarrowedIntent;
};

export { canonicalJson, sha256CanonicalJson } from './canonical.js';
