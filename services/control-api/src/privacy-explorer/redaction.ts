import type { ScalarValue } from './narrowing.js';
import { immutableJsonCopy } from './immutable.js';
import { sha256CanonicalJson } from './canonical.js';
import { requireValidatedProjection, type ValidatedProjection } from './validation.js';

export type RedactedProjection = Readonly<{
  boundary: ValidatedProjection['boundary'];
  outcome: 'COMPLETE' | 'PARTIAL' | 'UNKNOWN' | 'UNAVAILABLE';
  records: readonly Readonly<{
    id: string;
    fields: readonly Readonly<{ fieldId: string; value: ScalarValue }>[];
  }>[];
  page: Readonly<{ cursor: string | null; gapFree: boolean }>;
  responseDigest: string;
  validationDigest: string;
  redactionDigest: string;
}>;

const redacted = new WeakSet<RedactedProjection>();

export type LocalProjectionVisibility = Readonly<{
  fieldsForRecord(record: ValidatedProjection['projection']['records'][number]): readonly string[];
  recordReference(externalId: string): string;
  cursor: string | null;
}>;

export const redactProjection = (
  value: ValidatedProjection,
  local?: LocalProjectionVisibility,
): RedactedProjection => {
  if (!local && process.env.NODE_ENV !== 'test')
    throw new Error('local disclosure visibility required');
  const admitted = requireValidatedProjection(value);
  const allowed = new Set(admitted.boundary.request.projectionFields);
  const records = admitted.projection.records
    .map((record) => {
      const visible = new Set(
        local ? local.fieldsForRecord(record) : admitted.boundary.request.projectionFields,
      );
      return immutableJsonCopy({
        id: local ? local.recordReference(record.id) : record.id,
        fields: record.fields
          .filter((field) => visible.has(field.fieldId))
          .map((field) => {
            if (!allowed.has(field.fieldId)) throw new Error('redaction allowlist mismatch');
            return { fieldId: field.fieldId, value: field.value };
          }),
      });
    })
    .sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
  if (new Set(records.map((record) => record.id)).size !== records.length)
    throw new Error('local record reference collision');
  const redactionDigest = sha256CanonicalJson({
    requestDigest: admitted.boundary.requestDigest,
    responseDigest: admitted.projection.responseDigest,
    validationDigest: admitted.validationDigest,
    privacyProjectionId: admitted.boundary.request.exportProfile.privacyProjectionId,
    redactionProfileId: admitted.boundary.request.exportProfile.redactionProfileId,
    records,
  });
  const result = immutableJsonCopy({
    boundary: admitted.boundary,
    outcome: admitted.projection.completeness,
    records,
    page: {
      cursor: local ? local.cursor : admitted.projection.page.cursor,
      gapFree: admitted.projection.page.gapFree,
    },
    responseDigest: admitted.projection.responseDigest,
    validationDigest: admitted.validationDigest,
    redactionDigest,
  });
  redacted.add(result);
  return result;
};

export const requireRedactedProjection = (value: unknown): RedactedProjection => {
  if (!value || typeof value !== 'object' || !redacted.has(value as RedactedProjection))
    throw new Error('unredacted Explorer projection');
  return value as RedactedProjection;
};
