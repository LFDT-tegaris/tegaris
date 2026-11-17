import {
  assertExplorerProjectionResultSchema,
  type ExplorerProjectionResultV1,
} from '../contracts/privacy-explorer-adapter.js';
import { immutableJsonCopy } from './immutable.js';
import { canonicalJson, sha256CanonicalJson } from './canonical.js';
import { canonicalSafeProblem, safeProblemForCondition, type SafeProblem } from './problems.js';
import { requireGovernedProjectionBoundary, type GovernedProjectionBoundary } from './request.js';

export type ValidatedProjection = Readonly<{
  boundary: GovernedProjectionBoundary;
  projection: ExplorerProjectionResultV1;
  validationDigest: string;
}>;

const validated = new WeakSet<ValidatedProjection>();
const compare = (left: string, right: string) => (left < right ? -1 : left > right ? 1 : 0);

const condition = (id: string): SafeProblem => safeProblemForCondition(id);

const orderedAndUnique = (values: readonly string[]) =>
  values.every((value, index) => index === 0 || compare(values[index - 1]!, value) < 0);

const validateBindingProvenanceAndFreshness = (
  boundary: GovernedProjectionBoundary,
  projection: ExplorerProjectionResultV1,
): SafeProblem | undefined => {
  const profile = boundary.request.exportProfile;
  const { responseDigest, ...responsePreimage } = projection;
  if (
    responseDigest !== sha256CanonicalJson(responsePreimage) ||
    projection.schemaVersion !== profile.responseSchemaVersion ||
    projection.provenanceDigest !==
      sha256CanonicalJson({
        profileDigest: profile.digest,
        requestDigest: boundary.requestDigest,
        provenanceProfileDigest: profile.provenanceProfileDigest,
      })
  )
    return condition('EXP-COND-002');

  const issuedAt = Date.parse(boundary.request.issuedAt);
  const observedAt = Date.parse(projection.observedAt);
  if (
    !Number.isFinite(observedAt) ||
    observedAt > issuedAt ||
    observedAt > Date.parse(boundary.context.deadlineAt) ||
    issuedAt - observedAt > profile.maximumFreshnessAgeMilliseconds
  )
    return condition('EXP-COND-005');
  return undefined;
};

const validateScopeAndOrder = (
  boundary: GovernedProjectionBoundary,
  projection: ExplorerProjectionResultV1,
): SafeProblem | undefined => {
  if (projection.records.length > boundary.request.page.limit) return condition('EXP-COND-003');
  const recordIds = projection.records.map((record) => record.id);
  if (!orderedAndUnique(recordIds)) return condition('EXP-COND-003');
  for (const record of projection.records) {
    const fieldIds = record.fields.map((field) => field.fieldId);
    if (!orderedAndUnique(fieldIds)) return condition('EXP-COND-003');
    if (fieldIds.some((fieldId) => !boundary.request.projectionFields.includes(fieldId)))
      return condition('EXP-COND-001');
  }
  if (
    projection.page.cursor !== null &&
    projection.page.cursor === (boundary.request.page.cursor ?? null)
  )
    return condition('EXP-COND-003');
  return undefined;
};

const validateTruthRelations = (
  projection: ExplorerProjectionResultV1,
): SafeProblem | undefined => {
  if (projection.conflict === 'REORG') return condition('EXP-COND-006');
  if (projection.conflict === 'CONFLICT') return condition('EXP-COND-007');
  if (projection.freshness === 'STALE') return condition('EXP-COND-005');

  switch (projection.completeness) {
    case 'COMPLETE':
      return projection.freshness === 'FRESH' &&
        projection.page.gapFree &&
        projection.page.cursor === null
        ? undefined
        : condition('EXP-COND-003');
    case 'PARTIAL':
      return projection.freshness === 'FRESH' &&
        (!projection.page.gapFree || projection.page.cursor !== null)
        ? undefined
        : condition('EXP-COND-003');
    case 'UNKNOWN':
      return projection.freshness === 'UNKNOWN' &&
        projection.records.length === 0 &&
        projection.page.cursor === null &&
        !projection.page.gapFree
        ? undefined
        : condition('EXP-ABSENCE');
    case 'UNAVAILABLE':
      return projection.freshness === 'UNKNOWN' &&
        projection.records.length === 0 &&
        projection.page.cursor === null &&
        !projection.page.gapFree
        ? undefined
        : condition('EXP-COND-004');
  }
};

export const validateProjection = (
  boundary: GovernedProjectionBoundary,
  raw: unknown,
): ValidatedProjection | SafeProblem => {
  const admittedBoundary = requireGovernedProjectionBoundary(boundary);
  const safeProblem = canonicalSafeProblem(raw);
  if (safeProblem) return safeProblem;

  let projection: ExplorerProjectionResultV1;
  try {
    projection = assertExplorerProjectionResultSchema(immutableJsonCopy(raw));
  } catch {
    return condition('EXP-COND-002');
  }
  if (
    projection.requestDigest !== admittedBoundary.requestDigest ||
    projection.profileDigest !== admittedBoundary.request.exportProfile.digest ||
    projection.profileDigest !== admittedBoundary.context.profileDigest
  )
    return condition('EXP-COND-002');

  const relationFailure =
    validateBindingProvenanceAndFreshness(admittedBoundary, projection) ??
    validateScopeAndOrder(admittedBoundary, projection) ??
    validateTruthRelations(projection);
  if (relationFailure) return relationFailure;

  const result = Object.freeze({
    boundary: admittedBoundary,
    projection,
    validationDigest: sha256CanonicalJson({
      requestDigest: admittedBoundary.requestDigest,
      profileDigest: admittedBoundary.request.exportProfile.digest,
      responseDigest: projection.responseDigest,
      completeness: projection.completeness,
      freshness: projection.freshness,
      conflict: projection.conflict,
      relationSet: 'I07-G2-R11-R13-V1',
    }),
  });
  validated.add(result);
  return result;
};

export const requireValidatedProjection = (value: unknown): ValidatedProjection => {
  if (!value || typeof value !== 'object' || !validated.has(value as ValidatedProjection))
    throw new Error('unvalidated Explorer projection');
  return value as ValidatedProjection;
};

/** Public opaque cursors and external cursors identify the same narrowed query.
 * No other request or authorization field may change during custody resolution.
 */
export const assertContinuationBoundary = (
  publicBoundary: GovernedProjectionBoundary,
  sourceBoundary: GovernedProjectionBoundary,
) => {
  const logical = requireGovernedProjectionBoundary(publicBoundary);
  const source = requireGovernedProjectionBoundary(sourceBoundary);
  const normalized = (boundary: GovernedProjectionBoundary) => ({
    request: { ...boundary.request, page: { ...boundary.request.page, cursor: null } },
    context: { ...boundary.context, idempotencyDigest: null },
  });
  if (canonicalJson(normalized(logical)) !== canonicalJson(normalized(source)))
    throw new Error('continuation broadened governed projection');
};

export const bindValidatedContinuation = (
  value: ValidatedProjection,
  publicBoundary: GovernedProjectionBoundary,
): ValidatedProjection => {
  const admitted = requireValidatedProjection(value);
  assertContinuationBoundary(publicBoundary, admitted.boundary);
  if (publicBoundary.requestDigest === admitted.boundary.requestDigest) return admitted;
  // Retain the actual external response and validation digests. Public output
  // binds the logical request; no provider provenance is rewritten or invented.
  const result = Object.freeze({
    ...admitted,
    boundary: publicBoundary,
    validationDigest: sha256CanonicalJson({
      sourceValidationDigest: admitted.validationDigest,
      sourceRequestDigest: admitted.boundary.requestDigest,
      publicRequestDigest: publicBoundary.requestDigest,
      relation: 'OPENPC-CUSTODIED-CONTINUATION-1',
    }),
  });
  validated.add(result);
  return result;
};
