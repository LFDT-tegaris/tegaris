import {
  assertPrivacyExplorerResult,
  type PrivacyExplorerResultV1,
} from '../contracts/privacy-explorer-adapter.js';
import { immutableJsonCopy } from './immutable.js';
import { sha256CanonicalJson } from './narrowing.js';
import { canonicalSafeProblem, type SafeProblem } from './problems.js';
import { requireRedactedProjection, type RedactedProjection } from './redaction.js';
import { requireGovernedProjectionBoundary, type GovernedProjectionBoundary } from './request.js';

export type CandidateOutcome =
  | 'COMPLETE'
  | 'PARTIAL'
  | 'UNKNOWN'
  | 'UNAVAILABLE'
  | 'DENIED'
  | 'FAILED'
  | 'CANCELLED_BEFORE_DISPATCH'
  | 'CANCELLED_AFTER_DISPATCH_NO_RAW'
  | 'CANCELLED_AFTER_RAW';
export type CandidateDelivery = 'PENDING' | 'SUPPRESSED';
type CandidateIdentity = Readonly<{
  occurrenceId: string;
  correlationId: string;
  requestDigest: string;
  profileDigest: string;
  queryDigest: string;
  authorizationDigest: string;
  contextDigest: string;
  scopeDigest: string;
  responseDigest: string;
  validationDigest: string;
  redactionDigest: string;
  resultDigest: string;
  outcome: CandidateOutcome;
  truthState: string;
}>;
export type PublicResponseCandidate =
  | Readonly<
      CandidateIdentity & {
        response: PrivacyExplorerResultV1 | SafeProblem;
        delivery: 'PENDING';
      }
    >
  | Readonly<
      CandidateIdentity & {
        delivery: 'SUPPRESSED';
        response?: never;
      }
    >;

const candidates = new WeakSet<PublicResponseCandidate>();
const truthFor = (outcome: RedactedProjection['outcome']) =>
  ({
    COMPLETE: 'TRUE',
    PARTIAL: 'PARTIAL',
    UNKNOWN: 'UNKNOWN',
    UNAVAILABLE: 'UNAVAILABLE',
  })[outcome] as PrivacyExplorerResultV1['truthState'];

export const buildProjectionCandidate = (
  projection: RedactedProjection,
): PublicResponseCandidate => {
  const admitted = requireRedactedProjection(projection);
  const boundary = admitted.boundary;
  const preimage = immutableJsonCopy({
    schemaVersion: '1.0' as const,
    outcome: admitted.outcome,
    truthState: truthFor(admitted.outcome),
    requestDigest: boundary.requestDigest,
    profileDigest: boundary.request.exportProfile.digest,
    queryDigest: boundary.request.queryDigest,
    records: admitted.records,
    page: admitted.page,
  });
  const resultDigest = sha256CanonicalJson(preimage);
  const response = assertPrivacyExplorerResult(immutableJsonCopy({ ...preimage, resultDigest }));
  const candidate = immutableJsonCopy({
    response,
    occurrenceId: boundary.request.occurrence.requestId,
    correlationId: boundary.request.occurrence.correlationId,
    requestDigest: boundary.requestDigest,
    profileDigest: response.profileDigest,
    queryDigest: response.queryDigest,
    authorizationDigest: boundary.context.authorizationDigest,
    contextDigest: sha256CanonicalJson(boundary.context),
    scopeDigest: boundary.context.scopeDigest,
    responseDigest: admitted.responseDigest,
    validationDigest: admitted.validationDigest,
    redactionDigest: admitted.redactionDigest,
    resultDigest,
    outcome: response.outcome,
    truthState: response.truthState,
    delivery: 'PENDING' as const,
  });
  candidates.add(candidate);
  return candidate;
};

export const buildSafeProblemCandidate = (
  boundary: GovernedProjectionBoundary,
  problem: SafeProblem,
): PublicResponseCandidate => {
  const admittedBoundary = requireGovernedProjectionBoundary(boundary);
  const safeProblem = canonicalSafeProblem(problem);
  if (!safeProblem) throw new Error('unregistered safe problem');
  const outcome: CandidateOutcome =
    safeProblem.truthState === 'PARTIAL'
      ? 'PARTIAL'
      : safeProblem.truthState === 'UNKNOWN'
        ? 'UNKNOWN'
        : safeProblem.truthState === 'UNAVAILABLE'
          ? 'UNAVAILABLE'
          : safeProblem.truthState === 'DENIED'
            ? 'DENIED'
            : 'FAILED';
  const resultDigest = sha256CanonicalJson(safeProblem);
  const responseDigest = sha256CanonicalJson({ kind: 'SAFE_PROBLEM', problem: safeProblem });
  const validationDigest = sha256CanonicalJson({
    kind: 'TERMINAL_PROBLEM',
    requestDigest: admittedBoundary.requestDigest,
    responseDigest,
  });
  const redactionDigest = sha256CanonicalJson({
    kind: 'NO_PUBLIC_RAW',
    validationDigest,
    disclosure: safeProblem.disclosure,
  });
  const candidate = immutableJsonCopy({
    response: safeProblem,
    occurrenceId: admittedBoundary.request.occurrence.requestId,
    correlationId: admittedBoundary.request.occurrence.correlationId,
    requestDigest: admittedBoundary.requestDigest,
    profileDigest: admittedBoundary.request.exportProfile.digest,
    queryDigest: admittedBoundary.request.queryDigest,
    authorizationDigest: admittedBoundary.context.authorizationDigest,
    contextDigest: sha256CanonicalJson(admittedBoundary.context),
    scopeDigest: admittedBoundary.context.scopeDigest,
    responseDigest,
    validationDigest,
    redactionDigest,
    resultDigest,
    outcome,
    truthState: safeProblem.truthState,
    delivery: 'PENDING' as const,
  });
  candidates.add(candidate);
  return candidate;
};

export const buildSuppressedCandidate = (
  boundary: GovernedProjectionBoundary,
  outcome: 'CANCELLED_BEFORE_DISPATCH' | 'CANCELLED_AFTER_DISPATCH_NO_RAW' | 'CANCELLED_AFTER_RAW',
): PublicResponseCandidate => {
  const admittedBoundary = requireGovernedProjectionBoundary(boundary);
  const delivery = 'SUPPRESSED' as const;
  const resultDigest = sha256CanonicalJson({ outcome, delivery });
  const responseDigest = sha256CanonicalJson({ kind: 'SUPPRESSED', outcome, delivery });
  const validationDigest = sha256CanonicalJson({
    kind: 'CANCELLED',
    requestDigest: admittedBoundary.requestDigest,
    responseDigest,
  });
  const redactionDigest = sha256CanonicalJson({
    kind: 'NO_PUBLIC_RAW',
    validationDigest,
    disclosure: 'SUPPRESSED',
  });
  const candidate = immutableJsonCopy({
    occurrenceId: admittedBoundary.request.occurrence.requestId,
    correlationId: admittedBoundary.request.occurrence.correlationId,
    requestDigest: admittedBoundary.requestDigest,
    profileDigest: admittedBoundary.request.exportProfile.digest,
    queryDigest: admittedBoundary.request.queryDigest,
    authorizationDigest: admittedBoundary.context.authorizationDigest,
    contextDigest: sha256CanonicalJson(admittedBoundary.context),
    scopeDigest: admittedBoundary.context.scopeDigest,
    responseDigest,
    validationDigest,
    redactionDigest,
    resultDigest,
    outcome,
    truthState: 'FAILED',
    delivery,
  });
  candidates.add(candidate);
  return candidate;
};

export const requirePublicResponseCandidate = (value: unknown): PublicResponseCandidate => {
  if (!value || typeof value !== 'object' || !candidates.has(value as PublicResponseCandidate))
    throw new Error('invalid public response candidate');
  return value as PublicResponseCandidate;
};
