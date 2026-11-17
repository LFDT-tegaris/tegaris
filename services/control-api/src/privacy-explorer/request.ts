import {
  assertAdapterCallContext,
  assertExplorerProjectionRequest,
  type AdapterCallContextV1,
  type ExplorerProjectionRequestV1,
} from '../contracts/privacy-explorer-adapter.js';
import {
  requireNarrowedIntent,
  sha256CanonicalJson,
  type PrivacyExplorerNarrowedIntent,
} from './narrowing.js';
import { registeredProfileId, validDateTime } from './profile-registration.js';
import { immutableJsonCopy } from './immutable.js';

const boundaries = new WeakSet<GovernedProjectionBoundary>();
const boundaryRegistrationIds = new WeakMap<GovernedProjectionBoundary, string>();

export type CallContextSeed = Readonly<{
  now: string;
  deadlineAt: string;
  occurrenceId: string;
  auditCorrelationId: string;
  cancellationOccurrenceId: string;
  reconciliationOccurrenceId: string;
}>;
export type GovernedProjectionBoundary = Readonly<{
  request: ExplorerProjectionRequestV1;
  context: AdapterCallContextV1;
  requestDigest: string;
}>;

export const createProjectionRequest = (
  narrowed: PrivacyExplorerNarrowedIntent,
  seed: CallContextSeed,
): GovernedProjectionBoundary => {
  const admitted = requireNarrowedIntent(narrowed);
  const candidate = immutableJsonCopy(seed);
  if (
    Reflect.ownKeys(candidate).length !== 6 ||
    !Object.hasOwn(candidate, 'now') ||
    !Object.hasOwn(candidate, 'deadlineAt') ||
    !Object.hasOwn(candidate, 'occurrenceId') ||
    !Object.hasOwn(candidate, 'auditCorrelationId') ||
    !Object.hasOwn(candidate, 'cancellationOccurrenceId') ||
    !Object.hasOwn(candidate, 'reconciliationOccurrenceId')
  )
    throw new Error('invalid call context seed');
  const deadline = Date.parse(validDateTime(candidate.deadlineAt, 'seed deadline'));
  const now = Date.parse(validDateTime(candidate.now, 'seed now'));
  const profileDeadline = Date.parse(admitted.profile.maximumDeadlineAt);
  const authorizationDeadline = Date.parse(admitted.intent.context.deadlineAt);
  if (
    Number.isNaN(deadline) ||
    Number.isNaN(now) ||
    Number.isNaN(profileDeadline) ||
    Number.isNaN(authorizationDeadline) ||
    deadline <= now ||
    deadline > profileDeadline ||
    deadline > authorizationDeadline ||
    candidate.occurrenceId !== admitted.intent.context.occurrenceId ||
    candidate.auditCorrelationId !== admitted.intent.context.auditCorrelationId ||
    candidate.cancellationOccurrenceId !== candidate.occurrenceId ||
    candidate.reconciliationOccurrenceId !== candidate.occurrenceId
  )
    throw new Error('invalid call context seed');
  const request = immutableJsonCopy(
    assertExplorerProjectionRequest({
      operationVersion: 'v1',
      schemaVersion: '1.0',
      issuedAt: candidate.now,
      purpose: admitted.intent.purpose,
      subject: admitted.intent.context.subject,
      resource: admitted.intent.resource,
      action: admitted.intent.action,
      scope: {
        participantId: admitted.intent.context.participantId,
        privacyDomainId: admitted.intent.context.privacyDomainId,
        platformId: admitted.intent.context.platformId,
        workloadId: admitted.intent.context.workloadId,
        action: admitted.intent.action,
      },
      operationId: admitted.operationId,
      semanticOperationVersion: admitted.semanticOperationVersion,
      dataClassId: admitted.dataClassId,
      filters: admitted.filters,
      page: admitted.page,
      projectionFields: admitted.projectionFields,
      exportProfile: admitted.profile,
      queryDigest: admitted.queryDigest,
      occurrence: {
        requestId: candidate.occurrenceId,
        correlationId: candidate.auditCorrelationId,
      },
    }),
  );
  const idempotencyDigest = sha256CanonicalJson({
    queryDigest: request.queryDigest,
    cursor: request.page.cursor,
  });
  const context = immutableJsonCopy(
    assertAdapterCallContext({
      authorizationDigest: admitted.intent.context.authorizationDigest,
      profileDigest: admitted.profile.digest,
      authorizationContextId: admitted.intent.context.authorizationContextId,
      authorizationContextEpoch: admitted.intent.context.authorizationContextEpoch,
      accessClassIds: admitted.intent.context.accessClassIds,
      scopeDigest: sha256CanonicalJson({
        participantId: admitted.intent.context.participantId,
        privacyDomainId: admitted.intent.context.privacyDomainId,
        platformId: admitted.intent.context.platformId,
        workloadId: admitted.intent.context.workloadId,
        action: admitted.intent.action,
      }),
      deadlineAt: candidate.deadlineAt,
      idempotencyDigest,
      occurrenceId: candidate.occurrenceId,
      auditCorrelationId: candidate.auditCorrelationId,
      cancellation: {
        mode: 'NO_NEW_EFFECT_AFTER_CANCELLATION',
        occurrenceId: candidate.cancellationOccurrenceId,
      },
      reconciliation: {
        mode: 'EXACT_OCCURRENCE',
        occurrenceId: candidate.reconciliationOccurrenceId,
      },
    }),
  );
  const boundary = immutableJsonCopy({
    request,
    context,
    requestDigest: sha256CanonicalJson(request),
  });
  boundaries.add(boundary);
  boundaryRegistrationIds.set(boundary, registeredProfileId(admitted.profile));
  return boundary;
};

export const requireGovernedProjectionBoundary = (value: unknown): GovernedProjectionBoundary => {
  if (!value || typeof value !== 'object' || !boundaries.has(value as GovernedProjectionBoundary))
    throw new Error('unvalidated projection boundary');
  return value as GovernedProjectionBoundary;
};
export const governedBoundaryRegistrationId = (value: GovernedProjectionBoundary) => {
  const registrationId = boundaryRegistrationIds.get(requireGovernedProjectionBoundary(value));
  if (!registrationId) throw new Error('unvalidated projection boundary');
  return registrationId;
};
