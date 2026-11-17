import type {
  AdapterCallContextV1,
  EvidenceReferenceV1,
  ExplorerProjectionRequestV1,
  ExplorerProjectionResultV1,
} from '../../services/control-api/src/contracts/privacy-explorer-adapter.js';
import { bindGovernedProjectionConsumer } from '../../services/control-api/src/privacy-explorer/consumer-port.js';
import type { SafeProblem } from '../../services/control-api/src/privacy-explorer/problems.js';
import {
  bindLocalContext,
  type TerminalAuthorizationFacts,
} from '../../services/control-api/src/privacy-explorer/context.js';
import { sha256CanonicalJson } from '../../services/control-api/src/privacy-explorer/narrowing.js';
import {
  registerExplorerProfile,
  type ExplorerProfileRegistrationFacts,
} from '../../services/control-api/src/privacy-explorer/profile-registration.js';
import type { PrivacyExplorerReadInput } from '../../services/control-api/src/privacy-explorer/service.js';
import {
  privacyExplorerNarrowing,
  privacyExplorerProfileFacts,
  privacyExplorerScope,
} from './i07-gate2-contract-fixture.js';

const digest = (character: string) => `sha256:${character.repeat(64)}`;

export const b5OccurrenceId = '123e4567-e89b-42d3-a456-426614174101';
export const b5CorrelationId = '123e4567-e89b-42d3-a456-426614174102';

export type B5HarnessOptions = Readonly<{
  implementation: {
    readGovernedProjection(
      request: ExplorerProjectionRequestV1,
      context: AdapterCallContextV1,
    ): Promise<unknown | SafeProblem>;
    verifyEvidenceReference?(
      request: EvidenceReferenceV1,
      context: AdapterCallContextV1,
    ): Promise<unknown | SafeProblem>;
  };
  authorizationContextId?: string;
  occurrenceId?: string;
  correlationId?: string;
  profileRegistrationId?: string;
  signal?: AbortSignal;
}>;

export const buildB5Harness = (options: B5HarnessOptions) => {
  const now = Date.now();
  const occurrenceId = options.occurrenceId ?? b5OccurrenceId;
  const correlationId = options.correlationId ?? b5CorrelationId;
  const facts: TerminalAuthorizationFacts = {
    authorizationDigest: digest('b'),
    authorizationContextId:
      options.authorizationContextId ?? '123e4567-e89b-42d3-a456-426614174103',
    authorizationContextEpoch: 4,
    subject: 'subject-a',
    resource: 'resource-a',
    ...privacyExplorerScope,
    accessClassIds: ['ACCESS-PRIVATE'],
    allowedPurposeActions: [{ purpose: 'audit', action: 'read' }],
    allowedFieldIds: ['PEF-A', 'PEF-B'],
    auditCorrelationId: correlationId,
    occurrenceId,
    deadlineAt: '9999-12-31T23:59:59.000Z',
  };
  const profileFacts: ExplorerProfileRegistrationFacts = privacyExplorerProfileFacts(
    options.profileRegistrationId ?? '123e4567-e89b-42d3-a456-426614174104',
    ['PEFILTER-A'],
  );
  const context = bindLocalContext('terminal', {
    verify: (candidate) => (candidate === 'terminal' ? facts : undefined),
  });
  const profile = registerExplorerProfile('profile', {
    verify: (candidate) => (candidate === 'profile' ? profileFacts : undefined),
  });
  const port = bindGovernedProjectionConsumer(profile, {
    readGovernedProjection: options.implementation.readGovernedProjection,
    verifyEvidenceReference: options.implementation.verifyEvidenceReference ?? (async () => ({})),
  } as never);
  const input: PrivacyExplorerReadInput = {
    context,
    purposeAction: { purpose: 'audit', action: 'read', resource: 'resource-a' },
    profile,
    query: {
      ...privacyExplorerNarrowing,
      filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 7 }],
      projectionFields: ['PEF-A', 'PEF-B'],
      page: { limit: 2, cursor: null },
    },
    seed: {
      now: new Date(now).toISOString(),
      deadlineAt: new Date(now + 60_000).toISOString(),
      occurrenceId,
      auditCorrelationId: correlationId,
      cancellationOccurrenceId: occurrenceId,
      reconciliationOccurrenceId: occurrenceId,
    },
    ...(options.signal ? { signal: options.signal } : {}),
  };
  return Object.freeze({ context, profile, port, input });
};

export const projectionFor = (
  request: ExplorerProjectionRequestV1,
  _context: AdapterCallContextV1,
  outcome: 'COMPLETE' | 'PARTIAL' | 'UNKNOWN' | 'UNAVAILABLE' = 'COMPLETE',
): ExplorerProjectionResultV1 => {
  const preimage = {
    schemaVersion: '1.0' as const,
    requestDigest: sha256CanonicalJson(request),
    profileDigest: request.exportProfile.digest,
    provenanceDigest: sha256CanonicalJson({
      profileDigest: request.exportProfile.digest,
      requestDigest: sha256CanonicalJson(request),
      provenanceProfileDigest: request.exportProfile.provenanceProfileDigest,
    }),
    observedAt: request.issuedAt,
    records:
      outcome === 'UNKNOWN' || outcome === 'UNAVAILABLE'
        ? []
        : [
            {
              id: 'record-a',
              fields: [
                { fieldId: 'PEF-A', value: 7 },
                { fieldId: 'PEF-B', value: 'visible' },
              ],
            },
          ],
    page: {
      cursor: outcome === 'PARTIAL' ? 'next' : null,
      gapFree: outcome === 'COMPLETE',
    },
    completeness: outcome,
    freshness: (outcome === 'UNKNOWN' || outcome === 'UNAVAILABLE' ? 'UNKNOWN' : 'FRESH') as
      'UNKNOWN' | 'FRESH',
    conflict: 'NONE' as const,
  };
  return { ...preimage, responseDigest: sha256CanonicalJson(preimage) };
};
