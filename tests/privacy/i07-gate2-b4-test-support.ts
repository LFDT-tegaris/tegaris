import type { ExplorerProjectionResultV1 } from '../../services/control-api/src/contracts/privacy-explorer-adapter.js';
import {
  bindLocalContext,
  type TerminalAuthorizationFacts,
} from '../../services/control-api/src/privacy-explorer/context.js';
import {
  narrowIntent,
  sha256CanonicalJson,
} from '../../services/control-api/src/privacy-explorer/narrowing.js';
import { preauthorize } from '../../services/control-api/src/privacy-explorer/preauthorization.js';
import {
  registerExplorerProfile,
  type ExplorerProfileRegistrationFacts,
} from '../../services/control-api/src/privacy-explorer/profile-registration.js';
import { redactProjection } from '../../services/control-api/src/privacy-explorer/redaction.js';
import { buildProjectionCandidate } from '../../services/control-api/src/privacy-explorer/result-candidate.js';
import {
  createProjectionRequest,
  type GovernedProjectionBoundary,
} from '../../services/control-api/src/privacy-explorer/request.js';
import {
  requireValidatedProjection,
  validateProjection,
} from '../../services/control-api/src/privacy-explorer/validation.js';
import {
  privacyExplorerNarrowing,
  privacyExplorerProfileFacts,
  privacyExplorerScope,
} from './i07-gate2-contract-fixture.js';

let nextIdentity = 0x100;
const digest = (character: string) => `sha256:${character.repeat(64)}`;
const uuid = () => `123e4567-e89b-42d3-a456-${(nextIdentity++).toString(16).padStart(12, '0')}`;

type BoundaryOptions = Readonly<{
  occurrenceId?: string;
  correlationId?: string;
  authorizationContextId?: string;
}>;

export const buildB4Boundary = (options: BoundaryOptions = {}): GovernedProjectionBoundary => {
  const occurrenceId = options.occurrenceId ?? uuid();
  const correlationId = options.correlationId ?? uuid();
  const facts: TerminalAuthorizationFacts = {
    authorizationDigest: digest('b'),
    authorizationContextId: options.authorizationContextId ?? uuid(),
    authorizationContextEpoch: 4,
    subject: 'subject-a',
    resource: 'resource-a',
    ...privacyExplorerScope,
    accessClassIds: ['ACCESS-PRIVATE'],
    allowedPurposeActions: [{ purpose: 'audit', action: 'read' }],
    allowedFieldIds: ['PEF-A', 'PEF-B'],
    auditCorrelationId: correlationId,
    occurrenceId,
    deadlineAt: '2028-01-01T00:00:00.000Z',
  };
  const profileFacts: ExplorerProfileRegistrationFacts = privacyExplorerProfileFacts(uuid());
  const context = bindLocalContext('terminal', {
    verify: (candidate) => (candidate === 'terminal' ? facts : undefined),
  });
  const profile = registerExplorerProfile('profile', {
    verify: (candidate) => (candidate === 'profile' ? profileFacts : undefined),
  });
  const intent = preauthorize(context, {
    purpose: 'audit',
    action: 'read',
    resource: 'resource-a',
  });
  const narrowed = narrowIntent(intent, profile, {
    ...privacyExplorerNarrowing,
    filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: 7 }],
    projectionFields: ['PEF-A', 'PEF-B'],
    page: { limit: 2, cursor: null },
  });
  return createProjectionRequest(narrowed, {
    now: '2027-01-01T00:00:00.000Z',
    deadlineAt: '2027-01-01T00:01:00.000Z',
    occurrenceId,
    auditCorrelationId: correlationId,
    cancellationOccurrenceId: occurrenceId,
    reconciliationOccurrenceId: occurrenceId,
  });
};

export const buildB4Candidate = (
  boundary: GovernedProjectionBoundary,
  outcome: 'COMPLETE' | 'PARTIAL' | 'UNKNOWN' | 'UNAVAILABLE' = 'COMPLETE',
) => {
  const records =
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
        ];
  const preimage = {
    schemaVersion: '1.0',
    requestDigest: boundary.requestDigest,
    profileDigest: boundary.request.exportProfile.digest,
    provenanceDigest: sha256CanonicalJson({
      profileDigest: boundary.request.exportProfile.digest,
      requestDigest: boundary.requestDigest,
      provenanceProfileDigest: boundary.request.exportProfile.provenanceProfileDigest,
    }),
    observedAt: boundary.request.issuedAt,
    records,
    page: {
      cursor: outcome === 'PARTIAL' ? 'next' : null,
      gapFree: outcome === 'COMPLETE',
    },
    completeness: outcome,
    freshness: outcome === 'UNKNOWN' || outcome === 'UNAVAILABLE' ? 'UNKNOWN' : 'FRESH',
    conflict: 'NONE',
  };
  const raw: ExplorerProjectionResultV1 = {
    ...preimage,
    schemaVersion: '1.0',
    completeness: outcome,
    freshness: outcome === 'UNKNOWN' || outcome === 'UNAVAILABLE' ? 'UNKNOWN' : 'FRESH',
    conflict: 'NONE',
    responseDigest: sha256CanonicalJson(preimage),
  };
  return buildProjectionCandidate(
    redactProjection(requireValidatedProjection(validateProjection(boundary, raw))),
  );
};
