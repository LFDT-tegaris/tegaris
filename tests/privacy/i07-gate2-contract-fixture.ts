import type { ExplorerProfileRegistrationFacts } from '../../services/control-api/src/privacy-explorer/profile-registration.js';
import { sha256CanonicalJson } from '../../services/control-api/src/privacy-explorer/canonical.js';

export const privacyExplorerScope = Object.freeze({
  participantId: 'participant-a',
  privacyDomainId: 'privacy-a',
  platformId: 'platform-a',
  workloadId: 'workload-a',
});

export const privacyExplorerNarrowing = Object.freeze({
  operationId: 'OP-01',
  semanticOperationVersion: '1',
  dataClassId: 'CLASS-READ',
});

const operationVersions: ExplorerProfileRegistrationFacts['operationVersions'] = [
  { operationId: 'OP-01', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
  { operationId: 'OP-02', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
  { operationId: 'OP-03', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
  { operationId: 'OP-04', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
  { operationId: 'OP-05', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
  { operationId: 'OP-06', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
  { operationId: 'OP-07', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
  { operationId: 'OP-08', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
  { operationId: 'OP-09', version: '1', acceptedDataClassIds: ['CLASS-READ'] },
];

export const privacyExplorerProfileFacts = (
  registrationId: string,
  allowedFilterIds: readonly string[] = ['PEFILTER-A', 'PEFILTER-B'],
  maximumDeadlineAt = '9999-12-31T23:59:59.000Z',
): ExplorerProfileRegistrationFacts => {
  const profile = {
    id: 'local-qualified-profile',
    version: '1',
    operationVersions,
    allowedFieldIds: ['PEF-A', 'PEF-B'] as [string, ...string[]],
    allowedFilterIds: [...allowedFilterIds] as [string, ...string[]],
    maximumPageSize: 200,
    responseSchemaVersion: '1.0' as const,
    maximumFreshnessAgeMilliseconds: 60_000,
    provenanceProfileDigest: `sha256:${'d'.repeat(64)}`,
    privacyProjectionId: 'PROJECTION-LOCAL-1',
    redactionProfileId: 'REDACTION-LOCAL-1',
    evidenceClassId: 'EVIDENCE-LOCAL-1',
    maximumDeadlineAt,
    maximumReadAttempts: 2,
    retryBackoffMilliseconds: [0] as [number],
  };
  return Object.freeze({
    registrationId,
    ...profile,
    digest: sha256CanonicalJson(profile),
  });
};
