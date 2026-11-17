import { types } from 'node:util';

import {
  assertPrivacyExplorerEvidence,
  type PrivacyExplorerEvidenceDigestRecordV1,
} from '../contracts/privacy-explorer-adapter.js';
import { sha256CanonicalJson } from './canonical.js';
import { requireExactOwnData } from './server-input.js';

export type PrivacyExplorerEvidenceSink = Readonly<{
  append(evidence: PrivacyExplorerEvidenceDigestRecordV1): Promise<unknown>;
}>;

export type PrivacyExplorerRouteAuditFact =
  | Readonly<{ phase: 'ADMISSION_REJECTED'; attemptId: string }>
  | Readonly<{ phase: 'ADMISSION_SUPPRESSED'; attemptId: string }>
  | Readonly<{
      phase: 'EXECUTION_REJECTED';
      attemptId: string;
      occurrenceId: string;
      correlationId: string;
    }>;

export type PrivacyExplorerRouteAuditSink = Readonly<{
  append(fact: PrivacyExplorerRouteAuditFact): Promise<unknown>;
}>;

export type PrivacyExplorerOperationalEvent = Readonly<{
  correlationId?: string;
  profileState: 'NOT_ADMITTED' | 'ADMITTED';
  outcomeClass: 'RELEASED' | 'SUPPRESSED' | 'SAFE_PROBLEM' | 'EVIDENCE_FAILURE' | 'AUDIT_FAILURE';
  durationMilliseconds: number;
  errorClass: 'NONE' | 'SERVICE_FAILURE' | 'EVIDENCE_FAILURE' | 'AUDIT_FAILURE';
}>;

export type PrivacyExplorerOperationalEventSink = Readonly<{
  emit(event: PrivacyExplorerOperationalEvent): Promise<unknown>;
}>;

export type PrivacyExplorerEvidenceReceipt = Readonly<Record<never, never>>;

type Acceptance = Readonly<{
  outcome: 'ACCEPTED' | 'CONFLICT';
  occurrenceId: string;
  scopeDigest: string;
  resultDigest: string;
  recordDigest: string;
}>;

const receipts = new WeakMap<
  PrivacyExplorerEvidenceReceipt,
  Readonly<{ sink: PrivacyExplorerEvidenceSink; acceptance: Acceptance }>
>();

const exactSink = (value: unknown): PrivacyExplorerEvidenceSink => {
  const admitted = requireExactOwnData(value, ['append'], 'Privacy Explorer evidence sink');
  if (typeof admitted.append !== 'function')
    throw new Error('invalid Privacy Explorer evidence sink');
  return Object.freeze({ append: admitted.append as PrivacyExplorerEvidenceSink['append'] });
};

const exactAuditSink = (value: unknown): PrivacyExplorerRouteAuditSink => {
  const admitted = requireExactOwnData(value, ['append'], 'Privacy Explorer route audit sink');
  if (typeof admitted.append !== 'function')
    throw new Error('invalid Privacy Explorer route audit sink');
  return Object.freeze({ append: admitted.append as PrivacyExplorerRouteAuditSink['append'] });
};

const exactOperationalEventSink = (value: unknown): PrivacyExplorerOperationalEventSink => {
  const admitted = requireExactOwnData(value, ['emit'], 'Privacy Explorer operational event sink');
  if (typeof admitted.emit !== 'function')
    throw new Error('invalid Privacy Explorer operational event sink');
  return Object.freeze({ emit: admitted.emit as PrivacyExplorerOperationalEventSink['emit'] });
};

const exactAcceptance = (value: unknown): Acceptance | undefined => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || types.isProxy(value))
    return undefined;
  const admitted = requireExactOwnData(
    value,
    ['outcome', 'occurrenceId', 'scopeDigest', 'resultDigest', 'recordDigest'],
    'Privacy Explorer evidence receipt',
  );
  if (
    (admitted.outcome !== 'ACCEPTED' && admitted.outcome !== 'CONFLICT') ||
    typeof admitted.occurrenceId !== 'string' ||
    typeof admitted.scopeDigest !== 'string' ||
    typeof admitted.resultDigest !== 'string' ||
    typeof admitted.recordDigest !== 'string'
  )
    return undefined;
  return Object.freeze(admitted) as Acceptance;
};

const exactAuditAcceptance = (value: unknown, fact: PrivacyExplorerRouteAuditFact) => {
  const admitted = requireExactOwnData(
    value,
    ['outcome', 'attemptId', 'auditDigest'],
    'Privacy Explorer audit receipt',
  );
  return (
    admitted.outcome === 'ACCEPTED' &&
    admitted.attemptId === fact.attemptId &&
    admitted.auditDigest === sha256CanonicalJson(fact) &&
    typeof admitted.attemptId === 'string' &&
    typeof admitted.auditDigest === 'string'
  );
};

export const requirePrivacyExplorerEvidenceSink = (value: unknown) => exactSink(value);
export const requirePrivacyExplorerRouteAuditSink = (value: unknown) => exactAuditSink(value);
export const requirePrivacyExplorerOperationalEventSink = (value: unknown) =>
  exactOperationalEventSink(value);

export const appendPrivacyExplorerRouteAudit = async (
  sink: PrivacyExplorerRouteAuditSink,
  fact: PrivacyExplorerRouteAuditFact,
) => {
  if (!exactAuditAcceptance(await sink.append(fact), fact))
    throw new Error('Privacy Explorer audit was not accepted');
};

export const appendPrivacyExplorerEvidence = async (
  sink: PrivacyExplorerEvidenceSink,
  evidence: PrivacyExplorerEvidenceDigestRecordV1,
): Promise<PrivacyExplorerEvidenceReceipt | 'CONFLICT'> => {
  const record = assertPrivacyExplorerEvidence(evidence);
  const acceptance = exactAcceptance(await sink.append(record));
  if (!acceptance) throw new Error('Privacy Explorer evidence was not accepted');
  if (
    acceptance.occurrenceId !== record.occurrenceId ||
    acceptance.scopeDigest !== record.scopeDigest ||
    acceptance.resultDigest !== record.resultDigest ||
    acceptance.recordDigest !== sha256CanonicalJson(record)
  )
    throw new Error('Privacy Explorer evidence receipt identity mismatch');
  if (acceptance.outcome === 'CONFLICT') return 'CONFLICT';
  const receipt = Object.freeze({});
  receipts.set(receipt, Object.freeze({ sink, acceptance }));
  return receipt;
};

export const requirePrivacyExplorerEvidenceReceipt = (
  receipt: PrivacyExplorerEvidenceReceipt,
  sink: PrivacyExplorerEvidenceSink,
  evidence: PrivacyExplorerEvidenceDigestRecordV1,
) => {
  const admitted = receipts.get(receipt);
  if (!admitted || admitted.sink !== sink)
    throw new Error('invalid Privacy Explorer evidence receipt');
  const record = assertPrivacyExplorerEvidence(evidence);
  if (
    admitted.acceptance.occurrenceId !== record.occurrenceId ||
    admitted.acceptance.scopeDigest !== record.scopeDigest ||
    admitted.acceptance.resultDigest !== record.resultDigest ||
    admitted.acceptance.recordDigest !== sha256CanonicalJson(record)
  )
    throw new Error('invalid Privacy Explorer evidence receipt');
  return receipt;
};
