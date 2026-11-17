import { immutableJsonCopy } from './immutable.js';
import { boundedString, canonicalSet, validDateTime } from './profile-registration.js';

export type PurposeAction = Readonly<{ purpose: string; action: string }>;
export type TerminalAuthorizationFacts = Readonly<{
  authorizationDigest: string;
  authorizationContextId: string;
  authorizationContextEpoch: number;
  subject: string;
  resource: string;
  participantId: string;
  privacyDomainId: string;
  platformId: string;
  workloadId: string;
  accessClassIds: readonly string[];
  allowedPurposeActions: readonly PurposeAction[];
  allowedFieldIds: readonly string[];
  auditCorrelationId: string;
  occurrenceId: string;
  deadlineAt: string;
}>;
export interface TerminalAuthorizationVerifier {
  verify(candidate: unknown): TerminalAuthorizationFacts | undefined;
}
export type PrivacyExplorerLocalContext = Readonly<TerminalAuthorizationFacts>;

const contexts = new WeakSet<PrivacyExplorerLocalContext>();
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const digest = /^sha256:[0-9a-f]{64}$/;
const comparePurposeAction = (left: PurposeAction, right: PurposeAction) => {
  if (left.purpose !== right.purpose) return left.purpose < right.purpose ? -1 : 1;
  return left.action < right.action ? -1 : left.action > right.action ? 1 : 0;
};

const purposeActions = (value: unknown) => {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32)
    throw new Error('purpose/actions: invalid bounds');
  const result = value
    .map((entry) => {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry))
        throw new Error('purpose/actions: invalid value');
      const record = entry as Record<string, unknown>;
      if (Object.keys(record).length !== 2 || !('purpose' in record) || !('action' in record))
        throw new Error('purpose/actions: invalid shape');
      return immutableJsonCopy({
        purpose: boundedString(record.purpose, 'purpose'),
        action: boundedString(record.action, 'action'),
      });
    })
    .sort(comparePurposeAction);
  if (
    result.some(
      (entry, index) => index > 0 && comparePurposeAction(entry, result[index - 1]!) === 0,
    )
  )
    throw new Error('purpose/actions: duplicate value');
  return Object.freeze(result);
};

export const bindLocalContext = (
  terminalAuthorization: unknown,
  verifier: TerminalAuthorizationVerifier,
): PrivacyExplorerLocalContext => {
  const verified = verifier.verify(terminalAuthorization);
  if (!verified) throw new Error('terminal authorization denied');
  if (
    !digest.test(verified.authorizationDigest) ||
    !uuid.test(verified.authorizationContextId) ||
    !uuid.test(verified.auditCorrelationId) ||
    !uuid.test(verified.occurrenceId) ||
    !Number.isInteger(verified.authorizationContextEpoch) ||
    verified.authorizationContextEpoch < 0 ||
    verified.authorizationContextEpoch > Number.MAX_SAFE_INTEGER
  )
    throw new Error('authorization context: invalid');
  const context = immutableJsonCopy({
    authorizationDigest: verified.authorizationDigest,
    authorizationContextId: verified.authorizationContextId,
    authorizationContextEpoch: verified.authorizationContextEpoch,
    subject: boundedString(verified.subject, 'subject'),
    resource: boundedString(verified.resource, 'resource'),
    participantId: boundedString(verified.participantId, 'participant'),
    privacyDomainId: boundedString(verified.privacyDomainId, 'privacy domain'),
    platformId: boundedString(verified.platformId, 'platform'),
    workloadId: boundedString(verified.workloadId, 'workload'),
    accessClassIds: canonicalSet(
      verified.accessClassIds,
      'access classes',
      32,
      /^ACCESS-[A-Z0-9-]{1,64}$/,
    ),
    allowedPurposeActions: purposeActions(verified.allowedPurposeActions),
    allowedFieldIds: canonicalSet(
      verified.allowedFieldIds,
      'field allowlist',
      64,
      /^PEF-[A-Z0-9-]{1,64}$/,
    ),
    auditCorrelationId: verified.auditCorrelationId,
    occurrenceId: verified.occurrenceId,
    deadlineAt: validDateTime(verified.deadlineAt, 'authorization deadline'),
  });
  contexts.add(context);
  return context;
};
export const requireLocalContext = (value: unknown): PrivacyExplorerLocalContext => {
  if (!value || typeof value !== 'object' || !contexts.has(value as PrivacyExplorerLocalContext))
    throw new Error('unverified local context');
  return value as PrivacyExplorerLocalContext;
};
