import { typedEnvelopeCreateCandidate } from '../../participant-service/src/contracts/envelope.js';

/** Only the same-Participant Platform-root creation is qualified for continuation.
 * This is eligibility, never a replacement for current actor fencing/no-effect SQL. */
export function isEnvelopeCreateResumeCandidate(
  input: {
    catalogOperationId: string;
    actionIntentId: string;
    resourceType: string;
    operationClass: string;
    expectedRevision: string;
    resourceId: string;
    participantId: string;
    document: unknown;
  },
  nowMs = Date.now(),
): boolean {
  const parsed = typedEnvelopeCreateCandidate.safeParse(input.document);
  return (
    input.catalogOperationId === 'ID-OP-ENVELOPE-CREATE' &&
    input.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' &&
    input.resourceType === 'participant' &&
    input.operationClass === 'UPDATE' &&
    input.expectedRevision === '0' &&
    parsed.success &&
    parsed.data.issuance === 'PLATFORM_ROOT' &&
    parsed.data.platformScopeReplacementId === undefined &&
    parsed.data.envelopeId === input.resourceId &&
    parsed.data.participantId === input.participantId &&
    BigInt(parsed.data.usable.validUntilNs) > BigInt(nowMs) * 1_000_000n &&
    BigInt(parsed.data.grantable.validUntilNs) > BigInt(nowMs) * 1_000_000n
  );
}
