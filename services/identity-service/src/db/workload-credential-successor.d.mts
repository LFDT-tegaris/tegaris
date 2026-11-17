export function workloadCredentialSuccessorSql(binding: {
  participantId: string;
  privacyDomainId: string;
  predecessorId: string;
  successorId: string;
  predecessorEpoch: string;
  successorEpoch: string;
  operationId?: string;
}): string;
export const workloadCredentialContinuationReadSql: string;
