import { signingRotationCandidateOperations } from '../../../../packages/security-kernel/src/signing-operations.js';
import { workloadSigningHandoverAdmissionOperation } from '../../../../packages/security-kernel/src/workload-signing-handover-operations.js';
import { participantMutationOperations } from '../../../../packages/security-kernel/src/participant-mutation-operations.js';
import { identityMutationOperations } from '../../../../packages/security-kernel/src/identity-mutation-operations.js';
import { workloadRenewalPolicyOperations } from '../../../../packages/security-kernel/src/workload-renewal-operations.js';
import {
  moduleRegistrationOperation,
  moduleLifecycleOperations,
} from '../../../../packages/security-kernel/src/module-mutation-operations.js';

interface CandidateColumns {
  readonly catalogOperationId: string;
  readonly actionIntentId: string;
  readonly resourceType: string;
  readonly operationClass: string;
}
const literal = (value: string) => `'${value.replaceAll("'", "''")}'`;
/** Columns are SQL fragments supplied only by the schema/query owners; values come from the sealed catalog. */
export function signingCandidateCatalogSql(columns: CandidateColumns): string {
  const sealed = [
    ...participantMutationOperations,
    ...identityMutationOperations,
    ...workloadRenewalPolicyOperations,
    moduleRegistrationOperation,
    ...moduleLifecycleOperations,
    ...signingRotationCandidateOperations,
    workloadSigningHandoverAdmissionOperation,
  ]
    .map(
      (operation) =>
        `(${Object.entries(columns)
          .map(([key, column]) => `${column}=${literal(operation[key as keyof CandidateColumns])}`)
          .join(' AND ')})`,
    )
    .join(' OR ');
  return `((${columns.resourceType} NOT IN ('signing-key-rotation','workload-signing-handover') AND ${columns.catalogOperationId} ~ '^CFG-OP-[A-Z0-9-]+$') OR ${sealed})`;
}
export const signingCandidateConstraintSql = signingCandidateCatalogSql({
  catalogOperationId: 'catalog_operation_id',
  actionIntentId: 'action_intent_id',
  resourceType: 'resource_type',
  operationClass: 'operation_class',
});
export const signingCandidateStagingSql = signingCandidateCatalogSql({
  catalogOperationId: '$18::text',
  actionIntentId: '$6::text',
  resourceType: '$15::text',
  operationClass: '$16::text',
});
export const signingCandidateApprovalSql = signingCandidateCatalogSql({
  catalogOperationId: 'candidate.catalog_operation_id',
  actionIntentId: 'candidate.action_intent_id',
  resourceType: 'candidate.resource_type',
  operationClass: 'candidate.operation_class',
});
