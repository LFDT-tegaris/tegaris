import type {
  AdapterCallContextV1,
  EvidenceReferenceV1,
  EvidenceVerificationResultV1,
  PrivacyExplorerExportProfileV1,
  ExplorerProjectionRequestV1,
  ExplorerProjectionResultV1,
  PrivacyExplorerEvidenceDigestRecordV1,
  PrivacyExplorerProblemV1,
  PrivacyExplorerResultV1,
  PrivacyExplorerOccurrenceV1,
} from '../../../../generated/typescript/json-schema/privacy-explorer.js';
import { privacyExplorerExecutionRegistry } from '../../../../generated/typescript/privacy-explorer/execution-registry.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
// @ts-expect-error B1's generated validator is JavaScript-only; this adapter owns the bridge.
import * as generatedValidators from '../../../../generated/typescript/json-schema/privacy-explorer.validator.mjs';

type GeneratedValidator = ((value: unknown) => boolean) & {
  errors?: readonly Readonly<{ keyword?: string }>[] | null;
};

const validators = generatedValidators as Record<string, GeneratedValidator>;

const assertValid = <T>(name: string, value: unknown): T => {
  if (!validators[name]?.(value)) throw new Error(`invalid generated Privacy Explorer ${name}`);
  return immutableJsonCopy(value as T);
};

export type {
  AdapterCallContextV1,
  EvidenceReferenceV1,
  EvidenceVerificationResultV1,
  PrivacyExplorerExportProfileV1,
  ExplorerProjectionRequestV1,
  ExplorerProjectionResultV1,
  PrivacyExplorerEvidenceDigestRecordV1,
  PrivacyExplorerProblemV1,
  PrivacyExplorerResultV1,
  PrivacyExplorerOccurrenceV1,
};
export const executionRegistry = immutableJsonCopy(privacyExplorerExecutionRegistry);
export const assertAdapterCallContext = (value: unknown) =>
  assertValid<AdapterCallContextV1>('validateAdapterCallContextV1', value);
export const assertPrivacyExplorerExportProfile = (value: unknown) =>
  assertValid<PrivacyExplorerExportProfileV1>('validatePrivacyExplorerExportProfileV1', value);
export const assertExplorerProjectionRequest = (value: unknown) =>
  assertValid<ExplorerProjectionRequestV1>('validateExplorerProjectionRequestV1', value);
export const assertExplorerProjectionResult = (value: unknown) =>
  assertValid<ExplorerProjectionResultV1>('validateExplorerProjectionResultV1', value);
export const assertExplorerProjectionResultSchema = (value: unknown) => {
  const validator = validators.validateExplorerProjectionResultV1;
  const valid = validator?.(value);
  if (
    !valid &&
    !validator?.errors?.every((error) => error.keyword === 'x-openpc-order-or-relation')
  )
    throw new Error('invalid generated Privacy Explorer validateExplorerProjectionResultV1');
  return immutableJsonCopy(value as ExplorerProjectionResultV1);
};
export const assertPrivacyExplorerResult = (value: unknown) =>
  assertValid<PrivacyExplorerResultV1>('validatePrivacyExplorerResultV1', value);
export const assertPrivacyExplorerOccurrence = (value: unknown) =>
  assertValid<PrivacyExplorerOccurrenceV1>('validatePrivacyExplorerOccurrenceV1', value);
export const assertPrivacyExplorerEvidence = (value: unknown) =>
  assertValid<PrivacyExplorerEvidenceDigestRecordV1>(
    'validatePrivacyExplorerEvidenceDigestRecordV1',
    value,
  );
export const assertEvidenceReference = (value: unknown) =>
  assertValid<EvidenceReferenceV1>('validateEvidenceReferenceV1', value);
export const assertEvidenceVerificationResult = (value: unknown) =>
  assertValid<EvidenceVerificationResultV1>('validateEvidenceVerificationResultV1', value);
export const assertPrivacyExplorerProblem = (value: unknown) =>
  assertValid<PrivacyExplorerProblemV1>('validatePrivacyExplorerProblemV1', value);
