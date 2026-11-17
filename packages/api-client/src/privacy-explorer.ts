import { createClient } from '../generated/privacy-explorer/client/client.gen.js';
import type { Client, Config } from '../generated/privacy-explorer/client/types.gen.js';
import { readPrivacyExplorerProjection } from '../generated/privacy-explorer/sdk.gen.js';
import type {
  ExplorerProjectionRequestV1,
  PrivacyExplorerProblemV1,
  PrivacyExplorerResultV1,
} from '../generated/privacy-explorer/types.gen.js';
// @ts-expect-error B1's generated validator is JavaScript-only; this module owns the client bridge.
import * as generatedValidators from '../../../generated/typescript/json-schema/privacy-explorer.validator.mjs';

import { immutablePlainCopy } from './plain-data.js';

type GeneratedValidator = (value: unknown) => boolean;
const validators = generatedValidators as Record<string, GeneratedValidator>;
export type PrivacyExplorerProblem = Readonly<PrivacyExplorerProblemV1>;

export type PrivacyExplorerClientResult =
  | Readonly<{ data: PrivacyExplorerResultV1; problem?: never }>
  | Readonly<{ data?: never; problem: PrivacyExplorerProblem }>;
export type PrivacyExplorerClient = Readonly<{
  read(request: ExplorerProjectionRequestV1): Promise<PrivacyExplorerClientResult>;
}>;

const validateProblem = (value: unknown): PrivacyExplorerProblem => {
  const problem = immutablePlainCopy(value);
  if (!validators.validatePrivacyExplorerProblemV1?.(problem))
    throw new Error('invalid Privacy Explorer problem response');
  return problem as PrivacyExplorerProblem;
};

const validateRequest = async (value: unknown): Promise<ExplorerProjectionRequestV1> => {
  const request = immutablePlainCopy(value);
  if (!validators.validateExplorerProjectionRequestV1?.(request))
    throw new Error('invalid Privacy Explorer request');
  const typed = request as ExplorerProjectionRequestV1;
  const { digest: profileDigest, ...profilePreimage } = typed.exportProfile;
  const operation = typed.exportProfile.operationVersions.find(
    (entry) =>
      entry.operationId === typed.operationId && entry.version === typed.semanticOperationVersion,
  );
  const orderedUnique = (values: readonly string[]) =>
    values.every((entry, index) => index === 0 || values[index - 1]! < entry);
  if (
    profileDigest !== (await digest(profilePreimage)) ||
    typed.exportProfile.operationVersions.length !== 9 ||
    !orderedUnique(typed.exportProfile.operationVersions.map((entry) => entry.operationId)) ||
    !typed.exportProfile.operationVersions.every((entry) =>
      orderedUnique(entry.acceptedDataClassIds),
    ) ||
    !orderedUnique(typed.exportProfile.allowedFieldIds) ||
    !orderedUnique(typed.exportProfile.allowedFilterIds) ||
    typed.exportProfile.retryBackoffMilliseconds.length !==
      typed.exportProfile.maximumReadAttempts - 1 ||
    !operation?.acceptedDataClassIds.includes(typed.dataClassId) ||
    typed.scope.action !== typed.action ||
    typed.queryDigest !==
      (await digest({
        purpose: typed.purpose,
        subject: typed.subject,
        resource: typed.resource,
        action: typed.action,
        scope: typed.scope,
        operationId: typed.operationId,
        semanticOperationVersion: typed.semanticOperationVersion,
        dataClassId: typed.dataClassId,
        filters: typed.filters,
        page: { limit: typed.page.limit },
        projectionFields: typed.projectionFields,
        exportProfileDigest: typed.exportProfile.digest,
      }))
  )
    throw new Error('invalid Privacy Explorer request');
  return typed;
};

const canonicalJson = (value: unknown): string => {
  if (typeof value === 'number' && !Number.isSafeInteger(value))
    throw new Error('invalid canonical JSON number');
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'string' ||
    typeof value === 'number'
  )
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(',')}}`;
};

const digest = async (value: unknown) => {
  const bytes = new TextEncoder().encode(canonicalJson(value));
  const digestBytes = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return `sha256:${[...new Uint8Array(digestBytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
};

const validateResult = async (
  value: unknown,
  request: ExplorerProjectionRequestV1,
): Promise<PrivacyExplorerResultV1> => {
  const result = immutablePlainCopy(value);
  if (!validators.validatePrivacyExplorerResultV1?.(result))
    throw new Error('invalid Privacy Explorer result response');
  const typed = result as PrivacyExplorerResultV1;
  if (
    typed.profileDigest !== request.exportProfile.digest ||
    typed.queryDigest !== request.queryDigest ||
    typed.requestDigest !== (await digest(request))
  )
    throw new Error('invalid Privacy Explorer result response');
  const expectedDigest = await digest({
    schemaVersion: typed.schemaVersion,
    outcome: typed.outcome,
    truthState: typed.truthState,
    requestDigest: typed.requestDigest,
    profileDigest: typed.profileDigest,
    queryDigest: typed.queryDigest,
    records: typed.records,
    page: typed.page,
  });
  if (typed.resultDigest !== expectedDigest)
    throw new Error('invalid Privacy Explorer result response');
  return typed;
};

export const readPrivacyExplorer = async (
  client: Client,
  request: ExplorerProjectionRequestV1,
): Promise<PrivacyExplorerClientResult> => {
  const body = await validateRequest(request);
  let result: Readonly<{ data?: unknown; error?: unknown; response?: Response }>;
  try {
    result = (await readPrivacyExplorerProjection({
      body,
      client,
      responseStyle: 'fields',
      throwOnError: false,
    })) as Readonly<{ data?: unknown; error?: unknown; response?: Response }>;
  } catch {
    throw new Error('Privacy Explorer transport failed');
  }
  if (result.data !== undefined && result.error !== undefined)
    throw new Error('ambiguous Privacy Explorer response');
  if (result.error !== undefined) {
    const problem = validateProblem(result.error);
    if (!result.response || result.response.status !== problem.httpStatus)
      throw new Error('invalid Privacy Explorer problem response');
    return Object.freeze({ problem });
  }
  if (!result.response || result.response.status !== 200)
    throw new Error('invalid Privacy Explorer result response');
  return Object.freeze({ data: await validateResult(result.data, body) });
};

export const createPrivacyExplorerClient = (config: Config): PrivacyExplorerClient => {
  const client = createClient({ ...config, responseStyle: 'fields', throwOnError: false });
  return Object.freeze({
    read: (request: ExplorerProjectionRequestV1) => readPrivacyExplorer(client, request),
  });
};
