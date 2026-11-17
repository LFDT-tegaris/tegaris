import { executionRegistry } from '../contracts/privacy-explorer-adapter.js';

export type SafeProblem = Readonly<{
  code: string;
  httpStatus: number;
  jsonRpcCode: number;
  grpcStatus: string;
  truthState: string;
  retryable: boolean;
  disclosure: string;
  publicTitle: string;
}>;

type ConditionDefinition = (typeof executionRegistry.conditionDefinitions)[number];

export const safeProblemForCondition = (conditionId: string): SafeProblem => {
  const condition = executionRegistry.conditionDefinitions.find(
    (entry) => entry.id === conditionId,
  );
  if (!condition) throw new Error(`unknown Privacy Explorer condition: ${conditionId}`);
  const {
    code,
    httpStatus,
    jsonRpcCode,
    grpcStatus,
    truthState,
    retryable,
    disclosure,
    publicTitle,
  } = condition as ConditionDefinition;
  return Object.freeze({
    code,
    httpStatus,
    jsonRpcCode,
    grpcStatus,
    truthState,
    retryable,
    disclosure,
    publicTitle,
  });
};

const admitSafeProblem = (value: unknown): SafeProblem | undefined => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const candidate = value as Record<string, unknown>;
  const expectedKeys = [
    'code',
    'httpStatus',
    'jsonRpcCode',
    'grpcStatus',
    'truthState',
    'retryable',
    'disclosure',
    'publicTitle',
  ] as const;
  const ownKeys = Reflect.ownKeys(candidate);
  const prototype = Object.getPrototypeOf(candidate);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    ownKeys.length !== expectedKeys.length
  )
    return undefined;
  const admitted = Object.create(null) as Record<string, unknown>;
  for (const key of ownKeys) {
    if (typeof key !== 'string' || !expectedKeys.includes(key as never)) return undefined;
    const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return undefined;
    admitted[key] = descriptor.value;
  }
  if (
    typeof admitted.code !== 'string' ||
    typeof admitted.httpStatus !== 'number' ||
    typeof admitted.jsonRpcCode !== 'number' ||
    typeof admitted.grpcStatus !== 'string' ||
    typeof admitted.truthState !== 'string' ||
    typeof admitted.retryable !== 'boolean' ||
    typeof admitted.disclosure !== 'string' ||
    typeof admitted.publicTitle !== 'string'
  )
    return undefined;
  const condition = executionRegistry.conditionDefinitions.find(
    (entry) => entry.code === admitted.code,
  );
  if (!condition) return undefined;
  const expected = safeProblemForCondition(condition.id);
  return expectedKeys.every((key) => admitted[key] === expected[key]) ? expected : undefined;
};

export const isSafeProblem = (value: unknown): value is SafeProblem =>
  admitSafeProblem(value) !== undefined;

export const canonicalSafeProblem = (value: unknown): SafeProblem | undefined =>
  admitSafeProblem(value);
