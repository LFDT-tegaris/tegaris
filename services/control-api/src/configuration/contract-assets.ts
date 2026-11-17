import { transactionPolicySchema } from './transaction-policy.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { z } from 'zod';

import { canonicalJson, sha256 } from './digest.js';
import { digestSchema, openPcUrnSchema } from './resource-contracts.js';

const actionSchema = z.object({
  actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
});
const versionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u);
const addressSchema = z.string().regex(/^0x[0-9a-fA-F]{40}$/u);
const selectorSchema = z.string().regex(/^0x[0-9a-f]{8}$/u);
const signatureSchema = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*\([^\s]*\)$/u);
const canonicalAbiType =
  /^(?:address|bool|string|bytes(?:[1-9]|[12][0-9]|3[0-2])?|int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)|uint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)|tuple)(?:\[(?:[1-9][0-9]{0,3})?\])*$/u;

const abiParameterSchema: z.ZodType<unknown> = z.lazy(() =>
  z
    .object({
      name: z.string().max(256).optional(),
      type: z.string().regex(canonicalAbiType),
      internalType: z.string().max(512).optional(),
      components: z.array(abiParameterSchema).max(256).optional(),
      indexed: z.boolean().optional(),
    })
    .strict(),
);

const functionAbiItemSchema = z
  .object({
    type: z.literal('function'),
    name: z
      .string()
      .regex(/^[A-Za-z_][A-Za-z0-9_]*$/u)
      .max(256),
    inputs: z.array(abiParameterSchema).max(256),
    outputs: z.array(abiParameterSchema).max(256),
    stateMutability: z.enum(['pure', 'view', 'nonpayable', 'payable']),
  })
  .strict();
const eventAbiItemSchema = z
  .object({
    type: z.literal('event'),
    name: z
      .string()
      .regex(/^[A-Za-z_][A-Za-z0-9_]*$/u)
      .max(256),
    inputs: z.array(abiParameterSchema).max(256),
    anonymous: z.boolean(),
  })
  .strict();
const errorAbiItemSchema = z
  .object({
    type: z.literal('error'),
    name: z
      .string()
      .regex(/^[A-Za-z_][A-Za-z0-9_]*$/u)
      .max(256),
    inputs: z.array(abiParameterSchema).max(256),
  })
  .strict();
const abiItemSchema = z.union([
  functionAbiItemSchema,
  eventAbiItemSchema,
  errorAbiItemSchema,
  z
    .object({
      type: z.literal('constructor'),
      inputs: z.array(abiParameterSchema).max(256),
      stateMutability: z.enum(['nonpayable', 'payable']),
    })
    .strict(),
  z.object({ type: z.literal('receive'), stateMutability: z.literal('payable') }).strict(),
  z
    .object({ type: z.literal('fallback'), stateMutability: z.enum(['nonpayable', 'payable']) })
    .strict(),
]);

type AbiParameter = {
  readonly name?: string;
  readonly type: string;
  readonly components?: readonly AbiParameter[];
  readonly indexed?: boolean;
};

function canonicalParameterType(parameter: AbiParameter): string {
  if (!parameter.type.startsWith('tuple')) return parameter.type;
  if (parameter.components === undefined) throw new Error('PC-FACT-4001');
  return `(${parameter.components.map(canonicalParameterType).join(',')})${parameter.type.slice(5)}`;
}

export function functionSignature(item: unknown): string | undefined {
  const parsed = functionAbiItemSchema.safeParse(item);
  if (!parsed.success) return undefined;
  try {
    return `${parsed.data.name}(${parsed.data.inputs
      .map((input) => canonicalParameterType(input as AbiParameter))
      .join(',')})`;
  } catch {
    return undefined;
  }
}

/** Canonical event identity shares the admitted ABI parameter type owner. */
export function eventSignature(item: unknown): string | undefined {
  const parsed = eventAbiItemSchema.safeParse(item);
  if (!parsed.success) return undefined;
  try {
    return `${parsed.data.name}(${parsed.data.inputs.map((input) => canonicalParameterType(input as AbiParameter)).join(',')})`;
  } catch {
    return undefined;
  }
}

function validateParameter(
  value: unknown,
  context: z.RefinementCtx,
  path: readonly (string | number)[],
  indexedAllowed: boolean,
  depth = 0,
): void {
  const parameter = value as AbiParameter;
  const tuple = parameter.type.startsWith('tuple');
  if (tuple !== Array.isArray(parameter.components)) {
    context.addIssue({ code: 'custom', message: 'PC-FACT-4001', path: [...path, 'components'] });
  }
  if (!indexedAllowed && parameter.indexed !== undefined) {
    context.addIssue({ code: 'custom', message: 'PC-FACT-4001', path: [...path, 'indexed'] });
  }
  const dimensions = parameter.type.match(/\[[0-9]*\]/gu)?.length ?? 0;
  if (depth + dimensions > 16 || (tuple && parameter.components?.length === 0)) {
    context.addIssue({ code: 'custom', message: 'PC-FACT-4001', path: [...path, 'type'] });
  }
  parameter.components?.forEach((component, index) =>
    validateParameter(
      component,
      context,
      [...path, 'components', index],
      false,
      depth + dimensions + 1,
    ),
  );
}

function validateAbi(abi: readonly unknown[], context: z.RefinementCtx): void {
  const signatures = new Set<string>();
  const selectors = new Set<string>();
  abi.forEach((item, index) => {
    const typed = item as {
      readonly type?: string;
      readonly inputs?: unknown[];
      readonly outputs?: unknown[];
    };
    typed.inputs?.forEach((parameter, parameterIndex) =>
      validateParameter(
        parameter,
        context,
        [index, 'inputs', parameterIndex],
        typed.type === 'event',
      ),
    );
    typed.outputs?.forEach((parameter, parameterIndex) =>
      validateParameter(parameter, context, [index, 'outputs', parameterIndex], false),
    );
    const signature = functionSignature(item);
    if (signature !== undefined) {
      const selector = selectorFor(signature);
      if (signatures.has(signature) || selectors.has(selector)) {
        context.addIssue({ code: 'custom', message: 'PC-FACT-4001', path: [index] });
      }
      signatures.add(signature);
      selectors.add(selector);
    }
  });
}

export const createAbiArtifactSchema = actionSchema
  .extend({
    abi: z.array(abiItemSchema).min(1).max(4096),
    sourceDocument: z
      .string()
      .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u),
    provenance: z
      .object({
        source: z.enum(['AUTHENTICATED_REGISTRY', 'SOURCE_REPOSITORY', 'LOCAL_FIXTURE']),
        locator: z.string().min(1).max(2048),
        retrievedAt: z.iso.datetime({ offset: true }),
        sourceDigest: digestSchema,
      })
      .strict(),
    abiDigest: digestSchema,
  })
  .strict()
  .superRefine(({ abi }, context) => validateAbi(abi, context));

export const createLogicalContractSchema = actionSchema
  .extend({
    logicalName: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u),
    displayName: z.string().min(1).max(256),
  })
  .strict();

export const createRuntimeBindingSchema = actionSchema
  .extend({
    resourceId: z.uuidv7().optional(),
    logicalContractId: openPcUrnSchema,
    chainId: z.string().regex(/^[0-9]{1,20}$/u),
    networkId: z.string().min(1).max(128),
    genesisDigest: digestSchema,
    contractAddress: addressSchema,
    codeDigest: digestSchema,
    proxyAddress: addressSchema.optional(),
    implementationAddress: addressSchema.optional(),
    implementationCodeDigest: digestSchema.optional(),
    abiArtifactId: openPcUrnSchema,
    abiDigest: digestSchema,
    abiVersion: versionSchema,
    transactionPolicy: transactionPolicySchema.optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const proxyValues = [
      value.proxyAddress,
      value.implementationAddress,
      value.implementationCodeDigest,
    ];
    if (
      proxyValues.some((entry) => entry === undefined) &&
      proxyValues.some((entry) => entry !== undefined)
    ) {
      context.addIssue({ code: 'custom', message: 'PC-FACT-4001', path: ['proxyAddress'] });
    }
  });

const equality = z.enum(['EQ', 'IN']);
const comparison = z.enum(['EQ', 'IN', 'LT', 'LTE', 'GT', 'GTE']);
const parameterPath = z
  .string()
  .regex(/^inputs\[[0-9]+\](?:\.(?:[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\]))*$/u);
export const typedArgumentRuleSchema = z.discriminatedUnion('operandType', [
  z
    .object({
      parameterPath,
      operandType: z.literal('ADDRESS'),
      operator: equality,
      values: z.array(addressSchema).min(1).max(64),
    })
    .strict(),
  z
    .object({
      parameterPath,
      operandType: z.literal('BOOLEAN'),
      operator: equality,
      values: z.array(z.boolean()).min(1).max(2),
    })
    .strict(),
  z
    .object({
      parameterPath,
      operandType: z.literal('BYTES32'),
      operator: equality,
      values: z
        .array(z.string().regex(/^0x[0-9a-f]{64}$/u))
        .min(1)
        .max(64),
    })
    .strict(),
  z
    .object({
      parameterPath,
      operandType: z.literal('INTEGER'),
      operator: comparison,
      values: z
        .array(z.string().regex(/^-?(?:0|[1-9][0-9]{0,77})$/u))
        .min(1)
        .max(64),
    })
    .strict(),
  z
    .object({
      parameterPath,
      operandType: z.literal('STRING'),
      operator: equality,
      values: z.array(z.string().max(4096)).min(1).max(64),
    })
    .strict(),
]);

export const createArgumentRuleVersionSchema = actionSchema
  .extend({
    runtimeBindingId: openPcUrnSchema,
    abiArtifactId: openPcUrnSchema,
    abiDigest: digestSchema,
    canonicalSignature: signatureSchema,
    version: versionSchema,
    namedSetVersions: z
      .array(
        z
          .object({
            ownerId: openPcUrnSchema,
            setId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u),
            version: versionSchema,
            digest: digestSchema,
          })
          .strict(),
      )
      .max(0),
    rules: z.array(typedArgumentRuleSchema).min(1).max(256),
  })
  .strict();

export const createContractMethodPolicySchema = actionSchema
  .extend({
    runtimeBindingId: openPcUrnSchema,
    abiArtifactId: openPcUrnSchema,
    abiDigest: digestSchema,
    canonicalSignature: signatureSchema,
    selector: selectorSchema,
    effect: z.enum(['READ', 'WRITE']),
    requiredRoles: z.array(z.string().min(1).max(160)).min(1).max(64),
    approvalRequirement: z.enum(['NONE', 'SINGLE', 'MAKER_CHECKER']),
    mfaRequirement: z.enum(['NONE', 'WEBAUTHN']),
    environments: z.array(z.enum(['LOCAL', 'DEVELOPMENT', 'TEST', 'PRODUCTION'])).min(1),
    argumentRuleVersionId: openPcUrnSchema.optional(),
    rpcMethodPolicyDigest: digestSchema,
    nestedCallSetDigest: digestSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if (new Set(value.requiredRoles).size !== value.requiredRoles.length) {
      context.addIssue({ code: 'custom', message: 'PC-FACT-4001', path: ['requiredRoles'] });
    }
    if (new Set(value.environments).size !== value.environments.length) {
      context.addIssue({ code: 'custom', message: 'PC-FACT-4001', path: ['environments'] });
    }
  });

export const abiArtifactResponseSchema = z
  .object({
    abiArtifactId: openPcUrnSchema,
    abiDigest: digestSchema,
    provenance: z
      .object({
        source: z.string(),
        locator: z.string(),
        retrievedAt: z.string(),
        sourceDigest: digestSchema,
      })
      .strict(),
    canonicalAbi: z.array(abiItemSchema),
    // Immutable creation provenance; absence is governed pre-generation preparation.
    policyGenerationDigest: digestSchema.nullable(),
    revision: z.string().regex(/^[1-9][0-9]*$/u),
    createdAt: z.string(),
  })
  .strict();

const durableRecordFields = {
  // Immutable creation provenance; absence is governed pre-generation preparation.
  policyGenerationDigest: digestSchema.nullable(),
  revision: z.string().regex(/^[1-9][0-9]*$/u),
  createdAt: z.string(),
};

export const logicalContractResponseSchema = z
  .object({
    logicalContractId: openPcUrnSchema,
    logicalName: z.string(),
    displayName: z.string(),
    ...durableRecordFields,
  })
  .strict();

export const runtimeBindingResponseSchema = z
  .object({
    runtimeBindingId: openPcUrnSchema,
    logicalContractId: openPcUrnSchema,
    abiArtifactId: openPcUrnSchema,
    chainId: z.string(),
    networkId: z.string(),
    genesisDigest: digestSchema,
    contractAddress: addressSchema,
    codeDigest: digestSchema,
    proxyAddress: addressSchema.nullable(),
    implementationAddress: addressSchema.nullable(),
    implementationCodeDigest: digestSchema.nullable(),
    abiDigest: digestSchema,
    abiVersion: versionSchema,
    transactionPolicy: transactionPolicySchema.nullable(),
    state: z.enum(['BOUND', 'QUARANTINED', 'RETIRED']),
    ...durableRecordFields,
  })
  .strict();

export const argumentRuleVersionResponseSchema = z
  .object({
    argumentRuleVersionId: openPcUrnSchema,
    runtimeBindingId: openPcUrnSchema,
    abiArtifactId: openPcUrnSchema,
    canonicalSignature: signatureSchema,
    version: versionSchema,
    ruleDigest: digestSchema,
    state: z.enum(['PREPARED', 'ACTIVE', 'RETIRED']),
    namedSetVersions: z.array(
      z
        .object({
          ownerId: openPcUrnSchema,
          setId: z.string(),
          version: versionSchema,
          digest: digestSchema,
        })
        .strict(),
    ),
    rules: z.array(typedArgumentRuleSchema),
    ...durableRecordFields,
  })
  .strict();

export const contractMethodPolicyResponseSchema = z
  .object({
    contractMethodPolicyId: openPcUrnSchema,
    runtimeBindingId: openPcUrnSchema,
    abiArtifactId: openPcUrnSchema,
    canonicalSignature: signatureSchema,
    selector: selectorSchema,
    effect: z.enum(['READ', 'WRITE']),
    requiredRoles: z.array(z.string()),
    approvalRequirement: z.enum(['NONE', 'SINGLE', 'MAKER_CHECKER']),
    mfaRequirement: z.enum(['NONE', 'WEBAUTHN']),
    environments: z.array(z.enum(['LOCAL', 'DEVELOPMENT', 'TEST', 'PRODUCTION'])),
    argumentRuleVersionId: openPcUrnSchema.nullable(),
    rpcMethodPolicyDigest: digestSchema,
    nestedCallSetDigest: digestSchema,
    state: z.enum(['PREPARED', 'ACTIVE', 'RETIRED', 'QUARANTINED']),
    ...durableRecordFields,
  })
  .strict();

export function canonicalAbiBytes(abi: readonly unknown[]): Buffer {
  return Buffer.from(canonicalJson(abi), 'utf8');
}

export function selectorFor(signature: string): `0x${string}` {
  return `0x${Buffer.from(keccak_256(new TextEncoder().encode(signature)))
    .toString('hex')
    .slice(0, 8)}`;
}

export function assertAbiContainsFunction(abi: readonly unknown[], signature: string): void {
  // Revalidate persisted imports as well: an older ABI may contain two different
  // signatures with the same four-byte selector, even before either has a policy.
  const functions = abi.map(functionSignature).filter((value) => value !== undefined);
  if (
    !functions.includes(signature) ||
    new Set(functions.map(selectorFor)).size !== functions.length
  )
    throw new Error('PC-FACT-4001');
}

function parameterTypeFor(
  abi: readonly unknown[],
  signature: string,
  path: string,
): string | undefined {
  const fn = abi
    .map((item) => functionAbiItemSchema.safeParse(item))
    .find((item) => item.success && functionSignature(item.data) === signature)?.data;
  const root = /^inputs\[([0-9]+)\](.*)$/u.exec(path);
  if (fn === undefined || root === null) return undefined;
  let parameter = fn.inputs[Number(root[1])] as AbiParameter | undefined;
  if (parameter === undefined) return undefined;
  let parameterType = parameter.type;
  for (const segment of root[2]!.split('.').filter(Boolean)) {
    if (/^\[[0-9]+\]$/u.test(segment)) {
      const dimension = /\[([0-9]*)\]$/u.exec(parameterType);
      const index = Number(segment.slice(1, -1));
      if (
        dimension === null ||
        !Number.isSafeInteger(index) ||
        (dimension[1] !== '' && index >= Number(dimension[1]))
      ) {
        return undefined;
      }
      parameterType = parameterType.slice(0, dimension.index);
      continue;
    }
    if (parameterType !== 'tuple') return undefined;
    parameter = parameter.components?.find((component) => component.name === segment);
    if (parameter === undefined) return undefined;
    parameterType = parameter.type;
  }
  return parameterType.includes('[') ? undefined : parameterType;
}

function operandTypeFor(parameterType: string): string | undefined {
  if (parameterType === 'address') return 'ADDRESS';
  if (parameterType === 'bool') return 'BOOLEAN';
  if (parameterType === 'bytes32') return 'BYTES32';
  if (/^u?int[0-9]+$/u.test(parameterType)) return 'INTEGER';
  if (parameterType === 'string') return 'STRING';
  return undefined;
}

function integerFits(value: string, parameterType: string): boolean {
  const match = /^(u?)int([0-9]+)$/u.exec(parameterType);
  if (match === null) return false;
  const bits = BigInt(match[2]!);
  const parsed = BigInt(value);
  if (match[1] === 'u') return parsed >= 0n && parsed < 1n << bits;
  const limit = 1n << (bits - 1n);
  return parsed >= -limit && parsed < limit;
}

function canonicalRuleValue(value: string | boolean, operandType: string): string {
  if (operandType === 'ADDRESS' || operandType === 'BYTES32') return String(value).toLowerCase();
  if (operandType === 'INTEGER') return BigInt(String(value)).toString();
  return String(value);
}

export function assertArgumentRulesMatchAbi(
  abi: readonly unknown[],
  signature: string,
  rules: readonly {
    readonly parameterPath: string;
    readonly operandType: string;
    readonly operator?: string;
    readonly values?: readonly (string | boolean)[];
  }[],
): void {
  assertAbiContainsFunction(abi, signature);
  const canonicalRules = new Set<string>();
  for (const rule of rules) {
    const parameterType = parameterTypeFor(abi, signature, rule.parameterPath);
    const values = rule.values;
    if (
      parameterType === undefined ||
      operandTypeFor(parameterType) !== rule.operandType ||
      (values !== undefined && rule.operator !== 'IN' && values.length !== 1) ||
      (values !== undefined &&
        rule.operandType === 'INTEGER' &&
        values.some((value) => !integerFits(String(value), parameterType)))
    ) {
      throw new Error('PC-FACT-4001');
    }
    if (values !== undefined) {
      const canonicalValues = values.map((value) => canonicalRuleValue(value, rule.operandType));
      if (new Set(canonicalValues).size !== canonicalValues.length) {
        throw new Error('PC-FACT-4001');
      }
      const identity = canonicalJson({
        parameterPath: rule.parameterPath,
        operandType: rule.operandType,
        operator: rule.operator,
        values: canonicalValues,
      });
      if (canonicalRules.has(identity)) throw new Error('PC-FACT-4001');
      canonicalRules.add(identity);
    }
  }
}

export function ruleDigest(input: unknown): string {
  return sha256(input);
}
