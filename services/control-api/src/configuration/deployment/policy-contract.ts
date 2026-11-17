import { keccak_256 } from '@noble/hashes/sha3.js';
import { z } from 'zod';

import { sha256 } from '../digest.js';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';
import { transactionPolicySchema } from '../transaction-policy.js';

const address = z.string().regex(/^0x[0-9a-f]{40}$/u);
const hash = z.string().regex(/^0x[0-9a-f]{64}$/u);
const identifier = z.string().regex(/^[A-Za-z][A-Za-z0-9_.:@/-]{1,191}$/u);
const resourceReference = resourceUrnSchema.refine((value) =>
  value.startsWith('urn:openpc:resource:'),
);
const factory = {
  runtimeBindingId: resourceReference,
  canonicalSignature: z
    .string()
    .regex(/^[A-Za-z_][A-Za-z0-9_]*\((?:bytes|bytes,bytes32|bytes32,bytes)\)$/u),
  codeHash: hash,
  adapterDigest: digestSchema,
};

/** The admitted reference grammar is explicit. Publishing this definition is
 * not provider/tracer certification, activation, an intent or permission to send.
 * Other mechanisms and assurance profiles retain their own admission requirements.
 */
export const deploymentPolicyDefinitionSchema = z
  .strictObject({
    schemaVersion: z.literal('1.0.0'),
    profileId: identifier,
    profileVersion: z.string().regex(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u),
    assuranceLevel: z.literal('A0'),
    creationEvidence: z.enum([
      'COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1',
      'COMPLETE_SOLADY_CREATE3_CALL_AND_OPCODE_V1',
    ]),
    chainId: z
      .string()
      .regex(/^[1-9][0-9]{0,19}$/u)
      .pipe(z.string().refine((value) => BigInt(value) <= 18446744073709551615n)),
    networkId: identifier,
    genesisDigest: digestSchema,
    abiArtifactId: resourceReference,
    artifact: z.strictObject({
      mode: z.literal('EXACT_INIT_CODE'),
      initCode: z
        .string()
        .regex(/^0x(?:[0-9a-f]{2})+$/u)
        .max(65_538),
      runtimeCodeHash: hash,
    }),
    route: z.discriminatedUnion('mechanism', [
      z.strictObject({ mechanism: z.literal('TRANSACTION_CREATE') }),
      z.strictObject({ mechanism: z.literal('CREATE'), ...factory }),
      z.strictObject({
        mechanism: z.literal('CREATE2'),
        ...factory,
        arguments: z.enum(['INIT_CODE_SALT', 'SALT_INIT_CODE']),
        saltNamespaceDigest: digestSchema,
        saltTransform: z.enum(['IDENTITY', 'KECCAK_SENDER_SALT']),
      }),
      z.strictObject({
        mechanism: z.literal('CREATE3'),
        ...factory,
        arguments: z.enum(['INIT_CODE_SALT', 'SALT_INIT_CODE']),
        saltNamespaceDigest: digestSchema,
        saltTransform: z.enum(['IDENTITY', 'KECCAK_SENDER_SALT']),
        helperProfile: z.literal('SOLADY_CREATE3_V0_1_26'),
      }),
    ]),
    allowedSenders: z.array(address).min(1).max(256),
    requiredRoles: z.array(identifier).min(1).max(64),
    approvalRequirement: z.enum(['NONE', 'MAKER_CHECKER']),
    webauthnRequired: z.boolean(),
    transactionPolicy: transactionPolicySchema,
    expiresAt: z.iso.datetime({ precision: 3 }),
  })
  .superRefine((definition, context) => {
    const reject = (message: string) => context.addIssue({ code: 'custom', message });
    const evidence =
      definition.route.mechanism === 'CREATE3'
        ? 'COMPLETE_SOLADY_CREATE3_CALL_AND_OPCODE_V1'
        : 'COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1';
    if (definition.creationEvidence !== evidence)
      reject('creation evidence does not match the named route');
    for (const values of [definition.allowedSenders, definition.requiredRoles])
      if (values.some((value, index) => index > 0 && values[index - 1]! >= value))
        reject('policy sets must be sorted and unique');
    if (
      definition.route.mechanism !== 'TRANSACTION_CREATE' &&
      definition.transactionPolicy.maximumValue !== `0x${'00'.repeat(32)}`
    )
      reject('factory endowment requires an independently qualified value-flow profile');
    const initLength = (definition.artifact.initCode.length - 2) / 2;
    const calldataLength =
      definition.route.mechanism === 'TRANSACTION_CREATE'
        ? initLength
        : 4 + (definition.route.mechanism === 'CREATE' ? 64 : 96) + Math.ceil(initLength / 32) * 32;
    if (calldataLength > definition.transactionPolicy.maximumCalldataBytes)
      reject('deployment calldata exceeds the transaction budget');
    if (
      definition.artifact.runtimeCodeHash ===
      `0x${Buffer.from(keccak_256(new Uint8Array())).toString('hex')}`
    )
      reject('persistent runtime code must be nonempty');
    const route = definition.route;
    if (route.mechanism !== 'TRANSACTION_CREATE') {
      const inputs = route.canonicalSignature.slice(route.canonicalSignature.indexOf('('));
      const expected =
        route.mechanism === 'CREATE'
          ? '(bytes)'
          : route.arguments === 'INIT_CODE_SALT'
            ? '(bytes,bytes32)'
            : '(bytes32,bytes)';
      if (inputs !== expected) reject('factory signature does not match the closed adapter');
    }
  });

export type DeploymentPolicyDefinition = z.infer<typeof deploymentPolicyDefinitionSchema>;

export const createDeploymentPolicySchema = z.strictObject({
  actionIntentId: z.literal('ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
  definition: deploymentPolicyDefinitionSchema,
});

/** Digests identify exact retained inputs; neither identifier is a readiness proof. */
export function deploymentDefinitionDigests(definition: DeploymentPolicyDefinition) {
  const input = deploymentPolicyDefinitionSchema.parse(definition);
  const initCodeHash = `0x${Buffer.from(keccak_256(Buffer.from(input.artifact.initCode.slice(2), 'hex'))).toString('hex')}`;
  return {
    definitionDigest: sha256(input),
    artifactDigest: sha256({
      mode: input.artifact.mode,
      initCodeHash,
      runtimeCodeHash: input.artifact.runtimeCodeHash,
    }),
    initCodeHash,
  };
}

export const deploymentPolicyResponseSchema = z.strictObject({
  deploymentPolicyId: resourceUrnSchema,
  definition: deploymentPolicyDefinitionSchema,
  definitionDigest: digestSchema,
  artifactDigest: digestSchema,
  initCodeHash: hash,
  abiDigest: digestSchema,
  publicationOperationId: z.uuid(),
  publicationAuthorityDigest: digestSchema,
  revision: z.literal('1'),
  state: z.literal('STAGED'),
  runtimePermission: z.literal('REQUIRES_EFFECTIVE_POLICY_AND_LIVE_AUTHORITY'),
  createdAt: z.iso.datetime(),
});
