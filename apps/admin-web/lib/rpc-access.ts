export const rpcMethodCapabilities = {
  eth_call: 'CALL_RESULT_DISCLOSURE',
  eth_sendRawTransaction: 'SIGNED_TRANSACTION_SUBMISSION',
} as const;

export type RpcAccessMethod = keyof typeof rpcMethodCapabilities;

export interface RpcModuleBinding {
  readonly moduleId: string;
  readonly semanticVersion: string;
  readonly manifestDigest: string;
  readonly configurationDigest: string;
}

export function rpcPolicyDocument(input: {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly roleId: string;
  readonly rpcRoleIds?: Readonly<Record<RpcAccessMethod, string>>;
  readonly methods: readonly RpcAccessMethod[];
  readonly moduleBindings: readonly RpcModuleBinding[];
  readonly contractPolicies: Readonly<
    Record<RpcAccessMethod, { readonly contractMethodPolicyId: string; readonly revision: string }>
  >;
}) {
  const methods = [...new Set(input.methods)];
  return {
    schemaVersion: '1.0.0' as const,
    participantId: input.participantId,
    privacyDomainId: input.privacyDomainId,
    moduleBindings: input.moduleBindings.map((binding) => ({ ...binding })),
    rpcPolicies: [
      {
        schemaVersion: '1.0.0' as const,
        participantId: input.participantId,
        privacyDomainId: input.privacyDomainId,
        rules: (Object.keys(rpcMethodCapabilities) as RpcAccessMethod[]).map((method) => ({
          method,
          effect: 'ALLOW' as const,
          requiredRoles: [input.rpcRoleIds?.[method] ?? input.roleId],
        })),
      },
    ],
    contractPolicies: methods.map((method) => ({ ...input.contractPolicies[method] })),
    requiredFacts: [],
  };
}
