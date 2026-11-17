/** Actor-facing codes from rpc_invocation_capability_registry_v2.
 * Grants are distinct from management action intents and from transport names.
 * Possessing a grant never establishes profile support or complete runtime authority. */
export const runtimeInvocationCapabilities = [
  'CALL_RESULT_DISCLOSURE',
  'GAS_ESTIMATE_DISCLOSURE',
  'ACCESS_LIST_DISCLOSURE',
  'UNSIGNED_TRANSACTION_PREPARATION',
  'SIGNED_TRANSACTION_SUBMISSION',
  'OPERATION_STATUS_DISCLOSURE',
  'MULTI_CALL_SIMULATION_DISCLOSURE',
] as const;
export type RuntimeInvocationCapability = (typeof runtimeInvocationCapabilities)[number];
