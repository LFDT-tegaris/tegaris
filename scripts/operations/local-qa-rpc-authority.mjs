/** Disposable initial trust only. This ceiling creates no workload authority;
 * assignments and policy publication still use their governed owners. */
export function localQaRpcAuthority(environment, bindings, nowMs = Date.now()) {
  if (environment.OPENPC_LOCAL_RUNTIME_QA_FIXTURE !== '1')
    throw new Error('Explicit disposable QA authority required');
  const profile = environment.OPENPC_QA_RPC_AUTHORITY_PROFILE ?? 'GOVERNED';
  if (!['GOVERNED', 'CALL_ONLY_AUTONOMOUS', 'POLICY_CONTROLLED_RPC'].includes(profile))
    throw new Error('Unknown QA RPC authority profile');
  const rawLifetime = environment.OPENPC_QA_AUTHORITY_TTL_MS ?? '28800000';
  if (!/^[1-9][0-9]*$/.test(rawLifetime)) throw new Error('Invalid QA authority lifetime');
  const lifetimeMs = Number(rawLifetime);
  if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs < 3600000 || lifetimeMs > 86400000)
    throw new Error('QA authority lifetime outside supported bounds');
  if (
    !Number.isSafeInteger(nowMs) ||
    nowMs <= 0 ||
    !['participantId', 'privacyDomainId', 'runtimeBindingId', 'targetProfileId'].every(
      (key) => typeof bindings[key] === 'string' && bindings[key].length > 0,
    )
  )
    throw new Error('Exact QA runtime authority bindings required');
  const autonomous = profile === 'CALL_ONLY_AUTONOMOUS';
  const capabilityIds = autonomous
    ? ['CALL_RESULT_DISCLOSURE']
    : ['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION'];
  if (environment.OPENPC_QA_RPC_CAPABILITY_IDS !== undefined) {
    const selected = environment.OPENPC_QA_RPC_CAPABILITY_IDS.split(',');
    const supported = [
      'CALL_RESULT_DISCLOSURE',
      'GAS_ESTIMATE_DISCLOSURE',
      'ACCESS_LIST_DISCLOSURE',
      'UNSIGNED_TRANSACTION_PREPARATION',
      'SIGNED_TRANSACTION_SUBMISSION',
      'OPERATION_STATUS_DISCLOSURE',
    ];
    if (
      profile !== 'POLICY_CONTROLLED_RPC' ||
      selected.length > supported.length ||
      new Set(selected).size !== selected.length ||
      !capabilityIds.every((id) => selected.includes(id)) ||
      selected.some((id) => !supported.includes(id))
    )
      throw new Error('Exact supported QA invocation capabilities required');
    capabilityIds.splice(0, capabilityIds.length, ...selected.sort());
  }
  const resourceIds =
    environment.OPENPC_QA_RPC_RESOURCE_IDS === undefined
      ? [bindings.runtimeBindingId]
      : environment.OPENPC_QA_RPC_RESOURCE_IDS.split(',');
  if (
    environment.OPENPC_QA_RPC_RESOURCE_IDS !== undefined &&
    (profile !== 'POLICY_CONTROLLED_RPC' ||
      resourceIds.length > 16 ||
      new Set(resourceIds).size !== resourceIds.length ||
      !resourceIds.includes(bindings.runtimeBindingId) ||
      resourceIds.some(
        (id) => !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id),
      ))
  )
    throw new Error('Exact reserved QA runtime resources required');
  // This initial ceiling grants no workload permission. Method-policy approval
  // requirements still apply; a write needing unavailable proof must be denied.
  const scopeApprovalRequired = profile === 'GOVERNED';
  return {
    administration: {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      actionIntentIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [],
    },
    runtime: {
      participantIds: [bindings.participantId],
      privacyDomainIds: [bindings.privacyDomainId],
      resourceIds: [...resourceIds].sort(),
      capabilityIds,
      dataClasses: [],
      targetProfileIds: [bindings.targetProfileId],
      riskClasses: ['LOW'],
    },
    validFromNs: (BigInt(nowMs) * 1000000n).toString(),
    validUntilNs: (BigInt(nowMs + lifetimeMs) * 1000000n).toString(),
    makerCheckerRequired: scopeApprovalRequired,
    stepUpRequired: scopeApprovalRequired,
    onwardDelegationDepth: 0,
  };
}
