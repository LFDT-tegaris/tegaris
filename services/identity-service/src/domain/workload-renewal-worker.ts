import type {
  WorkloadRenewalClaim,
  WorkloadRenewalProvider,
  WorkloadRenewalReadback,
  WorkloadRenewalRecorded,
  WorkloadRenewalStore,
  WorkloadRenewalUnknownObservation,
  WorkloadRenewalUnknownReason,
} from './workload-renewal-worker-contract.js';

function unknown(reason: WorkloadRenewalUnknownReason): WorkloadRenewalUnknownObservation {
  return { kind: 'UNKNOWN', reason };
}

function validBudget(timeoutMs: number): boolean {
  // Larger Node timer delays overflow to a near-immediate timeout.
  return Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 2_147_483_647;
}

/** The timer bounds our wait even when the adapter ignores cancellation. Both
 * late fulfillment and late rejection are observed without further store I/O.
 * Cancellation says nothing about whether the external write took effect. */
function boundedProviderCall<T extends WorkloadRenewalReadback>(
  timeoutMs: number,
  call: (signal: AbortSignal) => Promise<T>,
): Promise<T | WorkloadRenewalUnknownObservation> {
  return new Promise((resolve) => {
    const controller = new AbortController();
    let settled = false;
    const finish = (observation: T | WorkloadRenewalUnknownObservation) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        if (observation.kind === 'UNKNOWN') {
          // Only fixed classifications cross this boundary, never exception text
          // or extra properties from an adapter's transport response.
          const reason = observation.reason;
          resolve(
            unknown(
              reason === 'TRANSPORT_UNAVAILABLE' ||
                reason === 'PROVIDER_OUTCOME_UNKNOWN' ||
                reason === 'UNQUALIFIED_RESPONSE'
                ? reason
                : 'UNQUALIFIED_RESPONSE',
            ),
          );
        } else {
          resolve(Object.freeze(observation));
        }
      } catch {
        // An unreadable adapter outcome must not leave a settled timer with an
        // unresolved wait. This does not authenticate any provider evidence.
        resolve(unknown('UNQUALIFIED_RESPONSE'));
      }
    };
    const timer = setTimeout(() => {
      finish(unknown('PROVIDER_OUTCOME_UNKNOWN'));
      controller.abort();
    }, timeoutMs);
    void Promise.resolve()
      .then(() => call(controller.signal))
      .then(finish, () => finish(unknown('TRANSPORT_UNAVAILABLE')));
  });
}

function sameClaim(expected: WorkloadRenewalClaim, actual: WorkloadRenewalClaim): boolean {
  const originalKeys = Object.keys(expected.original) as (keyof typeof expected.original)[];
  const claimKeys = Object.keys(expected) as (keyof WorkloadRenewalClaim)[];
  return (
    originalKeys.every((key) => expected.original[key] === actual.original[key]) &&
    claimKeys.every((key) => key === 'original' || expected[key] === actual[key])
  );
}

/** Process at most one existing intent. This worker cannot admit, retry,
 * schedule, verify a provider proof, publish a credential or perform cutover.
 * Durable recording and current issuance authority belong exclusively to the
 * store; an observation or recorded state is never an issuance permit. */
export async function runWorkloadRenewalWorkerOnce(
  store: WorkloadRenewalStore,
  provider: WorkloadRenewalProvider,
  workerId: string,
): Promise<WorkloadRenewalRecorded | undefined> {
  const claim = await store.claimDue(workerId);
  if (claim === undefined) return undefined;
  // These port inputs are immutable. Keep their object and exact bytes intact
  // across asynchronous adapter/store calls, including a cloned returned claim.
  Object.freeze(claim.original);
  Object.freeze(claim);
  const qualified = () =>
    provider.qualificationDigest === claim.original.providerQualificationDigest;
  if (
    !qualified() ||
    claim.original.providerRequestId !== claim.original.renewalId ||
    !validBudget(claim.providerTimeoutMs)
  ) {
    return store.recordReadback(claim, unknown('UNQUALIFIED_RESPONSE'));
  }

  const readback = await boundedProviderCall(claim.providerTimeoutMs, (signal) =>
    provider.readOriginal(claim.original, signal),
  );
  const recorded = await store.recordReadback(claim, readback);
  if (readback.kind !== 'NOT_ISSUED') return recorded;

  // The store authenticates this exact already-durable proof and commits its
  // authorization before returning. Failed recording/authorization propagates
  // without issuance; a future claim must reconcile the original ambiguity.
  const permit = await store.authorizeOriginalIssue(claim, readback);
  if (permit === undefined) return recorded;
  if (!sameClaim(claim, permit.claim) || !qualified()) {
    return store.recordReadback(claim, unknown('UNQUALIFIED_RESPONSE'));
  }
  Object.freeze(permit.claim.original);
  Object.freeze(permit.claim);
  Object.freeze(permit);
  const issued = await boundedProviderCall(claim.providerTimeoutMs, (signal) =>
    provider.issueExact(permit, signal),
  );
  return store.recordIssue(permit, issued);
}
