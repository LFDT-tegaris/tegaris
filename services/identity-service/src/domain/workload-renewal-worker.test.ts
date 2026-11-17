import { afterEach, expect, it, vi } from 'vitest';
import { runWorkloadRenewalWorkerOnce } from './workload-renewal-worker.js';
import type {
  WorkloadRenewalCertificateObservation,
  WorkloadRenewalClaim,
  WorkloadRenewalDigest,
  WorkloadRenewalIssuePermit,
  WorkloadRenewalNonIssuance,
  WorkloadRenewalOriginal,
  WorkloadRenewalProvider,
  WorkloadRenewalReadback,
  WorkloadRenewalRecorded,
  WorkloadRenewalStore,
} from './workload-renewal-worker-contract.js';

const digest: WorkloadRenewalDigest = `sha256:${'11'.repeat(32)}`;
const otherDigest: WorkloadRenewalDigest = `sha256:${'22'.repeat(32)}`;
const id = (suffix: string) => `018f0000-0000-7000-8000-${suffix.padStart(12, '0')}`;

/** Port orchestration only: no database, issuer qualification, certificate
 * authentication, admission, policy or runtime acceptance is simulated here. */
function fixture(
  claimChanges: Partial<WorkloadRenewalClaim> = {},
  originalChanges: Partial<WorkloadRenewalOriginal> = {},
) {
  const original: WorkloadRenewalOriginal = {
    version: 2,
    renewalId: id('1'),
    operationId: id('2'),
    credentialId: id('3'),
    participantId: id('4'),
    privacyDomainId: id('5'),
    principalId: id('6'),
    workloadId: id('7'),
    familyId: id('8'),
    instanceId: id('9'),
    instanceGeneration: '3',
    predecessorCredentialId: id('10'),
    expectedFamilyGeneration: '4',
    policyId: id('11'),
    policyRevision: '2',
    policyDigest: digest,
    attestationProfileDigest: digest,
    attestationDigest: digest,
    issuerProfileDigest: digest,
    providerQualificationDigest: digest,
    providerRequestId: id('1'),
    providerRequestBase64: 'ZXhhY3QtYWRtaXR0ZWQtcmVxdWVzdA==',
    providerRequestDigest: digest,
    ...originalChanges,
  };
  const claim: WorkloadRenewalClaim = {
    original,
    attemptId: id('12'),
    workerId: 'worker-a',
    leaseFence: '7',
    leaseExpiresAt: '2026-10-04T01:00:00.000Z',
    renewalDeadline: '2026-10-04T02:00:00.000Z',
    providerTimeoutMs: 100,
    ...claimChanges,
  };
  const nonIssuance: WorkloadRenewalNonIssuance = {
    kind: 'NOT_ISSUED',
    providerRequestId: original.providerRequestId,
    providerRequestDigest: original.providerRequestDigest,
    providerQualificationDigest: digest,
    proofBase64: 'dW50cnVzdGVkLXByb29m',
  };
  const certificate: WorkloadRenewalCertificateObservation = {
    kind: 'CERTIFICATE',
    providerRequestId: original.providerRequestId,
    providerRequestDigest: original.providerRequestDigest,
    providerQualificationDigest: digest,
    certificateDerBase64: 'dW50cnVzdGVkLWNlcnRpZmljYXRl',
    proofBase64: 'dW50cnVzdGVkLXByb29m',
  };
  const recorded: WorkloadRenewalRecorded = {
    renewalId: original.renewalId,
    operationId: original.operationId,
    revision: '6',
    observedAt: '2026-10-04T00:00:00.000Z',
    state: 'RECOVERING',
    providerOutcome: 'NOT_ISSUED',
  };
  const permit: WorkloadRenewalIssuePermit = { claim, issuanceAuthorizationId: id('13') };
  const store = {
    claimDue: vi.fn<WorkloadRenewalStore['claimDue']>().mockResolvedValue(claim),
    recordReadback: vi.fn<WorkloadRenewalStore['recordReadback']>().mockResolvedValue(recorded),
    authorizeOriginalIssue: vi
      .fn<WorkloadRenewalStore['authorizeOriginalIssue']>()
      .mockResolvedValue(permit),
    recordIssue: vi.fn<WorkloadRenewalStore['recordIssue']>().mockResolvedValue(recorded),
  } satisfies WorkloadRenewalStore;
  const provider = {
    qualificationDigest: digest,
    readOriginal: vi.fn<WorkloadRenewalProvider['readOriginal']>().mockResolvedValue(nonIssuance),
    issueExact: vi.fn<WorkloadRenewalProvider['issueExact']>().mockResolvedValue(certificate),
  } satisfies WorkloadRenewalProvider;
  const run = () => runWorkloadRenewalWorkerOnce(store, provider, 'worker-a');
  return { original, claim, nonIssuance, certificate, recorded, permit, store, provider, run };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

it('claims once and returns without provider or store effects when nothing is due', async () => {
  const f = fixture();
  f.store.claimDue.mockResolvedValue(undefined);
  expect(await f.run()).toBeUndefined();
  expect(f.store.claimDue).toHaveBeenCalledExactlyOnceWith('worker-a');
  expect(f.provider.readOriginal).not.toHaveBeenCalled();
  expect(f.provider.issueExact).not.toHaveBeenCalled();
  expect(f.store.recordReadback).not.toHaveBeenCalled();
  expect(f.store.authorizeOriginalIssue).not.toHaveBeenCalled();
  expect(f.store.recordIssue).not.toHaveBeenCalled();
});

it.each(['qualification', 'business identity'])(
  'rejects %s mismatch before network',
  async (kind) => {
    const f = fixture({}, kind === 'business identity' ? { providerRequestId: id('99') } : {});
    if (kind === 'qualification') f.provider.qualificationDigest = otherDigest;
    expect(await f.run()).toBe(f.recorded);
    expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, {
      kind: 'UNKNOWN',
      reason: 'UNQUALIFIED_RESPONSE',
    });
    expect(f.provider.readOriginal).not.toHaveBeenCalled();
    expect(f.provider.issueExact).not.toHaveBeenCalled();
    expect(f.store.authorizeOriginalIssue).not.toHaveBeenCalled();
  },
);

it.each([0, -1, 0.5, NaN, Infinity, 2_147_483_648])(
  'rejects an unbounded or invalid timer budget %s without network',
  async (providerTimeoutMs) => {
    const f = fixture({ providerTimeoutMs });
    await f.run();
    expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, {
      kind: 'UNKNOWN',
      reason: 'UNQUALIFIED_RESPONSE',
    });
    expect(f.provider.readOriginal).not.toHaveBeenCalled();
    expect(f.provider.issueExact).not.toHaveBeenCalled();
  },
);

it('records original certificate readback without authorization or another issue', async () => {
  const f = fixture();
  f.provider.readOriginal.mockResolvedValue(f.certificate);
  expect(await f.run()).toBe(f.recorded);
  expect(f.provider.readOriginal.mock.calls[0]?.[0]).toBe(f.original);
  expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, f.certificate);
  expect(f.store.authorizeOriginalIssue).not.toHaveBeenCalled();
  expect(f.provider.issueExact).not.toHaveBeenCalled();
});

it('preserves UNKNOWN and strips arbitrary transport diagnostics', async () => {
  const f = fixture();
  f.provider.readOriginal.mockResolvedValue({
    kind: 'UNKNOWN',
    reason: 'PROVIDER_OUTCOME_UNKNOWN',
    privateDiagnostic: 'provider bearer token',
  } as WorkloadRenewalReadback);
  await f.run();
  expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, {
    kind: 'UNKNOWN',
    reason: 'PROVIDER_OUTCOME_UNKNOWN',
  });
  expect(f.store.authorizeOriginalIssue).not.toHaveBeenCalled();
  expect(f.provider.issueExact).not.toHaveBeenCalled();
});

it('classifies an unsupported provider reason without forwarding it', async () => {
  const f = fixture();
  f.provider.readOriginal.mockResolvedValue({
    kind: 'UNKNOWN',
    reason: 'private issuer body',
  } as unknown as WorkloadRenewalReadback);
  await f.run();
  expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, {
    kind: 'UNKNOWN',
    reason: 'UNQUALIFIED_RESPONSE',
  });
  expect(f.store.authorizeOriginalIssue).not.toHaveBeenCalled();
  expect(f.provider.issueExact).not.toHaveBeenCalled();
});

it('returns UNKNOWN for an unreadable adapter outcome without leaving a pending wait', async () => {
  vi.useFakeTimers();
  const f = fixture();
  f.provider.readOriginal.mockResolvedValue(undefined as unknown as WorkloadRenewalReadback);
  expect(await f.run()).toBe(f.recorded);
  expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, {
    kind: 'UNKNOWN',
    reason: 'UNQUALIFIED_RESPONSE',
  });
  expect(f.provider.issueExact).not.toHaveBeenCalled();
  expect(vi.getTimerCount()).toBe(0);
});

it('classifies a synchronous read failure without exposing its exception', async () => {
  const f = fixture();
  f.provider.readOriginal.mockImplementation(() => {
    throw new Error('secret provider authorization header');
  });
  await f.run();
  expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, {
    kind: 'UNKNOWN',
    reason: 'TRANSPORT_UNAVAILABLE',
  });
  expect(f.provider.issueExact).not.toHaveBeenCalled();
});

it('awaits durable non-issuance recording before authorization and exact issuance', async () => {
  vi.useFakeTimers();
  const f = fixture();
  const events: string[] = [];
  const recording = deferred<WorkloadRenewalRecorded>();
  f.store.recordReadback.mockImplementation(() => {
    events.push('record-start');
    return recording.promise;
  });
  f.store.authorizeOriginalIssue.mockImplementation(async (claim, proof) => {
    events.push('authorize');
    expect(claim).toBe(f.claim);
    expect(proof).toBe(f.nonIssuance);
    return f.permit;
  });
  f.provider.issueExact.mockImplementation(async (permit) => {
    events.push('issue');
    expect(permit).toBe(f.permit);
    expect(permit.claim.original).toBe(f.original);
    expect(permit.claim.original.providerRequestBase64).toBe('ZXhhY3QtYWRtaXR0ZWQtcmVxdWVzdA==');
    return f.certificate;
  });
  f.store.recordIssue.mockImplementation(async (permit, observation) => {
    events.push('record-issue');
    expect(permit).toBe(f.permit);
    expect(observation).toBe(f.certificate);
    return f.recorded;
  });
  const running = f.run();
  await vi.advanceTimersByTimeAsync(0);
  expect(events).toEqual(['record-start']);
  expect(f.store.authorizeOriginalIssue).not.toHaveBeenCalled();
  expect(f.provider.issueExact).not.toHaveBeenCalled();
  events.push('record-durable');
  recording.resolve(f.recorded);
  expect(await running).toBe(f.recorded);
  expect(events).toEqual(['record-start', 'record-durable', 'authorize', 'issue', 'record-issue']);
  expect(f.provider.readOriginal).toHaveBeenCalledOnce();
  expect(f.provider.issueExact).toHaveBeenCalledOnce();
  expect(f.store.claimDue).toHaveBeenCalledOnce();
});

it('uses authorization rather than recorded state and stops on a denied permit', async () => {
  const f = fixture();
  f.store.authorizeOriginalIssue.mockResolvedValue(undefined);
  expect(await f.run()).toBe(f.recorded);
  expect(f.store.authorizeOriginalIssue).toHaveBeenCalledExactlyOnceWith(f.claim, f.nonIssuance);
  expect(f.provider.issueExact).not.toHaveBeenCalled();
  expect(f.store.recordIssue).not.toHaveBeenCalled();
});

it('rechecks provider qualification before an authorized write', async () => {
  const f = fixture();
  f.store.authorizeOriginalIssue.mockImplementation(async () => {
    f.provider.qualificationDigest = otherDigest;
    return f.permit;
  });
  await f.run();
  expect(f.provider.readOriginal).toHaveBeenCalledOnce();
  expect(f.store.recordReadback).toHaveBeenLastCalledWith(f.claim, {
    kind: 'UNKNOWN',
    reason: 'UNQUALIFIED_RESPONSE',
  });
  expect(f.provider.issueExact).not.toHaveBeenCalled();
  expect(f.store.recordIssue).not.toHaveBeenCalled();
});

it.each(['recordReadback', 'authorizeOriginalIssue'] as const)(
  'stops after failed durable %s without provider issuance',
  async (method) => {
    const f = fixture();
    const failure = new Error('durable store unavailable');
    f.store[method].mockRejectedValue(failure);
    await expect(f.run()).rejects.toBe(failure);
    expect(f.provider.issueExact).not.toHaveBeenCalled();
    expect(f.store.recordIssue).not.toHaveBeenCalled();
    if (method === 'recordReadback') expect(f.store.authorizeOriginalIssue).not.toHaveBeenCalled();
  },
);

it.each([
  { renewalId: id('99') },
  { participantId: id('99') },
  { credentialId: id('99') },
  { providerRequestId: id('99') },
  { providerRequestBase64: 'YWx0ZXJlZA==' },
  { providerRequestDigest: otherDigest },
  { policyRevision: '99' },
] satisfies Partial<WorkloadRenewalOriginal>[])(
  'refuses a permit replacing original fields %j',
  async (change) => {
    const f = fixture();
    f.store.authorizeOriginalIssue.mockResolvedValue({
      ...f.permit,
      claim: { ...f.claim, original: { ...f.original, ...change } },
    });
    await f.run();
    expect(f.store.recordReadback).toHaveBeenLastCalledWith(f.claim, {
      kind: 'UNKNOWN',
      reason: 'UNQUALIFIED_RESPONSE',
    });
    expect(f.provider.issueExact).not.toHaveBeenCalled();
    expect(f.store.recordIssue).not.toHaveBeenCalled();
  },
);

it.each([
  { attemptId: id('99') },
  { workerId: 'worker-b' },
  { leaseFence: '8' },
  { leaseExpiresAt: '2026-10-04T03:00:00.000Z' },
  { renewalDeadline: '2026-10-04T03:00:00.000Z' },
  { providerTimeoutMs: 200 },
] satisfies Partial<WorkloadRenewalClaim>[])(
  'refuses a permit replacing the claimed attempt or fence %j',
  async (change) => {
    const f = fixture();
    f.store.authorizeOriginalIssue.mockResolvedValue({
      ...f.permit,
      claim: { ...f.claim, ...change },
    });
    await f.run();
    expect(f.provider.issueExact).not.toHaveBeenCalled();
    expect(f.store.recordIssue).not.toHaveBeenCalled();
  },
);

it('accepts an unchanged cloned permit without reconstructing its request', async () => {
  const f = fixture();
  const permit = { ...f.permit, claim: { ...f.claim, original: { ...f.original } } };
  f.store.authorizeOriginalIssue.mockResolvedValue(permit);
  await f.run();
  expect(f.provider.issueExact.mock.calls[0]?.[0]).toBe(permit);
  expect(f.store.recordIssue).toHaveBeenCalledExactlyOnceWith(permit, f.certificate);
});

it('records ambiguous issuance loss and never retries within the invocation', async () => {
  const f = fixture();
  f.provider.issueExact.mockRejectedValue(new Error('private issuer response body'));
  await f.run();
  expect(f.store.recordIssue).toHaveBeenCalledExactlyOnceWith(f.permit, {
    kind: 'UNKNOWN',
    reason: 'TRANSPORT_UNAVAILABLE',
  });
  expect(f.provider.issueExact).toHaveBeenCalledOnce();
  expect(f.provider.readOriginal).toHaveBeenCalledOnce();
  expect(f.store.claimDue).toHaveBeenCalledOnce();
});

it('preserves a lost issue-record response without repeating the external effect', async () => {
  const f = fixture();
  const failure = new Error('record response lost');
  f.store.recordIssue.mockRejectedValue(failure);
  await expect(f.run()).rejects.toBe(failure);
  expect(f.provider.issueExact).toHaveBeenCalledOnce();
  expect(f.store.claimDue).toHaveBeenCalledOnce();
});

it('reconciles the same original on the next invocation after ambiguous issuance', async () => {
  const f = fixture();
  f.provider.issueExact.mockRejectedValue(new Error('response lost after external issuance'));
  await f.run();
  f.provider.readOriginal.mockResolvedValue(f.certificate);
  await f.run();
  expect(f.store.claimDue).toHaveBeenCalledTimes(2);
  expect(f.provider.readOriginal).toHaveBeenCalledTimes(2);
  for (const [original] of f.provider.readOriginal.mock.calls) expect(original).toBe(f.original);
  expect(f.provider.issueExact).toHaveBeenCalledOnce();
  expect(f.store.recordIssue).toHaveBeenCalledOnce();
  expect(f.store.recordReadback).toHaveBeenLastCalledWith(f.claim, f.certificate);
});

it('reconciles an expired original while leaving issuance eligibility to the store', async () => {
  const f = fixture({
    leaseExpiresAt: '2000-01-01T00:00:00.000Z',
    renewalDeadline: '2000-01-01T00:00:00.000Z',
  });
  f.store.authorizeOriginalIssue.mockResolvedValue(undefined);
  await f.run();
  expect(f.provider.readOriginal.mock.calls[0]?.[0]).toBe(f.original);
  expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, f.nonIssuance);
  expect(f.store.authorizeOriginalIssue).toHaveBeenCalledExactlyOnceWith(f.claim, f.nonIssuance);
  expect(f.provider.issueExact).not.toHaveBeenCalled();
});

it.each(['resolve', 'reject'] as const)(
  'bounds an abort-ignoring read and ignores late %s without another effect',
  async (settlement) => {
    vi.useFakeTimers();
    const f = fixture();
    const read = deferred<WorkloadRenewalReadback>();
    f.provider.readOriginal.mockReturnValue(read.promise);
    const running = f.run();
    await vi.advanceTimersByTimeAsync(99);
    expect(f.store.recordReadback).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(await running).toBe(f.recorded);
    expect(f.provider.readOriginal.mock.calls[0]?.[1].aborted).toBe(true);
    expect(f.store.recordReadback).toHaveBeenCalledExactlyOnceWith(f.claim, {
      kind: 'UNKNOWN',
      reason: 'PROVIDER_OUTCOME_UNKNOWN',
    });
    if (settlement === 'resolve') read.resolve(f.nonIssuance);
    else read.reject(new Error('late secret transport error'));
    await vi.advanceTimersByTimeAsync(0);
    expect(f.store.recordReadback).toHaveBeenCalledOnce();
    expect(f.store.authorizeOriginalIssue).not.toHaveBeenCalled();
    expect(f.provider.issueExact).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  },
);

it.each(['resolve', 'reject'] as const)(
  'bounds an abort-ignoring issue and ignores late %s without publication',
  async (settlement) => {
    vi.useFakeTimers();
    const f = fixture();
    const issue = deferred<WorkloadRenewalCertificateObservation>();
    f.provider.issueExact.mockReturnValue(issue.promise);
    const running = f.run();
    await vi.advanceTimersByTimeAsync(0);
    expect(f.provider.issueExact).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(99);
    expect(f.store.recordIssue).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(await running).toBe(f.recorded);
    expect(f.provider.issueExact.mock.calls[0]?.[1].aborted).toBe(true);
    expect(f.store.recordIssue).toHaveBeenCalledExactlyOnceWith(f.permit, {
      kind: 'UNKNOWN',
      reason: 'PROVIDER_OUTCOME_UNKNOWN',
    });
    if (settlement === 'resolve') issue.resolve(f.certificate);
    else issue.reject(new Error('late private issuer response'));
    await vi.advanceTimersByTimeAsync(0);
    expect(f.store.recordIssue).toHaveBeenCalledOnce();
    expect(f.provider.issueExact).toHaveBeenCalledOnce();
    expect(f.store.claimDue).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  },
);
