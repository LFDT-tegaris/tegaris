/** Internal routine-renewal ports. These types neither register an action nor
 * admit a renewal. The authoritative admission/store implementation owns real
 * workload TLS, independent attestation, current policy/business ancestors,
 * canonical signed bytes, tenant isolation and all durable transactions.
 * Existing v1 manual issuance and its signed history remain unchanged. */
export type WorkloadRenewalDigest = `sha256:${string}`;

/** Allocated and committed by admission before provider I/O. providerRequestId
 * equals renewalId (one UUIDv7 business identity); operationId and credentialId are
 * separately allocated and bound before signing. No worker-generated IDs,
 * keys, validity intervals or reconstructed JSON are permitted on retry. */
export interface WorkloadRenewalOriginal {
  readonly version: 2;
  readonly renewalId: string;
  readonly operationId: string;
  readonly credentialId: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
  readonly workloadId: string;
  readonly familyId: string;
  readonly instanceId: string;
  readonly instanceGeneration: string;
  readonly predecessorCredentialId: string;
  readonly expectedFamilyGeneration: string;
  readonly policyId: string;
  readonly policyRevision: string;
  readonly policyDigest: WorkloadRenewalDigest;
  readonly attestationProfileDigest: WorkloadRenewalDigest;
  readonly attestationDigest: WorkloadRenewalDigest;
  readonly issuerProfileDigest: WorkloadRenewalDigest;
  readonly providerQualificationDigest: WorkloadRenewalDigest;
  /** Exactly renewalId, including in the canonical request bytes. */
  readonly providerRequestId: string;
  /** Exact public provider request bytes and their digest, prepared by admission.
   * Include the successor public key, registered SAN/audience/algorithm and
   * approved finite interval; never contain private keys or provider secrets. */
  readonly providerRequestBase64: string;
  readonly providerRequestDigest: WorkloadRenewalDigest;
}

/** The store commits the original attempt before returning a claim. SQL owns
 * due time, bounded retry scheduling, deadline and the monotonic lease fence.
 * One nonterminal intent per family, tenant-fair selection and expired-claim
 * reconciliation are store obligations. A claim is never issuance authority. */
export interface WorkloadRenewalClaim {
  readonly original: WorkloadRenewalOriginal;
  readonly attemptId: string;
  readonly workerId: string;
  readonly leaseFence: string;
  readonly leaseExpiresAt: string;
  readonly renewalDeadline: string;
  /** Positive bounded I/O budget selected by the store/configuration. Aborting
   * a provider call is UNKNOWN, never evidence that issuance did not occur. */
  readonly providerTimeoutMs: number;
}

export type WorkloadRenewalUnknownReason =
  'TRANSPORT_UNAVAILABLE' | 'PROVIDER_OUTCOME_UNKNOWN' | 'UNQUALIFIED_RESPONSE';

/** Public response bytes remain untrusted until the authoritative store's
 * qualified verifier authenticates and binds them to this exact original.
 * NOT_ISSUED requires authoritative provider proof, never a generic HTTP 404.
 * An immutable replay-only v1 adapter does not implement this v2 port. */
export interface WorkloadRenewalNonIssuance {
  readonly kind: 'NOT_ISSUED';
  readonly providerRequestId: string;
  readonly providerRequestDigest: WorkloadRenewalDigest;
  readonly providerQualificationDigest: WorkloadRenewalDigest;
  readonly proofBase64: string;
}

export interface WorkloadRenewalCertificateObservation {
  readonly kind: 'CERTIFICATE';
  readonly providerRequestId: string;
  readonly providerRequestDigest: WorkloadRenewalDigest;
  readonly providerQualificationDigest: WorkloadRenewalDigest;
  readonly certificateDerBase64: string;
  readonly proofBase64: string;
}

export interface WorkloadRenewalUnknownObservation {
  readonly kind: 'UNKNOWN';
  /** Redacted classification only. Never propagate provider exception text,
   * authorization headers, private key material or an arbitrary HTTP body. */
  readonly reason: WorkloadRenewalUnknownReason;
}

export type WorkloadRenewalReadback =
  | WorkloadRenewalNonIssuance
  | WorkloadRenewalCertificateObservation
  | WorkloadRenewalUnknownObservation;

export interface WorkloadRenewalIssuePermit {
  readonly claim: WorkloadRenewalClaim;
  /** Persisted issuance authorization, distinct from the original attempt ID.
   * This is neither client-supplied approval nor permission to change bytes. */
  readonly issuanceAuthorizationId: string;
}

export interface WorkloadRenewalProvider {
  readonly qualificationDigest: WorkloadRenewalDigest;
  /** Read before every possible write, including the first claimed attempt.
   * Unsupported/missing/unqualified outcomes return UNKNOWN. Qualification
   * must guarantee exact-request idempotency across ambiguous writes and a
   * read-after-write non-issuance proof; eventual absence is insufficient. */
  readOriginal(
    original: WorkloadRenewalOriginal,
    signal: AbortSignal,
  ): Promise<WorkloadRenewalReadback>;
  /** Submit only the original immutable request. Transport loss is UNKNOWN;
   * retry/restart returns to readOriginal, never a new request/key/business ID. */
  issueExact(
    permit: WorkloadRenewalIssuePermit,
    signal: AbortSignal,
  ): Promise<WorkloadRenewalCertificateObservation | WorkloadRenewalUnknownObservation>;
}

export interface WorkloadRenewalRecorded {
  readonly renewalId: string;
  readonly operationId: string;
  readonly revision: string;
  readonly observedAt: string;
  readonly state: 'RECOVERING' | 'PREPARED' | 'FAILED';
  readonly providerOutcome: 'UNRESOLVED' | 'NOT_ISSUED' | 'ISSUED';
  /** PREPARED means verified issuance only. No business use, adoption,
   * consumer acknowledgment, cutover or EFFECTIVE result follows from it. */
  /** FAILED is not proof of non-issuance. Cleanup obligations survive failure
   * or deadline expiry whenever an external effect exists or is uncertain. */
}

export interface WorkloadRenewalStore {
  /** Bounded one-item claim; no caller-selected tenant or fresh business intent.
   * Deadline-expired originals with uncertain external effects remain eligible
   * for read-only reconciliation/cleanup, never for renewed issuance. */
  claimDue(workerId: string): Promise<WorkloadRenewalClaim | undefined>;
  /** Persist the original observation, including stale-worker evidence. Verify
   * provider proof, exact request, DER/SPKI/SAN/CA/profile/finite interval and
   * current family/policy/ancestor/security fences before a usable publication.
   * Invalid/expired/revoked outcomes remain nonusable for supported cleanup.
   * Stale workers cannot overwrite a newer projection or release its lease. */
  recordReadback(
    claim: WorkloadRenewalClaim,
    observation: WorkloadRenewalReadback,
  ): Promise<WorkloadRenewalRecorded>;
  /** Only after persisting this exact qualified NOT_ISSUED observation. In one
   * short transaction reauthenticate its proof/qualification, original intent,
   * lease/current policy/attestation/parents/security/generation and deadline;
   * commit issuance authorization before returning. Missing authority returns
   * undefined, never a renewal or automatic policy/recovery approval. A policy
   * approver's session is provenance; intentional continuing human parents
   * remain enforced. Reconciliation alone cannot reacquire expired authority. */
  authorizeOriginalIssue(
    claim: WorkloadRenewalClaim,
    nonIssuance: WorkloadRenewalNonIssuance,
  ): Promise<WorkloadRenewalIssuePermit | undefined>;
  /** Same verification/fencing/evidence rules as readback. Lost store responses
   * are reconciled via the original durable intent and provider readback. */
  recordIssue(
    permit: WorkloadRenewalIssuePermit,
    observation: WorkloadRenewalCertificateObservation | WorkloadRenewalUnknownObservation,
  ): Promise<WorkloadRenewalRecorded>;
}
