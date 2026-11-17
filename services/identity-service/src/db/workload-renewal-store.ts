import type { PoolClient } from 'pg';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { workloadRenewalOriginalSchema } from '../contracts/workload-renewal.js';
import {
  verifyWorkloadRenewalObservation,
  workloadRenewalProviderResponseSchema,
  type WorkloadRenewalProviderProfile,
  type WorkloadRenewalTransportBinding,
} from '../domain/workload-renewal-provider.js';
import type {
  WorkloadRenewalClaim,
  WorkloadRenewalIssuePermit,
  WorkloadRenewalNonIssuance,
  WorkloadRenewalOriginal,
  WorkloadRenewalReadback,
  WorkloadRenewalRecorded,
  WorkloadRenewalStore,
} from '../domain/workload-renewal-worker-contract.js';
import {
  fenceDurableAuthorities,
  revalidateDurableAuthorities,
  AuthorityFenceError,
  type DurableAuthority,
} from './authority-fence.js';
import {
  readEligibleWorkloadRenewalPolicySource,
  WorkloadRenewalPolicySourceUnavailable,
} from './workload-renewal-policy-source.js';
import { BusinessSigningTrustError } from '@openpc/security-kernel';

export class WorkloadRenewalUnavailable extends Error {
  constructor() {
    super('Workload renewal authority is unavailable');
  }
}
interface InstalledWorkerTransaction {
  readonly client: PoolClient;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly workerId: string;
  readonly providerProfile: WorkloadRenewalProviderProfile;
}
/** Implemented only by the actual installed worker + verified transport owner.
 * It creates short scoped transactions and resolves the installed provider
 * qualification; neither workerId nor a caller-selected scope grants access.
 * No composition currently installs this v2 owner. That prerequisite is OPEN.
 * The attestation assertion must authenticate independent registered source,
 * one-use nonce/new-key possession, instance generation and policy revision. */
export interface WorkloadRenewalInstallation {
  /** Authenticate the immutable governed policy/instance admission receipt and
   * consumed independent challenge against this exact original. Historical
   * proof survives revocation for reconciliation; it confers no current use.
   * ACTIVE rows or a bootstrap operation reference are never sufficient. */
  assertOriginalAdmission(client: PoolClient, original: WorkloadRenewalOriginal): Promise<void>;
  withTransaction<T>(
    workerId: string,
    operation: (bound: InstalledWorkerTransaction) => Promise<T>,
  ): Promise<T>;
  assertCurrentAttestation(
    client: PoolClient,
    original: WorkloadRenewalOriginal,
    evidence: Buffer,
  ): Promise<void>;
}
export const unavailableWorkloadRenewalInstallation: WorkloadRenewalInstallation = {
  async assertOriginalAdmission() {
    throw new WorkloadRenewalUnavailable();
  },
  async withTransaction() {
    throw new WorkloadRenewalUnavailable();
  },
  async assertCurrentAttestation() {
    throw new WorkloadRenewalUnavailable();
  },
};

interface IntentRow {
  original: WorkloadRenewalOriginal;
  state: WorkloadRenewalRecorded['state'] | 'COMPLETE';
  provider_outcome: WorkloadRenewalRecorded['providerOutcome'];
  row_version: string;
  lease_fence: string;
  worker_id: string | null;
  lease_expires_at: Date | null;
  renewal_deadline: Date;
  attestation_valid_until: Date;
  attestation_evidence: Buffer;
  family_security_epoch: string;
  latest_observation_id: string | null;
  now: Date;
}
const columns = `original,state,provider_outcome,row_version::text,lease_fence::text,worker_id,
  lease_expires_at,renewal_deadline,attestation_valid_until,attestation_evidence,
  family_security_epoch::text,latest_observation_id,clock_timestamp() as now`;
const exact = (left: unknown, right: unknown) =>
  canonicalDefinitionJson(left) === canonicalDefinitionJson(right);
const digestBytes = (value: string) => Buffer.from(value.slice(7), 'hex');
const scope = (original: WorkloadRenewalOriginal) => [
  original.participantId,
  original.privacyDomainId,
  original.renewalId,
];

/** Pure supplemental fence used only after reading the original attempt and
 * current durable row. It cannot authenticate/admit either argument. */
export function currentWorkloadRenewalLease(
  claim: WorkloadRenewalClaim,
  row: {
    original: WorkloadRenewalOriginal;
    worker_id: string | null;
    lease_fence: string;
    lease_expires_at: Date | null;
    now: Date;
  },
): boolean {
  return (
    exact(claim.original, row.original) &&
    claim.workerId === row.worker_id &&
    claim.leaseFence === row.lease_fence &&
    row.lease_expires_at !== null &&
    row.lease_expires_at.toISOString() === claim.leaseExpiresAt &&
    row.lease_expires_at > row.now
  );
}

async function guard(bound: InstalledWorkerTransaction, workerId: string) {
  if (bound.workerId !== workerId) throw new WorkloadRenewalUnavailable();
  await bound.client.query('select openpc.assert_request_context(true)');
  const result = await bound.client.query<{ valid: boolean }>(
    `select openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
       and current_setting('row_security')='on' and current_setting('transaction_isolation')='read committed'
       and not r.rolsuper and not r.rolbypassrls and
       pg_has_role(current_user,'openpc_control_worker','USAGE') as valid
     from pg_roles r where r.rolname=current_user`,
    [bound.participantId, bound.privacyDomainId],
  );
  if (result.rowCount !== 1 || result.rows[0]?.valid !== true)
    throw new WorkloadRenewalUnavailable();
}

async function originalAttempt(bound: InstalledWorkerTransaction, claim: WorkloadRenewalClaim) {
  const parsed = workloadRenewalOriginalSchema.parse(claim.original);
  if (
    parsed.participantId !== bound.participantId ||
    parsed.privacyDomainId !== bound.privacyDomainId ||
    parsed.providerQualificationDigest !== bound.providerProfile.qualificationDigest ||
    parsed.issuerProfileDigest !== bound.providerProfile.issuerProfileDigest
  )
    throw new WorkloadRenewalUnavailable();
  const attempt = await bound.client.query<{ valid: boolean }>(
    `select worker_id=$5 and lease_fence=$6::numeric and lease_expires_at=$7::timestamptz
       and provider_timeout_ms=$8::numeric as valid from control.workload_renewal_attempt
     where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3 and attempt_id=$4`,
    [
      ...scope(parsed),
      claim.attemptId,
      claim.workerId,
      claim.leaseFence,
      claim.leaseExpiresAt,
      claim.providerTimeoutMs,
    ],
  );
  if (attempt.rowCount !== 1 || attempt.rows[0]?.valid !== true)
    throw new WorkloadRenewalUnavailable();
  const result = await bound.client.query<IntentRow>(
    `select ${columns} from control.workload_renewal_intent where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3`,
    scope(parsed),
  );
  if (
    result.rowCount !== 1 ||
    !exact(result.rows[0]!.original, parsed) ||
    result.rows[0]!.renewal_deadline.toISOString() !== claim.renewalDeadline
  )
    throw new WorkloadRenewalUnavailable();
  return result.rows[0]!;
}

/** Check the actual business path before business aggregate locks (C04).
 * Approval sessions are provenance; intentionally retained human grants remain
 * in these durable ancestors and are never silently discarded. */
async function currentAuthority(
  bound: InstalledWorkerTransaction,
  row: IntentRow,
): Promise<{ revalidate(): Promise<void> } | undefined> {
  const o = row.original,
    client = bound.client;
  const params = [o.participantId, o.privacyDomainId, o.policyId, o.policyRevision];
  const policy = await client.query<{ business_ancestors: readonly DurableAuthority[] }>(
    `select business_ancestors from control.workload_renewal_policy
     where participant_id=$1 and privacy_domain_id=$2 and policy_id=$3 and revision=$4`,
    params,
  );
  if (policy.rowCount !== 1) return undefined;
  try {
    await fenceDurableAuthorities(client, o.participantId, policy.rows[0]!.business_ancestors, {
      participant: [{ id: o.participantId }],
      privacy_domain: [{ id: o.privacyDomainId }],
      principal: [{ id: o.principalId }],
      credential: [{ id: o.predecessorCredentialId }],
    });
    await bound.client.query('select openpc.assert_request_context(true)');
    const source = await readEligibleWorkloadRenewalPolicySource(client, o);
    if (
      source.definition.principalId !== o.principalId ||
      source.definition.workloadId !== o.workloadId ||
      !exact(source.businessAncestors, policy.rows[0]!.business_ancestors)
    )
      return undefined;
    await client.query(
      `select policy_id from control.workload_renewal_policy
      where participant_id=$1 and privacy_domain_id=$2 and policy_id=$3 and revision=$4 for share`,
      params,
    );
    const result = await client.query<{ valid: boolean }>(
      `select f.state='ACTIVE' and p.state='ACTIVE' and h.state='ACTIVE'
         and h.current_revision=p.revision and h.principal_id=p.principal_id and h.workload_id=p.workload_id
         and c.state='ACTIVE' and c.kind='WORKLOAD_MTLS'
         and principal.state='ACTIVE' and principal.kind='WORKLOAD' and participant.state='ACTIVE' and domain.state='ACTIVE'
         and f.principal_id=$4 and p.principal_id=$4 and c.principal_id=$4 and c.subject=$5 and f.workload_id=$5 and c.audience=$18
         and f.instance_id=$6 and f.instance_generation=$7::numeric and f.generation=$8::numeric
         and f.current_credential_id=$9 and f.current_fingerprint=c.secret_fingerprint
         and f.security_epoch=$10::numeric and f.policy_id=$11 and f.policy_revision=$12::numeric
         and p.digest=$13 and p.attestation_profile_digest=$14 and p.issuer_profile_digest=$15
         and p.provider_qualification_digest=$16 and p.business_ancestors=$17::jsonb
         and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
         and p.valid_from<=clock_timestamp() and p.valid_until>clock_timestamp() as valid
       from control.workload_credential_family f
       join control.workload_renewal_policy p using (participant_id,privacy_domain_id,policy_id)
       join control.workload_renewal_policy_head h using (participant_id,privacy_domain_id,policy_id)
       join control.credential c on c.participant_id=f.participant_id and c.credential_id=f.current_credential_id
       join control.principal principal on principal.participant_id=f.participant_id and principal.principal_id=f.principal_id
       join control.participant participant on participant.participant_id=f.participant_id
       join control.privacy_domain domain on domain.participant_id=f.participant_id and domain.privacy_domain_id=f.privacy_domain_id
       where f.participant_id=$1 and f.privacy_domain_id=$2 and f.family_id=$3 and p.revision=f.policy_revision
       for update of f`,
      [
        o.participantId,
        o.privacyDomainId,
        o.familyId,
        o.principalId,
        o.workloadId,
        o.instanceId,
        o.instanceGeneration,
        o.expectedFamilyGeneration,
        o.predecessorCredentialId,
        row.family_security_epoch,
        o.policyId,
        o.policyRevision,
        digestBytes(o.policyDigest),
        digestBytes(o.attestationProfileDigest),
        digestBytes(o.issuerProfileDigest),
        digestBytes(o.providerQualificationDigest),
        JSON.stringify(policy.rows[0]!.business_ancestors),
        bound.providerProfile.audience,
      ],
    );
    if (result.rowCount !== 1 || result.rows[0]?.valid !== true) return undefined;
    return {
      revalidate: async () => {
        await revalidateDurableAuthorities(client, o.participantId, source.businessAncestors);
        await source.revalidate();
        const credential = await client.query(
          `select c.credential_id from control.credential c
        join control.principal p using(participant_id,principal_id)
        join control.participant participant using(participant_id)
        join control.privacy_domain d on d.participant_id=c.participant_id and d.privacy_domain_id=$2
        where c.participant_id=$1 and c.credential_id=$3 and c.principal_id=$4
          and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and p.kind='WORKLOAD' and p.state='ACTIVE'
          and participant.state='ACTIVE' and d.state='ACTIVE'
          and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()`,
          [o.participantId, o.privacyDomainId, o.predecessorCredentialId, o.principalId],
        );
        if (credential.rowCount !== 1) throw new WorkloadRenewalUnavailable();
      },
    };
  } catch (error) {
    if (
      error instanceof AuthorityFenceError ||
      error instanceof WorkloadRenewalUnavailable ||
      error instanceof WorkloadRenewalPolicySourceUnavailable ||
      error instanceof BusinessSigningTrustError
    )
      return undefined;
    throw error;
  }
}

/** The returned store is executable against its owning schema, but the
 * installed native worker/attestor and SQL mutation admission are not yet wired.
 * Default composition rejects before a claim, not after an invented approval. */
export function createWorkloadRenewalStore(
  installation: WorkloadRenewalInstallation = unavailableWorkloadRenewalInstallation,
): WorkloadRenewalStore & {
  checkCommittedPermit(
    permit: WorkloadRenewalIssuePermit,
    binding: WorkloadRenewalTransportBinding,
  ): Promise<void>;
} {
  const transaction = <T>(
    workerId: string,
    operation: (bound: InstalledWorkerTransaction) => Promise<T>,
  ) =>
    installation.withTransaction(workerId, async (bound) => {
      await guard(bound, workerId);
      return operation(bound);
    });
  const lockIntent = async (bound: InstalledWorkerTransaction, o: WorkloadRenewalOriginal) => {
    const result = await bound.client.query<IntentRow>(
      `select ${columns} from control.workload_renewal_intent
      where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3 for update`,
      scope(o),
    );
    if (result.rowCount !== 1) throw new WorkloadRenewalUnavailable();
    return result.rows[0]!;
  };
  const record = async (
    claim: WorkloadRenewalClaim,
    observation: WorkloadRenewalReadback,
  ): Promise<WorkloadRenewalRecorded> =>
    transaction(claim.workerId, async (bound) => {
      // Persist bounded public evidence, never arbitrary adapter exception text.
      if (observation.kind === 'UNKNOWN') {
        observation = {
          kind: 'UNKNOWN',
          reason: [
            'TRANSPORT_UNAVAILABLE',
            'PROVIDER_OUTCOME_UNKNOWN',
            'UNQUALIFIED_RESPONSE',
          ].includes(observation.reason)
            ? observation.reason
            : 'UNQUALIFIED_RESPONSE',
        };
      } else if (!workloadRenewalProviderResponseSchema.safeParse(observation).success) {
        observation = { kind: 'UNKNOWN', reason: 'UNQUALIFIED_RESPONSE' };
      }
      const preliminary = await originalAttempt(bound, claim);
      await installation.assertOriginalAdmission(bound.client, claim.original);
      const verified = verifyWorkloadRenewalObservation(
        claim.original,
        observation,
        bound.providerProfile,
        preliminary.now,
      );
      // Authentic observations survive missing business authority. The worker's
      // independent installation admission, scope and attempt are still required.
      let authority = false;
      if (
        verified?.kind === 'CERTIFICATE' &&
        verified.certificate &&
        preliminary.attestation_valid_until > preliminary.now &&
        preliminary.renewal_deadline > preliminary.now
      ) {
        try {
          await installation.assertCurrentAttestation(
            bound.client,
            claim.original,
            preliminary.attestation_evidence,
          );
          const authorized = await bound.client.query<{ exists: boolean }>(
            `select exists(select 1
            from control.workload_renewal_issue_authorization where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3)`,
            scope(claim.original),
          );
          authority =
            authorized.rows[0]?.exists === true &&
            Boolean(await currentAuthority(bound, preliminary));
        } catch (error) {
          if (!(error instanceof WorkloadRenewalUnavailable)) throw error;
        }
      }
      const row = await lockIntent(bound, claim.original);
      const current = currentWorkloadRenewalLease(claim, row);
      const previous = await bound.client.query<{
        proof_revision: string | null;
        proof_digest: Buffer | null;
      }>(
        `select proof_revision::text,proof_digest from control.workload_renewal_observation
         where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3 and proof_revision is not null
         order by proof_revision desc limit 1`,
        scope(claim.original),
      );
      const prior = previous.rows[0];
      const monotonic =
        !verified ||
        !prior ||
        prior.proof_revision === null ||
        BigInt(verified.proofRevision) > BigInt(prior.proof_revision);
      const observed = await bound.client.query<{ observation_id: string }>(
        `insert into control.workload_renewal_observation
         (participant_id,privacy_domain_id,observation_id,renewal_id,attempt_id,observation,proof_digest,proof_revision,disposition)
         values($1,$2,uuidv7(),$3,$4,$5,$6,$7,$8) returning observation_id`,
        [
          ...scope(claim.original),
          claim.attemptId,
          JSON.stringify(observation),
          verified ? digestBytes(verified.proofDigest) : null,
          verified?.proofRevision ?? null,
          !verified ? 'UNQUALIFIED' : current && monotonic ? 'CURRENT' : 'STALE',
        ],
      );
      if (!current || !monotonic || row.state === 'COMPLETE') {
        if (verified?.kind === 'CERTIFICATE' && row.provider_outcome !== 'ISSUED')
          await bound.client.query(
            `update control.workload_renewal_intent set cleanup_required='RECONCILE'
            where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3 and cleanup_required='NONE'`,
            scope(claim.original),
          );
        return projection(row);
      }
      const expired = row.renewal_deadline <= row.now;
      const currentVerified = verifyWorkloadRenewalObservation(
        claim.original,
        observation,
        bound.providerProfile,
        row.now,
      );
      const prepared =
        verified?.kind === 'CERTIFICATE' &&
        currentVerified?.certificate !== undefined &&
        currentVerified.fresh &&
        authority &&
        !expired &&
        row.attestation_valid_until > row.now;
      const outcome =
        row.provider_outcome === 'ISSUED' || verified?.kind === 'CERTIFICATE'
          ? 'ISSUED'
          : verified?.kind === 'NOT_ISSUED' && verified.fresh
            ? 'NOT_ISSUED'
            : 'UNRESOLVED';
      const state = prepared ? 'PREPARED' : expired ? 'FAILED' : 'RECOVERING';
      const retryMs =
        [5000, 15000, 30000, 60000][Math.min(4, Number(row.lease_fence) - 1)] ?? 300_000;
      // NOT_ISSUED alone retains this lease for immediate authorization. All
      // finished/unknown paths release only the currently fenced worker lease.
      const releaseLease = observation.kind !== 'NOT_ISSUED' || !verified?.fresh;
      const updated = await bound.client.query<IntentRow>(
        `update control.workload_renewal_intent set state=$4,provider_outcome=$5,latest_observation_id=$6,
          certificate_der=coalesce($7,certificate_der),certificate_fingerprint=coalesce($8,certificate_fingerprint),
          cleanup_required=$9,row_version=row_version+1,next_attempt_at=clock_timestamp()+$10::int*interval '1 millisecond',
          worker_id=case when $11 then null else worker_id end,lease_expires_at=case when $11 then null else lease_expires_at end
         where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3 returning ${columns}`,
        [
          ...scope(claim.original),
          state,
          outcome,
          observed.rows[0]!.observation_id,
          prepared ? currentVerified!.certificate!.certificateDer : null,
          prepared ? currentVerified!.certificate!.certificateFingerprint : null,
          prepared || outcome === 'NOT_ISSUED'
            ? 'NONE'
            : outcome === 'ISSUED'
              ? 'REVOKE'
              : 'RECONCILE',
          retryMs,
          releaseLease,
        ],
      );
      return projection(updated.rows[0]!);
    });
  return {
    claimDue(workerId) {
      return transaction(workerId, async (bound) => {
        const result = await bound.client.query<IntentRow>(
          `select ${columns} from control.workload_renewal_intent
          where participant_id=$1 and privacy_domain_id=$2 and next_attempt_at<=clock_timestamp()
            and (lease_expires_at is null or lease_expires_at<=clock_timestamp())
            and (state='RECOVERING' or (state='FAILED' and cleanup_required<>'NONE'))
          order by next_attempt_at,created_at,renewal_id limit 1 for update skip locked`,
          [bound.participantId, bound.privacyDomainId],
        );
        if (!result.rowCount) return undefined;
        const row = result.rows[0]!,
          original = workloadRenewalOriginalSchema.parse(row.original);
        await installation.assertOriginalAdmission(bound.client, original);
        if (original.providerQualificationDigest !== bound.providerProfile.qualificationDigest)
          throw new WorkloadRenewalUnavailable();
        const attempt = await bound.client.query<{
          attempt_id: string;
          lease_fence: string;
          lease_expires_at: Date;
        }>(
          `with claimed as (update control.workload_renewal_intent
           set lease_fence=lease_fence+1,worker_id=$4,lease_expires_at=clock_timestamp()+interval '90 seconds'
           where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3 returning *)
           insert into control.workload_renewal_attempt
           (participant_id,privacy_domain_id,renewal_id,attempt_id,worker_id,lease_fence,lease_expires_at,provider_timeout_ms)
           select participant_id,privacy_domain_id,renewal_id,uuidv7(),worker_id,lease_fence,lease_expires_at,30000 from claimed
           returning attempt_id,lease_fence::text,lease_expires_at`,
          [...scope(original), workerId],
        );
        const a = attempt.rows[0]!;
        return {
          original,
          workerId,
          attemptId: a.attempt_id,
          leaseFence: a.lease_fence,
          leaseExpiresAt: a.lease_expires_at.toISOString(),
          renewalDeadline: row.renewal_deadline.toISOString(),
          providerTimeoutMs: 30000,
        };
      });
    },
    recordReadback: record,
    async authorizeOriginalIssue(claim, nonIssuance) {
      return transaction(claim.workerId, async (bound) => {
        const preliminary = await originalAttempt(bound, claim);
        await installation.assertOriginalAdmission(bound.client, claim.original);
        const proof = verifyWorkloadRenewalObservation(
          claim.original,
          nonIssuance,
          bound.providerProfile,
          preliminary.now,
        );
        if (
          proof?.kind !== 'NOT_ISSUED' ||
          !proof.fresh ||
          preliminary.renewal_deadline <= preliminary.now ||
          preliminary.attestation_valid_until <= preliminary.now
        )
          return undefined;
        await installation.assertCurrentAttestation(
          bound.client,
          claim.original,
          preliminary.attestation_evidence,
        );
        const authority = await currentAuthority(bound, preliminary);
        if (!authority) return undefined;
        const row = await lockIntent(bound, claim.original);
        if (
          !currentWorkloadRenewalLease(claim, row) ||
          row.state !== 'RECOVERING' ||
          row.provider_outcome !== 'NOT_ISSUED' ||
          row.renewal_deadline <= row.now ||
          row.attestation_valid_until <= row.now ||
          !verifyWorkloadRenewalObservation(
            claim.original,
            nonIssuance,
            bound.providerProfile,
            row.now,
          )?.fresh
        )
          return undefined;
        const latest = await bound.client.query<{
          observation: WorkloadRenewalNonIssuance;
          disposition: string;
        }>(
          `select observation,disposition from control.workload_renewal_observation
           where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3 and observation_id=$4 and attempt_id=$5`,
          [...scope(claim.original), row.latest_observation_id, claim.attemptId],
        );
        if (
          latest.rowCount !== 1 ||
          latest.rows[0]?.disposition !== 'CURRENT' ||
          !exact(latest.rows[0]?.observation, nonIssuance)
        )
          return undefined;
        const authorization = await bound.client.query<{ authorization_id: string }>(
          `insert into control.workload_renewal_issue_authorization
           (participant_id,privacy_domain_id,authorization_id,renewal_id,attempt_id,observation_id,lease_fence)
           values($1,$2,uuidv7(),$3,$4,$5,$6)
           on conflict(participant_id,privacy_domain_id,observation_id) do nothing returning authorization_id`,
          [...scope(claim.original), claim.attemptId, row.latest_observation_id, claim.leaseFence],
        );
        if (authorization.rowCount !== 1) return undefined;
        await authority.revalidate();
        return { claim, issuanceAuthorizationId: authorization.rows[0]!.authorization_id };
      });
    },
    async recordIssue(permit, observation) {
      // Authorizations are immutable history. A stale, genuinely authorized
      // attempt may retain its effect; an invented ID cannot impersonate it.
      await transaction(permit.claim.workerId, async (bound) => {
        await originalAttempt(bound, permit.claim);
        await installation.assertOriginalAdmission(bound.client, permit.claim.original);
        const result = await bound.client.query(
          `select authorization_id from control.workload_renewal_issue_authorization
          where participant_id=$1 and privacy_domain_id=$2 and renewal_id=$3 and authorization_id=$4 and attempt_id=$5 and lease_fence=$6`,
          [
            ...scope(permit.claim.original),
            permit.issuanceAuthorizationId,
            permit.claim.attemptId,
            permit.claim.leaseFence,
          ],
        );
        if (result.rowCount !== 1) throw new WorkloadRenewalUnavailable();
      });
      return record(permit.claim, observation);
    },
    async checkCommittedPermit(permit, binding) {
      await transaction(permit.claim.workerId, async (bound) => {
        if (
          binding.endpoint !== bound.providerProfile.endpoint ||
          binding.qualificationDigest !== bound.providerProfile.qualificationDigest
        )
          throw new WorkloadRenewalUnavailable();
        const row = await originalAttempt(bound, permit.claim);
        await installation.assertOriginalAdmission(bound.client, permit.claim.original);
        if (
          !currentWorkloadRenewalLease(permit.claim, row) ||
          row.renewal_deadline <= row.now ||
          row.attestation_valid_until <= row.now ||
          row.provider_outcome !== 'NOT_ISSUED' ||
          row.state !== 'RECOVERING'
        )
          throw new WorkloadRenewalUnavailable();
        await installation.assertCurrentAttestation(
          bound.client,
          permit.claim.original,
          row.attestation_evidence,
        );
        const authority = await currentAuthority(bound, row);
        if (!authority) throw new WorkloadRenewalUnavailable();
        const locked = await lockIntent(bound, permit.claim.original);
        if (
          !currentWorkloadRenewalLease(permit.claim, locked) ||
          locked.renewal_deadline <= locked.now ||
          locked.attestation_valid_until <= locked.now ||
          locked.state !== 'RECOVERING' ||
          locked.provider_outcome !== 'NOT_ISSUED'
        )
          throw new WorkloadRenewalUnavailable();
        const authorization = await bound.client.query<{
          valid: boolean;
          observation: WorkloadRenewalNonIssuance;
        }>(
          `select a.observation_id=i.latest_observation_id and o.disposition='CURRENT' and o.observation->>'kind'='NOT_ISSUED' as valid,o.observation
           from control.workload_renewal_issue_authorization a
           join control.workload_renewal_intent i using(participant_id,privacy_domain_id,renewal_id)
           join control.workload_renewal_observation o on o.participant_id=a.participant_id and o.privacy_domain_id=a.privacy_domain_id and o.observation_id=a.observation_id
           where a.participant_id=$1 and a.privacy_domain_id=$2 and a.renewal_id=$3 and a.authorization_id=$4 and a.attempt_id=$5 and a.lease_fence=$6`,
          [
            ...scope(permit.claim.original),
            permit.issuanceAuthorizationId,
            permit.claim.attemptId,
            permit.claim.leaseFence,
          ],
        );
        if (
          authorization.rowCount !== 1 ||
          authorization.rows[0]?.valid !== true ||
          !verifyWorkloadRenewalObservation(
            permit.claim.original,
            authorization.rows[0]!.observation,
            bound.providerProfile,
            locked.now,
          )?.fresh
        )
          throw new WorkloadRenewalUnavailable();
        await authority.revalidate();
      });
    },
  };
}

function projection(row: IntentRow): WorkloadRenewalRecorded {
  if (row.state === 'COMPLETE') throw new WorkloadRenewalUnavailable();
  return {
    renewalId: row.original.renewalId,
    operationId: row.original.operationId,
    revision: row.row_version,
    observedAt: row.now.toISOString(),
    state: row.state,
    providerOutcome: row.provider_outcome,
  };
}
