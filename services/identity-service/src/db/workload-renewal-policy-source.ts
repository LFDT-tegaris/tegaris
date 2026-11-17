import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  assertBusinessSigningGrant,
  businessSigningTrustDigest,
  businessSigningTrustPreimage,
  businessTransitionProfileForOperation,
  configurationRequestDigest,
  encodeCommandCommitted,
  commandCommittedEventType,
  commandCommittedDataSchema,
  type BusinessSigningTrust,
} from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';
import {
  verifyBusinessSource,
  type BusinessSourceRow,
} from '../../../control-api/src/evidence/business-source.js';
import {
  workloadRenewalPolicyDefinitionSchema,
  workloadRenewalPolicyDefinitionBytes,
  workloadRenewalPolicyDefinitionDigest,
  workloadRenewalPolicyProposalSchema,
} from '../contracts/workload-renewal-policy.js';
import type { DurableAuthority } from './authority-fence.js';
import { readRetainedBusinessSigningTrust } from './business-signing-store.js';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import {
  bindWorkloadRenewalPolicySnapshot,
  assertWorkloadRenewalPolicyTransition,
  type WorkloadRenewalPolicyState,
} from './workload-renewal-policy-store.js';

export class WorkloadRenewalPolicySourceUnavailable extends Error {
  constructor() {
    super('Workload renewal policy source is unavailable');
  }
}
interface Scope {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly policyId: string;
  readonly policyRevision: string;
}
export interface WorkloadRenewalPolicySourceRow extends BusinessSourceRow {
  readonly revision: string;
  readonly definition: unknown;
  readonly definitionCanonical: Buffer;
  readonly definitionDigest: Buffer;
  readonly businessAncestors: readonly DurableAuthority[];
  readonly governanceOperationId: string;
  readonly state: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
  readonly authoritySnapshot: Buffer;
  readonly beforeStatePreimage: Buffer;
  readonly afterStatePreimage: Buffer;
  readonly prior: WorkloadRenewalPolicyState | null;
  readonly candidate: unknown;
  readonly principalId: string;
  readonly idempotencyKey: string;
}
const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest();
const fail = (): never => {
  throw new WorkloadRenewalPolicySourceUnavailable();
};

/** Historical governance verification. It does not renew a human session,
 * select an old private key, establish current policy eligibility or sign376. */
export function verifyWorkloadRenewalPolicySource(
  row: WorkloadRenewalPolicySourceRow,
  scope: Scope,
  trust: BusinessSigningTrust,
) {
  try {
    const receipt = verifyBusinessSource(row, scope);
    const profile = businessTransitionProfileForOperation(receipt.catalogOperationId);
    const command =
      receipt.catalogOperationId === 'ID-OP-WORKLOAD-RENEWAL-POLICY-CREATE'
        ? 'CREATE'
        : receipt.catalogOperationId === 'ID-OP-WORKLOAD-RENEWAL-POLICY-REVISE'
          ? 'REVISE'
          : undefined;
    const definition = workloadRenewalPolicyDefinitionSchema.parse(row.definition);
    const candidate = workloadRenewalPolicyProposalSchema.parse(row.candidate);
    if (
      !profile ||
      !command ||
      row.state !== 'ACTIVE' ||
      row.revision !== scope.policyRevision ||
      receipt.aggregateId !== scope.policyId ||
      receipt.aggregateType !== 'workload-renewal-policy' ||
      receipt.operationId !== row.governanceOperationId ||
      definition.participantId !== scope.participantId ||
      definition.privacyDomainId !== scope.privacyDomainId ||
      definition.policyId !== scope.policyId ||
      canonicalDefinitionJson(candidate.definition) !== canonicalDefinitionJson(definition) ||
      sha256(candidate) !== `sha256:${receipt.candidateDigest.toString('hex')}` ||
      !workloadRenewalPolicyDefinitionBytes(definition).equals(row.definitionCanonical) ||
      workloadRenewalPolicyDefinitionDigest(definition) !==
        `sha256:${row.definitionDigest.toString('hex')}` ||
      !businessSigningTrustPreimage(trust).equals(row.trustPreimage) ||
      !businessSigningTrustDigest(trust).equals(receipt.signerTrustSnapshotDigest) ||
      !trust.publicKeySpkiDer.equals(row.publicKey) ||
      trust.signerId !== receipt.signerId ||
      !digest(row.authoritySnapshot).equals(receipt.preCommitAuthorityDigest) ||
      receipt.authorizationEvidence.length !== 2 ||
      receipt.authorizationEvidence[0]?.kind !== 3 ||
      receipt.authorizationEvidence[1]?.kind !== 4 ||
      receipt.outboxEvents.length !== 1
    )
      return fail();
    assertBusinessSigningGrant(trust, {
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      environmentId: receipt.environmentId,
      nowNs: receipt.recordedAtNs,
      profileId: profile.profileId,
      profileVersion: profile.profileVersion,
      profileDigest: receipt.transitionProfileDigest,
      actionIntentId: receipt.actionIntentId,
      catalogOperationId: receipt.catalogOperationId,
    });
    if (
      !configurationRequestDigest({
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        principalId: row.principalId,
        actionIntentId: receipt.actionIntentId,
        catalogOperationId: receipt.catalogOperationId,
        aggregateType: receipt.aggregateType,
        aggregateId: scope.policyId,
        expectedRevision: candidate.expectedRevision,
        candidateDigest: receipt.candidateDigest,
        idempotencyKey: row.idempotencyKey,
      }).equals(receipt.requestDigest)
    )
      return fail();
    const snapshot = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(row.authoritySnapshot),
    ) as {
      schema: string;
      participantId: string;
      privacyDomainId: string;
      operationId: string;
      decision: string;
      authorities: Record<string, unknown>[];
    };
    if (
      snapshot.schema !== 'pc.control.precommit-authority-snapshot.v1' ||
      snapshot.decision !== 'ALLOW' ||
      snapshot.participantId !== scope.participantId ||
      snapshot.privacyDomainId !== scope.privacyDomainId ||
      snapshot.operationId !== receipt.operationId ||
      !Array.isArray(snapshot.authorities) ||
      snapshot.authorities.length !== row.businessAncestors.length ||
      snapshot.authorities.length < 2 ||
      snapshot.authorities.length > 64 ||
      snapshot.authorities[0]?.principalId !== row.principalId ||
      snapshot.authorities
        .slice(1)
        .some((authority) => authority.principalId === row.principalId) ||
      !identityActorKeyDigest(scope.participantId, row.principalId).equals(
        receipt.actorKeyDigest,
      ) ||
      !Buffer.from(canonicalDefinitionJson(snapshot)).equals(row.authoritySnapshot)
    )
      return fail();
    for (const [i, ancestor] of row.businessAncestors.entries()) {
      const bound = Object.fromEntries(
        Object.entries(snapshot.authorities[i]!).filter(
          ([key]) => key !== 'sessionId' && key !== 'sessionEpoch',
        ),
      );
      const { catalogOperationId, ...grant } = ancestor.grant;
      if (
        canonicalDefinitionJson(grant) !== canonicalDefinitionJson(bound) ||
        (catalogOperationId !== undefined && catalogOperationId !== receipt.catalogOperationId)
      )
        return fail();
    }
    const after: WorkloadRenewalPolicyState = {
      revision: row.revision,
      definition,
      definitionDigest: `sha256:${row.definitionDigest.toString('hex')}`,
      state: row.state,
      governanceOperationId: row.governanceOperationId,
      businessAncestorsDigest: sha256(Buffer.from(canonicalDefinitionJson(row.businessAncestors))),
    };
    const before = row.prior ?? undefined;
    assertWorkloadRenewalPolicyTransition(
      command,
      candidate.expectedRevision,
      receipt.operationId,
      before,
      after,
    );
    const beforeBinding = bindWorkloadRenewalPolicySnapshot(
      scope,
      receipt.catalogOperationId,
      before,
    );
    const afterBinding = bindWorkloadRenewalPolicySnapshot(
      scope,
      receipt.catalogOperationId,
      after,
    );
    for (const [binding, ref, bytes] of [
      [beforeBinding, receipt.before, row.beforeStatePreimage],
      [afterBinding, receipt.after, row.afterStatePreimage],
    ] as const)
      if (
        !binding.preimage.equals(bytes) ||
        binding.reference.existence !== ref.existence ||
        binding.reference.revision !== ref.revision ||
        !binding.reference.stateDigest.equals(ref.stateDigest)
      )
        return fail();
    const event = receipt.outboxEvents[0]!;
    const eventPayload = encodeCommandCommitted({
      commandId: receipt.operationId,
      aggregateRef: `urn:openpc:workload-renewal-policy:${scope.policyId}`,
      actionIntentId: receipt.actionIntentId,
      intentDigest: `sha256:${receipt.actionIntentDigest.toString('hex')}`,
    });
    if (
      !digest(eventPayload).equals(event.payloadDigest) ||
      event.eventType !== commandCommittedEventType ||
      event.dataSchemaUri !== commandCommittedDataSchema ||
      event.source !== 'urn:openpc:service:control-api' ||
      event.subject !== `urn:openpc:workload-renewal-policy:${scope.policyId}` ||
      event.correlationId !== receipt.operationId ||
      event.occurredAtNs !== receipt.recordedAtNs ||
      event.causationId !== undefined ||
      event.authorityGeneration !== undefined
    )
      return fail();
    return { definition, businessAncestors: row.businessAncestors, receipt, eventPayload };
  } catch {
    return fail();
  }
}

/** Call only inside the owning scoped transaction, after durable parent fences,
 * before family/attempt locks. Historical signer lifecycle precedes policy head
 * locks, matching the human writer. No provider I/O or business mutation occurs. */
export async function readEligibleWorkloadRenewalPolicySource(client: PoolClient, scope: Scope) {
  const selected = await client.query<WorkloadRenewalPolicySourceRow>(
    `
    select p.revision::text as revision,p.definition,p.definition_canonical as "definitionCanonical",
      p.digest as "definitionDigest",p.business_ancestors as "businessAncestors",p.state,
      p.governance_operation_id as "governanceOperationId",
      e.evidence_record_id::text as "evidenceId",a.receipt_id::text as "receiptId",a.operation_id::text as "operationId",
      a.receipt_cbor as payload,a.receipt_digest as "payloadDigest",a.cose_sign1 as "coseSign1",
      a.signer_id as "signerId",k.public_key_spki_der as "publicKey",k.trust_digest as "trustDigest",
      k.trust_preimage as "trustPreimage",a.recorded_at_ns::text as "recordedAtNs",e.evidence_format as "evidenceFormat",
      a.authority_snapshot as "authoritySnapshot",a.before_state_preimage as "beforeStatePreimage",
      a.after_state_preimage as "afterStatePreimage",c.candidate_document as candidate,
      i.principal_id as "principalId",i.idempotency_key as "idempotencyKey",
      case when prior.policy_id is null then null else jsonb_build_object('revision',prior.revision::text,
        'definition',prior.definition,'definitionDigest','sha256:'||encode(prior.digest,'hex'),'state',prior.state,
        'governanceOperationId',prior.governance_operation_id,
        'businessAncestorsDigest','sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(prior.business_ancestors),'UTF8')),'hex')) end as prior
    from control.workload_renewal_policy p
    join control.audit_occurrence a on a.participant_id=p.participant_id and a.privacy_domain_id=p.privacy_domain_id
      and a.operation_id=p.governance_operation_id and a.aggregate_id=p.policy_id
    join control.evidence_record e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id
      and e.receipt_id=a.receipt_id and e.receipt_digest=a.receipt_digest
      and e.evidence_role='BUSINESS_TRANSITION_RECEIPT' and e.custody='CONTROL_STORE'
    join control.business_signing_key k on k.participant_id=a.participant_id and k.privacy_domain_id=a.privacy_domain_id
      and k.signer_id=a.signer_id and k.trust_digest=a.signer_trust_snapshot_digest and k.signing_purpose_code=338
    join control.mutation_candidate c on c.participant_id=a.participant_id and c.privacy_domain_id=a.privacy_domain_id
      and c.consumed_operation_id=a.operation_id and c.state='CONSUMED'
      and c.candidate_digest=a.candidate_digest and c.catalog_operation_id=a.catalog_operation_id
      and c.action_intent_id=a.action_intent_id and c.resource_id=p.policy_id
    join control.idempotency_record i on i.participant_id=a.participant_id and i.privacy_domain_id=a.privacy_domain_id
      and i.operation_id=a.operation_id and i.idempotency_record_id=a.idempotency_record_id
      and i.principal_id=c.maker_principal_id and i.idempotency_key=c.idempotency_key
      and i.catalog_operation_id=a.catalog_operation_id and i.action_intent_id=a.action_intent_id
      and i.input_digest=a.candidate_digest and i.terminal_state='COMMITTED'
      and i.result_aggregate_version=p.revision and i.expected_aggregate_version=c.expected_revision
    left join control.workload_renewal_policy prior on prior.participant_id=p.participant_id
      and prior.privacy_domain_id=p.privacy_domain_id and prior.policy_id=p.policy_id and prior.revision=p.revision-1
    where p.participant_id=$1 and p.privacy_domain_id=$2 and p.policy_id=$3 and p.revision=$4`,
    [scope.participantId, scope.privacyDomainId, scope.policyId, scope.policyRevision],
  );
  if (selected.rowCount !== 1 || !selected.rows[0]) return fail();
  const row = selected.rows[0];
  const trust = await readRetainedBusinessSigningTrust(client, scope, row.signerId);
  const verified = verifyWorkloadRenewalPolicySource(row, scope, trust);
  const keyState = await client.query(
    `select state from control.business_signing_key_state
    where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and state<>'COMPROMISED' for share`,
    [scope.participantId, scope.privacyDomainId, row.signerId],
  );
  if (keyState.rowCount !== 1) return fail();
  const head = await client.query(
    `select h.policy_id from control.workload_renewal_policy_head h
    join control.workload_renewal_policy p on p.participant_id=h.participant_id and p.privacy_domain_id=h.privacy_domain_id
      and p.policy_id=h.policy_id and p.revision=h.current_revision and p.state=h.state
      and p.principal_id=h.principal_id and p.workload_id=h.workload_id
    where h.participant_id=$1 and h.privacy_domain_id=$2 and h.policy_id=$3 and h.current_revision=$4
      and h.state='ACTIVE' and p.valid_from<=clock_timestamp() and p.valid_until>clock_timestamp() for share of h`,
    [scope.participantId, scope.privacyDomainId, scope.policyId, scope.policyRevision],
  );
  if (head.rowCount !== 1) return fail();
  const receipt = verified.receipt;
  const evidence = await client.query<{ kind: number; id: string; digest: Buffer }>(
    `
    select 3 as kind,d.approval_decision_id::text as id,sha256(d.evidence_cbor) as digest
    from control.approval_decision_record d
    join control.approval_request r using(participant_id,privacy_domain_id,approval_request_id)
    join control.mutation_candidate c on c.participant_id=r.participant_id and c.privacy_domain_id=r.privacy_domain_id
      and c.mutation_candidate_id=r.subject_id and c.candidate_digest=r.subject_digest
      and c.expected_revision=r.subject_version and c.action_intent_id=r.action_intent_id
    join control.mutation_evidence v on v.participant_id=c.participant_id and v.privacy_domain_id=c.privacy_domain_id
      and v.operation_id=c.consumed_operation_id and v.approval_request_id=d.approval_request_id
      and v.checker_principal_id=d.approver_principal_id and v.principal_id=c.maker_principal_id
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.state='CONSUMED' and c.consumed_operation_id=$3
      and c.catalog_operation_id=$4 and d.decision='APPROVE' and d.approver_principal_id<>c.maker_principal_id
    union all
    select 4 as kind,v.mutation_evidence_id::text as id,v.evidence_digest as digest
    from control.mutation_evidence v join control.mfa_challenge m on m.participant_id=v.participant_id
      and m.principal_id=v.principal_id and m.mfa_challenge_id=v.mfa_challenge_id
    where v.participant_id=$1 and v.privacy_domain_id=$2 and v.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY'
      and m.used_operation_id=$3 and m.action_intent_id=$5 and v.evidence_digest=sha256(v.evidence_cbor)`,
    [
      scope.participantId,
      scope.privacyDomainId,
      receipt.operationId,
      receipt.catalogOperationId,
      receipt.actionIntentId,
    ],
  );
  if (
    evidence.rowCount !== 2 ||
    receipt.authorizationEvidence.some(
      (ref) =>
        evidence.rows.filter(
          (actual) =>
            actual.kind === ref.kind &&
            actual.id === ref.evidenceId &&
            actual.digest.equals(ref.evidenceDigest),
        ).length !== 1,
    )
  )
    return fail();
  const event = receipt.outboxEvents[0]!;
  const outbox = await client.query(
    `select event_id from control.outbox_event
    where participant_id=$1 and privacy_domain_id=$2 and receipt_id=$3
      and event_id=$4 and event_type=$5 and aggregate_type='workload-renewal-policy' and aggregate_id=$6
      and business_sequence=$7 and payload_cbor=$8 and payload_digest=$9 and data_schema_uri=$10
      and source=$11 and subject=$12 and correlation_id=$13 and causation_id is null and authority_generation is null
      and floor(extract(epoch from occurred_at)*1000000)*1000=$14
      and proof_kind='BUSINESS_RECEIPT_REFERENCE' and sequence_namespace='CONTROL_BUSINESS_TRANSITION_V1'
      and not exists(select 1 from control.outbox_event other where other.participant_id=$1
        and other.privacy_domain_id=$2 and other.receipt_id=$3 and other.event_id<>$4)`,
    [
      scope.participantId,
      scope.privacyDomainId,
      receipt.receiptId,
      event.eventId,
      event.eventType,
      scope.policyId,
      event.aggregateSequence.toString(),
      verified.eventPayload,
      event.payloadDigest,
      event.dataSchemaUri,
      event.source,
      event.subject,
      event.correlationId,
      event.occurredAtNs.toString(),
    ],
  );
  if (outbox.rowCount !== 1) return fail();
  return {
    ...verified,
    revalidate: async () => {
      // These exact rows were already held above. Recheck time and compromise
      // without discovering new dependencies or taking late business locks.
      const current = await client.query(
        `select h.policy_id from control.workload_renewal_policy_head h
      join control.workload_renewal_policy p on p.participant_id=h.participant_id and p.privacy_domain_id=h.privacy_domain_id
        and p.policy_id=h.policy_id and p.revision=h.current_revision and p.state=h.state
        and p.principal_id=h.principal_id and p.workload_id=h.workload_id
      join control.business_signing_key_state k on k.participant_id=h.participant_id
        and k.privacy_domain_id=h.privacy_domain_id and k.signer_id=$5 and k.state<>'COMPROMISED'
      where h.participant_id=$1 and h.privacy_domain_id=$2 and h.policy_id=$3 and h.current_revision=$4
        and h.state='ACTIVE' and p.valid_from<=clock_timestamp() and p.valid_until>clock_timestamp()`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.policyId,
          scope.policyRevision,
          row.signerId,
        ],
      );
      if (current.rowCount !== 1) return fail();
    },
  };
}
