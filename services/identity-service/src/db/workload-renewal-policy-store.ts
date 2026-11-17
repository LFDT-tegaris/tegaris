import { createHash } from 'node:crypto';
import {
  businessTransitionProfileForOperation,
  workloadRenewalPolicyOperations,
} from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  transitionStatePreimage,
  type CborValue,
} from '@openpc/security-kernel/business-transition/state';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import {
  workloadRenewalPolicyDefinitionSchema,
  workloadRenewalPolicyDefinitionBytes,
  workloadRenewalPolicyDefinitionDigest,
  workloadRenewalPolicyProposalSchema,
  workloadRenewalPolicyStopSchema,
  type WorkloadRenewalPolicyDefinition,
} from '../contracts/workload-renewal-policy.js';
import { captureDurableAuthorities, type DurableAuthority } from './authority-fence.js';
import { AtomicConfigurationMutation } from '../../../control-api/src/configuration/persistence/atomic-mutation.js';
import {
  ScopedConfigurationRead,
  type ReadContext,
} from '../../../control-api/src/configuration/persistence/scoped-read.js';
import type { ConfigurationBusinessEvidence } from '../../../control-api/src/configuration/persistence/business-receipt-writer.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../../../control-api/src/configuration/persistence/types.js';

const u64 = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const stateSchema = z.strictObject({
  revision: u64,
  definition: workloadRenewalPolicyDefinitionSchema,
  definitionDigest: digest,
  state: z.enum(['ACTIVE', 'SUSPENDED', 'REVOKED']),
  governanceOperationId: z.uuidv7(),
  businessAncestorsDigest: digest,
});
export type WorkloadRenewalPolicyState = z.infer<typeof stateSchema>;
type Command = (typeof workloadRenewalPolicyOperations)[number]['command'];
interface PolicyRow {
  revision: string;
  definition: WorkloadRenewalPolicyDefinition;
  definition_canonical: Buffer;
  digest: Buffer;
  state: WorkloadRenewalPolicyState['state'];
  governance_operation_id: string;
  business_ancestors: readonly DurableAuthority[];
}
function policyState(row: PolicyRow): WorkloadRenewalPolicyState {
  const definition = workloadRenewalPolicyDefinitionSchema.parse(row.definition);
  if (
    !workloadRenewalPolicyDefinitionBytes(definition).equals(row.definition_canonical) ||
    workloadRenewalPolicyDefinitionDigest(definition) !== `sha256:${row.digest.toString('hex')}`
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  return stateSchema.parse({
    revision: row.revision,
    definition,
    definitionDigest: `sha256:${row.digest.toString('hex')}`,
    state: row.state,
    governanceOperationId: row.governance_operation_id,
    businessAncestorsDigest: `sha256:${createHash('sha256').update(canonicalDefinitionJson(row.business_ancestors)).digest('hex')}`,
  });
}

/** Real current head, never the latest timestamp or a historical ACTIVE row.
 * The caller owns scoped transaction and authority fences before requesting locks. */
async function currentPolicy(
  client: PoolClient,
  context: Pick<ReadContext, 'authorization' | 'resourceId'>,
  lock: boolean,
) {
  const selected = await client.query<PolicyRow>(
    `select p.revision::text,p.definition,p.definition_canonical,p.digest,p.state,
      p.governance_operation_id,p.business_ancestors
     from control.workload_renewal_policy_head h
     join control.workload_renewal_policy p on p.participant_id=h.participant_id
      and p.privacy_domain_id=h.privacy_domain_id and p.policy_id=h.policy_id
      and p.revision=h.current_revision and p.state=h.state
      and p.principal_id=h.principal_id and p.workload_id=h.workload_id
     where h.participant_id=$1 and h.privacy_domain_id=$2 and h.policy_id=$3
     ${lock ? 'for update of h' : ''}`,
    [
      context.authorization.participantId,
      context.authorization.privacyDomainId,
      context.resourceId,
    ],
  );
  if (selected.rowCount === 0) return undefined;
  if (selected.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
  return policyState(selected.rows[0]!);
}

/** Closed projection binds definition, actual parents and current selection.
 * It grants no authority independently of the governed mutation owner. */
export function bindWorkloadRenewalPolicyState(
  context: MutationContext,
  input: WorkloadRenewalPolicyState | undefined,
) {
  const profile = businessTransitionProfileForOperation(context.catalogOperationId);
  if (profile?.actionIntentId !== context.actionIntentId)
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  return bindWorkloadRenewalPolicySnapshot(
    {
      participantId: context.authorization.participantId,
      privacyDomainId: context.authorization.privacyDomainId,
      policyId: context.resourceId,
    },
    context.catalogOperationId,
    input,
  );
}

/** Pure canonical provenance projection; scope metadata is never authorization. */
export function bindWorkloadRenewalPolicySnapshot(
  scope: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly policyId: string;
  },
  catalogOperationId: string,
  input: WorkloadRenewalPolicyState | undefined,
) {
  const profile = businessTransitionProfileForOperation(catalogOperationId);
  if (!profile || profile.aggregateType !== 'workload-renewal-policy')
    throw new ConfigurationRepositoryError('PC-AUTH-0005');
  const state = input === undefined ? undefined : stateSchema.parse(input);
  if (
    state &&
    (state.definition.participantId !== scope.participantId ||
      state.definition.privacyDomainId !== scope.privacyDomainId ||
      state.definition.policyId !== scope.policyId ||
      workloadRenewalPolicyDefinitionDigest(state.definition) !== state.definitionDigest)
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  const uuid = (id: string) => Buffer.from(id.replaceAll('-', ''), 'hex');
  const ns = (instant: string) => BigInt(Date.parse(instant)) * 1000000n;
  const projection = state
    ? new Map<number, CborValue>([
        [0, Buffer.from(state.definitionDigest.slice(7), 'hex')],
        [1, uuid(state.definition.principalId)],
        [2, state.definition.workloadId],
        [3, state.state],
        [4, uuid(state.governanceOperationId)],
        [5, Buffer.from(state.businessAncestorsDigest.slice(7), 'hex')],
        [6, ns(state.definition.validFrom)],
        [7, ns(state.definition.validUntil)],
      ])
    : new Map<number, CborValue>();
  const existence = state ? (1 as const) : (0 as const);
  const revision = BigInt(state?.revision ?? '0');
  const preimage = transitionStatePreimage(
    {
      profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
      participantId: scope.participantId,
      privacyDomainId: scope.privacyDomainId,
      aggregateType: profile.aggregateType,
      aggregateId: scope.policyId,
    },
    existence,
    revision,
    projection,
  );
  return {
    preimage,
    reference: { existence, revision, stateDigest: createHash('sha256').update(preimage).digest() },
  };
}

export function assertWorkloadRenewalPolicyTransition(
  command: Command,
  expectedRevision: string,
  operationId: string,
  before: WorkloadRenewalPolicyState | undefined,
  after: WorkloadRenewalPolicyState,
) {
  const next = stateSchema.parse(after),
    prior = before === undefined ? undefined : stateSchema.parse(before);
  if (
    workloadRenewalPolicyDefinitionDigest(next.definition) !== next.definitionDigest ||
    (prior && workloadRenewalPolicyDefinitionDigest(prior.definition) !== prior.definitionDigest) ||
    next.governanceOperationId !== operationId ||
    (command === 'CREATE'
      ? prior !== undefined ||
        expectedRevision !== '0' ||
        next.revision !== '1' ||
        next.state !== 'ACTIVE'
      : !prior ||
        prior.state === 'REVOKED' ||
        prior.revision !== expectedRevision ||
        BigInt(next.revision) !== BigInt(prior.revision) + 1n ||
        next.definition.principalId !== prior.definition.principalId ||
        next.definition.workloadId !== prior.definition.workloadId ||
        next.definition.policyId !== prior.definition.policyId ||
        next.definition.participantId !== prior.definition.participantId ||
        next.definition.privacyDomainId !== prior.definition.privacyDomainId ||
        (command === 'REVISE'
          ? next.state !== 'ACTIVE' || next.definitionDigest === prior.definitionDigest
          : next.definitionDigest !== prior.definitionDigest ||
            next.state !== (command === 'SUSPEND' ? 'SUSPENDED' : 'REVOKED') ||
            (command === 'SUSPEND' && prior.state !== 'ACTIVE')))
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
}

/** The existing atomic public owner verifies original intent, independent
 * checker, fresh WebAuthn, current grants and signer, then commits the policy,
 * consumed inputs, signed receipt, event and result together. No unsigned path. */
export class WorkloadRenewalPolicyRepository {
  private readonly mutations: AtomicConfigurationMutation;
  private readonly reads: ScopedConfigurationRead;
  constructor(
    pool: Pool,
    private readonly businessEvidence: ConfigurationBusinessEvidence,
  ) {
    this.mutations = new AtomicConfigurationMutation(pool, undefined, businessEvidence);
    this.reads = new ScopedConfigurationRead(pool);
  }
  /** Configuration readback alone never attests routine renewal eligibility. */
  async read(context: ReadContext) {
    if (
      context.actionIntentId !== 'ACT-PARTICIPANTS_READ_RESOURCE-V1' ||
      context.resourceType !== 'participant'
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return this.reads.execute(context, async (client) => {
      const state = await currentPolicy(client, context, false);
      if (!state) throw new ConfigurationRepositoryError('PC-DATA-6001');
      return {
        policyId: context.resourceId,
        revision: state.revision,
        state: state.state,
        definition: state.definition,
        definitionDigest: state.definitionDigest,
        governanceOperationId: state.governanceOperationId,
        runtimePermission: 'NONE' as const,
      };
    });
  }
  async execute(context: MutationContext) {
    const operation = workloadRenewalPolicyOperations.find(
      (o) => o.catalogOperationId === context.catalogOperationId,
    );
    const profile = businessTransitionProfileForOperation(context.catalogOperationId);
    if (
      !this.businessEvidence ||
      !profile ||
      !operation ||
      context.authorization.evidenceKind !== 'USER_WEBAUTHN' ||
      context.actionIntentId !== operation.actionIntentId ||
      context.resourceType !== operation.resourceType ||
      context.operationClass !== operation.operationClass ||
      context.aggregateType !== operation.aggregateType ||
      profile.aggregateType !== context.aggregateType ||
      profile.resourceType !== context.resourceType
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    const proposal =
      operation.command === 'CREATE' || operation.command === 'REVISE'
        ? workloadRenewalPolicyProposalSchema.parse(context.candidate)
        : undefined;
    const stop = proposal ? undefined : workloadRenewalPolicyStopSchema.parse(context.candidate);
    const candidate = proposal ?? stop!;
    if (
      candidate.expectedRevision !== context.expectedRevision ||
      (proposal &&
        (proposal.definition.participantId !== context.authorization.participantId ||
          proposal.definition.privacyDomainId !== context.authorization.privacyDomainId ||
          proposal.definition.policyId !== context.resourceId))
    )
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return this.mutations.execute(
      context,
      async (client, policyId, operationId, authority) => {
        // Capture the already fenced real parents before taking the current head.
        const ancestors = await captureDurableAuthorities(
          client,
          context.authorization.participantId,
          authority.authorities,
        );
        const before = await currentPolicy(client, context, true);
        const definition = proposal?.definition ?? before?.definition;
        if (!definition) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const live = await client.query(
          `select principal_id from control.principal p
        where participant_id=$1 and principal_id=$2 and kind='WORKLOAD'
        and exists(select 1 from control.credential c where c.participant_id=p.participant_id and c.principal_id=p.principal_id
          and c.kind='WORKLOAD_MTLS' and c.subject=$3)
        and ($4::text not in ('CREATE','REVISE') or (p.state='ACTIVE' and $5::timestamptz>clock_timestamp()))`,
          [
            definition.participantId,
            definition.principalId,
            definition.workloadId,
            operation.command,
            definition.validUntil,
          ],
        );
        if (live.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
        const after: WorkloadRenewalPolicyState = {
          revision: (BigInt(context.expectedRevision) + 1n).toString(),
          definition,
          definitionDigest: workloadRenewalPolicyDefinitionDigest(definition),
          state:
            operation.command === 'SUSPEND'
              ? 'SUSPENDED'
              : operation.command === 'REVOKE'
                ? 'REVOKED'
                : 'ACTIVE',
          governanceOperationId: operationId,
          businessAncestorsDigest: `sha256:${createHash('sha256').update(canonicalDefinitionJson(ancestors)).digest('hex')}`,
        };
        assertWorkloadRenewalPolicyTransition(
          operation.command,
          context.expectedRevision,
          operationId,
          before,
          after,
        );
        await client.query(
          `insert into control.workload_renewal_policy
        (participant_id,privacy_domain_id,policy_id,revision,principal_id,workload_id,digest,definition,definition_canonical,
         governance_operation_id,business_ancestors,attestation_profile_digest,issuer_profile_digest,provider_qualification_digest,valid_from,valid_until,state)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
          [
            definition.participantId,
            definition.privacyDomainId,
            policyId,
            after.revision,
            definition.principalId,
            definition.workloadId,
            Buffer.from(after.definitionDigest.slice(7), 'hex'),
            definition,
            workloadRenewalPolicyDefinitionBytes(definition),
            operationId,
            JSON.stringify(ancestors),
            Buffer.from(definition.attestationProfileDigest.slice(7), 'hex'),
            Buffer.from(definition.issuerProfileDigest.slice(7), 'hex'),
            Buffer.from(definition.providerQualificationDigest.slice(7), 'hex'),
            definition.validFrom,
            definition.validUntil,
            after.state,
          ],
        );
        const head =
          operation.command === 'CREATE'
            ? await client.query(
                `insert into control.workload_renewal_policy_head
            (participant_id,privacy_domain_id,policy_id,principal_id,workload_id,current_revision,state)
            values($1,$2,$3,$4,$5,$6,$7)`,
                [
                  definition.participantId,
                  definition.privacyDomainId,
                  policyId,
                  definition.principalId,
                  definition.workloadId,
                  after.revision,
                  after.state,
                ],
              )
            : await client.query(
                `update control.workload_renewal_policy_head set current_revision=$4,state=$5,row_version=row_version+1
            where participant_id=$1 and privacy_domain_id=$2 and policy_id=$3 and current_revision=$6`,
                [
                  definition.participantId,
                  definition.privacyDomainId,
                  policyId,
                  after.revision,
                  after.state,
                  context.expectedRevision,
                ],
              );
        if (head.rowCount !== 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        const actual = await currentPolicy(client, context, false);
        if (!actual || canonicalDefinitionJson(actual) !== canonicalDefinitionJson(after))
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        return {
          result: actual,
          revision: actual.revision,
          outboxEventType: 'io.openpc.control.command.committed.v1',
          businessState: {
            before: bindWorkloadRenewalPolicyState(context, before),
            after: bindWorkloadRenewalPolicyState(context, actual),
          },
        };
      },
      undefined,
      undefined,
      async (client) => {
        // Discovery only; the atomic owner merges this target into the ordinary
        // maker/checker/signer fence before any business locks or effect.
        const definition =
          proposal?.definition ?? (await currentPolicy(client, context, false))?.definition;
        if (!definition) throw new ConfigurationRepositoryError('PC-DATA-6007');
        return { principal: [{ id: definition.principalId }] };
      },
    );
  }
}
