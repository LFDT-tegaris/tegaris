import { currentPlatformEnvelopeSql } from '../db/current-platform-envelope.js';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import type { PoolClient } from 'pg';
import { authorityEnvelopeDigest, decodeEnvelopeProposal } from '@openpc/security-kernel';
import { projectUsableEnvelopePermission } from '../db/identity-envelope-proposal.js';
import { runtimeTargetProfileBindingDigest } from '../../../control-api/src/configuration/runtime-profile/digest.js';

/** Stored projection content is a deterministic JSON view of the owning SQL
 * records. It is content-addressed by the signed actor projection; it is not a
 * replacement grant, signature schema, or independently trusted assertion. */
export type SourceValue =
  | null
  | boolean
  | number
  | string
  | readonly SourceValue[]
  | {
      readonly [key: string]: SourceValue;
    };
export function sourceBytes(value: SourceValue): Buffer {
  function ordered(item: SourceValue): SourceValue {
    if (Array.isArray(item)) return item.map(ordered);
    if (item !== null && typeof item === 'object') {
      return Object.fromEntries(
        Object.entries(item)
          .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
          .map(([key, entry]) => [key, ordered(entry)]),
      );
    }
    if (typeof item === 'number' && !Number.isSafeInteger(item))
      throw new Error('Inexact authority source');
    return item;
  }
  return Buffer.from(JSON.stringify(ordered(value)));
}
export const sourceDigest = (value: SourceValue): Buffer =>
  createHash('sha256').update(sourceBytes(value)).digest();

/** The signed snapshot attests this projection. Raw multi-context envelope
 * bytes are not forwarded to a target in just one privacy domain. */
export function scopedPermission(source: SourceValue, privacyDomainId: string): SourceValue {
  if (source === null || Array.isArray(source) || typeof source !== 'object')
    throw new Error('Invalid authority permission source');
  return {
    ...Object.fromEntries(
      Object.entries(source).filter(
        ([key, value]) =>
          key !== 'semantic_cbor' &&
          key !== 'cose_sign1' &&
          key !== 'privacy_domain_ids' &&
          key !== 'last_mutation_operation_id' &&
          // Bootstrap provenance remains in its control-store receipt owner;
          // it is not part of the target's permission record contract.
          key !== 'bootstrap_mandate_id' &&
          key !== 'bootstrap_platform_participant_id' &&
          key !== 'creator_participant_id' &&
          // Ordinary envelopes acquire this nullable persistence column. Omit
          // only its empty value; genuine recovery metadata still fails the
          // runtime's closed permission contract and cannot become CALL authority.
          (key !== 'recovery_case_id' || value !== null) &&
          // Fact admission checks this separate live Control binding under
          // custody; it is not an extension of the permission record format.
          key !== 'platform_context_id' &&
          key !== 'platform_authority_epoch',
      ),
    ),
    privacy_domain_ids: [privacyDomainId],
  };
}

/** Read restrictions from the original canonical proposal, rather than the flat
 * table projection. A profile name is not a native target UUID; this content
 * preserves the restriction but supplies no profile-to-target resolution. */
export function scopedEnvelopePermission(
  source: { readonly [key: string]: SourceValue },
  proposalBytes: Buffer,
  proposalDigest: Buffer,
  privacyDomainId: string,
): SourceValue {
  if (source.representation !== 'TYPED_V1') return scopedPermission(source, privacyDomainId);
  const proposal = decodeEnvelopeProposal(proposalBytes);
  const permission = projectUsableEnvelopePermission(proposal);
  if (
    authorityEnvelopeDigest(proposalBytes) !== `sha256:${proposalDigest.toString('hex')}` ||
    proposal.envelopeId !== source.authority_envelope_id ||
    proposal.participantId !== source.participant_id ||
    !permission.privacyDomainIds.includes(privacyDomainId) ||
    !isDeepStrictEqual(permission.privacyDomainIds, source.privacy_domain_ids) ||
    !isDeepStrictEqual(permission.actionIntentIds, source.action_intent_ids) ||
    !isDeepStrictEqual(permission.runtimeCapabilityIds, source.runtime_capability_ids) ||
    !isDeepStrictEqual(permission.resourceIds, source.resource_ids) ||
    !isDeepStrictEqual(permission.riskClasses, source.risk_classes) ||
    proposal.usable.validFromNs !== source.valid_from_ns ||
    proposal.usable.validUntilNs !== source.valid_until_ns ||
    proposal.usable.makerCheckerRequired !== source.maker_checker_required ||
    proposal.usable.stepUpRequired !== source.step_up_required ||
    proposal.usable.onwardDelegationDepth !== source.onward_delegation_depth
  )
    throw new Error('Typed envelope permission projection mismatch');
  const scoped = scopedPermission(source, privacyDomainId);
  if (scoped === null || Array.isArray(scoped) || typeof scoped !== 'object')
    throw new Error('Invalid scoped envelope permission');
  return {
    ...scoped,
    ...(permission.runtimeCapabilityIds.length === 0
      ? {}
      : {
          runtime_scope: {
            data_classes: permission.dataClasses,
            target_profile_ids: permission.targetProfileIds,
          },
        }),
  };
}

export interface AuthoritySource {
  readonly id: string;
  readonly principalId: string;
  readonly parentId: string | null;
  readonly parentKind: 'ASSIGNMENT' | 'DELEGATION' | null;
  readonly envelopeId: string | null;
  readonly roleId: string | null;
  readonly source: { readonly [key: string]: SourceValue };
}
interface PrincipalSource {
  readonly id: string;
  readonly kind: string;
  readonly source: { readonly [key: string]: SourceValue };
}
interface CredentialSource {
  readonly principalId: string;
  readonly workloadId: string;
  readonly source: { readonly [key: string]: SourceValue };
}

/** Retained credentials are evidence, while only live credentials establish a
 * current workload identity. Never select one of two live audiences. */
export function currentWorkloadCredentialBinding(credentials: readonly CredentialSource[]) {
  const currentIds = new Set(
    credentials
      .filter(
        (credential) =>
          credential.source.state === 'ACTIVE' && credential.source.valid_now === true,
      )
      .map((credential) => credential.workloadId),
  );
  if (currentIds.size > 1) throw new Error('Ambiguous workload principal binding');
  const workloadId = [...currentIds][0];
  if (workloadId === undefined) return undefined;
  return {
    workloadId,
    credentials: credentials.filter((credential) => credential.workloadId === workloadId),
  };
}
interface WalletBindingSource {
  readonly principalId: string;
  readonly source: { readonly [key: string]: SourceValue };
}
export interface WorkloadAuthoritySource {
  readonly principalId: string;
  readonly workloadId: string;
  readonly principal: SourceValue;
  readonly credentials: readonly SourceValue[];
  /** Scoped associations constrain recovered signers; they confer no permission. */
  readonly walletBindings: readonly SourceValue[];
  /** Root first; every source constraint remains available to the local owner. */
  readonly paths: readonly (readonly SourceValue[])[];
  readonly envelopes: readonly SourceValue[];
  readonly revocations: readonly SourceValue[];
}
export interface RuntimeAuthorityGraph {
  readonly participant: SourceValue;
  readonly privacy: SourceValue;
  readonly actors: readonly WorkloadAuthoritySource[];
  readonly nextTransitionNs: bigint | undefined;
  readonly runtimeTargetProfile: SourceValue;
}

const MAX_SOURCE_ROWS = 16_384;
function bounded<T>(rows: T[]): T[] {
  if (rows.length > MAX_SOURCE_ROWS) throw new Error('Identity authority graph capacity exceeded');
  return rows;
}

/** Caller holds the participant UPDATE fence for this entire transaction. The
 * supported graph mutation owners take at least a SHARE fence on that root
 * before their narrower write locks; that excludes concurrent publication.
 * Read inactive rows too: their retained versions prevent remove/regrant reuse. */
export async function readRuntimeAuthorityGraph(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  targetRuntimeId?: string,
): Promise<RuntimeAuthorityGraph> {
  const roots = await client.query<{ participant: SourceValue; privacy: SourceValue }>(
    `select jsonb_build_object('id',p.participant_id,'state',p.state,'epoch',p.authority_epoch::text) participant,
            jsonb_build_object('id',d.privacy_domain_id,'state',d.state,'version',d.row_version::text) privacy
       from control.participant p join control.privacy_domain d on d.participant_id=p.participant_id
      where p.participant_id=$1 and p.state='ACTIVE' and d.privacy_domain_id=$2 and d.state='ACTIVE'`,
    [participantId, privacyDomainId],
  );
  if (roots.rows.length !== 1) throw new Error('Identity authority context unavailable');
  let runtimeTargetProfile: SourceValue = null;
  if (targetRuntimeId !== undefined) {
    const bindings = await client.query<{
      binding_id: string;
      participant_id: string;
      privacy_domain_id: string;
      runtime_target_id: string;
      target_profile_id: string;
      binding_digest: string;
    }>(
      `select binding_id::text,participant_id::text,privacy_domain_id::text,
         runtime_target_id::text,target_profile_id,binding_digest
       from control.runtime_target_profile_binding
       where participant_id=$1 and privacy_domain_id=$2 and runtime_target_id=$3`,
      [participantId, privacyDomainId, targetRuntimeId],
    );
    if (bindings.rowCount !== 0) {
      const binding = bindings.rows[0];
      if (
        bindings.rowCount !== 1 ||
        binding === undefined ||
        binding.binding_digest !==
          runtimeTargetProfileBindingDigest({
            participantId,
            privacyDomainId,
            targetRuntimeId,
            targetProfileId: binding.target_profile_id,
          })
      )
        throw new Error('Runtime target profile binding unavailable');
      runtimeTargetProfile = binding;
    }
  }
  const principals = bounded(
    (
      await client.query<PrincipalSource>(
        `select principal_id id,kind,to_jsonb(p)-'created_at'-'updated_at'-'display_label'-'row_version'-'authority_epoch'
        ||jsonb_build_object('row_version',row_version::text,'authority_epoch',authority_epoch::text) source
       from control.principal p where participant_id=$1 order by principal_id limit 16385`,
        [participantId],
      )
    ).rows,
  );
  const credentials = bounded(
    (
      await client.query<CredentialSource>(
        `select principal_id "principalId",audience "workloadId",
            jsonb_build_object('credential_id',credential_id,'principal_id',principal_id,'issuer',issuer,
              'subject',subject,'audience',audience,'state',state,'epoch',credential_epoch::text,
              'public_key_digest',encode(public_key_digest,'hex'),'fingerprint',encode(secret_fingerprint,'hex'),
              'valid_from',valid_from,'valid_until',valid_until,
              'valid_from_ns',(extract(epoch from valid_from)*1000000000)::numeric(20,0)::text,
              'valid_until_ns',(extract(epoch from valid_until)*1000000000)::numeric(20,0)::text,
              'valid_now',valid_from<=transaction_timestamp() and valid_until>transaction_timestamp()) source
       from control.credential where participant_id=$1 and kind='WORKLOAD_MTLS'
       order by credential_id limit 16385`,
        [participantId],
      )
    ).rows,
  );
  const walletBindings = bounded(
    (
      await client.query<WalletBindingSource>(
        `select subject_id "principalId",jsonb_build_object(
           'wallet_binding_id',wallet_binding_id,'participant_id',participant_id,
           'privacy_domain_id',privacy_domain_id,'subject_id',subject_id,
           'chain_id',chain_id::text,'wallet_address',wallet_address,'state',state,
           'binding_epoch',binding_epoch::text,'row_version',row_version::text) source
         from control.wallet_binding where participant_id=$1 and privacy_domain_id=$2
         order by wallet_binding_id limit 16385`,
        [participantId, privacyDomainId],
      )
    ).rows,
  );
  const assignments = bounded(
    (
      await client.query<AuthoritySource>(
        `select a.assignment_id id,a.principal_id "principalId",null::text "parentId",null::text "parentKind",
            a.authority_envelope_id "envelopeId",a.role_id "roleId",
            to_jsonb(a)-'created_at'-'updated_at'-'row_version'-'delegation_epoch'-'last_mutation_operation_id'
              ||jsonb_build_object('row_version',a.row_version::text,'delegation_epoch',a.delegation_epoch::text,
                'valid_from_ns',(extract(epoch from lower(a.valid_during))*1000000000)::numeric(20,0)::text,
                'valid_until_ns',(extract(epoch from upper(a.valid_during))*1000000000)::numeric(20,0)::text,
                'valid_now',a.valid_during @> transaction_timestamp())
              ||case when a.authority_group_id is null then '{}'::jsonb else
                jsonb_build_object('group_scope',member.scope) end source
       from control.assignment a
       left join lateral (
         select jsonb_build_object('group_id',g.authority_group_id,'principal_id',m.principal_id,
           'group_revision',g.row_version::text,'member_id',m.authority_group_member_id,
           'active',openpc.assignment_group_permits(g.participant_id,g.authority_group_id,a.principal_id,a.valid_during),
           'valid_from_ns',(extract(epoch from lower(m.valid_during))*1000000000)::numeric(20,0)::text,
           'valid_until_ns',(extract(epoch from upper(m.valid_during))*1000000000)::numeric(20,0)::text,
           'fresh_until_ns',(extract(epoch from least(d.fresh_until,
             d.observed_at+make_interval(secs=>c.external_group_freshness_seconds)))*1000000000)::numeric(20,0)::text) scope
          from control.authority_group g
          join control.authority_group_member m on m.participant_id=g.participant_id
           and m.authority_group_id=g.authority_group_id and m.principal_id=a.principal_id
           and m.state='ACTIVE' and m.valid_during @> a.valid_during
          left join control.directory_group_mapping d on d.participant_id=g.participant_id
           and d.authority_group_id=g.authority_group_id
          left join control.directory_connector c on c.participant_id=d.participant_id and c.connector_id=d.connector_id
         where g.participant_id=a.participant_id and g.authority_group_id=a.authority_group_id
         order by m.authority_group_member_id limit 1
       ) member on true
       where a.participant_id=$1 order by a.assignment_id limit 16385`,
        [participantId],
      )
    ).rows,
  );
  const delegations = bounded(
    (
      await client.query<AuthoritySource>(
        `select delegation_id id,delegate_principal_id "principalId",
            coalesce(parent_assignment_id,parent_delegation_id)::text "parentId",
            case when parent_assignment_id is null then 'DELEGATION' else 'ASSIGNMENT' end "parentKind",
            null::text "envelopeId",null::text "roleId",
            to_jsonb(d)-'created_at'-'updated_at'-'row_version'-'delegation_epoch'-'last_mutation_operation_id'
              ||jsonb_build_object('row_version',row_version::text,'delegation_epoch',delegation_epoch::text,
                'valid_from_ns',(extract(epoch from lower(valid_during))*1000000000)::numeric(20,0)::text,
                'valid_until_ns',(extract(epoch from upper(valid_during))*1000000000)::numeric(20,0)::text,
                'valid_now',valid_during @> transaction_timestamp()) source
       from control.delegation d where participant_id=$1 order by delegation_id limit 16385`,
        [participantId],
      )
    ).rows,
  );
  const envelopes = bounded(
    (
      await client.query<{
        id: string;
        source: { readonly [key: string]: SourceValue };
        proposalBytes: Buffer;
        proposalDigest: Buffer;
      }>(
        `select authority_envelope_id id,semantic_cbor "proposalBytes",semantic_digest "proposalDigest",
        to_jsonb(e)-'created_at'-'updated_at'-'row_version'-'authority_epoch'-'delegation_epoch'-'semantic_cbor'-'cose_sign1'-'last_mutation_operation_id'
       ||jsonb_build_object('row_version',row_version::text,'authority_epoch',authority_epoch::text,
         'delegation_epoch',delegation_epoch::text,
         'valid_from_ns',(extract(epoch from valid_from)*1000000000)::numeric(20,0)::text,
         'valid_until_ns',(extract(epoch from valid_until)*1000000000)::numeric(20,0)::text,
         'valid_now',valid_from<=transaction_timestamp() and (valid_until is null or valid_until>transaction_timestamp())
          and ${currentPlatformEnvelopeSql('e', true)}) source
       from control.authority_envelope e where participant_id=$1 order by authority_envelope_id limit 16385`,
        [participantId],
      )
    ).rows,
  );
  const revocations = bounded(
    (
      await client.query<{ targetId: string; source: SourceValue }>(
        `select target_id "targetId",to_jsonb(r)-'created_at'-'authority_epoch'
       ||jsonb_build_object('authority_epoch',authority_epoch::text,
         'effective_now',effective_at<=transaction_timestamp()) source
       from control.revocation r where participant_id=$1 order by revocation_id limit 16385`,
        [participantId],
      )
    ).rows,
  );
  const assignmentById = new Map(assignments.map((a) => [a.id, a]));
  const delegationById = new Map(delegations.map((d) => [d.id, d]));
  const envelopeById = new Map(envelopes.map((e) => [e.id, e]));
  const principalById = new Map(principals.map((p) => [p.id, p]));
  function ancestry(leaf: AuthoritySource): AuthoritySource[] {
    const path = [leaf];
    const seen = new Set([leaf.id]);
    let cursor = leaf;
    while (cursor.parentId !== null) {
      const parent = (cursor.parentKind === 'ASSIGNMENT' ? assignmentById : delegationById).get(
        cursor.parentId,
      );
      if (parent === undefined || seen.has(parent.id) || path.length > 32)
        throw new Error('Invalid retained authority ancestry');
      seen.add(parent.id);
      path.push(parent);
      cursor = parent;
    }
    return path.reverse();
  }
  const actors: WorkloadAuthoritySource[] = [];
  for (const principal of principals.filter((p) => p.kind === 'WORKLOAD')) {
    const binding = currentWorkloadCredentialBinding(
      credentials.filter((c) => c.principalId === principal.id),
    );
    if (binding === undefined) continue;
    const boundCredentials = binding.credentials;
    const leaves = [...assignments, ...delegations].filter((a) => a.principalId === principal.id);
    const paths = leaves.map(ancestry).filter((path) => {
      const envelopeId = path[0]!.envelopeId;
      const envelope = envelopeId === null ? undefined : envelopeById.get(envelopeId)?.source;
      if (
        envelope === undefined ||
        envelope === null ||
        Array.isArray(envelope) ||
        typeof envelope !== 'object'
      )
        throw new Error('Missing authority envelope');
      return [...path.map((grant) => grant.source), envelope].every((source) => {
        const privacy = (source as { readonly privacy_domain_ids?: SourceValue })
          .privacy_domain_ids;
        return Array.isArray(privacy) && privacy.includes(privacyDomainId);
      });
    });
    const relevantIds = new Set([
      principal.id,
      ...paths.flatMap((path) => path.flatMap((a) => [a.id, a.principalId])),
    ]);
    const relevantEnvelopes = new Map<string, SourceValue>();
    for (const path of paths) {
      const envelopeId = path[0]!.envelopeId;
      const envelope = envelopeId === null ? undefined : envelopeById.get(envelopeId);
      if (envelope === undefined) throw new Error('Missing authority envelope');
      relevantIds.add(envelope.id);
      relevantEnvelopes.set(
        envelope.id,
        scopedEnvelopePermission(
          envelope.source,
          envelope.proposalBytes,
          envelope.proposalDigest,
          privacyDomainId,
        ),
      );
    }
    const actorWalletBindings = walletBindings
      .filter((binding) => binding.principalId === principal.id)
      .map((binding) => binding.source);
    if (actorWalletBindings.length > 4096)
      throw new Error('Workload wallet association capacity exceeded');
    actors.push({
      principalId: principal.id,
      workloadId: binding.workloadId,
      principal: principal.source,
      credentials: boundCredentials.map((c) => c.source),
      walletBindings: actorWalletBindings,
      paths: paths.map((path) =>
        path.map((a) => {
          const owner = principalById.get(a.principalId);
          if (owner === undefined) throw new Error('Missing authority principal');
          return { grant: scopedPermission(a.source, privacyDomainId), principal: owner.source };
        }),
      ),
      envelopes: [...relevantEnvelopes]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([, value]) => value),
      revocations: revocations.filter((r) => relevantIds.has(r.targetId)).map((r) => r.source),
    });
  }
  if (actors.length === 0 || actors.length > 8192)
    throw new Error('Identity snapshot actor capacity exceeded');
  // Time transitions invalidate the whole head even if no row was written.
  const transition = await client.query<{ ns: string | null }>(
    `select (extract(epoch from min(t))*1000000000)::numeric(20,0)::text ns from (
       select lower(valid_during) t from control.assignment where participant_id=$1
       union all select upper(valid_during) from control.assignment where participant_id=$1
       union all select lower(valid_during) from control.delegation where participant_id=$1
       union all select upper(valid_during) from control.delegation where participant_id=$1
       union all select valid_from from control.authority_envelope where participant_id=$1
       union all select valid_until from control.authority_envelope where participant_id=$1
       union all select valid_from from control.credential where participant_id=$1 and kind='WORKLOAD_MTLS'
       union all select valid_until from control.credential where participant_id=$1 and kind='WORKLOAD_MTLS'
       union all select effective_at from control.revocation where participant_id=$1
       union all select lower(valid_during) from control.authority_group_member where participant_id=$1
       union all select upper(valid_during) from control.authority_group_member where participant_id=$1
       union all select least(d.fresh_until,d.observed_at+make_interval(secs=>c.external_group_freshness_seconds))
         from control.directory_group_mapping d join control.directory_connector c
           on c.participant_id=d.participant_id and c.connector_id=d.connector_id where d.participant_id=$1
     ) transitions where t>transaction_timestamp() and isfinite(t)`,
    [participantId],
  );
  const ns = transition.rows[0]?.ns;
  return {
    ...roots.rows[0]!,
    actors,
    runtimeTargetProfile,
    nextTransitionNs: ns === null || ns === undefined ? undefined : BigInt(ns),
  };
}
