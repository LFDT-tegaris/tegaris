import type { PoolClient } from 'pg';
import { isDeepStrictEqual } from 'node:util';
import {
  assertEnvelopeScopeNarrowing,
  decodeEnvelopeScope,
  platformEnvelopeScopeSuccessorDigest,
  platformEnvelopeScopeSuccessorPreimage,
  type EnvelopeProposal,
  type PlatformEnvelopeScopeAdmission,
} from '@openpc/security-kernel';
import { platformScopeReplacementPreparation } from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import { AuthorityFenceError } from './authority-fence.js';
import type { EnvelopeGovernanceScope } from './identity-envelope-proposal.js';

type CurrentRoot = PlatformEnvelopeScopeAdmission & { platformAuthorityDigest: string };

/** Explicit administration handoff under one already governed replacement.
 * This is not general authority or permission to issue future workload grants.
 * The regular issuer/current-actor fences remain required before this lookup. */
export async function pendingPlatformAdministrator(
  client: PoolClient,
  scope: Pick<EnvelopeGovernanceScope, 'participantId' | 'privacyDomainId'>,
  current: CurrentRoot,
  envelopeId: string,
  replacementId?: string,
) {
  const rows = await client.query<{
    candidate: unknown;
    replacement_id: string;
    prepare_operation_id: string;
    now_ns: string;
    successor_scope_cbor: Buffer;
    successor_preimage: Buffer;
    successor_digest: Buffer;
  }>(
    `select r.candidate,r.replacement_id::text,r.prepare_operation_id::text,
      (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text now_ns,
      r.successor_scope_cbor,r.successor_preimage,r.successor_digest
    from control.platform_scope_replacement r join control.platform_context p
      on p.platform_context_id=r.platform_context_id and p.owner_participant_id=r.participant_id
      and p.state='ACTIVE' and p.authority_epoch=r.predecessor_epoch and p.row_version=r.expected_root_revision
    where r.participant_id=$1 and r.privacy_domain_id=$2 and r.platform_context_id=$3
      and r.state='WITHDRAWING' and r.row_version=1 and r.predecessor_epoch=$4
      and r.predecessor_digest=$5 and ($6::uuid is null or r.replacement_id=$6)
      and (openpc.business_cbor(r.successor_scope_cbor)->>'4')::numeric>extract(epoch from clock_timestamp())*1000000000
      and exists(select 1 from jsonb_array_elements(r.candidate->'administrators') admin
        where admin->>'envelopeId'=$7)`,
    [
      scope.participantId,
      scope.privacyDomainId,
      current.platformContextId,
      current.platformAuthorityEpoch,
      Buffer.from(current.platformAuthorityDigest.slice(7), 'hex'),
      replacementId ?? null,
      envelopeId,
    ],
  );
  if (
    rows.rowCount !== 1 ||
    current.ownerParticipantId !== scope.participantId ||
    current.installationPrivacyDomainId !== scope.privacyDomainId
  )
    throw new AuthorityFenceError();
  const row = rows.rows[0]!;
  const parsed = platformScopeReplacementPreparation.safeParse(row.candidate);
  if (!parsed.success) throw new AuthorityFenceError();
  const candidate = parsed.data;
  const administrator = candidate.administrators.find((admin) => admin.envelopeId === envelopeId);
  if (
    !administrator ||
    candidate.replacementId !== row.replacement_id ||
    candidate.platformContextId !== current.platformContextId ||
    candidate.predecessorEpoch !== current.platformAuthorityEpoch ||
    candidate.predecessorDigest !== current.platformAuthorityDigest
  )
    throw new AuthorityFenceError();
  try {
    const admission: PlatformEnvelopeScopeAdmission = {
      platformContextId: current.platformContextId,
      ownerParticipantId: current.ownerParticipantId,
      installationPrivacyDomainId: current.installationPrivacyDomainId,
      platformAuthorityEpoch: (BigInt(current.platformAuthorityEpoch) + 1n).toString(),
      environmentId: current.environmentId,
      installationDigest: current.installationDigest,
      grantable: decodeEnvelopeScope(row.successor_scope_cbor),
    };
    if (!/^[1-9][0-9]{0,19}$/u.test(row.now_ns)) throw new AuthorityFenceError();
    for (const declared of [administrator.usable, administrator.grantable]) {
      assertEnvelopeScopeNarrowing(admission.grantable, declared);
      if (
        BigInt(declared.validFromNs) > BigInt(row.now_ns) ||
        BigInt(declared.validUntilNs) <= BigInt(row.now_ns)
      )
        throw new AuthorityFenceError();
    }
    const source = {
      admission,
      replacementId: row.replacement_id,
      preparationOperationId: row.prepare_operation_id,
      predecessorEpoch: current.platformAuthorityEpoch,
      predecessorDigest: current.platformAuthorityDigest,
    };
    const platformAuthorityDigest = platformEnvelopeScopeSuccessorDigest(source);
    if (
      !isDeepStrictEqual(admission.grantable, candidate.successorScope) ||
      !platformEnvelopeScopeSuccessorPreimage(source).equals(row.successor_preimage) ||
      row.successor_digest.toString('hex') !== platformAuthorityDigest.slice(7)
    )
      throw new AuthorityFenceError();
    return {
      root: { ...admission, platformAuthorityDigest },
      administrator,
      replacementId: row.replacement_id,
    };
  } catch {
    throw new AuthorityFenceError();
  }
}

/** A signed future root binding is usable here only for the exact runtime-free
 * administration declared by the pending transition. General admission always
 * requires the durable current epoch, and cannot use this helper. */
export async function platformScopeForEnvelopeProposal(
  client: PoolClient,
  scope: Pick<EnvelopeGovernanceScope, 'participantId' | 'privacyDomainId'>,
  current: CurrentRoot,
  proposal: EnvelopeProposal,
) {
  if (
    proposal.issuer.platformContextId !== current.platformContextId ||
    current.ownerParticipantId !== scope.participantId
  )
    throw new AuthorityFenceError();
  if (
    proposal.issuer.platformAuthorityEpoch === current.platformAuthorityEpoch &&
    proposal.issuer.platformAuthorityDigest === current.platformAuthorityDigest
  )
    return current;
  const pending = await pendingPlatformAdministrator(client, scope, current, proposal.envelopeId);
  if (
    proposal.participantId !== scope.participantId ||
    proposal.issuance !== 'PLATFORM_ROOT' ||
    proposal.issuer.platformAuthorityEpoch !== pending.root.platformAuthorityEpoch ||
    proposal.issuer.platformAuthorityDigest !== pending.root.platformAuthorityDigest ||
    !isDeepStrictEqual(proposal.usable, pending.administrator.usable) ||
    !isDeepStrictEqual(proposal.grantable, pending.administrator.grantable)
  )
    throw new AuthorityFenceError();
  return pending.root;
}
