import type { PoolClient } from 'pg';
import {
  decodeEnvelopeScope,
  platformEnvelopeScopeExpiryRecoveryPreimage,
  platformEnvelopeScopeExpiryRecoveryDigest,
  platformEnvelopeScopeDigest,
  platformEnvelopeScopePreimage,
  platformEnvelopeScopeSuccessorDigest,
  platformEnvelopeScopeSuccessorPreimage,
  type PlatformEnvelopeScopeAdmission,
} from '../../../../packages/security-kernel/src/index.js';
import { AuthorityFenceError } from './authority-fence.js';
import { fenceEnvelopePlatformContext } from './platform-context.js';

/** The caller must hold the selected current grant path's Participant fences.
 * This returns the installed upper bound, never an actor permission. Neither a
 * caller-supplied Platform id nor a legacy envelope can select a substitute. */
export async function fenceEnvelopePlatformScope(
  client: PoolClient,
  participantId: string,
  selectedEnvelopeId: string,
) {
  const root = await fenceEnvelopePlatformContext(client, participantId, selectedEnvelopeId);
  if (!root) throw new AuthorityFenceError();
  return readCurrentPlatformScope(client, root.platformContextId, root.platformAuthorityEpoch);
}

/** Selection follows the durable current epoch. A prepared replacement is not
 * an effective ceiling; no caller may select a successor epoch or its digest.
 * This helper grants no permission: callers must hold their real actor fences. */
export async function readCurrentPlatformScope(
  client: PoolClient,
  platformContextId: string,
  expectedEpoch?: string,
) {
  const result = await client.query<{
    platform_context_id: string;
    owner_participant_id: string;
    installation_privacy_domain_id: string;
    platform_authority_epoch: string;
    environment_id: string;
    installation_digest: string;
    scope_cbor: Buffer;
    admission_preimage: Buffer;
    admission_digest: Buffer;
    recovery_id: string | null;
    enrollment_digest: Buffer | null;
    intent_digest: Buffer | null;
    replacement_id: string | null;
    prepare_operation_id: string | null;
    predecessor_epoch: string | null;
    predecessor_digest: Buffer | null;
  }>(
    `select s.* from openpc.lock_platform_scope_context($1) p join (
      select platform_context_id,owner_participant_id,installation_privacy_domain_id,
        platform_authority_epoch,environment_id,installation_digest,scope_cbor,admission_preimage,admission_digest,
        null::uuid as replacement_id,null::uuid as prepare_operation_id,
        null::numeric as predecessor_epoch,null::bytea as predecessor_digest,
        null::uuid as recovery_id,null::bytea as enrollment_digest,null::bytea as intent_digest
      from control.platform_envelope_scope
      union all
      select s.platform_context_id,s.owner_participant_id,s.installation_privacy_domain_id,
        s.platform_authority_epoch,s.environment_id,s.installation_digest,s.scope_cbor,s.admission_preimage,s.admission_digest,
        s.replacement_id,s.preparation_operation_id,s.predecessor_epoch,s.predecessor_digest,
        null::uuid,null::bytea,null::bytea
      from control.platform_envelope_scope_successor s
      union all select s.platform_context_id,s.owner_participant_id,s.installation_privacy_domain_id,
        s.platform_authority_epoch,s.environment_id,s.installation_digest,s.scope_cbor,s.admission_preimage,s.admission_digest,
        null::uuid,s.activation_operation_id,s.predecessor_epoch,s.predecessor_digest,s.recovery_id,s.enrollment_digest,s.intent_digest
      from control.root_expiry_recovery_scope s
     ) s on s.platform_context_id=p.platform_context_id and s.owner_participant_id=p.owner_participant_id
      and s.platform_authority_epoch=p.authority_epoch
     where p.platform_context_id=$1 and p.state='ACTIVE'
      and ($2::numeric is null or p.authority_epoch=$2)`,
    [platformContextId, expectedEpoch ?? null],
  );
  if (result.rowCount !== 1) throw new AuthorityFenceError();
  const row = result.rows[0]!;
  if (
    row.platform_context_id !== platformContextId ||
    (expectedEpoch !== undefined && String(row.platform_authority_epoch) !== expectedEpoch)
  )
    throw new AuthorityFenceError();
  try {
    const admission: PlatformEnvelopeScopeAdmission = {
      platformContextId: row.platform_context_id,
      ownerParticipantId: row.owner_participant_id,
      installationPrivacyDomainId: row.installation_privacy_domain_id,
      platformAuthorityEpoch: String(row.platform_authority_epoch),
      environmentId: row.environment_id,
      installationDigest: row.installation_digest,
      grantable: decodeEnvelopeScope(row.scope_cbor),
    };
    const successor =
      row.replacement_id === null
        ? null
        : {
            admission,
            replacementId: row.replacement_id,
            preparationOperationId: row.prepare_operation_id!,
            predecessorEpoch: String(row.predecessor_epoch),
            predecessorDigest: `sha256:${row.predecessor_digest!.toString('hex')}`,
          };
    const recovery =
      row.recovery_id === null || row.recovery_id === undefined
        ? null
        : {
            admission,
            recoveryId: row.recovery_id,
            activationOperationId: row.prepare_operation_id!,
            enrollmentDigest: `sha256:${row.enrollment_digest!.toString('hex')}`,
            intentDigest: `sha256:${row.intent_digest!.toString('hex')}`,
            predecessorEpoch: String(row.predecessor_epoch),
            predecessorDigest: `sha256:${row.predecessor_digest!.toString('hex')}`,
          };
    if (
      (admission.platformAuthorityEpoch === '1') !== (successor === null && recovery === null) ||
      (successor !== null && recovery !== null)
    )
      throw new AuthorityFenceError();
    const platformAuthorityDigest =
      recovery !== null
        ? platformEnvelopeScopeExpiryRecoveryDigest(recovery)
        : successor === null
          ? platformEnvelopeScopeDigest(admission)
          : platformEnvelopeScopeSuccessorDigest(successor);
    const preimage =
      recovery !== null
        ? platformEnvelopeScopeExpiryRecoveryPreimage(recovery)
        : successor === null
          ? platformEnvelopeScopePreimage(admission)
          : platformEnvelopeScopeSuccessorPreimage(successor);
    if (
      !preimage.equals(row.admission_preimage) ||
      row.admission_digest.toString('hex') !== platformAuthorityDigest.slice(7)
    )
      throw new AuthorityFenceError();
    return { ...admission, platformAuthorityDigest };
  } catch {
    throw new AuthorityFenceError();
  }
}
