import type { PoolClient } from 'pg';
import {
  signingRoleProfiles,
  signingRoleGrantBounds,
} from '../../../../packages/security-kernel/src/signing-roles.js';
import type { ReceiptSigningRotationRequest } from '../domain/signing-rotation.js';

/** Exact predecessor admission only. Current authority, candidate reservation
 * and write fencing remain with the rotation creator. Never grants a profile. */
export async function receiptRotationKey(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string; principalId: string },
  request: ReceiptSigningRotationRequest,
  idempotencyKey: string,
) {
  return client.query<{ trustDigest: Buffer; keyEpoch: string }>(
    `select k.trust_digest as "trustDigest", k.key_epoch::text as "keyEpoch"
      from control.business_signing_key k join control.business_signing_key_state s using(participant_id,privacy_domain_id,signer_id)
      where k.participant_id=$1 and k.privacy_domain_id=$2 and k.signer_id=$3 and k.secret_reference=$4
        and k.environment_id=$5 and k.workload_credential_id=$6 and k.signing_purpose_code=338
        and ((s.state='ACTIVE' and openpc.signing_admission_open($1,$2,$3,openpc.current_operation_id()) and exists(select 1 from control.business_signing_selection selection where selection.participant_id=k.participant_id
          and selection.privacy_domain_id=k.privacy_domain_id and selection.signer_id=k.signer_id and selection.environment_id=k.environment_id))
          or exists(select 1 from control.mutation_candidate c where c.participant_id=k.participant_id
            and c.privacy_domain_id=k.privacy_domain_id and c.maker_principal_id=$7
            and c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1'
            and c.catalog_operation_id='OPS-OP-CREATE-SIGNING-KEY-ROTATION' and c.idempotency_key=$8))
        and (select count(*) from control.business_signing_grant g where g.participant_id=k.participant_id and g.privacy_domain_id=k.privacy_domain_id and g.signer_id=k.signer_id) between $10::integer and $11::integer
        and not exists(select 1 from control.business_signing_grant g join control.business_transition_profile p using(profile_digest)
          where g.participant_id=k.participant_id and g.privacy_domain_id=k.privacy_domain_id and g.signer_id=k.signer_id and not(p.profile_id=any($9::text[])))`,
    [
      scope.participantId,
      scope.privacyDomainId,
      request.oldFingerprint,
      request.oldReference,
      request.environmentId,
      request.workloadCredentialId,
      scope.principalId,
      idempotencyKey,
      signingRoleProfiles[request.signerRole],
      signingRoleGrantBounds[request.signerRole].minimum,
      signingRoleGrantBounds[request.signerRole].maximum,
    ],
  );
}
