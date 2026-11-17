import type { PoolClient } from 'pg';
import { localOperationId } from '../domain/local-operation-id.js';
import { IdentityKernelError } from '../domain/identity-errors.js';

/** The private Identity transaction supplies verified protocol inputs. This
 * receipt is an immutable database occurrence, not a signed authority assertion.
 * No token, challenge, assertion bytes, password or external subject is stored.
 */
export async function appendAuthenticationOccurrence(
  client: PoolClient,
  input: {
    sessionId: string;
    operationId: string;
    method: 'OIDC_CODE_PKCE_S256' | 'WEBAUTHN_ASSERTION';
    sourceId: string;
    credentialId: string;
    proofDigest: Buffer;
    occurredAt: Date;
  },
) {
  await client.query('set local synchronous_commit=on');
  const webAuthn = input.method === 'WEBAUTHN_ASSERTION';
  // Platform login remains independent of MFA table read permissions. Only
  // the original WebAuthn owner copies its PostgreSQL verification timestamp.
  const occurredAt = webAuthn
    ? "case when $3::text='WEBAUTHN_ASSERTION' then challenge.consumed_at else $7::timestamptz end"
    : '$7::timestamptz';
  const source = webAuthn
    ? `join control.mfa_challenge challenge on challenge.participant_id=s.participant_id
         and challenge.session_id=s.session_id and challenge.principal_id=s.principal_id
         and challenge.mfa_challenge_id=$4::uuid and challenge.signer_credential_id=$5::uuid
         and challenge.mfa_challenge_id=s.step_up_mfa_challenge_id
         and challenge.consumed_at=s.step_up_verified_at and challenge.consumed_at is not null`
    : '';
  const result = await client.query(
    `with occurrence as (
       select $1::uuid occurrence_id,s.participant_id,coalesce(s.privacy_domain_id,p.root_privacy_domain_id) privacy_domain_id,
         s.principal_id,s.session_id,$2::uuid operation_id,$3::text method,$4::uuid source_id,$5::uuid credential_id,
         s.context_mode::text context_mode,$6::bytea proof_digest,${occurredAt} occurred_at
       from control.session s join control.participant p using(participant_id)
       ${source}
       where s.session_id=$8 and s.state='ACTIVE' and p.state='ACTIVE'
     ), encoded as (
       select o.*,openpc.authentication_occurrence_receipt(o.occurrence_id,o.participant_id,o.privacy_domain_id,
         o.principal_id,o.session_id,o.operation_id,o.method,o.source_id,o.credential_id,o.context_mode,
         o.proof_digest,o.occurred_at) receipt from occurrence o
     ) insert into control.authentication_occurrence
       (occurrence_id,participant_id,privacy_domain_id,principal_id,session_id,operation_id,method,source_id,
        credential_id,context_mode,proof_digest,occurred_at,receipt,receipt_digest)
       select occurrence_id,participant_id,privacy_domain_id,principal_id,session_id,operation_id,method,source_id,
        credential_id,context_mode,proof_digest,occurred_at,receipt,sha256(receipt) from encoded`,
    [
      localOperationId(),
      input.operationId,
      input.method,
      input.sourceId,
      input.credentialId,
      input.proofDigest,
      input.occurredAt,
      input.sessionId,
    ],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1004');
}

export async function oidcAuthenticationProofDigest(
  client: PoolClient,
  transactionId: string,
  credentialId: string,
) {
  const result = await client.query<{ digest: Buffer }>(
    `select sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
      'version','OPENPC_OIDC_VERIFIED_V1','sourceId',transaction_id::text,'credentialId',$2::text,
      'stateDigest',encode(state_digest,'hex'),'nonceDigest',encode(nonce_digest,'hex'),
      'pkceDigest',encode(code_verifier_digest,'hex'),'browserDigest',encode(browser_session_digest,'hex')
    )),'UTF8')) digest from control.oidc_transaction where transaction_id=$1 and consumed_at is not null`,
    [transactionId, credentialId],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1004');
  return result.rows[0]!.digest;
}

/** The caller supplies a consumed in-process proof from the verified TLS
 * transport. Credential last_used_at and scope are read back inside its locked
 * revalidation transaction; a failed occurrence prevents authentication success.
 */
export async function appendWorkloadAuthenticationOccurrence(
  client: PoolClient,
  input: { credentialId: string; operationId: string; proofDigest: Buffer },
) {
  await client.query('set local synchronous_commit=on');
  const result = await client.query(
    `with occurrence as (
      select $1::uuid occurrence_id,c.participant_id,
        coalesce(nullif(current_setting('openpc.privacy_domain_id',true),'')::uuid,p.root_privacy_domain_id) privacy_domain_id,
        c.principal_id,$2::uuid operation_id,c.credential_id,c.last_used_at occurred_at,$3::bytea proof_digest
      from control.credential c join control.participant p using(participant_id)
      where c.credential_id=$4 and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and p.state='ACTIVE'
    ), encoded as (
      select o.*,openpc.authentication_occurrence_receipt(o.occurrence_id,o.participant_id,o.privacy_domain_id,
        o.principal_id,null,o.operation_id,'TLS13_MTLS',o.operation_id,o.credential_id,'WORKLOAD',
        o.proof_digest,o.occurred_at) receipt from occurrence o
    ) insert into control.authentication_occurrence
      (occurrence_id,participant_id,privacy_domain_id,principal_id,session_id,operation_id,method,source_id,
       credential_id,context_mode,proof_digest,occurred_at,receipt,receipt_digest)
      select occurrence_id,participant_id,privacy_domain_id,principal_id,null,operation_id,'TLS13_MTLS',operation_id,
       credential_id,'WORKLOAD',proof_digest,occurred_at,receipt,sha256(receipt) from encoded`,
    [localOperationId(), input.operationId, input.proofDigest, input.credentialId],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1006');
}
