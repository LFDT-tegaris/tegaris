import type { PoolClient } from 'pg';
import {
  captureDurableAuthorities,
  fenceDurableAuthorities,
  type BoundAuthority,
  type DurableAuthority,
  type MutationAuthorityContext,
} from '../db/authority-fence.js';
import { IdentityKernelError } from './identity-errors.js';

interface Signer {
  readonly principalId: string;
  readonly credentialId: string;
  readonly credentialEpoch: string;
}

export interface InvitationAuthority {
  readonly version: 1;
  readonly operationId: string;
  readonly approvalRequestId: string;
  readonly candidateDigest: string;
  readonly authorities: readonly DurableAuthority[];
  readonly signers: readonly [Signer, Signer];
}

async function signer(
  client: PoolClient,
  participantId: string,
  principalId: string,
  credentialId: string | undefined,
): Promise<Signer> {
  if (!credentialId) throw new IdentityKernelError('PC-IDENTITY-1005');
  const selected = await client.query<{ credential_epoch: string }>(
    `select credential_epoch::text from control.credential
      where participant_id=$1 and principal_id=$2 and credential_id=$3 and state='ACTIVE' and kind='WEBAUTHN'
        and valid_from<=clock_timestamp() and (valid_until is null or valid_until>clock_timestamp())`,
    [participantId, principalId, credentialId],
  );
  if (selected.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1005');
  return { principalId, credentialId, credentialEpoch: selected.rows[0]!.credential_epoch };
}

/** Sessions authorize issuance. The captured exact grant paths authorize later redemption. */
export async function captureInvitationAuthority(
  client: PoolClient,
  participantId: string,
  input: MutationAuthorityContext & {
    readonly roleAuthority: BoundAuthority;
    readonly operationId: string;
    readonly approvalRequestId: string;
    readonly candidateDigest: string;
  },
): Promise<InvitationAuthority> {
  const checker = input.approvalAuthorities[1];
  if (
    input.approvalAuthorities.length !== 2 ||
    !checker ||
    checker.principalId === input.makerAuthority.principalId ||
    input.approvalAuthorities[0]!.principalId !== input.makerAuthority.principalId
  )
    throw new IdentityKernelError('PC-IDENTITY-1005');
  return {
    version: 1,
    operationId: input.operationId,
    approvalRequestId: input.approvalRequestId,
    candidateDigest: input.candidateDigest,
    authorities: await captureDurableAuthorities(client, participantId, [
      input.makerAuthority,
      ...input.approvalAuthorities,
      input.roleAuthority,
    ]),
    signers: [
      await signer(
        client,
        participantId,
        input.makerAuthority.principalId,
        input.makerSignerCredentialId,
      ),
      await signer(client, participantId, checker.principalId, input.checkerSignerCredentialId),
    ],
  };
}

/** Historical tokens without issuance provenance fail closed and need governed renewal. */
export async function fenceInvitationAuthority(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  operationId: string,
  value: InvitationAuthority | null,
): Promise<void> {
  if (
    !value ||
    value.version !== 1 ||
    value.operationId !== operationId ||
    value.authorities.length !== 4 ||
    value.signers.length !== 2 ||
    value.signers[0].principalId === value.signers[1].principalId ||
    value.authorities.some((entry) => entry.grant.privacyDomainId !== privacyDomainId)
  )
    throw new IdentityKernelError('PC-IDENTITY-1005');
  await fenceDurableAuthorities(client, participantId, value.authorities, {
    participant: [{ id: participantId, write: true }],
    credential: value.signers.map((entry) => ({ id: entry.credentialId })),
  });
  for (const expected of value.signers) {
    const current = await signer(
      client,
      participantId,
      expected.principalId,
      expected.credentialId,
    );
    if (current.credentialEpoch !== expected.credentialEpoch)
      throw new IdentityKernelError('PC-IDENTITY-1005');
  }
  // Expiry of consumed staging approval and browser sessions is intentionally irrelevant.
  const committed = await client.query(
    `select 1 from control.mutation_candidate candidate
      join control.approval_request approval on approval.participant_id=candidate.participant_id
        and approval.privacy_domain_id=candidate.privacy_domain_id and approval.subject_id=candidate.mutation_candidate_id
        and approval.subject_digest=candidate.candidate_digest
      join control.mutation_evidence evidence on evidence.participant_id=candidate.participant_id
        and evidence.privacy_domain_id=candidate.privacy_domain_id and evidence.operation_id=candidate.consumed_operation_id
        and evidence.candidate_digest=candidate.candidate_digest and evidence.approval_request_id=approval.approval_request_id
      where candidate.participant_id=$1 and candidate.privacy_domain_id=$2 and candidate.consumed_operation_id=$3
        and candidate.candidate_digest=$4 and candidate.state='CONSUMED' and approval.approval_request_id=$5
        and candidate.catalog_operation_id in ('ID-OP-INVITATION-CREATE','ID-OP-INVITATION-RESEND')`,
    [
      participantId,
      privacyDomainId,
      operationId,
      Buffer.from(value.candidateDigest.slice(7), 'hex'),
      value.approvalRequestId,
    ],
  );
  if (committed.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1005');
}
