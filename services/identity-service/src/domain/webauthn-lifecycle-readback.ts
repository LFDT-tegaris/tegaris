import type { PoolClient } from 'pg';
import { z } from 'zod';
import { IdentityKernelError } from './identity-errors.js';
import type { RecoveryProposalBinding } from './recovery-proposal.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const candidate = z.strictObject({
  enrollmentId: z.uuid(),
  replacedCredentialId: z.uuid(),
  externalCredentialId: z.string().min(1).max(2048),
  publicKeyDigest: digest,
  publicKeySpkiDer: z.string().min(1).max(16384),
  signCount: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  attestationDigest: digest,
  hardwareAttestation: z
    .strictObject({
      profileId: z.string().min(1).max(160),
      profileDigest: digest,
      aaguid: z.uuid(),
      attestationDigest: digest,
    })
    .optional(),
});

function bindingSql(binding: RecoveryProposalBinding) {
  return 'approvalRequestId' in binding
    ? { sql: 'a.approval_request_id=$4', values: [binding.approvalRequestId] }
    : {
        sql: 'm.expected_revision=$4 and m.maker_principal_id=$5',
        values: [binding.expectedRevision, binding.makerPrincipalId],
      };
}

/** Resolve only an opaque resource ID; the caller must fence read authority before projection. */
export async function resolveWebAuthnProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  candidateDigest: string,
  binding: RecoveryProposalBinding,
) {
  const bound = bindingSql(binding);
  const result = await client.query<{ resource_id: string }>(
    `select distinct m.resource_id from control.mutation_candidate m
     left join control.approval_request a on a.participant_id=m.participant_id and a.privacy_domain_id=m.privacy_domain_id and a.subject_id=m.mutation_candidate_id
     where m.participant_id=$1 and m.privacy_domain_id=$2 and m.candidate_digest=$3
       and m.catalog_operation_id='ID-OP-WEBAUTHN-REGISTER' and ${bound.sql} limit 2`,
    [participantId, privacyDomainId, Buffer.from(candidateDigest.slice(7), 'hex'), ...bound.values],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return result.rows[0]!.resource_id;
}

export async function readWebAuthnProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  resourceId: string,
  candidateDigest: string,
  binding: RecoveryProposalBinding,
) {
  const bound = bindingSql(binding);
  const result = await client.query<{
    resource_id: string;
    maker_principal_id: string;
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: unknown;
    approval_request_id: string | null;
    reason: string | null;
  }>(
    `select m.resource_id,m.maker_principal_id,m.expected_revision::text,m.state,m.expires_at,m.candidate_document,a.approval_request_id,a.reason
     from control.mutation_candidate m
     left join control.approval_request a on a.participant_id=m.participant_id and a.privacy_domain_id=m.privacy_domain_id and a.subject_id=m.mutation_candidate_id
     where m.participant_id=$1 and m.privacy_domain_id=$2 and m.candidate_digest=$3
       and m.catalog_operation_id='ID-OP-WEBAUTHN-REGISTER' and ${bound.sql} and m.resource_id=$${4 + bound.values.length} for share of m`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(candidateDigest.slice(7), 'hex'),
      ...bound.values,
      resourceId,
    ],
  );
  const row = result.rows[0];
  const parsed = candidate.safeParse(row?.candidate_document);
  if (
    result.rowCount !== 1 ||
    !row ||
    !parsed.success ||
    parsed.data.replacedCredentialId !== resourceId
  )
    throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    candidateDigest,
    resourceId,
    makerPrincipalId: row.maker_principal_id,
    catalogOperationId: 'ID-OP-WEBAUTHN-REGISTER' as const,
    expectedRevision: row.expected_revision,
    state: row.state,
    expiresAt: row.expires_at.toISOString(),
    candidate: parsed.data,
    ...(row.approval_request_id
      ? { approval: { approvalRequestId: row.approval_request_id, reason: row.reason } }
      : {}),
  };
}

/** Own-account inventory deliberately excludes attestation bytes and key material. */
export async function readWebAuthnCredentials(
  client: PoolClient,
  participantId: string,
  principalId: string,
  cursor?: string,
) {
  const result = await client.query<{
    credential_id: string;
    state: string;
    credential_epoch: string;
    row_version: string;
    issuer: string | null;
    active: boolean;
    rotated_from_credential_id: string | null;
  }>(
    `select credential_id,state,credential_epoch::text,row_version::text,issuer,rotated_from_credential_id,
       state='ACTIVE' and valid_from<=clock_timestamp() and (valid_until is null or valid_until>clock_timestamp()) as active
     from control.credential where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN'
       and ($3::uuid is null or credential_id>$3::uuid) order by credential_id limit 51`,
    [participantId, principalId, cursor ?? null],
  );
  const rows = result.rows.slice(0, 50);
  return {
    participantId,
    principalId,
    items: rows.map((row) => ({
      credentialId: row.credential_id,
      state: row.state,
      credentialEpoch: row.credential_epoch,
      revision: row.credential_epoch,
      issuer: row.issuer,
      active: row.active,
      replacedCredentialId: row.rotated_from_credential_id,
    })),
    nextCursor: result.rows.length > 50 ? rows.at(-1)!.credential_id : null,
  };
}
