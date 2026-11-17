import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  discoveryCertificateRecoveryIntent,
  discoveryCertificateRotationCandidate,
} from '../contracts/discovery-certificate-recovery.js';
import type { BoundAuthority } from '../db/authority-fence.js';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { IdentityKernelError } from './identity-errors.js';
import type { RecoveryProposalBinding } from './recovery-proposal.js';
import { currentMutationCandidateSql } from '../db/mutation-candidate-fence.js';

const issueCandidate = z.strictObject({
  credentialId: z.uuid(),
  participantId: z.uuid(),
  principalId: z.uuid(),
  workloadId: z.string().regex(/^urn:openpc:workload:[0-9a-f-]{36}$/u),
  publicKeySpkiDer: z.string().min(1).max(4096),
});
const rotateCandidate = z.strictObject({
  replacedCredentialId: z.uuid(),
  credentialId: z.uuid(),
  publicKeySpkiDer: z.string().min(1).max(4096),
});
const revokeCandidate = z.strictObject({ credentialId: z.uuid(), state: z.literal('REVOKED') });
const candidate = z.union([issueCandidate, rotateCandidate, revokeCandidate]);

function bindingSql(binding: RecoveryProposalBinding) {
  return 'approvalRequestId' in binding
    ? { sql: 'a.approval_request_id=$4', values: [binding.approvalRequestId] }
    : {
        sql: `m.expected_revision=$4 and m.maker_principal_id=$5 and ${currentMutationCandidateSql('m')}`,
        values: [binding.expectedRevision, binding.makerPrincipalId],
      };
}

/** Resolve only an opaque resource ID; the caller must fence read authority before projection. */
export async function resolveWorkloadProposal(
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
       and m.catalog_operation_id in ('ID-OP-WORKLOAD-ISSUE','ID-OP-WORKLOAD-ROTATE','ID-OP-WORKLOAD-REVOKE') and ${bound.sql} limit 2`,
    [participantId, privacyDomainId, Buffer.from(candidateDigest.slice(7), 'hex'), ...bound.values],
  );
  if (result.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
  return result.rows[0]!.resource_id;
}

export async function readWorkloadProposal(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  resourceId: string,
  candidateDigest: string,
  binding: RecoveryProposalBinding,
  preapproval?: {
    readonly authority: BoundAuthority;
    readonly recoveryId: string;
    readonly enrollmentId: string;
  },
) {
  if (preapproval) {
    if ('approvalRequestId' in binding) throw new IdentityKernelError('PC-IDENTITY-1008');
    const selected = await client.query<{ intent: unknown }>(
      `select c.intent from control.authority_envelope e join control.platform_recovery_case c
       on c.participant_id=e.participant_id and c.recovery_id=e.recovery_case_id
       where e.participant_id=$1 and e.authority_envelope_id=$2 and e.principal_id=$3
        and e.representation='RECOVERY_V1' and c.privacy_domain_id=$4 and c.state='ACTIVE'
        and c.recovery_id=$5 and c.enrollment_id=$6
        and c.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'
        and openpc.platform_recovery_envelope_current(e.authority_envelope_id)`,
      [
        participantId,
        preapproval.authority.authorityEnvelopeId,
        preapproval.authority.principalId,
        privacyDomainId,
        preapproval.recoveryId,
        preapproval.enrollmentId,
      ],
    );
    if (selected.rowCount !== 1) throw new IdentityKernelError('PC-IDENTITY-1008');
    const intent = discoveryCertificateRecoveryIntent.parse(selected.rows[0]!.intent);
    if (
      binding.makerPrincipalId !== intent.administrators[0].principalId ||
      binding.expectedRevision !== intent.certificateRecovery.predecessorRevision ||
      resourceId !== intent.certificateRecovery.predecessorCredentialId ||
      candidateDigest !==
        canonicalAuthorizationDigest(
          discoveryCertificateRotationCandidate(intent.certificateRecovery),
        )
    )
      throw new IdentityKernelError('PC-IDENTITY-1008');
  }
  const bound = bindingSql(binding);
  const result = await client.query<{
    resource_id: string;
    maker_principal_id: string;
    expected_revision: string;
    state: string;
    expires_at: Date;
    candidate_document: unknown;
    catalog_operation_id: string;
    consumed_operation_id: string | null;
    approval_request_id: string | null;
    reason: string | null;
  }>(
    `select m.resource_id,m.maker_principal_id,m.expected_revision::text,m.state,m.expires_at,m.candidate_document,m.catalog_operation_id,m.consumed_operation_id,a.approval_request_id,a.reason
     from control.mutation_candidate m
     left join control.approval_request a on a.participant_id=m.participant_id and a.privacy_domain_id=m.privacy_domain_id and a.subject_id=m.mutation_candidate_id
     where m.participant_id=$1 and m.privacy_domain_id=$2 and m.candidate_digest=$3
       and m.catalog_operation_id in ('ID-OP-WORKLOAD-ISSUE','ID-OP-WORKLOAD-ROTATE','ID-OP-WORKLOAD-REVOKE') and ${bound.sql} and m.resource_id=$${4 + bound.values.length} for share of m`,
    [
      participantId,
      privacyDomainId,
      Buffer.from(candidateDigest.slice(7), 'hex'),
      ...bound.values,
      resourceId,
    ],
  );
  if (preapproval && result.rowCount === 0) return { preapprovalState: 'ABSENT' as const };
  const row = result.rows[0];
  const parsed = candidate.safeParse(row?.candidate_document);
  if (
    result.rowCount !== 1 ||
    !row ||
    !parsed.success ||
    ('replacedCredentialId' in parsed.data
      ? parsed.data.replacedCredentialId
      : parsed.data.credentialId) !== resourceId ||
    (row.catalog_operation_id === 'ID-OP-WORKLOAD-ISSUE'
      ? !issueCandidate.safeParse(row.candidate_document).success
      : row.catalog_operation_id === 'ID-OP-WORKLOAD-ROTATE'
        ? !rotateCandidate.safeParse(row.candidate_document).success
        : !revokeCandidate.safeParse(row.candidate_document).success)
  )
    throw new IdentityKernelError('PC-IDENTITY-1008');
  const proposal = {
    candidateDigest,
    resourceId,
    makerPrincipalId: row.maker_principal_id,
    catalogOperationId: row.catalog_operation_id,
    expectedRevision: row.expected_revision,
    state: row.state,
    operationId: row.consumed_operation_id,
    expiresAt: row.expires_at.toISOString(),
    candidate: parsed.data,
    ...(row.approval_request_id
      ? { approval: { approvalRequestId: row.approval_request_id, reason: row.reason } }
      : {}),
  };
  return preapproval ? { preapprovalState: 'PRESENT' as const, proposal } : proposal;
}

/** Public certificate bytes are delivered only after the caller fences exact resource authority. */
export async function readWorkloadCertificate(
  client: PoolClient,
  participantId: string,
  credentialId: string,
) {
  const result = await client.query<{
    credential_id: string;
    principal_id: string;
    audience: string;
    state: string;
    credential_epoch: string;
    row_version: string;
    certificate_der: Buffer | null;
    public_key_digest: Buffer;
    secret_fingerprint: Buffer;
    subject: string;
    issuer: string;
    valid_from: Date;
    valid_until: Date;
    rotated_from_credential_id: string | null;
  }>(
    `select credential_id,principal_id,audience,state,credential_epoch::text,row_version::text,
     certificate_der,public_key_digest,secret_fingerprint,subject,issuer,valid_from,valid_until,rotated_from_credential_id
     from control.credential where participant_id=$1 and credential_id=$2 and kind='WORKLOAD_MTLS' for share`,
    [participantId, credentialId],
  );
  const row = result.rows[0];
  if (!row) throw new IdentityKernelError('PC-IDENTITY-1008');
  return {
    credentialId: row.credential_id,
    participantId,
    principalId: row.principal_id,
    workloadId: row.audience,
    state: row.state,
    workloadEpoch: row.credential_epoch,
    revision: row.row_version,
    certificateDer: row.certificate_der?.toString('base64') ?? null,
    keyId: `sha256:${row.public_key_digest.toString('hex')}`,
    certificateFingerprint: `sha256:${row.secret_fingerprint.toString('hex')}`,
    uriSan: row.subject,
    issuer: row.issuer,
    notBefore: row.valid_from.toISOString(),
    notAfter: row.valid_until.toISOString(),
    rotateAt: new Date(row.valid_from.getTime() + 12 * 60 * 60 * 1000).toISOString(),
    replacedCredentialId: row.rotated_from_credential_id,
  };
}
