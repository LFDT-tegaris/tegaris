import type { PoolClient } from 'pg';
import { canonicalAuthorizationDigestBytes } from '../contracts/authorization.js';
import {
  governedInitialEnrollmentEvidenceSchema,
  verifyGovernedInitialEnrollmentReceipt,
  type GovernedInitialEnrollmentEvidence,
} from '../domain/governed-initial-enrollment.js';
import type { IdentityRuntimeAssertionVerifier } from '../domain/identity-kernel.js';
import type { SignedIdentityRuntimeAssertion } from '../domain/identity-runtime-crypto.js';
import { IdentityKernelError } from '../domain/identity-errors.js';

/** Read the stored preimage, never reconstruct historical facts from mutable
 * session deadlines. The caller establishes the authenticated subject/scope. */
export async function readGovernedInitialEnrollmentResult(
  client: PoolClient,
  participantId: string,
  principalId: string,
  enrollmentId: string,
  verifier: IdentityRuntimeAssertionVerifier,
): Promise<GovernedInitialEnrollmentEvidence> {
  const result = await client.query<{
    document: unknown;
    document_digest: Buffer;
    evidence_cbor: Buffer;
    cose_sign1: Buffer;
  }>(
    `select result.document,result.document_digest,result.evidence_cbor,result.cose_sign1
     from control.governed_initial_enrollment_result result
     join control.outbox_event event on event.participant_id=result.participant_id
       and event.privacy_domain_id=result.privacy_domain_id and event.event_id=result.event_id
       and event.aggregate_type='credential' and event.aggregate_id=result.credential_id
       and event.event_type='openpc.identity.webauthn.governed-initial-enrollment.completed.v1'
       and event.payload_cbor=result.evidence_cbor and event.payload_digest=result.evidence_digest
       and event.cose_sign1=result.cose_sign1
     where result.participant_id=$1 and result.principal_id=$2 and result.enrollment_id=$3`,
    [participantId, principalId, enrollmentId],
  );
  const row = result.rows[0];
  if (result.rowCount !== 1 || !row) throw new IdentityKernelError('PC-IDENTITY-1004');
  const value = governedInitialEnrollmentEvidenceSchema.parse(row.document);
  if (
    value.account.participantId !== participantId ||
    value.account.principalId !== principalId ||
    value.enrollmentId !== enrollmentId ||
    !canonicalAuthorizationDigestBytes(value).equals(row.document_digest) ||
    !(await verifyGovernedInitialEnrollmentReceipt(
      verifier,
      value,
      row.evidence_cbor,
      row.cose_sign1,
    ))
  )
    throw new IdentityKernelError('PC-IDENTITY-1004');
  return value;
}

export async function saveGovernedInitialEnrollmentResult(
  client: PoolClient,
  input: GovernedInitialEnrollmentEvidence,
  eventId: string,
  signed: SignedIdentityRuntimeAssertion,
  verifier: IdentityRuntimeAssertionVerifier,
): Promise<void> {
  const value = governedInitialEnrollmentEvidenceSchema.parse(input);
  if (
    !(await verifyGovernedInitialEnrollmentReceipt(
      verifier,
      value,
      signed.evidenceCbor,
      signed.coseSign1,
    ))
  )
    throw new IdentityKernelError('PC-IDENTITY-1004');
  await client.query(
    `insert into control.governed_initial_enrollment_result
     (operation_id,participant_id,privacy_domain_id,principal_id,session_id,enrollment_id,credential_id,
      profile_digest,event_id,document,document_digest,evidence_cbor,evidence_digest,cose_sign1,committed_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15)`,
    [
      value.operationId,
      value.account.participantId,
      value.account.privacyDomainId,
      value.account.principalId,
      value.sessionId,
      value.enrollmentId,
      value.authenticatorCredentialId,
      Buffer.from(value.profileDigest.slice(7), 'hex'),
      eventId,
      JSON.stringify(value),
      canonicalAuthorizationDigestBytes(value),
      signed.evidenceCbor,
      signed.evidenceDigest,
      signed.coseSign1,
      value.committedAt,
    ],
  );
  await readGovernedInitialEnrollmentResult(
    client,
    value.account.participantId,
    value.account.principalId,
    value.enrollmentId,
    verifier,
  );
}
