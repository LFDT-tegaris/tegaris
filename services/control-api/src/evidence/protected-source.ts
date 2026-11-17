import { decodeIdentityAuthContextAssertionPayload } from '@openpc/security-kernel';
import type { PoolClient } from 'pg';
import type { z } from 'zod';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import {
  identityActorKeyDigest,
  identityMutationAudienceDigest,
} from '../../../identity-service/src/domain/identity-runtime-authorization.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { protectedDisclosure, protectedProofSource } from './protected-contracts.js';

type Scope = { participantId: string; privacyDomainId: string };
interface SourceRow {
  occurrenceId: string;
  operationId: string;
  principalId: string;
  sessionId: string;
  receipt: Buffer;
  receiptDigest: Buffer;
  proofDigest: Buffer;
  occurredAt: string;
  assertion: Buffer;
  signature: Buffer;
  assertionDigest: Buffer;
  candidateDigest: Buffer;
  verificationAt: Date;
}
/** Only the committed WebAuthn owner's original Identity assertion qualifies.
 * Historical verification uses its commit time; the proof supplies no live authority. */
export async function readProtectedProofSource(
  client: PoolClient,
  scope: Scope,
  evidenceId: string,
  verifier: IdentityRuntimeVerifier | undefined,
) {
  if (!verifier) throw new ConfigurationRepositoryError('PC-OPS-9002');
  const rows = await client.query<SourceRow>(
    `select a.occurrence_id::text as "occurrenceId",a.operation_id::text as "operationId",
     a.principal_id::text as "principalId",a.session_id::text as "sessionId",a.receipt,
     a.receipt_digest as "receiptDigest",a.proof_digest as "proofDigest",
     to_char(a.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') as "occurredAt",
     e.evidence_cbor assertion,e.cose_sign1 signature,e.evidence_digest as "assertionDigest",
     e.candidate_digest as "candidateDigest",e.occurred_at as "verificationAt"
     from control.evidence_catalogue c
     join control.authentication_occurrence a on a.participant_id=c.participant_id
      and a.privacy_domain_id=c.privacy_domain_id and a.occurrence_id::text=c.record_id
      and c.evidence_class='AUTHENTICATION' and c.receipt_digest='sha256:'||encode(a.receipt_digest,'hex')
     join control.mutation_evidence e on e.participant_id=a.participant_id and e.privacy_domain_id=a.privacy_domain_id
      and e.operation_id=a.operation_id and e.principal_id=a.principal_id and e.aggregate_id=a.session_id
      and e.mfa_challenge_id=a.source_id and e.signer_credential_id=a.credential_id
      and e.webauthn_assertion_binding_digest=a.proof_digest
      and e.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY' and e.action_intent_id='ACT-IDENTITY_UPDATE_STEP_UP-V1'
      and e.aggregate_type='webauthn-verification'
     join control.idempotency_record i on i.participant_id=e.participant_id and i.privacy_domain_id=e.privacy_domain_id
      and i.operation_id=e.operation_id and i.principal_id=e.principal_id and i.catalog_operation_id=e.catalog_operation_id
      and i.input_digest=e.candidate_digest and i.terminal_state='COMMITTED'
      and i.webauthn_assertion_binding_digest=e.webauthn_assertion_binding_digest
     where c.participant_id=$1 and c.privacy_domain_id=$2 and c.evidence_id=$3 and a.method='WEBAUTHN_ASSERTION'
      and exists(select 1 from control.outbox_event event where event.participant_id=e.participant_id
       and event.privacy_domain_id=e.privacy_domain_id and event.aggregate_type=e.aggregate_type
       and event.aggregate_id=e.aggregate_id and event.event_type='openpc.identity.webauthn-verification.mutation.committed.v1'
       and event.payload_cbor=e.evidence_cbor and event.payload_digest=e.evidence_digest and event.cose_sign1=e.cose_sign1
       and event.webauthn_assertion_binding_digest=e.webauthn_assertion_binding_digest) limit 2`,
    [scope.participantId, scope.privacyDomainId, evidenceId.slice(-36)],
  );
  if (rows.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
  const row = rows.rows[0]!;
  try {
    const occurrence = JSON.parse(row.receipt.toString('utf8')) as Record<string, unknown>;
    const verified = await verifier.verifyCanonicalAssertion(row.assertion, row.signature);
    const assertion = decodeIdentityAuthContextAssertionPayload(row.assertion);
    const committedAt = BigInt(row.verificationAt.getTime()) * 1_000_000n;
    if (
      !verified ||
      sha256(row.assertion) !== `sha256:${row.assertionDigest.toString('hex')}` ||
      sha256(row.receipt) !== `sha256:${row.receiptDigest.toString('hex')}` ||
      !Buffer.from(canonicalJson(occurrence)).equals(row.receipt) ||
      occurrence.version !== 'OPENPC_AUTHENTICATION_OCCURRENCE_V1' ||
      occurrence.method !== 'WEBAUTHN_ASSERTION' ||
      occurrence.participantId !== scope.participantId ||
      occurrence.privacyDomainId !== scope.privacyDomainId ||
      occurrence.occurrenceId !== row.occurrenceId ||
      occurrence.operationId !== row.operationId ||
      occurrence.principalId !== row.principalId ||
      occurrence.occurredAt !== row.occurredAt ||
      occurrence.proofDigest !== `sha256:${row.proofDigest.toString('hex')}` ||
      occurrence.integrity !== 'CONTROL_DATABASE_IMMUTABLE' ||
      occurrence.authorityEffect !== 'NONE' ||
      assertion.actorKind !== 0 ||
      assertion.senderBindingKind !== 1 ||
      !assertion.senderCredentialBindingDigest ||
      !assertion.actorKeyDigest.equals(
        identityActorKeyDigest(scope.participantId, row.principalId),
      ) ||
      !assertion.audienceDigest.equals(
        identityMutationAudienceDigest({
          actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
          catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
          resourceId: row.sessionId,
          candidateDigest: `sha256:${row.candidateDigest.toString('hex')}`,
        }),
      ) ||
      assertion.issuedAtNs > committedAt + 5_000_000_000n ||
      assertion.expiresAtNs <= committedAt ||
      assertion.expiresAtNs <= assertion.issuedAtNs ||
      assertion.expiresAtNs - assertion.issuedAtNs > 60_000_000_000n
    )
      throw new Error('source integrity');
    const source = protectedProofSource.parse({
      evidenceId,
      occurrenceId: row.occurrenceId,
      operationId: row.operationId,
      sourceReceiptDigest: sha256(row.receipt),
      proofDigest: `sha256:${row.proofDigest.toString('hex')}`,
      assertionDigest: sha256(row.assertion),
      signatureDigest: sha256(row.signature),
      signerKeyDigest: `sha256:${verified.signerKeyDigest.toString('hex')}`,
      occurredAt: row.occurredAt,
      materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
      evidenceClass: 'AUTHENTICATION',
      sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
      occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
      proofIntegrity: 'IDENTITY_COSE_ED25519',
      finality: 'NOT_APPLICABLE',
      authorityEffect: 'NONE',
    });
    return {
      source,
      disclosure: protectedDisclosure.parse({
        version: 'OPENPC_PROTECTED_IDENTITY_PROOF_V1',
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        source,
        assertionBase64: row.assertion.toString('base64'),
        coseSign1Base64: row.signature.toString('base64'),
      }),
    };
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  }
}

export function requireExactProofSource(
  expected: z.infer<typeof protectedProofSource>,
  actual: z.infer<typeof protectedProofSource>,
) {
  if (canonicalJson(expected) !== canonicalJson(actual))
    throw new ConfigurationRepositoryError('PC-DATA-6007');
}
