import type { PoolClient } from 'pg';
import {
  verifyInstalledFactConsumerProfile,
  type FactConsumerProfile,
} from '@openpc/security-kernel';
import {
  decodeFactConsumerFailure,
  type FactConsumerFailure,
} from '../../../../packages/security-kernel/src/fact-consumer/failure.js';
import { verifyFactConsumerFailureSignature } from '../../../../packages/security-kernel/src/fact-consumer/failure-cose.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { EvidenceCustodyError, type EvidenceScope, type SourceReceipt } from './segment.js';

export const FACT_FAILURE_FORMAT = 'COSE_SIGN1_24007_1_344';
export interface FactFailureSourceRow {
  claims: FactConsumerFailure;
  payload: Buffer;
  cose: Buffer;
  receiptId: string;
  receiptDigest: string;
  outboxDigest: string | null;
  workItemId: string;
  material: Buffer;
  materialDigest: Buffer;
  eventId: string;
  candidateId: string;
  generationId: string;
  factType: string;
  sequence: string;
  initialProfileDigest: string;
  failedAttempts: number;
  maximumAttempts: number;
  leaseGeneration: string;
  historyValid: boolean;
  committedAtMs: string;
  signerKeyId: string;
  signerSpki: Buffer;
  signerEnvironment: string;
  signerRole: string;
  signerPurpose: string;
  signerDatabaseRole: string;
  signerCredentialId: string;
  signerCredentialEpoch: string;
  signerValidFrom: string;
  signerValidUntil: string;
  profile: FactConsumerProfile;
  profilePayload: Buffer;
  profileCose: Buffer;
  profileIssuer: Buffer;
}

/** Historical verification only. Revocation blocks new signing at the source;
 * it does not erase an already committed receipt or authorize a Fact delivery. */
export function verifyFactFailureSource(row: FactFailureSourceRow, scope: EvidenceScope) {
  try {
    const receipt = decodeFactConsumerFailure(row.payload);
    const profile = verifyInstalledFactConsumerProfile(
      {
        ...row.profile,
        issuerSpkiDer: row.profileIssuer,
        signedProfileDigest: receipt.currentProfileDigest,
      },
      row.profilePayload,
      row.profileCose,
      receipt.recordedAtMs,
    );
    const material = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(row.material));
    const expected = {
      participantId: receipt.participantId,
      privacyDomainId: receipt.privacyDomainId,
      eventId: receipt.eventId,
      candidateId: receipt.candidateId,
      generationId: receipt.generationId,
      factType: receipt.factType,
      sequence: receipt.sequence,
      consumerId: receipt.consumerId,
      envelope: material.envelope,
      envelopeDigest: receipt.envelopeDigest,
      dataDigest: receipt.dataDigest,
    };
    if (
      canonicalJson(receipt) !== canonicalJson(row.claims) ||
      receipt.participantId !== scope.participantId ||
      receipt.privacyDomainId !== scope.privacyDomainId ||
      receipt.consumerId !== 'LS-FLEET-CONTROL' ||
      receipt.receiptId !== row.receiptId ||
      receipt.workItemId !== row.workItemId ||
      receipt.eventId !== row.eventId ||
      receipt.candidateId !== row.candidateId ||
      receipt.generationId !== row.generationId ||
      receipt.factType !== row.factType ||
      receipt.sequence !== row.sequence ||
      receipt.initialProfileDigest !== row.initialProfileDigest ||
      receipt.failedAttempts !== row.failedAttempts ||
      receipt.maximumAttempts !== row.maximumAttempts ||
      receipt.leaseGeneration !== row.leaseGeneration ||
      row.historyValid !== true ||
      row.material.toString('utf8') !== canonicalJson(expected) ||
      sha256(material.envelope) !== receipt.envelopeDigest ||
      sha256(row.material) !== receipt.materialDigest ||
      receipt.materialDigest !== `sha256:${row.materialDigest.toString('hex')}` ||
      sha256(row.cose) !== row.receiptDigest ||
      row.outboxDigest !== row.receiptDigest ||
      receipt.signerKeyId !== row.signerKeyId ||
      !verifyFactConsumerFailureSignature(row.signerSpki, row.payload, row.cose) ||
      row.signerEnvironment !== receipt.environmentId ||
      row.signerRole !== 'FACT_CONSUMER_FAILURE' ||
      row.signerPurpose !== '344' ||
      row.signerCredentialId !== receipt.workloadCredentialId ||
      row.signerCredentialEpoch !== receipt.workloadCredentialEpoch ||
      BigInt(row.signerValidFrom) > BigInt(receipt.recordedAtMs) ||
      BigInt(row.signerValidUntil) <= BigInt(row.committedAtMs) ||
      BigInt(row.committedAtMs) < BigInt(receipt.recordedAtMs) ||
      BigInt(row.committedAtMs) >= BigInt(profile.validUntilMs) ||
      profile.participantId !== receipt.participantId ||
      profile.privacyDomainId !== receipt.privacyDomainId ||
      profile.environmentId !== receipt.environmentId ||
      profile.consumerId !== receipt.consumerId ||
      profile.workloadCredentialId !== receipt.workloadCredentialId ||
      profile.workloadCredentialEpoch !== receipt.workloadCredentialEpoch ||
      profile.databaseRole !== row.signerDatabaseRole ||
      row.profileIssuer.equals(row.signerSpki)
    )
      throw new Error();
    return {
      recordId: receipt.receiptId,
      evidenceClass: 'EFFECT',
      sourceFormat: FACT_FAILURE_FORMAT,
      occurredAt: new Date(receipt.recordedAtMs).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z'),
      receiptDigest: row.receiptDigest,
      receiptBase64: row.cose.toString('base64'),
    } satisfies SourceReceipt;
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
}

/** Select only source-owned committed failures. LEFT JOINs make missing linked
 * trust/outbox/history fail verification rather than silently disappearing. The
 * immutable source/outbox remain retained after encrypted custody and export. */
export async function readFactFailureEvidenceSources(
  client: PoolClient,
  scope: EvidenceScope,
): Promise<SourceReceipt[]> {
  const result = await client.query<FactFailureSourceRow>(
    `select q.claims,q.payload,q.cose,q.receipt_id::text as "receiptId",q.receipt_digest as "receiptDigest",
     o.receipt_digest as "outboxDigest",q.work_item_id::text as "workItemId",
     d.material,q.material_digest as "materialDigest",d.event_id::text as "eventId",
     d.candidate_id::text as "candidateId",d.generation_id::text as "generationId",d.fact_type as "factType",
     d.sequence::text,d.initial_profile_digest as "initialProfileDigest",d.failed_attempts as "failedAttempts",
     d.maximum_attempts as "maximumAttempts",d.lease_generation::text as "leaseGeneration",
     (d.state='QUARANTINED' and d.last_problem='PC-DATA-6005' and d.lease_id is null
      and d.material_digest=q.material_digest
      and (select count(*) from control.fleet_fact_delivery_attempt a where a.participant_id=d.participant_id
       and a.privacy_domain_id=d.privacy_domain_id and a.event_id=d.event_id)=d.lease_generation
      and (select count(*) from control.fleet_fact_delivery_attempt a where a.participant_id=d.participant_id
       and a.privacy_domain_id=d.privacy_domain_id and a.event_id=d.event_id
       and a.outcome in ('FAILED','LEASE_EXPIRED'))=d.failed_attempts
      and not exists(select 1 from control.fleet_fact_delivery_attempt a where a.participant_id=d.participant_id
       and a.privacy_domain_id=d.privacy_domain_id and a.event_id=d.event_id and a.outcome in ('ACTIVE','COMMITTED'))
     ) as "historyValid",q.committed_at_ms::text as "committedAtMs",q.signer_key_id as "signerKeyId",
     s.public_key_spki as "signerSpki",s.environment_id as "signerEnvironment",s.signer_role as "signerRole",
     s.purpose_code::text as "signerPurpose",s.database_role as "signerDatabaseRole",
     s.workload_credential_id::text as "signerCredentialId",s.workload_credential_epoch::text as "signerCredentialEpoch",
     s.valid_from_ms::text as "signerValidFrom",s.valid_until_ms::text as "signerValidUntil",
     p.claims as profile,p.payload as "profilePayload",p.cose as "profileCose",p.issuer_spki as "profileIssuer"
     from control.fleet_fact_quarantine q
     left join control.fleet_fact_delivery d using(participant_id,privacy_domain_id,event_id)
     left join control.fleet_fact_failure_outbox o using(participant_id,privacy_domain_id,receipt_id)
     left join control.fact_consumer_failure_signer s on s.participant_id=q.participant_id
      and s.privacy_domain_id=q.privacy_domain_id and s.consumer_id='LS-FLEET-CONTROL' and s.signer_key_id=q.signer_key_id
     left join control.fact_consumer_profile p on p.participant_id=q.participant_id and p.privacy_domain_id=q.privacy_domain_id
      and p.profile_digest=q.claims->>'currentProfileDigest' and p.consumer_id='LS-FLEET-CONTROL'
     where q.participant_id=$1 and q.privacy_domain_id=$2 and q.state='COMMITTED'
      and not exists(select 1 from control.evidence_catalogue c where c.participant_id=q.participant_id
       and c.privacy_domain_id=q.privacy_domain_id and c.stream_id=$3 and c.record_id=q.receipt_id::text
       and c.receipt_digest=q.receipt_digest and c.source_format='COSE_SIGN1_24007_1_344' and c.evidence_class='EFFECT')
     order by q.committed_at_ms,q.receipt_id limit 8`,
    [scope.participantId, scope.privacyDomainId, scope.streamId],
  );
  return result.rows.map((row) => verifyFactFailureSource(row, scope));
}
