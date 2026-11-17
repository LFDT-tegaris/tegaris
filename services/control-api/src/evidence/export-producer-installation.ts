import { z } from 'zod';
import type { Pool, PoolClient } from 'pg';
import {
  evidenceKeyId,
  evidenceExportCoseContext,
  isExactSigningSecretReference,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { lockAuthorityFence } from '../../../identity-service/src/db/authority-fence.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';

const uuid = z.uuidv7();
const counter = z
  .string()
  .max(20)
  .regex(/^(0|[1-9][0-9]{0,19})$/u, { abort: true })
  .refine((value) => value === value.trim() && BigInt(value) <= 18446744073709551615n);
const publicInstallation = z.strictObject({
  owner: z.literal('LS-EVIDENCE-EXPORT'),
  purpose: z.literal('pc.cose.evidence-export-completion-receipt.v1'),
  environmentId: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u),
  participantId: uuid,
  privacyDomainId: uuid,
  sourceId: uuid,
  principalId: uuid,
  workloadCredentialId: uuid,
  workloadEpoch: counter,
  workloadId: z.string().min(1).max(160),
  secretClass: z.literal('SECRET-SIGNING-KEY'),
  secretReference: z.string().min(1).max(331),
  secretVersion: z.string().min(1).max(96),
  publicKeySpkiHex: z.string().regex(/^[0-9a-f]{182}$/u),
  keyEpoch: counter,
  validFromNs: counter,
  validUntilNs: counter,
  installationReference: z.string().min(1).max(256),
});
export type EvidenceExportProducerInstallation = z.infer<typeof publicInstallation>;

/** Installed public trust, never caller-supplied completion authority. No key
 * material or evidence-vault encryption reference is admitted by this owner.
 * Current TLS peer, credentials, source and key lifecycle are checked separately. */
export function validateEvidenceExportProducerInstallation(value: unknown) {
  try {
    const pins = publicInstallation.parse(value);
    if (
      Object.values(pins).some((entry) => entry !== entry.trim()) ||
      BigInt(pins.workloadEpoch) < 1n ||
      BigInt(pins.keyEpoch) < 1n ||
      BigInt(pins.validUntilNs) <= BigInt(pins.validFromNs) ||
      BigInt(pins.validFromNs) % 1000n !== 0n ||
      BigInt(pins.validUntilNs) % 1000n !== 0n ||
      !isExactSigningSecretReference(pins.secretReference, pins.secretVersion)
    )
      throw new Error();
    const signerKeyId = evidenceKeyId(Buffer.from(pins.publicKeySpkiHex, 'hex'));
    const trust = {
      schema: 'pc.evidence-export.producer-trust.v1',
      schemaDefinitionDigest: evidenceExportCoseContext.definitionDigest,
      ...pins,
      signerKeyId,
    };
    const bytes = Buffer.from(canonicalJson(trust));
    return { pins, signerKeyId, trust, bytes, digest: sha256(bytes) };
  } catch {
    throw new Error('Evidence export producer installation rejected');
  }
}

/** Privileged initial installation only. An existing tuple must match exactly;
 * this path cannot rotate/revoke/renew a key or replace its original trust. */
export async function installEvidenceExportProducer(
  pool: Pool,
  value: EvidenceExportProducerInstallation,
) {
  const valid = validateEvidenceExportProducerInstallation(value);
  const p = valid.pins;
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
      [p.participantId, p.privacyDomainId, localOperationId()],
    );
    await client.query(
      `insert into control.evidence_export_producer_installation
      (participant_id,privacy_domain_id,source_id,signer_id,environment_id,principal_id,workload_credential_id,workload_epoch,trust,trust_bytes,trust_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict do nothing`,
      [
        p.participantId,
        p.privacyDomainId,
        p.sourceId,
        valid.signerKeyId,
        p.environmentId,
        p.principalId,
        p.workloadCredentialId,
        p.workloadEpoch,
        valid.trust,
        valid.bytes,
        valid.digest,
      ],
    );
    const installed = await client.query<{ trust_bytes: Buffer; state: string }>(
      `select trust_bytes,state from control.evidence_export_producer_installation
      where participant_id=$1 and privacy_domain_id=$2 and source_id=$3 and signer_id=$4`,
      [p.participantId, p.privacyDomainId, p.sourceId, valid.signerKeyId],
    );
    if (
      installed.rowCount !== 1 ||
      installed.rows[0]!.state !== 'ACTIVE' ||
      !installed.rows[0]!.trust_bytes.equals(valid.bytes)
    )
      throw new Error('Evidence export producer installation conflict');
    await client.query('commit');
    return valid.digest;
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
}

/** Requires the Identity runtime connection, not the read-only export worker.
 * Current dependency locks belong to this actual transaction. The authenticated
 * TLS signer must additionally compare its peer to the returned installed tuple.
 * A credential-state check alone does not authenticate a workload transport. */
export async function fenceEvidenceExportProducer(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  trustDigest: string,
) {
  const found = await client.query<{ trust: Record<string, unknown>; trust_bytes: Buffer }>(
    `select trust,trust_bytes from control.evidence_export_producer_installation
      where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3`,
    [scope.participantId, scope.privacyDomainId, trustDigest],
  );
  if (found.rowCount !== 1) throw new Error('Evidence export producer unavailable');
  const { schema, schemaDefinitionDigest, signerKeyId, ...pins } = found.rows[0]!.trust;
  const valid = validateEvidenceExportProducerInstallation(pins);
  if (
    schema !== valid.trust.schema ||
    schemaDefinitionDigest !== valid.trust.schemaDefinitionDigest ||
    signerKeyId !== valid.signerKeyId ||
    valid.digest !== trustDigest ||
    !valid.bytes.equals(found.rows[0]!.trust_bytes)
  )
    throw new Error('Evidence export producer trust mismatch');
  const p = valid.pins;
  if (p.participantId !== scope.participantId || p.privacyDomainId !== scope.privacyDomainId)
    throw new Error('Evidence export producer scope mismatch');
  await lockAuthorityFence(client, p.participantId, {
    participant: [{ id: p.participantId }],
    privacy_domain: [{ id: p.privacyDomainId }],
    principal: [{ id: p.principalId }],
    credential: [{ id: p.workloadCredentialId }],
  });
  // The installation is immutable, but withdrawal is current authority. Acquire
  // its shared fence after Identity's ordered locks, then re-read its state.
  await client.query(
    `select pg_advisory_xact_lock_shared(hashtextextended(
    'evidence-export-producer:'||$1::text||':'||$2::text,0))`,
    [p.participantId, p.privacyDomainId],
  );
  const active = await client.query(
    `select 1 from control.evidence_export_producer_installation
    where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3 and state='ACTIVE'`,
    [p.participantId, p.privacyDomainId, valid.digest],
  );
  if (active.rowCount !== 1) throw new Error('Evidence export producer withdrawn');
  const current = await client
    .query<{ authority: Record<string, unknown> }>(
      'select openpc.evidence_export_producer_authority($1) authority',
      [valid.digest],
    )
    .catch(() => {
      throw new Error('Evidence export producer authority unavailable');
    });
  if (current.rowCount !== 1) throw new Error('Evidence export producer authority unavailable');
  const authority = Buffer.from(canonicalJson(current.rows[0]!.authority));
  return { ...valid, authority, authorityDigest: sha256(authority) };
}

/** Privileged, irreversible initial-trust withdrawal. Concurrent admitted readers
 * retain their transaction fence; the SQL owner rejects a reversed row-lock wait.
 * This is not a provider deletion or a replacement-key enrollment operation. */
export async function withdrawEvidenceExportProducer(
  pool: Pool,
  scope: { participantId: string; privacyDomainId: string },
  trustDigest: string,
) {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
      [scope.participantId, scope.privacyDomainId, localOperationId()],
    );
    await client.query(
      `select pg_advisory_xact_lock(hashtextextended(
      'evidence-export-producer:'||$1::text||':'||$2::text,0))`,
      [scope.participantId, scope.privacyDomainId],
    );
    const result = await client.query(
      `update control.evidence_export_producer_installation set state='REVOKED'
      where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3 and state='ACTIVE' returning trust_digest`,
      [scope.participantId, scope.privacyDomainId, trustDigest],
    );
    if (result.rowCount !== 1) {
      const prior = await client.query(
        `select 1 from control.evidence_export_producer_installation
        where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3 and state='REVOKED'`,
        [scope.participantId, scope.privacyDomainId, trustDigest],
      );
      if (prior.rowCount !== 1) throw new Error('Evidence export producer unavailable');
    }
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
}
