import type { Pool } from 'pg';
import { z } from 'zod';
import { uuidv7 } from '../configuration/governed-mutation-http.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { EvidenceCustodyError } from './segment.js';
import { protectedCiphertext, protectedVaultObject } from './protected-custody-contracts.js';
import type { LocalProtectedProofVault } from './protected-vault.js';

export const protectedCustodyScope = z.strictObject({
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
});

/** The existing custody worker's class-specific raw object adapter. A lost ACK
 * retries the same immutable object/version, then independently reads it back. */
export async function archiveProtectedProof(
  pool: Pool,
  value: z.infer<typeof protectedCustodyScope>,
  sink: LocalProtectedProofVault,
) {
  const scope = protectedCustodyScope.parse(value);
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('set local synchronous_commit=on');
    await client.query('set local row_security=on');
    await client.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true),openpc.assert_request_context(true)`,
      [scope.participantId, scope.privacyDomainId, uuidv7()],
    );
    await lockEvidenceLifecycle(client, scope.participantId, scope.privacyDomainId);
    const rows = await client.query(
      `select openpc.protected_proof_binding(o) binding,
      to_char(o.retain_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') retain_until,
      p.key_id,p.nonce,p.ciphertext from control.protected_proof_object o
      join control.protected_proof_payload p using(participant_id,privacy_domain_id,object_id)
      where o.participant_id=$1 and o.privacy_domain_id=$2 and not exists(
       select 1 from control.protected_proof_checkpoint c where c.participant_id=o.participant_id
        and c.privacy_domain_id=o.privacy_domain_id and c.object_id=o.object_id and c.sink_id=$3)
      order by o.object_id limit 1`,
      [scope.participantId, scope.privacyDomainId, sink.sinkId],
    );
    if (rows.rowCount === 0) {
      await client.query('commit');
      return null;
    }
    const row = rows.rows[0]!;
    const payload = protectedCiphertext.parse({
      keyId: row.key_id,
      nonceBase64: (row.nonce as Buffer).toString('base64'),
      ciphertextBase64: (row.ciphertext as Buffer).toString('base64'),
    });
    const object = protectedVaultObject.parse({
      ...row.binding,
      ...scope,
      sinkId: sink.sinkId,
      dataClass: 'RAW_SOURCE_BODY',
      payloadDigest: sha256(payload),
      ciphertextBytes: (row.ciphertext as Buffer).length,
      retainUntil: row.retain_until,
    });
    const acknowledged = await sink.put(object, payload);
    const verified = await sink.verify(object);
    if (canonicalJson(acknowledged) !== canonicalJson(verified))
      throw new EvidenceCustodyError('INTEGRITY');
    const checkpoint = {
      domain: 'pc.evidence.protected-checkpoint.v1',
      ...scope,
      objectRef: object.objectRef,
      objectVersion: object.objectVersion,
      sinkId: sink.sinkId,
      payloadDigest: object.payloadDigest,
      receiptDigest: verified.receiptDigest,
    };
    const checkpointDigest = sha256(checkpoint);
    await client.query(
      `insert into control.protected_proof_checkpoint
      (participant_id,privacy_domain_id,object_id,sink_id,payload_digest,ciphertext_bytes,receipt,receipt_digest,checkpoint_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        object.objectRef.slice(-36),
        sink.sinkId,
        object.payloadDigest,
        object.ciphertextBytes,
        verified,
        verified.receiptDigest,
        checkpointDigest,
      ],
    );
    await client.query('commit');
    return { ...checkpoint, checkpointDigest, assurance: verified.assurance };
  } catch (error) {
    await client.query('rollback').catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}
