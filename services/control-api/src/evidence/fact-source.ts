import { bindFactAdmissionDelivery, type FactAdmissionDelivery } from './fact-delivery-contract.js';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { EvidenceCustodyError, digest, type EvidenceScope, type SourceReceipt } from './segment.js';
import {
  FACT_EVIDENCE_FORMAT,
  factEvidenceBatch as batchSchema,
  factProvenance,
  type FactProvenance,
} from './fact-provenance-contract.js';

const absolute = z.string().refine(isAbsolute);
export const factEvidenceSource = z.strictObject({
  sourceProfileId: z.uuidv7(),
  database: z.strictObject({
    host: z.string().min(1),
    port: z.number().int().min(1).max(65535),
    database: z.string().min(1),
    user: z.string().min(1),
    passwordFile: absolute,
  }),
  verificationKeyFile: absolute,
  verificationKeyId: digest,
});
export type FactEvidenceSource = z.infer<typeof factEvidenceSource>;

/** Dedicated custody configuration owns database access and verification trust.
 * Neither the request nor a caller-provided readiness value can choose them. */
export async function readFactEvidenceBatch(
  client: PoolClient,
  scope: EvidenceScope,
  input: FactEvidenceSource,
) {
  const source = factEvidenceSource.parse(input);
  const prefix = `fact:${sha256([scope.participantId, scope.privacyDomainId, source.sourceProfileId]).slice(7)}:`;
  const tail = await client.query<{ record_id: string; sequence: string; source_format: string }>(
    `select record_id,sequence::text,source_format from control.evidence_catalogue c
     where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by c.sequence desc limit 1`,
    [scope.participantId, scope.privacyDomainId, scope.streamId],
  );
  const previous = tail.rows[0];
  if (
    previous &&
    (previous.source_format !== FACT_EVIDENCE_FORMAT ||
      previous.record_id !== prefix + previous.sequence)
  )
    throw new EvidenceCustodyError('CONFLICT');
  // Revisit the earliest already-custodied original lacking its consumer
  // identity before advancing to new source bytes. Never synthesize an event.
  const pending = await client.query<{ sequence: string }>(
    `select c.sequence::text from control.evidence_catalogue c
      where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3
        and c.source_format='OPENPC_CANONICAL_FACT_V1'
        and not exists(select 1 from control.evidence_fact_admission_inbox i
          where i.participant_id=c.participant_id and i.privacy_domain_id=c.privacy_domain_id
            and i.stream_id=c.stream_id and i.record_id=c.record_id)
      order by c.sequence limit 1`,
    [scope.participantId, scope.privacyDomainId, scope.streamId],
  );
  const after = pending.rows[0]
    ? String(BigInt(pending.rows[0].sequence) - 1n)
    : (previous?.sequence ?? '0');
  const executable =
    process.env.OPENPC_POLICY_FACT_READER_BIN ??
    fileURLToPath(new URL('../../../../target/debug/policy_fact_reader', import.meta.url));
  const verificationKey = await readFile(source.verificationKeyFile);
  if (verificationKey.length !== 33 || ![2, 3].includes(verificationKey[0]!))
    throw new EvidenceCustodyError('INTEGRITY');
  const verificationKeyDigest = sha256(verificationKey);
  let batch: z.infer<typeof batchSchema>;
  try {
    batch = batchSchema.parse(
      JSON.parse(
        execFileSync(executable, ['--evidence'], {
          input: JSON.stringify({
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            sourceProfileId: source.sourceProfileId,
            afterSequence: after,
          }),
          encoding: 'utf8',
          timeout: 10000,
          maxBuffer: 4 * 1024 * 1024,
          windowsHide: true,
          stdio: ['pipe', 'pipe', 'pipe'],
          env: {
            ...process.env,
            POLICY_FACT_DATABASE_HOST: source.database.host,
            POLICY_FACT_DATABASE_PORT: String(source.database.port),
            POLICY_FACT_DATABASE_NAME: source.database.database,
            POLICY_FACT_DATABASE_USER: source.database.user,
            POLICY_FACT_DATABASE_PASSWORD_FILE: source.database.passwordFile,
            POLICY_FACT_VERIFY_KEY_FILE: source.verificationKeyFile,
            POLICY_FACT_VERIFY_KEY_ID: source.verificationKeyId,
          },
        }),
      ),
    );
  } catch {
    throw new EvidenceCustodyError('INTEGRITY');
  }
  if (
    batch.verificationKeyDigest !== verificationKeyDigest ||
    batch.sourceProfileId !== source.sourceProfileId ||
    BigInt(batch.checkpointSequence) < BigInt(after) ||
    (!batch.records.length && batch.checkpointSequence !== after)
  )
    throw new EvidenceCustodyError('INTEGRITY');
  return batch.records.map(
    (
      entry,
      index,
    ): {
      source: SourceReceipt;
      provenance: FactProvenance;
      admissionDelivery?: FactAdmissionDelivery;
    } => {
      const bytes = Buffer.from(entry.receiptBase64, 'base64');
      if (
        bytes.toString('base64') !== entry.receiptBase64 ||
        sha256(bytes) !== entry.receiptDigest ||
        BigInt(entry.sourceSequence) !== BigInt(after) + BigInt(index) + 1n ||
        BigInt(entry.sourceSequence) > BigInt(batch.checkpointSequence)
      )
        throw new EvidenceCustodyError('INTEGRITY');
      const { receiptBase64, admissionDelivery, ...projection } = entry;
      return {
        ...(admissionDelivery === undefined
          ? {}
          : {
              admissionDelivery: bindFactAdmissionDelivery(
                admissionDelivery,
                scope,
                entry.candidateId,
                entry.lineage.factId,
              ),
            }),
        source: {
          recordId: prefix + entry.sourceSequence,
          evidenceClass: 'EFFECT',
          sourceFormat: FACT_EVIDENCE_FORMAT,
          receiptBase64,
          receiptDigest: entry.receiptDigest,
          occurredAt: entry.admittedAt,
        },
        provenance: factProvenance.parse({
          ...projection,
          integrity: 'FACT_COSE_VERIFIED_AT_CUSTODY',
          authority: 'NONE',
          currentReadiness: 'NOT_ESTABLISHED',
          sourceProfileId: source.sourceProfileId,
          verificationKeyId: source.verificationKeyId,
          verificationKeyDigest,
        }),
      };
    },
  );
}

export async function retainFactProvenance(
  client: PoolClient,
  scope: EvidenceScope,
  entries: readonly { source: SourceReceipt; provenance: FactProvenance }[],
) {
  for (const entry of entries) {
    const projection = factProvenance.parse(entry.provenance),
      hash = sha256(projection);
    const identity = [
      scope.participantId,
      scope.privacyDomainId,
      scope.streamId,
      entry.source.recordId,
    ];
    const retired = await client.query(
      `select 1 from control.evidence_projection_retirement r join control.deletion_job j using(participant_id,privacy_domain_id,deletion_job_id)
       where r.participant_id=$1 and r.privacy_domain_id=$2 and r.stream_id=$3 and r.record_id=$4
        and r.data_class='NORMALIZED_JSON_PROJECTION' and j.state='SUCCEEDED' and j.selection->>'sourceKind'='FACT_PROVENANCE'
        and r.projection_digest=$5 and r.source_receipt_digest=$6
        and r.preservation_metadata=jsonb_build_object('factLineage',$7::jsonb)
        and r.retirement_digest=openpc.projection_retirement_digest(r)`,
      [...identity, hash, entry.source.receiptDigest, projection.lineage],
    );
    if (retired.rowCount === 1) continue;
    await client.query(
      `insert into control.evidence_fact_provenance(participant_id,privacy_domain_id,stream_id,record_id,projection,projection_digest)
      values($1,$2,$3,$4,$5,$6) on conflict do nothing`,
      [...identity, projection, hash],
    );
    const retained = await client.query<{ projection: unknown; projection_digest: string }>(
      `select projection,projection_digest from control.evidence_fact_provenance where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$4`,
      identity,
    );
    if (
      retained.rowCount !== 1 ||
      retained.rows[0]!.projection_digest !== hash ||
      sha256(retained.rows[0]!.projection) !== hash
    )
      throw new EvidenceCustodyError('INTEGRITY');
  }
}
