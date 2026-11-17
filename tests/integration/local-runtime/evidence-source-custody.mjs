import assert from 'node:assert/strict';
import {
  verifyReceiptProvenanceSources,
  verifyPublicProvenance,
} from './evidence-provenance-checks.mjs';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdtemp } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';

// SEM-053/054/055/058/061. Called after real public indexer commits and
// signature-provider readback. No intermediate receipt/effect is seeded here.
// This proves local custody, not production object-lock assurance or user export.
const [secretRoot, participantId, privacyDomainId, session] = process.argv.slice(2);
async function readCatalogue() {
  const response = await fetch('http://127.0.0.1:8080/api/v1/evidence-records?limit=100', {
    headers: {
      'Cookie': `__Host-openpc_session=${session}`,
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
      'X-Request-ID': uuidv7(),
      'X-Correlation-ID': uuidv7(),
    },
  });
  assert.equal(response.status, 200, 'authorized catalogue prerequisite');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  return response.json();
}
const config = {
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 2,
};
const admin = new Pool({ ...config, user: 'openpc_control' });
const worker = new Pool({
  ...config,
  user: 'openpc_local_control_worker',
  password: (
    await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
  ).trim(),
});
const root = await mkdtemp(join(secretRoot, '..', 'data', 'evidence-source-'));
const scope = { participantId, privacyDomainId, streamId: `control-source-${uuidv7()}` };
const encryption = { keyId: 'isolated-runtime-evidence-key', key: randomBytes(32) };
const retentionUntil = new Date(Date.now() + 86_400_000).toISOString().replace(/Z$/u, '000Z');
const capacity = 1024 * 1024;
try {
  await readCatalogue();
  await writeFile(join(root, 'encryption.key'), encryption.key, { mode: 0o600, flag: 'wx' });
  const sources = (
    await admin.query(
      `select e.evidence_record_id::text as id,a.cose_sign1 as bytes,
    a.recorded_at_ns::text as ns from control.evidence_record e join control.audit_occurrence a
    using(participant_id,privacy_domain_id,receipt_id,receipt_digest)
    where e.participant_id=$1 and e.privacy_domain_id=$2 order by a.recorded_at_ns,e.evidence_record_id`,
      [participantId, privacyDomainId],
    )
  ).rows;
  assert.equal(sources.length, 3, 'public creates/update prerequisites committed three receipts');
  const custody = new EvidenceCustody(worker);
  await assert.rejects(
    custody.ingestBusiness(
      { ...scope, streamId: `${scope.streamId}-capacity` },
      encryption,
      retentionUntil,
      1024,
    ),
    /capacity/,
  );
  const competing = await Promise.all([
    custody.ingestBusiness(scope, encryption, retentionUntil, capacity),
    custody.ingestBusiness(scope, encryption, retentionUntil, capacity),
  ]);
  assert.equal(competing.filter(Boolean).length, 1, 'concurrent selection admits each source once');
  const admitted = competing.find(Boolean);
  assert.equal(admitted.firstSequence, '1');
  assert.equal(admitted.throughSequence, String(sources.length));
  assert.equal(admitted.sinkQuorum, 0);
  assert.equal(
    await new EvidenceCustody(worker).ingestBusiness(scope, encryption, retentionUntil, capacity),
    null,
  );
  assert.equal(
    (
      await admin.query(
        `select count(*)::int count from control.evidence_checkpoint
    where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
        Object.values(scope),
      )
    ).rows[0].count,
    0,
  );

  const sink = await LocalEvidenceVault.open(join(root, 'vault'), 'runtime-local-sink');
  const checkpoint = await custody.exportNext(scope, sink);
  assert.equal(checkpoint.throughSequence, admitted.throughSequence);
  const stored = (
    await admin.query(
      `select receipt from control.evidence_checkpoint
    where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
      Object.values(scope),
    )
  ).rows[0].receipt;
  const bytes = await sink.read(stored.object);
  const opened = openSegment(
    bytes,
    admitted.objectDigest,
    inspectSegment(bytes).header,
    encryption.key,
  );
  assert.deepEqual(
    opened.records.map((record) => record.recordId),
    sources.map((row) => row.id),
  );
  for (const [index, record] of opened.records.entries()) {
    const source = sources[index];
    assert.equal(record.evidenceClass, 'BUSINESS_TRANSITION');
    assert.equal(record.sourceFormat, 'COSE_SIGN1_24001_1_338');
    assert.equal(record.receiptDigest, sha256(source.bytes));
    assert.deepEqual(Buffer.from(record.receiptBase64, 'base64'), source.bytes);
    assert.equal(
      record.occurredAt.slice(-7, -1),
      String((BigInt(source.ns) / 1000n) % 1000000n).padStart(6, '0'),
    );
    assert.equal(bytes.includes(source.bytes), false, 'archive bytes are encrypted');
  }
  assert.equal(
    await new EvidenceCustody(worker).exportNext(
      scope,
      await LocalEvidenceVault.open(join(root, 'vault'), 'runtime-local-sink'),
    ),
    null,
  );

  const page = await readCatalogue();
  for (const source of sources)
    assert.ok(page.items.some((row) => row.recordDigest === sha256(source.bytes)));
  for (const row of page.items)
    assert.deepEqual(
      Object.keys(row).sort(),
      [
        'evidenceId',
        'participantId',
        'evidenceClass',
        'recordDigest',
        'sequence',
        'state',
        'occurredAt',
        'revision',
        'createdAt',
        'updatedAt',
      ].sort(),
    );
  const reader = await worker.connect();
  let provenance;
  try {
    await reader.query('begin isolation level repeatable read read only');
    await reader.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',true)",
      [participantId, privacyDomainId, uuidv7()],
    );
    provenance = await verifyReceiptProvenanceSources(reader, participantId, privacyDomainId, [
      'COSE_SIGN1_24001_1_338',
    ]);
  } finally {
    await reader.query('rollback');
    reader.release();
  }
  await verifyPublicProvenance(
    async (path, context = {}) => {
      const response = await fetch(`http://127.0.0.1:8080/api/v1/${path}`, {
        headers: {
          'Cookie': `__Host-openpc_session=${session}`,
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${context.participantId ?? participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${context.privacyDomainId ?? privacyDomainId}`,
          'X-Request-ID': uuidv7(),
          'X-Correlation-ID': uuidv7(),
        },
      });
      assert.equal(response.headers.get('cache-control'), 'no-store');
      return { status: response.status, body: await response.json() };
    },
    provenance,
    secretRoot,
  );
  process.stdout.write(
    'OPENPC_EVIDENCE_SOURCE_CUSTODY|PASS|public-business-receipts|encrypted-originals|concurrent-once|capacity|durable-sink|restart|safe-api-readback\n',
  );
} finally {
  encryption.key.fill(0);
  await worker.end();
  await admin.end();
  // Keep the owned key and immutable sink with this disposable environment;
  // its normal cleanup owns them together with the database checkpoints.
}
