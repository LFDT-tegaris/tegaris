import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { Pool } from 'pg';
import { expect } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import {
  LocalEvidenceVault,
  vaultObject,
} from '../../../services/control-api/src/evidence/local-vault.js';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.js';

/** Uses the real source-owned SQL quarantine produced by the parent scenario.
 * This joins signature/history, encrypted custody, the service entrypoint and
 * durable sink recovery. The parent's synthetic event is not a native Fact. */
export async function verifyFleetFailureCustody(
  admin: Pool,
  worker: Pool,
  participantId: string,
  privacyDomainId: string,
  otherPrivacyDomainId: string,
  originalCose: Buffer,
) {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT!, 'fleet-failure-custody-'));
  const scope = { participantId, privacyDomainId, streamId: 'fleet-failures' };
  const encryption = { keyId: 'failure-custody-test', key: randomBytes(32) };
  const url = new URL(process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL!);
  const configPath = join(root, 'worker.json');
  const vaultDirectory = join(root, 'vault');
  const sinkId = 'failure-local';
  const sourceState = async () =>
    (
      await admin.query(
        `select (select jsonb_agg(to_jsonb(q)) from control.fleet_fact_quarantine q where participant_id=$1) quarantine,
     (select jsonb_agg(to_jsonb(o)) from control.fleet_fact_failure_outbox o where participant_id=$1) outbox,
     (select jsonb_agg(to_jsonb(d) order by event_id) from control.fleet_fact_delivery d where participant_id=$1) delivery,
     (select jsonb_agg(to_jsonb(c) order by fact_type) from control.fleet_fact_admission_cursor c where participant_id=$1) cursor,
     (select jsonb_agg(to_jsonb(w) order by work_item_id) from control.work_item w where participant_id=$1) items`,
        [participantId],
      )
    ).rows[0];
  const counts = async () =>
    (
      await admin.query(
        `select (select count(*)::int from control.evidence_catalogue where participant_id=$1) records,
     (select count(*)::int from control.evidence_segment_payload where participant_id=$1) payloads,
     (select count(*)::int from control.evidence_checkpoint where participant_id=$1) checkpoints`,
        [participantId],
      )
    ).rows[0];
  const run = async (success: boolean) => {
    const result = await promisify(execFile)(
      process.execPath,
      ['--import', 'tsx', 'services/control-api/src/evidence/runtime.ts', '--once'],
      {
        cwd: process.cwd(),
        timeout: 30000,
        env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configPath },
      },
    ).then(
      (value) => ({ status: 0, stderr: value.stderr }),
      (error: { code: number; stderr: string }) => ({ status: error.code, stderr: error.stderr }),
    );
    expect(result.status, result.stderr).toBe(success ? 0 : 1);
  };
  const cleanupFaults = () =>
    admin.query(
      `drop trigger if exists test_fleet_failure_custody on control.evidence_catalogue;
     drop trigger if exists test_fleet_failure_archive on control.evidence_checkpoint;
     drop function if exists openpc.test_fleet_failure_custody()`,
    );
  try {
    await writeFile(join(root, 'key'), encryption.key, { mode: 0o600 });
    await writeFile(join(root, 'password'), decodeURIComponent(url.password), { mode: 0o600 });
    await writeFile(
      configPath,
      JSON.stringify({
        database: {
          host: url.hostname,
          port: Number(url.port),
          database: url.pathname.slice(1),
          user: decodeURIComponent(url.username),
          passwordFile: join(root, 'password'),
        },
        vaultDirectory,
        sinkId,
        scopes: [
          {
            ...scope,
            source: 'FACT_FAILURE',
            activeKeyId: encryption.keyId,
            keys: [{ keyId: encryption.keyId, keyFile: join(root, 'key') }],
            retentionSeconds: 86400,
            capacityBytes: 65536,
          },
        ],
      }),
      { mode: 0o600 },
    );
    const original = await sourceState();
    expect(await counts()).toEqual({ records: 0, payloads: 0, checkpoints: 0 });
    await admin.query(`create function openpc.test_fleet_failure_custody() returns trigger language plpgsql as $$ begin raise exception 'TEST_FAILURE_CUSTODY_ROLLBACK'; end $$;
     create trigger test_fleet_failure_custody before insert on control.evidence_catalogue for each row execute function openpc.test_fleet_failure_custody()`);
    await run(false);
    expect(await counts()).toEqual({ records: 0, payloads: 0, checkpoints: 0 });
    expect(await sourceState()).toEqual(original);
    await admin.query(`drop trigger test_fleet_failure_custody on control.evidence_catalogue;
     create trigger test_fleet_failure_archive before insert on control.evidence_checkpoint for each row execute function openpc.test_fleet_failure_custody()`);
    await run(false);
    expect(await counts()).toEqual({ records: 1, payloads: 1, checkpoints: 0 });
    await cleanupFaults();
    await Promise.all([run(true), run(true)]);
    expect(await counts()).toEqual({ records: 1, payloads: 1, checkpoints: 1 });
    expect(await sourceState()).toEqual(original);
    const row = (
      await admin.query(
        `select p.encrypted_segment,c.receipt_digest,c.record_id,c.source_format from control.evidence_segment_payload p
       join control.evidence_catalogue c using(participant_id,privacy_domain_id,stream_id,segment_id)
       where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3`,
        [participantId, privacyDomainId, scope.streamId],
      )
    ).rows[0];
    const segment = inspectSegment(row.encrypted_segment);
    const vault = await LocalEvidenceVault.open(vaultDirectory, sinkId);
    const archived = await vault.read(vaultObject(sinkId, segment.header, segment.objectDigest));
    expect(archived).toEqual(row.encrypted_segment);
    const readback = openSegment(archived, segment.objectDigest, segment.header, encryption.key);
    expect(readback.records).toHaveLength(1);
    expect(readback.records[0]).toMatchObject({
      recordId: row.record_id,
      sourceFormat: 'COSE_SIGN1_24007_1_344',
      evidenceClass: 'EFFECT',
      receiptDigest: row.receipt_digest,
      receiptBase64: originalCose.toString('base64'),
    });
    const foreign = { ...scope, privacyDomainId: otherPrivacyDomainId };
    expect(
      await new EvidenceCustody(worker).ingestFactFailure(
        foreign,
        encryption,
        segment.header.retentionUntil,
        65536,
      ),
    ).toBeNull();
    expect(await sourceState()).toEqual(original);
    expect(await counts()).toEqual({ records: 1, payloads: 1, checkpoints: 1 });
  } finally {
    await cleanupFaults();
    encryption.key.fill(0);
    await rm(root, { recursive: true, force: true });
  }
}
