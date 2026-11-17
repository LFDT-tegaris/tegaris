import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Pool } from 'pg';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import { readFactEvidenceBatch } from '../../../services/control-api/src/evidence/fact-source.ts';
import { FACT_EVIDENCE_FORMAT } from '../../../services/control-api/src/evidence/fact-provenance-contract.ts';
import { readEvidenceProvenance } from '../../../services/control-api/src/evidence/provenance.ts';
import {
  LocalEvidenceVault,
  vaultObject,
} from '../../../services/control-api/src/evidence/local-vault.ts';
import { openSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import {
  verifyFactReferenceClosure,
  verifyFactReferenceFaults,
} from './evidence-fact-reference-checks.mjs';
export { verifyFactReferenceClosure } from './evidence-fact-reference-checks.mjs';
import { verifyFactRetirementOwner } from './evidence-fact-retirement-checks.mjs';
import { exerciseFactDeliveryRecovery } from './evidence-fact-delivery-recovery.mjs';

// SEM-053/054/055/058/061: consume existing independently admitted Facts. This
// source/custody regression cannot create or renew a Fact or authorization.
export async function exerciseFactCustody({
  secretRoot,
  participantId,
  privacyDomainId,
  root,
  packaged,
  requireReferences = false,
  retirementChecks = false,
}) {
  const password = async (name) => (await readFile(join(secretRoot, name), 'utf8')).trim();
  const worker = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_local_control_worker',
    password: await password('control_worker_runtime_db_password.txt'),
    max: 2,
  });
  const facts = new Pool({
    host: '127.0.0.1',
    port: 55433,
    database: 'openpc_facts',
    user: 'openpc_policy_fact_runtime',
    password: await password('policy_fact_db_password.txt'),
    max: 1,
  });
  let key;
  const previousReader = process.env.OPENPC_POLICY_FACT_READER_BIN;
  try {
    if (packaged) {
      const binary = join(root, 'policy_fact_reader');
      await exec('docker', ['cp', `${packaged.api}:/usr/local/bin/policy_fact_reader`, binary]);
      await chmod(binary, 0o700);
      process.env.OPENPC_POLICY_FACT_READER_BIN = binary;
    }
    const reader = await facts.connect();
    let profiles;
    try {
      await reader.query('begin read only');
      await reader.query(
        "select set_config('openpc.participant_id',$1,true),set_config('openpc.privacy_domain_id',$2,true)",
        [participantId, privacyDomainId],
      );
      profiles = (
        await reader.query(
          `select source_profile_id,last_sequence::text,state from facts.source_checkpoint
        where participant_id=$1 and privacy_domain_id=$2 and last_sequence>0
          and source_profile_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        order by source_profile_id limit 17`,
          [participantId, privacyDomainId],
        )
      ).rows;
      assert.ok(
        profiles.length > 0 && profiles.length <= 16,
        'bounded actual Fact source prerequisites',
      );
    } finally {
      await reader.query('rollback');
      reader.release();
    }
    const until = new Date(Date.now() + 86400000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
    let config;
    try {
      config = JSON.parse(await readFile(join(root, 'worker.json'), 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    if (!config) {
      key = randomBytes(32);
      await writeFile(join(root, 'archive.key'), key, { mode: 0o600, flag: 'wx' });
      config = {
        database: {
          host: '127.0.0.1',
          port: 55432,
          database: 'openpc_control',
          user: 'openpc_local_control_worker',
          passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
        },
        vaultDirectory: join(root, 'vault'),
        sinkId: 'fact-local-sink',
        scopes: profiles.map((row) => ({
          participantId,
          privacyDomainId,
          streamId: 'canonical-facts-' + uuidv7(),
          source: 'FACT',
          activeKeyId: 'fact-archive-key',
          keys: [{ keyId: 'fact-archive-key', keyFile: join(root, 'archive.key') }],
          retentionSeconds: 86400,
          capacityBytes: 16 * 1024 * 1024,
          fact: {
            sourceProfileId: row.source_profile_id,
            database: {
              host: '127.0.0.1',
              port: 55433,
              database: 'openpc_facts',
              user: 'openpc_policy_fact_runtime',
              passwordFile: join(secretRoot, 'policy_fact_db_password.txt'),
            },
            verificationKeyFile: join(secretRoot, 'policy_fact_verify_key.sec1'),
            verificationKeyId:
              'sha256:6bd1b7ff42169210dab9f9a28055f450b422a47834ff4e68e8c2de9d54804efc',
          },
        })),
      };
      await writeFile(join(root, 'worker.json'), JSON.stringify(config), {
        mode: 0o600,
        flag: 'wx',
      });
    } else key = await readFile(join(root, 'archive.key'));
    assert.equal(key.length, 32);
    assert.equal(config.vaultDirectory, join(root, 'vault'));
    assert.deepEqual(
      config.scopes.map((s) => s.fact.sourceProfileId),
      profiles.map((p) => p.source_profile_id),
    );
    const encryption = { keyId: 'fact-archive-key', key };
    const sink = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId);
    const custody = new EvidenceCustody(worker),
      views = [];
    for (const entry of config.scopes) {
      assert.equal(entry.participantId, participantId);
      assert.equal(entry.privacyDomainId, privacyDomainId);
      const scope = { participantId, privacyDomainId, streamId: entry.streamId },
        values = Object.values(scope);
      const ingest = () =>
        custody.ingestFact(scope, entry.fact, encryption, until, entry.capacityBytes);
      const initial = await Promise.all([ingest(), ingest()]);
      assert.ok(initial.filter(Boolean).length <= 1, 'one admission for a concurrent source page');
      for (let page = 0; page < 64; page++) {
        if (!(await ingest())) break;
        assert.ok(page < 63, 'bounded retained source');
      }
      assert.equal(
        await new EvidenceCustody(worker).ingestFact(
          scope,
          entry.fact,
          encryption,
          until,
          entry.capacityBytes,
        ),
        null,
      );
      while (await custody.exportNext(scope, sink)) {
        /* bounded source above */
      }
      const client = await worker.connect();
      try {
        await client.query('begin');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [participantId, privacyDomainId, uuidv7()],
        );
        const catalogue = (
          await client.query(
            `select c.*,to_char(c.occurred_at at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') occurred_text,p.projection,
          openpc.evidence_hold_record_metadata(c) metadata from control.evidence_catalogue c
          join control.evidence_fact_provenance p using(participant_id,privacy_domain_id,stream_id,record_id)
          where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by c.sequence`,
            values,
          )
        ).rows;
        assert.equal(
          catalogue.length,
          Number(
            profiles.find((p) => p.source_profile_id === entry.fact.sourceProfileId).last_sequence,
          ),
        );
        assert.ok(catalogue.length > 0);
        for (const row of catalogue) {
          const l = row.projection.lineage,
            m = row.metadata;
          assert.equal(row.source_format, FACT_EVIDENCE_FORMAT);
          assert.ok(m);
          const selectors = [
            { type: 'PROJECTION', projectionId: l.projectionId },
            {
              type: 'FACT_TYPE_KEY',
              factType: l.factType,
              factProfileId: l.factProfileId,
              factKeyDigest: l.factKeyDigest,
            },
            {
              type: 'GENERATION',
              generation: {
                kind: 'CANONICAL_FACT',
                factProfileId: l.factProfileId,
                canonicalGeneration: l.canonicalGeneration,
              },
            },
            {
              type: 'BLOCK_RANGE',
              chainId: l.chainId,
              genesisDigest: l.genesisDigest,
              fromBlock: l.blockNumber,
              throughBlock: l.blockNumber,
            },
          ];
          for (const selector of selectors)
            assert.equal(
              (
                await client.query('select openpc.evidence_hold_source_match($1,$2) matched', [
                  selector,
                  m,
                ])
              ).rows[0].matched,
              true,
            );
          for (const selector of [
            { type: 'PROJECTION', projectionId: 'urn:openpc:resource:' + uuidv7() },
            {
              type: 'FACT_TYPE_KEY',
              factType: l.factType,
              factProfileId: l.factProfileId,
              factKeyDigest: 'sha256:' + 'ef'.repeat(32),
            },
            {
              type: 'GENERATION',
              generation: {
                kind: 'CANONICAL_FACT',
                factProfileId: l.factProfileId,
                canonicalGeneration: '18446744073709551615',
              },
            },
            {
              type: 'BLOCK_RANGE',
              chainId: l.chainId,
              genesisDigest: 'sha256:' + 'ef'.repeat(32),
              fromBlock: '0',
              throughBlock: null,
            },
          ])
            assert.equal(
              (
                await client.query('select openpc.evidence_hold_source_match($1,$2) matched', [
                  selector,
                  m,
                ])
              ).rows[0].matched,
              m.unresolvedReferences ? null : false,
            );
          assert.equal(
            (
              await client.query('select openpc.evidence_hold_source_match($1,$2) matched', [
                {
                  type: 'GENERATION',
                  generation: { kind: 'RUNTIME_CONFIGURATION', generationId: l.projectionId },
                },
                m,
              ])
            ).rows[0].matched,
            null,
          );
          const view = await readEvidenceProvenance(
            client,
            row.evidence_id,
            participantId,
            privacyDomainId,
          );
          assert.deepEqual(view.fact, row.projection);
          assert.equal(view.status, 'VERIFIED_FACT_CUSTODY_PROJECTION');
          assert.equal(view.custody.checkpointState, 'RECORDED');
          for (const forbidden of [
            'receiptBase64',
            'typedSubject',
            'typedObject',
            'rawValue',
            'coseSign1',
          ])
            assert.equal(JSON.stringify(view).includes(forbidden), false);
          views.push(view);
          for (const change of [
            { receipt_digest: 'sha256:' + 'ef'.repeat(32) },
            { sequence: '999999' },
            { occurred_at: '2000-01-01T00:00:00Z' },
            { evidence_class: 'AUTHENTICATION' },
          ])
            assert.equal(
              (
                await client.query(
                  `select openpc.evidence_hold_record_metadata(jsonb_populate_record(null::control.evidence_catalogue,to_jsonb(c)||$4::jsonb)) m
              from control.evidence_catalogue c where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and record_id=$5`,
                  [...values, change, row.record_id],
                )
              ).rows[0].m,
              null,
            );
        }
        const source = catalogue[0],
          insert = (p) =>
            client.query(
              `insert into control.evidence_fact_provenance(participant_id,privacy_domain_id,stream_id,record_id,projection,projection_digest)
          values($1,$2,$3,$4,$5,$6) on conflict do nothing`,
              [...values, source.record_id, p, sha256(p)],
            );
        for (const p of [
          { ...source.projection, raw: 'forbidden' },
          { ...source.projection, receiptDigest: 'sha256:' + 'ef'.repeat(32) },
          { ...source.projection, currentReadiness: 'PRESENT' },
          {
            ...source.projection,
            lineage: { ...source.projection.lineage, canonicalGeneration: '0' },
          },
          { ...source.projection, lineage: { ...source.projection.lineage, raw: 'forbidden' } },
        ]) {
          await client.query('savepoint invalid');
          await assert.rejects(insert(p));
          await client.query('rollback to savepoint invalid');
        }
        assert.deepEqual(await readFactEvidenceBatch(client, scope, entry.fact), []);
        for (const other of [
          { participantId: '018f0000-0000-7000-8000-000000000102', privacyDomainId },
          { participantId, privacyDomainId: '018f0000-0000-7000-8000-000000000202' },
        ]) {
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            [other.participantId, other.privacyDomainId, uuidv7()],
          );
          assert.equal(
            (
              await client.query(
                'select 1 from control.evidence_fact_provenance where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3',
                values,
              )
            ).rowCount,
            0,
          );
        }
      } finally {
        await client.query('rollback');
        client.release();
      }
      for (const view of views.filter((v) => v.custody.streamId === scope.streamId)) {
        const checkpoint = view.custody.checkpoints[0];
        // Resolve the real segment header through encrypted local custody.
        const client = await worker.connect();
        try {
          await client.query('begin read only');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
            [participantId, privacyDomainId, uuidv7()],
          );
          const row = (
            await client.query(
              `select s.*,p.encrypted_segment,to_char(s.retention_until at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') retention_text
            from control.evidence_segment s join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id) where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and segment_id=$4`,
              [...values, view.custody.segmentId],
            )
          ).rows[0];
          const opened = openSegment(
            row.encrypted_segment,
            checkpoint.objectDigest,
            {
              ...scope,
              version: 'OPENPC_EVIDENCE_SEGMENT_V1',
              segmentId: view.custody.segmentId,
              firstSequence: String(row.first_sequence),
              throughSequence: String(row.through_sequence),
              previousSegmentDigest: row.previous_segment_digest,
              keyId: row.key_id,
              retentionUntil: row.retention_text,
            },
            key,
          );
          const object = vaultObject(sink.sinkId, opened.header, checkpoint.objectDigest);
          assert.deepEqual(await sink.read(object), row.encrypted_segment);
          const original = opened.records.find((r) => r.recordId === view.recordId);
          assert.ok(original);
          assert.equal(sha256(Buffer.from(original.receiptBase64, 'base64')), view.recordDigest);
        } finally {
          await client.query('rollback');
          client.release();
        }
      }
    }
    const referenceClient = await worker.connect();
    try {
      await referenceClient.query('begin read only');
      await referenceClient.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        [participantId, privacyDomainId, uuidv7()],
      );
      await verifyFactReferenceClosure(referenceClient, views, requireReferences);
    } finally {
      await referenceClient.query('rollback');
      referenceClient.release();
    }
    if (requireReferences) {
      const admin = new Pool({
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: 'openpc_control',
        password: await password('control_pg_password.txt'),
        max: 1,
      });
      try {
        await verifyFactReferenceFaults(admin, participantId, privacyDomainId, views);
      } finally {
        await admin.end();
      }
    }
    if (retirementChecks) {
      assert.ok(packaged, 'Retirement prerequisite checks require the packaged Fact reader');
      await verifyFactRetirementOwner({
        secretRoot,
        participantId,
        privacyDomainId,
        views,
        executable: join(root, 'policy_fact_reader'),
      });
    }
    if (packaged)
      await exec(process.execPath, [packaged.workerBundle, '--once'], {
        env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: join(root, 'worker.json') },
        timeout: 30000,
        maxBuffer: 65536,
      });
    await exerciseFactDeliveryRecovery(secretRoot, join(root, 'worker.json'), false);
    process.stdout.write(
      'OPENPC_FACT_CUSTODY|PASS|records=' +
        views.length +
        '|original-signature|scope|replay|archive|source-selectors|minimized-readback\n',
    );
    return { root, config, views, profiles };
  } finally {
    if (previousReader === undefined) delete process.env.OPENPC_POLICY_FACT_READER_BIN;
    else process.env.OPENPC_POLICY_FACT_READER_BIN = previousReader;
    key?.fill(0);
    await worker.end();
    await facts.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [
    secretRoot,
    participantId,
    privacyDomainId,
    evidenceRoot,
    api,
    references,
    retirement,
    ...compose
  ] = process.argv.slice(2);
  await exec('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  assert.ok(api && participantId && privacyDomainId);
  assert.ok(references === 'required' || references === 'optional');
  assert.ok(
    retirement === undefined || retirement === 'retirement' || retirement === 'retirement-browser',
  );
  const retirementBrowser = retirement === 'retirement-browser';
  if (retirementBrowser) {
    assert.equal(references, 'required');
    assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  }
  const root = await mkdtemp(join(evidenceRoot, 'evidence-fact-references-'));
  const workerBundle = join(root, 'evidence-worker.mjs');
  await exec('docker', ['cp', api + ':/app/evidence-worker.mjs', workerBundle]);
  const result = await exerciseFactCustody({
    secretRoot,
    participantId,
    privacyDomainId,
    root,
    packaged: { api, workerBundle },
    requireReferences: references === 'required',
    retirementChecks: retirement !== undefined,
  });
  if (retirementBrowser) {
    const complete = result.profiles.filter((profile) => profile.state === 'COMPLETE');
    assert.equal(
      complete.length,
      1,
      'The closing relationship journey has one complete successor source',
    );
    const { projectionDeletionBrowser } =
      await import('./evidence-projection-deletion-browser.mjs');
    await projectionDeletionBrowser({
      secretRoot,
      evidenceRoot,
      dataRoot: join(dirname(secretRoot), 'data'),
      compose,
      participantId,
      privacyDomainId,
      factConfiguration: join(root, 'worker.json'),
      factSourceProfile: complete[0].source_profile_id,
    });
  }
}
