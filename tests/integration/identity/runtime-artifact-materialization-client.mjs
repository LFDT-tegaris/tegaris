// Invoked by the real Rust/PostgreSQL source test while its native IPC owner is
// running. No mocked database, socket, custody, permission or payload owner.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import pg from 'pg';
import { readFile } from 'node:fs/promises';
import { prepareRuntimeArtifactArchive } from '../../../services/control-api/src/evidence/runtime-artifact-archive-contract.ts';
import { sealSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.ts';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import { authorizeRuntimeArtifactRead } from '../../../services/module-registry/src/db/runtime-artifact-materialization.ts';

async function main() {
  const input = JSON.parse(process.env.OPENPC_RUNTIME_SOURCE_READ_TEST);
  if (input.format) {
    const payload = Buffer.alloc(400_001, 0x93);
    const manifestInput = {
      participantId: input.participant,
      privacyDomainId: input.privacy,
      runtimeConfigurationInputId: input.input,
      moduleInstallationId: input.module,
      moduleConfigurationGenerationId: input.generation,
      configurationDigest: `sha256:${input.digest}`,
      configurationBytes: payload.length,
      resourceBindingsDigest: `sha256:${'a'.repeat(64)}`,
      createdAt: '2026-09-27T00:00:00.000000Z',
    };
    const prepared = prepareRuntimeArtifactArchive(manifestInput, payload);
    let sequence = 1,
      previous = null;
    const segments = prepared.groups.map((group, index) => {
      const sealed = sealSegment(
        {
          participantId: input.participant,
          privacyDomainId: input.privacy,
          streamId: 'archive',
          version: 'OPENPC_EVIDENCE_SEGMENT_V1',
          segmentId: `01900000-0000-7000-8000-${String(index + 100).padStart(12, '0')}`,
          firstSequence: String(sequence),
          throughSequence: String(sequence + group.length - 1),
          previousSegmentDigest: previous,
          keyId: 'key',
          retentionUntil: '2030-01-01T00:00:00.000000Z',
        },
        group,
        Buffer.alloc(32, 11),
      );
      sequence += group.length;
      previous = sealed.objectDigest;
      return { ...sealed, bytes: sealed.bytes.toString('base64') };
    });
    process.stdout.write(canonicalJson({ manifest: prepared.manifest, segments }));
    return;
  }
  const url = new URL(process.env.OPENPC_I02_ADMIN_DATABASE_URL);
  url.username = input.role;
  url.password = input.password;
  if (input.archive) {
    const pool = new pg.Pool({ connectionString: url.toString(), max: 1 });
    let lostCommit = input.lost_commit === true;
    let insertedSegments = 0;
    pool.on('connect', (client) => {
      const query = client.query.bind(client);
      client.query = async (...args) => {
        const result = await query(...args);
        if (
          input.partial_rollback &&
          typeof args[0] === 'string' &&
          args[0].includes('insert into control.evidence_segment_payload')
        ) {
          insertedSegments += 1;
          if (insertedSegments === 2) throw new Error('archive second segment response lost');
        }
        if (lostCommit && args[0] === 'commit') {
          lostCommit = false;
          throw new Error('archive COMMIT response lost');
        }
        return result;
      };
    });
    const key = await readFile(input.key_file);
    const custody = new EvidenceCustody(pool);
    try {
      const scope = {
        participantId: input.participant,
        privacyDomainId: input.privacy,
        streamId: 'runtime-native-archive',
      };
      const request = {
        participantId: input.participant,
        privacyDomainId: input.privacy,
        runtimeConfigurationInputId: input.input,
      };
      const ingest = () =>
        custody.ingestRuntimeArtifact(
          scope,
          request,
          { keyId: 'archive-key', key },
          '2030-01-01T00:00:00.000000Z',
          16 * 1024 * 1024,
          async (id) => {
            assert.equal(id, 'archive-key');
            return key;
          },
        );
      if (input.partial_rollback) {
        await assert.rejects(ingest(), { message: 'archive second segment response lost' });
        assert.equal(insertedSegments, 2);
        return;
      }
      if (input.lost_commit)
        await assert.rejects(ingest(), { message: 'archive COMMIT response lost' });
      else assert.ok(await ingest());
      assert.equal(await ingest(), null);
      return;
    } finally {
      key.fill(0);
      await pool.end();
    }
  }
  const client = new pg.Client({ connectionString: url.toString() });
  await client.connect();
  try {
    await client.query('begin');
    await client.query(
      "select openpc.set_request_context('PARTICIPANT',$1::uuid,$2::uuid,uuidv7(),'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',true)",
      [input.participant, input.privacy],
    );
    await authorizeRuntimeArtifactRead(client, input.input);
    const result = await client.query(
      'select openpc.runtime_artifact_input_payload($1::uuid) payload',
      [input.input],
    );
    assert.equal(result.rowCount, 1);
    assert.equal(createHash('sha256').update(result.rows[0].payload).digest('hex'), input.digest);
    result.rows[0].payload.fill(0);
    // The ordinary Node producer can roll back while the native possible-use
    // original must remain. The parent validates the retained history/restart.
    await client.query('rollback');
  } finally {
    await client.end();
  }
}

main().catch((error) => {
  // Never print credentials, raw driver errors, challenge wires or payloads.
  const owners =
    typeof error?.where === 'string'
      ? [...error.where.matchAll(/PL\/pgSQL function ([a-z_0-9.]+)\([^\n]*?\) line ([0-9]+)/gu)]
          .map((match) => `${match[1]}:${match[2]}`)
          .join(',')
      : '';
  process.stderr.write(
    `Runtime source Node IPC integration failed: ${error?.code ?? error?.name ?? 'unknown'} owners=${owners}\n`,
  );
  process.exitCode = 1;
});
