import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';

/** Retained files are hints; current scoped database rows establish reuse. */
export function visibilityAcquisitionMatches(saved, currentConfiguration, current) {
  const { result, configuration, job, publication, candidate } = saved;
  return (
    result?.outcome === 'COMMITTED_CANDIDATE' &&
    currentConfiguration === configuration?.configurationDigest &&
    current?.configuration_digest === currentConfiguration &&
    current.publication_state === 'PUBLISHED' &&
    ['READY', 'ACTIVE'].includes(current.generation_state) &&
    current.candidate_state === 'VALIDATED_CANDIDATE' &&
    current.checkpoint_state === 'COMPLETE' &&
    current.operation_matches === true &&
    current.candidate_event_id === candidate?.candidateId &&
    current.projection_generation_id === publication?.projection_generation_id &&
    current.candidate_partition_id === publication?.candidate_partition_id &&
    [
      'participant_id',
      'privacy_domain_id',
      'projection_generation_id',
      'source_id',
      'partition_id',
    ].every((key) => typeof job?.[key] === 'string' && current[key] === job[key]) &&
    current.batch_id === job.batch_id &&
    current.batch_sequence === String(job.sequence) &&
    current.range_start === String(job.range?.start) &&
    current.range_end === String(job.range?.end)
  );
}

export async function visibilityAcquisitionReusable(
  root,
  evidence,
  participantId,
  privacyDomainId,
  generation,
) {
  const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
  const saved = {};
  try {
    for (const [key, name] of Object.entries({
      result: 'acquisition/result.json',
      configuration: 'visibility-source-configuration.json',
      job: 'acquisition/config.json',
      publication: 'acquisition/publication.json',
      candidate: 'acquisition/candidate.json',
    }))
      saved[key] = await load(join(evidence, name));
    if (generation !== undefined)
      saved.configuration = await load(
        join(evidence, `visibility-source-generation${generation}.json`),
      );
  } catch (error) {
    // A rejected/interrupted executable can leave an empty redirected output.
    // Local files are only reuse hints; they cannot attest a completed batch.
    if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
    return false;
  }
  const password = async (name) => (await readFile(join(root, 'secrets', name), 'utf8')).trim();
  const control = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: await password('control_pg_password.txt'),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  const candidates = new Pool({
    host: '127.0.0.1',
    port: 55434,
    database: 'openpc_candidate_index',
    user: 'openpc_candidate_index',
    password: await password('candidate_index_pg_password.txt'),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  try {
    await control.query('BEGIN READ ONLY');
    await control.query(
      "select openpc.set_request_context('PARTICIPANT',$1::uuid,$2::uuid,uuidv7(),'ACT-CANDIDATE_WRITE-V1',true)",
      [participantId, privacyDomainId],
    );
    const current = await control.query(
      `select 'sha256:'||encode(c.configuration_digest,'hex') as digest
  from control.runtime_configuration_input_current c
  join control.module_installation i using(module_installation_id)
  join control.module_version v on v.module_version_id=i.module_version_id and v.module_id='pc.config.assets'
  where c.participant_id=$1 and c.privacy_domain_id=$2 and c.active and i.state='ENABLED'`,
      [participantId, privacyDomainId],
    );
    await control.query('ROLLBACK');
    const candidate = await candidates.query(
      `select pub.participant_id::text,pub.privacy_domain_id::text,
  pub.projection_generation_id::text,'sha256:'||encode(pub.configuration_digest,'hex') as configuration_digest,
  pub.state as publication_state,g.state::text as generation_state,e.state::text as candidate_state,
  cp.candidate_partition_id::text,cp.source_id,cp.partition_id,e.candidate_event_id::text,
  ck.state::text as checkpoint_state,ck.batch_id,ck.batch_sequence::text,ck.range_start::text,ck.range_end::text,
  exists(select 1 from candidate.outbox_event o where o.participant_id=pub.participant_id
    and o.privacy_domain_id=pub.privacy_domain_id and o.aggregate_id=cp.candidate_partition_id
    and o.event_type='io.openpc.indexer.projection.checkpoint.completed.v1'
    and o.correlation_id=$5 and o.causation_id=$6 and o.payload_json->>'batchId'=ck.batch_id
    and o.payload_json->>'checkpointDigest'='sha256:'||encode(ck.position_digest,'hex')) as operation_matches
  from candidate.candidate_event e
  join candidate.source_publication pub using(participant_id,privacy_domain_id,projection_generation_id)
  join candidate.projection_generation g using(participant_id,privacy_domain_id,projection_generation_id)
  join candidate.candidate_partition cp using(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
  join candidate.checkpoint ck using(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
  where e.participant_id=$1 and e.privacy_domain_id=$2 and e.candidate_event_id=$3 and ck.batch_id=$4`,
      [
        participantId,
        privacyDomainId,
        saved.candidate.candidateId,
        saved.job.batch_id,
        saved.job.correlation_id,
        saved.job.operation_id,
      ],
    );
    return (
      current.rowCount === 1 &&
      candidate.rowCount === 1 &&
      visibilityAcquisitionMatches(saved, current.rows[0].digest, candidate.rows[0])
    );
  } finally {
    await control.end();
    await candidates.end();
  }
}
