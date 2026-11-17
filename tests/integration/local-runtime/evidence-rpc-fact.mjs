import assert from 'node:assert/strict';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { isIPv4 } from 'node:net';
import { Pool } from 'pg';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import {
  assignmentCreate,
  assignmentCreateCandidate,
} from '../../../services/participant-service/src/contracts/assignment.ts';
import { factTrustScenario } from './runtime-fact-initial-trust.mjs';
import { factArtifactUpdateSchema } from '../../../services/control-api/src/configuration/resource-contracts.ts';

// Acquisition uses the packaged service, admission uses the public Fact owner.
// These helpers only prepare inputs and read the resulting authoritative state.
const [mode, root, evidence] = process.argv.slice(2);
const generation = Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2);
assert.ok(Number.isSafeInteger(generation) && generation >= 2);
const suffix = generation === 2 ? '' : `-${generation}`;
const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
const input = await load(join(evidence, `rpc-source${suffix}-policy-input.json`));
const discovery = await load(join(evidence, 'discovery-credential-input.json'));
const { participantId, privacyDomainId } = input;
assert.equal(discovery.participantId, participantId);
assert.equal(discovery.privacyDomainId, privacyDomainId);
const job = join(evidence, `rpc-acquisition${suffix}`);
const password = async (name) => (await readFile(join(root, 'secrets', name), 'utf8')).trim();
const save = async (name, value) =>
  writeFile(join(job, name), JSON.stringify(value), { mode: 0o600 });
const immutable = async (name, value) => {
  try {
    await writeFile(join(job, name), JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assert.deepEqual(await load(join(job, name)), value, 'Acquisition intent is immutable');
  }
};
await mkdir(job, { recursive: true, mode: 0o700 });
const candidateRead = async (query, values) => {
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55434,
    database: 'openpc_candidate_index',
    user: 'openpc_candidate_index',
    password: await password('candidate_index_pg_password.txt'),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  try {
    return await pool.query(query, values);
  } finally {
    await pool.end();
  }
};

if (mode === 'authentication') {
  const owned = join(root, 'data/runtime-bootstrap');
  const configuration = await load(join(owned, 'fact-bridge/config/deployment.json'));
  assert.equal(configuration.participant_id, participantId);
  assert.equal(configuration.privacy_domain_id, privacyDomainId);
  assert.equal(configuration.runtime_target_id, discovery.targetId);
  assert.equal(configuration.identity_addresses.length, 1);
  const address = configuration.identity_addresses[0];
  assert.ok(isIPv4(address));
  const { stdout } = await promisify(execFile)(
    'curl',
    [
      '--silent',
      '--show-error',
      '--fail',
      '--max-time',
      '5',
      '--tlsv1.3',
      '--tls-max',
      '1.3',
      '--cacert',
      join(root, 'secrets/identity_mtls_ca.pem'),
      '--cert',
      join(owned, 'runtime/tls/ads-client.pem'),
      '--key',
      join(owned, 'runtime/tls/ads-client.key'),
      '--resolve',
      `identity.openpc.test:3443:${address}`,
      '-H',
      'Content-Type: application/json',
      '--data',
      JSON.stringify({ runtimeContext: { privacyDomainId, targetRuntimeId: discovery.targetId } }),
      'https://identity.openpc.test:3443/internal/v1/workload/authenticate',
    ],
    { timeout: 10000, maxBuffer: 128 * 1024 },
  );
  const value = JSON.parse(stdout);
  assert.equal(value.participantId, participantId);
  assert.equal(value.principalId, discovery.principalId);
  assert.equal(value.credentialId, discovery.credentialId);
  assert.ok(value.runtime?.assertionCoseSign1);
} else if (mode === 'acquisition') {
  const configuration = await load(join(evidence, `rpc-source${suffix}-configuration.json`));
  const result = await candidateRead(
    `select pub.projection_generation_id::text,cp.source_id,cp.partition_id,cp.candidate_partition_id::text
     from candidate.source_publication pub join candidate.candidate_partition cp
     using(participant_id,privacy_domain_id,projection_generation_id)
     where pub.participant_id=$1 and pub.privacy_domain_id=$2 and pub.state='PUBLISHED'
       and pub.configuration_digest=decode($3,'hex')`,
    [participantId, privacyDomainId, configuration.configurationDigest.slice(7)],
  );
  assert.equal(result.rowCount, 1, 'One exact governed source publication required');
  const published = result.rows[0];
  await immutable('publication.json', published);
  const tls = join(root, 'data/runtime-bootstrap/runtime/tls');
  const client = new X509Certificate(await readFile(join(tls, 'ads-client.pem')));
  const server = new X509Certificate(await readFile(join(tls, 'protected-server.pem')));
  for (const certificate of [client, server]) {
    assert.ok(Date.parse(certificate.validFrom) <= Date.now());
    assert.ok(
      Date.parse(certificate.validTo) > Date.now() + 300000,
      'Live transport credentials required',
    );
  }
  await writeFile(
    join(job, 'key.pk8'),
    createPrivateKey(await readFile(join(tls, 'ads-client.key'))).export({
      format: 'der',
      type: 'pkcs8',
    }),
    { mode: 0o600 },
  );
  await writeFile(join(job, 'client.der'), client.raw, { mode: 0o600 });
  await writeFile(
    join(job, 'root.der'),
    new X509Certificate(await readFile(join(root, 'secrets/identity_mtls_ca.pem'))).raw,
    { mode: 0o600 },
  );
  await writeFile(
    join(job, 'database-url'),
    `postgresql://openpc_indexer_writer:${encodeURIComponent(await password('indexer_writer_db_password.txt'))}@127.0.0.1:55434/openpc_candidate_index`,
    { mode: 0o600 },
  );
  const prior = await load(join(job, 'config.json')).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  await immutable('config.json', {
    participant_id: participantId,
    privacy_domain_id: privacyDomainId,
    projection_generation_id: published.projection_generation_id,
    operation_id: prior?.operation_id ?? localOperationId(),
    correlation_id: prior?.correlation_id ?? localOperationId(),
    source_id: published.source_id,
    partition_id: published.partition_id,
    batch_id: 'rpc-contract-state-prerequisite',
    sequence: 1,
    predecessor_digest: 'GENESIS',
    range: { start: 10, end: 10 },
    runtime_target_id: discovery.targetId,
    candidate_database_url_file: join(job, 'database-url'),
    endpoint: {
      endpoint_id: discovery.targetId,
      normalized_uri: 'https://runtime.openpc.test:18545/',
      reference_identity: 'runtime.openpc.test',
      port: 18545,
      path: '/',
      dns_policy_ref: 'openpc-local-pinned-runtime',
      tls_policy_ref: 'openpc-local-runtime-ca',
      credential_ref: `urn:openpc:workload:${discovery.targetId}`,
      egress_policy_ref: 'openpc-local-loopback-only',
      endpoint_generation: 1,
    },
    allowed_ranges: ['127.0.0.1/32'],
    private_network_ranges: ['127.0.0.1/32'],
    allow_ip_endpoint: false,
    addresses: ['127.0.0.1'],
    roots_der_files: [join(job, 'root.der')],
    client_chain_der_files: [join(job, 'client.der')],
    client_key_pkcs8_file: join(job, 'key.pk8'),
    server_certificate_digest: createHash('sha256').update(server.raw).digest('hex'),
  });
} else if (['candidate', 'assignment', 'artifact-reader-assignment'].includes(mode)) {
  const publication = await load(join(job, 'publication.json'));
  const result = await candidateRead(
    `select candidate_event_id::text from candidate.candidate_event where participant_id=$1
     and privacy_domain_id=$2 and projection_generation_id=$3 order by record_sequence`,
    [participantId, privacyDomainId, publication.projection_generation_id],
  );
  assert.equal(result.rowCount, 1, 'Exactly one acquired contract state candidate required');
  const candidateId = result.rows[0].candidate_event_id;
  await immutable('candidate.json', { candidateId });
  if (mode !== 'candidate') {
    const reader = mode === 'artifact-reader-assignment';
    const actors = await load(join(evidence, 'deployment-intent-actors.json'));
    const scenario = factTrustScenario(generation);
    let authorityEnvelopeId = scenario.envelopeId;
    const factTrust =
      generation === 2
        ? actors.maker.factPlatformTrust
        : actors.maker.factPlatformTrustByGeneration?.[generation];
    if (!reader) {
      assert.equal(
        factTrust?.platformContextId,
        scenario.platformContextId,
        'Fact assignment requires the installed initial scope; legacy trust is not eligible',
      );
      assert.equal(factTrust.platformAuthorityEpoch, '1');
      assert.equal(factTrust.resourceId, `urn:openpc:resource:${candidateId}`);
      assert.ok(Number.isFinite(Date.parse(factTrust.validUntil)));
    }
    if (reader) {
      const control = new Pool({
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: 'openpc_control',
        password: await password('control_pg_password.txt'),
        max: 1,
        options: '-c default_transaction_read_only=on',
      });
      try {
        const grants = await control.query(
          `select a.authority_envelope_id::text from control.assignment a
           join control.authority_envelope e using(participant_id,authority_envelope_id)
           join control.authority_role r using(participant_id,role_id)
           where a.participant_id=$1 and a.principal_id=$2 and a.state='ACTIVE'
             and a.valid_during @> clock_timestamp() and $3=any(a.privacy_domain_ids)
             and 'ACT-PARTICIPANT_CREATE_MEMBER-V1'=any(a.action_intent_ids)
             and a.role_id=$4 and e.state='ACTIVE' and $3=any(e.privacy_domain_ids)
             and 'ACT-FACT_ARTIFACTS_READ_RESOURCE-V1'=any(e.action_intent_ids)
             and 'ACT-FACT_ARTIFACTS_READ_RESOURCE-V1'=any(r.action_intent_ids)`,
          [
            participantId,
            actors.maker.principalId,
            privacyDomainId,
            input.semanticDocument.rpcPolicies[0].rules[0].requiredRoles[0],
          ],
        );
        assert.equal(grants.rowCount, 1, 'One current maker envelope must permit the Fact reader');
        authorityEnvelopeId = grants.rows[0].authority_envelope_id;
      } finally {
        await control.end();
      }
    }
    const scope = {
      privacyDomainIds: [privacyDomainId],
      actionIntentIds: [
        reader ? 'ACT-FACT_ARTIFACTS_READ_RESOURCE-V1' : 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',
      ],
      capabilityIds: [],
      // Public resource routes authorize their parsed UUID. The independent
      // workload Fact admission contract authorizes its canonical resource URN.
      resourceIds: [reader ? candidateId : `urn:openpc:resource:${candidateId}`],
      riskClasses: [reader ? 'LOW' : 'STANDARD'],
      makerCheckerRequired: reader,
      stepUpRequired: reader,
      onwardDelegationDepth: 0,
    };
    const filename = `${mode}-input.json`;
    const prior = await load(join(job, filename)).catch((error) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    });
    const body = JSON.parse(
      JSON.stringify(
        assignmentCreate.parse({
          assignmentId: reader ? (prior?.body.assignmentId ?? localOperationId()) : candidateId,
          principalId: reader ? actors.checker.principalId : discovery.principalId,
          roleId: input.semanticDocument.rpcPolicies[0].rules[0].requiredRoles[0],
          authorityEnvelopeId,
          scopeDigest: `sha256:${createHash('sha256').update(JSON.stringify(scope)).digest('hex')}`,
          ...scope,
          validFrom: prior?.body.validFrom ?? new Date().toISOString(),
          validUntil:
            prior?.body.validUntil ??
            (reader ? new Date(Date.now() + 86400000).toISOString() : factTrust.validUntil),
        }),
      ),
    );
    const candidate = assignmentCreateCandidate.parse({
      id: body.assignmentId,
      participantId,
      state: 'ACTIVE',
      delegationEpoch: '0',
      ...body,
    });
    const control = new Pool({
      host: '127.0.0.1',
      port: 55432,
      database: 'openpc_control',
      user: 'openpc_control',
      password: await password('control_pg_password.txt'),
      max: 1,
      options: '-c default_transaction_read_only=on',
    });
    try {
      const authority = await control.query(
        `select e.privacy_domain_ids,e.action_intent_ids,e.resource_ids,e.risk_classes,
         e.maker_checker_required,e.step_up_required,r.action_intent_ids role_actions,
         p.kind principal_kind,e.platform_context_id,e.platform_authority_epoch::text,e.valid_from,e.valid_until
         from control.authority_envelope e
         join control.authority_role r on r.participant_id=e.participant_id and r.role_id=$3
         join control.principal p on p.participant_id=e.participant_id and p.principal_id=$4
         where e.participant_id=$1 and e.authority_envelope_id=$2
           and e.state='ACTIVE' and r.state='ACTIVE' and p.state='ACTIVE'
           and e.valid_from<=clock_timestamp()
           and (e.valid_until is null or e.valid_until>clock_timestamp())`,
        [participantId, body.authorityEnvelopeId, body.roleId, body.principalId],
      );
      assert.equal(authority.rowCount, 1, 'One live role/envelope/principal intersection required');
      const row = authority.rows[0];
      for (const [field, granted] of [
        ['privacyDomainIds', row.privacy_domain_ids],
        ['actionIntentIds', row.action_intent_ids],
        ['actionIntentIds', row.role_actions],
        ['resourceIds', row.resource_ids],
        ['riskClasses', row.risk_classes],
      ])
        assert.ok(
          body[field].every((value) => granted.includes('*') || granted.includes(value)),
          `Grant stays inside ${field}`,
        );
      assert.ok(!row.maker_checker_required || body.makerCheckerRequired);
      assert.ok(!row.step_up_required || body.stepUpRequired);
      if (!reader) {
        assert.equal(row.principal_kind, 'WORKLOAD');
        assert.equal(row.platform_context_id, factTrust.platformContextId);
        assert.equal(row.valid_until?.toISOString(), factTrust.validUntil);
        assert.ok(Date.parse(body.validFrom) >= row.valid_from.getTime());
        assert.ok(Date.parse(body.validUntil) <= row.valid_until.getTime());
        assert.equal(row.platform_authority_epoch, '1');
      }
      assert.ok(
        Date.parse(body.validUntil) > Date.now() + 300000,
        'Grant must cover the next phase',
      );
    } finally {
      await control.end();
    }
    await immutable(filename, { body, candidate });
  }
} else if (mode === 'admission') {
  assert.equal(process.argv.length, 5, 'Session credentials must never be command arguments');
  const actors = await load(join(evidence, 'deployment-intent-actors.json'));
  const session = actors.maker.sessionToken,
    readerSession = actors.checker.sessionToken;
  assert.ok(session && readerSession);
  const csrfResponse = await fetch('http://127.0.0.1:8080/api/v1/session/csrf', {
    method: 'POST',
    headers: {
      'Cookie': `__Host-openpc_session=${session}`,
      'Content-Type': 'application/json',
      'Origin': 'http://127.0.0.1:8080',
    },
    body: JSON.stringify({ actionIntentId: 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1' }),
  });
  assert.equal(csrfResponse.status, 200);
  const { csrfToken: csrf } = await csrfResponse.json();
  assert.equal(typeof csrf, 'string');
  const { candidateId } = await load(join(job, 'candidate.json'));
  const origin = 'http://127.0.0.1:8080';
  const path = `${origin}/api/v1/fact-artifacts/urn:openpc:resource:${candidateId}`;
  const headers = () => ({
    'Cookie': `__Host-openpc_session=${readerSession}`,
    'OpenPC-API-Version': '1',
    'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
    'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
    'X-Request-ID': localOperationId(),
    'X-Correlation-ID': localOperationId(),
  });
  const selected = await fetch(path, { headers: headers() });
  const preview = await selected.json();
  assert.equal(selected.status, 200, JSON.stringify(preview));
  if (preview.state !== 'ADMITTED') {
    assert.equal(preview.state, 'CANDIDATE');
    await immutable('fact-preview.json', preview);
    const body = factArtifactUpdateSchema.parse({
      actionIntentId: 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',
      actionIntentDigest: factArtifactUpdateSchema.shape.actionIntentDigest.value,
      expectedRevision: preview.revision,
      replacementDigest: preview.artifactDigest,
      reason: 'Admit the acquired state of the exact governed RPC contract.',
    });
    await immutable('admission-input.json', body);
    const response = await fetch(path, {
      method: 'PATCH',
      headers: {
        ...headers(),
        'Cookie': `__Host-openpc_session=${session}`,
        'Origin': origin,
        'X-CSRF-Token': csrf,
        'Idempotency-Key': `rpc-fact-admission-${candidateId}`,
        'If-Match': selected.headers.get('etag'),
        'Content-Type': 'application/json',
        'OpenPC-Action-Intent-Digest': body.actionIntentDigest,
      },
      body: JSON.stringify(body),
    });
    const operation = await response.json();
    await save('admission-operation.json', operation);
    assert.equal(response.status, 202, JSON.stringify(operation));
    assert.equal(operation.state, 'SUCCEEDED');
  }
  const response = await fetch(path, { headers: headers() });
  const value = await response.json();
  assert.equal(response.status, 200);
  assert.equal(value.state, 'ADMITTED');
  await save('fact-readback.json', value);
} else throw new Error('Unsupported RPC Fact phase');
process.stdout.write(`OPENPC_RPC_FACT|PASS|${mode}|exact-scope|authoritative-owner\n`);
