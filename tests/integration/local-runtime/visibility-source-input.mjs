// Authored input for one publicly governed state acquisition; no business writes.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { visibilityAcquisitionReusable } from './visibility-source-custody.mjs';
import { Pool } from 'pg';
import { prepareVisibilityPolicy, visibilityReadAssignment } from './typed-visibility-policy.mjs';
import { pcCbor1 } from '../../../services/module-registry/src/domain/digest.ts';
import { validatePolicySemantics } from '../../../services/module-registry/src/domain/policy-semantics.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { factArtifactUpdateSchema } from '../../../services/control-api/src/configuration/resource-contracts.ts';
import { canonicalAbiBytes } from '../../../services/control-api/src/configuration/contract-assets.ts';

const [mode, root, evidence, target] = process.argv.slice(2);
const sourceKind = process.env.OPENPC_VISIBILITY_SOURCE_KIND ?? 'state';
assert.ok(['state', 'relationship'].includes(sourceKind), 'unsupported acquisition source kind');
const relationship = sourceKind === 'relationship';
const load = async (path) => JSON.parse(await readFile(path, 'utf8'));
const save = async (path, value, mode = 0o600) => {
  await writeFile(`${path}.next`, JSON.stringify(value), { mode });
  await rename(`${path}.next`, path);
};
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const workloadId = 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191';
const role = 'urn:openpc:role:018f0000-0000-7000-8000-000000000801';
const sources = join(root, 'data/provider-probe-source');
if (mode === 'visibility-assignment') {
  process.stdout.write(
    JSON.stringify(
      visibilityReadAssignment(
        await load(join(evidence, 'configuration-contract-binding-resource.json')),
      ),
    ),
  );
} else if (mode === 'reuse') {
  process.stdout.write(
    (await visibilityAcquisitionReusable(
      root,
      evidence,
      participantId,
      privacyDomainId,
      process.env.OPENPC_VISIBILITY_RENEW_FACT === '1'
        ? (process.env.OPENPC_VISIBILITY_SOURCE_GENERATION ?? '3')
        : undefined,
    ))
      ? 'REUSE\n'
      : 'REPLACE\n',
  );
} else if (
  ['assignment-readback', 'fact-assignment-readback', 'visibility-assignment-readback'].includes(
    mode,
  )
) {
  const candidateId =
    mode === 'fact-assignment-readback'
      ? (await load(join(evidence, 'acquisition/candidate.json'))).candidateId
      : undefined;
  const expected = await load(
    join(
      evidence,
      mode === 'assignment-readback'
        ? 'source-assignment.json'
        : mode === 'visibility-assignment-readback'
          ? 'visibility-read-assignment.json'
          : `fact-bound-assignment-${candidateId}.json`,
    ),
  );
  if (candidateId) {
    assert.equal(expected.id, candidateId);
    assert.deepEqual(expected.resourceIds, [`urn:openpc:resource:${candidateId}`]);
  }
  if (mode === 'visibility-assignment-readback') {
    const binding = await load(join(evidence, 'configuration-contract-binding-resource.json'));
    assert.deepEqual(expected.resourceIds, [binding.runtimeBindingId.split(':').at(-1)]);
    assert.deepEqual(expected.actionIntentIds, ['ACT-RUNTIME_READ_RPC-V1']);
  }
  const response = await fetch(
    `http://127.0.0.1:8080/v1/participants/${participantId}/assignments/${expected.id}`,
    {
      headers: {
        'authorization': `Bearer ${process.argv[6]}`,
        'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${privacyDomainId}`,
      },
      signal: AbortSignal.timeout(5_000),
    },
  );
  const current = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(current.effect, expected);
  assert.equal(current.effect.state, 'ACTIVE');
  assert.ok(Date.parse(current.effect.validUntil) > Date.now());
  await save(join(evidence, `${mode}.json`), current);
  if (mode === 'assignment-readback') {
    const configuration = await load(join(evidence, 'visibility-source-configuration.json'));
    assert.equal(
      `sha256:${createHash('sha256')
        .update(await readFile(join(sources, 'runtime-configuration.cbor')))
        .digest('hex')}`,
      configuration.configurationDigest,
    );
  }
  process.stdout.write(
    'OPENPC_SOURCE_ASSIGNMENT|PASS|public-current-readback|original-authored-input\n',
  );
} else if (mode === 'binding') {
  const prefix = relationship ? 'relationship' : 'configuration-contract';
  const binding = await load(join(evidence, `${prefix}-binding-resource.json`));
  const abi = await load(join(evidence, `${prefix}-abi-resource.json`));
  const value = {};
  for (const [output, input] of Object.entries({
    runtime_binding_id: 'runtimeBindingId',
    logical_contract_id: 'logicalContractId',
    chain_id: 'chainId',
    network_id: 'networkId',
    genesis_digest: 'genesisDigest',
    code_digest: 'codeDigest',
    contract_address: 'contractAddress',
    abi_digest: 'abiDigest',
    proxy_address: 'proxyAddress',
    implementation_address: 'implementationAddress',
    implementation_code_digest: 'implementationCodeDigest',
  }))
    value[output] = binding[input] ?? null;
  for (const key of ['runtime_binding_id', 'logical_contract_id'])
    value[key] = value[key].split(':').at(-1);
  const bytes = canonicalAbiBytes(abi.canonicalAbi);
  assert.equal(`sha256:${createHash('sha256').update(bytes).digest('hex')}`, binding.abiDigest);
  value.canonical_abi_hex = bytes.toString('hex');
  await save(join(sources, 'visibility-binding.json'), value, 0o444);
  await save(
    join(sources, 'visibility-acquisition.json'),
    {
      runtime_target_id: target,
      request: relationship
        ? {
            EventLogs: {
              contract_address: binding.contractAddress,
              event_name: 'RelationshipChanged',
              event_signature: '0xb1fad1cf1959b1f2ff99e75268b8f16a068328466f001adc4e591b68e642baf3',
            },
          }
        : {
            StateCall: {
              target_address: binding.contractAddress,
              calldata: `0x70a08231${'0'.repeat(24)}${'1'.repeat(40)}`,
            },
          },
      rate_limit: { window_ms: 60_000, maximum_requests: 24 },
    },
    0o444,
  );
} else if (mode === 'policy' || mode === 'policy-renewal') {
  await prepareVisibilityPolicy(join(root, 'secrets'), evidence);
  const input = await load(join(evidence, 'typed-policy-inputs.json'));
  const fixture = await load(join(evidence, 'visibility-source-configuration.json'));
  const source = (await load(join(evidence, 'configuration-indexer.json'))).resourceRef
    .split(':')
    .at(-1);
  const plan = (await load(join(evidence, 'configuration-projection.json'))).resourceRef
    .split(':')
    .at(-1);
  const rpc = {
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    rules: [relationship ? 'eth_getLogs' : 'eth_call', 'eth_getBlockByNumber(false)'].map(
      (method) => ({
        method,
        effect: 'ALLOW',
        requiredRoles: [role],
      }),
    ),
  };
  if (mode === 'policy-renewal')
    rpc.rules.push({ method: 'eth_sendRawTransaction', effect: 'DENY', requiredRoles: [] });
  const indexer = {
    schemaVersion: '1.0.0',
    participantId,
    privacyDomainId,
    workloadId,
    indexerProfileId: source,
    projectionPlanId: plan,
    profileArtifactDigest: fixture.indexerArtifactDigest,
    planArtifactDigest: fixture.projectionArtifactDigest,
    acquisitionConfigurationDigest: `sha256:${pcCbor1(['openpc:indexer-acquisition-configuration:v1', await load(join(sources, 'visibility-acquisition.json'))]).digest.toString('hex')}`,
    rpcPolicyDigest: `sha256:${pcCbor1(rpc).digest.toString('hex')}`,
    rangeStart: '10',
    rangeEnd: '12',
    maximumRangeBlocks: '3',
    maximumResponseBytes: 10000,
    rules: [relationship ? 'EVENT_LOG' : 'STATE_CALL', 'BLOCK_HEADER'].map((dataClass) => ({
      dataClass,
      effect: 'ALLOW',
      requiredRoles: [role],
    })),
  };
  Object.assign(input.semanticDocument, {
    visibilityPolicies: [],
    rpcPolicies: [rpc],
    indexerPolicies: [indexer],
  });
  input.semanticVersion =
    mode === 'policy-renewal'
      ? process.env.OPENPC_VISIBILITY_RENEW_FACT === '1'
        ? `10.2.${process.env.OPENPC_VISIBILITY_SOURCE_GENERATION ?? 3}`
        : '10.2.2'
      : '10.2.0';
  input.semanticDigest = `sha256:${validatePolicySemantics(input.semanticDocument).digest.toString('hex')}`;
  input.sourceRequest = {
    indexerProfileId: source,
    projectionPlanId: plan,
    dataClass: relationship ? 'EVENT_LOG' : 'STATE_CALL',
    rangeStart: '10',
    rangeEnd: '10',
    maximumResponseBytes: 10000,
  };
  delete input.visibilityRequest;
  await save(join(evidence, 'typed-policy-inputs.json'), input);
} else if (mode === 'reorg-config') {
  const config = await load(join(evidence, 'acquisition/config.json'));
  const publication = await load(join(evidence, 'acquisition/publication.json'));
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55434,
    database: 'openpc_candidate_index',
    user: 'openpc_candidate_index',
    password: (
      await readFile(join(root, 'secrets/candidate_index_pg_password.txt'), 'utf8')
    ).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  try {
    const result = await pool.query(
      `select batch_sequence::text,range_end::text,encode(batch_digest,'hex') digest,state::text
       from candidate.checkpoint where participant_id=$1 and privacy_domain_id=$2
       and projection_generation_id=$3 and candidate_partition_id=$4 order by batch_sequence desc limit 1`,
      [
        participantId,
        privacyDomainId,
        config.projection_generation_id,
        publication.candidate_partition_id,
      ],
    );
    assert.equal(result.rowCount, 1);
    const previous = result.rows[0];
    assert.equal(previous.state, 'COMPLETE');
    assert.equal(previous.batch_sequence, '1');
    assert.equal(previous.range_end, '10');
    await save(join(evidence, 'acquisition/reorg-config.json'), {
      ...config,
      operation_id: localOperationId(),
      correlation_id: localOperationId(),
      batch_id: 'visibility-observe-changed-predecessor',
      sequence: 2,
      predecessor_digest: `sha256:${previous.digest}`,
      range: { start: 11, end: 11 },
    });
  } finally {
    await pool.end();
  }
} else if (mode === 'acquisition' || mode === 'publication') {
  const secrets = join(root, 'secrets');
  const job = join(evidence, 'acquisition');
  await mkdir(job, { mode: 0o700, recursive: true });
  const password = async (name) => (await readFile(join(secrets, name), 'utf8')).trim();
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55434,
    database: 'openpc_candidate_index',
    user: 'openpc_candidate_index',
    password: await password('candidate_index_pg_password.txt'),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  let published;
  try {
    let result;
    for (let attempt = 0; attempt < 150; attempt++) {
      result = await pool.query(
        `select pub.projection_generation_id::text,cp.source_id,cp.partition_id,cp.candidate_partition_id::text from candidate.source_publication pub join candidate.candidate_partition cp using(participant_id,privacy_domain_id,projection_generation_id) where pub.participant_id=$1 and pub.privacy_domain_id=$2 and pub.state='PUBLISHED' and pub.configuration_digest=decode($3,'hex')`,
        [
          participantId,
          privacyDomainId,
          (
            await load(join(evidence, 'visibility-source-configuration.json'))
          ).configurationDigest.replace(/^sha256:/u, ''),
        ],
      );
      if (result.rowCount !== 0 || mode !== 'publication') break;
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    assert.equal(result.rowCount, 1);
    published = result.rows[0];
  } finally {
    await pool.end();
  }
  if (mode === 'publication') {
    process.stdout.write('OPENPC_SOURCE_PUBLICATION|PASS|exact-current-configuration\n');
    process.exit(0);
  }
  const key = createPrivateKey(
    await readFile(join(secrets, 'identity_mtls_rotated_key.pem')),
  ).export({ format: 'der', type: 'pkcs8' });
  await writeFile(join(job, 'key.pk8'), key, { mode: 0o600 });
  for (const [name, path] of [
    ['root', 'identity_mtls_ca.pem'],
    ['client', 'identity_mtls_rotated_cert.pem'],
  ])
    await writeFile(
      join(job, `${name}.der`),
      new X509Certificate(await readFile(join(secrets, path))).raw,
      { mode: 0o600 },
    );
  await writeFile(
    join(job, 'database-url'),
    `postgresql://openpc_indexer_writer:${encodeURIComponent(await password('indexer_writer_db_password.txt'))}@127.0.0.1:55434/openpc_candidate_index`,
    { mode: 0o600 },
  );
  await save(join(job, 'config.json'), {
    participant_id: participantId,
    privacy_domain_id: privacyDomainId,
    projection_generation_id: published.projection_generation_id,
    operation_id: localOperationId(),
    correlation_id: localOperationId(),
    source_id: published.source_id,
    partition_id: published.partition_id,
    batch_id: 'visibility-state-prerequisite',
    sequence: 1,
    predecessor_digest: 'GENESIS',
    range: { start: 10, end: 10 },
    runtime_target_id: target,
    candidate_database_url_file: join(job, 'database-url'),
    endpoint: {
      endpoint_id: target,
      normalized_uri: 'https://runtime.openpc.test:18545/',
      reference_identity: 'runtime.openpc.test',
      port: 18545,
      path: '/',
      dns_policy_ref: 'openpc-local-pinned-runtime',
      tls_policy_ref: 'openpc-local-runtime-ca',
      credential_ref: workloadId,
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
    server_certificate_digest: createHash('sha256')
      .update(
        new X509Certificate(await readFile(join(root, 'data/runtime/tls/protected-server.pem')))
          .raw,
      )
      .digest('hex'),
  });
  await save(join(job, 'publication.json'), published);
} else if (mode === 'candidate') {
  const publication = await load(join(evidence, 'acquisition/publication.json'));
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55434,
    database: 'openpc_candidate_index',
    user: 'openpc_candidate_index',
    password: (
      await readFile(join(root, 'secrets/candidate_index_pg_password.txt'), 'utf8')
    ).trim(),
    max: 1,
    options: '-c default_transaction_read_only=on',
  });
  let candidate;
  try {
    const result = await pool.query(
      'select candidate_event_id::text from candidate.candidate_event where participant_id=$1 and privacy_domain_id=$2 and projection_generation_id=$3 order by record_sequence',
      [participantId, privacyDomainId, publication.projection_generation_id],
    );
    const count = relationship && process.env.OPENPC_RELATIONSHIP_PHASE === 'closing' ? 2 : 1;
    const position = Number(process.env.OPENPC_VISIBILITY_CANDIDATE_POSITION ?? 0);
    assert.equal(result.rowCount, count);
    assert.ok(Number.isSafeInteger(position) && position >= 0 && position < count);
    candidate = result.rows[position].candidate_event_id;
  } finally {
    await pool.end();
  }
  await save(join(evidence, 'acquisition/candidate.json'), { candidateId: candidate });
} else if (mode === 'admission') {
  const [session, csrf, readerSession] = process.argv.slice(6);
  const digest = factArtifactUpdateSchema.shape.actionIntentDigest.value;
  const { candidateId: candidate } = await load(join(evidence, 'acquisition/candidate.json'));
  const origin = 'http://127.0.0.1:8080';
  const path = `${origin}/api/v1/fact-artifacts/urn:openpc:resource:${candidate}`;
  const headers = {
    'Cookie': `__Host-openpc_session=${readerSession}`,
    'OpenPC-API-Version': '1',
    'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
    'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
    'X-Request-ID': localOperationId(),
    'X-Correlation-ID': localOperationId(),
  };
  const selected = await fetch(path, { headers });
  const preview = await selected.json();
  assert.equal(selected.status, 200, JSON.stringify(preview));
  if (preview.state === 'ADMITTED') {
    await save(join(evidence, 'fact-public-readback.json'), preview);
    process.exit(0); // The caller still requires a fresh signed Fact-owner read.
  }
  assert.equal(preview.state, 'CANDIDATE');
  await save(join(evidence, 'fact-preview.json'), preview);
  const action = 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1';
  const response = await fetch(path, {
    method: 'PATCH',
    headers: {
      ...headers,
      'X-Request-ID': localOperationId(),
      'X-Correlation-ID': localOperationId(),
      'Cookie': `__Host-openpc_session=${session}`,
      'Origin': origin,
      'X-CSRF-Token': csrf,
      'Idempotency-Key': `visibility-fact-admission-${candidate}`,
      'If-Match': selected.headers.get('etag'),
      'Content-Type': 'application/json',
      'OpenPC-Action-Intent-Digest': digest,
    },
    body: JSON.stringify({
      actionIntentId: action,
      actionIntentDigest: digest,
      expectedRevision: preview.revision,
      replacementDigest: preview.artifactDigest,
      reason: 'Admit the publicly acquired anchored state prerequisite.',
    }),
  });
  const operation = await response.json();
  await save(join(evidence, 'fact-admission.json'), operation);
  assert.equal(response.status, 202, JSON.stringify(operation));
  assert.equal(operation.state, 'SUCCEEDED');
  const readyResponse = await fetch(path, {
    headers: {
      ...headers,
      'X-Request-ID': localOperationId(),
      'X-Correlation-ID': localOperationId(),
    },
  });
  const ready = await readyResponse.json();
  assert.equal(readyResponse.status, 200, JSON.stringify(ready));
  assert.equal(ready.state, 'ADMITTED');
  await save(join(evidence, 'fact-public-readback.json'), ready);
} else throw new Error('Unknown visibility source input mode');
