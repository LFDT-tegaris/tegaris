import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { businessTransitionProfiles } from '../../../packages/security-kernel/src/business-transition/profiles.generated.ts';
import {
  businessSigningTrustDigest,
  businessSigningTrustPreimage,
} from '../../../packages/security-kernel/src/business-transition/signing-trust.ts';
import { evidenceKeyId } from '../../../packages/security-kernel/src/business-transition/cose.ts';

import { createHttpBusinessSigningProvider } from '../../../services/identity-service/src/domain/http-business-signing-provider.ts';
import {
  businessProviderDescriptorSchema,
  businessSigningPurpose,
  validateBusinessProviderObservation,
} from '../../../services/identity-service/src/domain/business-signing-provider.ts';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.ts';
import { installInitialFleetConsumerProfile } from './fact-consumer-bootstrap.ts';
import { installInitialFleetFailureSigner } from './fact-failure-bootstrap.ts';
import {
  rpcRetirementSigningFamilies,
  rpcRetirementSigningWorkload,
  rpcRetirementSigningProfiles,
  projectionDeletionSigningProfiles,
  verifyRetainedRpcRetirementSelection,
  verifyUnproposedRetirementTrust,
} from './rpc-retirement-signing.ts';

import {
  runtimeSourceSigningFamilies,
  runtimeSourceSigningProfiles,
  runtimeSourceSigningName,
} from './runtime-source-disposition-signing.ts';

// Establish only initial identities/public signing trust, never approvals, receipts or business effects.
const [secretRoot, participantId, privacyDomainId, mode] = process.argv.slice(2);
assert.ok(
  mode === undefined ||
    mode === '--catalog-check' ||
    mode === '--hold-trust' ||
    mode === '--source-hold-trust' ||
    mode === '--raw-deletion-trust' ||
    mode === '--projection-deletion-trust' ||
    mode === '--rpc-retirement-trust' ||
    mode === '--store-retirement-trust' ||
    mode === '--work-item-trust' ||
    mode === '--participant-hold-trust' ||
    mode === '--retention-trust' ||
    mode === '--deletion-scope-trust' ||
    mode === '--deletion-batch-trust' ||
    mode === '--runtime-scope-trust' ||
    mode === '--runtime-source-disposition-trust' ||
    mode === '--rejection-deletion-trust',
);
const workItem = mode === '--work-item-trust';
const storeRetirement = mode === '--store-retirement-trust';
const rpcRetirement = mode === '--rpc-retirement-trust';
const projectionDeletion = mode === '--projection-deletion-trust';
const rawDeletion = mode === '--raw-deletion-trust';
const deletionScope = mode === '--deletion-scope-trust';
const deletionBatch = mode === '--deletion-batch-trust';
const rejectionDeletion = mode === '--rejection-deletion-trust';
const runtimeSource = mode === '--runtime-source-disposition-trust';
const runtimeScope = mode === '--runtime-scope-trust';
const participantHold = mode === '--participant-hold-trust';
const scopedParticipantHold =
  participantHold && privacyDomainId !== '018f0000-0000-7000-8000-000000000201';
const sourceHold = mode === '--source-hold-trust';
if (
  runtimeSource ||
  runtimeScope ||
  scopedParticipantHold ||
  sourceHold ||
  rawDeletion ||
  projectionDeletion ||
  rpcRetirement ||
  storeRetirement ||
  workItem
) {
  assert.match(
    privacyDomainId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  // Canonical Fact evidence can originate in the root context. Projection
  // bootstrap below reuses each complete retained signing family exactly.
  if (!projectionDeletion && !rpcRetirement)
    assert.notEqual(privacyDomainId, '018f0000-0000-7000-8000-000000000201');
}
if (deletionScope || deletionBatch)
  assert.equal(privacyDomainId, '018f0000-0000-7000-8000-000000004201');
const initialFamily = runtimeSource
  ? 'runtime-artifact-disposition'
  : workItem
    ? 'work-item'
    : storeRetirement
      ? 'store-retirement'
      : deletionScope ||
          deletionBatch ||
          rejectionDeletion ||
          rawDeletion ||
          projectionDeletion ||
          rpcRetirement
        ? 'evidence-deletion'
        : participantHold
          ? 'evidence-participant-hold'
          : mode === '--hold-trust' || sourceHold
            ? 'evidence-hold'
            : mode === '--retention-trust'
              ? 'retention-policy'
              : undefined;
const pool = new Pool({
  ...(process.env.OPENPC_SIGNING_BOOTSTRAP_DATABASE_URL
    ? { connectionString: process.env.OPENPC_SIGNING_BOOTSTRAP_DATABASE_URL }
    : {
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: 'openpc_control',
        password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
      }),
  max: 1,
});
async function insertProfiles(client) {
  for (const profile of businessTransitionProfiles.filter(
    (profile) =>
      (runtimeScope
        ? ['indexer-profile', 'module-registration'].includes(profile.aggregateType)
        : initialFamily === undefined) ||
      profile.aggregateType === initialFamily ||
      (runtimeSource &&
        runtimeSourceSigningFamilies.some((family) =>
          family.profileIds.includes(profile.profileId),
        )) ||
      (storeRetirement && profile.aggregateType === 'retention-policy') ||
      (participantHold && profile.profileId.startsWith('pc.control.evidence-participant-hold.')) ||
      ((deletionScope || rawDeletion || projectionDeletion) &&
        ['evidence-hold', 'retention-policy'].includes(profile.aggregateType)),
  )) {
    if (
      workItem ||
      storeRetirement ||
      deletionScope ||
      rawDeletion ||
      projectionDeletion ||
      rpcRetirement ||
      deletionBatch ||
      rejectionDeletion ||
      runtimeSource ||
      runtimeScope ||
      participantHold ||
      sourceHold
    ) {
      const existing = await client.query(
        `select profile_digest,schema_definition_digest,definition_canonical_json,action_intent_id,
          catalog_operation_id,resource_type,aggregate_type,sequence_namespace,transition_kind
         from control.business_transition_profile where profile_id=$1 and profile_version=$2`,
        [profile.profileId, profile.profileVersion],
      );
      if (existing.rowCount) {
        assert.equal(existing.rowCount, 1);
        assert.deepEqual(
          existing.rows[0],
          {
            profile_digest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
            schema_definition_digest: Buffer.from(profile.schemaDefinitionDigest.slice(7), 'hex'),
            definition_canonical_json: Buffer.from(profile.definitionCanonicalJson),
            action_intent_id: profile.actionIntentId,
            catalog_operation_id: profile.catalogOperationId,
            resource_type: profile.resourceType,
            aggregate_type: profile.aggregateType,
            sequence_namespace: profile.sequenceNamespace,
            transition_kind: profile.transitionKind,
          },
          'Existing global profile must match its complete canonical definition',
        );
        continue;
      }
    }
    await client.query(
      `insert into control.business_transition_profile(profile_id,profile_version,profile_digest,schema_definition_digest,
   definition_canonical_json,action_intent_id,catalog_operation_id,resource_type,aggregate_type,sequence_namespace,transition_kind)
   values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        profile.profileId,
        profile.profileVersion,
        Buffer.from(profile.profileDigest.slice(7), 'hex'),
        Buffer.from(profile.schemaDefinitionDigest.slice(7), 'hex'),
        Buffer.from(profile.definitionCanonicalJson),
        profile.actionIntentId,
        profile.catalogOperationId,
        profile.resourceType,
        profile.aggregateType,
        profile.sequenceNamespace,
        profile.transitionKind,
      ],
    );
  }
}

async function requireUnproposedRetirementTrust(profiles) {
  const { rows } = await client.query(
    `select exists(select 1 from control.mutation_candidate
      where participant_id=$1 and privacy_domain_id=$2 and catalog_operation_id=any($3::text[])) has_candidates`,
    [
      participantId,
      privacyDomainId,
      [...new Set(profiles.map((profile) => profile.catalogOperationId))],
    ],
  );
  verifyUnproposedRetirementTrust(rows);
}

// Run against the migrated initial-trust store before paying for application startup.
// Inserting the actual definitions tests foreign keys and all database constraints.
if (mode === '--catalog-check') {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await insertProfiles(client);
    const actions = [
      'ACT-MODULES_CREATE_RESOURCE-V1',
      'ACT-MODULE_CREATE_INSTALL-V1',
      'ACT-MODULE_ACTIVATE_RESOURCE-V1',
    ];
    const capabilities = (
      await client.query(
        `
      select count(*)::int count from control.assignment a
      join control.authority_envelope e using(participant_id,authority_envelope_id)
      cross join unnest($2::text[]) required(action)
      where a.participant_id=$1 and a.assignment_id in
       ('018f0000-0000-7000-8000-000000000122','018f0000-0000-7000-8000-000000000132')
       and a.state='ACTIVE' and e.state='ACTIVE'
       and required.action=any(a.action_intent_ids) and required.action=any(e.action_intent_ids)
       and (a.role_id is null or exists(select 1 from control.authority_role r
        where r.participant_id=a.participant_id and r.role_id=a.role_id and r.state='ACTIVE'
          and required.action=any(r.action_intent_ids)))`,
        [participantId, actions],
      )
    ).rows[0].count;
    assert.equal(capabilities, 6, 'module initial authority is complete and role-bound');
    const reads = [
      'ACT-FACT_ARTIFACTS_READ_COLLECTION-V1',
      'ACT-FACT_ARTIFACTS_READ_RESOURCE-V1',
      'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
      'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
    ];
    const paths = await client.query(
      `select required.action,count(*)::int count from control.assignment a
       join control.authority_envelope e using(participant_id,authority_envelope_id)
       cross join unnest($2::text[]) required(action)
       where a.participant_id=$1 and a.principal_id='018f0000-0000-7000-8000-000000000111'
        and a.state='ACTIVE' and e.state='ACTIVE' and a.valid_during @> clock_timestamp()
        and required.action=any(a.action_intent_ids) and required.action=any(e.action_intent_ids)
        and openpc.assignment_role_permits(a.participant_id,a.role_id,required.action)
       group by required.action order by required.action`,
      [participantId, reads],
    );
    assert.deepEqual(
      paths.rows,
      reads.sort().map((action) => ({ action, count: 1 })),
      'dedicated catalogue reads require exactly one initial authority path',
    );
  } finally {
    await client.query('rollback');
    client.release();
    await pool.end();
  }
  process.stdout.write(
    'OPENPC_BUSINESS_CATALOG_PREFLIGHT|PASS|actual-profile-inserts|initial-module-authority|unique-read-authority|rolled-back\n',
  );
  process.exit(0);
}
const transportRoot = rpcRetirement ? join(secretRoot, 'rpc-retirement-transport') : secretRoot;
const provider = createHttpBusinessSigningProvider({
  origin: process.env.OPENPC_SIGNING_BOOTSTRAP_PROVIDER_ORIGIN ?? 'https://127.0.0.1:53007',
  trustCa: await readFile(join(transportRoot, 'business_provider_ca.pem')),
  certificate: await readFile(join(transportRoot, 'business_api_cert.pem')),
  privateKey: await readFile(join(transportRoot, 'business_api_key.pem')),
});
const client = await pool.connect();
try {
  const businessKeyName = rpcRetirement
    ? `control_rpc_retirement_${privacyDomainId}_local-v2_signing`
    : runtimeScope
      ? `control_runtime_scope_${privacyDomainId}_signing`
      : 'control_business_signing';
  const publicKeySpkiDer = await readFile(join(secretRoot, `${businessKeyName}_public_key.der`));
  const authenticationKey = await readFile(
    join(secretRoot, 'identity_runtime_signing_public_key.der'),
  );
  assert.notDeepEqual(
    publicKeySpkiDer,
    authenticationKey,
    'business and authentication signing keys are separate',
  );
  const descriptor = businessProviderDescriptorSchema.parse(
    JSON.parse(await readFile(join(secretRoot, `${businessKeyName}_descriptor.json`), 'utf8')),
  );
  const inspect = {
    participantId,
    privacyDomainId: descriptor.privacyDomainId,
    environmentId: 'local',
    workloadCredentialId: descriptor.workloadCredentialId,
    callerWorkloadCredentialId: descriptor.workloadCredentialId,
    secretClass: 'SECRET-SIGNING-KEY',
    purpose: businessSigningPurpose,
    reference: descriptor.reference,
    version: descriptor.version,
    attemptId: localOperationId(),
    operationId: localOperationId(),
    method: 'INSPECT',
  };
  const inspected = await provider.perform(inspect);
  validateBusinessProviderObservation(inspect, inspected);
  assert.deepEqual(
    inspected.descriptor,
    descriptor,
    'provider public truth matches externally pinned first trust',
  );
  assert.equal(descriptor.publicKeySpkiHex, publicKeySpkiDer.toString('hex'));
  await client.query('begin');
  if (scopedParticipantHold) {
    const { rows } = await client.query(
      `select p.root_privacy_domain_id=$2::uuid as root_matches,
        (select count(*)::int from control.business_signing_selection s
          join control.business_transition_profile profile using(profile_digest)
          where s.participant_id=p.participant_id and s.privacy_domain_id=$2
          and s.environment_id='local'
          and starts_with(profile.profile_id,'pc.control.evidence-participant-hold.')) selected,
        exists(select 1 from control.mutation_candidate c where c.participant_id=p.participant_id
          and c.privacy_domain_id=$2) as has_candidates
       from control.participant p where p.participant_id=$1 and p.state='ACTIVE'`,
      [participantId, privacyDomainId],
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0].root_matches, true, 'Participant preservation trust requires actual root');
    assert.ok([0, 2].includes(rows[0].selected), 'Partial initial trust requires diagnosis');
    assert.ok(
      rows[0].selected === 2 || !rows[0].has_candidates,
      'Missing initial trust cannot be retrofitted after business proposals',
    );
  }
  const now = (
    await client.query(
      `select (floor(extract(epoch from clock_timestamp())*1000000)*1000)::text ns`,
    )
  ).rows[0].ns;
  const workloadCredentialId = rpcRetirement
    ? rpcRetirementSigningWorkload.credentialId
    : '018f0000-0000-7000-8000-000000000195';
  for (const [name, principalId, credentialId, workloadId] of rpcRetirement
    ? [
        [
          'api',
          rpcRetirementSigningWorkload.principalId,
          rpcRetirementSigningWorkload.credentialId,
          rpcRetirementSigningWorkload.workloadId,
        ],
      ]
    : [
        [
          'api',
          '018f0000-0000-7000-8000-000000000194',
          workloadCredentialId,
          '018f0000-0000-7000-8000-000000000196',
        ],
        [
          'worker',
          '018f0000-0000-7000-8000-000000000197',
          '018f0000-0000-7000-8000-000000000198',
          '018f0000-0000-7000-8000-000000000199',
        ],
      ]) {
    if (initialFamily !== undefined && !rpcRetirement && !runtimeSource) continue;
    const certificate = new X509Certificate(
      await readFile(join(transportRoot, `business_${name}_cert.pem`)),
    );
    if (runtimeScope || rpcRetirement || runtimeSource) {
      const existing = await client.query(
        `select c.principal_id,c.public_key_digest,c.public_key_spki_der,c.secret_fingerprint,c.subject,c.audience
         from control.credential c join control.principal p using(participant_id,principal_id)
         where c.participant_id=$1 and c.credential_id=$2 and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE'
           and c.credential_epoch=1 and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()+interval '2 minutes'
           and p.kind='WORKLOAD' and p.state='ACTIVE' and p.authority_epoch=1`,
        [participantId, credentialId],
      );
      const spki = certificate.publicKey.export({ type: 'spki', format: 'der' });
      if (runtimeScope || runtimeSource || existing.rowCount) {
        assert.equal(existing.rowCount, 1, 'Reuse requires a current pinned signing workload');
        assert.deepEqual(existing.rows[0], {
          principal_id: principalId,
          public_key_digest: createHash('sha256').update(spki).digest(),
          public_key_spki_der: spki,
          secret_fingerprint: createHash('sha256').update(certificate.raw).digest(),
          subject: `urn:openpc:participant:${participantId}:workload:${workloadId}`,
          audience: `urn:openpc:workload:${workloadId}`,
        });
        continue;
      }
      // Existing revoked/expired or mismatched identities are never replaced.
      const occupied = await client.query(
        'select 1 from control.credential where participant_id=$1 and credential_id=$2',
        [participantId, credentialId],
      );
      assert.equal(occupied.rowCount, 0, 'Retained workload identity requires diagnosis');
    }
    await client.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD',$3,'ACTIVE',1)`,
      [
        principalId,
        participantId,
        `${rpcRetirement ? 'Local RPC retirement signing' : 'Local business signing'} ${name} workload`,
      ],
    );
    await client.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,state,credential_epoch,valid_from,valid_until,public_key_spki_der,secret_fingerprint)
      values($1,$2,$3,'WORKLOAD_MTLS','urn:openpc:local-signing-provider-ca',$4,$5,$6,'ACTIVE',1,$7,$8,$9,$10)`,
      [
        credentialId,
        participantId,
        principalId,
        `urn:openpc:participant:${participantId}:workload:${workloadId}`,
        `urn:openpc:workload:${workloadId}`,
        createHash('sha256')
          .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
          .digest(),
        new Date(certificate.validFrom).toISOString(),
        new Date(certificate.validTo).toISOString(),
        certificate.publicKey.export({ type: 'spki', format: 'der' }),
        createHash('sha256').update(certificate.raw).digest(),
      ],
    );
  }
  if (initialFamily === undefined) {
    await installInitialFleetConsumerProfile(client, participantId, privacyDomainId);
    await installInitialFleetFailureSigner(client, secretRoot, participantId, privacyDomainId);
  }
  await insertProfiles(client);
  const lifecycleDescriptor = businessProviderDescriptorSchema.parse(
    JSON.parse(
      await readFile(join(secretRoot, 'control_lifecycle_signing_descriptor.json'), 'utf8'),
    ),
  );
  const lifecyclePublic = await readFile(
    join(secretRoot, 'control_lifecycle_signing_public_key.der'),
  );
  assert.notDeepEqual(lifecyclePublic, publicKeySpkiDer);
  assert.notDeepEqual(lifecyclePublic, authenticationKey);
  const holdKeyName = sourceHold
    ? `control_source_hold_scope_${privacyDomainId}_signing`
    : 'control_hold_signing';
  const holdDescriptor = businessProviderDescriptorSchema.parse(
    JSON.parse(await readFile(join(secretRoot, `${holdKeyName}_descriptor.json`), 'utf8')),
  );
  const holdPublic = await readFile(join(secretRoot, `${holdKeyName}_public_key.der`));
  assert.notDeepEqual(holdPublic, publicKeySpkiDer);
  assert.notDeepEqual(holdPublic, lifecyclePublic);
  assert.notDeepEqual(holdPublic, authenticationKey);
  const participantHoldKeyName = scopedParticipantHold
    ? `control_participant_hold_${privacyDomainId}_signing`
    : 'control_participant_hold_signing';
  const participantHoldDescriptor =
    (initialFamily === undefined && !runtimeScope) || participantHold
      ? businessProviderDescriptorSchema.parse(
          JSON.parse(
            await readFile(join(secretRoot, `${participantHoldKeyName}_descriptor.json`), 'utf8'),
          ),
        )
      : undefined;
  const participantHoldPublic = participantHoldDescriptor
    ? await readFile(join(secretRoot, `${participantHoldKeyName}_public_key.der`))
    : undefined;
  if (participantHoldPublic)
    for (const prior of [authenticationKey, publicKeySpkiDer, lifecyclePublic, holdPublic])
      assert.notDeepEqual(participantHoldPublic, prior);
  const retentionDescriptor =
    initialFamily === 'evidence-hold'
      ? undefined
      : businessProviderDescriptorSchema.parse(
          JSON.parse(
            await readFile(join(secretRoot, 'control_retention_signing_descriptor.json'), 'utf8'),
          ),
        );
  const retentionPublic = retentionDescriptor
    ? await readFile(join(secretRoot, 'control_retention_signing_public_key.der'))
    : undefined;
  if (retentionPublic)
    for (const key of [publicKeySpkiDer, lifecyclePublic, holdPublic, authenticationKey])
      assert.notDeepEqual(retentionPublic, key);
  const notificationTrusts = [];
  if (initialFamily === undefined && !runtimeScope) {
    const notificationDescriptor = businessProviderDescriptorSchema.parse(
      JSON.parse(
        await readFile(join(secretRoot, 'control_notification_signing_descriptor.json'), 'utf8'),
      ),
    );
    const notificationPublic = await readFile(
      join(secretRoot, 'control_notification_signing_public_key.der'),
    );
    for (const prior of [
      authenticationKey,
      publicKeySpkiDer,
      lifecyclePublic,
      holdPublic,
      retentionPublic,
    ])
      assert.notDeepEqual(notificationPublic, prior);
    notificationTrusts.push({
      descriptor: notificationDescriptor,
      publicKeySpkiDer: notificationPublic,
      profilePrefixes: ['pc.control.notification.'],
      admissionReference: 'OpenPC local initial notification metadata signing trust',
    });
  }
  const workItemTrusts = [];
  if (
    workItem ||
    (initialFamily === undefined &&
      !runtimeScope &&
      process.env.OPENPC_LOCAL_RUNTIME_WORK_ITEM_BROWSER_ONLY === '1')
  ) {
    const descriptor = businessProviderDescriptorSchema.parse(
      JSON.parse(
        await readFile(
          join(
            secretRoot,
            `${workItem ? `control_work_item_${privacyDomainId}_signing` : 'control_work_item_signing'}_descriptor.json`,
          ),
          'utf8',
        ),
      ),
    );
    const workItemPublic = await readFile(
      join(
        secretRoot,
        `${workItem ? `control_work_item_${privacyDomainId}_signing` : 'control_work_item_signing'}_public_key.der`,
      ),
    );
    for (const prior of [
      publicKeySpkiDer,
      authenticationKey,
      lifecyclePublic,
      holdPublic,
      retentionPublic,
      ...notificationTrusts.map((trust) => trust.publicKeySpkiDer),
    ])
      assert.notDeepEqual(workItemPublic, prior);
    assert.deepEqual(
      businessTransitionProfiles
        .filter((profile) => profile.profileId.startsWith('pc.control.work-item.'))
        .map((profile) => profile.catalogOperationId)
        .sort(),
      [
        'CFG-OP-CLAIM-WORK-ITEM',
        'CFG-OP-COMPLETE-WORK-ITEM',
        'CFG-OP-CREATE-WORK-ITEM',
        'CFG-OP-UPDATE-WORK-ITEM',
      ],
    );
    workItemTrusts.push({
      descriptor,
      publicKeySpkiDer: workItemPublic,
      profilePrefixes: ['pc.control.work-item.'],
      admissionReference: 'OpenPC local initial work-item evidence signing trust',
    });
  }
  let initialTrusts = [
    ...workItemTrusts,
    ...notificationTrusts,
    {
      descriptor,
      publicKeySpkiDer,
      profilePrefixes: ['pc.control.indexer-profile.', 'pc.control.module.'],
      admissionReference: 'OpenPC local first business signing trust',
    },
    {
      descriptor: lifecycleDescriptor,
      publicKeySpkiDer: lifecyclePublic,
      profilePrefixes: ['pc.control.signing-rotation.'],
      admissionReference: 'OpenPC local initial lifecycle evidence signing trust',
    },
    {
      descriptor: holdDescriptor,
      publicKeySpkiDer: holdPublic,
      profilePrefixes: ['pc.control.evidence-hold.'],
      admissionReference: 'OpenPC local first evidence hold signing trust',
    },
    ...(participantHoldDescriptor
      ? [
          {
            descriptor: participantHoldDescriptor,
            publicKeySpkiDer: participantHoldPublic,
            profilePrefixes: ['pc.control.evidence-participant-hold.'],
            admissionReference: 'OpenPC local first Participant preservation signing trust',
          },
        ]
      : []),
    ...(retentionDescriptor
      ? [
          {
            descriptor: retentionDescriptor,
            publicKeySpkiDer: retentionPublic,
            profilePrefixes: ['pc.control.retention-policy.'],
            admissionReference: 'OpenPC local first retention policy signing trust',
          },
        ]
      : []),
  ].filter((trust) =>
    workItem
      ? trust.descriptor === workItemTrusts[0]?.descriptor
      : runtimeScope
        ? trust.descriptor === descriptor
        : initialFamily === undefined ||
          (participantHold
            ? trust.descriptor === participantHoldDescriptor
            : initialFamily === 'evidence-hold'
              ? trust.descriptor === holdDescriptor
              : trust.descriptor === retentionDescriptor),
  );
  if (deletionScope || deletionBatch || rawDeletion || projectionDeletion || storeRetirement) {
    initialTrusts = [];
    const seenKeys = [
      authenticationKey,
      publicKeySpkiDer,
      lifecyclePublic,
      holdPublic,
      retentionPublic,
    ];
    for (const [family, prefix] of storeRetirement
      ? [
          ['store-retirement', 'store-retirement.'],
          ['retention', 'retention-policy.'],
        ]
      : projectionDeletion
        ? [
            ['hold', 'evidence-hold.'],
            ['retention', 'retention-policy.'],
            ['deletion-local', 'evidence-deletion.local'],
            ['deletion-projection', 'evidence-deletion.projection'],
          ]
        : rawDeletion
          ? [
              ['hold', 'evidence-hold.'],
              ['retention', 'retention-policy.'],
              ['deletion', 'evidence-deletion.raw-proof'],
            ]
          : deletionBatch
            ? [['deletion-batch', 'evidence-deletion.batch']]
            : [
                ['hold', 'evidence-hold.'],
                ['retention', 'retention-policy.'],
                ['deletion', 'evidence-deletion.local'],
              ]) {
      if ((rawDeletion && family !== 'deletion') || projectionDeletion || storeRetirement) {
        const expected = projectionDeletion
          ? projectionDeletionSigningProfiles(family)
          : businessTransitionProfiles.filter((profile) =>
              profile.profileId.startsWith(`pc.control.${prefix}`),
            );
        const retained = await client.query(
          `select p.profile_id,p.profile_version::text profile_version,p.profile_digest,k.state,key.workload_credential_id
           from control.business_signing_selection s join control.business_transition_profile p using(profile_digest)
           join control.business_signing_key_state k using(participant_id,privacy_domain_id,signer_id)
           join control.business_signing_key key using(participant_id,privacy_domain_id,signer_id)
           where s.participant_id=$1 and s.privacy_domain_id=$2 and s.environment_id='local' and starts_with(p.profile_id,$3)
            ${projectionDeletion ? 'and p.profile_digest=any($4::bytea[])' : ''}`,
          [
            participantId,
            privacyDomainId,
            `pc.control.${prefix}`,
            ...(projectionDeletion
              ? [expected.map((profile) => Buffer.from(profile.profileDigest.slice(7), 'hex'))]
              : []),
          ],
        );
        if (retained.rowCount) {
          assert.equal(
            retained.rowCount,
            expected.length,
            'Reuse requires the complete existing family',
          );
          for (const profile of expected) {
            const rows = retained.rows.filter(
              (r) =>
                r.profile_id === profile.profileId &&
                r.profile_version === String(profile.profileVersion),
            );
            assert.equal(rows.length, 1);
            assert.equal(rows[0].state, 'ACTIVE');
            if (projectionDeletion)
              assert.equal(rows[0].workload_credential_id, workloadCredentialId);
            assert.equal(`sha256:${rows[0].profile_digest.toString('hex')}`, profile.profileDigest);
          }
          continue;
        }
        if (projectionDeletion) await requireUnproposedRetirementTrust(expected);
      }
      const descriptor = businessProviderDescriptorSchema.parse(
        JSON.parse(
          await readFile(
            join(
              secretRoot,
              storeRetirement
                ? `control_store_retirement_${privacyDomainId}${family === 'retention' ? '_retention' : ''}_signing_descriptor.json`
                : projectionDeletion
                  ? `control_projection_deletion_${privacyDomainId}_${family}_signing_descriptor.json`
                  : rawDeletion
                    ? `control_raw_deletion_${privacyDomainId}_${family}_signing_descriptor.json`
                    : `control_deletion_scope_${family}_signing_descriptor.json`,
            ),
            'utf8',
          ),
        ),
      );
      const publicKeySpkiDer = await readFile(
        join(
          secretRoot,
          storeRetirement
            ? `control_store_retirement_${privacyDomainId}${family === 'retention' ? '_retention' : ''}_signing_public_key.der`
            : projectionDeletion
              ? `control_projection_deletion_${privacyDomainId}_${family}_signing_public_key.der`
              : rawDeletion
                ? `control_raw_deletion_${privacyDomainId}_${family}_signing_public_key.der`
                : `control_deletion_scope_${family}_signing_public_key.der`,
        ),
      );
      assert.equal(descriptor.publicKeySpkiHex, publicKeySpkiDer.toString('hex'));
      for (const previous of seenKeys) assert.notDeepEqual(publicKeySpkiDer, previous);
      seenKeys.push(publicKeySpkiDer);
      initialTrusts.push({
        descriptor,
        publicKeySpkiDer,
        profilePrefixes: projectionDeletion ? [] : [`pc.control.${prefix}`],
        ...(projectionDeletion ? { exactProfiles: projectionDeletionSigningProfiles(family) } : {}),
        admissionReference: `OpenPC isolated local deletion scope ${family} initial signing trust`,
      });
    }
  }
  if (runtimeSource) {
    initialTrusts = [];
    const seenKeys = [
      authenticationKey,
      publicKeySpkiDer,
      lifecyclePublic,
      holdPublic,
      retentionPublic,
    ];
    for (const { family } of runtimeSourceSigningFamilies) {
      const name = runtimeSourceSigningName(privacyDomainId, family);
      const descriptor = businessProviderDescriptorSchema.parse(
        JSON.parse(await readFile(join(secretRoot, `${name}_descriptor.json`), 'utf8')),
      );
      const publicKeySpkiDer = await readFile(join(secretRoot, `${name}_public_key.der`));
      assert.equal(descriptor.publicKeySpkiHex, publicKeySpkiDer.toString('hex'));
      for (const prior of seenKeys) assert.notDeepEqual(publicKeySpkiDer, prior);
      seenKeys.push(publicKeySpkiDer);
      initialTrusts.push({
        descriptor,
        publicKeySpkiDer,
        profilePrefixes: [],
        exactProfiles: runtimeSourceSigningProfiles(family),
        admissionReference: `OpenPC isolated runtime source ${family} initial signing trust`,
      });
    }
  }
  if (rpcRetirement) {
    initialTrusts = [];
    const seenKeys = [
      authenticationKey,
      await readFile(join(secretRoot, 'control_business_signing_public_key.der')),
      lifecyclePublic,
      holdPublic,
      retentionPublic,
    ];
    for (const { family, profileId, profileVersion } of rpcRetirementSigningFamilies) {
      const name = `control_rpc_retirement_${privacyDomainId}_${family}_signing`;
      const descriptor = businessProviderDescriptorSchema.parse(
        JSON.parse(await readFile(join(secretRoot, `${name}_descriptor.json`), 'utf8')),
      );
      const publicKeySpkiDer = await readFile(join(secretRoot, `${name}_public_key.der`));
      assert.equal(descriptor.publicKeySpkiHex, publicKeySpkiDer.toString('hex'));
      const retained = await client.query(
        `select p.profile_id,p.profile_version::text profile_version,p.profile_digest,k.state,
          s.participant_id,s.privacy_domain_id,s.environment_id,s.signer_id,
          key.workload_credential_id,key.public_key_spki_der,key.secret_reference,key.secret_version,
          key.valid_from_ns::text valid_from_ns,key.valid_until_ns::text valid_until_ns
         from control.business_signing_selection s join control.business_transition_profile p using(profile_digest)
         join control.business_signing_key_state k using(participant_id,privacy_domain_id,signer_id)
         join control.business_signing_key key using(participant_id,privacy_domain_id,signer_id)
         where s.participant_id=$1 and s.privacy_domain_id=$2 and s.environment_id='local'
          and p.profile_id=$3 and p.profile_version=$4`,
        [participantId, privacyDomainId, profileId, profileVersion],
      );
      if (verifyRetainedRpcRetirementSelection(family, retained.rows, descriptor)) continue;
      await requireUnproposedRetirementTrust(rpcRetirementSigningProfiles(family));
      for (const previous of seenKeys) assert.notDeepEqual(publicKeySpkiDer, previous);
      seenKeys.push(publicKeySpkiDer);
      initialTrusts.push({
        descriptor,
        publicKeySpkiDer,
        profilePrefixes: [],
        exactProfiles: rpcRetirementSigningProfiles(family),
        admissionReference: `OpenPC isolated local RPC retirement ${family} initial signing trust`,
      });
    }
  }
  if (rejectionDeletion) {
    assert.equal(privacyDomainId, '018f0000-0000-7000-8000-000000000201');
    const descriptor = businessProviderDescriptorSchema.parse(
      JSON.parse(
        await readFile(
          join(secretRoot, 'control_evidence_deletion_signing_descriptor.json'),
          'utf8',
        ),
      ),
    );
    const publicKeySpkiDer = await readFile(
      join(secretRoot, 'control_evidence_deletion_signing_public_key.der'),
    );
    assert.equal(descriptor.publicKeySpkiHex, publicKeySpkiDer.toString('hex'));
    for (const prior of [authenticationKey, lifecyclePublic, holdPublic, retentionPublic])
      assert.notDeepEqual(publicKeySpkiDer, prior);
    initialTrusts = [
      {
        descriptor,
        publicKeySpkiDer,
        profilePrefixes: ['pc.control.evidence-deletion.'],
        admissionReference: 'OpenPC local rejection evidence deletion initial signing trust',
      },
    ];
  }
  for (const {
    descriptor,
    publicKeySpkiDer,
    profilePrefixes,
    exactProfiles,
    admissionReference,
  } of initialTrusts) {
    assert.equal(descriptor.participantId, participantId);
    assert.equal(descriptor.privacyDomainId, privacyDomainId);
    const signerId = evidenceKeyId(publicKeySpkiDer);
    const inspection = {
      ...inspect,
      privacyDomainId: descriptor.privacyDomainId,
      reference: descriptor.reference,
      version: descriptor.version,
      attemptId: localOperationId(),
      operationId: localOperationId(),
    };
    const observed = await provider.perform(inspection);
    validateBusinessProviderObservation(inspection, observed);
    assert.deepEqual(observed.descriptor, descriptor);
    const admissionDigest = createHash('sha256')
      .update(admissionReference)
      .update(publicKeySpkiDer)
      .digest();
    const trust = {
      participantId,
      privacyDomainId,
      environmentId: 'local',
      signerId,
      publicKeySpkiDer,
      workloadCredentialId,
      workloadCredentialEpoch: 1n,
      keyEpoch: 1n,
      validFromNs: BigInt(descriptor.validFromNs),
      validUntilNs: BigInt(descriptor.validUntilNs),
      admissionKind: 'BOOTSTRAP',
      admissionReference,
      admissionDigest,
      secretClass: 'SECRET-SIGNING-KEY',
      secretReference: descriptor.reference,
      secretVersion: '1',
      grants: (
        exactProfiles ??
        businessTransitionProfiles.filter((profile) =>
          profilePrefixes.some((prefix) => profile.profileId.startsWith(prefix)),
        )
      )
        .map((profile) => ({
          profileId: profile.profileId,
          profileVersion: profile.profileVersion,
          profileDigest: Buffer.from(profile.profileDigest.slice(7), 'hex'),
          actionIntentId: profile.actionIntentId,
          catalogOperationId: profile.catalogOperationId,
        }))
        .sort(
          (left, right) =>
            Buffer.compare(Buffer.from(left.profileId), Buffer.from(right.profileId)) ||
            left.profileVersion - right.profileVersion,
        ),
    };
    if (participantHold || sourceHold || workItem || runtimeSource) {
      const retained = await client.query(
        `select k.trust_preimage,k.trust_digest,k.public_key_spki_der,s.state
         from control.business_signing_key k join control.business_signing_key_state s using(participant_id,privacy_domain_id,signer_id)
         where k.participant_id=$1 and k.privacy_domain_id=$2 and k.signer_id=$3`,
        [participantId, privacyDomainId, signerId],
      );
      if (retained.rowCount) {
        assert.equal(retained.rowCount, 1);
        assert.deepEqual(retained.rows[0], {
          trust_preimage: businessSigningTrustPreimage(trust),
          trust_digest: businessSigningTrustDigest(trust),
          public_key_spki_der: publicKeySpkiDer,
          state: 'ACTIVE',
        });
        const grants = await client.query(
          `select encode(g.profile_digest,'hex') digest,
          exists(select 1 from control.business_signing_selection s where s.participant_id=g.participant_id and s.privacy_domain_id=g.privacy_domain_id
           and s.signer_id=g.signer_id and s.profile_digest=g.profile_digest and s.environment_id='local') selected
          from control.business_signing_grant g where g.participant_id=$1 and g.privacy_domain_id=$2 and g.signer_id=$3 order by digest`,
          [participantId, privacyDomainId, signerId],
        );
        assert.deepEqual(
          grants.rows,
          trust.grants
            .map((g) => ({ digest: g.profileDigest.toString('hex'), selected: true }))
            .sort((a, b) => a.digest.localeCompare(b.digest)),
        );
        continue;
      }
    }
    const insertKey = `insert into control.business_signing_key(participant_id,privacy_domain_id,signer_id,environment_id,public_key_spki_der,
  workload_credential_id,workload_credential_epoch,key_epoch,valid_from_ns,valid_until_ns,admission_kind,admission_reference,admission_digest,
  secret_class,secret_reference,secret_version,trust_preimage,trust_digest)
  values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`;
    const keyValues = [
      participantId,
      privacyDomainId,
      signerId,
      'local',
      publicKeySpkiDer,
      workloadCredentialId,
      '1',
      '1',
      trust.validFromNs.toString(),
      trust.validUntilNs.toString(),
      trust.admissionKind,
      trust.admissionReference,
      admissionDigest,
      trust.secretClass,
      trust.secretReference,
      trust.secretVersion,
      businessSigningTrustPreimage(trust),
      businessSigningTrustDigest(trust),
    ];
    for (const [reference, version] of [
      ['local-control-business-evidence', '1'],
      ['secret://local/control-business-evidence', '1'],
      ['secret://local/control-business-evidence#latest', 'latest'],
      ['secret://local/control-business-evidence#CURRENT', 'CURRENT'],
      ['secret://local/control-business-evidence#1', '2'],
      ['secret://local/control-business-evidence#1\n', '1\n'],
    ]) {
      await client.query('savepoint rejected_secret_reference');
      const invalid = [...keyValues];
      invalid[14] = reference;
      invalid[15] = version;
      let failure;
      try {
        await client.query(insertKey, invalid);
      } catch (error) {
        failure = error;
      }
      await client.query('rollback to savepoint rejected_secret_reference');
      await client.query('release savepoint rejected_secret_reference');
      assert.equal(
        failure?.code,
        '23514',
        'store rejects invalid secret references before admission',
      );
      assert.equal(failure?.constraint, 'business_signing_key_secret_ck');
    }
    await client.query(insertKey, keyValues);
    for (const grant of trust.grants)
      await client.query(
        `insert into control.business_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest)
  values($1,$2,$3,$4)`,
        [participantId, privacyDomainId, signerId, grant.profileDigest],
      );
    await client.query(
      `insert into control.business_signing_key_state(participant_id,privacy_domain_id,signer_id,state,changed_at_ns,change_reference,change_digest)
  values($1,$2,$3,'ADMITTED',$4,$5,$6)`,
      [participantId, privacyDomainId, signerId, now, trust.admissionReference, admissionDigest],
    );
    const activeDigest = createHash('sha256')
      .update('initial signing selection')
      .update(admissionDigest)
      .digest();
    await client.query(
      `update control.business_signing_key_state set state='ACTIVE',row_version=row_version+1,change_digest=$4
  where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3`,
      [participantId, privacyDomainId, signerId, activeDigest],
    );
    for (const grant of trust.grants)
      await client.query(
        `insert into control.business_signing_selection(participant_id,privacy_domain_id,environment_id,
  profile_digest,signer_id,changed_at_ns,change_reference,change_digest) values($1,$2,'local',$3,$4,$5,$6,$7)`,
        [
          participantId,
          privacyDomainId,
          grant.profileDigest,
          signerId,
          now,
          trust.admissionReference,
          activeDigest,
        ],
      );
  }
  await client.query('commit');
  process.stdout.write(
    'OPENPC_BUSINESS_SIGNING_BOOTSTRAP|PASS|first-trust-only|two-roles-with-exact-profile-grants|separate-keys|no-business-state\n',
  );
} catch (error) {
  await client.query('rollback');
  throw error;
} finally {
  provider.close();
  client.release();
  await pool.end();
}
