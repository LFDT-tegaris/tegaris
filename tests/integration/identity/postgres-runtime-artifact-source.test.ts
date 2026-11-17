import { createECDH, createHash, createHmac, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import {
  exerciseSourceProducerGate,
  observedSourcePool,
  holdSourceProducer,
  sourceProducerKeys,
} from './runtime-artifact-contention-fixture.js';
import { createLocalConfigurationAuthorizer } from '../../../services/control-api/src/configuration/local-authorizer.js';
import { ScopedConfigurationRead } from '../../../services/control-api/src/configuration/persistence/scoped-read.js';
import { AtomicConfigurationMutation } from '../../../services/control-api/src/configuration/persistence/atomic-mutation.js';
import {
  isRuntimeSourceProducerContention,
  type MutationContext,
} from '../../../services/control-api/src/configuration/persistence/types.js';
import { createLocalIdentityRuntimeVerifier } from '../../../services/identity-service/src/domain/identity-runtime-crypto.js';
import { configurationMutationOperation } from '../../../packages/security-kernel/src/configuration-operations.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { runtimeArtifactDispositionSelection } from '../../../services/control-api/src/evidence/runtime-artifact-disposition-contract.js';
import { inspectRuntimeArtifactReferences } from '../../../services/control-api/src/evidence/runtime-artifact-references.js';
// @ts-expect-error The SQL owner declares the closed typed inventory.
import { runtimeArtifactReferenceOwners } from '../../../services/control-api/src/evidence/runtime-artifact-reference-guards.mjs';

// Predicate corpus only: no rows, custody, authority or disposition are created.
it('classifies only exact runtime-source producer contention', () => {
  expect(
    isRuntimeSourceProducerContention({
      code: '55P03',
      message: 'RUNTIME-DISPOSITION-PRODUCER-CONTENTION',
    }),
  ).toBe(true);
  for (const error of [
    null,
    {},
    { code: '55P03', message: 'other lock' },
    { code: 'P0001', message: 'PC-DATA-6007' },
    { code: '40001', message: 'RUNTIME-DISPOSITION-PRODUCER-CONTENTION' },
  ])
    expect(isRuntimeSourceProducerContention(error)).toBe(false);
});

function unusedReferenceCorpus() {
  const participantId = id(),
    privacyDomainId = id(),
    inputId = id(),
    configurationId = id(),
    installationId = id();
  const configurationDigest = sha256('old imported bytes');
  const reference = (kind: string, ref: string) => ({ kind, id: ref, required: true });
  const row = (kind: string, identity: string, state: string) => ({
    kind,
    id: identity,
    participantId,
    privacyDomainId,
    revision: '1',
    state,
    digests: {} as Record<string, string | null>,
    references: [] as ReturnType<typeof reference>[],
    tokens: [] as { kind: string; digest: string }[],
    checks: {} as Record<string, boolean>,
    details: {} as Record<string, string>,
  });
  const input = row('INPUT', inputId, 'RETAINED');
  input.digests = { configuration: configurationDigest };
  input.references = [
    reference('MODULE_CONFIGURATION', configurationId),
    reference('MODULE_INSTALLATION', installationId),
  ];
  input.tokens = [{ kind: 'CONFIGURATION', digest: configurationDigest }];
  input.checks = { bytesMatch: true, bindingsKnown: true };
  const generation = row('MODULE_CONFIGURATION', configurationId, 'ACTIVE');
  generation.digests = { configuration: sha256('module release settings') };
  generation.references = [reference('MODULE_INSTALLATION', installationId)];
  const installation = row('MODULE_INSTALLATION', installationId, 'ENABLED');
  installation.digests = {
    manifest: sha256('module manifest'),
    lifecycle: sha256('committed module enablement'),
  };
  installation.details = { lifecycleOperationId: id() };
  const owners: Record<string, { overflow: boolean; rows: ReturnType<typeof row>[] }> =
    Object.fromEntries(
      (runtimeArtifactReferenceOwners as { kind: string }[]).map(({ kind }) => [
        kind,
        { overflow: false, rows: [] },
      ]),
    );
  for (const item of [input, generation, installation]) owners[item.kind]!.rows.push(item);
  const observed = {
    participantId,
    privacyDomainId,
    runtimeProducerFencesObserved: true,
    dependencyProducerFencesObserved: true,
    root: input,
    owners,
  };
  const negative = new Map<string, typeof observed>();
  const changed = (name: string, mutate: (value: typeof observed) => void) => {
    const value = structuredClone(observed);
    mutate(value);
    negative.set(name, value);
  };
  changed('selected current input', (v) => {
    v.root.state = 'SELECTED';
    v.owners.INPUT!.rows[0]!.state = 'SELECTED';
  });
  changed('missing parent', (v) => {
    v.owners.MODULE_CONFIGURATION!.rows = [];
  });
  changed('unknown parent state', (v) => {
    v.owners.MODULE_CONFIGURATION!.rows[0]!.state = 'UNKNOWN';
  });
  changed('inactive enabled mismatch', (v) => {
    v.owners.MODULE_CONFIGURATION!.rows[0]!.state = 'INACTIVE';
  });
  changed('parent contains original bytes', (v) => {
    v.owners.MODULE_CONFIGURATION!.rows[0]!.digests.configuration = configurationDigest;
  });
  changed('parent link substitution', (v) => {
    v.owners.MODULE_CONFIGURATION!.rows[0]!.references[0]!.id = id();
  });
  changed('missing lifecycle provenance', (v) => {
    delete v.owners.MODULE_INSTALLATION!.rows[0]!.details.lifecycleOperationId;
  });
  changed('unbounded inventory', (v) => {
    v.owners.WORK!.overflow = true;
  });
  changed('unfenced producer', (v) => {
    v.runtimeProducerFencesObserved = false;
  });
  for (const kind of ['WORK', 'PROBE', 'INPUT'])
    changed(`retained ${kind} use`, (v) => {
      const use = row(kind, id(), 'RETAINED');
      use.tokens = [{ kind: 'CONFIGURATION', digest: configurationDigest }];
      v.owners[kind]!.rows.push(use);
    });
  changed('rollback consumer', (v) => {
    const work = row('WORK', id(), 'COMPLETED'),
      runtime = row('RUNTIME_GENERATION', id(), 'RETAINED'),
      rollback = row('POLICY_TARGET', id(), 'RETAINED');
    work.tokens = [{ kind: 'CONFIGURATION', digest: configurationDigest }];
    work.references = [reference('RUNTIME_GENERATION', runtime.id)];
    rollback.references = [reference('RUNTIME_GENERATION', runtime.id)];
    rollback.details = { phase: 'ROLLBACK' };
    for (const use of [work, runtime, rollback]) v.owners[use.kind]!.rows.push(use);
  });
  const inactive = structuredClone(observed);
  inactive.owners.MODULE_CONFIGURATION!.rows[0]!.state = 'INACTIVE';
  inactive.owners.MODULE_INSTALLATION!.rows[0]!.state = 'INSTALLED_DISABLED';
  inactive.owners.MODULE_INSTALLATION!.rows[0]!.digests.manifest = null;
  return {
    selector: { participantId, privacyDomainId, inputId, configurationDigest },
    observed,
    inactive,
    negative,
  };
}

// Request-shape fixture only. It is never persisted as source/archive custody;
// the real owner must reject it even after actual public approval and step-up.
function absentDispositionSelection(participantId: string, privacyDomainId: string) {
  const source = {
    participantId,
    privacyDomainId,
    runtimeConfigurationInputId: id(),
    moduleInstallationId: id(),
    moduleConfigurationGenerationId: id(),
    configurationDigest: sha256('unpersisted input'),
    configurationBytes: 17,
    resourceBindingsDigest: sha256([]),
    createdAt: '2026-09-27T00:00:00.000000Z',
  };
  const identity = sha256({ domain: 'pc.runtime-artifact.archive-identity.v1', identity: source });
  return runtimeArtifactDispositionSelection.parse({
    version: 'OPENPC_RUNTIME_ARTIFACT_SOURCE_DISPOSITION_V1',
    sourceOwnerId: id(),
    sourceRootDigest: sha256('unpersisted root'),
    archivePendingDigest: sha256('unpersisted original'),
    observation: {
      version: 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1',
      participantId: `urn:openpc:participant:${participantId}`,
      privacyDomainId,
      retentionPolicyId: `urn:openpc:resource:${id()}`,
      policyDigest: sha256('unpersisted policy'),
      targetDatabase: 'openpc_control',
      dataClass: 'RUNTIME_ARTIFACT',
      deletionMode: 'ROW_DELETE',
      source,
      streamId: 'unpersisted-archive',
      manifestRecordId: `runtime-artifact:${identity.slice(7)}:manifest`,
      manifestDigest: sha256('unpersisted manifest'),
      referenceObservationDigest: sha256('unpersisted references'),
      eligibleAfterMicros: '1800000000000000',
      priorCursor: null,
      archiveSegments: [
        {
          segmentId: id(),
          objectDigest: sha256('unpersisted encrypted segment'),
          firstSequence: '1',
          throughSequence: '2',
          sinkReceipts: [
            {
              sinkId: 'unpersisted-sink',
              checkpointDigest: sha256('unpersisted checkpoint'),
              receiptDigest: sha256('unpersisted receipt'),
              acknowledgedAtMicros: '1800000000000000',
            },
          ],
        },
      ],
    },
  });
}

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && workerUrl && runtimeUrl ? it : it.skip;

it('validates source-disposition request inputs before database allocation', () => {
  const participant = id(),
    privacy = id();
  const selection = absentDispositionSelection(participant, privacy);
  expect(selection.observation.source.participantId).toBe(participant);
  expect(selection.observation.privacyDomainId).toBe(privacy);
  expect(selection.observation.source.configurationBytes).toBe(
    Buffer.byteLength('unpersisted input'),
  );
  expect(() =>
    runtimeArtifactDispositionSelection.parse({ ...selection, nativeReady: true }),
  ).toThrow();
  const corpus = unusedReferenceCorpus();
  expect(inspectRuntimeArtifactReferences(corpus.selector, corpus.observed).databaseCoverage).toBe(
    'OBSERVED',
  );
  expect(inspectRuntimeArtifactReferences(corpus.selector, corpus.inactive).databaseCoverage).toBe(
    'OBSERVED',
  );
  expect(corpus.negative.size).toBe(13);
});

// Only initial scope and host trust are bootstrapped. No admission, approval,
// target transition, native result or physical effect is seeded by this test.
integration(
  'authenticates source custody installation and fails closed without governed intent',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const worker = new Pool({ connectionString: workerUrl, max: 1 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 1 });
    const participant = id(),
      privacy = id(),
      source = id();
    const key = createECDH('prime256v1');
    key.generateKeys();
    const publicKey = key.getPublicKey(undefined, 'compressed');
    const secret = randomBytes(32),
      binding = randomBytes(32);
    const installation = {
      participant_id: participant,
      privacy_domain_id: privacy,
      source_owner_id: source,
      source_file_binding: binding.toString('hex'),
    };
    const clients: PoolClient[] = [];
    const begin = async (
      client: PoolClient,
      p = participant,
      d = privacy,
      action = 'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
    ) => {
      await client.query('begin');
      await client.query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)", [
        p,
        d,
        id(),
        action,
      ]);
    };
    try {
      const native = await worker.connect(),
        api = await runtime.connect();
      clients.push(native, api);
      const corpus = unusedReferenceCorpus();
      for (const value of [corpus.observed, corpus.inactive])
        await api.query('select openpc.assert_runtime_artifact_unused_references($1,$2)', [
          value,
          corpus.selector.inputId,
        ]);
      for (const [name, value] of corpus.negative)
        await expect(
          api.query('select openpc.assert_runtime_artifact_unused_references($1,$2)', [
            value,
            corpus.selector.inputId,
          ]),
          name,
        ).rejects.toMatchObject({ code: 'P0001' });
      const role = (await native.query<{ role: string }>('select current_user role')).rows[0]!.role;
      await admin.query(
        "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Source custody initial trust','ACTIVE',1)",
        [participant],
      );
      await admin.query(
        "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Source custody','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
        [privacy, participant],
      );
      await admin.query(
        'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
        [participant, privacy],
      );
      const observe = (value: unknown = installation, publicBytes = publicKey) =>
        native.query('select * from openpc.read_runtime_artifact_source_admissions($1,$2)', [
          value,
          publicBytes,
        ]);
      await begin(native);
      await expect(observe()).rejects.toThrow();
      await native.query('rollback');
      await admin.query(
        `insert into control.runtime_artifact_source(participant_id,privacy_domain_id,source_owner_id,
       source_file_binding,source_public_key,database_role,installation_reference) values($1,$2,$3,$4,$5,$6,'isolated initial installation')`,
        [participant, privacy, source, binding, publicKey, role],
      );
      await begin(native);
      await expect(observe()).rejects.toMatchObject({ message: 'PC-AUTH-0005' });
      await native.query('rollback');
      await admin.query(
        'insert into control.runtime_artifact_source_verifier_key(participant_id,privacy_domain_id,source_owner_id,verifier_secret) values($1,$2,$3,$4)',
        [participant, privacy, source, secret],
      );
      await begin(native);
      expect((await observe()).rows).toEqual([]);
      expect(
        (
          await native.query('select openpc.runtime_artifact_source_key_installed($1) installed', [
            source,
          ])
        ).rows[0]?.installed,
      ).toBe(true);
      await native.query('rollback');
      // API planning/admission shares the producer lock order but never inherits
      // the installed native worker's reconciliation role/action admission.
      for (const action of [
        'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
        'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1',
      ]) {
        await begin(api, participant, privacy, action);
        await api.query('select openpc.lock_runtime_artifact_disposition()');
        await expect(
          api.query('select openpc.runtime_artifact_disposition_selection($1,$2)', [id(), id()]),
        ).rejects.toMatchObject({ code: 'P0002' });
        await api.query('rollback');
        await begin(native, participant, privacy, action);
        await expect(
          native.query('select openpc.lock_runtime_artifact_disposition()'),
        ).rejects.toMatchObject({ code: '42501' });
        await native.query('rollback');
      }
      for (const action of [
        'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
        'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1',
      ]) {
        await begin(api, participant, privacy, action);
        await api.query('select openpc.lock_runtime_artifact_disposition()');
        await expect(
          api.query('select openpc.runtime_artifact_retirement_selection($1,$2)', [id(), null]),
        ).rejects.toMatchObject({ message: 'RUNTIME-RETIREMENT-ALREADY_DELETED' });
        await api.query('rollback');
      }
      await begin(api, participant, privacy, 'ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1');
      await expect(
        api.query('select openpc.lock_runtime_artifact_disposition()'),
      ).rejects.toMatchObject({ message: 'PC-AUTH-0005' });
      await api.query('rollback');
      for (const isolation of ['repeatable read', 'serializable']) {
        await api.query(`begin isolation level ${isolation}`);
        await api.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',true)",
          [participant, privacy, id()],
        );
        await expect(
          api.query('select openpc.lock_runtime_artifact_disposition()'),
        ).rejects.toMatchObject({ message: 'PC-AUTH-0005' });
        await api.query('rollback');
      }
      for (const value of [
        { ...installation, participant_id: id() },
        { ...installation, privacy_domain_id: id() },
        { ...installation, source_owner_id: id() },
        { ...installation, source_file_binding: randomBytes(32).toString('hex') },
        { ...installation, ready: true },
      ]) {
        await begin(native);
        await expect(observe(value)).rejects.toThrow();
        await native.query('rollback');
      }
      await begin(native);
      await expect(observe(installation, Buffer.alloc(33, 3))).rejects.toMatchObject({
        message: 'PC-AUTH-0005',
      });
      await native.query('rollback');
      for (const client of [api, native]) {
        await begin(client);
        await expect(
          client.query('select verifier_secret from control.runtime_artifact_source_verifier_key'),
        ).rejects.toMatchObject({ code: '42501' });
        await client.query('rollback');
        await begin(client);
        expect(
          (
            await client.query(`select has_table_privilege(current_user,'control.runtime_artifact_source','INSERT') install,
        has_table_privilege(current_user,'control.runtime_artifact_source_disposition','INSERT') admit,
        has_table_privilege(current_user,'control.runtime_artifact_source_denial','UPDATE') rewrite,
        has_table_privilege(current_user,'control.runtime_artifact_source_denial','TRUNCATE') reset`)
          ).rows[0],
        ).toEqual({ install: false, admit: client === api, rewrite: false, reset: false });
        await client.query('rollback');
      }
      // The verifier binds this actual SQL transaction. A correct MAC grants no
      // intent and cannot publish an arbitrary wire or a caller-created result.
      const wire = Buffer.from('{}'),
        nonce = randomBytes(32);
      await begin(native);
      const transaction = (
        await native.query<{ id: string }>('select pg_current_xact_id()::text id')
      ).rows[0]!.id;
      const mac = createHmac('sha256', secret)
        .update(
          Buffer.concat([
            Buffer.from(
              'OPENPC_RUNTIME_ARTIFACT_SOURCE_DENIAL_COMMIT_V1' +
                transaction +
                createHash('sha256').update(wire).digest('hex'),
            ),
            nonce,
          ]),
        )
        .digest();
      await native.query('select openpc.verify_runtime_artifact_source_commit($1,$2,$3,$4)', [
        source,
        wire,
        nonce,
        mac,
      ]);
      await expect(
        native.query('select openpc.commit_runtime_artifact_source_denial($1,$2,$3,$4)', [
          id(),
          wire,
          nonce,
          mac,
        ]),
      ).rejects.toThrow();
      await native.query('rollback');
      await begin(native);
      await expect(
        native.query('select openpc.verify_runtime_artifact_source_commit($1,$2,$3,$4)', [
          source,
          wire,
          nonce,
          mac,
        ]),
      ).rejects.toMatchObject({ message: 'PC-AUTH-0005' });
      await native.query('rollback');
      await begin(native, participant, id());
      expect(
        (
          await native.query('select openpc.runtime_artifact_source_key_installed($1) installed', [
            source,
          ])
        ).rows[0]?.installed,
      ).toBe(false);
      expect((await native.query('select * from control.runtime_artifact_source')).rows).toEqual(
        [],
      );
      await native.query('rollback');
      await expect(
        admin.query(`insert into control.runtime_artifact_source_disposition
      (participant_id,privacy_domain_id,source_owner_id,disposition_id,runtime_configuration_input_id,configuration_digest,
       selection,selection_digest,approval_request_id,operation_id) select null,null,null,null,null,null,null,null,null,null where false`),
      ).rejects.toMatchObject({
        message: 'DATA-6001-CONTEXT-INVALID',
        detail: 'openpc.action_intent_id',
      });
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.runtime_artifact_source_denial where participant_id=$1',
            [participant],
          )
        ).rows[0]?.count,
      ).toBe(0);
    } finally {
      for (const client of clients) {
        await client.query('rollback');
        client.release();
      }
      await Promise.all([admin.end(), worker.end(), runtime.end()]);
      secret.fill(0);
    }
  },
  30_000,
);

integration(
  'holds current source-read authority through commit while preserving ordinary read isolation',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 3 });
    const participant = id(),
      privacy = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    try {
      fixture = await contractAdministrationFixture(admin, runtimeUrl!, participant, privacy);
      await fixture.selectPrivacyContext('maker', { freshStepUp: true });
      const maker = fixture.governance.maker;
      const authorizer = createLocalConfigurationAuthorizer(
        fixture.service.identityUrl,
        fixture.service.identityInternalToken,
        privacy,
      );
      const authorization = async (actionIntentId: string) =>
        authorizer.authorize({
          sessionToken: maker.sessionToken,
          participantId: participant,
          privacyDomainId: privacy,
          actionIntentId,
          resourceId: '*',
          candidateDigest: `sha256:${'01'.repeat(32)}`,
          makerCheckerRequired: false,
          stepUpRequired: false,
        });
      const reads = new ScopedConfigurationRead(runtime);
      const ordinaryAction = 'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1';
      const ordinary = {
        authorization: await authorization(ordinaryAction),
        actionIntentId: ordinaryAction,
        resourceType: 'evidence-deletions',
        resourceId: '*',
      };
      expect(
        await reads.execute(
          ordinary,
          async (client) =>
            (
              await client.query(
                "select current_setting('transaction_isolation') isolation,current_setting('transaction_read_only') read_only",
              )
            ).rows[0],
        ),
      ).toEqual({ isolation: 'repeatable read', read_only: 'on' });
      expect(
        await reads.executeCurrent(
          ordinary,
          async (client) =>
            (await client.query("select current_setting('transaction_isolation') isolation"))
              .rows[0],
        ),
      ).toEqual({ isolation: 'read committed' });
      const action = 'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1';
      const current = {
        ...ordinary,
        actionIntentId: action,
        authorization: await authorization(action),
      };
      expect(
        await reads.executeCurrent(current, async (client) => {
          await client.query('select openpc.lock_runtime_artifact_disposition()');
          return (
            await client.query(
              "select current_setting('transaction_isolation') isolation,current_setting('transaction_read_only') read_only,current_setting('row_security') rls",
            )
          ).rows[0];
        }),
      ).toEqual({ isolation: 'read committed', read_only: 'off', rls: 'on' });
      await exerciseSourceProducerGate(
        runtime,
        participant,
        privacy,
        (pool, entered) => new ScopedConfigurationRead(pool).executeCurrent(current, entered),
        async () => {
          expect(
            (
              await admin.query(
                'select count(*)::int n from control.runtime_artifact_source_disposition where participant_id=$1',
                [participant],
              )
            ).rows,
          ).toEqual([{ n: 0 }]);
        },
      );
      let reached = 0;
      const unreachable = async () => {
        reached++;
      };
      for (const context of [
        { ...ordinary, actionIntentId: 'ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1' },
        { ...current, resourceType: 'evidence-holds' },
        {
          ...current,
          authorization: {
            ...current.authorization,
            assignmentEpoch: String(BigInt(current.authorization.assignmentEpoch) + 1n),
          },
        },
        { ...current, authorization: { ...current.authorization, sessionEpoch: undefined } },
      ])
        await expect(reads.executeCurrent(context, unreachable)).rejects.toThrow('PC-AUTH-0005');
      expect(reached).toBe(0);
      // The exact mutation dispatch rejects mismatched tuples before reserving
      // idempotency or using the supplied authority; no business state is seeded.
      const atomic = new AtomicConfigurationMutation(runtime);
      const mutation = {
        authorization: current.authorization,
        candidate: {},
        resourceId: id(),
        actionIntentId: 'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1',
        actionIntentDigest: `sha256:${'02'.repeat(32)}`,
        idempotencyKey: id(),
        catalogOperationId: 'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
        resourceType: 'evidence-deletions',
        aggregateType: 'runtime-artifact-disposition',
        operationClass: 'CREATE',
        expectedRevision: '0',
      } as MutationContext;
      for (const patch of [
        { actionIntentId: ordinaryAction },
        { resourceType: 'evidence-holds' },
        { aggregateType: 'evidence-deletion' },
        { operationClass: 'UPDATE' as const },
        { expectedRevision: '1' },
      ])
        await expect(
          atomic.execute({ ...mutation, ...patch }, async () => {
            reached++;
            throw new Error('unreachable source mutation');
          }),
        ).rejects.toThrow('PC-AUTH-0005');
      expect(reached).toBe(0);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.idempotency_record where participant_id=$1 and catalog_operation_id=$2',
            [participant, mutation.catalogOperationId],
          )
        ).rows,
      ).toEqual([{ n: 0 }]);

      const verifier = createLocalIdentityRuntimeVerifier([
        await readFile(`${fixture.service.directory}/public.der`),
      ]);
      const governed = new AtomicConfigurationMutation(runtime, verifier);
      for (const [catalog, path, fields, isolation] of [
        [
          'CFG-OP-ACTIVATE-RETENTION-POLICY',
          'retention-policies',
          {
            participantId: `urn:openpc:participant:${participant}`,
            predecessorPolicyId: null,
            policy: {
              dataClass: 'RUNTIME_ARTIFACT',
              policyVersion: '1.0.0',
              retentionPeriodMs: '1',
              localGraceMs: '0',
              sinkQuorum: 1,
              deletionMode: 'ROW_DELETE',
              makerCheckerRequired: true,
            },
          },
          'serializable',
        ],
        [
          'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
          'evidence-deletions/runtime-sources',
          {
            participantId: `urn:openpc:participant:${participant}`,
            selection: absentDispositionSelection(participant, privacy),
          },
          'read committed',
        ],
      ] as const) {
        const operation = configurationMutationOperation(catalog);
        const prepared = await fixture.prepareMutation(
          path,
          operation.actionIntentId,
          fields,
          true,
        );
        expect((await prepared.commit()).status).toBe(403);
        await prepared.stepUp();
        const proof = await authorizer.authorize({
          sessionToken: maker.sessionToken,
          participantId: participant,
          privacyDomainId: privacy,
          resourceId: prepared.resourceId,
          catalogOperationId: catalog,
          idempotencyKey: prepared.idempotencyKey,
          actionIntentId: operation.actionIntentId,
          actionIntentDigest: String(prepared.body.actionIntentDigest),
          candidateDigest: sha256(prepared.body),
          expectedRevision: '0',
          makerCheckerRequired: true,
          stepUpRequired: true,
          csrfToken: await fixture.governance.client.csrf(
            maker,
            operation.actionIntentId,
            fixture.service.identityUrl,
          ),
          origin: fixture.service.identityUrl,
          host: new URL(fixture.service.identityUrl).host,
        });
        if (proof.evidenceKind === 'READ_CONTEXT')
          throw new Error('Expected actual governed mutation authority');
        const context: MutationContext = {
          ...operation,
          authorization: proof,
          sessionToken: maker.sessionToken,
          resourceId: prepared.resourceId,
          idempotencyKey: prepared.idempotencyKey,
          expectedRevision: '0',
          actionIntentDigest: String(prepared.body.actionIntentDigest),
          candidate: prepared.body,
        };
        const boundary = new Error(
          'Observed real authorized transaction; business effect deliberately unopened',
        );
        let admitted = 0;
        await expect(
          governed.execute(context, async (client) => {
            expect(
              (await client.query("select current_setting('transaction_isolation') isolation"))
                .rows,
            ).toEqual([{ isolation }]);
            admitted++;
            throw boundary;
          }),
        ).rejects.toBe(boundary);
        expect(admitted).toBe(1);
        expect(
          (
            await admin.query(
              'select count(*)::int n from control.idempotency_record where participant_id=$1 and catalog_operation_id=$2 and idempotency_key=$3',
              [participant, catalog, prepared.idempotencyKey],
            )
          ).rows,
        ).toEqual([{ n: 0 }]);
        if (catalog === 'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE') {
          const counts = async () =>
            Promise.all(
              [
                'idempotency_record',
                'receipt_signing_attempt',
                'runtime_artifact_source_disposition',
              ].map(
                async (table) =>
                  (
                    await admin.query(
                      `select count(*)::int n from control.${table} where participant_id=$1`,
                      [participant],
                    )
                  ).rows,
              ),
            );
          const priorCounts = await counts();
          await exerciseSourceProducerGate(
            runtime,
            participant,
            privacy,
            (pool, entered) =>
              new AtomicConfigurationMutation(pool, verifier).execute(context, entered),
            async () => {
              expect(await counts()).toEqual(priorCounts);
            },
          );
          // Independent approval does not manufacture native input/archive proof.
          expect(await prepared.commit()).toMatchObject({
            status: 412,
            body: { status: 412, code: 'PC-DATA-6007', truthState: 'STALE', retryable: false },
          });
          expect(
            (
              await admin.query(
                'select count(*)::int n from control.runtime_artifact_source_disposition where participant_id=$1',
                [participant],
              )
            ).rows,
          ).toEqual([{ n: 0 }]);
        }
      }

      // Real row-fence contention: revocation cannot complete while the read owns
      // the authority dependency. Once committed, that original proof is stale.
      let release!: () => void, entered!: () => void;
      const hold = new Promise<void>((resolve) => {
        release = resolve;
      });
      const started = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const reading = reads.executeCurrent(current, async (client) => {
        await client.query('select openpc.lock_runtime_artifact_disposition()');
        entered();
        await hold;
        return 'authorized original read';
      });
      await Promise.race([started, reading]);
      const revoker = await admin.connect();
      let revoked: Promise<unknown> | undefined;
      try {
        const pid = (await revoker.query<{ pid: number }>('select pg_backend_pid() pid')).rows[0]!
          .pid;
        revoked = revoker.query(
          'update control.principal set authority_epoch=authority_epoch+1 where participant_id=$1 and principal_id=$2',
          [participant, maker.principalId],
        );
        let blocked = false;
        for (let poll = 0; poll < 50 && !blocked; poll++) {
          blocked =
            (await admin.query('select wait_event_type from pg_stat_activity where pid=$1', [pid]))
              .rows[0]?.wait_event_type === 'Lock';
          if (!blocked) await new Promise((resolve) => setTimeout(resolve, 10));
        }
        expect(blocked).toBe(true);
      } finally {
        release();
        await reading;
        await revoked;
        revoker.release();
      }
      await expect(reads.executeCurrent(current, unreachable)).rejects.toThrow('PC-AUTH-0005');
      expect(reached).toBe(0);
    } finally {
      await fixture?.close();
      await Promise.all([admin.end(), runtime.end()]);
    }
  },
  60_000,
);

integration(
  'revalidates original read and mutation authority after producer contention',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const runtime = new Pool({ connectionString: runtimeUrl, max: 2 });
    try {
      for (const kind of ['READ', 'MUTATION'] as const)
        for (const invalidation of ['EXPIRY', 'REVOCATION'] as const) {
          const participant = id(),
            privacy = id();
          const fixture = await contractAdministrationFixture(
            admin,
            runtimeUrl!,
            participant,
            privacy,
          );
          const holder = await runtime.connect();
          try {
            await fixture.selectPrivacyContext('maker', { freshStepUp: true });
            const maker = fixture.governance.maker;
            const authorizer = createLocalConfigurationAuthorizer(
              fixture.service.identityUrl,
              fixture.service.identityInternalToken,
              privacy,
            );
            const action = 'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1';
            const readContext = {
              authorization: await authorizer.authorize({
                sessionToken: maker.sessionToken,
                participantId: participant,
                privacyDomainId: privacy,
                actionIntentId: action,
                resourceId: '*',
                candidateDigest: sha256('current source read'),
                makerCheckerRequired: false,
                stepUpRequired: false,
              }),
              actionIntentId: action,
              resourceType: 'evidence-deletions',
              resourceId: '*',
            };
            let mutation: MutationContext | undefined;
            const verifier = createLocalIdentityRuntimeVerifier([
              await readFile(`${fixture.service.directory}/public.der`),
            ]);
            if (kind === 'MUTATION') {
              const operation = configurationMutationOperation(
                'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
              );
              const prepared = await fixture.prepareMutation(
                'evidence-deletions/runtime-sources',
                operation.actionIntentId,
                {
                  participantId: `urn:openpc:participant:${participant}`,
                  selection: absentDispositionSelection(participant, privacy),
                },
                true,
              );
              expect((await prepared.commit()).status).toBe(403);
              await prepared.stepUp();
              const proof = await authorizer.authorize({
                sessionToken: maker.sessionToken,
                participantId: participant,
                privacyDomainId: privacy,
                resourceId: prepared.resourceId,
                catalogOperationId: operation.catalogOperationId,
                idempotencyKey: prepared.idempotencyKey,
                actionIntentId: operation.actionIntentId,
                actionIntentDigest: String(prepared.body.actionIntentDigest),
                candidateDigest: sha256(prepared.body),
                expectedRevision: '0',
                makerCheckerRequired: true,
                stepUpRequired: true,
                csrfToken: await fixture.governance.client.csrf(
                  maker,
                  operation.actionIntentId,
                  fixture.service.identityUrl,
                ),
                origin: fixture.service.identityUrl,
                host: new URL(fixture.service.identityUrl).host,
              });
              if (proof.evidenceKind === 'READ_CONTEXT')
                throw new Error('Expected governed mutation authority');
              mutation = {
                ...operation,
                authorization: proof,
                sessionToken: maker.sessionToken,
                resourceId: prepared.resourceId,
                idempotencyKey: prepared.idempotencyKey,
                expectedRevision: '0',
                actionIntentDigest: String(prepared.body.actionIntentDigest),
                candidate: prepared.body,
              };
            }
            let entered = 0;
            const unreachable = async (): Promise<never> => {
              entered++;
              throw new Error('Stale authority reached callback');
            };
            await holdSourceProducer(holder, sourceProducerKeys(participant, privacy)[0]);
            const observed = observedSourcePool(runtime, async () => {
              expect(entered).toBe(0);
              const changed =
                invalidation === 'EXPIRY'
                  ? await admin.query(
                      `update control.session set
                         issued_at=issued_at-interval '13 hours',
                         last_seen_at=last_seen_at-interval '13 hours',
                         idle_expires_at=idle_expires_at-interval '13 hours',
                         absolute_expires_at=absolute_expires_at-interval '13 hours',
                         step_up_verified_at=step_up_verified_at-interval '13 hours',
                         row_version=row_version+1
                       where participant_id=$1 and session_id=$2`,
                      [participant, maker.sessionId],
                    )
                  : await admin.query(
                      'update control.principal set authority_epoch=authority_epoch+1 where participant_id=$1 and principal_id=$2',
                      [participant, maker.principalId],
                    );
              expect(changed.rowCount).toBe(1);
              await holder.query('rollback');
            });
            const outcome = await (
              mutation
                ? new AtomicConfigurationMutation(observed.pool, verifier).execute(
                    mutation,
                    unreachable,
                  )
                : new ScopedConfigurationRead(observed.pool).executeCurrent(
                    readContext,
                    unreachable,
                  )
            ).catch((error: unknown) => error);
            observed.assertRollbackHook();
            expect(outcome, `${kind}/${invalidation}`).toMatchObject({ code: 'PC-AUTH-0005' });
            expect(entered).toBe(0);
            expect(observed.attempts()).toBe(2);
            expect(observed.released()).toBe(2);
            expect(
              (
                await admin.query(
                  "select count(*)::int n from control.idempotency_record where participant_id=$1 and catalog_operation_id='CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE'",
                  [participant],
                )
              ).rows,
            ).toEqual([{ n: 0 }]);
            expect(
              (
                await admin.query(
                  'select count(*)::int n from control.runtime_artifact_source_disposition where participant_id=$1',
                  [participant],
                )
              ).rows,
            ).toEqual([{ n: 0 }]);
          } finally {
            await holder.query('rollback');
            holder.release();
            await fixture.close();
          }
        }
    } finally {
      await Promise.all([admin.end(), runtime.end()]);
    }
  },
  120_000,
);
