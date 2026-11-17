import { readFile, stat } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { z } from 'zod';
import { runScopedTransaction } from '../../../identity-service/src/db/scoped-transaction.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../configuration/digest.js';
import {
  readRuntimeArtifactRetirement,
  assertRuntimeArtifactRetirementReceipt,
  parseRuntimeArtifactRetirement,
  runtimeArtifactRetirementDigest,
  runtimeArtifactRetirementMetadata,
  runtimeArtifactRetirementSelector,
  type RuntimeArtifactRetirementMetadata,
} from './runtime-artifact-retirement.js';
// @ts-expect-error The authoritative JavaScript declaration is checked in guards tests.
import { runtimeArtifactRetirementProfile as profile } from './runtime-artifact-retirement-guards.mjs';

const id = (n: number) => `01900000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const hash = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
const selection = { participantId: id(1), privacyDomainId: id(2), configurationDigest: hash(1) };
const operationId = id(8);
function metadata(): RuntimeArtifactRetirementMetadata {
  const value = {
    deletionJobId: id(3),
    source: {
      ...selection,
      runtimeConfigurationInputId: id(4),
      moduleInstallationId: id(5),
      moduleConfigurationGenerationId: id(6),
      configurationBytes: 42,
      resourceBindingsDigest: hash(2),
      createdAt: '2026-09-26T00:00:00.123456Z',
    },
  };
  return { ...value, retirementDigest: runtimeArtifactRetirementDigest(value) };
}
// Synthetic decoded fields exercise binding only. They are never passed to the
// production reader or treated as a signed receipt, native effect or authority.
function receipt() {
  return {
    authority: 'NONE',
    integrity: 'VERIFIED_PROFILE_COSE',
    meaning: 'COMMITTED_BUSINESS_TRANSITION',
    receiptId: id(9),
    operationId: `urn:openpc:operation:${operationId}`,
    profileId: profile.profileId,
    profileVersion: '1',
    profileDigest: profile.profileDigest,
    actionIntentId: profile.actionIntentId,
    catalogOperationId: profile.catalogOperationId,
    aggregateType: 'evidence-deletion',
    aggregateId: id(3),
    before: { existence: 0, revision: '0' },
    after: { existence: 1, revision: '1' },
    outboxReferences: [{ eventType: 'io.openpc.control.command.committed.v1' }],
    authorizationReferences: [{ kind: 3 }, { kind: 4 }],
  };
}
describe('immutable runtime retirement identity', () => {
  it('preserves exact original metadata across JSON readback without retaining source bytes', () => {
    const original = metadata();
    const readback = parseRuntimeArtifactRetirement(selection, JSON.parse(canonicalJson(original)));
    expect(readback).toEqual(original);
    expect(Object.isFrozen(readback.source)).toBe(true);
    expect(Object.keys(readback.source).sort()).toEqual(
      [
        'participantId',
        'privacyDomainId',
        'configurationDigest',
        'runtimeConfigurationInputId',
        'moduleInstallationId',
        'moduleConfigurationGenerationId',
        'configurationBytes',
        'resourceBindingsDigest',
        'createdAt',
      ].sort(),
    );
  });
  it('matches the retired digest independently of a newly proposed input/module identity', () => {
    const original = metadata();
    // New source identifiers are not part of this digest-wide selector.
    expect(
      parseRuntimeArtifactRetirement(selection, original).source.runtimeConfigurationInputId,
    ).toBe(id(4));
    expect(() =>
      runtimeArtifactRetirementSelector.parse({
        ...selection,
        moduleConfigurationGenerationId: id(99),
      }),
    ).toThrow();
    expect(() =>
      parseRuntimeArtifactRetirement(
        { ...selection, runtimeConfigurationInputId: id(99) },
        original,
      ),
    ).toThrow();
    expect(
      parseRuntimeArtifactRetirement(
        { ...selection, runtimeConfigurationInputId: id(4) },
        original,
      ),
    ).toEqual(original);
  });
  it.each(['participantId', 'privacyDomainId', 'configurationDigest'] as const)(
    'rejects foreign or mismatched %s',
    (field) => {
      const altered = {
        ...selection,
        [field]: field === 'configurationDigest' ? hash(99) : id(99),
      };
      expect(() => parseRuntimeArtifactRetirement(altered, metadata())).toThrow();
    },
  );
  it.each([
    (m: RuntimeArtifactRetirementMetadata) => {
      m.deletionJobId = id(99);
    },
    (m: RuntimeArtifactRetirementMetadata) => {
      m.source.runtimeConfigurationInputId = id(99);
    },
    (m: RuntimeArtifactRetirementMetadata) => {
      m.source.moduleInstallationId = id(99);
    },
    (m: RuntimeArtifactRetirementMetadata) => {
      m.source.moduleConfigurationGenerationId = id(99);
    },
    (m: RuntimeArtifactRetirementMetadata) => {
      m.source.resourceBindingsDigest = hash(99);
    },
    (m: RuntimeArtifactRetirementMetadata) => {
      m.source.configurationBytes++;
    },
    (m: RuntimeArtifactRetirementMetadata) => {
      m.source.createdAt = '2026-09-26T00:00:00.123457Z';
    },
  ])('detects changed original identity or deletion job (%#)', (change) => {
    const altered = metadata();
    change(altered);
    expect(() => parseRuntimeArtifactRetirement(selection, altered)).toThrow();
  });
  it.each([0, -1, 4_194_305, 1.5, Number.MAX_SAFE_INTEGER])(
    'rejects noncanonical byte count %s',
    (configurationBytes) => {
      const original = metadata();
      expect(() =>
        runtimeArtifactRetirementMetadata.parse({
          ...original,
          source: { ...original.source, configurationBytes },
        }),
      ).toThrow();
    },
  );
  it.each([
    { selected: false },
    { eligible: true },
    { state: 'RETIRED' },
    { physicalEffect: 'SUCCEEDED' },
    { authority: 'ADMITTED' },
    { references: [] },
    { configurationCbor: 'secret' },
  ])('rejects supplied success, reference clearance or source material (%#)', (extra) => {
    expect(() => parseRuntimeArtifactRetirement(selection, { ...metadata(), ...extra })).toThrow();
    const original = metadata();
    expect(() =>
      parseRuntimeArtifactRetirement(selection, {
        ...original,
        source: { ...original.source, ...extra },
      }),
    ).toThrow();
  });
  it('rejects missing or truncated metadata instead of producing an empty retirement proof', () => {
    for (const value of [null, undefined, {}, [], { deletionJobId: id(3) }])
      expect(() => parseRuntimeArtifactRetirement(selection, value)).toThrow();
  });
});
describe('original signed receipt binding (not signature verification)', () => {
  it('binds exact profile, source job, operation, one event and both required authority kinds', () => {
    expect(() =>
      assertRuntimeArtifactRetirementReceipt(metadata(), operationId, receipt()),
    ).not.toThrow();
  });
  it.each([
    { aggregateId: id(99) },
    { operationId: `urn:openpc:operation:${id(99)}` },
    { profileId: 'pc.control.evidence-deletion.projection' },
    { profileDigest: hash(99) },
    { profileVersion: '2' },
    { actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1' },
    { catalogOperationId: 'CFG-OP-DELETE-LOCAL-EVIDENCE' },
    { aggregateType: 'configuration-work' },
    { integrity: 'UNVERIFIED' },
    { meaning: 'UNKNOWN' },
    { authority: 'GRANTED' },
    { before: { existence: 1, revision: '1' } },
    { after: { existence: 1, revision: '0' } },
    { outboxReferences: [] },
    { outboxReferences: [{ eventType: 'wrong' }] },
    {
      outboxReferences: [
        { eventType: 'io.openpc.control.command.committed.v1' },
        { eventType: 'io.openpc.control.command.committed.v1' },
      ],
    },
    { authorizationReferences: [{ kind: 3 }] },
    { authorizationReferences: [{ kind: 4 }] },
    { authorizationReferences: [{ kind: 3 }, { kind: 3 }, { kind: 4 }] },
  ])('rejects substituted, incomplete or ambiguous receipt bindings (%#)', (changed) => {
    expect(() =>
      assertRuntimeArtifactRetirementReceipt(metadata(), operationId, { ...receipt(), ...changed }),
    ).toThrow();
  });
  it('does not accept UNKNOWN or missing signed effect as historical success', () => {
    for (const value of [
      undefined,
      null,
      {},
      { state: 'UNKNOWN' },
      { state: 'SUCCEEDED', eligible: true },
    ])
      expect(() =>
        assertRuntimeArtifactRetirementReceipt(metadata(), operationId, value),
      ).toThrow();
  });
});

// Opt-in real-owner readback. The canonical public journey supplies identifiers
// after genuine physical retirement; no approval/result/tombstone SQL seeding.
// These remain unexecuted until canonical installs the actual native owners.
const fixtureFile = process.env.OPENPC_RUNTIME_ARTIFACT_RETIREMENT_FIXTURE;
const databaseCase = fixtureFile !== undefined ? it : it.skip;
const databaseFixture = runtimeArtifactRetirementSelector
  .required()
  .extend({ deletionJobId: z.uuidv7(), operationId: z.uuidv7() });
function blocked(owner: string): never {
  throw new Error(`BLOCKED runtime artifact retirement: ${owner}`);
}
async function fixture() {
  if (!fixtureFile) blocked('original public retirement fixture');
  const info = await stat(fixtureFile);
  if (!info.isFile() || info.size > 4096) blocked('bounded identifier fixture');
  return databaseFixture.parse(JSON.parse(await readFile(fixtureFile, 'utf8')));
}
async function runtime() {
  const url = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
  if (!url) blocked('existing runtime PostgreSQL URL');
  const pool = new Pool({ connectionString: url, max: 1 });
  try {
    const row = await pool.query<{ allowed: boolean }>(
      "select not rolsuper and not rolbypassrls and pg_has_role(current_user,'openpc_control_runtime','USAGE') allowed from pg_roles where rolname=current_user",
    );
    if (row.rows[0]?.allowed !== true) blocked('non-bypass runtime principal');
    return pool;
  } catch (error) {
    await pool.end();
    throw error;
  }
}
async function scoped<T>(
  pool: Pool,
  q: z.infer<typeof databaseFixture>,
  run: (client: PoolClient) => Promise<T>,
) {
  return runScopedTransaction(
    pool,
    {
      participantId: q.participantId,
      privacyDomainId: q.privacyDomainId,
      actionIntentId: 'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
    },
    localOperationId,
    run,
  );
}
let originalPassed = false;
databaseCase(
  'reads the authentic original retirement across connections and denies the same bytes without generation identity',
  async () => {
    const q = await fixture();
    const read = async () => {
      const pool = await runtime();
      try {
        return await scoped(pool, q, (client) =>
          readRuntimeArtifactRetirement(client, {
            participantId: q.participantId,
            privacyDomainId: q.privacyDomainId,
            configurationDigest: q.configurationDigest,
          }),
        );
      } finally {
        await pool.end();
      }
    };
    const result = await read();
    expect(result.status).toBe('RETIRED');
    if (result.status !== 'RETIRED') blocked('actual retirement readback');
    expect(result.retirement.deletionJobId).toBe(q.deletionJobId);
    expect(result.retirement.source.runtimeConfigurationInputId).toBe(
      q.runtimeConfigurationInputId,
    );
    expect(result.receipt.operationId).toBe(`urn:openpc:operation:${q.operationId}`);
    expect(result.newUse).toBe('DENIED');
    expect(result.servingRestoration).toBe('DENIED');
    expect(result.originalReconciliation).toBe('ORIGINAL_RESULT_READBACK_ONLY');
    expect(result.authority).toBe('NONE');
    expect(await read()).toEqual(result);
    const pool = await runtime();
    try {
      await scoped(pool, q, async (client) => {
        await lockEvidenceLifecycle(client, q.participantId, q.privacyDomainId);
        expect(
          (
            await client.query<{ retired: boolean }>(
              'select openpc.runtime_artifact_digest_retired($1) retired',
              [q.configurationDigest],
            )
          ).rows[0]?.retired,
        ).toBe(true);
      });
    } finally {
      await pool.end();
    }
    originalPassed = true;
  },
);
databaseCase(
  'rejects foreign scope and never interprets unknown original identity as permission',
  async () => {
    if (!originalPassed) blocked('original signed retirement prerequisite failed');
    const q = await fixture(),
      pool = await runtime();
    const select = {
      participantId: q.participantId,
      privacyDomainId: q.privacyDomainId,
      configurationDigest: q.configurationDigest,
    };
    try {
      for (const altered of [
        { ...select, participantId: localOperationId() },
        { ...select, privacyDomainId: localOperationId() },
      ])
        await expect(
          scoped(pool, q, (client) => readRuntimeArtifactRetirement(client, altered)),
        ).rejects.toThrow();
      const unknown = await scoped(pool, q, (client) =>
        readRuntimeArtifactRetirement(client, {
          ...select,
          runtimeConfigurationInputId: localOperationId(),
        }),
      );
      expect(unknown.status).toBe('NOT_OBSERVED');
      expect(unknown.newUse).toBe('NOT_ESTABLISHED');
      expect(unknown.servingRestoration).toBe('NOT_ESTABLISHED');
    } finally {
      await pool.end();
    }
  },
);
databaseCase(
  'rejects direct mutation and truncate through the installed non-bypass role',
  async () => {
    const q = await fixture(),
      pool = await runtime();
    try {
      const immutable = {
        message: expect.stringMatching(
          /^(DATA-6020-IMMUTABLE-ROW|permission denied for table runtime_artifact_retirement)$/u,
        ),
      };
      for (const statement of [
        'update control.runtime_artifact_retirement set retirement_digest=retirement_digest where false',
        'delete from control.runtime_artifact_retirement where false',
        'truncate control.runtime_artifact_retirement',
      ])
        await scoped(pool, q, async (client) => {
          await lockEvidenceLifecycle(client, q.participantId, q.privacyDomainId);
          // Assert inside the transaction: unexpected success throws and rolls
          // back, including TRUNCATE. A broken guard must not commit test effects.
          await expect(client.query(statement)).rejects.toMatchObject(immutable);
        });
      await scoped(pool, q, async (client) => {
        await lockEvidenceLifecycle(client, q.participantId, q.privacyDomainId);
        await expect(
          client.query(
            'insert into control.runtime_artifact_retirement select * from control.runtime_artifact_retirement where deletion_job_id=$1',
            [q.deletionJobId],
          ),
        ).rejects.toMatchObject(immutable);
      });
    } finally {
      await pool.end();
    }
  },
);

describe('exact runtime artifact deletion selection', () => {
  it('binds source identity, archive range and scope without accepting readiness flags', async () => {
    const { runtimeArtifactDeletionSelection, runtimeArtifactRetirementSelection } =
      await import('./runtime-artifact-deletion-contracts.js');
    const { sha256 } = await import('../configuration/digest.js');
    const source = metadata().source;
    const identity = sha256({
      domain: 'pc.runtime-artifact.archive-identity.v1',
      identity: source,
    });
    const selected = {
      version: 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1',
      participantId: `urn:openpc:participant:${source.participantId}`,
      privacyDomainId: source.privacyDomainId,
      retentionPolicyId: `urn:openpc:resource:${id(10)}`,
      policyDigest: hash(10),
      targetDatabase: 'openpc_control',
      dataClass: 'RUNTIME_ARTIFACT',
      deletionMode: 'ROW_DELETE',
      source,
      streamId: 'artifact-archive',
      manifestRecordId: `runtime-artifact:${identity.slice(7)}:manifest`,
      manifestDigest: hash(11),
      archiveSegments: [
        {
          segmentId: id(11),
          objectDigest: hash(12),
          firstSequence: '1',
          throughSequence: '2',
          sinkReceipts: [
            {
              sinkId: 'original-sink',
              checkpointDigest: hash(13),
              receiptDigest: hash(14),
              acknowledgedAtMicros: '1800000000000000',
            },
          ],
        },
      ],
      referenceObservationDigest: hash(15),
      eligibleAfterMicros: '1800000000000000',
      priorCursor: null,
    };
    expect(runtimeArtifactDeletionSelection.parse(selected)).toEqual(selected);
    const physical = {
      ...selected,
      disposition: {
        dispositionId: id(20),
        operationId: id(21),
        receiptDigest: hash(20),
        nativeDenialDigest: hash(21),
        sourceOwnerId: id(22),
        sourceRootDigest: hash(22),
      },
      nextInput: {
        runtimeConfigurationInputId: id(30),
        configurationDigest: hash(30),
        beforeDigest: hash(31),
      },
    };
    expect(runtimeArtifactRetirementSelection.parse(physical)).toEqual(physical);
    expect(runtimeArtifactRetirementSelection.safeParse(selected).success).toBe(false);
    for (const inputId of [source.runtimeConfigurationInputId, id(1)])
      expect(
        runtimeArtifactRetirementSelection.safeParse({
          ...physical,
          nextInput: { ...physical.nextInput, runtimeConfigurationInputId: inputId },
        }).success,
      ).toBe(false);
    expect(
      runtimeArtifactRetirementSelection.safeParse({
        ...physical,
        disposition: { ...physical.disposition, nativeReady: true },
      }).success,
    ).toBe(false);
    const custodySegment = {
      ...selected,
      archiveSegments: [
        { ...selected.archiveSegments[0], segmentId: 'c59205e7-67c3-4f94-8964-d6b4422c4000' },
      ],
    };
    expect(runtimeArtifactDeletionSelection.parse(custodySegment)).toEqual(custodySegment);
    for (const patch of [
      { participantId: `urn:openpc:participant:${id(99)}` },
      { privacyDomainId: id(99) },
      { manifestRecordId: `runtime-artifact:${hash(99).slice(7)}:manifest` },
      { eligible: true },
      { referenceDisposition: 'CLEARED' },
      { source: { ...source, configurationBytes: 4194305 } },
      { source: { ...source, runtimeConfigurationInputId: id(99) } },
      { archiveSegments: [] },
      { archiveSegments: [{ ...selected.archiveSegments[0], segmentId: 'not-a-uuid' }] },
      { archiveSegments: [selected.archiveSegments[0], selected.archiveSegments[0]] },
      { archiveSegments: [{ ...selected.archiveSegments[0], firstSequence: '0' }] },
      { archiveSegments: [{ ...selected.archiveSegments[0], firstSequence: '3' }] },
      {
        archiveSegments: [
          {
            ...selected.archiveSegments[0],
            sinkReceipts: [
              selected.archiveSegments[0]!.sinkReceipts[0],
              selected.archiveSegments[0]!.sinkReceipts[0],
            ],
          },
        ],
      },
    ])
      expect(runtimeArtifactDeletionSelection.safeParse({ ...selected, ...patch }).success).toBe(
        false,
      );
    // Parsing an exact archive observation does not register the physical owner.
    expect(profile.catalogOperationId).toBe('CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH');
  });
});
