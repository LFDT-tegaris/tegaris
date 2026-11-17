import { createHash, createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  publicModuleListPage,
  publicModuleListRequest,
  publicModulePageSchema,
  publicModuleSchema,
  type ModuleListCursorBinding,
  type PublicModule,
} from '../../../services/module-registry/src/public-module-list-pagination.js';
import {
  assertModuleListCoverage,
  moduleListFenceDeclaration,
} from '../../../services/module-registry/src/db/public-module-list-store.js';
import type { readVerifiedModuleLifecycleSnapshot } from '../../../services/module-registry/src/db/module-lifecycle-store.js';
import { canonicalJson } from '../../../services/module-registry/src/domain/digest.js';
// @ts-expect-error Existing JavaScript migration declaration; the pure parser rejects an absent declaration.
import { moduleLifecycleGuardSql } from '../../../services/module-registry/src/db/module-lifecycle-guards.mjs';

const id = (suffix: number) => `018f0000-0000-7000-8000-${suffix.toString(16).padStart(12, '0')}`;
const bytes = Buffer.alloc(32, 17);
const digest = `sha256:${bytes.toString('hex')}`;
const bytesDigest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const otherDigest = `sha256:${'22'.repeat(32)}`;
const token = 'unit-only-cursor-session-not-a-runtime-credential';
const now = Date.parse('2026-09-25T00:00:00Z');
const binding: ModuleListCursorBinding = {
  participantId: id(1),
  privacyDomainId: id(2),
  authorityDigest: digest,
};
const module = (number: number, overrides: Partial<PublicModule> = {}): PublicModule => ({
  moduleId: `urn:openpc:resource:${id(number)}`,
  name: `pc.example.${number}`,
  semanticVersion: '1.0.0',
  manifestDigest: digest,
  state: 'REGISTERED',
  supportProfile: 'R1',
  revision: '1',
  createdAt: '2026-09-24T00:00:00.123456Z',
  updatedAt: '2026-09-24T00:00:00.123456Z',
  ...overrides,
});
const rows = [module(13), module(11), module(12)];
const first = (query: Record<string, unknown> = {}) =>
  publicModuleListPage(
    rows,
    digest,
    publicModuleListRequest({ limit: 1, sort: 'moduleId', ...query }, token, binding, now),
    token,
    binding,
  );
function resign(cursor: string, change: (value: Record<string, unknown>) => void) {
  const value = JSON.parse(Buffer.from(cursor.split('.')[1]!, 'base64url').toString('utf8'));
  change(value);
  const payload = Buffer.from(canonicalJson(value)).toString('base64url');
  const signature = createHmac('sha256', token)
    .update('openpc:module-collection-cursor:v1\0')
    .update(payload)
    .digest('base64url');
  return `pc1.${payload}.${signature}`;
}

describe('module collection projection and exact cursor binding', () => {
  it('paginates a complete inventory deterministically and keeps full-width revisions and microseconds', () => {
    const large = module(11, { revision: '18446744073709551615' });
    const data = [rows[0]!, large, rows[2]!];
    const request = publicModuleListRequest({ limit: '1', sort: 'moduleId' }, token, binding, now);
    const page = publicModuleListPage(data, digest, request, token, binding);
    expect(page.items).toEqual([large]);
    expect(page.total).toBe('3');
    expect(page.authorizedEmpty).toBe(false);
    expect(page.completeness).toBe('COMPLETE');
    expect(page.nextCursor).toMatch(/^pc1\./u);
    const next = publicModuleListRequest(
      { limit: 1, sort: 'moduleId', cursor: page.nextCursor },
      token,
      binding,
      now + 1000,
    );
    const rest = publicModuleListPage(data, digest, next, token, binding);
    expect(rest.items).toEqual([module(12)]);
    expect(rest.snapshotRevision).toBe(page.snapshotRevision);
    expect(rest.nextCursor).not.toBeNull();
    const last = publicModuleListPage(
      data,
      digest,
      publicModuleListRequest(
        { limit: 1, sort: 'moduleId', cursor: rest.nextCursor },
        token,
        binding,
        now + 2000,
      ),
      token,
      binding,
    );
    expect(last.items).toEqual([module(13)]);
    expect(last.snapshotRevision).toBe(page.snapshotRevision);
    expect(last.nextCursor).toBeNull();
  });

  it('uses an updatedAt/identity tie break and accepts the registered identity sort', () => {
    expect(first({ sort: '-updatedAt' }).items).toEqual([module(13)]);
    expect(first({ sort: 'updatedAt' }).items).toEqual([module(11)]);
    expect(first({ sort: '-moduleId' }).items).toEqual([module(13)]);
  });

  it('does not let a timestamp stand in for the exact source fingerprint', () => {
    const page = first();
    const request = publicModuleListRequest(
      { limit: 1, sort: 'moduleId', cursor: page.nextCursor },
      token,
      binding,
      now,
    );
    expect(() => publicModuleListPage(rows, otherDigest, request, token, binding)).toThrow(
      'PC-DATA-6007',
    );
  });

  it('returns authorized empty only for a proved empty inventory or admitted filter result', () => {
    const request = publicModuleListRequest({}, token, binding, now);
    expect(publicModuleListPage([], digest, request, token, binding)).toMatchObject({
      items: [],
      nextCursor: null,
      total: '0',
      authorizedEmpty: true,
      completeness: 'COMPLETE',
    });
    expect(first({ filter: 'state:eq:ACTIVE' })).toMatchObject({
      items: [],
      total: '0',
      authorizedEmpty: true,
    });
    expect(first({ filter: `moduleId:eq:${module(12).moduleId}` }).items).toEqual([module(12)]);
  });

  it.each([
    { limit: 0 },
    { limit: 201 },
    { limit: '01' },
    { limit: true },
    { limit: ['1', '2'] },
    { sort: 'signerKey' },
    { filter: 'signerKey:eq:active' },
    { filter: 'state:eq:ENABLED' },
    { filter: 'state:prefix:A' },
    { filter: 'moduleId:in:any' },
    { filter: 'moduleId:eq:not-a-urn' },
    { filter: 'state:eq:ACTIVE\n' },
    { active: true },
    { enabledModuleIds: [] },
    { cursor: 'pc2.a.b' },
  ])('rejects malformed or unregistered query %j', (query) => {
    expect(() => publicModuleListRequest(query, token, binding, now)).toThrow('PC-DATA-6004');
  });

  it('binds cursor to exact participant, privacy, authority path, session and effective query', () => {
    const cursor = first().nextCursor;
    for (const replacement of [
      { ...binding, participantId: id(8) },
      { ...binding, privacyDomainId: id(9) },
      { ...binding, authorityDigest: otherDigest },
    ])
      expect(() =>
        publicModuleListRequest({ cursor, limit: 1, sort: 'moduleId' }, token, replacement, now),
      ).toThrow('PC-DATA-6004');
    expect(() =>
      publicModuleListRequest(
        { cursor, limit: 1, sort: 'moduleId' },
        `${token}-other`,
        binding,
        now,
      ),
    ).toThrow('PC-DATA-6004');
    expect(() =>
      publicModuleListRequest({ cursor, limit: 1, sort: '-moduleId' }, token, binding, now),
    ).toThrow('PC-DATA-6004');
    expect(() =>
      publicModuleListRequest({ cursor, limit: 2, sort: 'moduleId' }, token, binding, now),
    ).toThrow('PC-DATA-6004');
    expect(() =>
      publicModuleListRequest(
        { cursor, limit: 1, sort: 'moduleId', filter: 'state:eq:REGISTERED' },
        token,
        binding,
        now,
      ),
    ).toThrow('PC-DATA-6004');
  });

  it('rejects tampered/noncanonical cursors even when a malformed payload has a valid test MAC', () => {
    const cursor = first().nextCursor!;
    expect(() =>
      publicModuleListRequest({ cursor: `${cursor.slice(0, -1)}!` }, token, binding, now),
    ).toThrow('PC-DATA-6004');
    for (const change of [
      (value: Record<string, unknown>) => {
        value.extra = true;
      },
      (value: Record<string, unknown>) => {
        value.resourceType = 'approval-requests';
      },
      (value: Record<string, unknown>) => {
        value.snapshotRevision = '18446744073709551616';
      },
      (value: Record<string, unknown>) => {
        value.snapshotRevision = 'bad';
      },
      (value: Record<string, unknown>) => {
        value.snapshotRevision = String(BigInt(now) * 1000n + 1n);
      },
    ])
      expect(() =>
        publicModuleListRequest(
          { cursor: resign(cursor, change), limit: 1, sort: 'moduleId' },
          token,
          binding,
          now,
        ),
      ).toThrow('PC-DATA-6004');
    const afterMissing = publicModuleListRequest(
      {
        cursor: resign(cursor, (value) => {
          value.lastId = module(99).moduleId;
        }),
        sort: 'moduleId',
        limit: 1,
      },
      token,
      binding,
      now,
    );
    expect(() => publicModuleListPage(rows, digest, afterMissing, token, binding)).toThrow(
      'PC-DATA-6007',
    );
  });

  it('keeps the wire closed and rejects numeric loss or impossible timestamps', () => {
    expect(publicModulePageSchema.safeParse({ ...first(), authorityGeneration: '1' }).success).toBe(
      false,
    );
    expect(
      publicModuleSchema.safeParse({ ...module(11), configurationDigest: digest }).success,
    ).toBe(false);
    for (const revision of ['18446744073709551616', '-1', '01', 'broken', 9007199254740992])
      expect(publicModuleSchema.safeParse({ ...module(11), revision }).success).toBe(false);
    expect(
      publicModuleSchema.safeParse({ ...module(11), updatedAt: '2026-02-30T00:00:00.000000Z' })
        .success,
    ).toBe(false);
  });
});

/** Pure classifier fixtures only. These bytes are never installed or presented
 * as a signed release, lifecycle receipt, approval or real acceptance result. */
function coverageFixture() {
  type Snapshot = Awaited<ReturnType<typeof readVerifiedModuleLifecycleSnapshot>>;
  const inventory = {
    id: id(11),
    versionId: id(21),
    state: 'ADMITTED',
    revision: '1',
    moduleId: 'pc.example.11',
    semanticVersion: '1.0.0',
    manifest: digest,
    manifestBytes: digest,
    signer: digest,
    releasePayload: bytesDigest,
    releaseSignature: bytesDigest,
    desired: digest,
    dependency: digest,
    activeManifest: null,
    configurationId: id(31),
    generation: '1',
    active: false,
    configuration: digest,
    configurationBytes: digest,
    operation: null,
    evaluation: null,
    signedRelease: true,
    createdAt: module(11).createdAt,
    updatedAt: module(11).updatedAt,
  };
  // The classifier reads only these verified-owner fields. It does not verify
  // signatures; real release verification belongs to the PG/public case leaf.
  const snapshot = [
    {
      stored: {
        moduleInstallationId: id(11),
        moduleVersionId: id(21),
        state: 'ADMITTED',
        revision: '1',
        admissionDependencyDigest: bytes,
        lifecycleOperationId: null,
      },
      release: {
        manifest: { metadata: { id: inventory.moduleId, version: '1.0.0' } },
        manifestDigest: bytes,
        signerKeyDigest: bytes,
        payloadCbor: bytes,
        coseSign1: bytes,
        configurationDigest: bytes,
      },
      configuration: {
        id: id(11),
        configurationId: id(31),
        digest: bytes,
        generation: '1',
        active: false,
        operationId: null,
        evaluationDigest: null,
        activeManifest: null,
      },
    },
  ] as unknown as Snapshot;
  return { inventory, snapshot };
}

describe('complete module inventory and installed fence prerequisites', () => {
  it('accepts only a complete one-to-one verified inventory, including genuine zero', () => {
    const { inventory, snapshot } = coverageFixture();
    expect(assertModuleListCoverage([inventory], snapshot)).toEqual([inventory]);
    expect(assertModuleListCoverage([], [])).toEqual([]);
    expect(() => assertModuleListCoverage([inventory], [])).toThrow('PC-INTEGRATION-5001');
    expect(() => assertModuleListCoverage([], snapshot)).toThrow('PC-INTEGRATION-5001');
    expect(() =>
      assertModuleListCoverage([inventory, inventory], [...snapshot, ...snapshot]),
    ).toThrow('PC-INTEGRATION-5001');
  });

  it.each([
    { state: 'FAILED_FENCED' },
    { signedRelease: false },
    { configurationId: null },
    { configurationBytes: otherDigest },
    { manifestBytes: otherDigest },
    { signer: otherDigest },
    { releasePayload: otherDigest },
    { releaseSignature: otherDigest },
    { desired: otherDigest },
    { dependency: otherDigest },
    { generation: '2' },
    { active: true },
    { activeManifest: digest },
    { operation: id(41) },
    { revision: '0' },
  ])('does not turn an omitted or malformed installation into authorized empty: %j', (change) => {
    const { inventory, snapshot } = coverageFixture();
    expect(() => assertModuleListCoverage([{ ...inventory, ...change }], snapshot)).toThrow(
      'PC-INTEGRATION-5001',
    );
  });

  it.each(['INSTALLED_DISABLED', 'ENABLED'] as const)(
    'keeps %s lifecycle and configuration bindings together',
    (state) => {
      const { inventory, snapshot } = coverageFixture();
      const active = state === 'ENABLED';
      const row = {
        ...inventory,
        state,
        revision: active ? '3' : '2',
        active,
        activeManifest: active ? digest : null,
        operation: id(41),
        evaluation: digest,
      };
      const original = snapshot[0]!;
      const current = [
        {
          ...original,
          stored: {
            ...original.stored,
            state,
            revision: row.revision,
            lifecycleOperationId: id(41),
          },
          configuration: {
            ...original.configuration,
            active,
            activeManifest: active ? bytes : null,
            operationId: id(41),
            evaluationDigest: bytes,
          },
        },
      ];
      expect(assertModuleListCoverage([row], current)).toEqual([row]);
      for (const mismatch of [
        { evaluation: null },
        { operation: null },
        { active: !active },
        { activeManifest: active ? null : digest },
      ])
        expect(() => assertModuleListCoverage([{ ...row, ...mismatch }], current)).toThrow(
          'PC-INTEGRATION-5001',
        );
      expect(() =>
        assertModuleListCoverage(
          [row],
          [{ ...current[0]!, configuration: { ...current[0]!.configuration, id: id(99) } }],
        ),
      ).toThrow('PC-INTEGRATION-5001');
    },
  );

  it('requires the current exact migration declaration and every collection producer', () => {
    expect(moduleListFenceDeclaration(moduleLifecycleGuardSql)).toContain(
      'pg_try_advisory_xact_lock',
    );
    expect(moduleListFenceDeclaration(undefined)).toBeUndefined();
    expect(moduleListFenceDeclaration('')).toBeUndefined();
    expect(
      moduleListFenceDeclaration(`${moduleLifecycleGuardSql}\n${moduleLifecycleGuardSql}`),
    ).toBeUndefined();
    expect(
      moduleListFenceDeclaration(
        String(moduleLifecycleGuardSql).replace(
          'CREATE TRIGGER a_module_reference_fence_module_capability',
          'CREATE TRIGGER missing_module_capability_fence',
        ),
      ),
    ).toBeUndefined();
  });
});
