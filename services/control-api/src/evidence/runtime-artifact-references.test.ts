import { describe, expect, it } from 'vitest';
import {
  assertRuntimeArtifactObservationUnchanged,
  inspectRuntimeArtifactReferences,
  RuntimeArtifactReferenceError,
  type RuntimeArtifactReferenceOwner,
} from './runtime-artifact-references.js';

const declaration = await import(
  new URL('./runtime-artifact-reference-guards.mjs', import.meta.url).href
);
const catalogue = declaration.runtimeArtifactReferenceOwners as { kind: string; table: string }[];
const sql = declaration.runtimeArtifactReferenceGuardsSql as string;
const uuid = (n: number) => `01900000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const hash = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
const selector = {
  participantId: uuid(1),
  privacyDomainId: uuid(2),
  inputId: uuid(3),
  configurationDigest: hash(1),
};
type Row = RuntimeArtifactReferenceOwner;
const ref = (kind: string, n: number) => ({ kind, id: uuid(n), required: true });
const row = (kind: string, n: number, overrides: Partial<Row> = {}): Row => ({
  kind,
  id: uuid(n),
  participantId: selector.participantId,
  privacyDomainId: selector.privacyDomainId,
  revision: '1',
  state: 'RETAINED',
  digests: {},
  references: [],
  tokens: [],
  checks: {},
  details: {},
  ...overrides,
});
function snapshot() {
  const root = row('INPUT', 3, {
    state: 'RETAINED',
    revision: null,
    digests: { configuration: hash(1), bindings: hash(11) },
    checks: { bytesMatch: true, bindingsKnown: true },
    tokens: [{ kind: 'CONFIGURATION', digest: hash(1) }],
    references: [
      ref('MODULE_CONFIGURATION', 4),
      ref('MODULE_INSTALLATION', 5),
      ref('PROVIDER', 9),
      ref('CIGL_SETTINGS', 21),
    ],
  });
  const rows = [
    root,
    row('MODULE_CONFIGURATION', 4, { references: [ref('MODULE_INSTALLATION', 5)] }),
    row('MODULE_INSTALLATION', 5, { state: 'DISABLED' }),
    row('WORK', 6, {
      state: 'COMPLETED',
      digests: { configuration: hash(1), result: hash(2) },
      checks: { resultMatch: true },
      references: [ref('RUNTIME_GENERATION', 7), ref('TARGET', 8)],
      tokens: [{ kind: 'CONFIGURATION', digest: hash(1) }],
    }),
    row('RUNTIME_GENERATION', 7, {
      state: 'QUARANTINED',
      references: [ref('TARGET', 8), ref('PROVIDER', 9), ref('PROJECTION', 10)],
    }),
    row('TARGET', 8, {
      state: 'OFFLINE',
      digests: { active: hash(3) },
      tokens: [{ kind: 'CAPSULE', digest: hash(3) }],
    }),
    row('PROVIDER', 9, { state: 'RETIRED', references: [ref('PROBE', 11)] }),
    row('PROJECTION', 10, { state: 'RETIRED', references: [ref('INDEXER', 12)] }),
    row('PROBE', 11, {
      state: 'OBSERVED',
      digests: { configuration: hash(1), observation: hash(4) },
      checks: { observationMatch: true },
      tokens: [{ kind: 'CONFIGURATION', digest: hash(1) }],
    }),
    row('INDEXER', 12, { state: 'RETIRED' }),
    row('ACTIVATION_OBSERVATION', 13, {
      digests: { receipt: hash(5) },
      checks: { receiptMatch: true },
      references: [ref('WORK', 6), ref('RUNTIME_GENERATION', 7), ref('TARGET', 8)],
    }),
    row('ROUTE_PUBLICATION', 14, { references: [ref('WORK', 6), ref('PROBE', 11)] }),
    row('POLICY_TARGET', 15, {
      state: 'ROLLED_BACK',
      details: { phase: 'FORWARD' },
      references: [ref('POLICY_OCCURRENCE', 17), ref('WORK', 6), ref('TARGET', 8)],
    }),
    row('POLICY_TARGET', 16, {
      state: 'ROLLED_BACK',
      details: { phase: 'ROLLBACK' },
      references: [ref('POLICY_OCCURRENCE', 17), ref('TARGET', 8)],
    }),
    row('POLICY_OCCURRENCE', 17, {
      state: 'ROLLED_BACK',
      references: [ref('POLICY_AUTHORIZATION', 18), ref('POLICY_GENERATION', 19)],
    }),
    row('POLICY_AUTHORIZATION', 18, {
      state: 'RETIRED',
      references: [ref('POLICY_GENERATION', 19)],
    }),
    row('POLICY_GENERATION', 19, { state: 'RETIRED' }),
    row('POLICY_PREREQUISITE', 20, {
      state: 'READY',
      references: [ref('POLICY_AUTHORIZATION', 18)],
    }),
    row('CIGL_SETTINGS', 21),
  ];
  const owners: Record<string, { overflow: boolean; rows: Row[] }> = Object.fromEntries(
    catalogue.map(({ kind }) => [
      kind,
      { overflow: false, rows: rows.filter((r) => r.kind === kind) },
    ]),
  );
  return {
    participantId: selector.participantId,
    privacyDomainId: selector.privacyDomainId,
    runtimeProducerFencesObserved: true,
    dependencyProducerFencesObserved: true,
    root: root as Row | null,
    owners,
  };
}
function owner(value: ReturnType<typeof snapshot>, kind: string, n: number) {
  return value.owners[kind]!.rows.find((r) => r.id === uuid(n))!;
}

describe('runtime artifact original-reference observation', () => {
  it('keeps the withdrawal, delivery and ACK chain as original custody rather than deletion authority', () => {
    const s = snapshot();
    s.owners.TARGET_DISPOSITION_ADMISSION!.rows.push(
      row('TARGET_DISPOSITION_ADMISSION', 30, {
        references: [ref('INPUT', 3), ref('TARGET', 8), ref('WORK', 6)],
        tokens: [{ kind: 'CONFIGURATION', digest: hash(1) }],
      }),
    );
    s.owners.TARGET_DISPOSITION_DELIVERY!.rows.push(
      row('TARGET_DISPOSITION_DELIVERY', 31, {
        references: [ref('TARGET_DISPOSITION_ADMISSION', 30)],
        checks: { bytesMatch: true },
      }),
    );
    s.owners.TARGET_DISPOSITION_ACK!.rows.push(
      row('TARGET_DISPOSITION_ACK', 32, {
        references: [ref('TARGET_DISPOSITION_DELIVERY', 31)],
        checks: { bytesMatch: true },
      }),
    );
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.references).toHaveLength(22);
    expect(result.authority).toBe('NONE');
    expect(result.disposition).toBe('UNPROVEN');
    expect(result.unresolved).toContain('GOVERNED_REFERENCE_DISPOSITION_REQUIRED');
  });
  it('retains completed effects, route/probe history and both activation directions without disposition authority', () => {
    const result = inspectRuntimeArtifactReferences(selector, snapshot());
    expect(result.databaseCoverage).toBe('OBSERVED');
    expect(result.references).toHaveLength(19);
    expect(result.authority).toBe('NONE');
    expect(result.disposition).toBe('UNPROVEN');
    expect(result.obligations).toEqual(
      expect.arrayContaining([
        { owner: `WORK:${uuid(6)}`, state: 'COMPLETED', reason: 'COMPLETED_WORK_REFERENCE' },
        { owner: `INPUT:${uuid(3)}`, state: 'RETAINED', reason: 'RETAINED_RELOAD_INPUT' },
        { owner: `POLICY_TARGET:${uuid(16)}`, state: 'ROLLED_BACK', reason: 'ROLLBACK_REFERENCE' },
        { owner: `TARGET:${uuid(8)}`, state: 'OFFLINE', reason: 'TARGET_CUSTODY_REFERENCE' },
      ]),
    );
    expect(result.unresolved).toEqual(
      expect.arrayContaining([
        'INPUT_REDELIVERY_DISPOSITION_UNPROVEN',
        'RUNTIME_CUSTODY_DISPOSITION_UNOBSERVED',
        'BACKUP_RESTORE_DISPOSITION_UNOBSERVED',
        'GOVERNED_REFERENCE_DISPOSITION_REQUIRED',
      ]),
    );
    expect(Object.isFrozen(result.references[0])).toBe(true);
  });
  it('keeps a missing or changed canonical producer fence unresolved', () => {
    const s = snapshot();
    s.runtimeProducerFencesObserved = false;
    expect(inspectRuntimeArtifactReferences(selector, s).unresolved).toContain(
      'RUNTIME_PRODUCER_FENCES_UNVERIFIED',
    );
    expect(inspectRuntimeArtifactReferences(selector, s).databaseCoverage).toBe('INCOMPLETE');
  });
  it('does not confuse runtime fences with dependency coverage or legacy observation coverage', () => {
    const complete = snapshot();
    const legacy: Partial<typeof complete> = { ...complete };
    delete legacy.dependencyProducerFencesObserved;
    for (const incomplete of [legacy, { ...complete, dependencyProducerFencesObserved: false }]) {
      const result = inspectRuntimeArtifactReferences(selector, incomplete);
      expect(result.runtimeProducerFencesObserved).toBe(true);
      expect(result.dependencyProducerFencesObserved).toBe(false);
      expect(result.databaseCoverage).toBe('INCOMPLETE');
      expect(result.unresolved).toContain('DEPENDENCY_PRODUCER_FENCES_UNVERIFIED');
      expect(result.authority).toBe('NONE');
      expect(result.disposition).toBe('UNPROVEN');
    }
    const observed = inspectRuntimeArtifactReferences(selector, complete);
    expect(observed.unresolved).not.toContain('DEPENDENCY_PRODUCER_FENCES_UNVERIFIED');
    expect(observed.unresolved).toContain('BACKUP_RESTORE_DISPOSITION_UNOBSERVED');
    expect(observed.observationDigest).not.toBe(
      inspectRuntimeArtifactReferences(selector, legacy).observationDigest,
    );
  });
  it('includes a successor and its different original configuration through the same target', () => {
    const s = snapshot();
    s.owners.WORK!.rows.push(
      row('WORK', 30, {
        state: 'RECONCILING',
        digests: { configuration: hash(30) },
        references: [ref('TARGET', 8)],
        tokens: [{ kind: 'CONFIGURATION', digest: hash(30) }],
      }),
    );
    s.owners.INPUT!.rows.push(
      row('INPUT', 31, {
        digests: { configuration: hash(30) },
        checks: { bytesMatch: true, bindingsKnown: true },
        tokens: [{ kind: 'CONFIGURATION', digest: hash(30) }],
      }),
    );
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.databaseCoverage).toBe('OBSERVED');
    expect(result.references.map((r) => r.id)).toEqual(
      expect.arrayContaining([uuid(30), uuid(31)]),
    );
  });
  it('does not confuse capsule/configuration tokens or fan out via shared module/resource parents', () => {
    const s = snapshot();
    s.owners.INPUT!.rows.push(
      row('INPUT', 30, {
        digests: { configuration: hash(30) },
        references: [
          ref('MODULE_INSTALLATION', 5),
          ref('MODULE_CONFIGURATION', 4),
          ref('PROVIDER', 9),
        ],
        tokens: [{ kind: 'CONFIGURATION', digest: hash(30) }],
      }),
    );
    s.owners.TARGET!.rows.push(
      row('TARGET', 31, { tokens: [{ kind: 'CAPSULE', digest: hash(1) }] }),
    );
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.references.some((r) => r.id === uuid(30) || r.id === uuid(31))).toBe(false);
  });
  it('follows predecessor capsule dependencies even without a direct work/target identity link', () => {
    const s = snapshot();
    s.owners.WORK!.rows.push(
      row('WORK', 30, {
        state: 'RECONCILING',
        digests: { configuration: hash(1) },
        tokens: [{ kind: 'CAPSULE', digest: hash(3) }],
      }),
    );
    expect(
      inspectRuntimeArtifactReferences(selector, s).references.some((r) => r.id === uuid(30)),
    ).toBe(true);
  });
  it.each(catalogue.map(({ kind }) => kind))(
    'marks a bounded %s branch incomplete even if its rows are unrelated',
    (kind) => {
      const s = snapshot();
      s.owners[kind]!.overflow = true;
      const result = inspectRuntimeArtifactReferences(selector, s);
      expect(result.databaseCoverage).toBe('INCOMPLETE');
      expect(result.unresolved).toContain(`TRUNCATED_OWNER:${kind}`);
      expect(result.disposition).toBe('UNPROVEN');
    },
  );
  it('observes the exact root outside a truncated input branch and never loses the truncation', () => {
    const s = snapshot();
    s.owners.INPUT = { overflow: true, rows: [] };
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.root?.id).toBe(selector.inputId);
    expect(result.unresolved).toContain('TRUNCATED_OWNER:INPUT');
  });
  it('makes missing original input unresolved without returning unrelated tenant metadata', () => {
    const s = snapshot();
    s.root = null;
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.references).toEqual([]);
    expect(result.unresolved).toContain('INPUT_NOT_OBSERVED');
  });
  it.each(['PROBE', 'MODULE_CONFIGURATION', 'CIGL_SETTINGS', 'TARGET'])(
    'does not treat a missing %s owner as clear',
    (kind) => {
      const s = snapshot();
      s.owners[kind]!.rows = [];
      const result = inspectRuntimeArtifactReferences(selector, s);
      expect(result.databaseCoverage).toBe('INCOMPLETE');
      expect(
        result.unresolved.some((v) => v.startsWith('MISSING_OWNER:') && v.includes(`:${kind}:`)),
      ).toBe(true);
    },
  );
  it.each([
    ['INPUT', 3, 'bytesMatch', 'INPUT_BYTES_UNVERIFIED'],
    ['INPUT', 3, 'bindingsKnown', 'INPUT_BINDINGS_UNVERIFIED'],
    ['WORK', 6, 'resultMatch', 'WORK_RESULT_UNVERIFIED'],
    ['PROBE', 11, 'observationMatch', 'PROBE_RESULT_UNVERIFIED'],
    ['ACTIVATION_OBSERVATION', 13, 'receiptMatch', 'ACTIVATION_RESULT_UNVERIFIED'],
  ] as const)('preserves unverified %s source integrity', (kind, n, check, code) => {
    const s = snapshot();
    owner(s, kind, n).checks[check] = false;
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.unresolved).toContain(`${code}:${uuid(n)}`);
    expect(result.databaseCoverage).toBe('INCOMPLETE');
  });
  it('requires the actual original input for completed work on another digest', () => {
    const s = snapshot();
    owner(s, 'WORK', 6).digests.configuration = hash(42);
    expect(inspectRuntimeArtifactReferences(selector, s).unresolved).toContain(
      `CONFIGURATION_SOURCE_NOT_OBSERVED:${uuid(6)}`,
    );
  });
  it('retains all original input identities and flags ambiguous digest-only work/probe linkage', () => {
    const s = snapshot();
    s.owners.INPUT!.rows.push(
      row('INPUT', 30, {
        digests: { configuration: hash(1) },
        checks: { bytesMatch: true, bindingsKnown: true },
        tokens: [{ kind: 'CONFIGURATION', digest: hash(1) }],
      }),
    );
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.references.filter((r) => r.kind === 'INPUT')).toHaveLength(2);
    expect(result.unresolved).toContain(`CONFIGURATION_SOURCE_AMBIGUOUS:${uuid(6)}`);
    expect(result.unresolved).toContain(`CONFIGURATION_SOURCE_AMBIGUOUS:${uuid(11)}`);
  });
  it('keeps disconnected target connection history as a custody reference', () => {
    const s = snapshot();
    s.owners.TARGET_CONNECTION!.rows.push(
      row('TARGET_CONNECTION', 8, { state: 'DISCONNECTED', references: [ref('TARGET', 8)] }),
    );
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.obligations).toContainEqual({
      owner: `TARGET_CONNECTION:${uuid(8)}`,
      state: 'DISCONNECTED',
      reason: 'TARGET_CONNECTION_REFERENCE',
    });
    expect(result.disposition).toBe('UNPROVEN');
  });
  it('keeps selected input explicit and cannot convert stopped business states into retirement', () => {
    const s = snapshot();
    s.root!.state = 'SELECTED';
    const result = inspectRuntimeArtifactReferences(selector, s);
    expect(result.obligations.some((r) => r.reason === 'SELECTED_INPUT')).toBe(true);
    expect(result.references.find((r) => r.kind === 'RUNTIME_GENERATION')?.state).toBe(
      'QUARANTINED',
    );
    expect(result.disposition).toBe('UNPROVEN');
  });
  it('normalizes order but invalidates the observation on source revision, lease or selection changes', () => {
    const s = snapshot(),
      before = inspectRuntimeArtifactReferences(selector, s);
    for (const branch of Object.values(s.owners)) {
      branch.rows.reverse();
      for (const r of branch.rows) {
        r.references.reverse();
        r.tokens.reverse();
      }
    }
    expect(inspectRuntimeArtifactReferences(selector, s).observationDigest).toBe(
      before.observationDigest,
    );
    for (const change of [
      (v: ReturnType<typeof snapshot>) => {
        owner(v, 'TARGET', 8).revision = '2';
      },
      (v: ReturnType<typeof snapshot>) => {
        owner(v, 'WORK', 6).details.leaseUntil = '2026-09-26T01:00:00.000000Z';
      },
      (v: ReturnType<typeof snapshot>) => {
        v.root!.state = 'SELECTED';
      },
    ]) {
      const changed = snapshot();
      change(changed);
      expect(() =>
        assertRuntimeArtifactObservationUnchanged(
          before.observationDigest,
          inspectRuntimeArtifactReferences(selector, changed),
        ),
      ).toThrow(RuntimeArtifactReferenceError);
    }
    expect(() =>
      assertRuntimeArtifactObservationUnchanged(before.observationDigest, before),
    ).not.toThrow();
  });
  it.each([
    (s: ReturnType<typeof snapshot>) => {
      s.participantId = uuid(77);
    },
    (s: ReturnType<typeof snapshot>) => {
      s.root!.id = uuid(77);
    },
    (s: ReturnType<typeof snapshot>) => {
      s.root!.digests.configuration = hash(77);
    },
    (s: ReturnType<typeof snapshot>) => {
      owner(s, 'TARGET', 8).privacyDomainId = uuid(77);
    },
    (s: ReturnType<typeof snapshot>) => {
      s.owners.INPUT!.rows = [];
    },
    (s: ReturnType<typeof snapshot>) => {
      s.owners.TARGET!.rows.push({ ...owner(s, 'TARGET', 8) });
    },
    (s: ReturnType<typeof snapshot>) => {
      s.owners.TARGET!.rows[0]!.kind = 'PROVIDER';
    },
    (s: ReturnType<typeof snapshot>) => {
      delete s.owners.PROBE;
    },
    (s: ReturnType<typeof snapshot>) => {
      s.owners.UNKNOWN = { overflow: false, rows: [] };
    },
    (s: ReturnType<typeof snapshot>) => {
      s.root = { ...s.root!, state: 'SELECTED' };
    },
    (s: ReturnType<typeof snapshot>) => {
      owner(s, 'TARGET', 8).revision = '18446744073709551616';
    },
    (s: ReturnType<typeof snapshot>) => {
      owner(s, 'TARGET', 8).digests.active = 'not-a-digest';
    },
  ])('rejects malformed, contradictory or foreign database observations (%#)', (alter) => {
    const s = snapshot();
    alter(s);
    expect(() => inspectRuntimeArtifactReferences(selector, s)).toThrow(
      RuntimeArtifactReferenceError,
    );
  });
  it('rejects caller authority, over-cap branches and extra payload fields', () => {
    expect(() =>
      inspectRuntimeArtifactReferences({ ...selector, authorized: true }, snapshot()),
    ).toThrow();
    expect(() =>
      inspectRuntimeArtifactReferences(selector, { ...snapshot(), clear: true }),
    ).toThrow();
    const s = snapshot();
    s.owners.TARGET!.rows = Array.from({ length: 129 }, (_, i) => row('TARGET', 100 + i));
    expect(() => inspectRuntimeArtifactReferences(selector, s)).toThrow();
    expect(() =>
      inspectRuntimeArtifactReferences(selector, {
        ...snapshot(),
        root: { ...snapshot().root, configurationCbor: 'secret' },
      }),
    ).toThrow();
  });
});

it('declares scoped original-table reads and live shared-owner fences without grants, mutation or current-only filtering', () => {
  expect(sql).toContain('SECURITY INVOKER');
  expect(sql).toContain("current_setting('transaction_isolation')<>'read committed'");
  expect(sql).toContain('l.pid=pg_backend_pid()');
  expect(sql).toContain("'module-release-catalog','module-admission:'");
  expect(sql).toContain("'openpc-policy-generations:'");
  expect(sql).toContain('REVOKE ALL ON FUNCTION');
  expect(sql).not.toMatch(
    /\b(?:GRANT|INSERT INTO|UPDATE control\.|DELETE FROM|TRUNCATE control\.)/u,
  );
  expect(sql).not.toContain('runtime_configuration_input_current');
  expect(sql).not.toMatch(/(?:lease_token|credential_ref|secret_ref)/u);
  for (const { table } of catalogue) expect(sql).toContain(`from control.${table}`);
  expect(sql).toContain('limit 129');
  expect(sql).toContain(
    'where participant_id=openpc.current_participant_id() and privacy_domain_id=openpc.current_privacy_domain_id()',
  );
  expect(sql).toContain(
    "'bytesMatch',(openpc.runtime_artifact_input_information(runtime_configuration_input_id)->>'bytesMatch')::boolean",
  );
  expect(sql).toContain("'bindingsKnown'");
  expect(sql).toContain("at time zone 'UTC'");
});
