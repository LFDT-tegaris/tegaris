import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import type { MutationContext } from '../../../control-api/src/configuration/persistence/types.js';
import { canonicalJson } from '../domain/digest.js';
import type { RenewPolicyActivation } from '../policy-activation-renewal-contract.js';
import {
  initialQaPolicyRenewalEnvelope,
  renewPolicyActivationInTransaction,
} from './policy-activation-renewal-store.js';

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const d = (c: string) => `sha256:${c.repeat(64)}`;
const b = (c: string) => Buffer.from(c.repeat(64), 'hex');
const hash = (value: unknown) => createHash('sha256').update(canonicalJson(value)).digest();
const cohort = hash([
  { runtimeTargetId: `urn:openpc:resource:${id(301)}`, expectedPredecessorDigest: d('9') },
]);
const input: RenewPolicyActivation = {
  command: 'RENEW_POLICY_ACTIVATION',
  actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
  actionIntentDigest: d('b'),
  reason: 'Fresh governed activation after the root transition.',
  targetRef: `urn:openpc:resource:${id(501)}`,
  expectedRevision: '1',
  releaseBundleId: id(601),
  releaseRevision: '4',
  policyVersionId: id(701),
  policyGenerationId: id(801),
  policyGenerationDigest: d('1'),
  artifactDigest: d('2'),
  compilerManifestDigest: d('3'),
  dependencyClosureDigest: d('4'),
  simulationId: id(901),
  simulationInputDigest: d('5'),
  simulationResultDigest: d('6'),
  factGenerationDigest: d('7'),
  platformContextId: id(401),
  platformAuthorityEpoch: '2',
  platformRevision: '2',
  exactCohortDigest: `sha256:${cohort.toString('hex')}`,
  targets: [
    {
      targetId: id(301),
      expectedRevision: '42',
      expectedPredecessorDigest: d('9'),
      configurationDigest: d('a'),
      providerProfileId: id(302),
      providerRevision: '20',
      providerFingerprint: d('c'),
      providerObservationId: id(304),
      providerObservationDigest: d('d'),
      providerObservationValidUntil: '2026-10-01T16:00:00.000Z',
      providerObservationConfigurationDigest: d('a'),
      projectionPlanId: id(303),
    },
  ],
};
const context = {
  actionIntentId: input.actionIntentId,
  actionIntentDigest: input.actionIntentDigest,
  catalogOperationId: 'CFG-OP-RENEW-POLICY-ACTIVATION',
  resourceId: id(501),
  expectedRevision: '1',
  idempotencyKey: 'policy-renewal-exact-intent',
  candidate: input,
  authorization: {
    participantId: id(101),
    privacyDomainId: id(201),
    principalId: id(111),
    checkerPrincipalId: id(112),
    authorityEnvelopeId: id(911),
    approvalRequestId: id(912),
    sessionId: id(913),
    participantEpoch: '1',
    principalEpoch: '1',
  },
} as unknown as MutationContext;
function fixture(
  mode:
    | 'current'
    | 'initial-prepared'
    | 'initial-reconnect'
    | 'active-revision-drift'
    | 'prior-effect'
    | 'stale-root'
    | 'missing-root'
    | 'missing-approval'
    | 'dispatch-failure' = 'current',
) {
  const statements: { sql: string; args: readonly unknown[] }[] = [];
  const reconnected = mode === 'initial-reconnect';
  const initialCohort = hash([
    { runtimeTargetId: `urn:openpc:resource:${id(301)}`, expectedPredecessorDigest: null },
  ]);
  const occurrence = {
    activationOccurrenceId: id(501),
    releaseBundleId: id(601),
    policyGenerationId: id(801),
    createdByPrincipalId: id(111),
    targetGenerationDigest: b('1'),
    exactCohortDigest: reconnected ? initialCohort : cohort,
    state: 'REQUESTED',
    totalTargetCount: '1',
    matchedTargetCount: '1',
    revision: '1',
  };
  const release = {
    releaseBundleId: id(601),
    releaseRevision: '4',
    policyId: id(602),
    policyVersionId: id(701),
    approvalRequestId: id(610),
    createdByPrincipalId: id(111),
    manifestDigest: b('1'),
    dependencyClosureDigest: b('4'),
    schemaDigest: b('3'),
    simulationId: id(901),
    simulationInputDigest: b('5'),
    simulationResultDigest: b('6'),
    simulationTruthState: 'SUCCESS',
    simulationAuthorityLabel: 'SIMULATION_ONLY',
    factGenerationDigest: b('7'),
    simulationCompletedAt: '2026-10-01T15:00:00.000Z',
    artifactPayloadDigest: b('2'),
    checkerPrincipalId: id(112),
    approvalDecisionDigest: b('c'),
  };
  const target = {
    ...input.targets[0],
    state: 'ACTIVE_MATCHED',
    revision: '42',
    activeGenerationDigest: d('9'),
    desiredGenerationDigest: d('9'),
    policyGenerationDigest: d('1'),
    configurationDigest: b('a'),
    ...(reconnected
      ? {
          state: 'DISCOVERED',
          revision: '44',
          activeGenerationDigest: null,
          desiredGenerationDigest: null,
          policyGenerationDigest: null,
        }
      : mode === 'active-revision-drift'
        ? { revision: '44' }
        : {}),
  };
  const query = vi.fn(async (sql: string, args: readonly unknown[] = []) => {
    statements.push({ sql, args: [...args] });
    if (
      sql.includes('from control.policy_activation_occurrence occurrence') &&
      sql.includes('as "activationOccurrenceId"')
    )
      return { rowCount: 1, rows: [occurrence] };
    if (sql.includes('from control.policy_release_bundle release'))
      return { rowCount: 1, rows: [release] };
    if (sql.includes('as "initialPrepared" from control.policy_generation'))
      return mode === 'prior-effect'
        ? { rowCount: 0, rows: [] }
        : {
            rowCount: 1,
            rows: [{ initialPrepared: mode === 'initial-prepared' || reconnected }],
          };
    if (sql.includes('select 1 from control.runtime_target where'))
      return { rowCount: 0, rows: [] };
    if (sql.includes('target.runtime_target_id::text as "targetId",target.state'))
      return { rowCount: 1, rows: [target] };
    if (sql.includes('expected_target_revision::text as "expectedRevision"'))
      return {
        rowCount: 1,
        rows: [{ targetId: id(301), expectedRevision: '42', requiresAuthenticatedDiscovery: true }],
      };
    if (
      sql.includes('from control.provider_profile provider join control.provider_probe_observation')
    )
      return { rowCount: 1, rows: [{ ...input.targets[0]! }] };
    if (sql.includes('select root.platform_context_id'))
      return mode === 'missing-root'
        ? { rowCount: 0, rows: [] }
        : {
            rowCount: 1,
            rows: [
              {
                platformContextId: id(401),
                platformAuthorityEpoch: mode === 'stale-root' ? '3' : '2',
                platformRevision: '2',
              },
            ],
          };
    if (
      sql.includes('decision.decision_digest as "approvalDecisionDigest"') &&
      sql.includes('control.mutation_candidate')
    )
      return mode === 'missing-approval'
        ? { rowCount: 0, rows: [] }
        : { rowCount: 1, rows: [{ approvalRequestId: id(912), approvalDecisionDigest: b('d') }] };
    if (sql.includes('challenge.mfa_challenge_id::text as "mfaChallengeId"'))
      return {
        rowCount: 1,
        rows: [
          {
            mfaChallengeId: id(914),
            assertionBindingDigest: b('e'),
            evidenceCbor: Buffer.alloc(1),
            evidenceDigest: b('f'),
            coseSign1: Buffer.alloc(1),
            signerCredentialId: id(915),
          },
        ],
      };
    if (sql.includes('select generation_digest as prior')) return { rowCount: 0, rows: [] };
    if (sql.includes('target.revision::text as "targetRevision"')) {
      if (mode === 'dispatch-failure') return { rowCount: 0, rows: [] };
      return {
        rowCount: 1,
        rows: [
          {
            configurationDigest: d('a'),
            providerProfileId: id(302),
            projectionPlanId: id(303),
            targetRevision: target.revision,
            activeGenerationDigest: target.activeGenerationDigest,
          },
        ],
      };
    }
    if (sql.includes('insert into control.runtime_configuration_generation'))
      return { rowCount: 1, rows: [{ id: id(916) }] };
    if (sql.includes('insert into control.configuration_work'))
      return { rowCount: 1, rows: [{ id: id(917), operationId: id(918) }] };
    if (sql.includes("set state='STAGING',matched_target_count=0"))
      return { rowCount: 1, rows: [{ revision: '2' }] };
    return { rowCount: 1, rows: [{}] };
  });
  return { client: { query } as unknown as PoolClient, statements };
}
describe('governed renewal transaction writer', () => {
  it('dispatches the freshly approved initial revision while preserving the original cohort snapshot', async () => {
    const f = fixture('initial-reconnect');
    const fresh = {
      ...input,
      exactCohortDigest: `sha256:${hash([
        { runtimeTargetId: `urn:openpc:resource:${id(301)}`, expectedPredecessorDigest: null },
      ]).toString('hex')}`,
      targets: [{ ...input.targets[0]!, expectedRevision: '44', expectedPredecessorDigest: null }],
    };
    await expect(
      renewPolicyActivationInTransaction(f.client, context, id(919), fresh),
    ).resolves.toMatchObject({ state: 'STAGING', revision: '2' });
    const targetUpdate = f.statements.find(({ sql }) =>
      sql.includes('set desired_generation_digest=$5'),
    );
    expect(targetUpdate?.args[3]).toBe('44');
    expect(f.statements.some(({ sql }) => /set\s+expected_target_revision/iu.test(sql))).toBe(
      false,
    );
    expect(
      f.statements.find(({ sql }) => sql.includes('expected_target_revision::text'))?.sql,
    ).toContain('for share');
  });
  it('rejects active-target revision drift before approval, activation or work dispatch', async () => {
    const f = fixture('active-revision-drift');
    await expect(
      renewPolicyActivationInTransaction(f.client, context, id(919), input),
    ).rejects.toThrow('PC-POLICY-2003');
    expect(f.statements.some(({ sql }) => /insert into control\./u.test(sql))).toBe(false);
  });
  it('records fresh approval on a new activation and leaves historical release/generation authority intact', async () => {
    const f = fixture();
    await expect(
      renewPolicyActivationInTransaction(f.client, context, id(919), input),
    ).resolves.toMatchObject({ state: 'STAGING', revision: '2' });
    const activation = f.statements.find(({ sql }) =>
      sql.includes('insert into control.policy_activation\n'),
    );
    expect(activation?.args[4]).toBe(id(912));
    expect(activation?.args[4]).not.toBe(id(610));
    expect(
      f.statements.some(({ sql }) =>
        /^update control\.(?:policy_generation|policy_release_bundle)/u.test(sql.trim()),
      ),
    ).toBe(false);
    const work = f.statements.find(({ sql }) =>
      sql.includes('insert into control.configuration_work'),
    );
    expect(work).toBeDefined();
    expect(work?.args).toContain(input.policyGenerationDigest);
    const root = f.statements.find(({ sql }) => sql.includes('select root.platform_context_id'));
    expect(root?.sql).toContain('openpc.lock_platform_scope_context(envelope.platform_context_id)');
    expect(root?.sql).toContain('root.owner_participant_id=envelope.participant_id');
    expect(root?.sql).toContain('envelope.platform_authority_epoch=root.authority_epoch');
    expect(root?.sql).toContain("pending.state='WITHDRAWING'");
    expect(root?.sql).toContain('for share of envelope');
    expect(root?.sql).not.toContain('for share of root');
    expect(root?.args).toEqual([
      context.authorization.participantId,
      context.authorization.authorityEnvelopeId,
      false,
      context.authorization.privacyDomainId,
    ]);
    // Completed native observations are immutable and SELECT-only to Policy;
    // the mutable provider pointer/revision is the row that must be locked.
    const providers = f.statements.find(({ sql }) =>
      sql.includes(
        'from control.provider_profile provider join control.provider_probe_observation',
      ),
    )!;
    expect(providers.sql).toContain('for share of provider');
    expect(providers.sql).not.toContain('for share of provider,observation');
  });
  it('allows an unexecuted PREPARED generation through fresh typed approval without granting legacy compatibility', async () => {
    const f = fixture('initial-prepared');
    await expect(
      renewPolicyActivationInTransaction(f.client, context, id(919), input),
    ).resolves.toMatchObject({ state: 'STAGING' });
    const retained = f.statements.find(({ sql }) => sql.includes('as "initialPrepared"'))!;
    expect(retained.sql).toContain("generation.state='PREPARED' and not generation.active");
    expect(retained.sql).toContain(
      'activation.policy_generation_id=generation.policy_generation_id',
    );
    expect(retained.sql).toContain("runtime.policy_generation_digest='sha256:'");
    for (const field of [
      'expected_predecessor_digest',
      'configuration_work_id',
      'runtime_configuration_generation_id',
      'command_operation_id',
      'observed_generation_digest',
      'activation_receipt_digest',
    ])
      expect(retained.sql).toContain(`initial_cohort.${field} is not null`);
    expect(
      f.statements.find(({ sql }) => sql.includes('select root.platform_context_id'))?.args[2],
    ).toBe(false);
  });
  it.each(['prior-effect', 'stale-root', 'missing-root', 'missing-approval'] as const)(
    'denies %s before producing activation or runtime work',
    async (mode) => {
      const f = fixture(mode);
      await expect(
        renewPolicyActivationInTransaction(f.client, context, id(919), input),
      ).rejects.toThrow();
      expect(
        f.statements.some(({ sql }) =>
          /insert into control\.(?:policy_activation|configuration_work)/u.test(sql),
        ),
      ).toBe(false);
    },
  );
  it('rejects self-approval before reading any business state', async () => {
    const f = fixture();
    await expect(
      renewPolicyActivationInTransaction(
        f.client,
        {
          ...context,
          authorization: {
            ...context.authorization,
            checkerPrincipalId: context.authorization.principalId,
          },
        },
        id(919),
        input,
      ),
    ).rejects.toThrow('PC-POLICY-2004');
    expect(f.statements).toHaveLength(0);
  });
  it('propagates dispatch failure to the atomic owner without marking the occurrence staged', async () => {
    const f = fixture('dispatch-failure');
    await expect(
      renewPolicyActivationInTransaction(f.client, context, id(919), input),
    ).rejects.toThrow('PC-POLICY-2003');
    expect(
      f.statements.some(({ sql }) => sql.includes("set state='STAGING',matched_target_count=0")),
    ).toBe(false);
    expect(f.statements.some(({ sql }) => sql === 'commit')).toBe(false);
  });
});

describe('initial QA bootstrap compatibility pin', () => {
  const env = {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1',
    OPENPC_LOCAL_QA_INITIAL_POLICY_RENEWAL_ENVELOPE_IDS: `${id(911)},${id(912)}`,
  };
  it('requires both QA gates and the exact installed envelope pin', () => {
    expect(initialQaPolicyRenewalEnvelope(env, id(911))).toBe(true);
    expect(initialQaPolicyRenewalEnvelope(env, id(913))).toBe(false);
    for (const key of Object.keys(env))
      expect(initialQaPolicyRenewalEnvelope({ ...env, [key]: undefined }, id(911))).toBe(false);
    expect(
      initialQaPolicyRenewalEnvelope(
        { ...env, OPENPC_LOCAL_QA_INITIAL_POLICY_RENEWAL_ENVELOPE_IDS: `${id(911)},*` },
        id(911),
      ),
    ).toBe(false);
  });
  it('never admits LEGACY through the active renewal branch', async () => {
    vi.stubEnv('OPENPC_LOCAL_RUNTIME', '1');
    vi.stubEnv('OPENPC_LOCAL_RUNTIME_QA_FIXTURE', '1');
    vi.stubEnv('OPENPC_LOCAL_QA_INITIAL_POLICY_RENEWAL_ENVELOPE_IDS', id(911));
    try {
      const f = fixture();
      await renewPolicyActivationInTransaction(f.client, context, id(919), input);
      expect(
        f.statements.find(({ sql }) => sql.includes('select root.platform_context_id'))?.args[2],
      ).toBe(false);
    } finally {
      vi.unstubAllEnvs();
    }
  });
  it('binds a pinned initial branch to authenticated immutable epoch-one installation and fresh root ownership', async () => {
    for (const [key, value] of Object.entries(env)) vi.stubEnv(key, value);
    try {
      const f = fixture('initial-prepared');
      await renewPolicyActivationInTransaction(f.client, context, id(919), input);
      const root = f.statements.find(({ sql }) => sql.includes('select root.platform_context_id'))!;
      expect(root.args[2]).toBe(true);
      expect(root.sql).toContain("envelope.representation='LEGACY' and root.authority_epoch=1");
      expect(root.sql).toContain('installation.owner_participant_id=envelope.participant_id');
      expect(root.sql).toContain('installation.installation_privacy_domain_id=$4::uuid');
      expect(root.sql).toContain(
        'installation.admission_digest=sha256(installation.admission_preimage)',
      );
      expect(root.sql).toContain('SYNTHETIC_LOCAL_QA_TRUST');
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
