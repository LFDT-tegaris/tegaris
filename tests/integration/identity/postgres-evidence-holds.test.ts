import { randomBytes } from 'node:crypto';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.js';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.js';
import {
  encodeEvidenceHoldSelector,
  evidenceHoldSelector,
} from '../../../services/control-api/src/evidence/hold-contracts.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { digest } from './public-governance-client.js';
import {
  verifyReceiptCose,
  decodeAdmittedReceipt,
} from '../../../packages/security-kernel/src/index.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const workerUrl = process.env.OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL;
const integration = adminUrl && workerUrl ? it : it.skip;

integration(
  'resumes both exact hold creation intents after natural approval expiry without duplicating effects',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const pid = id(),
      privacy = id();
    const fixture = await contractAdministrationFixture(
      admin,
      process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
      pid,
      privacy,
    );
    const signing = await evidenceGovernanceSigningFixture(admin, pid, privacy);
    const { client, policyUrl } = fixture.governance;
    const resumeAction = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
    const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
    const read = async (approvalId: string) => {
      const result = await fixture.approvalRead(approvalId);
      expect(result.status, JSON.stringify(result)).toBe(200);
      return result.body;
    };
    const resume = async (
      approvalId: string,
      view: Awaited<ReturnType<typeof read>>,
      key: string,
      actor = fixture.governance.maker,
    ) =>
      client.request(
        `${policyUrl}/api/v1/approval-requests/urn:openpc:resource:${approvalId}`,
        actor,
        {
          command: 'RESUME',
          actionIntentId: resumeAction,
          actionIntentDigest: client.actionDigests.get(resumeAction),
          expectedRevision: '2',
          predecessorCandidateId: view.attemptId,
          expectedAttempt: view.attempt,
          candidateDigest: view.candidateDigest,
          reason: 'Resume the exact unchanged preservation intent.',
        },
        {
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${pid}`,
          'X-Request-ID': id(),
          'X-Correlation-ID': id(),
          'Idempotency-Key': key,
          'X-CSRF-Token': await client.csrf(actor, resumeAction, policyUrl),
          'X-OpenPC-Action-Intent-Digest': client.actionDigests.get(resumeAction)!,
          'If-Match': `"${digest({ resourceId: approvalId, revision: '2' })}"`,
        },
        'PATCH',
      );
    try {
      await fixture.restartConfiguration(signing.evidence);
      const pending = [];
      for (const participant of [false, true]) {
        const action = participant
          ? 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1'
          : 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1';
        const prepared = await fixture.prepareMutation(
          'evidence-holds',
          action,
          {
            participantId: `urn:openpc:participant:${pid}`,
            holdKind: 'LEGAL',
            selector: { type: participant ? 'PARTICIPANT' : 'PRIVACY_DOMAIN' },
          },
          true,
        );
        await prepared.stepUp();
        signing.faults.mode = 'UNAVAILABLE';
        const callsBefore = signing.faults.calls;
        expect((await prepared.commit()).status).toBe(409);
        expect(signing.faults.calls).toBe(callsBefore + 1);
        signing.faults.mode = undefined;
        const original = await read(prepared.approvalId);
        expect(original).toMatchObject({
          state: 'APPROVED',
          approvalUsable: true,
          canRequestResume: false,
          operationRef: null,
        });
        expect([403, 409]).toContain(
          (await resume(prepared.approvalId, original, `live-${id()}`)).status,
        );
        const expiry = (
          await admin.query(
            `select extract(epoch from least(m.expires_at,m.consumed_at+interval '5 minutes'))*1000 expiry
          from control.approval_decision_record d join control.mfa_challenge m using(participant_id,mfa_challenge_id)
          where d.approval_request_id=$1`,
            [prepared.approvalId],
          )
        ).rows[0].expiry;
        pending.push({ prepared, original, action, expiry: Number(expiry) });
      }
      const expiry = Math.max(...pending.map((item) => item.expiry));
      while (Date.now() <= expiry) {
        process.stdout.write(
          `OPENPC_HOLD_RESUME|natural-expiry|remaining_ms=${Math.ceil(expiry - Date.now())}\n`,
        );
        await delay(Math.min(30000, expiry - Date.now() + 100));
      }
      for (const { prepared, original, action } of pending) {
        expect(
          (
            await admin.query(
              'select count(*)::int n from control.retention_hold where retention_hold_id=$1',
              [prepared.resourceId],
            )
          ).rows[0].n,
        ).toBe(0);
        const expired = await read(prepared.approvalId);
        expect(expired).toMatchObject({
          canRequestResume: true,
          approvalUsable: false,
          operationRef: null,
        });
        expect([403, 404]).toContain(
          (
            await resume(
              prepared.approvalId,
              original,
              `checker-${id()}`,
              fixture.governance.checker,
            )
          ).status,
        );
        expect([403, 404, 422]).toContain(
          (
            await resume(
              prepared.approvalId,
              { ...original, candidateDigest: digest({}) },
              `changed-${id()}`,
            )
          ).status,
        );
        const keys = [`resume-${id()}`, `resume-${id()}`];
        const raced = await Promise.all(
          keys.map((key) => resume(prepared.approvalId, original, key)),
        );
        const winner = raced.findIndex((value) => value.status === 202);
        expect(winner).toBeGreaterThanOrEqual(0);
        expect(raced.filter((value) => value.status === 202)).toHaveLength(1);
        expect([403, 409]).toContain(raced[1 - winner]!.status);
        expect(await resume(prepared.approvalId, original, keys[winner]!)).toEqual(raced[winner]);
        const nextId = String(raced[winner]!.body.resourceRef).slice(-36);
        const next = await read(nextId);
        expect(next).toMatchObject({
          attempt: '2',
          state: 'APPROVAL_REQUESTED',
          candidate: original.candidate,
          candidateDigest: original.candidateDigest,
          resourceRef: original.resourceRef,
          businessIdempotencyKey: original.businessIdempotencyKey,
          predecessorApprovalRef: `urn:openpc:resource:${prepared.approvalId}`,
          operationRef: null,
        });
        expect((await prepared.commit()).status).toBe(403);
        const targetRef = `urn:openpc:resource:${nextId}`;
        const inputDigest = digest({
          actionIntentId: approveAction,
          approvalRequestId: targetRef,
          candidateDigest: original.candidateDigest,
          expectedRevision: '1',
          decision: 'APPROVE',
        });
        await client.stepUp(fixture.governance.checker, approveAction, nextId, inputDigest);
        const approved = await client.policyMutation(
          fixture.governance.checker,
          `/api/v1/approval-requests/${targetRef}/approve`,
          {
            targetRef,
            actionIntentId: approveAction,
            actionIntentDigest: client.actionDigests.get(approveAction),
            inputDigest,
            expectedRevision: '1',
            reason: 'Independently approve the original exact hold.',
          },
          '1',
        );
        expect(approved.status, JSON.stringify(approved)).toBe(202);
        await client.stepUp(
          fixture.governance.maker,
          action,
          prepared.resourceId,
          original.candidateDigest,
        );
        const created = await prepared.commit();
        expect(created.status, JSON.stringify(created)).toBe(202);
        expect((await prepared.commit()).body).toEqual(created.body);
        expect(String(created.body.resourceRef)).toBe(original.resourceRef);
        expect([403, 409]).toContain(
          (await resume(nextId, await read(nextId), `committed-${id()}`)).status,
        );
        expect(
          (
            await admin.query(
              `select
          (select count(*)::int from control.retention_hold where retention_hold_id=$1) holds,
          (select count(*)::int from control.audit_occurrence where aggregate_id=$1) receipts,
          (select count(*)::int from control.outbox_event where aggregate_id=$1) outbox`,
              [prepared.resourceId],
            )
          ).rows[0],
        ).toEqual({ holds: 1, receipts: 1, outbox: 1 });
        await fixture.restartConfiguration(signing.evidence);
        expect((await fixture.read(`evidence-holds/${original.resourceRef}`)).body.state).toBe(
          'ACTIVE',
        );
      }
    } finally {
      signing.close();
      await fixture.close();
      await admin.end();
    }
  },
  480000,
);

integration(
  'governs a Participant hold at the root and preserves existing and future objects in another explicit privacy domain',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'participant-held' };
    const child = { ...scope, privacyDomainId: id() };
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'participant-hold-'));
    let maker: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let childActor: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let signing: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>> | undefined;
    const createAction = 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1';
    const releaseAction = 'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1';
    const records = () => {
      const bytes = Buffer.from(`Labelled custody fixture ${id()}`);
      return [
        {
          recordId: id(),
          evidenceClass: 'AUTHENTICATION' as const,
          sourceFormat: 'FIXTURE',
          occurredAt: '2026-09-21T00:00:00.000000Z',
          receiptDigest: sha256(bytes),
          receiptBase64: bytes.toString('base64'),
        },
      ];
    };
    try {
      maker = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
      );
      signing = await evidenceGovernanceSigningFixture(
        admin,
        scope.participantId,
        scope.privacyDomainId,
      );
      await maker.restartConfiguration(signing.evidence);
      await admin.query(
        `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
      values($1,$2,'Child initial trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')`,
        [child.privacyDomainId, child.participantId],
      );
      // Both bootstrap actors can authenticate/step up in the root and explicitly
      // select the child. The test's business requests remain child scoped.
      childActor = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        child.participantId,
        child.privacyDomainId,
        {
          existingScope: true,
          initialPrivacyDomainIds: [scope.privacyDomainId, child.privacyDomainId],
        },
      );
      await childActor.selectPrivacyContext('maker', { freshStepUp: true });
      await childActor.selectPrivacyContext('checker', { freshStepUp: true });
      expect((await childActor.read('evidence-holds?limit=50')).status).toBe(200);
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      const custody = new EvidenceCustody(worker);
      const encryption = { keyId: 'participant-hold-key', key: randomBytes(32) };
      const first = records();
      await custody.admit(child, first, encryption, '2027-01-01T00:00:00.000000Z', 65536);
      const fields = {
        participantId: `urn:openpc:participant:${scope.participantId}`,
        holdKind: 'LEGAL',
        selector: { type: 'PARTICIPANT' },
      };
      // A valid child approval must hit the root-only boundary even when the
      // child has no Participant receipt signing selection. It is a scope
      // denial, not a transient provider error or a reason to retry elsewhere.
      await childActor.restartConfiguration(signing.evidence);
      const childCreate = await childActor.prepareMutation(
        'evidence-holds',
        createAction,
        fields,
        true,
      );
      await childCreate.stepUp();
      const signingCalls = signing.faults.calls;
      expect(await childCreate.commit()).toMatchObject({
        status: 403,
        body: { code: 'PC-AUTH-0005' },
      });
      expect(signing.faults.calls).toBe(signingCalls);
      expect((await childActor.read('evidence-holds?limit=50')).body.items).toEqual([]);
      const wrongAction = maker.ordinaryMutation(
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
        fields,
      );
      expect((await wrongAction.call(wrongAction.body, true)).status).toBe(400);
      const prepared = await maker.prepareMutation('evidence-holds', createAction, fields, true);
      expect((await prepared.commit()).status).toBe(403);
      await prepared.stepUp();
      const created = await prepared.commit();
      expect(created, JSON.stringify(created)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      const reference = String(created.body.resourceRef);
      expect((await prepared.commit()).body).toEqual(created.body);
      const rootView = await maker.read(`evidence-holds/${reference}`);
      expect(rootView).toMatchObject({
        status: 200,
        body: {
          state: 'ACTIVE',
          selector: { type: 'PARTICIPANT' },
          governancePrivacyDomainId: scope.privacyDomainId,
        },
      });
      expect(rootView.body.creationReceiptDigest).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(await childActor.read(`evidence-holds/${reference}`)).toMatchObject({
        status: 200,
        body: {
          coverage: 'PENDING',
          coveragePrivacyDomainId: child.privacyDomainId,
          governancePrivacyDomainId: scope.privacyDomainId,
        },
      });
      expect((await foreign.read(`evidence-holds/${reference}`)).status).toBe(404);
      const catalogue = await childActor.read('evidence-records?limit=50');
      const record = catalogue.body.items.find(
        (value: { recordDigest: string }) => value.recordDigest === first[0]!.receiptDigest,
      );
      expect(record.state).toBe('HELD');
      const plan = await childActor.read(`evidence-records/${record.evidenceId}/deletion-plan`);
      expect(plan.status).toBe(200);
      expect(plan.body.blockers).toContain('ACTIVE_HOLD');
      const sink = await LocalEvidenceVault.open(join(root, 'vault'), 'participant-hold-sink');
      await custody.exportNext(child, sink);
      expect((await childActor.read(`evidence-holds/${reference}`)).body.coverage).toBe('VERIFIED');
      // A held object in a new segment is fenced immediately, before sink contact.
      const rootFence = await worker.connect();
      let future: ReturnType<typeof custody.admit> | undefined;
      try {
        await rootFence.query('begin');
        await rootFence.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
          [scope.participantId, scope.privacyDomainId, id()],
        );
        const blocker = (await rootFence.query('select pg_backend_pid() pid')).rows[0].pid;
        await rootFence.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
          `evidence-lifecycle:${scope.participantId}`,
        ]);
        future = custody.admit(child, records(), encryption, '2027-01-01T00:00:00.000000Z', 65536);
        let blocked = false;
        for (let attempt = 0; attempt < 100; attempt++) {
          blocked = (
            await admin.query(
              'select exists(select 1 from pg_stat_activity where $1::int=any(pg_blocking_pids(pid))) blocked',
              [blocker],
            )
          ).rows[0].blocked;
          if (blocked) break;
          await delay(10);
        }
        expect(blocked).toBe(true);
        await rootFence.query('commit');
      } finally {
        await rootFence.query('rollback');
        rootFence.release();
      }
      await future;
      expect((await childActor.read(`evidence-holds/${reference}`)).body.coverage).toBe('PENDING');
      await custody.exportNext(child, sink);
      await maker.restartConfiguration(signing.evidence);
      await childActor.restartConfiguration();
      expect((await childActor.read(`evidence-holds/${reference}`)).body.coverage).toBe('VERIFIED');
      // The child can see the rule affecting its objects, but cannot mutate the
      // root-governed aggregate even with a child-scoped grant for the new action.
      const denied = await childActor.create(
        `evidence-holds/${reference}/release`,
        releaseAction,
        { targetRef: reference, expectedRevision: '1' },
        0,
      );
      expect(denied.status).toBeGreaterThanOrEqual(400);
      expect((await maker.read(`evidence-holds/${reference}`)).body.state).toBe('ACTIVE');
      const release = await maker.prepareMutation(
        `evidence-holds/${reference}/release`,
        releaseAction,
        { targetRef: reference, expectedRevision: '1' },
        true,
      );
      await release.stepUp();
      const released = await release.commit();
      expect(released, JSON.stringify(released)).toMatchObject({ status: 202 });
      expect((await release.commit()).body).toEqual(released.body);
      await custody.reconcileHolds(child, sink);
      expect((await childActor.read(`evidence-holds/${reference}`)).body).toMatchObject({
        state: 'RELEASED',
        revision: '2',
        coverage: 'VERIFIED',
      });
      const oldCount = (
        await admin.query(
          'select count(*)::int n from control.evidence_hold_coverage where retention_hold_id=$1',
          [reference.slice(-36)],
        )
      ).rows[0].n;
      expect(oldCount).toBe(4);
      await custody.admit(child, records(), encryption, '2027-01-01T00:00:00.000000Z', 65536);
      await custody.exportNext(child, sink);
      expect(
        (
          await admin.query(
            'select count(*)::int n from control.evidence_hold_coverage where retention_hold_id=$1',
            [reference.slice(-36)],
          )
        ).rows[0].n,
      ).toBe(oldCount);
      const receipts = await admin.query(
        `select a.receipt_cbor,a.cose_sign1,k.public_key_spki_der from control.audit_occurrence a
      join control.business_signing_key k using(participant_id,privacy_domain_id,signer_id) where a.participant_id=$1 and a.aggregate_id=$2 order by a.after_revision`,
        [scope.participantId, reference.slice(-36)],
      );
      expect(receipts.rowCount).toBe(2);
      for (const [index, row] of receipts.rows.entries()) {
        expect(verifyReceiptCose(row.public_key_spki_der, row.receipt_cbor, row.cose_sign1)).toBe(
          true,
        );
        expect(decodeAdmittedReceipt(row.receipt_cbor).transitionProfileId).toBe(
          `pc.control.evidence-participant-hold.${index === 0 ? 'create' : 'release'}`,
        );
      }
    } finally {
      signing?.close();
      await maker?.close();
      await childActor?.close();
      await foreign?.close();
      await worker.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  120000,
);

integration(
  'matches exact source dimensions and the independent SQL/PC-CBOR selector encoding without treating missing knowledge as a non-match',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 1 });
    const scope = { participantId: id(), privacyDomainId: id() };
    const projection = `urn:openpc:resource:${id()}`;
    const profile = `urn:openpc:fact-profile:${id()}`;
    const generation = {
      kind: 'CANONICAL_FACT',
      factProfileId: profile,
      canonicalGeneration: '9007199254740993',
    };
    const hash = `sha256:${'ab'.repeat(32)}`;
    const block = {
      chainId: String(2n ** 256n - 1n),
      genesisDigest: hash,
      blockNumber: '18446744073709551615',
    };
    const metadata = {
      projections: [projection],
      facts: [{ factType: 'RELATIONSHIP', factProfileId: profile, factKeyDigest: hash }],
      generations: { CANONICAL_FACT: [generation], RUNTIME_CONFIGURATION: [] },
      blocks: [block],
    };
    try {
      for (const input of [
        { type: 'PARTICIPANT' },
        { type: 'PRIVACY_DOMAIN' },
        {
          type: 'SEQUENCE_RANGE',
          streamId: 'exact-stream',
          fromSequence: '9007199254740993',
          throughSequence: null,
        },
        { type: 'DIGEST', recordDigest: hash },
        { type: 'PROJECTION', projectionId: projection },
        {
          type: 'FACT_TYPE_KEY',
          factType: 'RELATIONSHIP',
          factProfileId: profile,
          factKeyDigest: null,
        },
        {
          type: 'FACT_TYPE_KEY',
          factType: 'RELATIONSHIP',
          factProfileId: profile,
          factKeyDigest: hash,
        },
        {
          type: 'BLOCK_RANGE',
          chainId: block.chainId,
          genesisDigest: hash,
          fromBlock: block.blockNumber,
          throughBlock: null,
        },
        {
          type: 'BLOCK_RANGE',
          chainId: block.chainId,
          genesisDigest: hash,
          fromBlock: '0',
          throughBlock: block.blockNumber,
        },
        { type: 'GENERATION', generation },
        {
          type: 'GENERATION',
          generation: { kind: 'RUNTIME_CONFIGURATION', generationId: projection },
        },
      ]) {
        const bound = encodeEvidenceHoldSelector(scope, evidenceHoldSelector.parse(input));
        expect(
          (
            await admin.query(
              'select openpc.business_cbor($1)=openpc.evidence_hold_selector_encoding($2::jsonb,$3,$4) equal',
              [bound.bytes, JSON.stringify(input), scope.participantId, scope.privacyDomainId],
            )
          ).rows[0].equal,
        ).toBe(true);
      }
      const match = async (selector: unknown, source: unknown = metadata) =>
        (
          await admin.query(
            'select openpc.evidence_hold_source_match($1::jsonb,$2::jsonb) matched',
            [JSON.stringify(selector), JSON.stringify(source)],
          )
        ).rows[0].matched;
      for (const selector of [
        { type: 'PROJECTION', projectionId: projection },
        {
          type: 'FACT_TYPE_KEY',
          factType: 'RELATIONSHIP',
          factProfileId: profile,
          factKeyDigest: hash,
        },
        {
          type: 'FACT_TYPE_KEY',
          factType: 'RELATIONSHIP',
          factProfileId: profile,
          factKeyDigest: null,
        },
        {
          type: 'BLOCK_RANGE',
          chainId: block.chainId,
          genesisDigest: hash,
          fromBlock: block.blockNumber,
          throughBlock: null,
        },
        { type: 'GENERATION', generation },
      ]) {
        expect(await match(selector)).toBe(true);
        expect(await match(selector, { ...metadata, unresolvedReferences: true })).toBe(true);
        for (const invalid of [null, 'false', 0, []])
          expect(await match(selector, { ...metadata, unresolvedReferences: invalid })).toBeNull();
        expect(await match(selector, {})).toBeNull();
        expect(await match(selector, null)).toBeNull();
        expect(
          await match(selector, {
            projections: [],
            facts: [],
            blocks: [],
            generations: { CANONICAL_FACT: [], RUNTIME_CONFIGURATION: [] },
          }),
        ).toBe(false);
        for (const malformed of [null, {}, '*', { blockNumber: '-1' }]) {
          const dimension: keyof typeof metadata =
            selector.type === 'PROJECTION'
              ? 'projections'
              : selector.type === 'FACT_TYPE_KEY'
                ? 'facts'
                : selector.type === 'BLOCK_RANGE'
                  ? 'blocks'
                  : 'generations';
          const entries =
            dimension === 'generations' ? metadata.generations.CANONICAL_FACT : metadata[dimension];
          for (const values of [[malformed], [...entries, malformed]]) {
            const value = dimension === 'generations' ? { CANONICAL_FACT: values } : values;
            expect(await match(selector, { ...metadata, [dimension]: value })).toBeNull();
          }
        }
      }
      for (const selector of [
        { type: 'PROJECTION', projectionId: `urn:openpc:resource:${id()}` },
        {
          type: 'FACT_TYPE_KEY',
          factType: 'CONTRACT_STATE_CALL',
          factProfileId: profile,
          factKeyDigest: hash,
        },
        {
          type: 'FACT_TYPE_KEY',
          factType: 'RELATIONSHIP',
          factProfileId: `urn:openpc:fact-profile:${id()}`,
          factKeyDigest: hash,
        },
        {
          type: 'FACT_TYPE_KEY',
          factType: 'RELATIONSHIP',
          factProfileId: profile,
          factKeyDigest: `sha256:${'cd'.repeat(32)}`,
        },
        {
          type: 'BLOCK_RANGE',
          chainId: block.chainId,
          genesisDigest: `sha256:${'cd'.repeat(32)}`,
          fromBlock: '0',
          throughBlock: null,
        },
        {
          type: 'BLOCK_RANGE',
          chainId: '31337',
          genesisDigest: hash,
          fromBlock: '0',
          throughBlock: null,
        },
        {
          type: 'BLOCK_RANGE',
          chainId: block.chainId,
          genesisDigest: hash,
          fromBlock: '0',
          throughBlock: '18446744073709551614',
        },
        {
          type: 'GENERATION',
          generation: { ...generation, canonicalGeneration: '9007199254740992' },
        },
        {
          type: 'GENERATION',
          generation: { kind: 'RUNTIME_CONFIGURATION', generationId: projection },
        },
      ]) {
        expect(await match(selector)).toBe(false);
        expect(await match(selector, { ...metadata, unresolvedReferences: true })).toBeNull();
      }
      const runtimeGeneration = { kind: 'RUNTIME_CONFIGURATION', generationId: projection };
      const runtimeOnly = { generations: { RUNTIME_CONFIGURATION: [runtimeGeneration] } };
      expect(await match({ type: 'GENERATION', generation }, runtimeOnly)).toBeNull();
      expect(await match({ type: 'GENERATION', generation: runtimeGeneration }, runtimeOnly)).toBe(
        true,
      );
      expect(
        await match(
          {
            type: 'GENERATION',
            generation: { ...runtimeGeneration, generationId: `urn:openpc:resource:${id()}` },
          },
          runtimeOnly,
        ),
      ).toBe(false);
      expect(
        await match(
          { type: 'GENERATION', generation },
          { generations: { CANONICAL_FACT: [runtimeGeneration] } },
        ),
      ).toBeNull();
      expect(
        await match({ type: 'GENERATION', generation }, { generations: [generation] }),
      ).toBeNull();
      for (const selector of [
        { type: 'PARTICIPANT', privacyDomainId: null },
        { type: 'GLOBAL' },
        {
          type: 'BLOCK_RANGE',
          chainId: '31337',
          genesisDigest: hash,
          fromBlock: '2',
          throughBlock: '1',
        },
        { type: 'FACT_TYPE_KEY', factType: 'RELATIONSHIP', factProfileId: profile },
        { type: 'GENERATION', generation: { ...generation, state: 'READY' } },
        { type: 'GENERATION', generation: { ...generation, canonicalGeneration: '0' } },
      ])
        await expect(
          admin.query('select openpc.evidence_hold_selector_encoding($1::jsonb,$2,$3)', [
            JSON.stringify(selector),
            scope.participantId,
            scope.privacyDomainId,
          ]),
        ).rejects.toThrow('PC-DATA-6004');
    } finally {
      await admin.end();
    }
  },
);
// SEM-059: real public approval/WebAuthn, PostgreSQL, immutable local sink, recovery.
// Source bytes are labelled fixtures; source authentication has separate runtime acceptance.
integration(
  'preserves existing and future evidence until a separate exact approved release, with truthful sink coverage',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 2 });
    const worker = new Pool({ connectionString: workerUrl, max: 2 });
    const runtime = new Pool({
      connectionString: process.env.OPENPC_I02_RUNTIME_DATABASE_URL,
      max: 1,
    });
    const scope = { participantId: id(), privacyDomainId: id(), streamId: 'held-evidence' };
    const root = await mkdtemp(join(process.env.OPENPC_TEST_TMP_ROOT!, 'evidence-holds-'));
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let signing: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>> | undefined;
    const count = async (table: string) =>
      (
        await admin.query(
          `select count(*)::int count from control.${table} where participant_id=$1`,
          [scope.participantId],
        )
      ).rows[0].count;
    const createAction = 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
      releaseAction = 'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1';
    try {
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        scope.participantId,
        scope.privacyDomainId,
      );
      signing = await evidenceGovernanceSigningFixture(
        admin,
        scope.participantId,
        scope.privacyDomainId,
      );
      await fixture.restartConfiguration(signing.evidence);
      const custody = new EvidenceCustody(worker),
        encryption = { keyId: 'hold-test-key', key: randomBytes(32) };
      const records = () =>
        [1, 2, 3].map(() => {
          const bytes = Buffer.from(`private hold fixture ${id()}`);
          return {
            recordId: id(),
            evidenceClass: 'EFFECT' as const,
            sourceFormat: 'FIXTURE',
            occurredAt: '2026-09-21T00:00:00.000000Z',
            receiptDigest: sha256(bytes),
            receiptBase64: bytes.toString('base64'),
          };
        });
      const first = records();
      await custody.admit(scope, first, encryption, '2027-01-01T00:00:00.000000Z', 65536);
      const selector = {
        type: 'SEQUENCE_RANGE' as const,
        streamId: scope.streamId,
        fromSequence: '2',
        throughSequence: null,
      };
      const prepared = await fixture.prepareMutation(
        'evidence-holds',
        createAction,
        {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          holdKind: 'LEGAL',
          selector,
        },
        true,
      );
      expect(await count('retention_hold')).toBe(0);
      expect((await prepared.commit()).status).toBe(403);
      expect(await count('retention_hold')).toBe(0);
      await prepared.stepUp();
      for (const mode of ['UNAVAILABLE', 'CORRUPT'] as const) {
        signing.faults.mode = mode;
        const previousCalls = signing.faults.calls;
        expect((await prepared.commit()).status).toBeGreaterThanOrEqual(400);
        expect(signing.faults.calls).toBe(previousCalls + 1);
        expect(await count('retention_hold')).toBe(0);
        expect(await count('audit_occurrence')).toBe(0);
        expect(await count('receipt_signing_attempt')).toBe(0);
      }
      signing.faults.mode = undefined;
      const created = await prepared.commit();
      expect(created, JSON.stringify(created)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED', truthState: 'SUCCESS' },
      });
      expect((await prepared.commit()).body).toEqual(created.body);
      const ref = String(created.body.resourceRef),
        holdId = ref.slice(-36);
      const signed = async () =>
        (
          await admin.query(
            `select receipt_cbor,cose_sign1,receipt_digest,profile_id,before_revision::text,after_revision::text,
         before_state_preimage,after_state_preimage from control.audit_occurrence where participant_id=$1
         and privacy_domain_id=$2 and aggregate_id=$3 order by after_revision`,
            [scope.participantId, scope.privacyDomainId, holdId],
          )
        ).rows;
      const creationReceipts = await signed();
      expect(creationReceipts).toHaveLength(1);
      const creationReceipt = decodeAdmittedReceipt(creationReceipts[0].receipt_cbor);
      expect(creationReceipt.receiptId).not.toBe(creationReceipt.operationId);
      expect(creationReceipt.operationId).toBe(created.body.operationId);
      expect(
        verifyReceiptCose(
          signing.publicKey,
          creationReceipts[0].receipt_cbor,
          creationReceipts[0].cose_sign1,
        ),
      ).toBe(true);
      expect(decodeAdmittedReceipt(creationReceipts[0].receipt_cbor)).toMatchObject({
        transitionProfileId: 'pc.control.evidence-hold.create',
        aggregateId: holdId,
        before: { existence: 0, revision: 0n },
        after: { existence: 1, revision: 1n },
      });
      const read = () => fixture!.read(`evidence-holds/${ref}`);
      expect(await read()).toMatchObject({
        status: 200,
        body: {
          state: 'ACTIVE',
          revision: '1',
          coverage: 'PENDING',
          selector,
          creationReceiptDigest: `sha256:${creationReceipts[0].receipt_digest.toString('hex')}`,
          releaseReceiptDigest: null,
        },
      });
      expect(await count('retention_hold')).toBe(1);
      const direct = await runtime.connect();
      try {
        await direct.query('begin');
        const operation = id(),
          bound = encodeEvidenceHoldSelector(scope, { type: 'PRIVACY_DOMAIN' });
        await direct.query(`select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)`, [
          scope.participantId,
          scope.privacyDomainId,
          operation,
          createAction,
        ]);
        await direct.query(
          `insert into control.retention_hold(retention_hold_id,participant_id,privacy_domain_id,hold_kind,
        selector_type,selector,selector_cbor,selector_digest,approval_request_id,creation_operation_id)
        values($1,$2,$3,'INCIDENT','PRIVACY_DOMAIN',$4::jsonb,$5,$6,$7,$8)`,
          [
            id(),
            scope.participantId,
            scope.privacyDomainId,
            JSON.stringify(bound.selector),
            bound.bytes,
            bound.digest,
            id(),
            operation,
          ],
        );
        await expect(direct.query('commit')).rejects.toThrow(
          'PC-AUTH-0002-EVIDENCE-HOLD-PROVENANCE',
        );
        await direct.query('rollback');
      } finally {
        direct.release();
      }
      expect(await count('retention_hold')).toBe(1);
      const unavailable = await LocalEvidenceVault.open(
        join(root, 'unavailable'),
        'local-hold-sink',
      );
      await rm(join(root, 'unavailable'), { recursive: true });
      await expect(custody.exportNext(scope, unavailable)).rejects.toThrow('unavailable');
      expect(await count('evidence_checkpoint')).toBe(0);
      expect(await count('evidence_hold_coverage')).toBe(0);
      const sink = await LocalEvidenceVault.open(join(root, 'vault'), 'local-hold-sink');
      await custody.exportNext(scope, sink);
      expect((await read()).body.coverage).toBe('VERIFIED');
      expect(await count('evidence_hold_coverage')).toBe(1);
      const second = records();
      await Promise.all([
        custody.admit(scope, second, encryption, '2027-01-01T00:00:00.000000Z', 65536),
        custody.admit(scope, second, encryption, '2027-01-01T00:00:00.000000Z', 65536),
      ]);
      expect((await read()).body.coverage).toBe('PENDING');
      const archived = await Promise.all([
        custody.exportNext(scope, sink),
        custody.exportNext(scope, sink),
      ]);
      expect(archived.filter(Boolean)).toHaveLength(1);
      expect(await count('evidence_hold_coverage')).toBe(2);
      const original = (
        await admin.query(
          'select receipt_digest from control.evidence_hold_coverage where retention_hold_id=$1 order by segment_id',
          [holdId],
        )
      ).rows;
      await fixture.restartConfiguration();
      expect((await read()).body).toMatchObject({
        state: 'ACTIVE',
        coverage: 'VERIFIED',
        revision: '1',
      });
      expect(await signed()).toEqual(creationReceipts);
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect((await foreign.read(`evidence-holds/${ref}`)).status).toBe(404);
      expect(
        (
          await fixture.read(`evidence-holds/${ref}`, {
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${id()}`,
          })
        ).status,
      ).toBe(403);
      const released = await fixture.prepareMutation(
        `evidence-holds/${ref}/release`,
        releaseAction,
        { targetRef: ref, expectedRevision: '1' },
        true,
      );
      expect((await released.commit()).status).toBe(403);
      expect((await read()).body.state).toBe('ACTIVE');
      await released.stepUp();
      const result = await released.commit();
      expect(result, JSON.stringify(result)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      expect((await released.commit()).body).toEqual(result.body);
      const receipts = await signed();
      expect(receipts).toHaveLength(2);
      expect(receipts[0]).toEqual(creationReceipts[0]);
      expect(
        verifyReceiptCose(signing.publicKey, receipts[1].receipt_cbor, receipts[1].cose_sign1),
      ).toBe(true);
      expect(decodeAdmittedReceipt(receipts[1].receipt_cbor)).toMatchObject({
        transitionProfileId: 'pc.control.evidence-hold.release',
        aggregateId: holdId,
        before: { existence: 1, revision: 1n },
        after: { existence: 1, revision: 2n },
      });
      expect((await read()).body).toMatchObject({
        state: 'RELEASED',
        revision: '2',
        coverage: 'PENDING',
        creationReceiptDigest: `sha256:${receipts[0].receipt_digest.toString('hex')}`,
        releaseReceiptDigest: `sha256:${receipts[1].receipt_digest.toString('hex')}`,
      });
      await new EvidenceCustody(worker).reconcileHolds(
        scope,
        await LocalEvidenceVault.open(join(root, 'vault'), 'local-hold-sink'),
      );
      expect((await read()).body.coverage).toBe('VERIFIED');
      expect(await count('evidence_hold_coverage')).toBe(4);
      expect(
        (
          await admin.query(
            'select receipt_digest from control.evidence_hold_coverage where retention_hold_id=$1 and hold_revision=1 order by segment_id',
            [holdId],
          )
        ).rows,
      ).toEqual(original);
      expect(
        (await readdir(join(root, 'vault'))).filter((name) => name.endsWith('.hold-1')),
      ).toHaveLength(2);
      expect(
        (await readdir(join(root, 'vault'))).filter((name) => name.endsWith('.hold-2')),
      ).toHaveLength(2);
      expect(await new EvidenceCustody(worker).reconcileHolds(scope, sink)).toBe(0);
      expect(await count('evidence_segment')).toBe(2);
      expect(await count('evidence_catalogue')).toBe(6);
      const third = records();
      const digestHold = await fixture.prepareMutation(
        'evidence-holds',
        createAction,
        {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          holdKind: 'INCIDENT',
          selector: { type: 'DIGEST', recordDigest: third[1]!.receiptDigest },
        },
        true,
      );
      await digestHold.stepUp();
      const blocker = await worker.connect();
      let pending: ReturnType<typeof digestHold.commit> | undefined;
      let admission: ReturnType<typeof custody.admit> | undefined;
      try {
        await blocker.query('begin');
        const pid = (await blocker.query('select pg_backend_pid() pid')).rows[0].pid;
        await blocker.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
          `evidence-lifecycle:${scope.participantId}`,
        ]);
        pending = digestHold.commit();
        // Observe real lock contention, rather than relying on an elapsed sleep.
        let waiting = false;
        for (let attempt = 0; attempt < 100; attempt++) {
          waiting = (
            await admin.query(
              'select exists(select 1 from pg_stat_activity where $1::int=any(pg_blocking_pids(pid))) waiting',
              [pid],
            )
          ).rows[0].waiting;
          if (waiting) break;
          await delay(10);
        }
        expect(waiting).toBe(true);
        admission = custody.admit(scope, third, encryption, '2027-01-01T00:00:00.000000Z', 65536);
        await blocker.query('commit');
      } finally {
        await blocker.query('rollback');
        blocker.release();
      }
      const digestResult = await pending!;
      await admission!;
      // Admission after approved release must not re-open that rule's coverage.
      expect((await read()).body).toMatchObject({ state: 'RELEASED', coverage: 'VERIFIED' });
      expect(digestResult, JSON.stringify(digestResult)).toMatchObject({ status: 202 });
      const digestRef = String(digestResult.body.resourceRef);
      expect((await fixture.read(`evidence-holds/${digestRef}`)).body).toMatchObject({
        state: 'ACTIVE',
        coverage: 'PENDING',
      });
      await custody.exportNext(scope, sink);
      expect(
        (
          await admin.query(
            'select count(*)::int count from control.evidence_hold_coverage where retention_hold_id=$1',
            [holdId],
          )
        ).rows[0].count,
      ).toBe(4);
      expect(
        (await readdir(join(root, 'vault'))).filter((name) => name.endsWith('.hold-2')),
      ).toHaveLength(2);
      expect((await fixture.read(`evidence-holds/${digestRef}`)).body.coverage).toBe('VERIFIED');
      const catalogue = await fixture.read('evidence-records?limit=50');
      expect(
        (catalogue.body.items as { recordDigest: string; state: string }[]).find(
          (row) => row.recordDigest === third[1]!.receiptDigest,
        )?.state,
      ).toBe('HELD');
      const domain = await fixture.prepareMutation(
        'evidence-holds',
        createAction,
        {
          participantId: `urn:openpc:participant:${scope.participantId}`,
          holdKind: 'REGULATORY',
          selector: { type: 'PRIVACY_DOMAIN' },
        },
        true,
      );
      await domain.stepUp();
      const domainResult = await domain.commit();
      expect(domainResult, JSON.stringify(domainResult)).toMatchObject({ status: 202 });
      const domainRef = String(domainResult.body.resourceRef);
      expect((await fixture.read(`evidence-holds/${domainRef}`)).body.coverage).toBe('PENDING');
      await custody.reconcileHolds(scope, sink);
      expect((await fixture.read(`evidence-holds/${domainRef}`)).body.coverage).toBe('VERIFIED');
      expect((await fixture.read('evidence-holds?limit=50')).body.items).toHaveLength(3);
      // Real authentication receipts have no projection/Fact/block lineage. The
      // preservation reader sees this minimized fact only in its own context.
      const authentication = { ...scope, streamId: 'hold-authentication-source' };
      expect(
        await custody.ingestAuthentication(
          authentication,
          encryption,
          '2027-01-01T00:00:00.000000Z',
          65536,
        ),
      ).not.toBeNull();
      const reader = await runtime.connect();
      try {
        await reader.query('begin');
        await reader.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1',true)`,
          [scope.participantId, scope.privacyDomainId, id()],
        );
        const metadata = await reader.query(
          `select openpc.evidence_hold_record_metadata(c) known,
          openpc.evidence_hold_record_metadata(jsonb_populate_record(null::control.evidence_catalogue,
            to_jsonb(c)||jsonb_build_object('receipt_digest',$4::text))) altered
          from control.evidence_catalogue c where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
          [
            scope.participantId,
            scope.privacyDomainId,
            authentication.streamId,
            `sha256:${'00'.repeat(32)}`,
          ],
        );
        expect(metadata.rows.length).toBeGreaterThan(0);
        for (const row of metadata.rows)
          expect(row).toEqual({
            known: {
              projections: [],
              facts: [],
              blocks: [],
              generations: { CANONICAL_FACT: [], RUNTIME_CONFIGURATION: [] },
            },
            altered: null,
          });
        await reader.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1',true)`,
          [scope.participantId, id(), id()],
        );
        expect(
          (
            await reader.query(
              'select 1 from control.authentication_occurrence where participant_id=$1 and privacy_domain_id=$2',
              [scope.participantId, scope.privacyDomainId],
            )
          ).rowCount,
        ).toBe(0);
      } finally {
        await reader.query('rollback');
        reader.release();
      }
    } finally {
      signing?.close();
      await fixture?.close();
      await foreign?.close();
      await runtime.end();
      await worker.end();
      await admin.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  120000,
);
