import { setTimeout as delay } from 'node:timers/promises';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  verifyReceiptCose,
  decodeAdmittedReceipt,
} from '../../../packages/security-kernel/src/index.js';
import { contractAdministrationFixture } from './contract-administration-fixture.js';
import { evidenceGovernanceSigningFixture } from './evidence-governance-signing-fixture.js';
import { digest } from './public-governance-client.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const integration = adminUrl ? it : it.skip;
// TP-RETENTION-RECOVERY: activated versioned policy authority, not deletion eligibility.
integration(
  'governs exact retention versions with signed intervals, isolated classes and serialized activation',
  async () => {
    const admin = new Pool({ connectionString: adminUrl, max: 3 });
    const participantId = id(),
      privacyDomainId = id();
    let fixture: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let foreign: Awaited<ReturnType<typeof contractAdministrationFixture>> | undefined;
    let signing: Awaited<ReturnType<typeof evidenceGovernanceSigningFixture>> | undefined;
    const activate = 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',
      retire = 'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1';
    const policy = {
      dataClass: 'AUDIT_EVIDENCE',
      policyVersion: '1.0.0',
      retentionPeriodMs: '9007199254740993',
      localGraceMs: '123',
      sinkQuorum: 2,
      deletionMode: 'ROW_DELETE',
      makerCheckerRequired: true,
    };
    const fields = {
      participantId: `urn:openpc:participant:${participantId}`,
      predecessorPolicyId: null,
      policy,
    };
    const count = async (table: string) =>
      (
        await admin.query(
          `select count(*)::int count from control.${table} where participant_id=$1`,
          [participantId],
        )
      ).rows[0].count;
    try {
      fixture = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        participantId,
        privacyDomainId,
      );
      signing = await evidenceGovernanceSigningFixture(
        admin,
        participantId,
        privacyDomainId,
        'retention-policy',
      );
      await fixture.restartConfiguration(signing.evidence);
      for (const invalid of [
        { retentionPeriodMs: '-1' },
        { retentionPeriodMs: '9223372036854775808' },
        { localGraceMs: '1.5' },
        { sinkQuorum: 9 },
        { dataClass: 'CACHE_ENTRY' },
        { deletionMode: 'DELETE' },
      ])
        expect(
          (
            await fixture.attemptMutation('retention-policies', activate, {
              ...fields,
              policy: { ...policy, ...invalid },
            })
          ).status,
        ).toBe(400);
      const prepared = await fixture.prepareMutation('retention-policies', activate, fields, true);
      expect(await count('retention_policy')).toBe(0);
      expect((await prepared.commit()).status).toBe(403);
      await prepared.stepUp();
      signing.faults.mode = 'UNAVAILABLE';
      const beforeCalls = signing.faults.calls;
      expect((await prepared.commit()).status).toBeGreaterThanOrEqual(400);
      expect(signing.faults.calls).toBe(beforeCalls + 1);
      for (const table of ['retention_policy', 'audit_occurrence', 'receipt_signing_attempt'])
        expect(await count(table)).toBe(0);
      signing.faults.mode = undefined;
      const { client, policyUrl } = fixture.governance;
      const resumeAction = 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1';
      const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
      const readApproval = async (approvalId: string) => {
        const result = await fixture!.approvalRead(approvalId);
        expect(result.status, JSON.stringify(result)).toBe(200);
        return result.body;
      };
      const resume = async (
        approvalId: string,
        view: Awaited<ReturnType<typeof readApproval>>,
        key: string,
        actor = fixture!.governance.maker,
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
            reason: 'Recover the unchanged retention policy after signer unavailability.',
          },
          {
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
            'X-Request-ID': id(),
            'X-Correlation-ID': id(),
            'Idempotency-Key': key,
            'X-CSRF-Token': await client.csrf(actor, resumeAction, policyUrl),
            'X-OpenPC-Action-Intent-Digest': client.actionDigests.get(resumeAction)!,
            'If-Match': `"${digest({ resourceId: approvalId, revision: '2' })}"`,
          },
          'PATCH',
        );
      const original = await readApproval(prepared.approvalId);
      expect(original).toMatchObject({
        state: 'APPROVED',
        approvalUsable: true,
        canRequestResume: false,
        operationRef: null,
      });
      expect([403, 409]).toContain(
        (await resume(prepared.approvalId, original, `live-${id()}`)).status,
      );
      // An identical intent cannot bypass recovery by obtaining another candidate.
      expect((await fixture.attemptMutation('retention-policies', activate, fields)).status).toBe(
        412,
      );
      const expiry = Number(
        (
          await admin.query(
            `select max(extract(epoch from least(m.expires_at,m.consumed_at+interval '5 minutes'))*1000) expiry
         from control.approval_decision_record d join control.mfa_challenge m using(participant_id,mfa_challenge_id)
         where d.approval_request_id=$1`,
            [prepared.approvalId],
          )
        ).rows[0].expiry,
      );
      expect(expiry).toBeGreaterThan(Date.now());
      while (Date.now() <= expiry) {
        process.stdout.write(
          `OPENPC_RETENTION_RESUME|natural-expiry|remaining_ms=${Math.ceil(expiry - Date.now())}\n`,
        );
        await delay(Math.min(30000, expiry - Date.now() + 100));
      }
      expect(await count('retention_policy')).toBe(0);
      expect(await readApproval(prepared.approvalId)).toMatchObject({
        canRequestResume: true,
        approvalUsable: false,
        operationRef: null,
      });
      expect([403, 404]).toContain(
        (await resume(prepared.approvalId, original, `checker-${id()}`, fixture.governance.checker))
          .status,
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
      expect(winner, JSON.stringify(raced)).toBeGreaterThanOrEqual(0);
      expect(raced.filter((value) => value.status === 202)).toHaveLength(1);
      expect([403, 409]).toContain(raced[1 - winner]!.status);
      expect(await resume(prepared.approvalId, original, keys[winner]!)).toEqual(raced[winner]);
      const nextId = String(raced[winner]!.body.resourceRef).slice(-36);
      expect(await readApproval(nextId)).toMatchObject({
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
          reason: 'Independently approve the original unchanged policy.',
        },
        '1',
      );
      expect(approved.status, JSON.stringify(approved)).toBe(202);
      await prepared.stepUp();
      const activated = await prepared.commit();
      expect(activated, JSON.stringify(activated)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED', truthState: 'SUCCESS' },
      });
      expect((await prepared.commit()).body).toEqual(activated.body);
      expect(activated.body.resourceRef).toBe(original.resourceRef);
      expect([403, 409]).toContain(
        (await resume(nextId, await readApproval(nextId), `consumed-${id()}`)).status,
      );
      const ref = String(activated.body.resourceRef),
        policyId = ref.slice(-36);
      const verify = async (operationId: string, verb: string, before: bigint, after: bigint) => {
        const receipts = await admin.query(
          `select receipt_cbor,cose_sign1,receipt_digest from control.audit_occurrence
       where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
          [participantId, privacyDomainId, operationId],
        );
        expect(receipts.rowCount).toBe(1);
        const receipt = receipts.rows[0];
        expect(
          verifyReceiptCose(signing!.publicKey, receipt.receipt_cbor, receipt.cose_sign1),
        ).toBe(true);
        const decoded = decodeAdmittedReceipt(receipt.receipt_cbor);
        expect(decoded.receiptId).not.toBe(decoded.operationId);
        expect(decoded).toMatchObject({
          transitionProfileId: `pc.control.retention-policy.${verb}`,
          operationId,
          before: { revision: before },
          after: { revision: after },
        });
        return {
          digest: `sha256:${receipt.receipt_digest.toString('hex')}`,
          bytes: receipt.receipt_cbor as Buffer,
        };
      };
      const activationReceipt = await verify(
        String(activated.body.operationId),
        'activate',
        0n,
        1n,
      );
      const read = () => fixture!.read(`retention-policies/${ref}`);
      expect(await read()).toMatchObject({
        status: 200,
        body: {
          ...policy,
          state: 'ACTIVE',
          revision: '1',
          activeUntil: null,
          activationReceiptDigest: activationReceipt.digest,
        },
      });
      expect(
        (await fixture.read('retention-policies?filter=dataClass:eq:RAW_SOURCE_BODY')).body,
      ).toMatchObject({ items: [] });
      foreign = await contractAdministrationFixture(
        admin,
        process.env.OPENPC_I02_RUNTIME_DATABASE_URL!,
        id(),
        id(),
      );
      expect((await foreign.read(`retention-policies/${ref}`)).status).toBe(404);
      const overlap = await fixture.prepareMutation(
        'retention-policies',
        activate,
        { ...fields, predecessorPolicyId: ref, policy: { ...policy, policyVersion: '2.0.0' } },
        true,
      );
      await overlap.stepUp();
      expect((await overlap.commit()).status).toBe(412);
      expect(await count('retention_policy')).toBe(1);
      const retirement = await fixture.prepareMutation(
        `retention-policies/${ref}/retire`,
        retire,
        { targetRef: ref, expectedRevision: '1' },
        true,
      );
      expect((await retirement.commit()).status).toBe(403);
      await retirement.stepUp();
      const retired = await retirement.commit();
      expect(retired, JSON.stringify(retired)).toMatchObject({
        status: 202,
        body: { state: 'SUCCEEDED' },
      });
      const retirementReceipt = await verify(String(retired.body.operationId), 'retire', 1n, 2n);
      expect((await retirement.commit()).body).toEqual(retired.body);
      const retiredView = await read();
      expect(retiredView).toMatchObject({
        status: 200,
        body: {
          ...policy,
          state: 'RETIRED',
          revision: '2',
          retirementReceiptDigest: retirementReceipt.digest,
        },
      });
      expect(Date.parse(retiredView.body.activeUntil)).toBeGreaterThanOrEqual(
        Date.parse(retiredView.body.activeFrom),
      );
      const stale = await fixture.prepareMutation(
        'retention-policies',
        activate,
        { ...fields, policy: { ...policy, policyVersion: '3.0.0' } },
        true,
      );
      await stale.stepUp();
      expect((await stale.commit()).status).toBe(412);
      // The previously approved exact successor can now activate; the predecessor is rechecked live.
      await overlap.stepUp();
      const replacement = await overlap.commit();
      expect(replacement, JSON.stringify(replacement)).toMatchObject({ status: 202 });
      expect(
        await fixture.read(`retention-policies/${String(replacement.body.resourceRef)}`),
      ).toMatchObject({
        body: { state: 'ACTIVE', predecessorPolicyId: ref, policyVersion: '2.0.0' },
      });
      await fixture.restartConfiguration();
      expect((await prepared.commit()).body).toEqual(activated.body);
      expect((await retirement.commit()).body).toEqual(retired.body);
      expect((await verify(String(activated.body.operationId), 'activate', 0n, 1n)).bytes).toEqual(
        activationReceipt.bytes,
      );
      expect((await read()).body).toEqual(retiredView.body);
      const contenders = [];
      for (const version of ['1.0.0', '2.0.0']) {
        const candidate = await fixture.prepareMutation(
          'retention-policies',
          activate,
          {
            ...fields,
            policy: {
              ...policy,
              dataClass: 'RAW_SOURCE_BODY',
              policyVersion: version,
              retentionPeriodMs: '0',
              sinkQuorum: 0,
            },
          },
          true,
        );
        await candidate.stepUp();
        contenders.push(candidate);
      }
      const blocker = await admin.connect();
      let pending: ReturnType<(typeof contenders)[number]['commit']>[] = [];
      try {
        await blocker.query('begin');
        await blocker.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [
          `evidence-lifecycle:${participantId}`,
        ]);
        pending = contenders.map((candidate) => candidate.commit());
        let observed = false;
        for (let attempt = 0; attempt < 100; attempt++) {
          const locks = await admin.query(
            `select exists(select 1 from pg_locks where locktype='advisory' and not granted) waiting`,
          );
          if (locks.rows[0].waiting) {
            observed = true;
            break;
          }
          await delay(10);
        }
        expect(observed, 'observe real activation blocked at the lifecycle fence').toBe(true);
      } finally {
        await blocker.query('rollback');
        blocker.release();
      }
      const results = await Promise.all(pending);
      expect(results.map((result) => result.status).sort()).toEqual([202, 412]);
      expect(
        (
          await admin.query(
            `select count(*)::int count from control.retention_policy where participant_id=$1 and privacy_domain_id=$2 and data_class='RAW_SOURCE_BODY' and active_until is null`,
            [participantId, privacyDomainId],
          )
        ).rows[0].count,
      ).toBe(1);
      expect(await count('retention_policy')).toBe(3);
      // No policy transition deletes existing hold, source, custody or receipt rows.
      expect(await count('audit_occurrence')).toBe(4);
      expect(await count('outbox_event')).toBeGreaterThanOrEqual(4);
      expect(
        (
          await admin.query(
            'select retention_period_ms::text from control.retention_policy where retention_policy_id=$1',
            [policyId],
          )
        ).rows[0].retention_period_ms,
      ).toBe(policy.retentionPeriodMs);
    } finally {
      await foreign?.close();
      await fixture?.close();
      signing?.close();
      await admin.end();
    }
  },
  480000,
);
