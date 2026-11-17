import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  approvalCreateIntent,
  createApprovalSchema,
} from '../../../services/module-registry/src/public-approval-contract.js';

const maker = '018f0000-0000-7000-8000-000000000011';
const checker = '018f0000-0000-7000-8000-000000000012';
const request = () => ({
  actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1' as const,
  candidateDigest: `sha256:${'a'.repeat(64)}`,
  makerSubjectRef: `urn:openpc:resource:${maker}`,
  checkerSubjectRef: `urn:openpc:resource:${checker}`,
  actionIntentDigest: `sha256:${'b'.repeat(64)}`,
  reason: 'Approve this exact proposal',
});

describe('fresh envelope submission uses the existing public approval intent', () => {
  it('binds the exact six-field canonical body, separately from proposal and action metadata', () => {
    const value = request();
    const intent = approvalCreateIntent(value);
    const wire = `{"actionIntentDigest":"sha256:${'b'.repeat(64)}","actionIntentId":"ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1","candidateDigest":"sha256:${'a'.repeat(64)}","checkerSubjectRef":"urn:openpc:resource:${checker}","makerSubjectRef":"urn:openpc:resource:${maker}","reason":"Approve this exact proposal"}`;
    expect(intent).toEqual({
      request: value,
      actionIntentId: value.actionIntentId,
      resourceId: maker,
      intentDigest: `sha256:${createHash('sha256').update(wire).digest('hex')}`,
    });
    expect(intent.intentDigest).not.toBe(value.candidateDigest);
    expect(intent.intentDigest).not.toBe(value.actionIntentDigest);
    expect(approvalCreateIntent(Object.fromEntries(Object.entries(value).reverse()))).toEqual(
      intent,
    );
  });
  it('changes the step-up binding for changed proposal, checker, actor, reason or action metadata', () => {
    const original = approvalCreateIntent(request()).intentDigest;
    for (const change of [
      { candidateDigest: `sha256:${'c'.repeat(64)}` },
      { checkerSubjectRef: null },
      { makerSubjectRef: `urn:openpc:resource:${checker}` },
      { checkerSubjectRef: `urn:openpc:resource:${maker}` },
      { actionIntentDigest: `sha256:${'c'.repeat(64)}` },
      { reason: 'Approve another proposal' },
    ])
      expect(approvalCreateIntent({ ...request(), ...change }).intentDigest).not.toBe(original);
  });
  it('rejects new subject selectors, caller authority, changed action and revision fields', () => {
    for (const change of [
      { subjectType: 'AUTHORITY_ENVELOPE' },
      { issuerParticipantId: maker },
      { authority: {} },
      { schemaVersion: 1 },
      { expectedRevision: '1' },
      { actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
      { candidateDigest: 'sha256:00' },
      { makerSubjectRef: maker },
    ])
      expect(createApprovalSchema.safeParse({ ...request(), ...change }).success).toBe(false);
  });
});
