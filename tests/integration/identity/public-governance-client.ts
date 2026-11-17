import { createHash, sign, type KeyObject } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import type { Pool } from 'pg';
import { expect } from 'vitest';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { canonicalJson } from '../../../services/module-registry/src/domain/digest.js';

export const sha = (value: string | Buffer) => createHash('sha256').update(value).digest();
export const digest = (value: unknown) => `sha256:${sha(canonicalJson(value)).toString('hex')}`;
export interface GovernanceActor {
  principalId: string;
  sessionToken: string;
  sessionId: string;
}
export interface TestAuthenticator {
  credentialId: string;
  externalCredentialId?: string;
  privateKey: KeyObject;
  count: number;
}
const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
const createApprovalAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1';
const stepUpAction = 'ACT-IDENTITY_UPDATE_STEP_UP-V1';

/** HTTP ingress and an external authenticator; authorization, approval, state and evidence remain real. */
export async function publicGovernanceClient(input: {
  admin: Pool;
  identityUrl: string;
  policyUrl: string;
  participantId: string;
  privacyDomainId: string;
  devices: Map<string, TestAuthenticator>;
}) {
  const { identityUrl: origin, policyUrl, participantId, privacyDomainId } = input;
  const actions = await input.admin.query<{ action_intent_id: string; digest: string }>(
    "select action_intent_id,'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent",
  );
  const actionDigests = new Map(actions.rows.map((row) => [row.action_intent_id, row.digest]));
  const request = async (
    url: string,
    session: GovernanceActor,
    body: unknown,
    headers: Record<string, string> = {},
    method: 'POST' | 'PATCH' = 'POST',
  ) =>
    new Promise<{ status: number; body: Record<string, unknown> }>((resolve, reject) => {
      const payload = JSON.stringify(body);
      const outbound = httpRequest(
        url,
        {
          method,
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': String(Buffer.byteLength(payload)),
            'Cookie': `__Host-openpc_session=${session.sessionToken}`,
            'Origin': new URL(url).origin,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
            ...headers,
          },
          signal: AbortSignal.timeout(10000),
        },
        (response) => {
          const chunks: Buffer[] = [];
          response.on('data', (chunk: Buffer) => chunks.push(chunk));
          response.on('error', reject);
          response.on('end', () => {
            try {
              resolve({
                status: response.statusCode!,
                body: JSON.parse(Buffer.concat(chunks).toString()),
              });
            } catch (error) {
              reject(error);
            }
          });
        },
      );
      outbound.on('error', reject);
      outbound.end(payload);
    });
  const csrf = async (session: GovernanceActor, intent: string, targetOrigin: string) => {
    const value = await request(
      `${origin}/api/v1/session/csrf`,
      session,
      { actionIntentId: intent },
      { Origin: targetOrigin, Host: new URL(targetOrigin).host },
    );
    expect(value.status, JSON.stringify(value.body)).toBe(200);
    return value.body.csrfToken as string;
  };
  const stepUp = async (
    session: GovernanceActor,
    intent: string,
    resourceId: string,
    resourceDigest: string,
    verificationResourceId = resourceId,
  ) => {
    const token = await csrf(session, intent, origin);
    const rpIdHash = `sha256:${sha(new URL(origin).hostname).toString('hex')}`;
    const challenge = await request(
      `${origin}/v1/identity/webauthn/assertion/challenge`,
      session,
      { actionIntentId: intent, resourceId, resourceDigest, rpIdHash },
      { 'X-CSRF-Token': token },
    );
    expect(challenge.status, JSON.stringify(challenge.body)).toBe(200);
    const device = input.devices.get(session.principalId)!;
    expect(challenge.body.credentialIds).toContain(
      device.externalCredentialId ?? device.credentialId,
    );
    const clientData = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: challenge.body.challenge, origin }),
    );
    const authenticatorData = Buffer.alloc(37);
    sha(new URL(origin).hostname).copy(authenticatorData);
    authenticatorData[32] = 5;
    authenticatorData.writeUInt32BE(++device.count, 33);
    const signature = sign(
      'sha256',
      Buffer.concat([authenticatorData, sha(clientData)]),
      device.privateKey,
    );
    const version = await input.admin.query(
      'select row_version::text from control.session where session_id=$1',
      [session.sessionId],
    );
    const verified = await request(
      `${origin}/v1/identity/webauthn/assertion/verify`,
      session,
      {
        actionIntentId: intent,
        resourceId: verificationResourceId,
        resourceDigest,
        rpIdHash,
        challenge: challenge.body.challenge,
        assertion: JSON.stringify({
          credentialId: device.externalCredentialId ?? device.credentialId,
          authenticatorData: authenticatorData.toString('base64url'),
          clientDataJson: clientData.toString('base64url'),
          signature: signature.toString('base64url'),
        }),
      },
      {
        'X-CSRF-Token': token,
        'Idempotency-Key': `step-up-${id()}`,
        'X-OpenPC-Aggregate-Version': version.rows[0].row_version,
        'OpenPC-Action-Intent-Digest': actionDigests.get(stepUpAction)!,
      },
    );
    expect(verified.status, JSON.stringify(verified.body)).toBe(200);
  };
  const policyMutation = async (
    session: GovernanceActor,
    path: string,
    body: { actionIntentId: string; targetRef?: string; [key: string]: unknown },
    revision?: string,
  ) =>
    request(`${policyUrl}${path}`, session, body, {
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
      'X-Request-ID': id(),
      'X-Correlation-ID': id(),
      'Idempotency-Key': `recovery-approval-${id()}`,
      'X-CSRF-Token': await csrf(session, body.actionIntentId, policyUrl),
      'OpenPC-Action-Intent-Digest': actionDigests.get(body.actionIntentId)!,
      'X-OpenPC-Action-Intent-Digest': actionDigests.get(body.actionIntentId)!,
      ...(revision === undefined
        ? {}
        : { 'If-Match': `"${digest({ resourceId: body.targetRef!.slice(-36), revision })}"` }),
    });
  const mutation = async (
    maker: GovernanceActor,
    path: string,
    body: unknown,
    key: string,
    revision: string,
    approvalId = '018f0000-0000-7000-8000-000000000001',
  ) =>
    request(`${origin}${path}`, maker, body, {
      'X-CSRF-Token': await csrf(maker, action, origin),
      'Idempotency-Key': key,
      'X-OpenPC-Aggregate-Version': revision,
      'X-OpenPC-Approval-Request-ID': approvalId,
      'OpenPC-Action-Intent-Digest': actionDigests.get(action)!,
    });
  const prepare = async (
    maker: GovernanceActor,
    checker: GovernanceActor,
    path: string,
    body: unknown,
    candidate: unknown,
    resourceId: string,
    revision: string,
    beforeMakerStepUp?: () => Promise<void>,
  ) => {
    const key = `recovery-journey-${id()}`,
      candidateDigest = digest(candidate);
    const staged = await mutation(maker, path, body, key, revision);
    expect(staged, path).toMatchObject({
      status: 409,
      body: { error: { code: 'PC-IDENTITY-1005' } },
    });
    const readProposal = async (privacy = privacyDomainId) => {
      const response = await fetch(
        `${origin}/v1/identity/recovery-proposals/${candidateDigest}?expectedRevision=${revision}&makerPrincipalId=${maker.principalId}`,
        {
          headers: {
            'Cookie': `__Host-openpc_session=${checker.sessionToken}`,
            'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacy}`,
          },
        },
      );
      return { status: response.status, body: await response.json() };
    };
    expect(await readProposal()).toMatchObject({
      status: 200,
      body: { candidateDigest, resourceId, expectedRevision: revision, candidate },
    });
    expect((await readProposal(id())).status).toBe(404);
    const created = await policyMutation(maker, '/api/v1/approval-requests', {
      actionIntentId: createApprovalAction,
      actionIntentDigest: actionDigests.get(createApprovalAction),
      candidateDigest,
      makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
      reason: 'Approve this exact purpose-bound identity recovery transition.',
    });
    expect(created.status, JSON.stringify(created.body)).toBe(202);
    const approvalRef = created.body.resourceRef as string,
      approvalId = approvalRef.slice(-36);
    const changedReason = await policyMutation(maker, '/api/v1/approval-requests', {
      actionIntentId: createApprovalAction,
      actionIntentDigest: actionDigests.get(createApprovalAction),
      candidateDigest,
      makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
      reason: 'A different explanation must not replace the original request.',
    });
    expect(changedReason.status).toBe(409);
    const boundProposal = await fetch(
      `${origin}/v1/identity/recovery-proposals/${candidateDigest}?approvalRequestId=${approvalId}`,
      {
        headers: {
          'Cookie': `__Host-openpc_session=${checker.sessionToken}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
        },
      },
    );
    expect(boundProposal.status).toBe(200);
    expect(await boundProposal.json()).toMatchObject({
      candidateDigest,
      makerPrincipalId: maker.principalId,
      expectedRevision: revision,
      resourceId,
      candidate,
      approval: {
        approvalRequestId: approvalId,
        reason: 'Approve this exact purpose-bound identity recovery transition.',
      },
    });
    const decisionDigest = digest({
      actionIntentId: approveAction,
      approvalRequestId: approvalRef,
      candidateDigest,
      expectedRevision: '1',
      decision: 'APPROVE',
    });
    await stepUp(checker, approveAction, approvalId, decisionDigest);
    const approved = await policyMutation(
      checker,
      `/api/v1/approval-requests/${approvalRef}/approve`,
      {
        targetRef: approvalRef,
        actionIntentId: approveAction,
        actionIntentDigest: actionDigests.get(approveAction),
        inputDigest: decisionDigest,
        expectedRevision: '1',
        reason: 'Independent checker approves the exact recovery transition.',
      },
      '1',
    );
    expect(approved.status, JSON.stringify(approved.body)).toBe(202);
    await beforeMakerStepUp?.();
    await stepUp(maker, action, resourceId, candidateDigest);
    return {
      key,
      approvalId,
      commit: () => mutation(maker, path, body, key, revision, approvalId),
    };
  };
  return { request, csrf, stepUp, prepare, mutation, policyMutation, actionDigests };
}
