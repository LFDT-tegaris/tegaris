import { describe, expect, it } from 'vitest';
import { parseResourceRead, parseTransactionInput, requireDraftActor } from './browser-commands.js';
import { responseError } from './client.js';

const participantId = '018f0000-0000-7000-8000-000000000101',
  privacyDomainId = '018f0000-0000-7000-8000-000000000201',
  principalId = '018f0000-0000-7000-8000-000000000141';
const ref = 'urn:openpc:resource:018f0000-0000-7000-8000-000000000401';
const checkerId = '018f0000-0000-7000-8000-000000000142';
const input = {
  fields: { deploymentIntentId: ref, signedTransaction: '0x01020304' },
  reason: 'Submit the independently reviewed deployment.',
  checkerId,
};

describe('governed CLI contracts and recovery binding', () => {
  it('correlates typed public resource readback and rejects substituted IDs or unfiltered fields', () => {
    const view = {
      actor: {
        sessionId: checkerId,
        principalId,
        participantId,
        privacyDomainId,
        contextEpoch: '1',
      },
      kind: 'deployment-submission',
      result: {
        deploymentSubmissionId: ref,
        operationId: ref.replace(':resource:', ':operation:'),
        state: 'WRITE_AMBIGUITY',
        truthState: 'WRITE_AMBIGUITY',
        revision: '1',
        runtimePermission: 'NONE',
        attempt: null,
        occurrence: null,
        invalidation: null,
        association: null,
        associationCurrent: false,
      },
    };
    expect(parseResourceRead(view.kind, ref.slice(-36), view).result).toEqual(view.result);
    expect(() => parseResourceRead(view.kind, checkerId, view)).toThrow('RESPONSE');
    expect(() =>
      parseResourceRead(view.kind, ref.slice(-36), {
        ...view,
        result: { ...view.result, signedTransaction: '0x01020304' },
      }),
    ).toThrow('RESPONSE');
  });
  it('preserves exact signed bytes and predecessor replacement semantics', () => {
    const parsed = parseTransactionInput('deployment-submission', input);
    expect(parsed.fields).toEqual(input.fields);
    expect(
      parseTransactionInput('deployment-submission', {
        ...input,
        fields: { signedTransaction: '0x01020304', deploymentIntentId: ref },
      }).candidateDigest,
    ).toBe(parsed.candidateDigest);
    const replacement = parseTransactionInput('deployment-submission', {
      ...input,
      fields: { ...input.fields, predecessorOperationId: ref.replace(':resource:', ':operation:') },
    });
    expect(replacement.candidateDigest).not.toBe(parsed.candidateDigest);
    expect(() =>
      parseTransactionInput('deployment-submission', {
        ...input,
        fields: { ...input.fields, predecessorOperationId: ref },
      }),
    ).toThrow('INPUT');
    expect(() =>
      parseTransactionInput('deployment-submission', {
        ...input,
        fields: { ...input.fields, approved: true },
      }),
    ).toThrow('INPUT');
  });

  it('retains the approved policy occurrence and exact CIGL profile renewal input', () => {
    const digest = `sha256:${'ab'.repeat(32)}`;
    const fields = {
      targetRef: ref,
      expectedRevision: '18',
      expectedGenerationDigest: digest,
      participantEpoch: '1',
      profiles: [
        {
          profileId: ref,
          profileRevision: '1',
          profileDigest: digest,
          compilationArtifactDigest: digest,
          grantSourcesDigest: digest,
        },
      ],
      policyRenewal: {
        activationOccurrenceRef: ref,
        expectedRevision: '3',
        policyGenerationDigest: digest,
      },
    };
    expect(parseTransactionInput('cigl-activation', { ...input, fields }).fields).toEqual(fields);
    expect(() =>
      parseTransactionInput('cigl-activation', {
        ...input,
        fields: { ...fields, policyRenewal: { ...fields.policyRenewal, ready: true } },
      }),
    ).toThrow('INPUT');
    expect(() =>
      parseTransactionInput('cigl-activation', {
        ...input,
        fields: { ...fields, expectedRevision: '0' },
      }),
    ).toThrow('INPUT');
  });

  it('binds durable requests to origin, maker and exact tenant/privacy context, while allowing fresh sessions', () => {
    const origin = 'https://openpc.example';
    const draft = {
      version: 1 as const,
      requestKey: '38dc94e2-d402-4db0-a3e7-643102a60cab',
      origin,
      participantId,
      privacyDomainId,
      principalId,
      ...parseTransactionInput('deployment-submission', input),
    };
    const actor = {
      participantId,
      privacyDomainId,
      principalId,
      sessionId: '018f0000-0000-7000-8000-000000000701',
      contextEpoch: '2',
    };
    expect(() => requireDraftActor(draft, actor, origin)).not.toThrow();
    expect(() =>
      requireDraftActor(
        draft,
        { ...actor, sessionId: '018f0000-0000-7000-8000-000000000702', contextEpoch: '3' },
        origin,
      ),
    ).not.toThrow();
    for (const field of ['participantId', 'privacyDomainId', 'principalId'] as const)
      expect(() => requireDraftActor(draft, { ...actor, [field]: checkerId }, origin)).toThrow(
        'CONTEXT',
      );
    expect(() => requireDraftActor(draft, actor, 'https://other.example')).toThrow('CONTEXT');
  });

  it('retains safe public stale/denial codes without exposing error details or payloads', () => {
    expect(
      responseError(412, {
        code: 'PC-DATA-6007',
        status: 412,
        truthState: 'STALE',
        retryable: false,
        detail: 'private payload',
        sessionToken: 'secret',
      }).problem,
    ).toEqual({ code: 'PC-DATA-6007', status: 412, truthState: 'STALE', retryable: false });
    expect(responseError(412, {}).code).toBe('STALE');
    expect(responseError(403, { code: 'secret', status: 403 }).problem).toBeUndefined();
    expect(() => parseTransactionInput('arbitrary-admin-operation', input)).toThrow('INPUT');
  });
});
