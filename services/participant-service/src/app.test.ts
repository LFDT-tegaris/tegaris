import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  buildParticipantService,
  type ParticipantMutationAuthorizationAdapter,
  type ParticipantMutationCandidateStager,
} from './app.js';
import {
  ParticipantKernel,
  ParticipantKernelError,
  type AuthenticatedActor,
  type EffectiveAuthority,
  type ParticipantRepository,
} from './domain/participant-kernel.js';

const ids = {
  participant: '018f0000-0000-7000-8000-000000000101',
  principal: '018f0000-0000-7000-8000-000000000111',
  checker: '018f0000-0000-7000-8000-000000000112',
  session: '018f0000-0000-7000-8000-000000000121',
  assignment: '018f0000-0000-7000-8000-000000000122',
  envelope: '018f0000-0000-7000-8000-000000000123',
  privacy: '018f0000-0000-7000-8000-000000000201',
  approval: '018f0000-0000-7000-8000-000000000301',
  credential: '018f0000-0000-7000-8000-000000000401',
} as const;

const actor: AuthenticatedActor = {
  principalId: ids.principal,
  participantId: ids.participant,
  boundParticipantEpoch: '1',
  boundPrincipalEpoch: '2',
  boundEnvelopeEpoch: '3',
  sessionId: ids.session,
  sessionToken: `${ids.participant}.${ids.session}`,
  platform: true,
};

const proposal = {
  participantId: ids.participant,
  privacyDomainId: ids.privacy,
  principalId: ids.principal,
  sessionId: ids.session,
  sessionEpoch: '4',
  participantEpoch: '1',
  principalEpoch: '2',
  assignmentId: ids.assignment,
  assignmentRowVersion: '5',
  authorityEnvelopeId: ids.envelope,
  authorityEpoch: '3',
  delegationEpoch: '6',
} as const;

function readBinding(resourceId: string) {
  return {
    ...proposal,
    authorityEpoch: actor.boundEnvelopeEpoch,
    participantEpoch: actor.boundParticipantEpoch,
    principalEpoch: actor.boundPrincipalEpoch,
    actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
    resourceId,
  };
}

function readAuthority(): EffectiveAuthority {
  const permission = {
    participantId: ids.participant,
    privacyDomainIds: [ids.privacy],
    actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
    resourceIds: ['*'],
    riskClasses: ['LOW'],
    validFrom: new Date('2026-01-01T00:00:00.000Z'),
    validUntil: new Date('2030-01-01T00:00:00.000Z'),
    makerCheckerRequired: false,
    stepUpRequired: false,
    onwardDelegationDepth: 0,
    state: 'ACTIVE' as const,
  };
  return {
    participantEpoch: '1',
    principalEpoch: '2',
    envelopeEpoch: '3',
    currentParticipantEpoch: '1',
    currentPrincipalEpoch: '2',
    currentEnvelopeEpoch: '3',
    envelope: {
      ...permission,
      id: ids.envelope,
      authorityEpoch: '3',
      semanticDigest: `sha256:${'a'.repeat(64)}`,
    },
    assignment: {
      ...permission,
      id: ids.assignment,
      principalId: ids.principal,
      authorityEnvelopeId: ids.envelope,
      delegationEpoch: '6',
      scopeDigest: `sha256:${'b'.repeat(64)}`,
      roleId: `urn:openpc:role:${ids.assignment}`,
    },
    delegations: [],
  };
}

const apps: ReturnType<typeof buildParticipantService>[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe('participant mutation candidate boundary', () => {
  it.each([
    {
      error: new ParticipantKernelError('PC-IDENTITY-1004'),
      category: 'kernel',
      code: 'PC-IDENTITY-1004',
      status: 403,
    },
    {
      error: Object.assign(new Error('private SQL and credential material'), {
        code: '42P01',
        detail: actor.sessionToken,
      }),
      category: 'database',
      code: '42P01',
      status: 500,
    },
    {
      error: Object.assign(new Error('private provider response'), { code: 'private-token' }),
      category: 'unexpected',
      code: undefined,
      status: 500,
    },
  ])(
    'logs a redacted $category failure at the owning route',
    async ({ error, category, code, status }) => {
      const write = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
      try {
        const app = buildParticipantService(
          new ParticipantKernel({} as ParticipantRepository),
          {
            authenticate: async () => actor,
          },
          undefined,
          {
            propose: async () => {
              throw error;
            },
            authorize: async () => undefined,
          },
        );
        apps.push(app);
        const response = await app.inject({
          method: 'POST',
          url: `/v1/participants/${ids.participant}/roles`,
          headers: {
            'authorization': `Bearer ${actor.sessionToken}`,
            'idempotency-key': 'redacted-role-failure',
            'x-openpc-approval-request-id': ids.approval,
            'x-openpc-aggregate-version': '0',
            'openpc-action-intent-digest': `sha256:${'a'.repeat(64)}`,
            'x-csrf-token': 'c'.repeat(32),
            'origin': 'https://control.openpc.example',
            'host': 'control.openpc.example',
          },
          payload: {
            roleId: ids.assignment,
            displayName: 'Private role label',
            actionIntentIds: [],
          },
        });
        expect(response.statusCode).toBe(status);
        expect(write).toHaveBeenCalledOnce();
        expect(JSON.parse(String(write.mock.calls[0]?.[0]))).toEqual({
          level: 'error',
          event: 'participant_request_failed',
          route: '/v1/participants/:participantId/roles',
          category,
          ...(code ? { code } : {}),
        });
      } finally {
        write.mockRestore();
      }
    },
  );

  it('binds an exact envelope revocation candidate before the durable transition', async () => {
    const revokeEnvelope = vi.fn(async () => ({
      id: ids.envelope,
      participantId: ids.participant,
      authorityEpoch: '3',
      revision: '5',
      state: 'REVOKED' as const,
      semanticDigest: `sha256:${'a'.repeat(64)}`,
      privacyDomainIds: [ids.privacy],
      actionIntentIds: [],
      capabilityIds: ['CALL_RESULT_DISCLOSURE'] as const,
      resourceIds: ['*'],
      riskClasses: ['LOW'],
      validFrom: new Date('2026-01-01T00:00:00.000Z'),
      validUntil: new Date('2030-01-01T00:00:00.000Z'),
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
    }));
    const repository = new Proxy({} as ParticipantRepository, {
      get: (_target, property) =>
        property === 'revokeEnvelope' ? revokeEnvelope : async () => undefined,
    });
    const stage = vi.fn<ParticipantMutationCandidateStager['stage']>(async () => ids.envelope);
    const authorization: ParticipantMutationAuthorizationAdapter = {
      async propose() {
        return proposal;
      },
      async authorize(input) {
        return {
          ...proposal,
          ...input,
          checkerPrincipalId: ids.checker,
          signerCredentialId: ids.credential,
          evidenceCbor: Buffer.from('approval'),
          evidenceDigest: Buffer.alloc(32, 1),
          coseSign1: Buffer.from('signature'),
        };
      },
    };
    const app = buildParticipantService(
      new ParticipantKernel(repository),
      {
        async authenticate() {
          return actor;
        },
      },
      undefined,
      authorization,
      { stage },
    );
    apps.push(app);
    const reason = 'Replace this bound with its narrower active successor.';
    const response = await app.inject({
      method: 'POST',
      url: `/v1/participants/${ids.participant}/envelopes/${ids.envelope}/revoke`,
      headers: {
        'authorization': `Bearer ${actor.sessionToken}`,
        'idempotency-key': 'envelope-revoke-candidate',
        'x-openpc-approval-request-id': ids.approval,
        'x-openpc-aggregate-version': '4',
        'openpc-action-intent-digest': `sha256:${'a'.repeat(64)}`,
        'x-csrf-token': 'c'.repeat(32),
        'origin': 'https://control.openpc.example',
        'host': 'control.openpc.example',
      },
      payload: { envelopeId: ids.envelope, reason },
    });
    expect(response.statusCode).toBe(200);
    expect(stage).toHaveBeenCalledWith(
      expect.objectContaining({
        catalogOperationId: 'ID-OP-ENVELOPE-REVOKE',
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        resourceId: ids.envelope,
        expectedRevision: '4',
        candidate: { envelopeId: ids.envelope, reason },
      }),
    );
    expect(revokeEnvelope).toHaveBeenCalledWith(
      expect.objectContaining({ mutationAuthorization: expect.any(Object) }),
      ids.participant,
      ids.envelope,
      reason,
    );
  });

  it('binds role identity and administrative capabilities before approval without accepting runtime grants', async () => {
    const stage = vi.fn<ParticipantMutationCandidateStager['stage']>(async () => ids.envelope);
    const authorize = vi.fn<ParticipantMutationAuthorizationAdapter['authorize']>(
      async () => undefined,
    );
    const app = buildParticipantService(
      undefined,
      {
        async authenticate() {
          return actor;
        },
      },
      undefined,
      {
        async propose() {
          return proposal;
        },
        authorize,
      },
      { stage },
    );
    apps.push(app);
    const post = (payload: Record<string, unknown>) =>
      app.inject({
        method: 'POST',
        url: `/v1/participants/${ids.participant}/roles`,
        headers: {
          'authorization': `Bearer ${actor.sessionToken}`,
          'idempotency-key': 'role-create-candidate',
          'x-openpc-approval-request-id': ids.approval,
          'x-openpc-aggregate-version': '0',
          'openpc-action-intent-digest': `sha256:${'a'.repeat(64)}`,
          'x-csrf-token': 'c'.repeat(32),
          'origin': 'https://control.openpc.example',
          'host': 'control.openpc.example',
        },
        payload,
      });
    const body = {
      roleId: ids.assignment,
      displayName: 'Auditors',
      actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
    };
    for (const invalid of [
      { ...body, capabilityIds: ['CALL_RESULT_DISCLOSURE'] },
      { ...body, actionIntentIds: [...body.actionIntentIds, ...body.actionIntentIds] },
      { ...body, state: 'ARCHIVED' },
      { ...body, displayName: ' ' },
    ]) {
      expect((await post(invalid)).statusCode).toBe(403);
    }
    expect(stage).not.toHaveBeenCalled();
    expect((await post(body)).statusCode).toBe(403);
    expect(stage).toHaveBeenCalledOnce();
    expect(stage.mock.calls[0]![0]).toMatchObject({
      catalogOperationId: 'ID-OP-ROLE-CREATE',
      resourceId: ids.assignment,
      candidate: {
        id: ids.assignment,
        roleId: `urn:openpc:role:${ids.assignment}`,
        participantId: ids.participant,
        displayName: 'Auditors',
        actionIntentIds: body.actionIntentIds,
        state: 'ACTIVE',
      },
    });
    expect(authorize).toHaveBeenCalledOnce();
  });

  it('binds explicit runtime grants into the approval candidate and rejects malformed grants before staging', async () => {
    const stage = vi.fn<ParticipantMutationCandidateStager['stage']>(async () => ids.envelope);
    const authorize = vi.fn<ParticipantMutationAuthorizationAdapter['authorize']>(
      async () => undefined,
    );
    const app = buildParticipantService(
      undefined,
      {
        async authenticate() {
          return actor;
        },
      },
      undefined,
      {
        async propose() {
          return proposal;
        },
        authorize,
      },
      { stage },
    );
    apps.push(app);
    const payload = {
      envelopeId: ids.envelope,
      semanticDigest: `sha256:${'a'.repeat(64)}`,
      privacyDomainIds: [ids.privacy],
      actionIntentIds: [],
      resourceIds: ['*'],
      riskClasses: ['LOW'],
      validFrom: '2026-01-01T00:00:00.000Z',
      validUntil: '2030-01-01T00:00:00.000Z',
      makerCheckerRequired: false,
      stepUpRequired: false,
      onwardDelegationDepth: 1,
    };
    const post = (grants: Record<string, unknown>) =>
      app.inject({
        method: 'POST',
        url: `/v1/participants/${ids.participant}/envelopes`,
        headers: {
          'authorization': `Bearer ${actor.sessionToken}`,
          'idempotency-key': 'runtime-envelope-candidate',
          'x-openpc-approval-request-id': ids.approval,
          'x-openpc-aggregate-version': '0',
          'openpc-action-intent-digest': `sha256:${'a'.repeat(64)}`,
          'x-csrf-token': 'c'.repeat(32),
          'origin': 'https://control.openpc.example',
          'host': 'control.openpc.example',
        },
        payload: { ...payload, ...grants },
      });
    for (const capabilityIds of [
      null,
      ['eth_call'],
      ['CALL_RESULT_DISCLOSURE', 'CALL_RESULT_DISCLOSURE'],
      ['SEALED_INTERNAL_SAFETY_PREFLIGHT'],
    ]) {
      expect((await post({ capabilityIds })).statusCode).toBe(403);
    }
    expect(stage).not.toHaveBeenCalled();
    for (const grants of [
      {},
      { capabilityIds: [] },
      { capabilityIds: ['CALL_RESULT_DISCLOSURE'] },
      { capabilityIds: ['SIGNED_TRANSACTION_SUBMISSION'] },
    ]) {
      // Approval is deliberately withheld; this is a request-binding test only.
      expect((await post(grants)).statusCode).toBe(403);
    }
    expect(stage).toHaveBeenCalledTimes(4);
    const candidates = stage.mock.calls.map(([input]) => input);
    expect(candidates[0]!.candidate).not.toHaveProperty('capabilityIds');
    expect(candidates[2]!.candidate).toMatchObject({ capabilityIds: ['CALL_RESULT_DISCLOSURE'] });
    expect(new Set(candidates.map((c) => c.candidateDigest)).size).toBe(4);
    expect(authorize.mock.calls.map(([input]) => input.candidateDigest)).toEqual(
      candidates.map((c) => c.candidateDigest),
    );
  });

  it('stages the immutable candidate before requesting its bound approval proof', async () => {
    const calls: string[] = [];
    const repository = new Proxy({} as ParticipantRepository, {
      get: (_target, property) =>
        property === 'createParticipant'
          ? async (_actor: AuthenticatedActor, participant: unknown) => ({
              operationId: ids.session,
              result: participant,
            })
          : async () => undefined,
    });
    const authorization: ParticipantMutationAuthorizationAdapter = {
      async propose() {
        calls.push('propose');
        return proposal;
      },
      async authorize(input) {
        calls.push('authorize');
        return {
          privacyDomainId: ids.privacy,
          checkerPrincipalId: ids.checker,
          signerCredentialId: ids.credential,
          evidenceCbor: Buffer.from('approval'),
          evidenceDigest: Buffer.alloc(32, 1),
          coseSign1: Buffer.from('signature'),
          sessionEpoch: '4',
          participantEpoch: '1',
          principalEpoch: '2',
          assignmentId: ids.assignment,
          assignmentRowVersion: '5',
          authorityEnvelopeId: ids.envelope,
          authorityEpoch: '3',
          delegationEpoch: '6',
          principalId: ids.principal,
          sessionId: ids.session,
          participantId: ids.participant,
          ...input,
        };
      },
    };
    const stage = vi.fn(async () => {
      calls.push('stage');
      return ids.participant;
    });
    const app = buildParticipantService(
      new ParticipantKernel(repository),
      {
        async authenticate() {
          return actor;
        },
      },
      undefined,
      authorization,
      { stage },
    );
    apps.push(app);
    const intentDigest = `sha256:${'a'.repeat(64)}`;
    const response = await app.inject({
      method: 'POST',
      url: '/v1/participants',
      headers: {
        'authorization': `Bearer ${actor.sessionToken}`,
        'idempotency-key': 'participant-create-0001',
        'x-openpc-approval-request-id': ids.approval,
        'x-openpc-aggregate-version': '0',
        'openpc-action-intent-digest': intentDigest,
        'x-csrf-token': 'c'.repeat(32),
        'origin': 'https://control.openpc.example',
        'host': 'control.openpc.example',
      },
      payload: {
        participantId: ids.participant,
        displayName: 'Candidate-bound participant',
        idempotencyKey: 'participant-create-0001',
        firstAdministrator: {
          mandateId: ids.approval,
          invitationId: ids.credential,
          privacyDomainId: ids.privacy,
          roleId: ids.principal,
          authorityEnvelopeId: ids.envelope,
          assignmentId: ids.assignment,
          displayName: 'Candidate-bound first administrator',
          recipientIssuer: 'https://identity.example',
          recipientSubject: 'recipient',
          recipientAudience: 'workbench',
          tokenDigest: `sha256:${'b'.repeat(64)}`,
          actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
          configuration: { 'participant.first_admin_invite_ttl': 86400000 },
        },
      },
    });
    expect(response.statusCode).toBe(201);
    expect(calls).toEqual(['propose', 'stage', 'authorize']);
    expect(stage).toHaveBeenCalledWith(
      expect.objectContaining({
        participantId: ids.participant,
        privacyDomainId: ids.privacy,
        actionIntentDigest: intentDigest,
        catalogOperationId: 'ID-OP-PARTICIPANT-CREATE',
        operationClass: 'CREATE',
        expectedRevision: '0',
      }),
    );
  });

  it('rejects an unbound browser mutation before candidate staging', async () => {
    const stage = vi.fn();
    const app = buildParticipantService(
      undefined,
      {
        async authenticate() {
          return actor;
        },
      },
      undefined,
      undefined,
      { stage },
    );
    apps.push(app);
    const response = await app.inject({
      method: 'POST',
      url: '/v1/participants',
      headers: {
        'authorization': `Bearer ${actor.sessionToken}`,
        'idempotency-key': 'participant-create-0002',
        'x-openpc-approval-request-id': ids.approval,
        'x-openpc-aggregate-version': '0',
      },
      payload: {
        participantId: ids.participant,
        displayName: 'Unbound participant',
        idempotencyKey: 'participant-create-0002',
      },
    });
    expect(response.statusCode).toBe(403);
    expect(stage).not.toHaveBeenCalled();
  });
});

describe('participant envelope read boundary', () => {
  it('returns an authorized same-participant envelope and keeps denied existence hidden', async () => {
    const envelope = {
      id: ids.envelope,
      participantId: ids.participant,
      authorityEpoch: '1',
      state: 'DRAFT' as const,
      semanticDigest: `sha256:${'a'.repeat(64)}`,
      privacyDomainIds: [ids.privacy],
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
      resourceIds: ['*'],
      riskClasses: ['HIGH'],
      validFrom: new Date('2026-01-01T00:00:00.000Z'),
      validUntil: new Date('2030-01-01T00:00:00.000Z'),
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
    };
    const repository = new Proxy({} as ParticipantRepository, {
      get: (_target, property) =>
        property === 'effectiveAuthority'
          ? async () => readAuthority()
          : property === 'getEnvelope'
            ? async () => ({ effect: envelope, operationId: ids.session })
            : async () => undefined,
    });
    const visible = buildParticipantService(
      new ParticipantKernel(repository),
      {
        async authenticate() {
          return actor;
        },
      },
      {
        async resolve({ target }) {
          return {
            boundAuthority: readBinding(target.resourceId),
            platformPermits: true,
            policyAvailable: true,
            factsAvailable: true,
            factsTampered: false,
            existenceVisible: true,
            payloadVisible: true,
            stepUpFresh: false,
          };
        },
      },
    );
    apps.push(visible);
    const response = await visible.inject({
      method: 'GET',
      url: `/v1/participants/${ids.participant}/envelopes/${ids.envelope}`,
      headers: {
        'authorization': `Bearer ${actor.sessionToken}`,
        'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${ids.privacy}`,
      },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      operationId: ids.session,
      effect: { id: ids.envelope, state: 'DRAFT' },
    });

    const hidden = await visible.inject({
      method: 'GET',
      url: `/v1/participants/018f0000-0000-7000-8000-000000000199/envelopes/${ids.envelope}`,
      headers: { authorization: `Bearer ${actor.sessionToken}` },
    });
    expect(hidden.statusCode).toBe(404);
    expect(hidden.json()).toEqual({ error: { code: 'PC-IDENTITY-1008', status: 404 } });
  });
});

describe('participant group catalogue boundary', () => {
  it('requires collection and per-group authority, preserves the cursor, and hides foreign Participants', async () => {
    const groupIds = [
      '018f0000-0000-7000-8000-000000000801',
      '018f0000-0000-7000-8000-000000000802',
    ];
    const calls: string[] = [];
    const repository = new Proxy({} as ParticipantRepository, {
      get: (_target, property) => {
        if (property === 'effectiveAuthority')
          return async (
            _actor: AuthenticatedActor,
            _participantId: string,
            target: { actionIntentId: string },
          ) => {
            const authority = readAuthority();
            return {
              ...authority,
              envelope: { ...authority.envelope, actionIntentIds: [target.actionIntentId] },
              assignment: { ...authority.assignment, actionIntentIds: [target.actionIntentId] },
            };
          };
        if (property === 'groupCatalogueCandidates')
          return async () => ({ ids: groupIds, observedAt: '2026-09-29T12:00:00.000Z' });
        if (property === 'fenceGroupCatalogue') return async () => undefined;
        if (property === 'getGroup')
          return async (
            _actor: AuthenticatedActor,
            participantId: string,
            _privacy: string,
            groupId: string,
          ) => {
            calls.push(groupId);
            return {
              effect: {
                groupId,
                participantId,
                groupName: groupId === groupIds[0] ? 'Alpha' : 'Beta',
                state: 'ACTIVE',
                revision: '1',
                createdAt: '2026-09-29T12:00:00.000Z',
                updatedAt: '2026-09-29T12:00:00.000Z',
                operationId: ids.session,
              },
              members: [],
              nextCursor: null,
            };
          };
        return async () => undefined;
      },
    });
    const denial = { resourceId: undefined as string | undefined };
    const app = buildParticipantService(
      new ParticipantKernel(repository),
      { authenticate: async () => actor },
      {
        resolve: async ({ target }) => ({
          boundAuthority: {
            ...readBinding(target.resourceId),
            actionIntentId: target.actionIntentId,
          },
          platformPermits: true,
          policyAvailable: true,
          factsAvailable: true,
          factsTampered: false,
          existenceVisible: target.resourceId !== denial.resourceId,
          payloadVisible: target.resourceId !== denial.resourceId,
          stepUpFresh: false,
        }),
      },
    );
    apps.push(app);
    const headers = {
      'authorization': `Bearer ${actor.sessionToken}`,
      'openpc-privacy-domain-id': `urn:openpc:privacy-domain:${ids.privacy}`,
    };
    const response = await app.inject({
      method: 'GET',
      url: `/v1/participants/${ids.participant}/groups?search=a&state=ACTIVE&limit=1`,
      headers,
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      items: [{ effect: { groupId: groupIds[0], groupName: 'Alpha' } }],
      nextCursor: groupIds[0],
      completeness: 'COMPLETE',
      authorizedEmpty: false,
    });
    expect(calls).toEqual(groupIds);

    denial.resourceId = groupIds[1];
    expect(
      (
        await app.inject({
          method: 'GET',
          url: `/v1/participants/${ids.participant}/groups?limit=1`,
          headers,
        })
      ).statusCode,
    ).toBe(404);
    expect(
      (
        await app.inject({
          method: 'GET',
          url: '/v1/participants/018f0000-0000-7000-8000-000000000199/groups',
          headers,
        })
      ).statusCode,
    ).toBe(404);
  });
});

describe('role binding preview', () => {
  it('requires exact current role visibility and explicit tenant/privacy context before readback', async () => {
    let authority = readAuthority();
    const preview = {
      participantId: ids.participant,
      roleId: ids.credential,
      roleRef: `urn:openpc:role:${ids.credential}`,
      revision: '2',
      roleDigest: `sha256:${'d'.repeat(64)}`,
      actionIntentIds: [],
    };
    const read = vi.fn(async () => preview);
    const repository = new Proxy({} as ParticipantRepository, {
      get: (_target, property) =>
        property === 'effectiveAuthority' ? async () => authority : read,
    });
    const app = buildParticipantService(
      new ParticipantKernel(repository),
      { authenticate: async () => actor },
      {
        resolve: async ({ target }) => ({
          boundAuthority: readBinding(target.resourceId),
          platformPermits: true,
          policyAvailable: true,
          factsAvailable: true,
          factsTampered: false,
          existenceVisible: true,
          payloadVisible: true,
          stepUpFresh: false,
        }),
      },
    );
    apps.push(app);
    const get = (
      participant: string = ids.participant,
      privacy: string | undefined = `urn:openpc:privacy-domain:${ids.privacy}`,
    ) =>
      app.inject({
        method: 'GET',
        url: `/v1/participants/${participant}/roles/${ids.credential}/binding-preview`,
        headers: {
          authorization: `Bearer ${actor.sessionToken}`,
          ...(privacy ? { 'openpc-privacy-domain-id': privacy } : {}),
        },
      });
    const result = await get();
    expect(result.statusCode).toBe(200);
    expect(result.headers['cache-control']).toBe('no-store');
    expect(result.json()).toEqual(preview);
    expect(read).toHaveBeenCalledExactlyOnceWith(
      { ...actor, readAuthorization: readBinding(ids.credential) },
      ids.participant,
      ids.privacy,
      ids.credential,
    );
    read.mockClear();
    expect((await get(ids.participant, ids.privacy)).statusCode).toBe(404);
    expect((await get(ids.checker)).statusCode).toBe(404);
    authority = { ...authority, currentPrincipalEpoch: '3' };
    expect((await get()).statusCode).toBe(404);
    expect(read).not.toHaveBeenCalled();
    authority = readAuthority();
    const output = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      read.mockRejectedValueOnce(
        Object.assign(new Error('private signed bytes and database inputs'), { code: '42501' }),
      );
      const failed = await get();
      expect(failed.statusCode).toBe(409);
      expect(failed.body).not.toContain('private signed bytes');
      const diagnostic = JSON.parse(String(output.mock.calls[0]?.[0]));
      expect(diagnostic).toMatchObject({
        event: 'role_binding_preview_failed',
        stage: 'fence_session_and_read_role_binding',
        participantId: ids.participant,
        roleId: ids.credential,
        sqlstate: '42501',
      });
      expect(JSON.stringify(diagnostic)).not.toContain('private signed bytes');
    } finally {
      output.mockRestore();
    }
  });
});

describe('assignment role readback', () => {
  it('reads the persisted assignment role and revision, including a revoked result', async () => {
    let authority = readAuthority();
    const storedAssignment = {
      ...authority.assignment,
      id: ids.credential,
      principalId: ids.checker,
      roleId: `urn:openpc:role:${ids.credential}`,
      state: 'REVOKED' as const,
    };
    const read = vi.fn(async () => ({
      effect: storedAssignment,
      revision: '2',
      operationId: ids.approval,
    }));
    const repository = new Proxy({} as ParticipantRepository, {
      get: (_target, property) =>
        property === 'effectiveAuthority' ? async () => authority : read,
    });
    const app = buildParticipantService(
      new ParticipantKernel(repository),
      { authenticate: async () => actor },
      {
        resolve: async ({ target }) => ({
          boundAuthority: readBinding(target.resourceId),
          platformPermits: true,
          policyAvailable: true,
          factsAvailable: true,
          factsTampered: false,
          existenceVisible: true,
          payloadVisible: true,
          stepUpFresh: false,
        }),
      },
    );
    apps.push(app);
    const get = (privacy = `urn:openpc:privacy-domain:${ids.privacy}`) =>
      app.inject({
        method: 'GET',
        url: `/v1/participants/${ids.participant}/assignments/${ids.credential}`,
        headers: {
          'authorization': `Bearer ${actor.sessionToken}`,
          'openpc-privacy-domain-id': privacy,
        },
      });
    const result = await get();
    expect(result.statusCode).toBe(200);
    expect(result.json()).toMatchObject({
      effect: { roleId: storedAssignment.roleId, state: 'REVOKED', principalId: ids.checker },
      revision: '2',
      operationId: ids.approval,
    });
    expect(read).toHaveBeenCalledExactlyOnceWith(
      { ...actor, readAuthorization: readBinding(ids.credential) },
      ids.participant,
      ids.privacy,
      ids.credential,
    );
    read.mockClear();
    for (const privacy of [ids.privacy, `urn:openpc:participant:${ids.privacy}`]) {
      expect((await get(privacy)).statusCode).toBe(404);
    }
    const denied = [
      { ...readAuthority(), currentParticipantEpoch: '2' },
      { ...readAuthority(), currentPrincipalEpoch: '3' },
      {
        ...readAuthority(),
        assignment: { ...readAuthority().assignment, state: 'REVOKED' as const },
      },
      { ...readAuthority(), assignment: { ...readAuthority().assignment, actionIntentIds: [] } },
      {
        ...readAuthority(),
        assignment: { ...readAuthority().assignment, validUntil: new Date('2026-01-01') },
      },
      { ...readAuthority(), assignment: { ...readAuthority().assignment, stepUpRequired: true } },
    ];
    for (const candidate of denied) {
      authority = candidate;
      const response = await get();
      expect(response.statusCode).toBe(404);
      expect(response.json()).toEqual({ error: { code: 'PC-IDENTITY-1008', status: 404 } });
    }
    expect(read).not.toHaveBeenCalled();
  });
});

it('prepares group candidates without approval placeholders and binds repeated changes to their revision', async () => {
  const stage = vi.fn<ParticipantMutationCandidateStager['stage']>(async () => ids.envelope);
  const authorize = vi.fn<ParticipantMutationAuthorizationAdapter['authorize']>(
    async () => undefined,
  );
  const mutate = vi.fn();
  const repository = new Proxy({} as ParticipantRepository, { get: () => mutate });
  const app = buildParticipantService(
    new ParticipantKernel(repository),
    { authenticate: async () => actor },
    undefined,
    { propose: async () => proposal, authorize },
    { stage },
  );
  try {
    const payload = { mutation: 'ADD_MEMBER', groupId: ids.envelope, principalId: ids.checker };
    for (const revision of ['2', '4']) {
      const result = await app.inject({
        method: 'POST',
        url: `/v1/participants/${ids.participant}/groups/prepare`,
        payload,
        headers: {
          'authorization': `Bearer ${actor.sessionToken}`,
          'idempotency-key': `group-version-${revision}`,
          'x-openpc-aggregate-version': revision,
          'openpc-action-intent-digest': `sha256:${'a'.repeat(64)}`,
          'x-csrf-token': 'c'.repeat(32),
          'origin': 'https://control.openpc.example',
          'host': 'control.openpc.example',
        },
      });
      expect(result.statusCode, result.body).toBe(202);
    }
    expect(stage.mock.calls.map(([value]) => value.candidate)).toEqual([
      { ...payload, expectedRevision: '2' },
      { ...payload, expectedRevision: '4' },
    ]);
    expect(new Set(stage.mock.calls.map(([value]) => value.candidateDigest)).size).toBe(2);
    expect(authorize).not.toHaveBeenCalled();
    expect(mutate).not.toHaveBeenCalled();
  } finally {
    await app.close();
  }
});
