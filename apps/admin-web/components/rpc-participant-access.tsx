'use client';

import { performWebAuthnStepUp } from '@openpc/ui-shell';
import Link from 'next/link';
import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { z } from 'zod';
import { rpcPolicyDocument, type RpcAccessMethod } from '../lib/rpc-access';

const panel = 'rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4';
const field = 'min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2';
const button =
  'w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-white disabled:opacity-60';
const requiredModules = [
  'pc.config.assets',
  'pc.evidence',
  'pc.fact-bridge',
  'pc.foundation.kernel',
  'pc.identity',
  'pc.module.framework',
  'pc.multi-rpc',
  'pc.participant.governance',
  'pc.policy.argument-guard',
  'pc.policy.compiler-distributor',
  'pc.policy.contract-method',
  'pc.policy.invocation-capability',
  'pc.policy.lifecycle',
  'pc.policy.rpc-surface',
  'pc.policy.runtime-guard',
  'pc.policy.state-read',
  'pc.runtime',
  'pc.transaction.delivery',
] as const;

interface Actor {
  sessionId: string;
  principalId: string;
  participantId: string;
  privacyDomainId: string;
  contextEpoch: string;
  contextMode: 'PARTICIPANT';
  role: 'operator' | 'viewer';
}
interface Principal {
  principalId: string;
  displayLabel: string;
  kind: string;
  state: string;
}
interface Role {
  id: string;
  roleId: string;
  displayName: string;
  state: string;
}
interface Envelope {
  id: string;
  state: string;
  capabilityIds?: string[];
  resourceIds: string[];
  operationId?: string | null;
  semanticDigest: string;
  validFrom: string;
  validUntil: string | null;
}
interface ModuleBinding {
  moduleId: string;
  semanticVersion: string;
  manifestDigest: string;
  configurationDigest: string;
}
interface SimulationAuthority {
  assignmentId: string;
  envelopeId: string;
  principalId: string;
  roleId: string;
  workloadId: string;
}
interface PolicySet {
  policySetId: string;
  name: string;
}
interface State {
  actor: Actor;
  requiresStepUp?: {
    actionIntentId: string;
    actionIntentDigest: string;
    resourceId: string;
    resourceDigest: string;
  };
  workloads: { effect?: Principal }[];
  roles: { effect?: Role }[];
  envelopes: { effect: Envelope; operationId: string | null }[];
  modules: {
    moduleBindings: ModuleBinding[];
    simulationAuthorities: SimulationAuthority[];
    simulationWorkloads: { principalId: string; workloadId: string }[];
    authorizedEmpty: boolean;
  };
  policySets: PolicySet[];
  preview?: {
    authoritative: false;
    workloadId: string;
    credentialCurrent: boolean;
    policyGenerationId: string;
    policyGeneration: string;
    policyVersionId: string;
    methods: {
      method: string;
      capabilityId: string;
      truthState: string;
      reasons: string[];
      assignments: {
        assignmentId: string;
        assignmentState: string;
        assignmentRevision: string;
        roleId: string | null;
        envelopeId: string;
        envelopeState: string;
        validFrom: string;
        validUntil: string | null;
      }[];
    }[];
  };
}

const requestFailure = 'The request was not completed. Refresh RPC access before continuing.';
const readFailure = 'Participant RPC access is unavailable. Refresh to try again.';
const identifier = z.uuid();
const revision = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const workloadIdentifier = z
  .string()
  .regex(
    /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const stepUpSchema = z.object({
  actionIntentId: z.string().min(1),
  actionIntentDigest: digest,
  resourceId: identifier,
  resourceDigest: digest,
});
// Validate the fields consumed here. The owners may also return additional metadata.
const stateSchema = z.object({
  actor: z.object({
    sessionId: identifier,
    principalId: identifier,
    participantId: identifier,
    privacyDomainId: identifier,
    contextMode: z.literal('PARTICIPANT'),
    contextEpoch: revision,
    role: z.enum(['operator', 'viewer']),
  }),
  requiresStepUp: stepUpSchema.optional(),
  workloads: z.array(
    z.object({
      effect: z
        .object({
          principalId: identifier,
          displayLabel: z.string().min(1).max(160),
          kind: z.literal('WORKLOAD'),
          state: z.literal('ACTIVE'),
        })
        .optional(),
    }),
  ),
  roles: z.array(
    z.object({
      effect: z
        .object({
          id: identifier,
          roleId: z.string().regex(/^urn:openpc:role:[0-9a-f-]{36}$/u),
          displayName: z.string().min(1).max(160),
          state: z.literal('ACTIVE'),
        })
        .optional(),
    }),
  ),
  envelopes: z.array(
    z.object({
      effect: z.object({
        id: identifier,
        state: z.enum(['DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED']),
        capabilityIds: z
          .array(z.enum(['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION']))
          .optional(),
        resourceIds: z.array(z.string()),
        semanticDigest: digest,
        validFrom: z.string().datetime(),
        validUntil: z.string().datetime().nullable(),
      }),
      operationId: identifier.nullable(),
    }),
  ),
  modules: z.object({
    moduleBindings: z.array(
      z.object({
        moduleId: z.string(),
        semanticVersion: z.string(),
        manifestDigest: digest,
        configurationDigest: digest,
      }),
    ),
    simulationAuthorities: z.array(
      z.object({
        assignmentId: identifier,
        envelopeId: identifier,
        principalId: identifier,
        roleId: z.string().min(1).max(256),
        workloadDisplayLabel: z.string().min(1).max(160).optional(),
        roleDisplayName: z.string().min(1).max(160).optional(),
        workloadId: workloadIdentifier,
      }),
    ),
    simulationWorkloads: z.array(
      z.object({ principalId: identifier, workloadId: workloadIdentifier }),
    ),
    authorizedEmpty: z.boolean(),
  }),
  policySets: z.array(
    z.object({
      policySetId: z
        .string()
        .regex(
          /^urn:openpc:policy-set:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
        ),
      name: z.string().min(1).max(160),
    }),
  ),
  preview: z
    .object({
      authoritative: z.literal(false),
      workloadId: workloadIdentifier,
      credentialCurrent: z.boolean(),
      policyGenerationId: identifier,
      policyGeneration: revision,
      policyVersionId: identifier,
      methods: z.array(
        z.object({
          method: z.enum(['eth_call', 'eth_sendRawTransaction']),
          capabilityId: z.enum(['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION']),
          truthState: z.enum(['SUCCESS', 'DENIED']),
          reasons: z.array(z.string()),
          assignments: z.array(
            z.object({
              assignmentId: identifier,
              assignmentState: z.string(),
              assignmentRevision: revision,
              roleId: z.string().nullable(),
              envelopeId: identifier,
              envelopeState: z.string(),
              validFrom: z.string().datetime(),
              validUntil: z.string().datetime().nullable(),
            }),
          ),
        }),
      ),
    })
    .optional(),
});
const policyOperationSchema = z
  .object({
    operationId: identifier,
    actionIntentId: z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u),
    intentDigest: digest,
    idempotencyKey: z.string().min(1).max(256),
    resourceRef: z
      .string()
      .refine(
        (value) =>
          /^urn:openpc:[a-z][a-z0-9-]*:/u.test(value) &&
          identifier.safeParse(value.split(':').at(-1)).success,
      )
      .nullable(),
    revision,
    state: z.enum(['ACCEPTED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'WRITE_AMBIGUITY']),
    truthState: z.literal('SUCCESS'),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
  })
  .passthrough();
const policyBootstrapSchema = z.object({
  actionIntentDigest: digest,
  csrfToken: z.string().min(1),
  path: z.literal(
    '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/create-version',
  ),
});
function actorKey(actor?: Actor) {
  return actor ? JSON.stringify(actor) : '';
}
const localSessionSchema = stateSchema.shape.actor.extend({
  enabled: z.literal(true),
  authenticated: z.literal(true),
});
async function readLocalSession(signal: AbortSignal): Promise<Actor> {
  const value = await fetch('/api/v1/ui/local-session', {
    cache: 'no-store',
    credentials: 'same-origin',
    signal,
  }).then(json<unknown>);
  return stateSchema.shape.actor.parse(localSessionSchema.parse(value));
}
interface MutationContext {
  generation: number;
  actor: string;
  workloadId: string;
  policySetId: string;
}
interface Mutation {
  context: MutationContext;
  actor: Actor;
  frame: State;
  inputRevision: number;
  controller: AbortController;
  sent: boolean;
  originalRequest?: { path: string; options: RequestInit };
}
async function json<T>(response: Response): Promise<T> {
  if (!response.ok) throw new Error(requestFailure);
  return response.json().catch(() => {
    throw new Error(requestFailure);
  }) as Promise<T>;
}
function uuidV7() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let timestamp = Date.now();
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = timestamp & 0xff;
    timestamp = Math.floor(timestamp / 256);
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
  return (
    hex.slice(0, 8) +
    '-' +
    hex.slice(8, 12) +
    '-' +
    hex.slice(12, 16) +
    '-' +
    hex.slice(16, 20) +
    '-' +
    hex.slice(20)
  );
}

export function RpcParticipantAccess() {
  const mounted = useRef(false);
  const read = useRef<{ generation: number; controller?: AbortController }>({ generation: 0 });
  const currentActor = useRef('');
  const selectors = useRef({ workloadId: '', policySetId: '' });
  const [state, setState] = useState<State>();
  const [status, setStatus] = useState('Loading Participant RPC access.');
  const [busy, setBusy] = useState(false);
  const [selectedWorkload, setSelectedWorkload] = useState('');
  const [selectedPolicySet, setSelectedPolicySet] = useState('');
  const [createdVersion, setCreatedVersion] = useState('');
  const [readSelected, setReadSelected] = useState(true);
  const [writeSelected, setWriteSelected] = useState(true);
  const [assignmentRoleId, setAssignmentRoleId] = useState('');
  const [now, setNow] = useState(() => Date.now());
  useLayoutEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const update = () => {
      const time = Date.now();
      setNow(time);
      const boundaries = state?.envelopes
        .flatMap(({ effect }) => [effect.validFrom, effect.validUntil])
        .filter((value): value is string => value !== null)
        .map((value) => Date.parse(value))
        .filter((value) => value > time);
      if (boundaries?.length)
        timer = setTimeout(update, Math.min(Math.min(...boundaries) - time + 1, 2_147_483_647));
    };
    update();
    return () => clearTimeout(timer);
  }, [state]);
  const createdVersionActor = useRef('');
  const mutation = useRef<Mutation | undefined>(undefined);
  const unresolved = useRef<Mutation | undefined>(undefined);
  const inputRevision = useRef(0);
  const frame = useRef(state);
  useLayoutEffect(() => {
    frame.current = state;
    if (mutation.current && !mutation.current.sent && mutation.current.frame !== state)
      mutation.current.controller.abort();
  }, [state]);
  const load = useCallback(async (workloadId?: string, policySetId?: string) => {
    if (!mounted.current) return false;
    read.current.controller?.abort();
    const controller = new AbortController();
    const generation = read.current.generation + 1;
    read.current = { generation, controller };
    const previousActor = currentActor.current;
    const requested = { ...selectors.current };
    setState(undefined);
    setStatus('Loading Participant RPC access.');
    const relevant = () => mounted.current && read.current.generation === generation;
    const parameters = new URLSearchParams({ mode: 'participant' });
    if (workloadId && policySetId) {
      parameters.set('workloadId', workloadId);
      parameters.set('policySetId', policySetId);
    }
    try {
      const before = await readLocalSession(controller.signal);
      if (!relevant()) return false;
      const payload = await fetch('/api/v1/ui/rpc-access-workbench?' + parameters, {
        cache: 'no-store',
        credentials: 'same-origin',
        signal: controller.signal,
      })
        .then(json<unknown>)
        .catch(() => undefined);
      if (!relevant()) return false;
      const after = await readLocalSession(controller.signal);
      if (!relevant()) return false;
      const next = stateSchema.parse(payload);
      if (actorKey(before) !== actorKey(after) || actorKey(next.actor) !== actorKey(after))
        throw new Error(readFailure);
      const sameActor = previousActor === actorKey(next.actor);
      if (!sameActor || next.requiresStepUp) {
        setReadSelected(true);
        setWriteSelected(true);
        setAssignmentRoleId('');
      }
      const selected = {
        workloadId:
          !next.requiresStepUp &&
          sameActor &&
          next.modules.simulationWorkloads.some((item) => item.workloadId === requested.workloadId)
            ? requested.workloadId
            : next.requiresStepUp
              ? ''
              : (next.modules.simulationWorkloads[0]?.workloadId ?? ''),
        policySetId:
          !next.requiresStepUp &&
          sameActor &&
          next.policySets.some((item) => item.policySetId === requested.policySetId)
            ? requested.policySetId
            : next.requiresStepUp
              ? ''
              : (next.policySets[0]?.policySetId ?? ''),
      };
      // A preview belongs to the exact requested selection, never a replacement default.
      if (next.preview && (!workloadId || !policySetId || next.preview.workloadId !== workloadId))
        throw new Error(readFailure);
      if (
        next.requiresStepUp ||
        !sameActor ||
        selected.workloadId !== workloadId ||
        selected.policySetId !== policySetId
      )
        delete next.preview;
      currentActor.current = actorKey(next.actor);
      selectors.current = selected;
      setSelectedWorkload(selected.workloadId);
      setSelectedPolicySet(selected.policySetId);
      setState(next);
      setStatus(
        next.requiresStepUp
          ? 'Verify the registered Participant authenticator to load RPC access.'
          : 'Participant RPC configuration loaded.',
      );
      return true;
    } catch {
      if (relevant()) {
        selectors.current = { workloadId: '', policySetId: '' };
        setSelectedWorkload('');
        setSelectedPolicySet('');
        setStatus(readFailure);
      }
      return false;
    }
  }, []);
  useLayoutEffect(() => {
    mounted.current = true;
    setBusy(false);
    void load();
    return () => {
      mounted.current = false;
      mutation.current?.controller.abort();
      mutation.current = undefined;
      read.current.generation += 1;
      read.current.controller?.abort();
    };
  }, [load]);
  const captureContext = (): MutationContext => ({
    generation: read.current.generation,
    actor: actorKey(state?.actor),
    ...selectors.current,
  });
  const sameContext = (context: MutationContext) =>
    mounted.current &&
    context.actor !== '' &&
    read.current.generation === context.generation &&
    currentActor.current === context.actor &&
    selectors.current.workloadId === context.workloadId &&
    selectors.current.policySetId === context.policySetId;
  const showMutationStatus = (message: string, context: MutationContext) => {
    if (sameContext(context)) setStatus(message);
  };
  const refreshMutation = async (context: MutationContext) => {
    if (!sameContext(context) || !(await load()) || currentActor.current !== context.actor)
      return undefined;
    return captureContext();
  };
  const currentMutation = (operation: Mutation) =>
    mutation.current === operation &&
    !operation.controller.signal.aborted &&
    frame.current === operation.frame &&
    inputRevision.current === operation.inputRevision &&
    sameContext(operation.context);
  const assertMutation = (operation = mutation.current) => {
    if (!operation || !currentMutation(operation)) throw new Error(requestFailure);
    return operation;
  };
  const invalidateInput = () => {
    inputRevision.current += 1;
    if (mutation.current && !mutation.current.sent) mutation.current.controller.abort();
  };
  const qualify = async (operation: Mutation) => {
    assertMutation(operation);
    try {
      const actual = await readLocalSession(operation.controller.signal);
      assertMutation(operation);
      if (actorKey(actual) !== actorKey(operation.actor)) throw new Error(requestFailure);
    } catch {
      if (
        !operation.controller.signal.aborted &&
        mutation.current === operation &&
        mounted.current &&
        frame.current === operation.frame
      ) {
        currentActor.current = '';
        setState(undefined);
        setCreatedVersion('');
        setStatus(readFailure);
      }
      throw new Error(requestFailure);
    }
  };
  const stepUp = async (
    action: Parameters<typeof performWebAuthnStepUp>[0],
    binding: Parameters<typeof performWebAuthnStepUp>[1],
  ) => {
    const operation = assertMutation();
    await performWebAuthnStepUp(action, binding, {
      signal: operation.controller.signal,
      isCurrent: () => currentMutation(operation),
    });
    assertMutation(operation);
    await qualify(operation);
    assertMutation(operation);
  };
  const run = async (work: () => Promise<void>, proofOnly = false) => {
    if (mutation.current || !state || !mounted.current) return;
    if (unresolved.current && !proofOnly) {
      setStatus(
        'The original RPC policy request requires authoritative readback before continuing.',
      );
      return;
    }
    const operation: Mutation = {
      context: captureContext(),
      actor: state.actor,
      frame: state,
      inputRevision: inputRevision.current,
      controller: new AbortController(),
      sent: false,
    };
    mutation.current = operation;
    setBusy(true);
    try {
      await work();
    } catch {
      if (operation.sent ? mutation.current === operation : currentMutation(operation))
        showMutationStatus(
          unresolved.current === operation
            ? 'The request was not completed. The original RPC policy request requires authoritative readback before continuing.'
            : requestFailure,
          operation.context,
        );
    } finally {
      if (mutation.current === operation) {
        mutation.current = undefined;
        if (mounted.current) setBusy(false);
      }
    }
  };
  const write = async (path: string, options: RequestInit, operation: Mutation) => {
    assertMutation(operation);
    operation.originalRequest = { path, options };
    operation.sent = true;
    unresolved.current = operation;
    try {
      const response = await fetch(path, options);
      if (response.status >= 500) throw new Error(requestFailure);
      if (!response.ok && unresolved.current === operation) unresolved.current = undefined;
      return response;
    } catch {
      if (mutation.current === operation) unresolved.current = operation;
      // A lost response cannot prove absence or authorize replay of the captured request.
      if (sameContext(operation.context))
        setStatus(
          'The original RPC policy request requires authoritative readback before continuing.',
        );
      throw new Error(requestFailure);
    }
  };
  const workloads = useMemo(
    () => state?.workloads.flatMap((item) => (item.effect ? [item.effect] : [])) ?? [],
    [state],
  );
  const roles = useMemo(
    () => state?.roles.flatMap((item) => (item.effect ? [item.effect] : [])) ?? [],
    [state],
  );
  const envelopes =
    state?.envelopes.map((item) => ({ ...item.effect, operationId: item.operationId })) ?? [];
  const missingModules =
    state?.modules.moduleBindings === undefined
      ? [...requiredModules]
      : requiredModules.filter(
          (name) => !state.modules.moduleBindings.some((binding) => binding.moduleId === name),
        );
  async function createPolicySet(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const context = captureContext();
    const values = new FormData(event.currentTarget);
    const requestKey = uuidV7();
    const operation = assertMutation();
    const body = JSON.stringify({
      requestKey,
      name: values.get('name'),
      reason: 'Create a policy set for governed RPC access.',
    });
    await qualify(operation);
    const result = await json<unknown>(
      await write(
        '/api/v1/ui/policy-sets',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
        },
        operation,
      ),
    );
    const resultOperation = z.object({ operation: policyOperationSchema }).parse(result).operation;
    if (
      resultOperation.actionIntentId !== 'ACT-POLICY_SETS_CREATE_RESOURCE-V1' ||
      resultOperation.state !== 'SUCCEEDED' ||
      resultOperation.idempotencyKey !== `policy-set-${requestKey}`
    )
      throw new Error(requestFailure);
    if (unresolved.current === operation) unresolved.current = undefined;
    const refreshed = await refreshMutation(context);
    if (refreshed) showMutationStatus('The RPC policy set was created.', refreshed);
  }
  async function createPolicyVersion(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!state || missingModules.length > 0) return;
    const context = captureContext();
    const values = new FormData(event.currentTarget);
    const roleId = String(values.get('readRoleId'));
    const writeRoleId = String(values.get('writeRoleId'));
    const methods = values.getAll('methods').map(String);
    if (methods.length === 0) {
      setStatus('Choose at least one RPC method.');
      return;
    }
    if (
      ![roleId, writeRoleId].every((selected) => roles.some((role) => role.roleId === selected))
    ) {
      setStatus('Choose a role for RPC reads and writes.');
      return;
    }
    const contractPolicies = {
      eth_call: {
        contractMethodPolicyId: String(values.get('readContractPolicyId')),
        revision: String(values.get('readContractPolicyRevision')),
      },
      eth_sendRawTransaction: {
        contractMethodPolicyId: String(values.get('writeContractPolicyId')),
        revision: String(values.get('writeContractPolicyRevision')),
      },
    };
    const bindings = requiredModules.map((name) =>
      state.modules.moduleBindings.find((binding) => binding.moduleId === name)!,
    );
    const semanticDocument = rpcPolicyDocument({
      participantId: state.actor.participantId,
      privacyDomainId: state.actor.privacyDomainId,
      roleId,
      rpcRoleIds: { eth_call: roleId, eth_sendRawTransaction: writeRoleId },
      moduleBindings: bindings.map(
        ({ moduleId, semanticVersion, manifestDigest, configurationDigest }) => ({
          moduleId,
          semanticVersion,
          manifestDigest,
          configurationDigest,
        }),
      ),
      methods: methods as RpcAccessMethod[],
      contractPolicies,
    });
    const operation = assertMutation();
    const body = JSON.stringify({
      policySetId: values.get('policySetId'),
      semanticVersion: values.get('semanticVersion'),
      semanticDocument,
      reason: 'Create the role-bound RPC access policy version.',
    });
    const idempotencyKey = 'policy-create-version-' + uuidV7();
    const bootstrap = policyBootstrapSchema.parse(
      await json<unknown>(
        await fetch('/api/v1/ui/policy-session?action=create-version', {
          cache: 'no-store',
          signal: operation.controller.signal,
        }),
      ),
    );
    assertMutation(operation);
    await qualify(operation);
    const result = await json<unknown>(
      await write(
        bootstrap.path,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Idempotency-Key': idempotencyKey,
            'OpenPC-Action-Intent-Digest': bootstrap.actionIntentDigest,
            'OpenPC-API-Version': '1',
            'OpenPC-Participant-ID': 'urn:openpc:participant:' + operation.actor.participantId,
            'X-CSRF-Token': bootstrap.csrfToken,
            'X-Request-ID': uuidV7(),
            'X-Correlation-ID': uuidV7(),
          },
          body,
        },
        operation,
      ),
    );
    const response = policyOperationSchema
      .extend({
        actionIntentId: z.literal('ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1'),
        resourceRef: z
          .string()
          .refine(
            (value) =>
              value.startsWith('urn:openpc:policy-version:') &&
              identifier.safeParse(value.slice('urn:openpc:policy-version:'.length)).success,
          ),
        revision: z.literal('1'),
        state: z.literal('ACCEPTED'),
      })
      .parse(result);
    if (
      response.intentDigest !== bootstrap.actionIntentDigest ||
      response.idempotencyKey !== idempotencyKey
    )
      throw new Error(requestFailure);
    if (unresolved.current === operation) unresolved.current = undefined;
    if (sameContext(context)) {
      createdVersionActor.current = context.actor;
      setCreatedVersion(response.resourceRef.slice(-36));
    }
    showMutationStatus(
      'The immutable RPC policy version was accepted and is ready for release.',
      context,
    );
  }
  if (!state)
    return (
      <section className={panel}>
        <h2 className="text-xl font-semibold">Participant RPC access</h2>
        <p className="mt-3" role="status">
          {status}
        </p>
        <button className={button + ' mt-3'} disabled={busy} onClick={() => void load()}>
          Refresh Participant RPC access
        </button>
      </section>
    );
  if (state.requiresStepUp)
    return (
      <section className={panel}>
        <h2 className="text-xl font-semibold">Participant RPC access</h2>
        <p className="mt-3" role="status">
          {status}
        </p>
        <button
          className={`${button} mt-4`}
          disabled={busy}
          onClick={() =>
            void run(async () => {
              const context = captureContext();
              await stepUp(
                { ...state.requiresStepUp!, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
                {
                  resourceId: state.requiresStepUp!.resourceId,
                  resourceDigest: state.requiresStepUp!.resourceDigest,
                },
              );
              await refreshMutation(context);
            }, true)
          }
        >
          Verify Participant authenticator and load RPC access
        </button>
      </section>
    );
  return (
    <div className="mt-6 space-y-6" onChangeCapture={invalidateInput}>
      <section className={panel}>
        <h2 className="text-xl font-semibold">RPC access by workload</h2>
        <p className="mt-2 text-[color:var(--muted)]">
          Policies require roles. Assignments bind those roles and RPC capabilities to workload
          principals. Runtime mTLS remains authoritative.
        </p>
        <p className="mt-3" role="status">
          {status}
        </p>
        <button className={button + ' mt-3'} disabled={busy} onClick={() => void load()}>
          Refresh Participant RPC access
        </button>
        <form
          className="mt-4 grid max-w-2xl gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            void load(selectedWorkload, selectedPolicySet);
          }}
        >
          <label className="grid gap-1">
            Workload
            <select
              className={field}
              value={selectedWorkload}
              onChange={(event) => {
                read.current.generation += 1;
                read.current.controller?.abort();
                selectors.current.workloadId = event.target.value;
                setSelectedWorkload(event.target.value);
                setState((current) => current && { ...current, preview: undefined });
              }}
            >
              {state.modules.simulationWorkloads.map((subject) => {
                const workload = workloads.find(
                  (candidate) => candidate.principalId === subject.principalId,
                );
                return (
                  <option key={subject.workloadId} value={subject.workloadId}>
                    {workload?.displayLabel ?? subject.principalId}
                  </option>
                );
              })}
            </select>
          </label>
          <label className="grid gap-1">
            Policy set
            <select
              className={field}
              value={selectedPolicySet}
              onChange={(event) => {
                read.current.generation += 1;
                read.current.controller?.abort();
                selectors.current.policySetId = event.target.value;
                setSelectedPolicySet(event.target.value);
                setState((current) => current && { ...current, preview: undefined });
              }}
            >
              {state.policySets.map((set) => (
                <option key={set.policySetId} value={set.policySetId}>
                  {set.name}
                </option>
              ))}
            </select>
          </label>
          <button className={button} disabled={busy || !selectedWorkload || !selectedPolicySet}>
            Read current RPC access
          </button>
        </form>
        {state.preview ? (
          <div className="mt-4 overflow-x-auto">
            <table className="min-w-full border-collapse text-left text-sm">
              <thead>
                <tr>
                  <th className="border p-2">Workload</th>
                  <th className="border p-2">Method</th>
                  <th className="border p-2">Capability</th>
                  <th className="border p-2">Current preview</th>
                  <th className="border p-2">Role / assignment / envelope</th>
                </tr>
              </thead>
              <tbody>
                {state.preview.methods.map((method) => (
                  <tr key={method.method}>
                    <td className="border p-2 break-all">{state.preview!.workloadId}</td>
                    <td className="border p-2">{method.method}</td>
                    <td className="border p-2">{method.capabilityId}</td>
                    <td className="border p-2">
                      {method.truthState}
                      {method.reasons.length ? ' · ' + method.reasons.join(', ') : ''}
                    </td>
                    <td className="border p-2">
                      {method.assignments.length
                        ? method.assignments
                            .map(
                              (assignment) =>
                                assignment.roleId +
                                ' / ' +
                                assignment.assignmentId +
                                ' / ' +
                                assignment.envelopeId,
                            )
                            .join('; ')
                        : 'No current matching assignment'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="mt-2 text-sm">
              Active policy generation {state.preview.policyGeneration} ·{' '}
              {state.preview.policyGenerationId}. Preview only; protected RPC authorizes again.
            </p>
          </div>
        ) : (
          <p className="mt-4">Select a workload and active policy set to read current access.</p>
        )}
      </section>
      <section className={panel}>
        <h2 className="text-xl font-semibold">Platform RPC envelopes</h2>
        {envelopes.length === 0 ? (
          <p className="mt-3">No authorized RPC envelopes are visible.</p>
        ) : (
          <div className="mt-3 grid gap-3 lg:grid-cols-2">
            {envelopes.map((envelope) => (
              <article
                className="rounded border border-[color:var(--border)] p-3"
                key={envelope.id}
              >
                <p className="break-all">{envelope.id}</p>
                <p className="font-medium">
                  {envelope.state === 'ACTIVE' &&
                  envelope.validUntil !== null &&
                  Date.parse(envelope.validUntil) <= now
                    ? 'Expired'
                    : envelope.state === 'ACTIVE' && Date.parse(envelope.validFrom) > now
                      ? 'Scheduled'
                      : envelope.state}
                </p>
                <p>
                  {(envelope.capabilityIds ?? [])
                    .map((capability) =>
                      capability === 'CALL_RESULT_DISCLOSURE'
                        ? 'Read contract data'
                        : 'Submit signed transactions',
                    )
                    .join(' · ') || 'No RPC capabilities'}
                </p>
                <p className="mt-2 text-sm text-[color:var(--muted)]">
                  {envelope.validUntil === null
                    ? 'No expiry recorded'
                    : 'Expires ' + new Date(envelope.validUntil).toLocaleString()}
                </p>
              </article>
            ))}
          </div>
        )}
      </section>
      {state.actor.role === 'operator' ? (
        <>
          <section className={panel}>
            <h2 className="text-xl font-semibold">Create RPC policy set</h2>
            <form
              className="mt-3 flex flex-wrap items-end gap-3"
              onSubmit={(event) => {
                event.preventDefault();
                void run(() => createPolicySet(event));
              }}
            >
              <label className="grid gap-1">
                Name
                <input className={field} name="name" defaultValue="RPC access policy" required />
              </label>
              <button className={button} disabled={busy}>
                Create policy set
              </button>
            </form>
          </section>
          <section className={panel}>
            <h2 className="text-xl font-semibold">Compose role-bound RPC policy</h2>
            <p className="mt-2">
              Enabled module bindings: {requiredModules.length - missingModules.length}/
              {requiredModules.length}.
            </p>
            {missingModules.length ? (
              <p className="mt-2 text-[color:var(--danger)]">
                Enable these modules first: {missingModules.join(', ')}
              </p>
            ) : null}
            <form
              className="mt-4 grid max-w-3xl gap-3"
              onSubmit={(event) => {
                event.preventDefault();
                void run(() => createPolicyVersion(event));
              }}
            >
              <label className="grid gap-1">
                Policy set
                <select className={field} name="policySetId" required>
                  {state.policySets.map((set) => (
                    <option key={set.policySetId} value={set.policySetId}>
                      {set.name}
                    </option>
                  ))}
                </select>
              </label>
              <fieldset className="grid gap-3 md:grid-cols-2">
                <legend className="mb-2 font-medium">RPC roles</legend>
                {(
                  [
                    ['readRoleId', 'Read RPC role'],
                    ['writeRoleId', 'Write RPC role'],
                  ] as const
                ).map(([name, label]) => (
                  <label key={name} className="grid gap-1">
                    {label}
                    <select
                      className={field}
                      name={name}
                      defaultValue={roles.length === 1 ? roles[0]!.roleId : ''}
                      required
                    >
                      <option value="">Choose a role</option>
                      {roles.map((role) => (
                        <option key={role.id} value={role.roleId}>
                          {role.displayName}
                        </option>
                      ))}
                    </select>
                  </label>
                ))}
              </fieldset>
              <p className="text-sm text-[color:var(--muted)]">
                Set a role for each RPC method, then choose the contract operations to include.
                Workloads need a separate grant for each capability.
              </p>
              <label className="grid gap-1">
                Semantic version
                <input
                  className={field}
                  name="semanticVersion"
                  defaultValue="1.0.0"
                  pattern="(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
                  required
                />
              </label>
              <fieldset className="grid gap-2">
                <legend className="font-medium">Contract operations</legend>
                <label>
                  <input
                    type="checkbox"
                    name="methods"
                    value="eth_call"
                    checked={readSelected}
                    onChange={(event) => setReadSelected(event.target.checked)}
                  />{' '}
                  eth_call
                </label>
                <label>
                  <input
                    type="checkbox"
                    name="methods"
                    value="eth_sendRawTransaction"
                    checked={writeSelected}
                    onChange={(event) => setWriteSelected(event.target.checked)}
                  />{' '}
                  eth_sendRawTransaction
                </label>
              </fieldset>
              <div hidden={!readSelected} className="space-y-3">
                <label className="grid gap-1">
                  Read contract-method policy ID
                  <input
                    className={field}
                    name="readContractPolicyId"
                    required={readSelected}
                    disabled={!readSelected}
                  />
                </label>
                <label className="grid gap-1">
                  Read policy revision
                  <input
                    className={field}
                    name="readContractPolicyRevision"
                    defaultValue="1"
                    required={readSelected}
                    disabled={!readSelected}
                  />
                </label>
              </div>
              <div hidden={!writeSelected} className="space-y-3">
                <label className="grid gap-1">
                  Write contract-method policy ID
                  <input
                    className={field}
                    name="writeContractPolicyId"
                    required={writeSelected}
                    disabled={!writeSelected}
                  />
                </label>
                <label className="grid gap-1">
                  Write policy revision
                  <input
                    className={field}
                    name="writeContractPolicyRevision"
                    defaultValue="1"
                    required={writeSelected}
                    disabled={!writeSelected}
                  />
                </label>
              </div>
              <button
                className={button}
                disabled={
                  busy ||
                  (!readSelected && !writeSelected) ||
                  missingModules.length > 0 ||
                  roles.length === 0 ||
                  state.policySets.length === 0
                }
              >
                Create immutable RPC policy version
              </button>
            </form>
            {createdVersion && createdVersionActor.current === actorKey(state.actor) ? (
              <p className="mt-3 break-all">
                Created version: {createdVersion}. Continue in{' '}
                <Link className="underline" href="/govern/policy-releases">
                  Policy releases
                </Link>
                .
              </p>
            ) : null}
          </section>
          <section className={panel}>
            <h2 className="text-xl font-semibold">Assign RPC role to workload</h2>
            <label className="mt-3 grid max-w-md gap-1">
              Role to assign
              <select
                className={field}
                value={
                  roles.some((role) => role.roleId === assignmentRoleId) ? assignmentRoleId : ''
                }
                disabled={busy || roles.length === 0}
                onChange={(event) => setAssignmentRoleId(event.target.value)}
              >
                <option value="">Choose a role</option>
                {roles.map((role) => (
                  <option key={role.id} value={role.roleId}>
                    {role.displayName}
                  </option>
                ))}
              </select>
            </label>
            <div className="mt-3 grid gap-3 lg:grid-cols-2">
              {workloads.map((workload) => {
                const role = roles.find((item) => item.roleId === assignmentRoleId);
                const callEnvelopes = envelopes.filter(
                  (item) =>
                    item.state === 'ACTIVE' &&
                    Date.parse(item.validFrom) <= now &&
                    (item.validUntil === null || Date.parse(item.validUntil) > now) &&
                    (item.capabilityIds ?? []).includes('CALL_RESULT_DISCLOSURE'),
                );
                const envelope =
                  callEnvelopes.find(
                    (item) =>
                      item.capabilityIds?.length === 1 &&
                      item.capabilityIds[0] === 'CALL_RESULT_DISCLOSURE',
                  ) ?? callEnvelopes[0];
                const params = new URLSearchParams({
                  view: 'grants',
                  principalId: workload.principalId,
                  ...(role ? { roleId: role.roleId } : {}),
                  ...(envelope ? { authorityEnvelopeId: envelope.id } : {}),
                  capabilityIds: 'CALL_RESULT_DISCLOSURE',
                  ...(envelope ? { resourceIds: envelope.resourceIds.join(',') } : {}),
                });
                return (
                  <article
                    className="rounded border border-[color:var(--border)] p-3"
                    key={workload.principalId}
                  >
                    <h3 className="font-semibold">{workload.displayLabel}</h3>
                    <p className="break-all text-sm">{workload.principalId}</p>
                    {role && envelope ? (
                      <Link
                        className={button + ' mt-3 inline-block'}
                        href={'/govern/memberships?' + params}
                      >
                        Assign RPC role
                      </Link>
                    ) : role ? (
                      <p className="mt-3 text-sm text-[color:var(--muted)]">
                        An active, unexpired read envelope is required before assigning this role.
                      </p>
                    ) : (
                      <p className="mt-3 text-sm text-[color:var(--muted)]">
                        Choose a role to prepare its assignment.
                      </p>
                    )}
                  </article>
                );
              })}
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
