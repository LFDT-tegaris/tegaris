'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import type { AuthorizedAction } from '@openpc/ui-shell';
import { PolicySets } from './policy-sets';
import {
  PolicySourceSimulation,
  emptySourceSimulation,
  type SourceSimulationInput,
} from './policy-source-simulation';
import { ContractMethodInspector } from './contract-method-inspector';
import { ContractCatalogue } from './contract-catalogue';
import { SecondaryPanel } from './secondary-panel';
import { PolicySimulationAuthority } from './policy-simulation-authority';
import { PolicyVersionPicker } from './policy-version-picker';
import { PolicyDocumentInput } from './policy-document-input';
import { CopyReference } from './copy-reference';
import { reviewPolicyDocument } from '../lib/policy-document-review';
import { isSessionTransitionPending, observeSessionTransitions } from './session-transition';

import {
  policyAuthorStorageKey,
  policyWorkflowPrivacyRevision,
  readBoundPolicyState,
  writeBoundPolicyState,
  transactionWorkflowPrivacyEvent,
  type PolicyWorkflowActorBinding,
} from './policy-workflow-storage';

const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

interface EffectiveAccessProjection {
  readonly authoritative: false;
  readonly authorityGeneration: string;
  readonly truthState: 'SUCCESS' | 'DENIED' | 'UNKNOWN';
}

function effectiveAccessProjection(value: unknown): EffectiveAccessProjection {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Effective access response rejected.');
  const result = value as Record<string, unknown>;
  if (
    result.authoritative !== false ||
    typeof result.authorityGeneration !== 'string' ||
    !digestPattern.test(result.authorityGeneration) ||
    (result.truthState !== 'SUCCESS' &&
      result.truthState !== 'DENIED' &&
      result.truthState !== 'UNKNOWN')
  )
    throw new Error('Effective access response rejected.');
  return {
    authoritative: false,
    authorityGeneration: result.authorityGeneration,
    truthState: result.truthState,
  };
}

function uuidV7(): string {
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
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

interface PolicyActionBootstrap {
  readonly actionIntentDigest: string;
  readonly csrfToken: string;
  readonly path: string;
}

async function invoke(
  intent: string,
  action: AuthorizedAction,
  body: unknown,
  participantRef: string,
  idempotencyKey: string,
  beforePost?: () => Promise<void>,
) {
  const bootstrapResponse = await fetch(
    `/api/v1/ui/policy-session?action=${encodeURIComponent(intent)}`,
    { cache: 'no-store', credentials: 'same-origin' },
  );
  if (!bootstrapResponse.ok) throw new Error('Policy action bootstrap failed.');
  const bootstrap = (await bootstrapResponse.json()) as PolicyActionBootstrap;
  if (
    bootstrap.path !== action.path ||
    bootstrap.actionIntentDigest !== action.actionIntentDigest ||
    !digestPattern.test(bootstrap.actionIntentDigest)
  )
    throw new Error('Policy action binding failed.');
  await beforePost?.();
  const requestId = uuidV7();
  const response = await fetch(action.path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'OpenPC-Action-Intent-Digest': action.actionIntentDigest,
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': participantRef,
      'X-CSRF-Token': bootstrap.csrfToken,
      'X-Request-ID': requestId,
      'X-Correlation-ID': uuidV7(),
    },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error('The policy owner rejected the action.');
  return response.json() as Promise<Record<string, unknown>>;
}

interface SavedPolicyAuthorState {
  readonly policySetId?: string;
  readonly semanticDocument?: string;
  readonly semanticVersion: string;
  readonly normalizedPolicyDigest: string;
  readonly dependencyClosureDigest: string;
  readonly policyVersionId: string;
  readonly createIdempotencyKey?: string;
}

interface OriginalVersionCreate {
  readonly actor: PolicyWorkflowActorBinding;
  readonly draft: SavedPolicyAuthorState;
  readonly body: string;
  readonly key: string;
  readonly privacyRevision: number;
  outcome: 'UNKNOWN' | 'ACCEPTED';
  versionId?: string;
}
interface SimulationDraft {
  readonly kind: 'CONTRACT' | 'VISIBILITY' | 'SOURCE';
  readonly source: SourceSimulationInput;
  readonly visibilityPolicyId: string;
  readonly purpose: string;
  readonly dimensions: string;
  readonly fields: string;
  readonly contractMethodPolicyId: string;
  readonly method: 'eth_call' | 'eth_sendRawTransaction';
  readonly calldata: string;
}
function sameActor(
  left: PolicyWorkflowActorBinding | undefined,
  right: PolicyWorkflowActorBinding,
): boolean {
  return (
    !!left &&
    ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].every(
      (field) =>
        left[field as keyof PolicyWorkflowActorBinding] ===
        right[field as keyof PolicyWorkflowActorBinding],
    )
  );
}
function sameVersionInput(left: SavedPolicyAuthorState, right: SavedPolicyAuthorState): boolean {
  return (
    left.policySetId === right.policySetId &&
    left.semanticVersion === right.semanticVersion &&
    left.semanticDocument === right.semanticDocument &&
    left.normalizedPolicyDigest === right.normalizedPolicyDigest &&
    left.dependencyClosureDigest === right.dependencyClosureDigest
  );
}
function createBody(draft: SavedPolicyAuthorState): string {
  return JSON.stringify({
    policySetId: draft.policySetId,
    semanticVersion: draft.semanticVersion,
    ...(draft.semanticDocument !== undefined
      ? { semanticDocument: JSON.parse(draft.semanticDocument) as unknown }
      : {
          normalizedPolicyDigest: draft.normalizedPolicyDigest,
          dependencyClosureDigest: draft.dependencyClosureDigest,
        }),
    reason: 'Create the policy version authored in Workbench.',
  });
}

function savedPolicyAuthorState(value: unknown): value is SavedPolicyAuthorState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const saved = value as Record<string, unknown>;
  return (
    (saved.policySetId === undefined ||
      /^urn:openpc:policy-set:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
        String(saved.policySetId),
      )) &&
    /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u.test(String(saved.semanticVersion)) &&
    ((typeof saved.semanticDocument === 'string' && saved.semanticDocument.length <= 1048576) ||
      (digestPattern.test(String(saved.normalizedPolicyDigest)) &&
        digestPattern.test(String(saved.dependencyClosureDigest)))) &&
    (uuidPattern.test(String(saved.policyVersionId)) ||
      (saved.policyVersionId === '' && typeof saved.createIdempotencyKey === 'string')) &&
    (saved.createIdempotencyKey === undefined ||
      /^policy-create-version-[A-Za-z0-9-]{16,128}$/u.test(String(saved.createIdempotencyKey)))
  );
}

function actorBinding(
  value: unknown,
  participantRef: string,
): PolicyWorkflowActorBinding | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const session = value as Record<string, unknown>;
  const participantId = participantRef.slice(participantRef.lastIndexOf(':') + 1);
  if (
    session.authenticated !== true ||
    session.contextMode !== 'PARTICIPANT' ||
    session.participantId !== participantId ||
    !['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].every(
      (field) => typeof session[field] === 'string' && String(session[field]).length > 0,
    )
  )
    return undefined;
  return session as unknown as PolicyWorkflowActorBinding;
}

export function PolicyComposer({
  actions,
  authorityContextKey,
  participantRef,
  stateReadVisibility = false,
  view = 'all',
}: Readonly<{
  actions: readonly AuthorizedAction[];
  authorityContextKey: string;
  participantRef: string;
  stateReadVisibility?: boolean;
  view?: 'all' | 'author' | 'simulation';
}>) {
  const createAction = actions.find((action) => action.operationId === 'createPolicyVersion');
  const simulateAction = actions.find((action) => action.operationId === 'simulatePolicyVersion');
  const [semanticVersion, setSemanticVersion] = useState('');
  const [sourceMode, setSourceMode] = useState<'ADMITTED' | 'DOCUMENT'>('DOCUMENT');
  const [semanticDocument, setSemanticDocument] = useState('');
  const [semanticDocumentOriginal, setSemanticDocumentOriginal] = useState('');
  const documentOriginalRef = useRef(semanticDocumentOriginal);
  documentOriginalRef.current = semanticDocumentOriginal;
  const documentValueRef = useRef(semanticDocument);
  documentValueRef.current = semanticDocument;
  const [simulationKind, setSimulationKind] = useState<'CONTRACT' | 'VISIBILITY' | 'SOURCE'>(
    stateReadVisibility ? 'VISIBILITY' : 'CONTRACT',
  );
  const [sourceSimulation, setSourceSimulation] = useState(emptySourceSimulation);
  const [visibilityPolicyId, setVisibilityPolicyId] = useState('');
  const [purpose, setPurpose] = useState(stateReadVisibility ? 'STATE_READ' : 'AUDIT');
  const [dimensions, setDimensions] = useState(
    stateReadVisibility ? 'EXISTENCE,METADATA,PAYLOAD' : 'EXISTENCE,PAYLOAD',
  );
  const [fields, setFields] = useState('');
  const [normalizedPolicyDigest, setNormalizedPolicyDigest] = useState('');
  const [dependencyClosureDigest, setDependencyClosureDigest] = useState('');
  const [contractMethodPolicyId, setContractMethodPolicyId] = useState('');
  const [methodLibraryOpen, setMethodLibraryOpen] = useState(false);
  const [methodSelectionRevision, setMethodSelectionRevision] = useState(0);
  const [method, setMethod] = useState<'eth_call' | 'eth_sendRawTransaction'>('eth_call');
  const [calldata, setCalldata] = useState('');
  const [simulationWorkloadId, setSimulationWorkloadId] = useState('');
  const [simulationAssignmentId, setSimulationAssignmentId] = useState('');
  const [policyVersionId, setPolicyVersionId] = useState('');
  const [versionReady, setVersionReady] = useState(false);
  const [policySetId, setPolicySetId] = useState('');
  const [simulation, setSimulation] = useState<Record<string, unknown>>();
  const [effectiveAccess, setEffectiveAccess] = useState<EffectiveAccessProjection>();
  const [decisionContextKey, setDecisionContextKey] = useState('');
  const decisionRevision = useRef(0);
  const effectiveReadRef = useRef<AbortController | undefined>(undefined);
  const invalidateDecision = useCallback(() => {
    decisionRevision.current += 1;
    effectiveReadRef.current?.abort();
    effectiveReadRef.current = undefined;
    setSimulation(undefined);
    setEffectiveAccess(undefined);
  }, []);
  const [status, setStatus] = useState('');
  const originalCreate = useRef<OriginalVersionCreate | undefined>(undefined);
  const pendingRestoration = useRef<
    | {
        actor: PolicyWorkflowActorBinding;
        draft: SavedPolicyAuthorState;
        privacyRevision: number;
      }
    | undefined
  >(undefined);
  const createBusyRef = useRef(false);
  const [createBusy, setCreateBusy] = useState(false);
  const [originalOutcome, setOriginalOutcome] = useState<'UNKNOWN' | 'ACCEPTED' | undefined>(
    undefined,
  );
  const [selectionValid, setSelectionValid] = useState(false);
  const selectionRef = useRef({ id: policySetId, valid: selectionValid });
  selectionRef.current = { id: policySetId, valid: selectionValid };
  const workspaceKey = JSON.stringify([authorityContextKey, participantRef, stateReadVisibility]);
  const activeWorkspace = useRef(workspaceKey);
  activeWorkspace.current = workspaceKey;
  const [verifiedWorkspace, setVerifiedWorkspace] = useState<string>();
  const actorReady = verifiedWorkspace === workspaceKey;
  const setActorReady = useCallback(
    (ready: boolean) => setVerifiedWorkspace(ready ? workspaceKey : undefined),
    [workspaceKey],
  );
  const [sessionRevision, setSessionRevision] = useState(0);
  const cacheRestorationAllowed = useRef(true);
  const concealedDraft = useRef<
    | (NonNullable<typeof pendingRestoration.current> & {
        documentOriginal: string;
        documentValue: string;
      })
    | undefined
  >(undefined);
  const concealedSimulation = useRef<
    | {
        actor: PolicyWorkflowActorBinding;
        contextKey: string;
        privacyRevision: number;
        draft: SimulationDraft;
      }
    | undefined
  >(undefined);
  const currentSimulationInput: SimulationDraft = {
    kind: simulationKind,
    source: sourceSimulation,
    visibilityPolicyId,
    purpose,
    dimensions,
    fields,
    contractMethodPolicyId,
    method,
    calldata,
  };
  const simulationInput = useRef(currentSimulationInput);
  simulationInput.current = currentSimulationInput;
  const authorInput = useRef<SavedPolicyAuthorState>({
    semanticVersion: '',
    normalizedPolicyDigest: '',
    dependencyClosureDigest: '',
    policyVersionId: '',
  });
  const actorRef = useRef<PolicyWorkflowActorBinding | undefined>(undefined);
  const loadRevisionRef = useRef(0);
  const simulationTruth = String(
    (simulation?.evaluation as Record<string, unknown> | undefined)?.truthState ?? '',
  );

  const selectSimulationAuthority = useCallback(
    (workloadId: string, assignmentId: string) => {
      setSimulationWorkloadId(workloadId);
      setSimulationAssignmentId(assignmentId);
      invalidateDecision();
    },
    [invalidateDecision],
  );

  const conceal = useCallback(() => {
    if (actorRef.current) {
      concealedDraft.current = {
        actor: actorRef.current,
        draft: { ...authorInput.current },
        documentOriginal: documentOriginalRef.current,
        documentValue: documentValueRef.current,
        privacyRevision: policyWorkflowPrivacyRevision(),
      };
      concealedSimulation.current = {
        actor: actorRef.current,
        contextKey: authorityContextKey,
        privacyRevision: policyWorkflowPrivacyRevision(),
        draft: simulationInput.current,
      };
    }
    loadRevisionRef.current++;
    actorRef.current = undefined;
    pendingRestoration.current = undefined;
    setActorReady(false);
    setSemanticDocument('');
    setSemanticDocumentOriginal('');
    setSemanticVersion('');
    setNormalizedPolicyDigest('');
    setDependencyClosureDigest('');
    setPolicySetId('');
    setSelectionValid(false);
    setVersionReady(false);
    setPolicyVersionId('');
    setSourceSimulation(emptySourceSimulation);
    setVisibilityPolicyId('');
    setPurpose(stateReadVisibility ? 'STATE_READ' : 'AUDIT');
    setDimensions(stateReadVisibility ? 'EXISTENCE,METADATA,PAYLOAD' : 'EXISTENCE,PAYLOAD');
    setFields('');
    setContractMethodPolicyId('');
    setMethod('eth_call');
    setCalldata('');
    setSimulationWorkloadId('');
    setSimulationAssignmentId('');
    invalidateDecision();
  }, [invalidateDecision, authorityContextKey, stateReadVisibility, setActorReady]);

  useEffect(() => {
    const revalidate = (pending: boolean) => {
      conceal();
      if (!pending) setSessionRevision((value) => value + 1);
    };
    const privacyClear = () => {
      cacheRestorationAllowed.current = false;
      actorRef.current = undefined;
      concealedDraft.current = undefined;
      concealedSimulation.current = undefined;
      revalidate(isSessionTransitionPending());
    };
    const hidden = () => {
      if (document.visibilityState !== 'visible') conceal();
    };
    const stop = observeSessionTransitions(conceal, revalidate);
    window.addEventListener('blur', conceal);
    window.addEventListener(transactionWorkflowPrivacyEvent, privacyClear);
    document.addEventListener('visibilitychange', hidden);
    return () => {
      stop();
      window.removeEventListener('blur', conceal);
      window.removeEventListener(transactionWorkflowPrivacyEvent, privacyClear);
      document.removeEventListener('visibilitychange', hidden);
    };
  }, [conceal]);

  useEffect(() => {
    const revision = ++loadRevisionRef.current;
    actorRef.current = undefined;
    pendingRestoration.current = undefined;
    setActorReady(false);
    setStatus(
      originalCreate.current?.outcome === 'UNKNOWN'
        ? 'The original version remains unresolved in its original context.'
        : '',
    );
    setPolicySetId('');
    setSemanticVersion('');
    setSemanticDocument('');
    setSemanticDocumentOriginal('');
    setSourceMode('DOCUMENT');
    setVisibilityPolicyId('');
    setSourceSimulation(emptySourceSimulation);
    setFields('');
    setSimulationKind(stateReadVisibility ? 'VISIBILITY' : 'CONTRACT');
    setPurpose(stateReadVisibility ? 'STATE_READ' : 'AUDIT');
    setDimensions(stateReadVisibility ? 'EXISTENCE,METADATA,PAYLOAD' : 'EXISTENCE,PAYLOAD');
    setNormalizedPolicyDigest('');
    setDependencyClosureDigest('');
    setSimulationWorkloadId('');
    setSimulationAssignmentId('');
    setContractMethodPolicyId('');
    setMethod('eth_call');
    setCalldata('');
    setPolicyVersionId('');
    setVersionReady(false);
    setSelectionValid(false);
    invalidateDecision();
    void fetch('/api/v1/ui/local-session', { credentials: 'same-origin', cache: 'no-store' })
      .then((response) => (response.ok ? response.json() : undefined))
      .then((session: unknown) => {
        if (loadRevisionRef.current !== revision || isSessionTransitionPending()) return;
        const actor = actorBinding(session, participantRef);
        if (!actor) return;
        actorRef.current = actor;
        setActorReady(true);
        const simulationDraft = concealedSimulation.current;
        concealedSimulation.current = undefined;
        if (
          simulationDraft &&
          sameActor(simulationDraft.actor, actor) &&
          simulationDraft.contextKey === authorityContextKey &&
          simulationDraft.privacyRevision === policyWorkflowPrivacyRevision()
        ) {
          const input = simulationDraft.draft;
          setSimulationKind(input.kind);
          setSourceSimulation(input.source);
          setVisibilityPolicyId(input.visibilityPolicyId);
          setPurpose(input.purpose);
          setDimensions(input.dimensions);
          setFields(input.fields);
          setContractMethodPolicyId(input.contractMethodPolicyId);
          setMethod(input.method);
          setCalldata(input.calldata);
        }
        const held = concealedDraft.current;
        concealedDraft.current = undefined;
        const restored =
          held &&
          sameActor(held.actor, actor) &&
          held.privacyRevision === policyWorkflowPrivacyRevision()
            ? held.draft
            : cacheRestorationAllowed.current
              ? readBoundPolicyState(policyAuthorStorageKey, actor, savedPolicyAuthorState)
              : undefined;
        if (!restored) return;
        setSemanticVersion(restored.semanticVersion);
        const originalDocumentCurrent =
          held &&
          sameActor(held.actor, actor) &&
          held.privacyRevision === policyWorkflowPrivacyRevision();
        setSemanticDocument(
          originalDocumentCurrent ? held.documentValue : (restored.semanticDocument ?? ''),
        );
        setSemanticDocumentOriginal(
          originalDocumentCurrent ? held.documentOriginal : (restored.semanticDocument ?? ''),
        );
        setPolicySetId(restored.policySetId ?? '');
        setSourceMode(restored.semanticDocument === undefined ? 'ADMITTED' : 'DOCUMENT');
        setNormalizedPolicyDigest(restored.normalizedPolicyDigest);
        setDependencyClosureDigest(restored.dependencyClosureDigest);
        // A stored version is only a selection hint. Wait for the policy catalogue
        // to confirm the current context before making it available for simulation.
        if (restored.policyVersionId) {
          pendingRestoration.current = {
            actor,
            draft: restored,
            privacyRevision: policyWorkflowPrivacyRevision(),
          };
        }
        if (restored.createIdempotencyKey && !originalCreate.current) {
          try {
            originalCreate.current = {
              actor,
              draft: restored,
              body: createBody(restored),
              key: restored.createIdempotencyKey,
              privacyRevision: policyWorkflowPrivacyRevision(),
              outcome: 'UNKNOWN',
            };
            setOriginalOutcome('UNKNOWN');
          } catch {
            // Invalid retained input is unresolved, never permission for a replacement request.
            setOriginalOutcome('UNKNOWN');
          }
        }
      })
      .catch(() => undefined);
    return () => {
      if (loadRevisionRef.current === revision) loadRevisionRef.current += 1;
      decisionRevision.current += 1;
      effectiveReadRef.current?.abort();
    };
  }, [
    authorityContextKey,
    participantRef,
    invalidateDecision,
    stateReadVisibility,
    sessionRevision,
    setActorReady,
  ]);

  const draft: SavedPolicyAuthorState = {
    policySetId,
    semanticVersion,
    ...(sourceMode === 'DOCUMENT' ? { semanticDocument } : {}),
    normalizedPolicyDigest,
    dependencyClosureDigest,
    policyVersionId: '',
  };
  const draftRef = useRef(draft);
  draftRef.current = draft;
  authorInput.current = { ...draft, policyVersionId };
  const original = originalCreate.current;
  const originalCompatible =
    !original ||
    (sameActor(actorRef.current, original.actor) &&
      original.privacyRevision === policyWorkflowPrivacyRevision() &&
      sameVersionInput(draft, original.draft));
  const documentReady =
    actorReady &&
    actorRef.current &&
    !('error' in reviewPolicyDocument(semanticDocument, actorRef.current));
  const artifactReady =
    digestPattern.test(normalizedPolicyDigest) && digestPattern.test(dependencyClosureDigest);

  async function createVersion(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!actorReady || !createAction || !policySetId || !selectionValid || createBusyRef.current)
      return;
    if (sourceMode === 'DOCUMENT' && !documentReady && originalOutcome !== 'UNKNOWN') {
      setStatus('Review a policy document for the current workspace before creating a version.');
      return;
    }
    const actor = actorRef.current;
    if (
      !actor ||
      (originalOutcome === 'UNKNOWN' && (!originalCreate.current || !originalCompatible)) ||
      (originalCreate.current?.outcome === 'ACCEPTED' &&
        sameVersionInput(draft, originalCreate.current.draft))
    ) {
      setStatus(
        'The original policy version remains unresolved in its original actor and input context.',
      );
      return;
    }
    let attempt = originalCreate.current;
    try {
      // Validate and freeze meaningful input before minting or persisting a request key.
      const body = createBody(draft);
      if (!attempt || attempt.outcome === 'ACCEPTED') {
        const key = `policy-create-version-${uuidV7()}`;
        const capturedDraft = { ...draft, createIdempotencyKey: key };
        if (!savedPolicyAuthorState(capturedDraft)) throw new Error();
        attempt = {
          actor,
          draft: capturedDraft,
          body,
          key,
          privacyRevision: policyWorkflowPrivacyRevision(),
          outcome: 'UNKNOWN',
        };
        originalCreate.current = attempt;
        setOriginalOutcome('UNKNOWN');
        writeBoundPolicyState(policyAuthorStorageKey, actor, capturedDraft);
      }
    } catch {
      setStatus('The policy input must be valid before a version can be created.');
      return;
    }
    if (!attempt) return;
    const captured = attempt;
    const revision = loadRevisionRef.current;
    const current = () =>
      loadRevisionRef.current === revision &&
      sameActor(actorRef.current, captured.actor) &&
      captured.privacyRevision === policyWorkflowPrivacyRevision();
    createBusyRef.current = true;
    setCreateBusy(true);
    invalidateDecision();
    setStatus('Reconciling the original immutable version through the policy owner.');
    try {
      const operation = await invoke(
        'create-version',
        createAction,
        JSON.parse(captured.body) as unknown,
        participantRef,
        captured.key,
        async () => {
          const response = await fetch('/api/v1/ui/local-session', {
            cache: 'no-store',
            credentials: 'same-origin',
          });
          const session: unknown = response.ok ? await response.json() : undefined;
          if (
            !current() ||
            !sameActor(actorBinding(session, participantRef), captured.actor) ||
            !selectionRef.current.valid ||
            selectionRef.current.id !== captured.draft.policySetId ||
            !sameVersionInput(draftRef.current, captured.draft)
          )
            throw new Error('The original actor or selection is unavailable.');
        },
      );
      if (!current()) return;
      const resourceRef = operation.resourceRef;
      if (
        typeof resourceRef !== 'string' ||
        !/^urn:openpc:policy-version:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
          resourceRef,
        )
      )
        throw new Error('Policy owner returned an invalid version reference.');
      const acceptedId = resourceRef.slice(resourceRef.lastIndexOf(':') + 1);
      captured.outcome = 'ACCEPTED';
      captured.versionId = acceptedId;
      setOriginalOutcome('ACCEPTED');
      writeBoundPolicyState(policyAuthorStorageKey, captured.actor, {
        ...captured.draft,
        createIdempotencyKey: undefined,
        policyVersionId: acceptedId,
      });
      if (
        selectionRef.current.valid &&
        selectionRef.current.id === captured.draft.policySetId &&
        sameVersionInput(draftRef.current, captured.draft)
      ) {
        setPolicyVersionId(acceptedId);
        setStatus(
          `Immutable version ${captured.draft.semanticVersion} was accepted. It is not active.`,
        );
      } else
        setStatus(
          'The original version was accepted. Select its original policy set to use its readback.',
        );
    } catch {
      if (current())
        setStatus(
          'The original version result is unknown. Keep the original input and key for reconciliation.',
        );
    } finally {
      createBusyRef.current = false;
      setCreateBusy(false);
    }
  }

  async function simulate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!actorReady || !simulateAction || !policyVersionId || !versionReady) return;
    const actor = actorRef.current;
    if (!actor) {
      setStatus('The current actor and privacy context must be reloaded before simulation.');
      return;
    }
    invalidateDecision();
    const revision = decisionRevision.current;
    const privacyRevision = policyWorkflowPrivacyRevision();
    const current = () =>
      activeWorkspace.current === workspaceKey &&
      actorRef.current === actor &&
      revision === decisionRevision.current &&
      privacyRevision === policyWorkflowPrivacyRevision() &&
      !isSessionTransitionPending();
    setStatus('Running a non-authoritative simulation through the policy evaluator.');
    try {
      const result = await invoke(
        'simulate',
        simulateAction,
        {
          policyVersionId,
          ...(simulationKind === 'VISIBILITY'
            ? {
                visibilityPolicyId,
                purpose,
                dimensions: dimensions
                  .split(',')
                  .map((value) => value.trim())
                  .filter(Boolean),
                fields: fields
                  .split(',')
                  .map((value) => value.trim())
                  .filter(Boolean),
              }
            : simulationKind === 'SOURCE'
              ? {
                  ...sourceSimulation,
                  maximumResponseBytes: Number(sourceSimulation.maximumResponseBytes),
                }
              : {
                  contractMethodPolicyId,
                  method,
                  workloadId: simulationWorkloadId,
                  assignmentId: simulationAssignmentId,
                  calldata,
                }),
        },
        participantRef,
        `policy-simulate-${uuidV7()}`,
        async () => {
          if (!current()) throw new Error('Simulation context changed.');
          const response = await fetch('/api/v1/ui/local-session', {
            cache: 'no-store',
            credentials: 'same-origin',
            signal: AbortSignal.timeout(20_000),
          }).catch(() => undefined);
          const session: unknown = response?.ok
            ? await response.json().catch(() => undefined)
            : undefined;
          if (!current()) throw new Error('Simulation context changed.');
          if (!sameActor(actorBinding(session, participantRef), actor)) {
            conceal();
            setSessionRevision((value) => value + 1);
            throw new Error('Simulation account or workspace could not be confirmed.');
          }
        },
      );
      if (!current()) return;
      setDecisionContextKey(authorityContextKey);
      setSimulation(result);
      setStatus('Simulation completed. No authority or runtime generation was changed.');
    } catch {
      if (!current()) return;
      invalidateDecision();
      setStatus('The policy simulation could not be completed safely.');
    }
  }

  async function checkEffectiveAccess() {
    const actor = actorRef.current;
    const parent = selectionRef.current.id;
    if (!actor || !actorReady || !parent || !selectionRef.current.valid) return;
    invalidateDecision();
    const revision = decisionRevision.current;
    const controller = new AbortController();
    effectiveReadRef.current = controller;
    const current = () =>
      !controller.signal.aborted &&
      actorRef.current === actor &&
      revision === decisionRevision.current &&
      selectionRef.current.id === parent &&
      selectionRef.current.valid;
    setStatus('Reading the current active generation. This preview grants no authority.');
    try {
      const query = new URLSearchParams({
        policySetId: parent,
        visibilityPolicyId,
        purpose,
        dimensions: dimensions
          .split(',')
          .map((value) => value.trim())
          .filter(Boolean)
          .join(','),
        fields: fields
          .split(',')
          .map((value) => value.trim())
          .filter(Boolean)
          .join(','),
      });
      const response = await fetch(`/api/v1/ui/effective-access?${query}`, {
        cache: 'no-store',
        credentials: 'same-origin',
        signal: controller.signal,
      });
      if (!current()) return;
      if (response.status === 404) {
        setStatus('No active policy is available for this visibility request.');
        return;
      }
      if (!response.ok) throw new Error('Effective access unavailable.');
      const value: unknown = await response.json();
      if (!current()) return;
      const result = effectiveAccessProjection(value);
      setDecisionContextKey(authorityContextKey);
      setEffectiveAccess(result);
      setStatus('Current effective access was read. Protected requests are authorized separately.');
    } catch {
      if (!current()) return;
      setStatus('Current effective access could not be read safely.');
    } finally {
      if (effectiveReadRef.current === controller) effectiveReadRef.current = undefined;
    }
  }

  return (
    <section
      aria-labelledby="policy-composer"
      className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
    >
      <h2 className="text-xl font-semibold" id="policy-composer">
        {view === 'simulation'
          ? 'Simulate a policy version'
          : view === 'author'
            ? 'Create a policy version'
            : 'Compose and simulate policy'}
      </h2>
      <p className="mt-2 max-w-3xl text-[color:var(--muted)]">
        {view === 'simulation'
          ? 'Choose an existing policy version and test the expected allowed and denied inputs. Simulation does not change active permissions.'
          : 'Choose a policy file or an existing compiled artifact. Creating a version does not publish it or make it active.'}
      </p>
      {actorReady && actorRef.current ? (
        <PolicySets
          showCreation={view !== 'simulation'}
          actor={actorRef.current}
          selected={policySetId}
          onReadValidityChange={(value) => {
            if (!sameActor(actorRef.current, value.actor)) return;
            selectionRef.current = {
              id: value.policySetId ?? '',
              valid: value.policySetId !== null,
            };
            setSelectionValid(value.policySetId !== null);
            if (value.policySetId === null) {
              setPolicyVersionId('');
              invalidateDecision();
            } else if (pendingRestoration.current) {
              const restored = pendingRestoration.current;
              pendingRestoration.current = undefined;
              if (
                sameActor(actorRef.current, restored.actor) &&
                restored.privacyRevision === policyWorkflowPrivacyRevision() &&
                value.policySetId === restored.draft.policySetId &&
                sameVersionInput(draftRef.current, restored.draft)
              )
                setPolicyVersionId(restored.draft.policyVersionId);
            }
          }}
          onSelect={(value) => {
            if (value !== policySetId) {
              selectionRef.current = { id: value, valid: false };
              setSelectionValid(false);
              setPolicySetId(value);
              setPolicyVersionId(
                originalCreate.current?.outcome === 'ACCEPTED' &&
                  sameActor(actorRef.current, originalCreate.current.actor) &&
                  originalCreate.current.privacyRevision === policyWorkflowPrivacyRevision() &&
                  sameVersionInput(
                    { ...draftRef.current, policySetId: value },
                    originalCreate.current.draft,
                  )
                  ? (originalCreate.current.versionId ?? '')
                  : '',
              );
              invalidateDecision();
            }
          }}
        />
      ) : null}
      {view !== 'simulation' && (
        <form
          className="mt-5 grid gap-4 lg:grid-cols-2"
          onSubmit={(event) => void createVersion(event)}
        >
          <div className="grid gap-1 font-medium">
            <label htmlFor="policy-semantic-version">Semantic version</label>
            <input
              id="policy-semantic-version"
              className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2 font-mono"
              onChange={(event) => setSemanticVersion(event.target.value)}
              pattern="(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
              required
              value={semanticVersion}
              placeholder="e.g. 1.0.0"
            />
          </div>
          <div className="grid gap-1 font-medium">
            <label htmlFor="policy-source-mode">Policy source</label>
            <select
              id="policy-source-mode"
              value={sourceMode}
              onChange={(event) => {
                setSourceMode(event.target.value as typeof sourceMode);
              }}
              className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
            >
              <option value="DOCUMENT">Policy file</option>
              <option value="ADMITTED">Compiled artifact (advanced)</option>
            </select>
          </div>
          {sourceMode === 'DOCUMENT' ? (
            <PolicyDocumentInput
              actor={actorReady ? actorRef.current : undefined}
              value={semanticDocument}
              originalValue={semanticDocumentOriginal}
              onChange={(value, original = value) => {
                setSemanticDocument(value);
                setSemanticDocumentOriginal(original);
              }}
            />
          ) : (
            <fieldset className="lg:col-span-2 min-w-0 rounded-lg border border-[color:var(--border)] p-4">
              <legend className="px-1 font-semibold">Artifact references</legend>
              <p className="mt-2 text-sm text-[color:var(--muted)]">
                Use an existing compiled artifact. Tegaris checks its fingerprints when you create
                the version.
              </p>
              <div className="mt-3 grid gap-4">
                <div className="grid gap-1 font-medium lg:col-span-2">
                  <label htmlFor="policy-normalized-digest">Normalized policy digest</label>
                  <input
                    id="policy-normalized-digest"
                    className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2 font-mono"
                    onChange={(event) => setNormalizedPolicyDigest(event.target.value)}
                    pattern="sha256:[0-9a-f]{64}"
                    placeholder="sha256:…"
                    required
                    value={normalizedPolicyDigest}
                  />
                </div>
                <div className="grid gap-1 font-medium lg:col-span-2">
                  <label htmlFor="policy-dependency-digest">Dependency closure digest</label>
                  <input
                    id="policy-dependency-digest"
                    className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2 font-mono"
                    onChange={(event) => setDependencyClosureDigest(event.target.value)}
                    pattern="sha256:[0-9a-f]{64}"
                    placeholder="sha256:…"
                    required
                    value={dependencyClosureDigest}
                  />
                </div>
              </div>
            </fieldset>
          )}
          <button
            className="w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60"
            disabled={
              !createAction ||
              !actorReady ||
              !policySetId ||
              !selectionValid ||
              createBusy ||
              (sourceMode === 'DOCUMENT' && !documentReady && originalOutcome !== 'UNKNOWN') ||
              (sourceMode === 'ADMITTED' && !artifactReady && originalOutcome !== 'UNKNOWN') ||
              (originalOutcome === 'UNKNOWN' && (!originalCreate.current || !originalCompatible)) ||
              (originalOutcome === 'ACCEPTED' && originalCompatible)
            }
            type="submit"
          >
            {originalOutcome === 'UNKNOWN'
              ? 'Reconcile original version'
              : 'Create immutable version'}
          </button>
        </form>
      )}

      {view === 'author' && policyVersionId && (
        <dl className="mt-4 rounded-lg border border-[color:var(--border)] bg-[color:var(--canvas)] p-4 text-sm">
          <dt className="mb-2 font-medium">Version reference</dt>
          <dd>
            <CopyReference label="Policy version reference" value={policyVersionId} />
          </dd>
        </dl>
      )}

      {view === 'author' && policyVersionId && (
        <a
          className="mt-4 inline-flex min-h-11 items-center gap-2 rounded-lg bg-[color:var(--accent)] px-4 py-2 text-sm font-semibold text-[color:var(--surface)]"
          href="/configure/policies?view=simulation"
        >
          Continue to simulation
          <span aria-hidden="true">→</span>
        </a>
      )}
      {view !== 'author' && (
        <>
          {actorReady && actorRef.current && (
            <PolicyVersionPicker
              actor={actorRef.current}
              policySetId={policySetId}
              enabled={selectionValid && !!policySetId}
              selected={policyVersionId}
              onInvalidated={() => {
                setVersionReady(false);
                invalidateDecision();
              }}
              onVerified={({ actor, version }) => {
                if (
                  !sameActor(actorRef.current, actor) ||
                  version.policySetId !== selectionRef.current.id ||
                  !selectionRef.current.valid
                )
                  return;
                setPolicyVersionId(version.policyVersionId.split(':').at(-1)!);
                setVersionReady(true);
                invalidateDecision();
              }}
            />
          )}
          <form
            className="mt-8 grid gap-4 border-t border-[color:var(--border)] pt-5 lg:grid-cols-2"
            onSubmit={(event) => void simulate(event)}
          >
            <h3 className="text-lg font-semibold lg:col-span-2">Simulation input</h3>
            <div className="grid gap-1 font-medium lg:col-span-2">
              <label htmlFor="simulation-kind">Policy family</label>
              <select
                id="simulation-kind"
                value={simulationKind}
                disabled={!actorReady}
                onChange={(event) => {
                  setSimulationKind(event.target.value as typeof simulationKind);
                  invalidateDecision();
                }}
                className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
              >
                <option value="CONTRACT">Contract method</option>
                <option value="VISIBILITY">Visibility and disclosure</option>
                <option value="SOURCE">Indexer and source acquisition</option>
              </select>
            </div>
            {!actorReady ? (
              <p className="lg:col-span-2 text-sm text-[color:var(--muted)]">
                Checking the current account and workspace before loading simulation inputs.
              </p>
            ) : simulationKind === 'SOURCE' ? (
              <PolicySourceSimulation
                value={sourceSimulation}
                onChange={(value) => {
                  setSourceSimulation(value);
                  invalidateDecision();
                }}
              />
            ) : simulationKind === 'VISIBILITY' ? (
              <>
                {(
                  [
                    [
                      'visibility-policy-id',
                      'Visibility policy ID',
                      visibilityPolicyId,
                      setVisibilityPolicyId,
                    ],
                    ['visibility-purpose', 'Purpose', purpose, setPurpose],
                    [
                      'visibility-dimensions',
                      'Dimensions (comma-separated)',
                      dimensions,
                      setDimensions,
                    ],
                    [
                      'visibility-fields',
                      'Fields (comma-separated; empty for whole receipts)',
                      fields,
                      setFields,
                    ],
                  ] as const
                ).map(([id, label, value, update]) => (
                  <div key={id} className="grid gap-1 font-medium">
                    <label htmlFor={id}>{label}</label>
                    <input
                      id={id}
                      value={value}
                      required={id !== 'visibility-fields'}
                      onChange={(event) => {
                        update(event.target.value);
                        invalidateDecision();
                      }}
                      className="min-w-0 rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                    />
                  </div>
                ))}
              </>
            ) : !versionReady ? (
              <p className="lg:col-span-2 text-sm text-[color:var(--muted)]">
                Choose a policy set and review a version to configure a contract simulation.
              </p>
            ) : (
              <>
                <PolicySimulationAuthority
                  actor={actorReady ? actorRef.current : undefined}
                  contextKey={authorityContextKey}
                  onChange={selectSimulationAuthority}
                />
                <div className="grid gap-1 font-medium">
                  <label htmlFor="simulation-rpc-method">RPC method</label>
                  <select
                    id="simulation-rpc-method"
                    className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2"
                    value={method}
                    onChange={(event) => {
                      setMethod(event.target.value as typeof method);
                      invalidateDecision();
                    }}
                  >
                    <option value="eth_call">Read — eth_call</option>
                    <option value="eth_sendRawTransaction">Write — eth_sendRawTransaction</option>
                  </select>
                </div>
                <div className="grid gap-1 font-medium">
                  <label htmlFor="simulation-contract-method">Contract method policy ID</label>
                  <input
                    id="simulation-contract-method"
                    className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2 font-mono"
                    value={contractMethodPolicyId}
                    onChange={(event) => {
                      setContractMethodPolicyId(event.target.value);
                      invalidateDecision();
                    }}
                    required
                  />
                </div>
                <div className="grid gap-1 font-medium lg:col-span-2">
                  <label htmlFor="simulation-calldata">Encoded call data</label>
                  <textarea
                    id="simulation-calldata"
                    className="rounded border border-[color:var(--border)] bg-[color:var(--canvas)] p-2 font-mono"
                    value={calldata}
                    onChange={(event) => {
                      setCalldata(event.target.value);
                      invalidateDecision();
                    }}
                    placeholder="0x followed by the selector and ABI-encoded arguments"
                    maxLength={262146}
                    required
                  />
                </div>
                <ContractMethodInspector
                  methodPolicyId={contractMethodPolicyId}
                  actor={actorReady ? actorRef.current : undefined}
                  authorityContextKey={authorityContextKey}
                />
                <SecondaryPanel
                  title="Choose a contract method"
                  triggerLabel="Browse method library"
                  className="lg:col-span-2"
                  closeOnChange={`${authorityContextKey}:${methodSelectionRevision}`}
                  onOpenChange={setMethodLibraryOpen}
                >
                  <ContractCatalogue
                    actor={actorReady && methodLibraryOpen ? actorRef.current : undefined}
                    authorityContextKey={authorityContextKey}
                    initialKind="methods"
                    onSelectMethod={(selected) => {
                      setContractMethodPolicyId(selected.id.split(':').at(-1)!);
                      setMethodSelectionRevision((revision) => revision + 1);
                      invalidateDecision();
                    }}
                  />
                </SecondaryPanel>
              </>
            )}
            <button
              className="w-fit rounded bg-[color:var(--accent)] px-3 py-2 font-medium text-[color:var(--surface)] disabled:opacity-60"
              disabled={
                !simulateAction ||
                !policyVersionId ||
                !versionReady ||
                !actorReady ||
                (simulationKind === 'CONTRACT' &&
                  (!simulationWorkloadId || !simulationAssignmentId))
              }
              type="submit"
            >
              Run simulation
            </button>
          </form>

          {simulationKind === 'VISIBILITY' && (
            <button
              className="mt-4 w-fit rounded border border-[color:var(--border)] px-3 py-2 font-medium disabled:opacity-60"
              disabled={
                !actorReady ||
                !policySetId ||
                !selectionValid ||
                !uuidPattern.test(visibilityPolicyId) ||
                !purpose ||
                !dimensions
              }
              type="button"
              onClick={() => void checkEffectiveAccess()}
            >
              Check current effective access
            </button>
          )}
          {effectiveAccess && decisionContextKey === authorityContextKey && (
            <section
              aria-label="Current effective access"
              className="mt-5 rounded border border-[color:var(--border)] p-3"
            >
              <strong>Current effective access — preview only</strong>
              <dl className="mt-2 grid gap-2">
                <div>
                  <dt className="font-medium">Truth</dt>
                  <dd>{String(effectiveAccess.truthState)}</dd>
                </div>
                <div>
                  <dt className="font-medium">Active generation</dt>
                  <dd className="break-all font-mono">
                    {String(effectiveAccess.authorityGeneration)}
                  </dd>
                </div>
              </dl>
            </section>
          )}

          {simulation && decisionContextKey === authorityContextKey && (
            <section
              aria-label="Simulation result"
              className={`mt-5 rounded border p-3 ${simulationTruth === 'DENIED' ? 'border-[color:var(--danger)]' : simulationTruth === 'SUCCESS' ? 'border-[color:var(--success)]' : 'border-[color:var(--border)]'}`}
            >
              <h3 className="font-semibold">Simulation result</h3>
              <p className="mt-1 text-sm text-[color:var(--muted)]">
                Preview only. Live access is unchanged.
              </p>
              <dl className="mt-2 grid gap-2 sm:grid-cols-2">
                <div>
                  <dt className="font-medium">Scope</dt>
                  <dd>
                    {simulation.authorityLabel === 'SIMULATION_ONLY'
                      ? 'Policy preview'
                      : 'Unavailable'}
                  </dd>
                </div>
                <div>
                  <dt className="font-medium">Outcome</dt>
                  <dd>
                    {simulationTruth === 'SUCCESS'
                      ? 'Permitted'
                      : simulationTruth === 'DENIED'
                        ? 'Denied'
                        : 'Not determined'}
                  </dd>
                </div>
              </dl>
            </section>
          )}
        </>
      )}
      <p aria-live="polite" className="mt-4 text-sm" role="status">
        {status}
      </p>
    </section>
  );
}
