'use client';

import { useCallback, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { performWebAuthnStepUp } from '@openpc/ui-shell';
import { LocalSessionSurface } from './local-session';
import { WorkspaceEntry } from './workspace-entry';
import { WorkspaceStatus } from './workspace-status';
import { ContractCatalogue } from './contract-catalogue';
import { SecondaryPanel, focusFirstInvalidField } from './secondary-panel';
import { ContractRecordSummary, recordStateLabel } from './contract-record-summary';
import { ProviderRecordSummary } from './provider-record-summary';
import {
  RuntimeTargetSelect,
  RuntimeProfileSummary,
  RuntimeProfileDirectory,
} from './runtime-profile-workflow';
import { ModuleRecordSummary } from './module-record-summary';
import { localSessionStatusSchema } from '../lib/local-session-status';
import { readAbiJsonFile } from '../lib/abi-json-file';
import { ContractMethodSelect, ContractRoleSelect } from './contract-method-fields';
import { InteractionAnalysisFields } from './interaction-analysis-fields';
import { InteractionGrantFields } from './interaction-grant-fields';
import { PrincipalCatalogue } from './principal-catalogue';
import { ApprovalCatalogue } from './approval-catalogue';
import { approvalStateLabels, approvalTime } from '../lib/approval-catalogue';
import { WorkflowDetails } from './workflow-details';
import { RequestOutcome } from './request-outcome';
import { protectedUtcInput } from '../lib/protected-proof-catalogue';
import type { ContractCatalogueSelection } from '../lib/contract-catalogue';
import { sessionTransitionEvent, sessionTransitionStorageKey } from './session-transition';
import {
  clearBoundPolicyState,
  readBoundPolicyState,
  transactionWorkflowPrivacyEvent,
  transactionWorkflowPrivacyStorageKey,
  writeBoundPolicyState,
  type PolicyWorkflowActorBinding,
} from './policy-workflow-storage';
import {
  transactionFields,
  transactionForms,
  visibleTransactionFields,
  type TransactionKind,
  type TransactionField,
} from '../lib/transaction-workflow';
import type { ApprovalCandidateView } from '../../../services/module-registry/src/approval-candidate-contract';
import type { FactRetirementSummary } from '../app/api/v1/ui/fact-retirement-preview';

interface StepUp {
  actionIntentId: string;
  actionIntentDigest: string;
  resourceId: string;
  resourceDigest: string;
}
interface State {
  functionalTest?: true;
  actor: PolicyWorkflowActorBinding;
  kind?: TransactionKind;
  reviewToken?: string;
  approval?: {
    approvalRequestId: string;
    makerSubjectRef: string;
    checkerSubjectRef: string | null;
    state: string;
    revision: string;
  };
  candidate?: ApprovalCandidateView;
  evidenceSelection?: unknown;
  factRetirement?: FactRetirementSummary;
  stepUp?: StepUp | null;
  result?: Record<string, unknown> | null;
  resultUnavailable?: boolean;
  operation?: {
    operationId: string;
    state: string;
    truthState: string;
    revision: string;
    updatedAt: string;
  } | null;
  operationUnavailable?: boolean;
}
interface Saved {
  reviewToken?: string;
  approvalId?: string;
  kind?: TransactionKind;
}
interface Preview {
  kind: TransactionKind;
  candidateDigest: string;
  candidate: Record<string, unknown>;
  redactedFields: ApprovalCandidateView['redactedFields'];
  authority: 'NONE';
  factRetirement?: FactRetirementSummary;
}
interface Session extends Partial<PolicyWorkflowActorBinding> {
  authenticated?: boolean;
  contextMode?: string;
  availableContexts?: { participantId: string; privacyDomainId: string }[];
}
const endpoint = '/api/v1/ui/transaction-workbench';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const fieldClass =
  'mt-1 w-full rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-2';
const buttonClass = 'rounded border border-[color:var(--border)] px-3 py-2 disabled:opacity-50';
const methodEnvironments = ['LOCAL', 'DEVELOPMENT', 'TEST', 'PRODUCTION'] as const;
const methodChoiceLabels: Record<string, Record<string, string>> = {
  effect: { READ: 'Read data', WRITE: 'Change state' },
  approvalRequirement: {
    NONE: 'No execution approval',
    SINGLE: 'One approver',
    MAKER_CHECKER: 'Independent maker and checker',
  },
  mfaRequirement: { NONE: 'No additional verification', WEBAUTHN: 'Security key verification' },
};
const operationChoiceLabels: Record<string, Record<string, string>> = {
  dataClass: {
    RAW_SOURCE_BODY: 'Raw source body',
    NORMALIZED_JSON_PROJECTION: 'Normalized JSON projection',
    SEARCH_PROJECTION: 'Search projection',
    RUNTIME_ARTIFACT: 'Runtime artifact',
    ADMITTED_FACT: 'Admitted Fact',
    CANDIDATE_PROJECTION: 'Candidate projection',
    AUDIT_EVIDENCE: 'Audit evidence',
    NOTIFICATION_PAYLOAD: 'Notification payload',
    OUTBOX_INBOX: 'Outbox and inbox records',
    IDENTITY_RECORD: 'Identity record',
  },
  deletionMode: {
    ROW_DELETE: 'Delete record',
    PROJECTION_DELETE: 'Delete projection',
    IDENTIFIER_ALIAS: 'Identifier aliasing',
    CRYPTO_SHRED: 'Cryptographic erasure',
  },
  makerCheckerRequired: { true: 'Required', false: 'Not required by this policy' },
  holdKind: { LEGAL: 'Legal', REGULATORY: 'Regulatory', INCIDENT: 'Incident' },
  selectorType: {
    PRIVACY_DOMAIN: 'Entire privacy domain',
    SEQUENCE_RANGE: 'Sequence range',
    DIGEST: 'Exact digest',
    PROJECTION: 'Projection',
    FACT_TYPE_KEY: 'Fact type and key',
    BLOCK_RANGE: 'Block range',
    GENERATION: 'Generation',
  },
  factType: {
    CONTRACT_STATE_CALL: 'Contract state call',
    RELATIONSHIP: 'Relationship',
    EXTERNAL_DECISION: 'External decision',
  },
  generationKind: {
    RUNTIME_CONFIGURATION: 'Runtime configuration',
    CANONICAL_FACT: 'Canonical Fact',
  },
  amountMode: { EXACT: 'Exact amount', MAXIMUM: 'Maximum amount' },
  status: { ACTIVE: 'Active', DISABLED: 'Disabled' },
};
function stringArray(value: string | undefined): string[] | undefined {
  if (!value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) && parsed.every((item) => typeof item === 'string')
      ? parsed
      : undefined;
  } catch {
    return undefined;
  }
}
const contextAction = {
  actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
  actionIntentDigest: 'sha256:dbc8290dd60814d5bb4248fefc9550f43d0dc97d6333ac232c8ab8a98c3354d2',
  stepUp: 'FRESH_WEBAUTHN_MAX_5M' as const,
};
const contextDigest = 'sha256:21e6f6ef3dfec5acda58eebd0e07fca2e1394a9777f13157e3e514d611248700';

const failureMessages = {
  unavailable:
    'The request could not be confirmed. Read the original approval and result before retrying.',
  authorization:
    'The request was not authorized. Refresh the authenticated context before continuing.',
  conflict: 'The request changed. Read the original approval and result before continuing.',
  input: 'The request was rejected. Check the inputs before continuing.',
  context: 'The active context changed. Refresh the page.',
  noContext: 'No authorized Participant context is available.',
  checker: 'Choose an independent reviewer or enter their reference.',
  refresh: 'Refresh the authorized request before continuing.',
  resume: 'Refresh the stored request before resuming.',
  abiFile:
    'The ABI could not be loaded. Choose a UTF-8 JSON file containing an ABI array, up to 256 KB.',
  lost: 'The response was lost. Read the approval and original result before retrying.',
} as const;
class WorkflowFailure extends Error {
  constructor(readonly kind: keyof typeof failureMessages) {
    super(failureMessages[kind]);
  }
}
function failureMessage(error: unknown) {
  return error instanceof WorkflowFailure ? error.message : failureMessages.unavailable;
}
async function json<T>(response: Response): Promise<T> {
  const body = await response.json().catch(() => undefined);
  if (!response.ok)
    throw new WorkflowFailure(
      [401, 403, 404].includes(response.status)
        ? 'authorization'
        : [409, 412, 428].includes(response.status)
          ? 'conflict'
          : [400, 422].includes(response.status)
            ? 'input'
            : 'unavailable',
    );
  if (body === undefined) throw new WorkflowFailure('unavailable');
  return body as T;
}
async function command<T>(body: unknown): Promise<T> {
  const response = await fetch(endpoint, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).catch(() => undefined);
  if (!response) throw new WorkflowFailure('lost');
  return json<T>(response);
}
function sameActor(
  left: PolicyWorkflowActorBinding | undefined,
  right: PolicyWorkflowActorBinding | undefined,
) {
  return (
    !!left &&
    !!right &&
    ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].every(
      (field) =>
        left[field as keyof PolicyWorkflowActorBinding] ===
        right[field as keyof PolicyWorkflowActorBinding],
    )
  );
}
function validActor(value: unknown): value is PolicyWorkflowActorBinding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].every(
    (field) =>
      typeof (value as Record<string, unknown>)[field] === 'string' &&
      (value as Record<string, string>)[field]!.length > 0,
  );
}
interface Operation {
  phase: 'PREPARING' | 'SENT';
  readonly controller: AbortController;
  readonly key: string;
  readonly snapshot: string;
  readonly actor: PolicyWorkflowActorBinding | undefined;
}
const validSaved = (value: unknown): value is Saved =>
  typeof value === 'object' &&
  value !== null &&
  (!('reviewToken' in value) || typeof value.reviewToken === 'string') &&
  (!('approvalId' in value) ||
    (typeof value.approvalId === 'string' && uuid.test(value.approvalId))) &&
  (!('kind' in value) ||
    (typeof value.kind === 'string' && Object.hasOwn(transactionForms, value.kind)));

function Document({ label, value }: { label: string; value: unknown }) {
  return (
    <SecondaryPanel title={label}>
      <pre tabIndex={0} className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-sm">
        {JSON.stringify(value, null, 2)}
      </pre>
    </SecondaryPanel>
  );
}

function FactRetirementReview({ value }: { value: FactRetirementSummary }) {
  return (
    <section
      className="mt-3 space-y-2 rounded border border-[color:var(--border)] p-3"
      aria-label={
        value.class === 'CANDIDATE_PROJECTION'
          ? 'Exact candidate retirement'
          : 'Exact Fact retirement'
      }
    >
      <h3 className="font-semibold">
        {value.class === 'CANDIDATE_PROJECTION' ? 'Exact candidate payload' : 'Exact Fact payload'}
      </h3>
      <dl className="grid gap-2 break-all sm:grid-cols-[12rem_1fr]">
        {value.class === 'CANDIDATE_PROJECTION' ? (
          <>
            <dt>Candidate</dt>
            <dd>{value.candidateId}</dd>
            <dt>Generation</dt>
            <dd>{value.generationId}</dd>
            <dt>Partition</dt>
            <dd>{value.partitionId}</dd>
            <dt>Payload digest</dt>
            <dd>{value.payloadDigest}</dd>
          </>
        ) : (
          <>
            <dt>Fact</dt>
            <dd>{value.factId}</dd>
            <dt>Fact generation</dt>
            <dd>{value.factGenerationId}</dd>
            <dt>Canonical generation</dt>
            <dd>{value.canonicalGeneration}</dd>
          </>
        )}
        <dt>Payload bytes</dt>
        <dd>{value.payloadBytes}</dd>
        <dt>Evidence</dt>
        <dd>{value.evidenceId}</dd>
        <dt>Retention policy</dt>
        <dd>{value.retentionPolicyId}</dd>
        <dt>Installed target digest</dt>
        <dd>{value.hostDigest}</dd>
        <dt>Archive acknowledgements</dt>
        <dd>{value.archiveAcknowledgements}</dd>
      </dl>
      <p>
        Approval covers this exact row and archived source. Current holds, policy, references and
        native source conditions are checked again at admission and execution. Signed custody,
        immutable identity and required lineage remain retained.
      </p>
      <p>
        Admission records an approved attempt. Refresh its readback to inspect the signed physical
        outcome. UNKNOWN remains unresolved; do not submit a new retirement to replace it.
      </p>
    </section>
  );
}

function transactionInMode(kind: TransactionKind, mode: string): boolean {
  if (kind === 'runtime-profile-binding') return mode === 'profiles';
  if (mode === 'profiles') return false;
  if (kind === 'policy-activation-renewal') return mode === 'policy';
  if (mode === 'policy') return false;
  if (kind === 'runtime-activation') return false;
  if (kind === 'indexer-admission') return mode === 'runtime';
  if (mode === 'runtime') return false;
  if (kind === 'wallet-binding') return mode === 'wallets';
  if (mode === 'wallets') return false;
  if (kind.startsWith('provider-')) return mode === 'providers';
  if (mode === 'providers') return false;
  if (kind.startsWith('module-') || kind.startsWith('contract-')) return mode === 'modules';
  if (mode === 'modules') return false;
  const evidence =
    kind.startsWith('evidence-') ||
    kind.startsWith('retention-') ||
    kind.startsWith('protected-proof-');
  if (evidence) return mode === 'evidence';
  if (mode === 'evidence') return false;
  return kind.startsWith('cigl-') ? mode === 'cigl' : mode === 'deployment';
}

function contractFieldGroups(mode: string, kind: TransactionKind, values: Record<string, string>) {
  const fields = visibleTransactionFields(kind, values);
  const sections: { title: string; names: string[] }[] =
    mode !== 'modules'
      ? []
      : kind === 'contract-abi'
        ? [{ title: 'Source details', names: ['source', 'locator', 'retrievedAt'] }]
        : kind === 'contract-binding'
          ? [
              {
                title: 'Network identity and code evidence',
                names: ['resourceId', 'genesisDigest', 'codeDigest'],
              },
              {
                title: 'Proxy configuration',
                names: ['proxyAddress', 'implementationAddress', 'implementationCodeDigest'],
              },
              { title: 'Transaction limits', names: ['transactionPolicy'] },
            ]
          : kind === 'contract-method'
            ? [
                {
                  title: 'Policy references',
                  names: ['argumentRuleVersionId', 'rpcMethodPolicyDigest', 'nestedCallSetDigest'],
                },
              ]
            : [];
  const grouped = new Set(sections.flatMap((section) => section.names));
  const groups: { title?: string; fields: TransactionField[] }[] = [
    { fields: fields.filter((field) => !grouped.has(field.name)) },
    ...sections.map((section) => ({
      title: section.title,
      fields: fields.filter((field) => section.names.includes(field.name)),
    })),
  ];
  return groups.filter((group) => group.fields.length > 0);
}

function RequestFieldGroup({ title, children }: { title?: string; children: ReactNode }) {
  return title ? (
    <section className="contract-field-group">
      <h3>{title}</h3>
      <div className="contract-field-group-content">{children}</div>
    </section>
  ) : (
    <>{children}</>
  );
}
function RequestTools({ collapsed, children }: { collapsed: boolean; children: ReactNode }) {
  return collapsed ? (
    <SecondaryPanel title="Register or update a provider">{children}</SecondaryPanel>
  ) : (
    <>{children}</>
  );
}
function RecoveryControls({
  collapsed,
  children,
  resolved,
}: {
  collapsed: boolean;
  children: ReactNode;
  resolved?: string;
}) {
  return collapsed ? (
    <SecondaryPanel title="Recover an existing request" closeOnChange={resolved}>
      {children}
    </SecondaryPanel>
  ) : (
    <>{children}</>
  );
}
function RequestPanel({
  hidden = false,
  title,
  className = '',
  children,
}: {
  hidden?: boolean;
  title: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section hidden={hidden} aria-label={title} className={`workflow-page ${className}`}>
      {children}
    </section>
  );
}

export function TransactionWorkflow({
  mode,
  initialFields,
  initialKind,
  showSessionControls = true,
  collapseRequestTools = false,
  collapseRecoveryControls = false,
  guidedRecovery = false,
  showApprovalCatalogue = guidedRecovery || mode === 'modules' || mode === 'profiles',
  onRecordedResult,
}: {
  mode:
    | 'deployment'
    | 'cigl'
    | 'evidence'
    | 'modules'
    | 'providers'
    | 'wallets'
    | 'runtime'
    | 'profiles'
    | 'policy';
  initialFields?: Record<string, string>;
  initialKind?: TransactionKind;
  showSessionControls?: boolean;
  collapseRequestTools?: boolean;
  collapseRecoveryControls?: boolean;
  guidedRecovery?: boolean;
  showApprovalCatalogue?: boolean;
  onRecordedResult?: (actor: PolicyWorkflowActorBinding) => void;
}) {
  const formId = useId();
  const namedChecker = mode === 'modules' || mode === 'providers' || mode === 'profiles';
  const compactReview = namedChecker || guidedRecovery;
  const [workspaceView, setWorkspaceView] = useState<
    'library' | 'create' | 'activity' | 'references'
  >((mode === 'modules' || mode === 'profiles') && !initialKind ? 'library' : 'create');
  const recordedResultCallback = useRef(onRecordedResult);
  recordedResultCallback.current = onRecordedResult;
  const runtimeKey =
    initialKind === 'evidence-deletion-runtime'
      ? `:${initialKind}:${initialFields?.retentionPolicyId ?? ''}:${initialFields?.previousDeletionJobId ?? 'root'}`
      : '';
  const key = `openpc:transaction-workbench:v1:${mode}${initialKind?.startsWith('evidence-deletion') && (initialFields?.evidenceId || initialFields?.deletionJobId || initialFields?.objectRef) ? `:${initialKind}:${initialFields.evidenceId ?? initialFields.deletionJobId ?? initialFields.objectRef}${initialKind === 'evidence-deletion-fact' || initialKind === 'evidence-deletion-candidate' ? `:${initialFields.hostDigest}:${initialFields.retentionPolicyId}` : ''}` : ''}${runtimeKey}`;
  const [kind, setKind] = useState<TransactionKind>(
    initialKind ??
      (mode === 'policy'
        ? 'policy-activation-renewal'
        : mode === 'profiles'
          ? 'runtime-profile-binding'
          : mode === 'runtime'
            ? 'indexer-admission'
            : mode === 'wallets'
              ? 'wallet-binding'
              : mode === 'providers'
                ? 'provider-profile'
                : mode === 'modules'
                  ? 'contract-asset'
                  : mode === 'deployment'
                    ? 'deployment-intent'
                    : mode === 'evidence'
                      ? 'evidence-export'
                      : 'cigl-analysis'),
  );
  const [values, setValues] = useState<Record<string, string>>(initialFields ?? {});
  const [roleDraft, setRoleDraft] = useState<string>();
  const [abiFileName, setAbiFileName] = useState<string>();
  const abiFileInput = useRef<HTMLInputElement>(null);
  const [resourceSelections, setResourceSelections] = useState<
    Record<string, { value: string; label: string }>
  >({});
  const [reason, setReason] = useState('');
  const [checkerId, setCheckerId] = useState('');
  const [checkerSelection, setCheckerSelection] = useState<{
    id: string;
    displayLabel: string;
  }>();
  const [choosingChecker, setChoosingChecker] = useState(false);
  const [checkerKind, setCheckerKind] = useState<'USER' | 'PLATFORM_OPERATOR'>('USER');
  const checkerChoiceButton = useRef<HTMLButtonElement>(null);
  const [reservedApprovalId, setReservedApprovalId] = useState('');
  const [originalRequestKey, setOriginalRequestKey] = useState('');
  const [approvalInput, setApprovalInput] = useState('');
  const [resourceInput, setResourceInput] = useState('');
  const [saved, setSaved] = useState<Saved>({});
  const [preview, setPreview] = useState<Preview>();
  const [state, setState] = useState<State>();
  const [session, setSession] = useState<Session>();
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [loadingContext, setLoadingContext] = useState(true);
  const requestHeading = useRef<HTMLHeadingElement>(null);
  const requestType = useRef<HTMLSelectElement>(null);
  const requestFocus = useRef<'review' | 'inputs' | undefined>(undefined);
  useLayoutEffect(() => {
    if (loadingContext || !state?.actor) return;
    if (requestFocus.current === 'review' && preview) {
      requestFocus.current = undefined;
      requestHeading.current?.focus();
    } else if (requestFocus.current === 'inputs' && !preview && !saved.approvalId) {
      requestFocus.current = undefined;
      requestType.current?.focus();
    }
  }, [loadingContext, preview, saved.approvalId, state?.actor]);
  const actorRef = useRef<PolicyWorkflowActorBinding | undefined>(undefined);
  const recoveryHeading = useRef<HTMLHeadingElement>(null);
  const recoveryFocus = useRef<string | undefined>(undefined);
  useLayoutEffect(() => {
    if (busy || loadingContext || !recoveryFocus.current) return;
    const selected = recoveryFocus.current;
    recoveryFocus.current = undefined;
    if (
      guidedRecovery &&
      state?.approval?.approvalRequestId === `urn:openpc:resource:${selected}` &&
      sameActor(state.actor, actorRef.current)
    )
      recoveryHeading.current?.focus();
  }, [busy, guidedRecovery, loadingContext, state]);
  const sequence = useRef(0);
  const mounted = useRef(false);
  const changingSession = useRef(false);
  const revalidating = useRef(false);
  const focusGeneration = useRef(0);
  const memorySaved = useRef<
    { key: string; actor: PolicyWorkflowActorBinding; value: Saved } | undefined
  >(undefined);
  const operationRef = useRef<Operation | undefined>(undefined);
  const frame = useRef({ key, snapshot: '', initialFields });
  const snapshot = JSON.stringify({
    mode,
    initialKind,
    initialFields,
    kind,
    values,
    reason,
    checkerId,
    reservedApprovalId,
    originalRequestKey,
    approvalInput,
    resourceInput,
    saved,
    state,
    session,
  });
  useLayoutEffect(() => {
    frame.current = { key, snapshot, initialFields };
    const pending = operationRef.current;
    if (pending?.phase === 'PREPARING' && pending.snapshot !== snapshot) pending.controller.abort();
  });
  const current = useCallback((operation: Operation, exact = false) => {
    return (
      mounted.current &&
      operationRef.current === operation &&
      frame.current.key === operation.key &&
      !operation.controller.signal.aborted &&
      (!operation.actor || sameActor(operation.actor, actorRef.current)) &&
      (!exact || frame.current.snapshot === operation.snapshot)
    );
  }, []);
  function assertCurrent(operation: Operation, exact = true) {
    if (!current(operation, exact))
      throw new DOMException('The operation was cancelled.', 'AbortError');
  }
  const clearPrivateInputs = useCallback(() => {
    requestFocus.current = undefined;
    recoveryFocus.current = undefined;
    setValues({});
    setRoleDraft(undefined);
    setAbiFileName(undefined);
    setResourceSelections({});
    setReason('');
    setCheckerId('');
    setCheckerSelection(undefined);
    setChoosingChecker(false);
    setCheckerKind('USER');
    setReservedApprovalId('');
    setOriginalRequestKey('');
    setApprovalInput('');

    setResourceInput('');
  }, []);
  const save = useCallback(
    (value: Saved, actor: PolicyWorkflowActorBinding) => {
      if (!mounted.current || frame.current.key !== key || !sameActor(actor, actorRef.current))
        return;
      memorySaved.current = { key, actor, value };
      setSaved(value);
      writeBoundPolicyState(key, actor, value);
    },
    [key],
  );
  const load = useCallback(
    async (approvalId?: string, operation?: Operation) => {
      const order = ++sequence.current;
      const active = () =>
        mounted.current &&
        frame.current.key === key &&
        order === sequence.current &&
        (!operation || current(operation));
      const read = async <T,>(url: string): Promise<T | undefined> => {
        const response = await fetch(url, {
          cache: 'no-store',
          credentials: 'same-origin',
          ...(operation ? { signal: operation.controller.signal } : {}),
        });
        if (!active()) return;
        const body = await json<T>(response);
        if (active()) return body;
      };
      const currentSession = await read<Session>('/api/v1/ui/local-session');
      if (!active()) return;
      if (!currentSession) throw new WorkflowFailure('unavailable');
      if (!currentSession.authenticated || currentSession.contextMode !== 'PARTICIPANT') {
        const confirmed = localSessionStatusSchema.safeParse(currentSession);
        if (confirmed.success && confirmed.data.enabled && !confirmed.data.authenticated) {
          clearBoundPolicyState(key);
          memorySaved.current = undefined;
        }
        setSession(currentSession);
        clearPrivateInputs();
        actorRef.current = undefined;
        setState(undefined);
        setSaved({});
        setPreview(undefined);
        return;
      }
      const base = await read<State>(endpoint);
      if (!active()) return;
      if (!validActor(base?.actor)) throw new WorkflowFailure('unavailable');
      const priorActor = actorRef.current;
      const changed = !sameActor(base.actor, priorActor);
      if (operation?.actor && !sameActor(base.actor, operation.actor)) {
        setSession(currentSession);
        clearPrivateInputs();
        actorRef.current = undefined;
        setState(undefined);
        setSaved({});
        setPreview(undefined);
        return;
      }
      const memory = memorySaved.current;
      const retained =
        memory?.key === key
          ? sameActor(memory.actor, base.actor)
            ? memory.value
            : {}
          : (readBoundPolicyState(key, base.actor, validSaved) ?? {});
      if (Object.keys(retained).length)
        memorySaved.current = { key, actor: base.actor, value: retained };
      // A read stays cancellable while its responses are pending. Publish its
      // own snapshot updates only after the final await so they cannot cancel it.
      const publishContext = () => {
        actorRef.current = base.actor;
        setSession(currentSession);
        if (changed) {
          if (priorActor) clearPrivateInputs();
          setPreview(undefined);
        }
      };
      const id = approvalId ?? retained.approvalId;
      if (!id) {
        publishContext();
        setSaved(retained);
        setState(base);
        return;
      }
      const next = await read<State>(`${endpoint}?${new URLSearchParams({ approvalId: id })}`);
      if (!active()) return;
      if (!validActor(next?.actor)) throw new WorkflowFailure('unavailable');
      publishContext();
      if (
        !sameActor(next.actor, base.actor) ||
        (next.kind && !transactionInMode(next.kind, mode)) ||
        (next.approval && next.approval.approvalRequestId !== `urn:openpc:resource:${id}`)
      ) {
        setState(undefined);
        setSaved({});
        setPreview(undefined);
        return;
      }
      setState(next);
      setWorkspaceView('activity');
      if (next.kind) setKind(next.kind);
      setApprovalInput(id);
      save(
        {
          ...(retained.approvalId === id ? retained : {}),
          ...(next.reviewToken ? { reviewToken: next.reviewToken } : {}),
          approvalId: id,
          kind: next.kind,
        },
        base.actor,
      );
      if (
        mode === 'providers' &&
        next.result &&
        next.operation?.state === 'SUCCEEDED' &&
        next.operation.truthState === 'SUCCESS'
      )
        recordedResultCallback.current?.(next.actor);
    },
    [clearPrivateInputs, current, key, mode, save],
  );
  useLayoutEffect(() => {
    mounted.current = true;
    memorySaved.current = undefined;
    clearPrivateInputs();
    setValues(frame.current.initialFields ?? {});
    setSaved({});
    setState(undefined);
    setPreview(undefined);
    setSession(undefined);
    setApprovalInput('');
    setResourceInput('');
    setStatus('');
    setBusy(false);
    setLoadingContext(true);
    const defaults: Record<typeof mode, TransactionKind> = {
      policy: 'policy-activation-renewal',
      runtime: 'indexer-admission',
      profiles: 'runtime-profile-binding',
      wallets: 'wallet-binding',
      providers: 'provider-profile',
      modules: 'contract-asset',
      deployment: 'deployment-intent',
      evidence: 'evidence-export',
      cigl: 'cigl-analysis',
    };
    setKind(initialKind ?? defaults[mode]);
    let obsolete = false;
    changingSession.current = false;
    const invalidate = () => {
      focusGeneration.current++;
      sequence.current++;
      actorRef.current = undefined;
      operationRef.current?.controller.abort();
      clearPrivateInputs();
      setState(undefined);
      setSession(undefined);
      setSaved({});
      setPreview(undefined);
      setStatus('');
      revalidating.current = true;
      setLoadingContext(true);
    };
    const refreshContext = (force = false) => {
      if (changingSession.current || (!force && operationRef.current)) return;
      const generation = ++focusGeneration.current;
      const order = sequence.current + 1;
      revalidating.current = true;
      setLoadingContext(true);
      void load()
        .catch((error: unknown) => {
          if (mounted.current && frame.current.key === key && sequence.current === order) {
            actorRef.current = undefined;
            clearPrivateInputs();
            setState(undefined);
            setSession(undefined);
            setSaved({});
            setPreview(undefined);
            setStatus(failureMessage(error));
          }
        })
        .finally(() => {
          if (
            !obsolete &&
            mounted.current &&
            frame.current.key === key &&
            sequence.current === order &&
            generation === focusGeneration.current
          ) {
            revalidating.current = false;
            setLoadingContext(false);
          }
        });
    };
    const transition = (phase: unknown) => {
      if (phase !== 'changing' && phase !== 'settled') return;
      invalidate();
      changingSession.current = phase === 'changing';
      if (!changingSession.current) refreshContext(true);
    };
    const event = (value: Event) =>
      transition((value as CustomEvent<{ phase?: unknown }>).detail?.phase);
    const clearCustody = () => {
      clearBoundPolicyState(key);
      memorySaved.current = undefined;
      invalidate();
      refreshContext(true);
    };
    const storage = (value: StorageEvent) => {
      if (
        value.key === transactionWorkflowPrivacyStorageKey ||
        (value.key === key && value.newValue === null)
      ) {
        clearCustody();
        return;
      }
      if (value.key !== sessionTransitionStorageKey) return;
      try {
        transition((JSON.parse(value.newValue ?? 'null') as { phase?: unknown } | null)?.phase);
      } catch {
        invalidate();
        changingSession.current = false;
        refreshContext(true);
      }
    };
    const focus = () => {
      if (changingSession.current) return;
      const generation = ++focusGeneration.current;
      const originalActor = actorRef.current;
      revalidating.current = true;
      setLoadingContext(true);
      const active = () =>
        !obsolete &&
        mounted.current &&
        frame.current.key === key &&
        generation === focusGeneration.current;
      const read = async <T,>(url: string) => {
        const response = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
        if (!active()) return;
        const value = await json<T>(response);
        if (active()) return value;
      };
      void (async () => {
        const currentSession = await read<Session>('/api/v1/ui/local-session');
        if (!active()) return;
        if (!currentSession) throw new WorkflowFailure('unavailable');
        if (!currentSession.authenticated || currentSession.contextMode !== 'PARTICIPANT') {
          if (originalActor || !currentSession.authenticated) invalidate();
          setSession(currentSession);
          revalidating.current = false;
          setLoadingContext(false);
          return;
        }
        const base = await read<State>(endpoint);
        if (!active()) return;
        if (!validActor(base?.actor)) throw new WorkflowFailure('unavailable');
        const latest = await read<Session>('/api/v1/ui/local-session');
        if (!active()) return;
        if (
          !latest?.authenticated ||
          latest.contextMode !== 'PARTICIPANT' ||
          !['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].every(
            (field) =>
              currentSession[field as keyof PolicyWorkflowActorBinding] ===
                base.actor[field as keyof PolicyWorkflowActorBinding] &&
              latest[field as keyof PolicyWorkflowActorBinding] ===
                base.actor[field as keyof PolicyWorkflowActorBinding],
          )
        )
          throw new WorkflowFailure('context');
        if (!sameActor(originalActor, base.actor)) {
          invalidate();
          refreshContext(true);
        }
      })()
        .catch((error: unknown) => {
          if (!active()) return;
          invalidate();
          setStatus(failureMessage(error));
          revalidating.current = false;
          setLoadingContext(false);
        })
        .finally(() => {
          if (active()) {
            revalidating.current = false;
            setLoadingContext(false);
          }
        });
    };
    const visibility = () => {
      if (document.visibilityState === 'visible') focus();
    };
    refreshContext();
    window.addEventListener('focus', focus);
    window.addEventListener('storage', storage);
    window.addEventListener(sessionTransitionEvent, event);
    window.addEventListener(transactionWorkflowPrivacyEvent, clearCustody);
    document.addEventListener('visibilitychange', visibility);
    return () => {
      obsolete = true;
      mounted.current = false;
      operationRef.current?.controller.abort();
      operationRef.current = undefined;
      sequence.current += 1;
      actorRef.current = undefined;
      revalidating.current = false;
      focusGeneration.current++;
      window.removeEventListener('focus', focus);
      window.removeEventListener('storage', storage);
      window.removeEventListener(sessionTransitionEvent, event);
      window.removeEventListener(transactionWorkflowPrivacyEvent, clearCustody);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [clearPrivateInputs, initialKind, key, load, mode]);

  async function run(action: (operation: Operation) => Promise<void>) {
    if (!mounted.current || operationRef.current || revalidating.current || changingSession.current)
      return;
    const operation: Operation = {
      controller: new AbortController(),
      phase: 'PREPARING',
      key,
      snapshot: frame.current.snapshot,
      actor: actorRef.current,
    };
    operationRef.current = operation;
    sequence.current++;
    setBusy(true);
    setStatus('');
    try {
      await action(operation);
    } catch (error) {
      if (current(operation)) {
        setPreview(undefined);
        if (error instanceof WorkflowFailure && error.kind === 'context') {
          actorRef.current = undefined;
          clearPrivateInputs();
          setState(undefined);
        } else
          setState(
            operation.actor
              ? {
                  actor: operation.actor,
                  ...(state?.functionalTest ? { functionalTest: true } : {}),
                }
              : undefined,
          );
        setStatus(failureMessage(error));
      }
    } finally {
      if (operationRef.current === operation) {
        operationRef.current = undefined;
        if (mounted.current && frame.current.key === key) setBusy(false);
      }
    }
  }
  async function readCurrent<T>(operation: Operation, url: string): Promise<T> {
    assertCurrent(operation);
    const response = await fetch(url, {
      cache: 'no-store',
      credentials: 'same-origin',
      signal: operation.controller.signal,
    });
    assertCurrent(operation);
    const body = await json<T>(response);
    assertCurrent(operation);
    return body;
  }
  async function qualify(operation: Operation, original?: State) {
    const nextSession = await readCurrent<Session>(operation, '/api/v1/ui/local-session');
    if (
      !nextSession.authenticated ||
      nextSession.contextMode !== 'PARTICIPANT' ||
      (operation.actor &&
        ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].some(
          (field) =>
            nextSession[field as keyof PolicyWorkflowActorBinding] !== undefined &&
            nextSession[field as keyof PolicyWorkflowActorBinding] !==
              operation.actor?.[field as keyof PolicyWorkflowActorBinding],
        ))
    )
      throw new WorkflowFailure('context');
    const next = await readCurrent<State>(
      operation,
      original && saved.approvalId
        ? `${endpoint}?${new URLSearchParams({ approvalId: saved.approvalId })}`
        : endpoint,
    );
    if (!sameActor(operation.actor, next.actor)) throw new WorkflowFailure('context');
    if (
      original &&
      JSON.stringify({
        kind: next.kind,
        approval: next.approval,
        candidate: next.candidate,
        stepUp: next.stepUp,
      }) !==
        JSON.stringify({
          kind: original.kind,
          approval: original.approval,
          candidate: original.candidate,
          stepUp: original.stepUp,
        })
    )
      throw new WorkflowFailure('conflict');
    // The BFF may re-seal the same durable candidate with a new issuedAt.
    // Keep the original token/body; compare its public immutable owners above.
  }
  const lifecycle = (operation: Operation) => ({
    signal: operation.controller.signal,
    isCurrent: () => current(operation, true),
  });
  async function selectContext(operation: Operation) {
    const available = session?.availableContexts?.[0];
    if (!available) throw new WorkflowFailure('noContext');
    await performWebAuthnStepUp(
      contextAction,
      { resourceId: available.participantId, resourceDigest: contextDigest },
      lifecycle(operation),
    );
    assertCurrent(operation);
    const nextSession = await readCurrent<Session>(operation, '/api/v1/ui/local-session');
    if (
      !nextSession.authenticated ||
      nextSession.contextMode !== session?.contextMode ||
      ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].some(
        (field) =>
          session?.[field as keyof PolicyWorkflowActorBinding] !== undefined &&
          nextSession[field as keyof PolicyWorkflowActorBinding] !==
            session[field as keyof PolicyWorkflowActorBinding],
      ) ||
      JSON.stringify(nextSession.availableContexts?.[0]) !== JSON.stringify(available)
    )
      throw new WorkflowFailure('context');
    operation.phase = 'SENT';
    await json(
      await fetch('/api/v1/ui/session/context', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(available),
      }),
    );
    assertCurrent(operation);
    await load(undefined, operation);
  }
  async function chooseAbiFile(operation: Operation, file: File) {
    if (!operation.actor || kind !== 'contract-abi' || saved.approvalId) return;
    let text: string;
    try {
      text = await readAbiJsonFile(file);
    } catch {
      assertCurrent(operation);
      save({}, operation.actor);
      throw new WorkflowFailure('abiFile');
    }
    assertCurrent(operation);
    setValues((previous) => ({
      ...previous,
      abiSource: text,
      source: 'LOCAL_FIXTURE',
      locator: file.name,
      retrievedAt: new Date().toISOString(),
    }));
    setAbiFileName(file.name);
    setPreview(undefined);
    save({}, operation.actor);
    setStatus('ABI file loaded. Review its source details and request independent approval.');
  }
  async function previewRequest(operation: Operation) {
    const actor = operation.actor;
    if (!actor) return;
    const body = {
      command: 'PREVIEW',
      requestKey: originalRequestKey || undefined,
      resourceReservationId: reservedApprovalId || undefined,
      kind,
      fields: transactionFields(kind, values),
      reason,
    };
    await qualify(operation);
    assertCurrent(operation);
    operation.phase = 'SENT';
    const next = await command<{ reviewToken: string; preview: Preview }>(body);
    assertCurrent(operation);
    if (
      typeof next.reviewToken !== 'string' ||
      !next.preview ||
      !Array.isArray(next.preview.redactedFields)
    )
      throw new WorkflowFailure('unavailable');
    setWorkspaceView('create');
    setPreview(next.preview);
    if (namedChecker) requestFocus.current = 'review';
    save({ kind, reviewToken: next.reviewToken }, actor);
    setState({ actor, ...(state?.functionalTest ? { functionalTest: true } : {}) });
    setApprovalInput('');
    setStatus(
      state?.functionalTest
        ? 'Review the change, then apply it to the test workspace.'
        : 'Preview prepared. Request independent approval for these exact inputs.',
    );
  }
  async function applyTestChange(operation: Operation) {
    const actor = operation.actor;
    if (!actor || !saved.reviewToken || !state?.functionalTest)
      throw new WorkflowFailure('refresh');
    const original = { ...saved };
    await qualify(operation);
    assertCurrent(operation);
    operation.phase = 'SENT';
    const submit = async (body: unknown) => {
      const response = await fetch('/api/v1/ui/functional-transaction', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }).catch(() => undefined);
      if (!response) throw new WorkflowFailure('lost');
      return json<{ approvalId: string; outcome: string }>(response);
    };
    if (!original.approvalId) {
      const prepared = await submit({
        command: 'PREPARE',
        reviewToken: original.reviewToken,
        resourceReservationId: reservedApprovalId || undefined,
      });
      assertCurrent(operation);
      if (!uuid.test(prepared.approvalId)) throw new WorkflowFailure('unavailable');
      original.approvalId = prepared.approvalId;
      save(original, actor);
      setApprovalInput(prepared.approvalId);
      setWorkspaceView('activity');
    }
    // The durable original is stored before execution. A lost acknowledgement
    // or component unmount cannot change its intent or abort a dispatched write.
    const response = await submit({
      command: 'APPLY',
      approvalId: original.approvalId,
      reviewToken: original.reviewToken,
    });
    // Saving the admitted approval changes this component's snapshot. After
    // dispatch, retain the actor/context fence without rejecting our own save.
    assertCurrent(operation, false);
    if (!uuid.test(response.approvalId) || response.approvalId !== original.approvalId)
      throw new WorkflowFailure('unavailable');
    save({ ...original, approvalId: response.approvalId }, actor);
    await load(response.approvalId, operation);
    if (current(operation))
      setStatus(
        response.outcome === 'PENDING'
          ? 'The change is pending. Its original request is retained for reconciliation.'
          : 'Change submitted. The recorded result is shown below.',
      );
  }
  async function requestApproval(operation: Operation) {
    const actor = operation.actor;
    if (!actor || !saved.reviewToken || !uuid.test(checkerId)) throw new WorkflowFailure('checker');
    const original = { ...saved };
    const body = {
      command: 'REQUEST_APPROVAL',
      resourceReservationId: reservedApprovalId || undefined,
      reviewToken: original.reviewToken,
      checkerId,
    };
    await qualify(operation);
    assertCurrent(operation);
    operation.phase = 'SENT';
    const response = await command<{ approvalId: string }>(body);
    assertCurrent(operation);
    if (!uuid.test(response.approvalId)) throw new WorkflowFailure('unavailable');
    save({ ...original, approvalId: response.approvalId }, actor);
    await load(response.approvalId, operation);
    if (current(operation))
      setStatus('Approval requested. Share the approval ID with the independent checker.');
  }
  async function act(operation: Operation, commandName: 'APPROVE' | 'EXECUTE') {
    const binding = state?.stepUp,
      original = { ...saved },
      originalState = state;
    if (!operation.actor || !binding || !original.approvalId) throw new WorkflowFailure('refresh');
    const body = {
      command: commandName,
      approvalId: original.approvalId,
      ...(commandName === 'EXECUTE' ? { reviewToken: original.reviewToken } : {}),
    };
    await qualify(operation, originalState);
    if (current(operation))
      setStatus(
        commandName === 'APPROVE'
          ? 'Complete the authenticator prompt to approve this request.'
          : 'Complete the authenticator prompt to execute this request.',
      );
    await performWebAuthnStepUp(
      { ...binding, stepUp: 'FRESH_WEBAUTHN_MAX_5M' },
      binding,
      lifecycle(operation),
    );
    await qualify(operation, originalState);
    assertCurrent(operation);
    operation.phase = 'SENT';
    let response: { truthState?: string } | undefined;
    try {
      response = await command<{ truthState?: string }>(body);
    } catch (error) {
      if (error instanceof WorkflowFailure && error.kind === 'lost' && current(operation)) {
        await load(original.approvalId, operation);
        if (current(operation)) setStatus(failureMessages.lost);
        return;
      }
      throw error;
    }
    if (!current(operation)) return;
    await load(original.approvalId, operation);
    if (current(operation))
      setStatus(
        response?.truthState === 'UNKNOWN'
          ? 'The command response is unresolved. Read the original approval and result before continuing.'
          : commandName === 'APPROVE'
            ? 'Independent approval recorded.'
            : 'Command readback refreshed. Inspect the operation and effect state below.',
      );
  }
  async function resumeRequest(operation: Operation) {
    const candidate = state?.candidate,
      approval = state?.approval,
      originalId = saved.approvalId;
    if (!operation.actor || !candidate?.canRequestResume || !approval || !originalId)
      throw new WorkflowFailure('resume');
    const body = {
      command: 'RESUME',
      approvalId: originalId,
      predecessorCandidateId: candidate.attemptId,
      expectedAttempt: candidate.attempt,
      expectedRevision: approval.revision,
      reason: 'Resume the unchanged request after approval expiry.',
    };
    await qualify(operation, state);
    assertCurrent(operation);
    operation.phase = 'SENT';
    const response = await command<{ approvalId?: string; truthState?: string }>(body);
    assertCurrent(operation);
    await load(response.approvalId ?? originalId, operation);
    if (current(operation))
      setStatus(
        response.truthState === 'UNKNOWN'
          ? 'The resume response is unavailable. Read the stored successor before continuing.'
          : 'A fresh approval request is ready. The previous attempt remains in its history.',
      );
  }
  const isMaker =
    state?.approval?.makerSubjectRef === `urn:openpc:resource:${state?.actor.principalId}`;
  const isChecker =
    !isMaker &&
    state?.approval?.checkerSubjectRef === `urn:openpc:resource:${state?.actor.principalId}`;
  const form = transactionForms[kind];
  const prepared = state?.candidate?.deploymentIntent;
  function selectContractResource(selection: ContractCatalogueSelection) {
    if (
      !state?.actor ||
      loadingContext ||
      busy ||
      saved.approvalId ||
      !sameActor(state.actor, actorRef.current)
    )
      return;
    const fields: Record<string, string> = {};
    const labels: Record<string, { value: string; label: string }> = {};
    const assign = (field: string, value: string, label: string) => {
      fields[field] = value;
      labels[field] = { value, label };
    };
    if (kind === 'contract-binding' && selection.kind === 'contracts')
      assign('logicalContractId', selection.item.id, selection.item.label);
    else if (kind === 'contract-binding' && selection.kind === 'abis') {
      assign('abiArtifactId', selection.item.id, selection.item.label);
      assign('abiDigest', selection.item.abiDigest, 'Fingerprint from the selected imported ABI');
    } else if (kind === 'contract-method' && selection.kind === 'bindings') {
      if (selection.item.state !== 'BOUND') return;
      assign(
        'runtimeBindingId',
        selection.item.id,
        `${selection.item.networkId} · ${selection.item.contractAddress}`,
      );
      assign(
        'abiArtifactId',
        selection.item.abiArtifactId,
        'ABI attached to the selected deployed contract',
      );
      assign(
        'abiDigest',
        selection.item.abiDigest,
        'Fingerprint from the selected deployed contract',
      );
    } else return;
    setValues((previous) => ({
      ...previous,
      ...fields,
      ...(kind === 'contract-method' && previous.runtimeBindingId !== fields.runtimeBindingId
        ? { canonicalSignature: '' }
        : {}),
    }));
    setWorkspaceView('create');
    setResourceSelections((previous) => ({ ...previous, ...labels }));
    setPreview(undefined);
    save({}, state.actor);
  }
  const requestSummaryTitle =
    state?.candidate?.state === 'CONSUMED'
      ? state.operation?.state === 'SUCCEEDED' && state.operation.truthState === 'SUCCESS'
        ? 'Recorded change'
        : 'Submitted change'
      : 'Change under review';
  return (
    <section
      aria-label={
        mode === 'policy'
          ? 'Governed policy activation renewal'
          : mode === 'profiles'
            ? 'Governed runtime profile binding'
            : mode === 'runtime'
              ? 'Governed runtime activation'
              : mode === 'wallets'
                ? 'Governed wallet binding'
                : mode === 'providers'
                  ? 'Governed provider setup'
                  : mode === 'modules'
                    ? 'Governed modules and contracts'
                    : mode === 'deployment'
                      ? 'Governed deployment workflow'
                      : mode === 'evidence'
                        ? 'Governed evidence requests'
                        : 'Contract interaction workflow'
      }
      className="space-y-5"
      aria-busy={loadingContext || busy}
    >
      {showSessionControls ? (
        <LocalSessionSurface
          compactAuthenticated={mode === 'modules' || mode === 'providers' || mode === 'profiles'}
        />
      ) : null}
      {session?.authenticated && session.contextMode !== 'PARTICIPANT' ? (
        <WorkspaceStatus
          state="UNKNOWN"
          title="Choose an organization workspace"
          detail="Enter your organization's workspace to view its records and continue."
        >
          <WorkspaceEntry disabled={busy}>
            <button className={buttonClass} disabled={busy} onClick={() => void run(selectContext)}>
              Enter workspace
            </button>
          </WorkspaceEntry>
        </WorkspaceStatus>
      ) : null}
      <RequestTools collapsed={collapseRequestTools}>
        {state?.actor ? (
          <nav className="feature-navigation" aria-label="Workflow views">
            {mode === 'modules' || mode === 'profiles' ? (
              <button
                type="button"
                aria-current={workspaceView === 'library' ? 'page' : undefined}
                onClick={() => setWorkspaceView('library')}
              >
                {mode === 'profiles' ? 'Bindings' : 'Library'}
              </button>
            ) : null}
            <button
              type="button"
              aria-current={workspaceView === 'create' ? 'page' : undefined}
              onClick={() => setWorkspaceView(saved.approvalId ? 'activity' : 'create')}
            >
              Create change
            </button>
            <button
              type="button"
              aria-current={workspaceView === 'activity' ? 'page' : undefined}
              onClick={() => setWorkspaceView('activity')}
            >
              Activity
            </button>
            <button
              type="button"
              aria-current={workspaceView === 'references' ? 'page' : undefined}
              onClick={() => setWorkspaceView('references')}
            >
              Technical references
            </button>
            <button
              className="workflow-new-action"
              disabled={busy || loadingContext}
              onClick={() => {
                if (
                  busy ||
                  loadingContext ||
                  operationRef.current ||
                  changingSession.current ||
                  revalidating.current ||
                  !sameActor(state.actor, actorRef.current)
                )
                  return;
                save({}, state.actor);
                setPreview(undefined);
                if (namedChecker) {
                  setCheckerId('');
                  setCheckerSelection(undefined);
                  setChoosingChecker(false);
                }
                setApprovalInput('');
                setWorkspaceView('create');
                requestFocus.current = 'inputs';
                setState({
                  actor: state.actor,
                  ...(state.functionalTest ? { functionalTest: true } : {}),
                });
                setStatus('Enter a new request. Existing approvals remain available by ID.');
              }}
            >
              New request
            </button>
          </nav>
        ) : null}
        {state?.functionalTest && saved.approvalId && state.candidate?.state !== 'CONSUMED' ? (
          <section
            className="rounded border border-[color:var(--border)] p-4"
            aria-label="Change progress"
          >
            <h3 className="font-semibold">Your change is saved</h3>
            <p className="my-2 text-sm text-[color:var(--muted)]">
              Refresh its result or continue the same change.
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                className={buttonClass}
                disabled={busy || loadingContext}
                onClick={() => void run((operation) => load(saved.approvalId, operation))}
              >
                Refresh result
              </button>
              {saved.reviewToken ? (
                <button
                  className={`${buttonClass} workflow-primary`}
                  disabled={busy || loadingContext}
                  onClick={() => void run(applyTestChange)}
                >
                  Continue change
                </button>
              ) : null}
            </div>
          </section>
        ) : null}
        <p role="status" aria-live="polite">
          {loadingContext ? 'Loading workspace…' : status}
        </p>
        {!state?.actor ? (
          <button
            className={buttonClass}
            disabled={busy || loadingContext}
            onClick={() => void run((operation) => load(saved.approvalId, operation))}
          >
            Refresh workspace
          </button>
        ) : null}
        <div
          hidden={loadingContext}
          className={
            mode === 'modules' || mode === 'profiles'
              ? 'contract-workspace-content'
              : guidedRecovery && showApprovalCatalogue
                ? 'request-recovery-workspace'
                : undefined
          }
        >
          {state?.actor ? (
            <>
              <section
                hidden={workspaceView !== 'references'}
                className="workflow-page"
                aria-label="Workspace references"
              >
                <h2 className="text-xl font-semibold">Workspace references</h2>
                <dl className="reference-grid">
                  <dt>Participant</dt>
                  <dd>{state.actor.participantId}</dd>
                  <dt>Privacy domain</dt>
                  <dd>{state.actor.privacyDomainId}</dd>
                </dl>
              </section>
              {showApprovalCatalogue && workspaceView === 'activity' ? (
                <ApprovalCatalogue
                  actor={state.actor}
                  supportedKinds={(Object.keys(transactionForms) as TransactionKind[]).filter(
                    (value) => transactionInMode(value, mode),
                  )}
                  disabled={busy || loadingContext}
                  selectedApprovalId={state.approval?.approvalRequestId}
                  onSelect={(id) =>
                    void run(async (operation) => {
                      recoveryFocus.current = id;
                      await load(id, operation);
                    })
                  }
                />
              ) : null}
              {mode === 'profiles' && workspaceView === 'library' ? (
                <RuntimeProfileDirectory
                  actor={state.actor}
                  disabled={busy || loadingContext}
                  refreshToken={state.operation?.operationId}
                  onCreate={() => {
                    if (!sameActor(state.actor, actorRef.current) || busy || loadingContext) return;
                    setWorkspaceView('create');
                    requestFocus.current = 'inputs';
                  }}
                />
              ) : null}
              {mode === 'modules' ? (
                <section
                  className="contract-library-panel"
                  hidden={
                    workspaceView !== 'library' &&
                    !(
                      workspaceView === 'create' &&
                      !preview &&
                      !saved.approvalId &&
                      (kind === 'contract-binding' || kind === 'contract-method')
                    )
                  }
                >
                  <ContractCatalogue
                    headingLevel={2}
                    actor={loadingContext ? undefined : state.actor}
                    authorityContextKey={JSON.stringify(state.actor)}
                    refreshToken={
                      state.result
                        ? JSON.stringify([
                            state.kind,
                            state.operation?.operationId,
                            state.operation?.revision,
                            state.result.revision,
                          ])
                        : undefined
                    }
                    onSelectResource={selectContractResource}
                    creationDisabled={busy || loadingContext}
                    onCreate={(nextKind) => {
                      if (
                        busy ||
                        loadingContext ||
                        operationRef.current ||
                        changingSession.current ||
                        revalidating.current ||
                        !sameActor(state.actor, actorRef.current)
                      )
                        return;
                      save({}, state.actor);
                      setPreview(undefined);
                      setApprovalInput('');
                      setKind(nextKind);
                      setValues({});
                      setResourceSelections({});
                      setReason('');
                      setCheckerId('');
                      setCheckerSelection(undefined);
                      setChoosingChecker(false);
                      setRoleDraft(undefined);
                      setAbiFileName(undefined);
                      setState({
                        actor: state.actor,
                        ...(state.functionalTest ? { functionalTest: true } : {}),
                      });
                      setWorkspaceView('create');
                      requestFocus.current = 'inputs';
                      setStatus('');
                    }}
                    selectionKinds={
                      kind === 'contract-binding'
                        ? ['contracts', 'abis']
                        : kind === 'contract-method'
                          ? ['bindings']
                          : []
                    }
                    selectionDisabled={busy || Boolean(saved.approvalId)}
                  />
                </section>
              ) : null}
              <RequestPanel
                hidden={workspaceView !== 'create' || Boolean(saved.approvalId)}
                className="request-recovery-create"
                title={
                  guidedRecovery
                    ? 'Prepare a new request'
                    : namedChecker && preview
                      ? 'Review your request'
                      : mode === 'profiles'
                        ? 'Prepare a profile binding'
                        : mode === 'providers'
                          ? 'Prepare a provider request'
                          : mode === 'policy'
                            ? 'Renew policy activation'
                            : mode === 'cigl'
                              ? 'Prepare a contract interaction'
                              : kind.startsWith('module-')
                                ? 'Prepare a module request'
                                : 'Prepare a contract request'
                }
              >
                <ol className="workflow-stepper" aria-label="Change steps">
                  <li aria-current={!preview ? 'step' : undefined}>
                    <span>1</span>Details
                  </li>
                  <li aria-current={preview ? 'step' : undefined}>
                    <span>2</span>Review
                  </li>
                  <li>
                    <span>3</span>Result
                  </li>
                </ol>
                <h2 ref={requestHeading} tabIndex={-1} className="text-xl font-semibold">
                  {namedChecker && preview
                    ? 'Review request'
                    : namedChecker || mode === 'cigl' || mode === 'policy'
                      ? form.label
                      : 'Prepare a governed request'}
                </h2>
                <form
                  onInvalidCapture={focusFirstInvalidField}
                  hidden={namedChecker && Boolean(preview)}
                  onSubmit={(event) => {
                    event.preventDefault();
                    void run(previewRequest);
                  }}
                >
                  <fieldset disabled={busy || Boolean(saved.approvalId)} className="mt-3 space-y-3">
                    <div>
                      <label className="block" htmlFor={`${formId}-kind`}>
                        Request type
                      </label>
                      <select
                        ref={requestType}
                        id={`${formId}-kind`}
                        className={fieldClass}
                        value={kind}
                        onChange={(event) => {
                          setKind(event.target.value as TransactionKind);
                          setValues({});
                          setReason('');
                          setStatus('');
                          setRoleDraft(undefined);
                          setAbiFileName(undefined);
                          setResourceSelections({});
                          if (namedChecker) {
                            setCheckerId('');
                            setCheckerSelection(undefined);
                            setChoosingChecker(false);
                          }
                          setPreview(undefined);
                          save({}, state.actor);
                        }}
                      >
                        {(Object.entries(transactionForms) as [TransactionKind, typeof form][])
                          .filter(([id]) => transactionInMode(id, mode))
                          .map(([id, item]) => (
                            <option key={id} value={id}>
                              {item.label}
                            </option>
                          ))}
                      </select>
                    </div>
                    <p className="text-sm text-[color:var(--muted)]">{form.help}</p>
                    {contractFieldGroups(mode, kind, values).map((group, index) => (
                      <RequestFieldGroup
                        key={`${kind}:${group.title ?? index}`}
                        title={group.title}
                      >
                        {group.fields.map((field) => {
                          if (kind === 'cigl-grant' && field.name === 'definition')
                            return (
                              <InteractionGrantFields
                                key={field.name}
                                value={values.definition ?? ''}
                                onChange={(definition) => {
                                  setValues({ ...values, definition });
                                  setPreview(undefined);
                                  save({}, state.actor);
                                }}
                              />
                            );
                          if (kind === 'cigl-analysis' && field.name === 'definition')
                            return (
                              <InteractionAnalysisFields
                                key={field.name}
                                value={values.definition ?? ''}
                                onChange={(definition) => {
                                  setValues({ ...values, definition });
                                  setPreview(undefined);
                                  save({}, state.actor);
                                }}
                              />
                            );
                          if (
                            kind === 'runtime-profile-binding' &&
                            field.name === 'runtimeTargetRef'
                          )
                            return (
                              <RuntimeTargetSelect
                                key={field.name}
                                actor={state.actor}
                                value={values.runtimeTargetRef ?? ''}
                                disabled={busy || Boolean(saved.approvalId)}
                                onSelect={(target) => {
                                  if (
                                    loadingContext ||
                                    busy ||
                                    saved.approvalId ||
                                    !sameActor(state.actor, actorRef.current)
                                  )
                                    return;
                                  setValues((previous) => ({ ...previous, ...target }));
                                  setPreview(undefined);
                                  save({}, state.actor);
                                }}
                              />
                            );
                          if (kind === 'runtime-profile-binding' && field.name === 'targetRevision')
                            return (
                              <div key={field.name}>
                                <label htmlFor={`${formId}-target-revision`}>{field.label}</label>
                                <input
                                  id={`${formId}-target-revision`}
                                  className={fieldClass}
                                  readOnly
                                  required
                                  value={values.targetRevision ?? ''}
                                />
                                <p className="mt-1 text-sm text-[color:var(--muted)]">
                                  The selected target supplies its revision. Changes to the target
                                  require a new review.
                                </p>
                              </div>
                            );
                          const list =
                            kind === 'contract-method' &&
                            ['requiredRoles', 'environments'].includes(field.name)
                              ? stringArray(values[field.name])
                              : undefined;
                          if (
                            mode === 'modules' &&
                            kind === 'contract-abi' &&
                            field.name === 'abiSource'
                          )
                            return (
                              <div key={field.name}>
                                <label className="block font-medium" htmlFor={`${formId}-abi-file`}>
                                  ABI JSON file
                                </label>
                                <input
                                  id={`${formId}-abi-file`}
                                  ref={abiFileInput}
                                  hidden
                                  type="file"
                                  accept=".json,application/json"
                                  aria-describedby={`${formId}-abi-file-help`}
                                  onChange={(event) => {
                                    const file = event.target.files?.[0];
                                    event.target.value = '';
                                    if (
                                      !file ||
                                      loadingContext ||
                                      busy ||
                                      saved.approvalId ||
                                      !sameActor(state.actor, actorRef.current)
                                    )
                                      return;
                                    void run((operation) => chooseAbiFile(operation, file));
                                  }}
                                />
                                <button
                                  type="button"
                                  className={`${buttonClass} mt-2`}
                                  aria-describedby={`${formId}-abi-file-help`}
                                  onClick={() => abiFileInput.current?.click()}
                                >
                                  {abiFileName && values.abiSource
                                    ? 'Replace ABI file'
                                    : 'Choose ABI file'}
                                </button>
                                <p
                                  id={`${formId}-abi-file-help`}
                                  className="mt-2 text-sm text-[color:var(--muted)]"
                                >
                                  Select an ABI array exported as JSON, up to 256 KB. The file stays
                                  in this browser until you review the request.
                                </p>
                                {abiFileName && values.abiSource ? (
                                  <p className="mt-2 break-all text-sm font-medium">
                                    Selected artifact: {abiFileName}
                                  </p>
                                ) : null}
                                <SecondaryPanel title="Paste or inspect the original ABI">
                                  <label className="block" htmlFor={`${formId}-${field.name}`}>
                                    {field.label}
                                  </label>
                                  <textarea
                                    id={`${formId}-${field.name}`}
                                    className={`${fieldClass} font-mono text-sm`}
                                    rows={8}
                                    required
                                    value={values.abiSource ?? ''}

                                    onChange={(event) => {
                                      setValues({ ...values, abiSource: event.target.value });
                                      setAbiFileName(undefined);
                                      setPreview(undefined);
                                      save({}, state.actor);
                                    }}
                                    spellCheck={false}
                                  />
                                </SecondaryPanel>
                              </div>
                            );
                          if (
                            mode === 'modules' &&
                            kind === 'contract-method' &&
                            field.name === 'canonicalSignature'
                          )
                            return (
                              <div key={field.name}>
                                <ContractMethodSelect
                                  actor={state.actor}
                                  bindingId={values.runtimeBindingId}
                                  abiArtifactId={values.abiArtifactId}
                                  abiDigest={values.abiDigest}
                                  value={values.canonicalSignature ?? ''}
                                  disabled={busy || Boolean(saved.approvalId)}
                                  onSelect={(method) => {
                                    if (
                                      loadingContext ||
                                      busy ||
                                      saved.approvalId ||
                                      !sameActor(state.actor, actorRef.current)
                                    )
                                      return;
                                    setValues((previous) => ({
                                      ...previous,
                                      canonicalSignature: method.signature,
                                      effect: method.effect,
                                    }));
                                    setPreview(undefined);
                                    save({}, state.actor);
                                  }}
                                />
                                <SecondaryPanel title="Enter or inspect the method signature">
                                  <label className="mt-2 block" htmlFor={`${formId}-${field.name}`}>
                                    {field.label}
                                  </label>
                                  <input
                                    id={`${formId}-${field.name}`}
                                    className={fieldClass}
                                    value={values.canonicalSignature ?? ''}
                                    required

                                    onChange={(event) => {
                                      setValues({
                                        ...values,
                                        canonicalSignature: event.target.value,
                                      });
                                      setPreview(undefined);
                                      save({}, state.actor);
                                    }}
                                  />
                                </SecondaryPanel>
                              </div>
                            );
                          if (
                            kind === 'contract-method' &&
                            field.name === 'requiredRoles' &&
                            list &&
                            list.every(
                              (role) =>
                                role.length > 0 && role === role.trim() && !/[\r\n]/u.test(role),
                            )
                          )
                            return (
                              <div key={field.name}>
                                {mode === 'modules' ? (
                                  <ContractRoleSelect
                                    actor={state.actor}
                                    selected={list}
                                    disabled={busy || Boolean(saved.approvalId)}
                                    onChange={(roles) => {
                                      if (
                                        loadingContext ||
                                        busy ||
                                        saved.approvalId ||
                                        !sameActor(state.actor, actorRef.current)
                                      )
                                        return;
                                      setRoleDraft(undefined);
                                      setValues({
                                        ...values,
                                        requiredRoles: JSON.stringify(roles),
                                      });
                                      setPreview(undefined);
                                      save({}, state.actor);
                                    }}
                                  />
                                ) : null}
                                <SecondaryPanel title="Enter or inspect role references">
                                  <label className="block" htmlFor={`${formId}-${field.name}`}>
                                    Required roles
                                  </label>
                                  <textarea
                                    id={`${formId}-${field.name}`}
                                    aria-describedby={`${formId}-roles-help`}
                                    className={fieldClass}
                                    rows={3}
                                    required

                                    value={roleDraft ?? list.join('\n')}
                                    onChange={(event) => {
                                      const text = event.target.value;
                                      setRoleDraft(text);
                                      setValues({
                                        ...values,
                                        requiredRoles: JSON.stringify(
                                          text
                                            .split(/\r?\n/u)
                                            .map((role) => role.trim())
                                            .filter(Boolean),
                                        ),
                                      });
                                      setPreview(undefined);
                                      save({}, state.actor);
                                    }}
                                    spellCheck={false}
                                  />
                                  <p
                                    id={`${formId}-roles-help`}
                                    className="text-sm text-[color:var(--muted)]"
                                  >
                                    Enter one exact role name or reference per line. Values are
                                    case-sensitive. Role assignments and execution permissions are
                                    reviewed separately.
                                  </p>
                                </SecondaryPanel>
                              </div>
                            );
                          if (
                            kind === 'contract-method' &&
                            field.name === 'environments' &&
                            list &&
                            list.every((value) => methodEnvironments.some((item) => item === value))
                          )
                            return (
                              <fieldset
                                key={field.name}
                                aria-describedby={`${formId}-environments-help`}
                              >
                                <legend className="font-medium">Allowed environments</legend>
                                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                                  {methodEnvironments.map((environment, index) => (
                                    <label
                                      key={environment}
                                      className="flex min-h-11 items-center gap-2 rounded border border-[color:var(--border)] px-3 py-2"
                                    >
                                      <input
                                        type="checkbox"
                                        checked={list.includes(environment)}
                                        required={list.length === 0 && index === 0}
                                        onChange={(event) => {
                                          setValues({
                                            ...values,
                                            environments: JSON.stringify(
                                              event.target.checked
                                                ? [...list, environment]
                                                : list.filter((item) => item !== environment),
                                            ),
                                          });
                                          setPreview(undefined);
                                          save({}, state.actor);
                                        }}
                                      />
                                      {environment[0] + environment.slice(1).toLowerCase()}
                                    </label>
                                  ))}
                                </div>
                                <p
                                  id={`${formId}-environments-help`}
                                  className="mt-2 text-sm text-[color:var(--muted)]"
                                >
                                  Select at least one environment. No environment is selected for a
                                  new request.
                                </p>
                              </fieldset>
                            );
                          const referenceField =
                            mode === 'modules' &&
                            [
                              'logicalContractId',
                              'runtimeBindingId',
                              'abiArtifactId',
                              'abiDigest',
                            ].includes(field.name);
                          const selection = resourceSelections[field.name];
                          const selected =
                            selection?.value === values[field.name] ? selection : undefined;
                          if (referenceField)
                            return (
                              <div
                                key={field.name}
                                className="min-w-0 rounded-lg border border-[color:var(--border)] p-3"
                              >
                                <p className="font-medium">
                                  {
                                    {
                                      logicalContractId: 'Contract',
                                      runtimeBindingId: 'Deployed contract',
                                      abiArtifactId: 'Imported ABI',
                                      abiDigest: 'ABI fingerprint',
                                    }[field.name]
                                  }
                                </p>
                                <p className="mt-1 break-all text-sm">
                                  {selected?.label ??
                                    (values[field.name]
                                      ? 'Resource entered by reference'
                                      : 'Choose a resource from the contract library.')}
                                </p>
                                <SecondaryPanel title="Enter or inspect the resource reference">
                                  <label className="block" htmlFor={`${formId}-${field.name}`}>
                                    {field.label}
                                  </label>
                                  <input
                                    id={`${formId}-${field.name}`}
                                    className={`${fieldClass} font-mono text-sm`}
                                    value={values[field.name] ?? ''}
                                    onChange={(event) => {
                                      setValues({ ...values, [field.name]: event.target.value });
                                      setPreview(undefined);
                                      save({}, state.actor);
                                    }}
                                  />
                                </SecondaryPanel>
                              </div>
                            );
                          if (
                            guidedRecovery &&
                            mode === 'evidence' &&
                            initialKind === 'protected-proof-access' &&
                            initialFields?.objectRef &&
                            kind === 'protected-proof-access'
                          ) {
                            if (field.name === 'objectRef')
                              return (
                                <WorkflowDetails
                                  key={field.name}
                                  enabled
                                  summary="Selected proof reference"
                                >
                                  <label className="block" htmlFor={`${formId}-${field.name}`}>
                                    {field.label}
                                  </label>
                                  <input
                                    id={`${formId}-${field.name}`}
                                    className={fieldClass}
                                    readOnly
                                    value={values.objectRef ?? ''}
                                  />
                                </WorkflowDetails>
                              );
                            if (field.name === 'expiresAt')
                              return (
                                <div key={field.name}>
                                  <label className="block" htmlFor={`${formId}-${field.name}`}>
                                    {field.label}
                                  </label>
                                  <input
                                    id={`${formId}-${field.name}`}
                                    className={fieldClass}
                                    required
                                    type="datetime-local"
                                    step="0.001"
                                    value={(values.expiresAt ?? '').slice(0, 23)}
                                    onChange={(event) => {
                                      setValues({
                                        ...values,
                                        expiresAt: protectedUtcInput(event.target.value),
                                      });
                                      setPreview(undefined);
                                      save({}, state.actor);
                                    }}
                                  />
                                  <p className="text-sm text-[color:var(--muted)]">
                                    Enter the UTC deadline for this access. The exact expiry is
                                    sealed with its purpose and case for review.
                                  </p>
                                </div>
                              );
                          }
                          return (
                            <div
                              key={field.name}
                              className={field.json ? 'workflow-definition-field' : undefined}
                            >
                              <label className="block" htmlFor={`${formId}-${field.name}`}>
                                {field.label}
                                {field.optional ? ' (optional)' : ''}
                              </label>
                              {field.choices ? (
                                <select
                                  id={`${formId}-${field.name}`}
                                  className={fieldClass}
                                  required={!field.optional}
                                  value={values[field.name] ?? ''}
                                  onChange={(event) => {
                                    setValues({ ...values, [field.name]: event.target.value });
                                    setPreview(undefined);
                                    save({}, state.actor);
                                  }}
                                >
                                  <option value="">Select…</option>
                                  {field.choices.map((choice) => (
                                    <option key={choice} value={choice}>
                                      {kind === 'contract-abi' && field.name === 'source'
                                        ? ((
                                            {
                                              LOCAL_FIXTURE: 'Local artifact',
                                              SOURCE_REPOSITORY: 'Source repository',
                                              AUTHENTICATED_REGISTRY: 'Authenticated registry',
                                            } as Record<string, string>
                                          )[choice] ?? choice)
                                        : kind === 'contract-method'
                                          ? (methodChoiceLabels[field.name]?.[choice] ?? choice)
                                          : (operationChoiceLabels[field.name]?.[choice] ?? choice)}
                                    </option>
                                  ))}
                                </select>
                              ) : field.json || field.multiline ? (
                                <textarea
                                  id={`${formId}-${field.name}`}
                                  aria-describedby={
                                    field.json ? `${formId}-${field.name}-help` : undefined
                                  }
                                  className={`${fieldClass} font-mono text-sm`}
                                  rows={field.json ? 8 : 4}
                                  required={!field.optional}
                                  value={values[field.name] ?? ''}
                                  onChange={(event) => {
                                    setValues({ ...values, [field.name]: event.target.value });
                                    setPreview(undefined);
                                    save({}, state.actor);
                                  }}
                                  spellCheck={false}
                                />
                              ) : (
                                <input
                                  id={`${formId}-${field.name}`}
                                  className={fieldClass}
                                  required={!field.optional}
                                  value={values[field.name] ?? ''}
                                  onChange={(event) => {
                                    setValues({ ...values, [field.name]: event.target.value });
                                    setPreview(undefined);
                                    save({}, state.actor);
                                  }}
                                />
                              )}
                              {field.json ? (
                                <span
                                  id={`${formId}-${field.name}-help`}
                                  className="text-sm text-[color:var(--muted)]"
                                >
                                  Enter the exact JSON definition for review.
                                </span>
                              ) : null}
                            </div>
                          );
                        })}
                      </RequestFieldGroup>
                    ))}
                    <div>
                      <label className="block" htmlFor={`${formId}-reason`}>
                        Reason
                      </label>
                      <textarea
                        id={`${formId}-reason`}
                        className={fieldClass}
                        required
                        maxLength={1024}
                        value={reason}
                        onChange={(event) => {
                          setReason(event.target.value);
                          setPreview(undefined);
                          save({}, state.actor);
                        }}
                      />
                    </div>
                    <RecoveryControls
                      collapsed={compactReview || collapseRecoveryControls}
                      resolved={JSON.stringify(state.actor)}
                    >
                      <label className="block" htmlFor={`${formId}-original-proposal-key`}>
                        Original proposal key, for unchanged request recovery
                      </label>
                      <input
                        id={`${formId}-original-proposal-key`}
                        className={fieldClass}
                        value={originalRequestKey}
                        onChange={(event) => {
                          setOriginalRequestKey(event.target.value);
                          setPreview(undefined);
                          save({}, state.actor);
                        }}
                        aria-describedby={`${formId}-original-proposal-help`}
                      />
                      <p id={`${formId}-original-proposal-help`}>
                        Leave empty for a new intent. Recovery must use the original key and
                        unchanged business inputs; a reservation correction does not create another
                        proposal.
                      </p>
                      <label className="block" htmlFor={`${formId}-reserved-approval`}>
                        Reserved approval operation ID
                      </label>
                      <input
                        id={`${formId}-reserved-approval`}
                        className={fieldClass}
                        value={reservedApprovalId}
                        onChange={(event) => {
                          setReservedApprovalId(event.target.value);
                        }}
                      />
                    </RecoveryControls>
                    <button className={`${buttonClass} workflow-primary`} type="submit">
                      Review request
                    </button>
                  </fieldset>
                </form>
                {preview ? (
                  <>
                    {namedChecker ? (
                      <div className="contract-review-actions">
                        <p>{form.label}</p>
                        <button
                          className={buttonClass}
                          type="button"
                          disabled={busy || Boolean(saved.approvalId)}
                          onClick={() => {
                            if (operationRef.current || !sameActor(state.actor, actorRef.current))
                              return;
                            requestFocus.current = 'inputs';
                            setPreview(undefined);
                            save({}, state.actor);
                            setCheckerId('');
                            setCheckerSelection(undefined);
                            setChoosingChecker(false);
                            setStatus('Edit the request, then review the updated inputs.');
                          }}
                        >
                          Edit request
                        </button>
                      </div>
                    ) : null}
                    {namedChecker ? (
                      <>
                        {mode === 'profiles' ? (
                          <RuntimeProfileSummary
                            value={preview.candidate}
                            title="Review this binding"
                            review
                          />
                        ) : mode === 'providers' ? (
                          <ProviderRecordSummary
                            value={preview.candidate}
                            title="Review this change"
                            review
                          />
                        ) : preview.kind.startsWith('module-') ? (
                          <ModuleRecordSummary
                            kind={preview.kind}
                            value={preview.candidate}
                            title="Review this change"
                            review
                          />
                        ) : (
                          <ContractRecordSummary
                            kind={preview.kind}
                            value={preview.candidate}
                            title="Review this change"
                            review
                          />
                        )}
                        <SecondaryPanel title="Request fingerprint">
                          <p className="break-all">Candidate digest: {preview.candidateDigest}</p>
                        </SecondaryPanel>
                      </>
                    ) : (
                      <p className="mt-3 break-all">Candidate digest: {preview.candidateDigest}</p>
                    )}
                    {preview.factRetirement ? (
                      <FactRetirementReview value={preview.factRetirement} />
                    ) : null}
                    <Document label="Request preview" value={preview.candidate} />
                    {preview.redactedFields.length ? (
                      <Document
                        label="Signed material fingerprints"
                        value={preview.redactedFields}
                      />
                    ) : null}
                  </>
                ) : null}
                {state?.functionalTest &&
                saved.reviewToken &&
                !saved.approvalId &&
                state.candidate?.state !== 'CONSUMED' ? (
                  <button
                    className={`${buttonClass} workflow-primary mt-3`}
                    disabled={busy}
                    onClick={() => void run(applyTestChange)}
                  >
                    Apply change
                  </button>
                ) : null}
                {!state?.functionalTest && saved.reviewToken && !saved.approvalId ? (
                  <div className="mt-3 space-y-3">
                    {namedChecker ? (
                      <>
                        <h3 className="font-semibold">Independent review</h3>
                        <p className="text-sm text-[color:var(--muted)]">
                          Choose a reviewer for these exact inputs. Their authority is checked when
                          the approval request is submitted.
                        </p>
                        {checkerId ? (
                          <p>
                            Selected checker:{' '}
                            {checkerSelection?.id === checkerId
                              ? checkerSelection.displayLabel
                              : 'Checker entered by reference'}
                          </p>
                        ) : null}
                        <button
                          ref={checkerChoiceButton}
                          className={buttonClass}
                          type="button"
                          disabled={busy}
                          onClick={() => setChoosingChecker((previous) => !previous)}
                          aria-expanded={choosingChecker}
                        >
                          {choosingChecker ? 'Close checker choices' : 'Choose checker'}
                        </button>
                        {choosingChecker ? (
                          <>
                            <label className="grid gap-1" htmlFor={`${formId}-checker-kind`}>
                              Checker account type
                              <select
                                id={`${formId}-checker-kind`}
                                className={fieldClass}
                                value={checkerKind}
                                disabled={busy || loadingContext}
                                onChange={(event) => {
                                  if (
                                    busy ||
                                    loadingContext ||
                                    saved.approvalId ||
                                    changingSession.current ||
                                    revalidating.current ||
                                    !sameActor(state.actor, actorRef.current)
                                  )
                                    return;
                                  const value = event.target.value;
                                  if (
                                    value === checkerKind ||
                                    (value !== 'USER' && value !== 'PLATFORM_OPERATOR')
                                  )
                                    return;
                                  setCheckerId('');
                                  setCheckerSelection(undefined);
                                  setCheckerKind(value);
                                }}
                              >
                                <option value="USER">Participant user</option>
                                <option value="PLATFORM_OPERATOR">Platform operator</option>
                              </select>
                            </label>
                            <PrincipalCatalogue
                              key={JSON.stringify([state.actor, checkerKind])}
                              actor={state.actor}
                              selection={{
                                kind: checkerKind,
                                excludedPrincipalId: state.actor.principalId,
                                disabled: busy,
                                onSelect(id, displayLabel) {
                                  if (
                                    loadingContext ||
                                    busy ||
                                    saved.approvalId ||
                                    changingSession.current ||
                                    revalidating.current ||
                                    !sameActor(state.actor, actorRef.current) ||
                                    !uuid.test(id) ||
                                    id === state.actor.principalId
                                  )
                                    return;
                                  setCheckerId(id);
                                  setCheckerSelection({ id, displayLabel });
                                  setChoosingChecker(false);
                                  checkerChoiceButton.current?.focus();
                                },
                              }}
                            />
                          </>
                        ) : null}
                      </>
                    ) : null}
                    <SecondaryPanel title="Enter or inspect the checker reference">
                      <div>
                        <label className="block" htmlFor={`${formId}-checker`}>
                          Independent checker principal ID
                        </label>
                        <input
                          id={`${formId}-checker`}
                          className={fieldClass}
                          value={checkerId}
                          onChange={(event) => {
                            setCheckerId(event.target.value);
                            setCheckerSelection(undefined);
                          }}
                        />
                      </div>
                    </SecondaryPanel>
                    <button
                      className={`${buttonClass} workflow-primary`}
                      disabled={busy || (namedChecker && !uuid.test(checkerId))}
                      onClick={() => void run(requestApproval)}
                    >
                      Request approval
                    </button>
                  </div>
                ) : null}
              </RequestPanel>
              <RequestPanel
                hidden={workspaceView !== 'activity'}
                className="request-recovery-review"
                title="Approvals and results"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h2 ref={recoveryHeading} tabIndex={-1} className="text-xl font-semibold">
                    {guidedRecovery ? 'Selected request' : 'Change details'}
                  </h2>
                  {state.approval ? (
                    <button
                      className={buttonClass}
                      type="button"
                      disabled={busy || loadingContext}
                      onClick={() =>
                        void run((operation) =>
                          load(state.approval!.approvalRequestId.slice(-36), operation),
                        )
                      }
                    >
                      Refresh details
                    </button>
                  ) : null}
                </div>
                {guidedRecovery ? (
                  state.approval ? (
                    <div className="request-recovery-selection">
                      <p className="font-semibold">
                        {state.kind ? transactionForms[state.kind].label : 'Governed request'}
                      </p>
                      <p>Ref …{state.approval.approvalRequestId.slice(-12)}</p>
                      {state.candidate?.state === 'CONSUMED' ? (
                        <p>This approval has been used. Its command cannot be executed again.</p>
                      ) : null}
                    </div>
                  ) : (
                    <p className="request-recovery-empty">
                      Choose a request to review its approval, recorded outcome and available
                      actions.
                    </p>
                  )
                ) : null}
                <RecoveryControls
                  collapsed={compactReview}
                  resolved={state.approval?.approvalRequestId}
                >
                  <div className="mt-3">
                    <label className="block" htmlFor={`${formId}-approval`}>
                      Approval ID
                    </label>
                    <input
                      id={`${formId}-approval`}
                      className={fieldClass}
                      value={approvalInput}
                      disabled={busy || loadingContext}
                      onChange={(event) => setApprovalInput(event.target.value)}
                    />
                  </div>
                  <button
                    className={`${buttonClass} mt-3`}
                    disabled={busy || loadingContext || !uuid.test(approvalInput)}
                    onClick={() => void run((operation) => load(approvalInput, operation))}
                  >
                    Read approval and result
                  </button>
                </RecoveryControls>
                {state.approval && state.candidate ? (
                  <>
                    {state.factRetirement ? (
                      <FactRetirementReview value={state.factRetirement} />
                    ) : null}
                    {namedChecker ? (
                      <>
                        {mode === 'profiles' ? (
                          <RuntimeProfileSummary
                            value={state.candidate.candidate}
                            title={requestSummaryTitle}
                            review
                          />
                        ) : mode === 'providers' ? (
                          <ProviderRecordSummary
                            value={state.candidate.candidate}
                            title={requestSummaryTitle}
                            review
                          />
                        ) : (state.kind ?? kind).startsWith('module-') ? (
                          <ModuleRecordSummary
                            kind={state.kind ?? kind}
                            value={state.candidate.candidate}
                            title={requestSummaryTitle}
                            review
                          />
                        ) : (
                          <ContractRecordSummary
                            kind={state.kind ?? kind}
                            value={state.candidate.candidate}
                            title={requestSummaryTitle}
                            review
                          />
                        )}
                        <dl className="contract-request-status">
                          <div>
                            <dt>Approval status</dt>
                            <dd>{recordStateLabel(state.approval.state)}</dd>
                          </div>
                          <div>
                            <dt>Request status</dt>
                            <dd>{recordStateLabel(state.candidate.state)}</dd>
                          </div>
                          <div>
                            <dt>Request expires</dt>
                            <dd>
                              {typeof state.candidate.expiresAt === 'string' &&
                              Number.isFinite(Date.parse(state.candidate.expiresAt)) ? (
                                <time dateTime={state.candidate.expiresAt}>
                                  {approvalTime(state.candidate.expiresAt)}
                                </time>
                              ) : (
                                'Not available'
                              )}
                            </dd>
                          </div>
                        </dl>
                        <SecondaryPanel title="Approval and request references">
                          <dl>
                            <dt>Approval reference</dt>
                            <dd>{state.approval.approvalRequestId}</dd>
                            <dt>Resource</dt>
                            <dd>{state.candidate.resourceRef}</dd>
                            <dt>Candidate digest</dt>
                            <dd>{state.candidate.candidateDigest}</dd>
                            <dt>Original operation</dt>
                            <dd>{state.candidate.operationRef ?? 'No committed operation'}</dd>
                          </dl>
                        </SecondaryPanel>
                      </>
                    ) : (
                      <>
                        {guidedRecovery ? (
                          <p className="mt-3 font-semibold">
                            Approval:{' '}
                            {approvalStateLabels[
                              state.approval.state as keyof typeof approvalStateLabels
                            ] ?? 'Unconfirmed'}
                          </p>
                        ) : null}
                        <WorkflowDetails enabled={guidedRecovery} summary="Request audit details">
                          <dl className="mt-3 grid gap-2 break-all sm:grid-cols-[12rem_1fr]">
                            <dt>Approval</dt>
                            <dd>{state.approval.state}</dd>
                            <dt>Candidate</dt>
                            <dd>{state.candidate.state}</dd>
                            <dt>Resource</dt>
                            <dd>{state.candidate.resourceRef}</dd>
                            <dt>Candidate digest</dt>
                            <dd>{state.candidate.candidateDigest}</dd>
                            <dt>Original operation</dt>
                            <dd>{state.candidate.operationRef ?? 'No committed operation'}</dd>
                          </dl>
                        </WorkflowDetails>
                      </>
                    )}
                    {prepared ? (
                      <div aria-label="Prepared deployment details" className="mt-3">
                        <h3 className="font-semibold">Referenced prepared deployment</h3>
                        <dl className="grid gap-2 break-all sm:grid-cols-[12rem_1fr]">
                          {(
                            [
                              'state',
                              'sender',
                              'chainId',
                              'nonce',
                              'gasLimit',
                              'expectedContractAddress',
                              'signingHash',
                            ] as const
                          ).map((field) => (
                            <div key={field} className="contents">
                              <dt>{field}</dt>
                              <dd>{prepared[field] ?? 'Not derived'}</dd>
                            </div>
                          ))}
                        </dl>
                        <p className="mt-2 text-sm">
                          Submission still verifies the signed transaction against this intent and
                          current authority.
                        </p>
                      </div>
                    ) : null}
                    {state.candidate.approvalUsable === false &&
                    state.candidate.state !== 'CONSUMED' ? (
                      <p>
                        {state.approval.state === 'REQUESTED'
                          ? 'Waiting for independent approval. Execution also requires current authentication.'
                          : 'Approval is not currently usable. Execution requires a current approval and fresh authentication.'}
                      </p>
                    ) : null}
                    {state.candidate.attempt && !guidedRecovery ? (
                      <p>Approval attempt {state.candidate.attempt}</p>
                    ) : null}
                    {isMaker &&
                    state.candidate.makerSessionMatches === false &&
                    state.candidate.state !== 'CONSUMED' ? (
                      <p>
                        This request was prepared in a different sign-in session. It cannot execute
                        in this session. Request fresh approval when recovery becomes available; the
                        existing approval cannot be replaced while it is still fresh.
                      </p>
                    ) : null}
                    {state.candidate.predecessorApprovalRef ? (
                      <button
                        className={buttonClass}
                        disabled={busy}
                        onClick={() =>
                          void run((operation) =>
                            load(state.candidate!.predecessorApprovalRef!.slice(-36), operation),
                          )
                        }
                      >
                        Read previous attempt
                      </button>
                    ) : null}
                    {state.candidate.successorApprovalRef ? (
                      <button
                        className={buttonClass}
                        disabled={busy}
                        onClick={() =>
                          void run((operation) =>
                            load(state.candidate!.successorApprovalRef!.slice(-36), operation),
                          )
                        }
                      >
                        Read resumed request
                      </button>
                    ) : null}
                    <Document label="Stored candidate details" value={state.candidate.candidate} />
                    {state.evidenceSelection ? (
                      <Document label="Selected evidence records" value={state.evidenceSelection} />
                    ) : null}
                    {state.candidate.redactedFields.length ? (
                      <Document
                        label="Stored signed material fingerprints"
                        value={state.candidate.redactedFields}
                      />
                    ) : null}
                    <div className="flex flex-wrap gap-3">
                      {isMaker && state.candidate.canRequestResume ? (
                        <button
                          className={buttonClass}
                          disabled={busy}
                          onClick={() => void run(resumeRequest)}
                        >
                          Request fresh approval
                        </button>
                      ) : null}
                      {isChecker && !(guidedRecovery && state.candidate.state === 'CONSUMED') ? (
                        <button
                          className={buttonClass}
                          disabled={busy || !state.stepUp}
                          onClick={() => void run((operation) => act(operation, 'APPROVE'))}
                        >
                          Approve with security key
                        </button>
                      ) : null}
                      {isMaker && !(guidedRecovery && state.candidate.state === 'CONSUMED') ? (
                        <button
                          className={buttonClass}
                          disabled={busy || !state.stepUp || !saved.reviewToken}
                          onClick={() => void run((operation) => act(operation, 'EXECUTE'))}
                        >
                          Execute approved request
                        </button>
                      ) : null}
                    </div>
                    {state.resultUnavailable ? (
                      <p role="alert">
                        The command is recorded, but its current result is unavailable. Refresh
                        readback; do not create a replacement transaction.
                      </p>
                    ) : null}
                  </>
                ) : null}
                {state.operation ? (
                  <WorkflowDetails enabled={guidedRecovery} summary="Command admission record">
                    <p className="mt-3 font-semibold">
                      {state.kind === 'evidence-deletion-fact' ||
                      state.kind === 'evidence-deletion-candidate'
                        ? 'Admission operation'
                        : 'Operation state'}
                      :{' '}
                      {compactReview
                        ? recordStateLabel(state.operation.state)
                        : state.operation.state}{' '}
                      ·{' '}
                      {state.kind === 'evidence-deletion-fact' ||
                      state.kind === 'evidence-deletion-candidate'
                        ? 'Admission result'
                        : 'Effect'}
                      :{' '}
                      {compactReview
                        ? recordStateLabel(state.operation.truthState)
                        : state.operation.truthState}
                    </p>
                  </WorkflowDetails>
                ) : null}
                {state.operationUnavailable ? (
                  <p role="alert">
                    The original operation is recorded, but its current state is unavailable.
                    Refresh readback before taking another action.
                  </p>
                ) : null}
                {state.result ? (
                  <>
                    {mode === 'profiles' ? (
                      <RuntimeProfileSummary value={state.result} title="Recorded binding" />
                    ) : mode === 'providers' ? (
                      <ProviderRecordSummary value={state.result} title="Recorded outcome" />
                    ) : (state.kind ?? kind).startsWith('module-') ? (
                      <ModuleRecordSummary
                        kind={state.kind ?? kind}
                        value={state.result}
                        title="Recorded outcome"
                      />
                    ) : mode === 'modules' ? (
                      <ContractRecordSummary
                        kind={state.kind ?? kind}
                        value={state.result}
                        title="Recorded outcome"
                      />
                    ) : guidedRecovery || mode === 'wallets' ? (
                      <RequestOutcome
                        kind={state.kind}
                        value={state.result}
                        actor={state.actor}
                        resourceRef={state.candidate?.resourceRef}
                        operationRef={state.candidate?.operationRef}
                      />
                    ) : (
                      <p className="mt-3 font-semibold">
                        Result state:{' '}
                        {String(state.result.admissionState ?? state.result.state ?? 'Available')} ·
                        Effect:{' '}
                        {String(
                          state.result.physicalState ??
                            state.result.truthState ??
                            state.result.runtimePermission ??
                            state.result.authority ??
                            'See details',
                        )}
                      </p>
                    )}
                    {state.kind?.startsWith('contract-') ? (
                      <>
                        <p>
                          Registration alone grants no runtime permission. Use requires an approved
                          active policy and a matching installed runtime generation.
                        </p>
                        <SecondaryPanel title="Registration provenance">
                          <p>
                            {state.result.policyGenerationDigest === null
                              ? 'This record was created before the first policy generation. Its creation provenance remains absent.'
                              : 'The recorded policy digest is historical registration provenance.'}
                          </p>
                        </SecondaryPanel>
                      </>
                    ) : null}
                    <Document label="Authoritative result" value={state.result} />
                  </>
                ) : null}
              </RequestPanel>
              <RequestPanel
                hidden={workspaceView !== 'references'}
                className="request-recovery-resource"
                title="Look up a resource by reference"
              >
                <h2 className="text-xl font-semibold">Read an existing resource</h2>
                <p className="text-sm">
                  Choose the resource type and enter its reference to inspect the current record.
                </p>
                <label className="block mt-3" htmlFor={`${formId}-lookup-kind`}>
                  Resource type
                </label>
                <select
                  id={`${formId}-lookup-kind`}
                  className={fieldClass}
                  disabled={busy || Boolean(saved.approvalId)}
                  value={kind}
                  onChange={(event) => {
                    setKind(event.target.value as TransactionKind);
                    setResourceInput('');
                  }}
                >
                  {(Object.entries(transactionForms) as [TransactionKind, typeof form][])
                    .filter(([id]) => transactionInMode(id, mode))
                    .map(([id, item]) => (
                      <option key={id} value={id}>
                        {item.label}
                      </option>
                    ))}
                </select>
                <div className="mt-3">
                  <label className="block" htmlFor={`${formId}-resource`}>
                    Resource ID
                  </label>
                  <input
                    id={`${formId}-resource`}
                    className={fieldClass}
                    value={resourceInput}
                    onChange={(event) => setResourceInput(event.target.value)}
                  />
                </div>
                <button
                  className={`${buttonClass} mt-3`}
                  disabled={busy || !uuid.test(resourceInput)}
                  onClick={() =>
                    void run(async (operation) => {
                      const next = await readCurrent<State>(
                        operation,
                        `${endpoint}?${new URLSearchParams({ kind, resourceId: resourceInput })}`,
                      );
                      if (JSON.stringify(next.actor) !== JSON.stringify(actorRef.current))
                        throw new WorkflowFailure('context');
                      setState(next);
                      setWorkspaceView('activity');
                    })
                  }
                >
                  Read resource
                </button>
              </RequestPanel>
            </>
          ) : null}
        </div>
      </RequestTools>
    </section>
  );
}
