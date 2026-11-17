export const policySetDraftStorageKey = 'openpc:policy-set-draft:v1';
export const policyAuthorStorageKey = 'openpc:policy-author-workflow:v2';
export const policyReleaseStorageKey = 'openpc:policy-release-workflow:v2';
export const transactionWorkflowPrivacyEvent = 'openpc:transaction-custody-cleared';
export const transactionWorkflowPrivacyStorageKey = 'openpc:transaction-custody-clear:v1';

let privacyRevision = 0;
export function policyWorkflowPrivacyRevision(): number {
  return privacyRevision;
}

export interface PolicyWorkflowActorBinding {
  readonly sessionId: string;
  readonly principalId: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly contextEpoch: string;
}

interface BoundValue<T> {
  readonly actor: PolicyWorkflowActorBinding;
  readonly value: T;
}

function actorMatches(
  left: PolicyWorkflowActorBinding,
  right: PolicyWorkflowActorBinding,
): boolean {
  return (
    left.sessionId === right.sessionId &&
    left.principalId === right.principalId &&
    left.participantId === right.participantId &&
    left.privacyDomainId === right.privacyDomainId &&
    left.contextEpoch === right.contextEpoch
  );
}

function actorShape(value: unknown): value is PolicyWorkflowActorBinding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actor = value as Record<string, unknown>;
  return ['sessionId', 'principalId', 'participantId', 'privacyDomainId', 'contextEpoch'].every(
    (field) => typeof actor[field] === 'string' && actor[field].length > 0,
  );
}

function remove(key: string): void {
  if (key === policyAuthorStorageKey) privacyRevision += 1;
  try {
    globalThis.localStorage?.removeItem(key);
  } catch {
    // Browser storage is optional; authoritative server readback remains usable.
  }
}

export function readBoundPolicyState<T>(
  key: string,
  actor: PolicyWorkflowActorBinding,
  valid: (value: unknown) => value is T,
): T | undefined {
  try {
    const raw = globalThis.localStorage?.getItem(key);
    if (!raw) return undefined;
    const parsed = JSON.parse(raw) as Partial<BoundValue<unknown>>;
    if (!actorShape(parsed.actor) || !actorMatches(parsed.actor, actor) || !valid(parsed.value)) {
      remove(key);
      return undefined;
    }
    return parsed.value;
  } catch {
    remove(key);
    return undefined;
  }
}

export function writeBoundPolicyState<T>(
  key: string,
  actor: PolicyWorkflowActorBinding,
  value: T,
): void {
  try {
    globalThis.localStorage?.setItem(key, JSON.stringify({ actor, value }));
  } catch {
    // Persistence must never turn an accepted owner mutation into a UI failure.
  }
}

export function clearBoundPolicyState(key: string): void {
  remove(key);
}

export function clearTransactionWorkflowStorage(): void {
  try {
    const storage = globalThis.localStorage;
    if (!storage) return;
    const keys = Array.from({ length: storage.length }, (_, index) => storage.key(index));
    for (const key of keys) {
      if (key?.startsWith('openpc:transaction-workbench:v1:')) remove(key);
    }
    storage.setItem(transactionWorkflowPrivacyStorageKey, crypto.randomUUID());
  } catch {
    // A blocked browser cache must not prevent native session readback.
  } finally {
    if (typeof window !== 'undefined')
      window.dispatchEvent(new Event(transactionWorkflowPrivacyEvent));
  }
}

export function clearPolicyWorkflowStorage(): void {
  remove(policyAuthorStorageKey);
  remove(policyReleaseStorageKey);
  remove(policySetDraftStorageKey);
  // Remove the unscoped pre-acceptance keys so they cannot be restored by an
  // older cached page after logout or an actor/context transition.
  remove('openpc:policy-author-workflow:v1');
  remove('openpc:policy-release-workflow:v1');
}
