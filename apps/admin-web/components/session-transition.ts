'use client';

export const sessionTransitionEvent = 'openpc:session-transition';
export const sessionTransitionStorageKey = 'openpc:session-transition:v1';

type StoredNotification = { available: boolean; raw: string | null };
type OwnedTransition = {
  nonce: string;
  before: StoredNotification;
  persisted: boolean;
};
let ownedTransition: OwnedTransition | undefined;
let pendingTransition: { nonce: unknown } | undefined;

export function isSessionTransitionPending(): boolean {
  reconcilePendingSettlement();
  return pendingTransition !== undefined;
}

function storedNotification(): StoredNotification {
  try {
    return { available: true, raw: localStorage.getItem(sessionTransitionStorageKey) };
  } catch {
    return { available: false, raw: null };
  }
}

function reconcilePendingSettlement(): void {
  if (!pendingTransition) return;
  const stored = storedNotification();
  if (!stored.available || stored.raw === null) return;
  try {
    const latest: { phase?: unknown; nonce?: unknown } | null = JSON.parse(stored.raw);
    if (latest?.phase === 'settled' && latest.nonce === pendingTransition.nonce)
      pendingTransition = undefined;
  } catch {
    /* A missed settlement can be recovered only for its original owner. */
  }
}

function publish(notification: { phase: 'changing' | 'settled'; nonce: string }): boolean {
  let persisted = false;
  try {
    localStorage.setItem(sessionTransitionStorageKey, JSON.stringify(notification));
    persisted = true;
  } catch {
    /* Same-tab notifications and focus revalidation remain available. */
  }
  return persisted;
}

export function observeSessionTransitions(
  changing: () => void,
  revalidate: (pending: boolean) => void,
): () => void {
  reconcilePendingSettlement();
  let pending = pendingTransition !== undefined;
  let owner: unknown = pendingTransition?.nonce;
  const observe = (notification: unknown) => {
    const value =
      notification && typeof notification === 'object'
        ? (notification as { phase?: unknown; nonce?: unknown })
        : undefined;
    if (value?.phase === 'changing') {
      pendingTransition = { nonce: value.nonce };
      pending = true;
      owner = value.nonce;
      changing();
    } else if (value?.phase === 'settled') {
      if (pending && owner !== value.nonce) return;
      if (pendingTransition?.nonce === value.nonce) pendingTransition = undefined;
      pending = false;
      owner = undefined;
      revalidate(false);
    } else revalidate(pending);
  };
  const event = (value: Event) => observe(value instanceof CustomEvent ? value.detail : undefined);
  const storage = (value: StorageEvent) => {
    if (value.key !== sessionTransitionStorageKey) return;
    let notification: unknown;
    try {
      notification = JSON.parse(value.newValue ?? 'null');
    } catch {
      /* Notifications carry no authority. */
    }
    observe(notification);
  };
  const focus = () => revalidate(pending);
  const visibility = () => {
    if (document.visibilityState === 'visible') focus();
  };
  window.addEventListener(sessionTransitionEvent, event);
  window.addEventListener('storage', storage);
  window.addEventListener('focus', focus);
  document.addEventListener('visibilitychange', visibility);
  if (pending) changing();
  return () => {
    window.removeEventListener(sessionTransitionEvent, event);
    window.removeEventListener('storage', storage);
    window.removeEventListener('focus', focus);
    document.removeEventListener('visibilitychange', visibility);
  };
}

// Only a random notification ID crosses tabs. Account and workflow data stay
// with their owners; every observer must read the authenticated session again.
export function notifySessionTransition(
  phase: 'changing' | 'settled',
  owner?: string,
): string | undefined {
  const nonce = phase === 'changing' ? crypto.randomUUID() : owner;
  if (!nonce) return undefined;
  if (phase === 'settled') {
    const owned = ownedTransition;
    if (!owned || owned.nonce !== nonce) return undefined;
    if (pendingTransition && pendingTransition.nonce !== nonce) return undefined;
    const stored = storedNotification();
    // A failed write can leave an older readable marker behind. It does not
    // supersede this owner unless storage changed after that failed write.
    const unchanged = owned.before.available && stored.raw === owned.before.raw;
    if (stored.available && (owned.persisted || !unchanged)) {
      let latest: { phase?: unknown; nonce?: unknown };
      try {
        latest = JSON.parse(stored.raw ?? 'null');
      } catch {
        return undefined;
      }
      if (!latest || latest.phase !== 'changing' || latest.nonce !== nonce) return undefined;
    }
    ownedTransition = undefined;
    pendingTransition = undefined;
  } else {
    ownedTransition = { nonce, before: storedNotification(), persisted: false };
    pendingTransition = { nonce };
  }
  const notification = { phase, nonce };
  const persisted = publish(notification);
  if (phase === 'changing' && ownedTransition?.nonce === nonce)
    ownedTransition.persisted = persisted;
  window.dispatchEvent(new CustomEvent(sessionTransitionEvent, { detail: notification }));
  return nonce;
}
