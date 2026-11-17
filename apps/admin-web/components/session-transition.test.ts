import { afterEach, expect, it, vi } from 'vitest';
import {
  notifySessionTransition,
  observeSessionTransitions,
  sessionTransitionStorageKey,
} from './session-transition';

let stop: (() => void) | undefined;
afterEach(() => {
  stop?.();
  stop = undefined;
  localStorage.clear();
  vi.restoreAllMocks();
  const owner = notifySessionTransition('changing');
  notifySessionTransition('settled', owner);
});

it('keeps focus reads fenced until the matching notification settles', () => {
  const changing = vi.fn(),
    read = vi.fn();
  stop = observeSessionTransitions(changing, read);
  const older = notifySessionTransition('changing');
  const latest = notifySessionTransition('changing');
  window.dispatchEvent(new Event('focus'));
  expect(read).toHaveBeenLastCalledWith(true);
  expect(notifySessionTransition('settled', older)).toBeUndefined();
  expect(read).toHaveBeenCalledTimes(1);
  notifySessionTransition('settled', latest);
  expect(read).toHaveBeenLastCalledWith(false);
  expect(changing).toHaveBeenCalledTimes(2);
});

it('rejects obsolete settlement after another tab owns the stored notification', () => {
  const older = notifySessionTransition('changing');
  localStorage.setItem(
    sessionTransitionStorageKey,
    JSON.stringify({ phase: 'changing', nonce: 'other-tab-owner' }),
  );
  const changing = vi.fn(),
    read = vi.fn();
  stop = observeSessionTransitions(changing, read);
  expect(notifySessionTransition('settled', older)).toBeUndefined();
  expect(read).not.toHaveBeenCalled();
  expect(changing).toHaveBeenCalledTimes(1);
});

it('inherits an unfinished same-tab transition after every observer unmounts', () => {
  const owner = notifySessionTransition('changing');
  stop = observeSessionTransitions(vi.fn(), vi.fn());
  stop();
  const changing = vi.fn(),
    read = vi.fn();
  stop = observeSessionTransitions(changing, read);
  expect(changing).toHaveBeenCalledTimes(1);
  window.dispatchEvent(new Event('focus'));
  expect(read).toHaveBeenLastCalledWith(true);
  notifySessionTransition('settled', owner);
  expect(read).toHaveBeenLastCalledWith(false);
});

it('inherits an observed cross-tab transition across navigation', () => {
  stop = observeSessionTransitions(vi.fn(), vi.fn());
  window.dispatchEvent(
    new StorageEvent('storage', {
      key: sessionTransitionStorageKey,
      newValue: JSON.stringify({ phase: 'changing', nonce: 'external-owner' }),
    }),
  );
  stop();
  const changing = vi.fn(),
    read = vi.fn();
  stop = observeSessionTransitions(changing, read);
  expect(changing).toHaveBeenCalledTimes(1);
  window.dispatchEvent(
    new StorageEvent('storage', {
      key: sessionTransitionStorageKey,
      newValue: JSON.stringify({ phase: 'settled', nonce: 'older-owner' }),
    }),
  );
  expect(read).not.toHaveBeenCalled();
  window.dispatchEvent(
    new StorageEvent('storage', {
      key: sessionTransitionStorageKey,
      newValue: JSON.stringify({ phase: 'settled', nonce: 'external-owner' }),
    }),
  );
  expect(read).toHaveBeenCalledExactlyOnceWith(false);
});

it('recovers a matching cross-tab settlement that arrived while observers were unmounted', () => {
  stop = observeSessionTransitions(vi.fn(), vi.fn());
  window.dispatchEvent(
    new StorageEvent('storage', {
      key: sessionTransitionStorageKey,
      newValue: JSON.stringify({ phase: 'changing', nonce: 'external-owner' }),
    }),
  );
  stop();
  localStorage.setItem(
    sessionTransitionStorageKey,
    JSON.stringify({ phase: 'settled', nonce: 'external-owner' }),
  );
  const changing = vi.fn(),
    read = vi.fn();
  stop = observeSessionTransitions(changing, read);
  expect(changing).not.toHaveBeenCalled();
  window.dispatchEvent(new Event('focus'));
  expect(read).toHaveBeenCalledExactlyOnceWith(false);
});

it.each(['{bad', JSON.stringify({ phase: 'settled', nonce: 'different-owner' })])(
  'retains the navigation fence for unmatched persisted settlement (%s)',
  (raw) => {
    stop = observeSessionTransitions(vi.fn(), vi.fn());
    window.dispatchEvent(
      new StorageEvent('storage', {
        key: sessionTransitionStorageKey,
        newValue: JSON.stringify({ phase: 'changing', nonce: 'external-owner' }),
      }),
    );
    stop();
    localStorage.setItem(sessionTransitionStorageKey, raw);
    const changing = vi.fn(),
      read = vi.fn();
    stop = observeSessionTransitions(changing, read);
    expect(changing).toHaveBeenCalledTimes(1);
    window.dispatchEvent(new Event('focus'));
    expect(read).toHaveBeenCalledExactlyOnceWith(true);
  },
);

it('settles its own transition when a failed write leaves an older readable marker', () => {
  localStorage.setItem(
    sessionTransitionStorageKey,
    JSON.stringify({ phase: 'settled', nonce: 'old-marker' }),
  );
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('Quota');
  });
  const read = vi.fn();
  stop = observeSessionTransitions(vi.fn(), read);
  const owner = notifySessionTransition('changing');
  expect(notifySessionTransition('settled', owner)).toBe(owner);
  expect(read).toHaveBeenCalledExactlyOnceWith(false);
});

it('rejects a newer stored owner even when its own changing write failed', () => {
  localStorage.setItem(
    sessionTransitionStorageKey,
    JSON.stringify({ phase: 'settled', nonce: 'old-marker' }),
  );
  const write = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('Quota');
  });
  const read = vi.fn();
  stop = observeSessionTransitions(vi.fn(), read);
  const owner = notifySessionTransition('changing');
  write.mockRestore();
  localStorage.setItem(
    sessionTransitionStorageKey,
    JSON.stringify({ phase: 'changing', nonce: 'new-owner' }),
  );
  expect(notifySessionTransition('settled', owner)).toBeUndefined();
  expect(read).not.toHaveBeenCalled();
});

it('does not release a pending fence for malformed storage notifications', () => {
  const read = vi.fn();
  stop = observeSessionTransitions(vi.fn(), read);
  const owner = notifySessionTransition('changing');
  window.dispatchEvent(
    new StorageEvent('storage', { key: sessionTransitionStorageKey, newValue: '{bad' }),
  );
  expect(read).toHaveBeenLastCalledWith(true);
  notifySessionTransition('settled', owner);
  expect(read).toHaveBeenLastCalledWith(false);
});

it('preserves same-tab ownership when browser storage is unavailable', () => {
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
    throw new Error('Unavailable');
  });
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
    throw new Error('Unavailable');
  });
  const read = vi.fn();
  stop = observeSessionTransitions(vi.fn(), read);
  const older = notifySessionTransition('changing'),
    latest = notifySessionTransition('changing');
  expect(notifySessionTransition('settled', older)).toBeUndefined();
  notifySessionTransition('settled', latest);
  expect(read).toHaveBeenCalledExactlyOnceWith(false);
});

it('removes notification and focus observers when their owner unmounts', () => {
  const read = vi.fn();
  stop = observeSessionTransitions(vi.fn(), read);
  stop();
  stop = undefined;
  window.dispatchEvent(new Event('focus'));
  const owner = notifySessionTransition('changing');
  notifySessionTransition('settled', owner);
  expect(read).not.toHaveBeenCalled();
});
