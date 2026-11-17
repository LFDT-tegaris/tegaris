import type { EventEmitter } from 'node:events';

const observedPools = new WeakSet<object>();
const observedClients = new WeakSet<object>();

// pg evicts a failed idle client before emitting this event. Query and
// transaction failures still belong to their callers; never replay them here.
export function handleDatabaseIdleErrors(pool: Pick<EventEmitter, 'on'>): void {
  if (observedPools.has(pool)) return;
  observedPools.add(pool);
  pool.on('connect', (client: Pick<EventEmitter, 'on'>) => {
    if (observedClients.has(client)) return;
    observedClients.add(client);
    // A checked-out client has no pool idle listener. Its query still rejects;
    // keep the emitter from terminating the process while that failure returns.
    client.on('error', () => {
      // eslint-disable-next-line no-console -- Installed before application logger construction.
      console.error('{"event":"database_connection_failed"}');
    });
  });
  pool.on('error', () => {
    // Neither the Error nor pg's Client is safe to serialize: both may contain
    // connection credentials, query input or protocol authentication fields.
    // eslint-disable-next-line no-console -- Installed before application logger construction.
    console.error('{"event":"database_idle_connection_failed"}');
  });
}
