import { EventEmitter } from 'node:events';

import { describe, expect, it, vi } from 'vitest';

import { handleDatabaseIdleErrors } from './pool-idle-errors.js';

describe('database idle connection errors', () => {
  it('handles repeated idle failures without serializing either error or client', () => {
    const pool = new EventEmitter();
    const output = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      handleDatabaseIdleErrors(pool);
      handleDatabaseIdleErrors(pool);
      const failure = Object.assign(new Error('database password: protected'), {
        connectionParameters: { password: 'protected' },
      });
      const client = { secretKey: 12345, query: 'protected input' };
      expect(() => pool.emit('error', failure, client)).not.toThrow();
      expect(() => pool.emit('error', failure, client)).not.toThrow();
      expect(output.mock.calls).toEqual([
        ['{"event":"database_idle_connection_failed"}'],
        ['{"event":"database_idle_connection_failed"}'],
      ]);
    } finally {
      output.mockRestore();
    }
  });

  it('preserves caller-owned query failures and does not add a retry owner', async () => {
    const pool = Object.assign(new EventEmitter(), {
      query: vi.fn().mockRejectedValue(new Error('connection interrupted')),
    });
    const originalQuery = pool.query;
    handleDatabaseIdleErrors(pool);
    await expect(pool.query('COMMIT')).rejects.toThrow('connection interrupted');
    expect(pool.query).toBe(originalQuery);
    expect(pool.query).toHaveBeenCalledExactlyOnceWith('COMMIT');
    expect(pool.eventNames().sort()).toEqual(['connect', 'error']);
  });

  it('handles a borrowed client failure once while the original COMMIT rejects without retry', async () => {
    const failure = Object.assign(new Error('connection interrupted: protected'), {
      connectionParameters: { password: 'protected' },
    });
    const pool = new EventEmitter();
    const client = Object.assign(new EventEmitter(), {
      secretKey: 'protected',
      query: vi.fn().mockRejectedValue(failure),
    });
    const originalQuery = client.query;
    const output = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      handleDatabaseIdleErrors(pool);
      handleDatabaseIdleErrors(pool);
      pool.emit('connect', client);
      pool.emit('connect', client);
      const rejected = expect(client.query('COMMIT')).rejects.toBe(failure);
      expect(() => client.emit('error', failure)).not.toThrow();
      await rejected;
      expect(client.listenerCount('error')).toBe(1);
      expect(client.query).toBe(originalQuery);
      expect(client.query).toHaveBeenCalledExactlyOnceWith('COMMIT');
      expect(output.mock.calls).toEqual([['{"event":"database_connection_failed"}']]);
    } finally {
      output.mockRestore();
    }
  });
});
