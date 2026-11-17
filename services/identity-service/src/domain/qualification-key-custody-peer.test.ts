import { expect, it } from 'vitest';
import { TLSSocket } from 'node:tls';
import { Socket } from 'node:net';
import { Pool } from 'pg';
import { createQualificationKeyCustodyPeer } from './qualification-key-custody-peer.js';
import { IdentityKernel, PostgresIdentityRepository, systemClock } from './identity-kernel.js';
it('rejects a native unauthenticated socket before opening any database connection', async () => {
  const pool = new Pool({ host: 'unreachable.invalid', max: 1 }),
    socket = new TLSSocket(new Socket());
  try {
    const kernel = new IdentityKernel(new PostgresIdentityRepository(pool, systemClock));
    const owner = createQualificationKeyCustodyPeer({
      ownerPool: pool,
      kernel,
      tls: { certificate: Buffer.alloc(0), privateKey: Buffer.alloc(0), trustCa: Buffer.alloc(0) },
    });
    const id = '018f0000-0000-7000-8000-000000000001';
    await expect(
      owner.observe(
        socket,
        { participantId: id, privacyDomainId: id, installationId: id },
        { method: 'INSPECT', operationId: id, attemptId: id },
      ),
    ).rejects.toThrow();
    expect(pool.totalCount).toBe(0);
  } finally {
    socket.destroy();
    await pool.end();
  }
});
