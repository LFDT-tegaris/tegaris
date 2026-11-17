import { Socket } from 'node:net';
import { TLSSocket } from 'node:tls';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import { IdentityKernel, PostgresIdentityRepository } from './identity-kernel.js';
import { createQualificationDeploymentPeer } from './qualification-deployment-peer.js';
import { localOperationId as id } from './local-operation-id.js';
import { qualificationDeploymentObservationSchema } from '../../../control-api/src/configuration/operations/qualification-deployment-observation.js';
it('unauthenticated native socket cannot reserve or contact Docker', async () => {
  const pool = new Pool({ connectionString: 'postgres://unavailable.invalid/unused', max: 1 });
  const socket = new TLSSocket(new Socket());
  try {
    const peer = createQualificationDeploymentPeer({
      ownerPool: pool,
      kernel: new IdentityKernel(new PostgresIdentityRepository(pool)),
    });
    await expect(
      peer.observe(
        socket,
        { participantId: id(), privacyDomainId: id(), installationId: id() },
        { observationId: id(), operationId: id() },
      ),
    ).rejects.toThrow();
    expect(pool.totalCount).toBe(0);
  } finally {
    socket.destroy();
    await pool.end();
  }
});
it('unknown original cannot claim observed readiness or authenticated provenance', () => {
  const value = {
    schemaVersion: 1,
    observationId: id(),
    requestDigest: 'sha256:' + 'a'.repeat(64),
    state: 'UNKNOWN',
    measurement: null,
    identityRecheckedAtMs: null,
    retainedAtMs: 10,
  };
  expect(qualificationDeploymentObservationSchema.parse(value)).toEqual(value);
  for (const changed of [
    { state: 'OBSERVED' },
    { state: 'CURRENT' },
    { current: true },
    { authorship: 'verified' },
    { identityRecheckedAtMs: 11 },
  ])
    expect(
      qualificationDeploymentObservationSchema.safeParse({ ...value, ...changed }).success,
    ).toBe(false);
});
