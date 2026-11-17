import type { TLSSocket } from 'node:tls';

import Fastify, { LogController } from 'fastify';
import type { Pool } from 'pg';
import { z } from 'zod';

import { IdentityKernel } from './identity-kernel.js';
import { authenticateWorkloadPeer } from './workload-peer.js';
export { presentedCertificate, type PresentedCertificate } from './workload-transport.js';

const runtimeRequest = z
  .object({
    runtimeContext: z
      .object({
        privacyDomainId: z.uuidv7(),
        targetRuntimeId: z.uuidv7(),
      })
      .strict()
      .optional(),
  })
  .strict();

export interface LocalWorkloadMtlsOptions {
  readonly ca: Buffer;
  readonly certificate: Buffer;
  readonly privateKey: Buffer;
}

/** Authenticate only facts derived from a TLS-authorized peer certificate. */
export function buildLocalWorkloadMtlsService(
  pool: Pool,
  kernel: IdentityKernel,
  options: LocalWorkloadMtlsOptions,
) {
  const app = Fastify({
    logger: false,
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: false,
    https: {
      ca: options.ca,
      cert: options.certificate,
      key: options.privateKey,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
  });

  app.post('/internal/v1/workload/authenticate', async (request, reply) => {
    const parsed = runtimeRequest.safeParse(request.body ?? {});
    if (!parsed.success) return reply.code(400).send({ code: 'PC-IDENTITY-1006' });
    try {
      const identity = await authenticateWorkloadPeer(
        pool,
        kernel,
        request.raw.socket as TLSSocket,
        parsed.data.runtimeContext,
      );
      return {
        ...identity,
        notBefore: identity.notBefore.toISOString(),
        notAfter: identity.notAfter.toISOString(),
      };
    } catch {
      return reply.code(401).send({ code: 'PC-IDENTITY-1006' });
    }
  });

  return app;
}
