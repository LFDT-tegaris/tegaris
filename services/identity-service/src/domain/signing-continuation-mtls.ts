import type { TLSSocket } from 'node:tls';
import Fastify, { LogController } from 'fastify';
import type { Pool } from 'pg';
import { z } from 'zod';
import { SigningContinuationIssuer } from '../db/signing-continuation-store.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { localOperationId } from './local-operation-id.js';
import { presentedCertificate, type LocalWorkloadMtlsOptions } from './local-workload-mtls.js';

const requestSchema = z.strictObject({
  privacyDomainId: z.uuidv7(),
  rotationId: z.uuidv7(),
  operationId: z.uuidv7(),
  attemptId: z.uuidv7(),
});

/** A separate TLS listener trusts only the control API's CA; it exposes no user authentication or mutation route. */
export function buildSigningContinuationMtlsService(
  pool: Pool,
  issuer: SigningContinuationIssuer,
  options: LocalWorkloadMtlsOptions,
) {
  const app = Fastify({
    logger: false,
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: false,
    bodyLimit: 2048,
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
  app.post('/internal/v1/signing-rotation-attempts/reconcile-assertion', async (request, reply) => {
    const presented = presentedCertificate(request.raw.socket as TLSSocket);
    const parsed = requestSchema.safeParse(request.body);
    if (!presented || !parsed.success) return reply.code(403).send({ code: 'PC-IDENTITY-1006' });
    try {
      const input = parsed.data;
      const credential = await runScopedTransaction(
        pool,
        {
          participantId: presented.participantId,
          privacyDomainId: input.privacyDomainId,
          actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
        },
        localOperationId,
        async (client) => {
          const found = await client.query<{
            principalId: string;
            credentialId: string;
            credentialEpoch: string;
            publicKeyDigest: Buffer;
          }>(
            `select c.principal_id::text as "principalId",c.credential_id::text as "credentialId",c.credential_epoch::text as "credentialEpoch",
       c.public_key_digest as "publicKeyDigest" from control.credential c join control.principal p using(participant_id,principal_id)
       where c.participant_id=$1 and c.kind='WORKLOAD_MTLS' and c.subject=$2 and c.audience=$3 and c.public_key_digest=$4
        and c.valid_from=$5 and c.valid_until=$6 and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
        and c.state='ACTIVE' and p.state='ACTIVE' and p.kind='WORKLOAD'`,
            [
              presented.participantId,
              presented.uriSan,
              presented.workloadId,
              Buffer.from(presented.keyId.slice(7), 'hex'),
              presented.notBefore,
              presented.notAfter,
            ],
          );
          if (found.rowCount !== 1) throw new Error('Workload unavailable');
          return found.rows[0]!;
        },
      );
      return await issuer.issue(
        {
          ...credential,
          participantId: presented.participantId,
          privacyDomainId: input.privacyDomainId,
        },
        input.rotationId,
        input.operationId,
        input.attemptId,
      );
    } catch {
      return reply.code(403).send({ code: 'PC-IDENTITY-1006' });
    }
  });
  return app;
}
