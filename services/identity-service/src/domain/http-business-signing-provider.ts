import { request as httpsRequest, Agent } from 'node:https';
import { z } from 'zod';
import {
  businessProviderObservationSchema,
  businessProviderRequestSchema,
  validateBusinessProviderObservation,
  BusinessSigningProviderUnknown,
  type BusinessProviderObservation,
  type BusinessSigningProvider,
} from './business-signing-provider.js';

const lookupSchema = z.discriminatedUnion('state', [
  z.strictObject({ state: z.literal('ABSENT'), attemptId: z.uuidv7() }),
  z.strictObject({ state: z.literal('OBSERVED'), observation: businessProviderObservationSchema }),
]);

/** Private provider transport, never a public OpenPC signing endpoint. Every client has its own mTLS identity. */
export function createHttpBusinessSigningProvider(config: {
  readonly origin: string;
  readonly certificate: Buffer;
  readonly privateKey: Buffer;
  readonly trustCa: Buffer;
  readonly timeoutMs?: number;
}): BusinessSigningProvider & { close(): void } {
  const origin = new URL(config.origin);
  if (
    origin.protocol !== 'https:' ||
    origin.username ||
    origin.password ||
    origin.pathname !== '/' ||
    origin.search ||
    origin.hash ||
    config.certificate.length === 0 ||
    config.privateKey.length === 0 ||
    config.trustCa.length === 0
  )
    throw new Error('Invalid signing provider transport configuration');
  const timeoutMs = config.timeoutMs ?? 5000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 10000)
    throw new Error('Invalid signing provider transport timeout');
  const agent = new Agent({
    cert: config.certificate,
    key: config.privateKey,
    ca: config.trustCa,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    rejectUnauthorized: true,
    keepAlive: true,
    maxSockets: 2,
  });
  const exchange = (path: string, input?: unknown): Promise<unknown> =>
    new Promise((resolve, reject) => {
      const body = input === undefined ? undefined : Buffer.from(JSON.stringify(input));
      const rejectUnknown = () => reject(new BusinessSigningProviderUnknown());
      const request = httpsRequest(
        new URL(path, origin),
        {
          method: body === undefined ? 'GET' : 'POST',
          agent,
          headers: {
            accept: 'application/json',
            ...(body === undefined
              ? {}
              : { 'content-type': 'application/json', 'content-length': body.length }),
          },
        },
        (response) => {
          if (
            response.statusCode !== 200 ||
            !response.headers['content-type']?.startsWith('application/json')
          ) {
            response.destroy();
            rejectUnknown();
            return;
          }
          const chunks: Buffer[] = [];
          let length = 0;
          response.on('data', (chunk: Buffer) => {
            length += chunk.length;
            if (length > 262144) {
              response.destroy();
              rejectUnknown();
              return;
            }
            chunks.push(chunk);
          });
          response.on('error', rejectUnknown);
          response.on('end', () => {
            try {
              resolve(
                JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))),
              );
            } catch {
              rejectUnknown();
            }
          });
        },
      );
      // Total deadline includes connection establishment and a peer that trickles response bytes.
      const timer = setTimeout(() => {
        request.destroy();
        rejectUnknown();
      }, timeoutMs);
      request.once('close', () => clearTimeout(timer));
      request.on('error', rejectUnknown);
      request.end(body);
    });
  return {
    async perform(input) {
      const request = businessProviderRequestSchema.parse(input);
      const raw = await exchange('/v1/business-signing/requests', request);
      // Closed public fields only; never retain an unknown provider field or private-key response.
      const parsed = businessProviderObservationSchema.safeParse(raw);
      if (!parsed.success) throw new BusinessSigningProviderUnknown();
      validateBusinessProviderObservation(request, parsed.data);
      return parsed.data;
    },
    async lookup(attemptId): Promise<BusinessProviderObservation | undefined> {
      const id = z.uuidv7().parse(attemptId);
      const parsed = lookupSchema.safeParse(await exchange(`/v1/business-signing/attempts/${id}`));
      if (!parsed.success) throw new BusinessSigningProviderUnknown();
      if (parsed.data.state === 'ABSENT') {
        if (parsed.data.attemptId !== id) throw new BusinessSigningProviderUnknown();
        return undefined;
      }
      if (parsed.data.observation.attemptId !== id) throw new BusinessSigningProviderUnknown();
      return parsed.data.observation;
    },
    close() {
      agent.destroy();
    },
  };
}
