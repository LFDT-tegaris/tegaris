import { Agent, request } from 'node:https';
import { z } from 'zod';

const responseSchema = z.strictObject({
  assertion: z.string().min(1).max(16384),
  expiresAtNs: z.string().regex(/^[0-9]{1,20}$/u),
});
/** The API presents its own certificate to the identity-owned continuation issuer. No user token is sent. */
export function createSigningContinuationClient(options: {
  origin: string;
  ca: Buffer;
  certificate: Buffer;
  privateKey: Buffer;
}) {
  const origin = new URL(options.origin);
  if (
    origin.protocol !== 'https:' ||
    origin.username ||
    origin.password ||
    origin.pathname !== '/' ||
    origin.search ||
    origin.hash
  )
    throw new Error('Invalid continuation issuer origin');
  const agent = new Agent({
    ca: options.ca,
    cert: options.certificate,
    key: options.privateKey,
    rejectUnauthorized: true,
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
    maxSockets: 1,
  });
  return {
    close: () => agent.destroy(),
    issue(input: {
      privacyDomainId: string;
      rotationId: string;
      operationId: string;
      attemptId: string;
    }): Promise<string | undefined> {
      return new Promise((resolve, reject) => {
        const req = request(
          new URL('/internal/v1/signing-rotation-attempts/reconcile-assertion', origin),
          { agent, method: 'POST', timeout: 5000, headers: { 'Content-Type': 'application/json' } },
          (res) => {
            const chunks: Buffer[] = [];
            let size = 0;
            res.on('data', (chunk: Buffer) => {
              size += chunk.length;
              if (size > 20000)
                res.destroy(new Error('Continuation issuer response exceeded bound'));
              else chunks.push(chunk);
            });
            res.on('error', reject);
            res.on('end', () => {
              if (res.statusCode !== 200) {
                resolve(undefined);
                return;
              }
              try {
                resolve(
                  responseSchema.parse(JSON.parse(Buffer.concat(chunks).toString())).assertion,
                );
              } catch {
                reject(new Error('Invalid continuation assertion response'));
              }
            });
          },
        );
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('Continuation issuer timeout')));
        req.end(JSON.stringify(input));
      });
    },
  };
}
