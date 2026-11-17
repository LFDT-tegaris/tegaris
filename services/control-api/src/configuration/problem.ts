import { randomBytes } from 'node:crypto';
import { BusinessSigningTrustError } from '@openpc/security-kernel';

import type { FastifyReply, FastifyRequest } from 'fastify';

import { ConfigurationRepositoryError } from './persistence/types.js';
import { BusinessSigningProviderUnknown } from '../../../identity-service/src/domain/business-signing-provider.js';
import { AuthorityFenceError } from '../../../identity-service/src/db/authority-fence.js';
import { MutationCandidateError } from '../../../identity-service/src/db/mutation-candidate-store.js';

function uuidv7(): string {
  const bytes = randomBytes(16);
  let time = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(time & 0xffn);
    time >>= 8n;
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function traceId(request: FastifyRequest): string {
  const candidate = request.headers['x-request-id'];
  return typeof candidate === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(candidate)
    ? candidate
    : uuidv7();
}

export function configurationProblem(reply: FastifyReply, request: FastifyRequest, error: unknown) {
  if (error instanceof ConfigurationRepositoryError && error.code === 'PC-OPS-9002') {
    return reply
      .code(503)
      .type('application/problem+json')
      .send({
        type: 'https://errors.openpc.local/unavailable',
        title: 'Evidence is unavailable',
        status: 503,
        code: error.code,
        truthState: 'UNAVAILABLE',
        retryable: true,
        traceId: traceId(request),
      });
  }
  // Receipt signing runs before COMMIT; no provider failure can publish the rolled-back
  // business transition. Unknown database COMMIT outcomes retain their separate mapping.
  if (
    error instanceof BusinessSigningProviderUnknown ||
    error instanceof BusinessSigningTrustError ||
    (error instanceof ConfigurationRepositoryError && error.code === 'PC-INTEGRATION-5001')
  ) {
    return reply
      .code(503)
      .type('application/problem+json')
      .send({
        type: 'https://errors.openpc.local/unavailable',
        title: 'The service is unavailable',
        status: 503,
        code: 'PC-INTEGRATION-5001',
        truthState: 'UNAVAILABLE',
        retryable: true,
        traceId: traceId(request),
      });
  }
  const code =
    error instanceof AuthorityFenceError
      ? 'PC-AUTH-0005'
      : error instanceof ConfigurationRepositoryError || error instanceof MutationCandidateError
        ? error.code
        : 'PC-FACT-4001';
  const status =
    error instanceof ConfigurationRepositoryError && error.statusOverride !== undefined
      ? error.statusOverride
      : code === 'PC-AUTH-0003'
        ? 401
        : code === 'PC-AUTH-0005'
          ? 403
          : code === 'PC-DATA-6004'
            ? 400
            : code === 'PC-DATA-6007'
              ? 412
              : 409;
  const problem =
    code === 'PC-AUTH-0003' || code === 'PC-AUTH-0005'
      ? {
          type: 'https://errors.openpc.local/hidden-or-not-found',
          title: 'Resource is unavailable',
          truthState: 'DENIED',
          retryable: false,
        }
      : code === 'PC-DATA-6004'
        ? {
            type: 'https://errors.openpc.local/invalid-request',
            title: 'Request validation failed',
            truthState: 'FAILED',
            retryable: false,
          }
        : code === 'PC-DATA-6007'
          ? {
              type: 'https://errors.openpc.local/stale',
              title: 'The supplied revision is stale',
              truthState: 'STALE',
              retryable: false,
            }
          : code === 'PC-DATA-6001'
            ? {
                type: 'https://errors.openpc.local/conflict',
                title: 'The operation conflicts with current state',
                truthState: 'CONFLICTING',
                retryable: false,
              }
            : {
                type: 'https://errors.openpc.local/conflict',
                title: 'Result unknown',
                truthState: 'UNKNOWN',
                retryable: false,
              };
  return reply
    .code(status)
    .type('application/problem+json')
    .send({
      ...problem,
      status,
      code,
      traceId: traceId(request),
    });
}
