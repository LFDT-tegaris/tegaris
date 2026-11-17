import { z } from 'zod';
import { digest, sequence } from './segment.js';

const reference = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
const optionalHash = digest.nullable();
export const rpcTransitionProjection = z
  .strictObject({
    phase: z.enum([
      'PRE_ADMISSION_DENIAL',
      'RESERVED',
      'INTERRUPTED',
      'SOURCE_READ_STARTED',
      'SOURCE_READ_RELEASED',
      'COMMITTED',
      'RELEASED',
      'OPERATION_STATUS_RELEASED',
    ]),
    traceId: reference.nullable(),
    requestDigest: optionalHash,
    decisionDigest: optionalHash,
    responseDigest: optionalHash,
    authorityBindingDigest: optionalHash,
    sourceScopeDigest: optionalHash,
    operationId: z.uuidv7().nullable(),
    pcCode: reference.nullable(),
    decisionEffect: z
      .enum([
        'ALLOW_FORWARD',
        'DENY_TERMINAL',
        'AUTHORIZED_EMPTY',
        'WITHHOLD_STALE',
        'WRITE_AMBIGUITY',
      ])
      .nullable(),
    boundary: z
      .enum(['ext-proc', 'pds-pre-admission', 'broker', 'source-only-invocation-denial'])
      .nullable(),
    sourceSegmentId: reference,
    sourceRecordDigest: digest,
    admittedAtNs: sequence,
  })
  .refine((v) => {
    const denial = v.phase === 'PRE_ADMISSION_DENIAL';
    const source = v.phase === 'SOURCE_READ_STARTED' || v.phase === 'SOURCE_READ_RELEASED';
    return (
      (v.requestDigest === null) === denial &&
      (v.boundary !== null) === denial &&
      (v.decisionEffect !== null) === (v.phase === 'COMMITTED') &&
      (v.decisionDigest !== null) === ['COMMITTED', 'RELEASED'].includes(v.phase) &&
      (v.pcCode !== null) === ['PRE_ADMISSION_DENIAL', 'COMMITTED', 'RELEASED'].includes(v.phase) &&
      (v.responseDigest !== null) ===
        ['RELEASED', 'SOURCE_READ_RELEASED', 'OPERATION_STATUS_RELEASED'].includes(v.phase) &&
      (v.sourceScopeDigest !== null) === source &&
      (v.authorityBindingDigest !== null) === (source || v.phase === 'OPERATION_STATUS_RELEASED') &&
      (v.operationId !== null) === (v.phase === 'OPERATION_STATUS_RELEASED')
    );
  });

/** Verified off-path by the configured custody worker. The database projection
 * is not an individual decision signature and cannot create current authority. */
export const rpcProvenance = z.strictObject({
  integrity: z.literal('AEAD_CHAIN_VERIFIED_AT_CUSTODY'),
  activationIntegrity: z.literal('ACTIVATION_COSE_VERIFIED_AT_CUSTODY'),
  authority: z.literal('NONE'),
  currentAuthority: z.literal('NOT_ESTABLISHED'),
  providerEffect: z.literal('NOT_ESTABLISHED'),
  chainFinality: z.literal('NOT_ESTABLISHED'),
  decisionId: z.uuidv7(),
  targetRuntimeId: z.uuid(),
  spoolId: reference,
  sourceSequence: sequence,
  sourceDigest: digest,
  capsuleDigest: digest,
  reservedAtNs: sequence,
  occurredAtNs: sequence,
  transition: rpcTransitionProjection,
  activation: z.strictObject({
    operationId: z.uuidv7(),
    attemptId: z.uuidv7(),
    configurationWorkId: z.uuidv7(),
    generationId: z.uuidv7(),
    generationDigest: digest,
    receiptDigest: digest,
    signerId: reference,
    verificationKeyDigest: digest,
  }),
});
export type RpcProvenance = z.infer<typeof rpcProvenance>;
