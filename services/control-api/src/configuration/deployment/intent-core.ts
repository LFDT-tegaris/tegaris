import { z } from 'zod';
import { configurationCoreCommand } from '../core-command.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';
import { parseDeploymentReservationBinding } from './reservations.js';

const bytes = z.string().regex(/^0x(?:[0-9a-f]{2})+$/u);
const digest = z.string().regex(/^[0-9a-f]{64}$/u);
const hash = z.string().regex(/^0x[0-9a-f]{64}$/u);
const address = z.string().regex(/^0x[0-9a-f]{40}$/u);
const decimal = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const result = z.strictObject({
  identity: z.literal('PC-DEPLOYMENT-PREPARATION-1'),
  authority: z.literal('NONE'),
  recordBytes: bytes.max(2_097_154),
  recordDigest: digest,
  intentBytes: bytes.max(524_290),
  intentDigest: digest,
  signingPayload: bytes.max(262_146),
  signingHash: hash,
  sender: address,
  chainId: decimal,
  nonce: decimal,
  gasLimit: decimal,
  transactionType: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  expectedContractAddress: address.nullable(),
  expiresAtMs: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});

/** Adapter to the shared Rust decoder and intent model. Canonical bytes stay
 * opaque here to preserve the full uint64 range. */
export function deploymentIntentCore(
  command: 'PREPARE_DEPLOYMENT_INTENT' | 'READ_DEPLOYMENT_INTENT',
  value: unknown,
) {
  try {
    return result.parse(configurationCoreCommand(command, value));
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
}

export function deploymentReservationCore(value: unknown) {
  try {
    const parsed = z
      .strictObject({ authority: z.literal('NONE'), binding: z.unknown() })
      .parse(configurationCoreCommand('BIND_DEPLOYMENT_RESERVATION', value));
    return parseDeploymentReservationBinding(parsed.binding);
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
}

export function deploymentProjectionCore(value: unknown): unknown {
  return configurationCoreCommand('READ_DEPLOYMENT_PROJECTION', value);
}
