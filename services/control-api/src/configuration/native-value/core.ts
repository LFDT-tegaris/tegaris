import { z } from 'zod';
import { configurationCoreCommand } from '../core-command.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';

const result = z.strictObject({
  identity: z.literal('PC-NATIVE-VALUE-AUTHORIZATION-1'),
  authority: z.literal('NONE'),
  documentBytes: z
    .string()
    .regex(/^0x(?:[0-9a-f]{2})+$/u)
    .max(8194),
  semanticDigest: z.string().regex(/^[0-9a-f]{64}$/u),
  authorizationId: z.string().min(1).max(128),
  participantEpoch: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  validUntil: z.string().min(1).max(128),
  used: z.boolean(),
});

/** The native-value model and digest are owned by Rust. Opaque canonical bytes preserve
 * the complete uint64 epoch across the JavaScript/database boundary. */
export function nativeValueCore(
  command: 'ENCODE_NATIVE_VALUE_AUTHORIZATION' | 'READ_NATIVE_VALUE_AUTHORIZATION',
  value: unknown,
) {
  try {
    return result.parse(configurationCoreCommand(command, value));
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
}
