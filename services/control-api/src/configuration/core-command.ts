import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ConfigurationRepositoryError } from './persistence/types.js';

type ConfigurationCoreCommand =
  | 'READ_CIGL_PROFILE'
  | 'READ_CIGL_ANALYSIS'
  | 'REVIEW_CIGL_ANALYSIS'
  | 'VALIDATE_CIGL_GRANT'
  | 'VALIDATE_CIGL_DEPENDENCIES'
  | 'VALIDATE_CIGL_SETTINGS'
  | 'ENCODE_CIGL_SETTINGS_SOURCE'
  | 'PREPARE_DEPLOYMENT_INTENT'
  | 'READ_DEPLOYMENT_INTENT'
  | 'BIND_DEPLOYMENT_RESERVATION'
  | 'READ_DEPLOYMENT_PROJECTION'
  | 'READ_DEPLOYMENT_REJECTION'
  | 'ENCODE_NATIVE_VALUE_AUTHORIZATION'
  | 'READ_NATIVE_VALUE_AUTHORIZATION';

/** Existing bounded transport to the shared Rust model. The caller still owns
 * authentication, authorization, persistence and validation of its result. */
export function configurationCoreCommand(
  command: ConfigurationCoreCommand,
  value: unknown,
): unknown {
  const executable =
    process.env.OPENPC_POLICY_CORE_BIN ??
    fileURLToPath(new URL('../../../../target/debug/openpc-policy-evaluator', import.meta.url));
  try {
    return JSON.parse(
      execFileSync(executable, [], {
        encoding: 'utf8',
        input: JSON.stringify({ command, value }),
        timeout: 10_000,
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
      }),
    );
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
}
