import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../services/identity-service/src/domain/identity-runtime-crypto.js';
export type PlatformRecoveryInstallationResult =
  | {
      custodyTrustId: string;
      digest: string;
      state: 'INSTALLED';
      authority: 'NONE';
    }
  | {
      enrollmentId: string;
      revision: string;
      digest: string;
      state: 'ENROLLED';
      authority: 'NONE';
      assurance?: 'HARDWARE_ATTESTED' | 'LOCAL_QA_VIRTUAL_AUTHENTICATOR';
    };
export function installPlatformRecoveryEnrollment(
  pool: Pool,
  input: unknown,
  options?: { localQaEnabled?: boolean; identityRuntimeVerifier?: IdentityRuntimeVerifier },
): Promise<PlatformRecoveryInstallationResult>;
export function parsePlatformRecoveryEnrollmentArguments(args: string[]): {
  'localQaEnabled': boolean;
  '--enrollment': string;
  '--database-url-file': string;
  'provisionInstallationLogin'?: boolean;
  '--bootstrap-database-url-file'?: string;
  '--identity-runtime-trust-file'?: string;
};
export function readPlatformRecoveryDatabaseUrl(path: string): Promise<string>;
export const installDiscoveryCertificateRecoveryEnrollment: typeof installPlatformRecoveryEnrollment;
export function installIdentityEnvelopeRecoveryReceivingTrust(
  pool: Pool,
  input: unknown,
  options?: { localQaEnabled?: boolean },
): Promise<Extract<PlatformRecoveryInstallationResult, { state: 'INSTALLED' }>>;
export function installIdentityEnvelopeRecoveryEnrollment(
  pool: Pool,
  input: unknown,
  options?: { localQaEnabled?: boolean; identityRuntimeVerifier?: IdentityRuntimeVerifier },
): Promise<Extract<PlatformRecoveryInstallationResult, { state: 'ENROLLED' }>>;
export function runRecoveryEnrollmentInstallation(
  install: typeof installPlatformRecoveryEnrollment,
  reason?: string,
): Promise<void>;

export function provisionPlatformRecoveryInstallationLogin(
  pool: Pool,
  connectionString: string,
): Promise<{
  login: 'openpc_recovery_installation';
  created: boolean;
  authority: 'INSTALLATION_ONLY';
  ownership: 'openpc:installation-recovery-login:v1';
}>;
export function validatePlatformRecoveryInstallationPeer(
  bootstrapConnectionString: string,
  installationConnectionString: string,
): void;
