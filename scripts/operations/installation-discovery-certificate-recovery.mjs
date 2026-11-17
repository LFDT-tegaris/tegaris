import { pathToFileURL } from 'node:url';
import {
  installDiscoveryCertificateRecoveryEnrollment,
  runRecoveryEnrollmentInstallation,
} from './installation-platform-recovery.mjs';

export { installDiscoveryCertificateRecoveryEnrollment };

// Host initial trust only; the service owns custody, approval and certificate effects.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  await runRecoveryEnrollmentInstallation(
    installDiscoveryCertificateRecoveryEnrollment,
    'DISCOVERY_CERTIFICATE_RECOVERY_ENROLLMENT_UNAVAILABLE',
  );
