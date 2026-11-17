import { isExactSigningSecretReference } from '../../packages/security-kernel/src/business-transition/secret-reference.ts';
import { invalid } from './installation-config-inputs.mjs';

/** First test-profile binding to an existing consumer, not a resolver or readiness
 * assertion. Only the owning workload receives bytes; the installer sees this
 * non-secret descriptor. Local OS-keystore and production CSI are separate owners. */
export { testFactCandidateDatabaseConsumer } from '../../packages/security-kernel/src/secret-recipient/profile.ts';
import { testFactCandidateDatabaseConsumer } from '../../packages/security-kernel/src/secret-recipient/profile.ts';

export function bindTestFactCandidateDatabaseReference(reference, version) {
  if (
    !isExactSigningSecretReference(reference, version) ||
    !reference.startsWith(`secret://${testFactCandidateDatabaseConsumer.providerId}/`)
  )
    invalid('SECRET_CONSUMER_BINDING');
  const name = reference.slice(
    reference.indexOf('/', 'secret://'.length) + 1,
    reference.lastIndexOf('#'),
  );
  if (name.split('/').some((part) => ['', '.', '..'].includes(part)))
    invalid('SECRET_CONSUMER_BINDING');
  return Object.freeze({ ...testFactCandidateDatabaseConsumer, reference, version });
}
