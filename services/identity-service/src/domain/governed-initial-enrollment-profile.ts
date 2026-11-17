import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import {
  governedInitialEnrollmentProfileSchema,
  type GovernedInitialEnrollmentProfile,
} from './governed-initial-enrollment.js';

/** Optional, bounded operator configuration. It cannot enable this path
 * outside the explicit local QA runtime or select a different issuer/scope. */
export async function readGovernedInitialEnrollmentProfile(input: {
  readonly path?: string;
  readonly localQaEnabled: boolean;
  readonly origin: string;
  readonly issuer: string;
  readonly audience: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
}): Promise<GovernedInitialEnrollmentProfile | undefined> {
  if (input.path === undefined) return undefined;
  if (!input.localQaEnabled) throw new Error('Governed first enrollment requires local QA');
  const file = await open(
    input.path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  let value: unknown;
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size === 0 || stat.size > 65_536)
      throw new Error('Invalid governed enrollment profile size');
    const data = Buffer.alloc(65_537);
    let length = 0;
    while (length < data.length) {
      const read = await file.read(data, length, data.length - length, null);
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
    }
    if (length === 0 || length > 65_536)
      throw new Error('Invalid governed enrollment profile size');
    value = JSON.parse(data.subarray(0, length).toString('utf8'));
  } finally {
    await file.close();
  }
  const profile = governedInitialEnrollmentProfileSchema.parse(value);
  if (
    profile.origin !== input.origin ||
    profile.accounts.some(
      (account) =>
        account.participantId !== input.participantId ||
        account.privacyDomainId !== input.privacyDomainId ||
        account.issuer !== input.issuer ||
        account.audience !== input.audience,
    )
  )
    throw new Error('Governed enrollment profile does not match the configured runtime');
  return profile;
}
