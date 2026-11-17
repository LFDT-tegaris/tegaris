import { expect, it, vi } from 'vitest';
import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from './identity-kernel.js';
import {
  assertEvidenceKeyAdmission,
  withEvidenceKeyRecipient,
  type EvidenceKeyAdmission,
} from './evidence-key-recipient.js';

const request = {
  participantId: '018f0000-0000-7000-8000-000000000001',
  privacyDomainId: '018f0000-0000-7000-8000-000000000002',
  producerTrustDigest: `sha256:${'1'.repeat(64)}`,
  installationDigest: `sha256:${'2'.repeat(64)}`,
};

it('an asserted identity or copied transaction descriptor cannot acquire Evidence admission', () => {
  const admission = {
    installation: {},
    authorityDigest: `sha256:${'3'.repeat(64)}`,
    use: 'ENCRYPT',
  } as EvidenceKeyAdmission;
  const client = {} as PoolClient;
  expect(() => assertEvidenceKeyAdmission(admission, client, request)).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
  expect(() => assertEvidenceKeyAdmission({ ...admission }, client, request)).toThrow(
    'OPS_SECRET_UNRESOLVED',
  );
});

it('rejects caller-authored grant/provider/material fields before SQL or Identity authentication', async () => {
  const connect = vi.fn(),
    authenticateWorkload = vi.fn(),
    operation = vi.fn();
  for (const patch of [
    { admitted: true },
    { owner: 'LS-EVIDENCE-EXPORT' },
    { purpose: 'UNWRAP' },
    { provider: { verified: true } },
    { bytes: Buffer.alloc(32) },
    { credentialId: request.participantId },
    { reference: 'secret://test-kms/key#v1' },
    { privacyDomainId: request.participantId + '\n' },
  ]) {
    await expect(
      withEvidenceKeyRecipient(
        { connect } as unknown as Pool,
        { authenticateWorkload } as unknown as IdentityKernel,
        {} as TLSSocket,
        { ...request, ...patch },
        'ENCRYPT',
        operation,
      ),
    ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  }
  expect(connect).not.toHaveBeenCalled();
  expect(authenticateWorkload).not.toHaveBeenCalled();
  expect(operation).not.toHaveBeenCalled();
});

it('valid-looking scope plus a fabricated socket cannot become a material grant', async () => {
  const connect = vi.fn(),
    authenticateWorkload = vi.fn(),
    operation = vi.fn();
  for (const use of ['ENCRYPT', 'DECRYPT', 'READBACK'] as const)
    await expect(
      withEvidenceKeyRecipient(
        { connect } as unknown as Pool,
        { authenticateWorkload } as unknown as IdentityKernel,
        {} as TLSSocket,
        request,
        use,
        operation,
      ),
    ).rejects.toThrow('OPS_SECRET_UNRESOLVED');
  expect(connect).not.toHaveBeenCalled();
  expect(authenticateWorkload).not.toHaveBeenCalled();
  expect(operation).not.toHaveBeenCalled();
});
