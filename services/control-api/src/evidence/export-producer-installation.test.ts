import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { validateEvidenceExportProducerInstallation } from './export-producer-installation.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
  type: 'spki',
  format: 'der',
});
const pins = {
  owner: 'LS-EVIDENCE-EXPORT',
  purpose: 'pc.cose.evidence-export-completion-receipt.v1',
  environmentId: 'local-export',
  participantId: id(1),
  privacyDomainId: id(2),
  sourceId: id(3),
  principalId: id(4),
  workloadCredentialId: id(5),
  workloadEpoch: '1',
  workloadId: 'export-worker',
  secretClass: 'SECRET-SIGNING-KEY',
  secretReference: 'secret://test-export/signer#v1',
  secretVersion: 'v1',
  publicKeySpkiHex: spki.toString('hex'),
  keyEpoch: '1',
  validFromNs: '1800000000000000000',
  validUntilNs: '1800000600000000000',
  installationReference: 'local-initial-trust',
};

it('binds the complete installed producer tuple and separate receipt purpose into retained trust', () => {
  const installed = validateEvidenceExportProducerInstallation(pins);
  expect(installed.bytes).toEqual(Buffer.from(canonicalJson(installed.trust)));
  expect(installed.digest).toBe(sha256(installed.bytes));
  expect(installed.pins).toEqual(pins);
  for (const patch of [
    { sourceId: id(9) },
    { workloadCredentialId: id(9) },
    { privacyDomainId: id(9) },
    { workloadEpoch: '2' },
    { keyEpoch: '2' },
    { environmentId: 'other' },
    { secretReference: 'secret://test-export/signer#v2', secretVersion: 'v2' },
  ])
    expect(validateEvidenceExportProducerInstallation({ ...pins, ...patch }).digest).not.toBe(
      installed.digest,
    );
  expect(installed).not.toHaveProperty('authorized');
});

it('rejects another owner, shared encryption purpose, alias/version ambiguity, malformed keys and missing pins', () => {
  const otherCurve = generateKeyPairSync('ec', { namedCurve: 'secp384r1' })
    .publicKey.export({ type: 'spki', format: 'der' })
    .toString('hex');
  for (const patch of [
    { owner: 'LS-NOTIFICATION' },
    { purpose: 'pc.cose.control-business-transition.v1' },
    { secretClass: 'SECRET-EVIDENCE-VAULT' },
    { secretReference: 'secret://test-export/signer#latest', secretVersion: 'latest' },
    { secretVersion: 'v2' },
    { publicKeySpkiHex: otherCurve },
    { publicKeySpkiHex: '00'.repeat(91) },
    { workloadEpoch: '0' },
    { keyEpoch: '-1' },
    { keyEpoch: '18446744073709551616' },
    { validFromNs: 'not-an-integer' },
    { validUntilNs: pins.validFromNs },
    { validUntilNs: '1800000600000000001' },
    { participantId: id(1) + '\n' },
    { workloadId: 'export-worker\n' },
    { privateKey: 'private-canary' },
    { installed: true },
  ]) {
    expect(() => validateEvidenceExportProducerInstallation({ ...pins, ...patch })).toThrow(
      'Evidence export producer installation rejected',
    );
  }
  for (const key of Object.keys(pins)) {
    const missing = { ...pins } as Record<string, unknown>;
    delete missing[key];
    expect(() => validateEvidenceExportProducerInstallation(missing)).toThrow(
      'Evidence export producer installation rejected',
    );
  }
});
