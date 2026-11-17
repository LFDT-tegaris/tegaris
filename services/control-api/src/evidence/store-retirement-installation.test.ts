import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { expect, it } from 'vitest';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import {
  validateStoreRetirementInstallation,
  type StoreRetirementInstallation,
} from './store-retirement-installation.js';

const publicKey = (curve = 'prime256v1') =>
  generateKeyPairSync('ec', { namedCurve: curve }).publicKey.export({
    type: 'spki',
    format: 'der',
  });
const pins: StoreRetirementInstallation = {
  host: {
    environment_id: 'TEST',
    target_id: 'fact-test',
    store: 'openpc_facts',
    scope: {
      participant_id: localOperationId(),
      privacy_domain_id: localOperationId(),
    },
  },
  controlSpki: publicKey(),
  targetSpki: publicKey(),
  verifierSecret: randomBytes(32),
  databaseRole: 'openpc_test_worker',
  workloadCredentialId: localOperationId(),
  workloadCredentialEpoch: '1',
  validFromMs: 1,
  validUntilMs: 2000,
  installationReference: 'TEST initial trust',
};

it.each(['openpc_facts', 'openpc_candidate_index'] as const)(
  'validates exact separate P-256 public roles for %s without claiming installed or current authority',
  (store) => {
    const original = Buffer.from(pins.verifierSecret);
    const installed = { ...pins, host: { ...pins.host, store } };
    expect(validateStoreRetirementInstallation(installed)).toEqual(installed);
    expect(pins.verifierSecret).toEqual(original);
  },
);

it.each([
  { controlSpki: pins.targetSpki },
  { controlSpki: publicKey('secp384r1') },
  { targetSpki: Buffer.concat([pins.targetSpki, Buffer.from([0])]) },
  { targetSpki: Buffer.alloc(91) },
  { verifierSecret: Buffer.alloc(31) },
  { databaseRole: 'worker; select true' },
  { workloadCredentialId: 'caller' },
  { workloadCredentialEpoch: '18446744073709551616' },
  { workloadCredentialEpoch: '01' },
  { validFromMs: 2000 },
  { validUntilMs: Number.MAX_SAFE_INTEGER + 1 },
  { installationReference: '' },
  { host: { ...pins.host, store: 'openpc_control' } },
  { host: { ...pins.host, scope: { ...pins.host.scope, participant_id: 'foreign' } } },
  { eligibility: true },
])(
  'rejects malformed or unsupported installation pins before database allocation: %j',
  (changed) => {
    expect(() =>
      validateStoreRetirementInstallation({ ...pins, ...changed } as StoreRetirementInstallation),
    ).toThrow('Store retirement installation rejected');
  },
);
