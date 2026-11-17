import { createHash, createPublicKey } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { isExactSigningSecretReference } from '../business-transition/secret-reference.js';
import { signConsumerCose, verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { secretRecipientContext as context } from './generated.js';

export const testFactCandidateDatabaseConsumer = Object.freeze({
  profile: 'test',
  providerId: 'test-memory-resolver',
  field: '/postgres/candidateIndexDsnSecretRef',
  workload: 'LS-FACT-BRIDGE',
  secretClass: 'SECRET-DB-CREDENTIAL',
  purpose: 'POSTGRES_CONNECT',
  store: 'STORE-CANDIDATE-INDEX-PG',
  databaseRole: 'openpc_fact_bridge_reader',
  databaseHost: 'candidate-index-pg',
  databasePort: 5432,
  databaseName: 'openpc_candidate_index',
  composeService: 'fact-service',
  entrypoint: '/usr/local/bin/openpc-fact-local-runtime',
  configurationEnvironmentKey: 'OPENPC_FACT_BRIDGE_CONFIGURATION_FILE',
  configurationPath: '/fact-bridge/deployment.json',
  configurationMember: 'candidate_database_url_file',
  mountPath: '/fact-bridge/candidate-url',
  mountReadOnly: true,
  requiredMountBacking: 'EPHEMERAL_MEMORY',
  workloadUid: 65532,
  workloadGid: 65532,
});

export interface SecretRecipientProfile {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  installationDigest: string;
  generation: string;
  consumerId: 'LS-FACT-BRIDGE';
  secretClass: 'SECRET-DB-CREDENTIAL';
  purpose: 'POSTGRES_CONNECT';
  store: 'STORE-CANDIDATE-INDEX-PG';
  reference: string;
  version: string;
  principalId: string;
  workloadCredentialId: string;
  workloadCredentialEpoch: string;
  validFromMs: number;
  validUntilMs: number;
  issuerKeyId: string;
}
const rejected = (): never => {
  throw new Error('Installed secret recipient rejected');
};
const hash = (bytes: Buffer) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
function requireP256(spki: Buffer) {
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
    rejected();
}
const digest = (value: unknown): Buffer => {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return rejected();
  return Buffer.from(value.slice(7), 'hex');
};
const uuid = (value: unknown): Buffer => {
  if (
    typeof value !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
  )
    return rejected();
  return Buffer.from(value.replaceAll('-', ''), 'hex');
};
function validate(value: SecretRecipientProfile) {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== context.fields.length - 1
  )
    rejected();
  for (const field of context.fields.slice(1)) {
    const p = Object.getOwnPropertyDescriptor(value, field.name);
    if (!p || !('value' in p)) rejected();
  }
  if (
    !/^[a-z][a-z0-9-]{2,31}$/u.test(value.environmentId) ||
    value.consumerId !== testFactCandidateDatabaseConsumer.workload ||
    value.secretClass !== testFactCandidateDatabaseConsumer.secretClass ||
    value.purpose !== testFactCandidateDatabaseConsumer.purpose ||
    value.store !== testFactCandidateDatabaseConsumer.store ||
    !isExactSigningSecretReference(value.reference, value.version) ||
    !value.reference.startsWith('secret://test-memory-resolver/') ||
    value.reference
      .slice('secret://test-memory-resolver/'.length, value.reference.lastIndexOf('#'))
      .split('/')
      .some((v) => ['', '.', '..'].includes(v)) ||
    !Number.isSafeInteger(value.validFromMs) ||
    Object.is(value.validFromMs, -0) ||
    value.validFromMs < 0 ||
    !Number.isSafeInteger(value.validUntilMs) ||
    value.validUntilMs <= value.validFromMs
  )
    rejected();
}
export function encodeSecretRecipientProfile(value: SecretRecipientProfile): Buffer {
  validate(value);
  const map = new Map<number, CborValue>([[0, digest(context.definitionDigest)]]);
  for (const field of context.fields.slice(1)) {
    const v = value[field.name as keyof SecretRecipientProfile];
    if (field.type === 'H32') map.set(field.key, digest(v));
    else if (field.type === 'uuidv7') map.set(field.key, uuid(v));
    else if (field.type === 'u64' || field.type === 'u64p') {
      if (
        typeof v !== 'string' ||
        !/^(0|[1-9][0-9]{0,19})$/u.test(v) ||
        BigInt(v) > MAX_UINT64 ||
        (field.type === 'u64p' && v === '0')
      )
        rejected();
      map.set(field.key, BigInt(v));
    } else {
      if (typeof v !== 'string' && typeof v !== 'number') rejected();
      map.set(field.key, v);
    }
  }
  return encodeCbor(map);
}
export function decodeSecretRecipientProfile(payload: Buffer): SecretRecipientProfile {
  const map = decodeCbor(payload);
  if (
    !(map instanceof Map) ||
    map.size !== context.fields.length ||
    !Buffer.isBuffer(map.get(0)) ||
    !map.get(0).equals(digest(context.definitionDigest))
  )
    return rejected();
  const values: Record<string, unknown> = {};
  for (const field of context.fields.slice(1)) {
    const v = map.get(field.key);
    if (field.type === 'H32') {
      if (!Buffer.isBuffer(v) || v.length !== 32) rejected();
      values[field.name] = `sha256:${v.toString('hex')}`;
    } else if (field.type === 'uuidv7') {
      if (!Buffer.isBuffer(v) || v.length !== 16) rejected();
      const h = v.toString('hex');
      values[field.name] =
        `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    } else if (field.type === 'u64' || field.type === 'u64p' || field.type === 'safe_uint') {
      if (typeof v !== 'bigint' || v < 0n || v > MAX_UINT64) rejected();
      values[field.name] = field.type === 'safe_uint' ? Number(v) : v.toString();
    } else {
      if (typeof v !== 'string') rejected();
      values[field.name] = v;
    }
  }
  const result = values as unknown as SecretRecipientProfile;
  if (!encodeSecretRecipientProfile(result).equals(payload)) return rejected();
  return result;
}
export function signSecretRecipientProfile(
  privateKey: Buffer,
  spki: Buffer,
  profile: SecretRecipientProfile,
) {
  requireP256(spki);
  if (profile.issuerKeyId !== evidenceKeyId(spki)) return rejected();
  const payload = encodeSecretRecipientProfile(profile);
  return { payload, cose: signConsumerCose(context, privateKey, spki, payload) };
}
export interface InstalledSecretRecipient {
  readonly issuerSpkiDer: Buffer;
  readonly signedBindingDigest: string;
  readonly installationDigest: string;
  readonly environmentId: string;
  readonly generation: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
  readonly workloadCredentialId: string;
  readonly workloadCredentialEpoch: string;
}
/** Installation pins are trusted server configuration, not fields from a resolver request. */
export function verifyInstalledSecretRecipient(
  installed: InstalledSecretRecipient,
  payload: Buffer,
  cose: Buffer,
  nowMs: number,
): Readonly<SecretRecipientProfile> {
  try {
    requireP256(installed.issuerSpkiDer);
    if (
      !Number.isSafeInteger(nowMs) ||
      nowMs < 0 ||
      hash(cose) !== installed.signedBindingDigest ||
      !verifyConsumerCose(context, installed.issuerSpkiDer, payload, cose)
    )
      return rejected();
    const p = decodeSecretRecipientProfile(payload);
    if (p.issuerKeyId !== evidenceKeyId(installed.issuerSpkiDer)) return rejected();
    for (const key of [
      'installationDigest',
      'environmentId',
      'generation',
      'participantId',
      'privacyDomainId',
      'principalId',
      'workloadCredentialId',
      'workloadCredentialEpoch',
    ] as const)
      if (p[key] !== installed[key]) return rejected();
    if (nowMs < p.validFromMs || nowMs >= p.validUntilMs) return rejected();
    return Object.freeze(p);
  } catch {
    return rejected();
  }
}
