// Pure cross-language proof vectors. Synthetic state and ephemeral keys test
// the real codecs; they establish no database effect or business authority.
import { createHash, generateKeyPairSync } from 'node:crypto';
import { businessTransitionProfileForOperation } from '../../../packages/security-kernel/src/business-transition/profiles.js';
import { encodeAdmittedReceipt } from '../../../packages/security-kernel/src/business-transition/admitted-receipt.js';
import {
  decodeCbor,
  encodeCbor,
  type CborValue,
} from '../../../packages/security-kernel/src/business-transition/cbor.js';
import {
  evidenceKeyId,
  signReceiptCose,
} from '../../../packages/security-kernel/src/business-transition/cose.js';
import { encodeCommandCommitted } from '../../../packages/security-kernel/src/business-transition/command-event.js';
import { businessSigningTrustPreimage } from '../../../packages/security-kernel/src/business-transition/signing-trust.js';
import { bindDeletionTransition } from '../../../services/control-api/src/evidence/deletion-business-state.js';
import { runtimeArtifactRetirementDigest } from '../../../services/control-api/src/evidence/runtime-artifact-retirement.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import type { MutationContext } from '../../../services/control-api/src/configuration/persistence/types.js';

const id = (n: number) => `01900000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest();
const digest = (value: string) => Buffer.from(value.slice(7), 'hex');
const profile = businessTransitionProfileForOperation('CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH')!;
if (!profile) throw new Error('Physical retirement profile is not admitted');
const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const publicKey = key.publicKey.export({ format: 'der', type: 'spki' });
const secret = key.privateKey.export({ format: 'der', type: 'pkcs8' });
const grant = {
  profileId: profile.profileId,
  profileVersion: 1,
  profileDigest: digest(profile.profileDigest),
  actionIntentId: profile.actionIntentId,
  catalogOperationId: profile.catalogOperationId,
};
const source = {
  participantId: id(1),
  privacyDomainId: id(2),
  runtimeConfigurationInputId: id(3),
  moduleInstallationId: id(4),
  moduleConfigurationGenerationId: id(5),
  configurationDigest: sha256(Buffer.from('source')),
  configurationBytes: 42,
  resourceBindingsDigest: sha256([]),
  createdAt: '2026-09-26T00:00:00.123456Z',
};
const original = { deletionJobId: id(6), source };
const metadata = { ...original, retirementDigest: runtimeArtifactRetirementDigest(original) };
const selection = {
  retentionPolicyId: `urn:openpc:resource:${id(7)}`,
  source,
  disposition: { dispositionId: id(8) },
  nextInput: null,
};
const recorded = 1_800_000_000_000_000_000n;
const authority = Buffer.from(canonicalJson({ decision: 'ALLOW', operationId: id(9) }));
const context = {
  catalogOperationId: profile.catalogOperationId,
  resourceId: id(6),
  authorization: { participantId: id(1), privacyDomainId: id(2), approvalRequestId: id(10) },
} as MutationContext;
const states = bindDeletionTransition(context, id(9), undefined, {
  retentionPolicyId: id(7),
  targetSelectorDigest: sha256({ domain: 'pc.evidence.runtime-artifact-selector.v1', source }),
  eligibilityDigest: sha256(selection),
  beforeDigest: sha256({ domain: 'pc.evidence.runtime-artifact-before.v1', source }),
  afterDigest: sha256({
    domain: 'pc.evidence.runtime-artifact-after.v1',
    retirementDigest: metadata.retirementDigest,
  }),
  attemptId: id(11),
  operationId: id(9),
  approvalRequestId: id(10),
  revision: '1',
  state: 'SUCCEEDED',
  deletedCount: '1',
  deletedBytes: '42',
  retainedAliasCount: '0',
  beforeUsedBytes: '42',
  afterUsedBytes: '0',
  startedAtNs: String(recorded - 2000n),
  completedAtNs: String(recorded - 1000n),
});
const intentDigest = sha256('intent');
const event = encodeCommandCommitted({
  commandId: id(9),
  aggregateRef: `urn:openpc:evidence-deletion:${id(6)}`,
  actionIntentId: profile.actionIntentId,
  intentDigest,
});
function produce(admissionKind: 'BOOTSTRAP' | 'GOVERNED') {
  const trust = businessSigningTrustPreimage({
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'local',
    signerId: evidenceKeyId(publicKey),
    publicKeySpkiDer: publicKey,
    workloadCredentialId: id(12),
    workloadCredentialEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: recorded - 100000n,
    validUntilNs: recorded + 100000n,
    admissionKind,
    admissionReference: 'initial-trust',
    admissionDigest: hash(Buffer.from('admission')),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://local/runtime-retirement#1',
    secretVersion: '1',
    grants: [grant],
  });
  const payload = encodeAdmittedReceipt({
    receiptId: id(13),
    schemaDefinitionDigest: digest(profile.schemaDefinitionDigest),
    transitionProfileId: profile.profileId,
    transitionProfileVersion: 1,
    transitionProfileDigest: digest(profile.profileDigest),
    environmentId: 'local',
    participantId: id(1),
    privacyDomainId: id(2),
    operationId: id(9),
    actionIntentId: profile.actionIntentId,
    catalogOperationId: profile.catalogOperationId,
    aggregateType: 'evidence-deletion',
    aggregateId: id(6),
    actorKeyDigest: hash(Buffer.from('actor')),
    preCommitAuthorityDigest: hash(authority),
    actionIntentDigest: digest(intentDigest),
    candidateDigest: hash(Buffer.from('candidate')),
    idempotencyRecordId: id(14),
    before: states.before.reference,
    after: states.after.reference,
    authorizationEvidence: [
      {
        kind: 3,
        evidenceId: `urn:openpc:resource:${id(10)}`,
        evidenceDigest: hash(Buffer.from('approval')),
      },
      {
        kind: 4,
        evidenceId: `urn:openpc:resource:${id(15)}`,
        evidenceDigest: hash(Buffer.from('step-up')),
      },
    ],
    outboxEvents: [
      {
        eventId: id(16),
        eventType: 'io.openpc.control.command.committed.v1',
        dataSchemaUri:
          'https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted',
        source: 'urn:openpc:service:control-api',
        subject: `urn:openpc:evidence-deletion:${id(6)}`,
        aggregateSequence: 1n,
        occurredAtNs: recorded,
        correlationId: id(9),
        payloadDigest: hash(event),
      },
    ],
    transitionKind: 1,
    recordedAtNs: recorded,
    signerId: evidenceKeyId(publicKey),
    signerTrustSnapshotDigest: hash(trust),
    requestDigest: hash(Buffer.from('request')),
  });
  const base = {
    public: [...publicKey],
    payload: [...payload],
    cose: [...signReceiptCose(secret, publicKey, payload)],
    trust: [...trust],
    before: [...states.before.preimage],
    after: [...states.after.preimage],
    authority: [...authority],
    event: [...event],
    participant: id(1),
    privacy: id(2),
    receipt_id: id(13),
    operation_id: id(9),
    event_id: id(16),
    event_recorded_ns: recorded.toString(),
    metadata,
    selection,
  };
  const malformed = [];
  function changed(name: string, change: (value: Map<number, CborValue>) => void) {
    const receipt = decodeCbor(payload) as Map<number, CborValue>;
    change(receipt);
    const bytes = encodeCbor(receipt);
    malformed.push({
      name,
      value: { ...base, payload: [...bytes], cose: [...signReceiptCose(secret, publicKey, bytes)] },
    });
  }
  for (let i = 0; i < 27; i++)
    changed(`missing ${i}`, (r) => {
      r.delete(i);
    });
  for (const [name, field, value] of [
    ['wrong profile', 2, 'pc.control.other'],
    ['wrong version', 3, 2n],
    ['wrong action', 9, 'ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1'],
    ['wrong operation', 10, 'CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH'],
    ['idempotency type', 17, 'invalid'],
    ['request width', 26, Buffer.alloc(31)],
    ['recorded precision', 23, recorded + 1n],
  ] as const)
    changed(name, (r) => {
      r.set(field, value);
    });
  changed('extra', (r) => {
    r.set(27, 1n);
  });
  changed('reversed authority', (r) => {
    r.set(20, [...(r.get(20) as CborValue[])].reverse());
  });
  changed('missing authority', (r) => {
    r.set(20, (r.get(20) as CborValue[]).slice(0, 1));
  });
  for (const field of [
    'public',
    'trust',
    'before',
    'after',
    'authority',
    'event',
    'cose',
  ] as const) {
    const bytes = [...base[field]];
    bytes[bytes.length - 1] = bytes.at(-1)! ^ 1;
    malformed.push({ name: `tampered ${field}`, value: { ...base, [field]: bytes } });
  }
  for (const field of ['participant', 'privacy', 'receipt_id', 'operation_id', 'event_id'] as const)
    malformed.push({ name: `foreign ${field}`, value: { ...base, [field]: id(99) } });
  malformed.push({
    name: 'substituted source',
    value: { ...base, metadata: { ...metadata, source: { ...source, configurationBytes: 43 } } },
  });
  malformed.push({
    name: 'substituted selection',
    value: {
      ...base,
      selection: { ...selection, nextInput: { runtimeConfigurationInputId: id(99) } },
    },
  });
  return { base, malformed };
}
process.stdout.write(
  JSON.stringify(
    ['BOOTSTRAP', 'GOVERNED'].map((kind) => produce(kind as 'BOOTSTRAP' | 'GOVERNED')),
  ),
);
