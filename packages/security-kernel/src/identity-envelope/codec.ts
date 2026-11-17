import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { identityEnvelopeContext as context } from './generated.js';
import type { EnvelopeProposal, EnvelopeScope, IdentityAuthorityEnvelope } from './types.js';

const reject = (): never => {
  throw new Error('Invalid typed authority envelope');
};
const types: Readonly<Record<string, readonly { key: number; name: string; type: string }[]>> =
  context.types;
const enums: Readonly<Record<string, Readonly<Record<string, number>>>> = {
  issuerKind: { PLATFORM: 1, PARTICIPANT: 2 },
  issuance: { PLATFORM_ROOT: 1, CHILD: 2, ROTATION: 3 },
  activateAction: { 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1': 1 },
  activateOperation: { 'ID-OP-ENVELOPE-ACTIVATE': 1 },
};
const risks = new Set(['BREAK_GLASS', 'HIGH', 'LOW', 'STANDARD']);
const capabilities = new Set([
  'ACCESS_LIST_DISCLOSURE',
  'CALL_RESULT_DISCLOSURE',
  'GAS_ESTIMATE_DISCLOSURE',
  'MULTI_CALL_SIMULATION_DISCLOSURE',
  'OPERATION_STATUS_DISCLOSURE',
  'SIGNED_TRANSACTION_SUBMISSION',
  'UNSIGNED_TRANSACTION_PREPARATION',
]);
function h32(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return reject();
  return Buffer.from(value.slice(7), 'hex');
}
function uuid(value: unknown): Buffer {
  if (
    typeof value !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
  )
    return reject();
  return Buffer.from(value.replaceAll('-', ''), 'hex');
}
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u.test(value))
    return reject();
  return value;
}
function uint(value: unknown, positive = false): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/u.test(value)) return reject();
  const result = BigInt(value);
  if (result > MAX_UINT64 || (positive && result === 0n)) return reject();
  return result;
}
function wire(type: string, value: unknown): CborValue {
  const fields = types[type];
  if (fields) {
    if (
      value === null ||
      typeof value !== 'object' ||
      Object.getPrototypeOf(value) !== Object.prototype
    )
      return reject();
    const names = fields
      .filter((field) => field.type !== 'definitionDigest')
      .map((field) => field.name);
    if (Reflect.ownKeys(value).length !== names.length) return reject();
    const result = new Map<number, CborValue>();
    for (const field of fields) {
      if (field.type === 'definitionDigest') {
        result.set(field.key, h32(context.definitionDigest));
        continue;
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, field.name);
      if (!descriptor || !('value' in descriptor)) return reject();
      result.set(field.key, wire(field.type, descriptor.value));
    }
    return result;
  }
  const choices = enums[type];
  if (choices) {
    if (typeof value !== 'string' || !Object.hasOwn(choices, value)) return reject();
    return choices[value]!;
  }
  if (type.endsWith('Set')) {
    if (
      !Array.isArray(value) ||
      value.length > (type === 'riskSet' ? 4 : type === 'capabilitySet' ? 7 : 256)
    )
      return reject();
    const items: CborValue[] = [];
    for (let index = 0; index < value.length; index++) {
      if (!Object.hasOwn(value, index)) return reject();
      const item = id(value[index]);
      if (index > 0 && item <= value[index - 1]) return reject();
      if (type === 'actionSet' && !/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u.test(item))
        return reject();
      if (type === 'riskSet' && !risks.has(item)) return reject();
      if (type === 'capabilitySet' && !capabilities.has(item)) return reject();
      if (!['uuidSet', 'idSet', 'actionSet', 'riskSet', 'capabilitySet'].includes(type))
        return reject();
      items.push(type === 'uuidSet' ? uuid(item) : item);
    }
    return items;
  }
  switch (type) {
    case 'H32':
      return h32(value);
    case 'uuid':
      return uuid(value);
    case 'id':
      return id(value);
    case 'u64':
      return uint(value);
    case 'u64p':
      return uint(value, true);
    case 'nanos': {
      const result = uint(value);
      if (result % 1000n !== 0n) return reject();
      return result;
    }
    case 'depth':
      if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        Object.is(value, -0) ||
        value < 0 ||
        value > 32
      )
        return reject();
      return value;
    case 'flag':
      if (typeof value !== 'boolean') return reject();
      return value ? 1 : 0;
    case 'optionalParent':
      return value === null ? new Map() : wire('Parent', value);
    case 'proposalBytes':
      if (!Buffer.isBuffer(value)) return reject();
      decodeEnvelopeProposal(value);
      return value;
    default:
      return reject();
  }
}
function fromWire(type: string, value: CborValue | undefined): unknown {
  const fields = types[type];
  if (fields) {
    if (!(value instanceof Map) || value.size !== fields.length) return reject();
    const result: Record<string, unknown> = {};
    for (const field of fields) {
      if (!value.has(field.key)) return reject();
      if (field.type === 'definitionDigest') {
        const digest = value.get(field.key);
        if (!Buffer.isBuffer(digest) || !digest.equals(h32(context.definitionDigest)))
          return reject();
      } else result[field.name] = fromWire(field.type, value.get(field.key));
    }
    return result;
  }
  const choices = enums[type];
  if (choices) {
    if (typeof value !== 'bigint') return reject();
    return Object.entries(choices).find(([, number]) => BigInt(number) === value)?.[0] ?? reject();
  }
  if (type.endsWith('Set')) {
    if (!Array.isArray(value)) return reject();
    return value.map((item) => (type === 'uuidSet' ? fromWire('uuid', item) : item));
  }
  switch (type) {
    case 'H32':
      if (!Buffer.isBuffer(value) || value.length !== 32) return reject();
      return `sha256:${value.toString('hex')}`;
    case 'uuid': {
      if (!Buffer.isBuffer(value) || value.length !== 16) return reject();
      const hex = value.toString('hex');
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }
    case 'u64':
    case 'u64p':
    case 'nanos':
      if (typeof value !== 'bigint') return reject();
      return value.toString();
    case 'depth':
      if (typeof value !== 'bigint' || value < 0n || value > 32n) return reject();
      return Number(value);
    case 'flag':
      if (value !== 0n && value !== 1n) return reject();
      return value === 1n;
    case 'id':
      if (typeof value !== 'string') return reject();
      return value;
    case 'optionalParent':
      return value instanceof Map && value.size === 0 ? null : fromWire('Parent', value);
    case 'proposalBytes':
      if (!Buffer.isBuffer(value)) return reject();
      return value;
    default:
      return reject();
  }
}
export function authorityEnvelopeDigest(bytes: Buffer): string {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
function validScope(value: EnvelopeScope) {
  if (BigInt(value.validUntilNs) <= BigInt(value.validFromNs)) return reject();
}
/** The existing frozen Scope wire type, also used by installation upper bounds. */
export function encodeEnvelopeScope(value: EnvelopeScope): Buffer {
  const map = wire('Scope', value);
  validScope(value);
  return encodeCbor(map);
}
export function decodeEnvelopeScope(bytes: Buffer): EnvelopeScope {
  const value = fromWire('Scope', decodeCbor(bytes)) as EnvelopeScope;
  if (!encodeEnvelopeScope(value).equals(bytes)) return reject();
  return value;
}
function validProposal(value: EnvelopeProposal) {
  validScope(value.usable);
  validScope(value.grantable);
  const parent = value.issuer.parent;
  if (value.issuance === 'PLATFORM_ROOT') {
    if (value.issuer.kind !== 'PLATFORM' || parent !== null || value.semanticRevision !== '1')
      return reject();
  } else {
    if (parent === null || parent.envelopeId !== value.issuer.authority.authorityEnvelopeId)
      return reject();
    if (
      parent.authorityEpoch !== value.issuer.authority.authorityEpoch ||
      parent.delegationEpoch !== value.issuer.authority.delegationEpoch
    )
      return reject();
    if (
      value.issuance === 'CHILD' &&
      (parent.envelopeId === value.envelopeId || value.semanticRevision !== '1')
    )
      return reject();
    if (
      value.issuance === 'ROTATION' &&
      (parent.envelopeId !== value.envelopeId ||
        BigInt(value.semanticRevision) !== BigInt(parent.semanticRevision) + 1n)
    )
      return reject();
  }
}
export function encodeEnvelopeProposal(value: EnvelopeProposal): Buffer {
  const map = wire('Proposal', value);
  validProposal(value);
  return encodeCbor(map);
}
export function decodeEnvelopeProposal(bytes: Buffer): EnvelopeProposal {
  const value = fromWire('Proposal', decodeCbor(bytes)) as EnvelopeProposal;
  if (!encodeEnvelopeProposal(value).equals(bytes)) return reject();
  return value;
}
function validEnvelope(value: IdentityAuthorityEnvelope) {
  const proposal = decodeEnvelopeProposal(value.proposalBytes);
  const { submission, activation } = value;
  if (
    value.proposalDigest !== authorityEnvelopeDigest(value.proposalBytes) ||
    value.signer.participantId !== proposal.participantId ||
    submission.candidateId === activation.candidateId ||
    submission.operationId === activation.operationId ||
    submission.approvalRequestId === activation.approvalRequestId ||
    BigInt(submission.approvedVersion) !== BigInt(submission.submittedVersion) + 1n ||
    activation.expectedApprovedVersion !== submission.approvedVersion ||
    BigInt(activation.activeVersion) !== BigInt(activation.expectedApprovedVersion) + 1n ||
    !encodeCbor(wire('Authority', proposal.issuer.authority)).equals(
      encodeCbor(wire('Authority', submission.maker.authority)),
    )
  )
    return reject();
  for (const phase of [submission, activation]) {
    const maker = phase.maker.authority;
    const checker = phase.checker.authority;
    if (
      maker.principalId === checker.principalId ||
      maker.participantId !== checker.participantId ||
      maker.participantId !== proposal.issuer.authority.participantId ||
      phase.maker.stepUpChallengeId === phase.checker.stepUpChallengeId ||
      phase.maker.signerCredentialId === phase.checker.signerCredentialId
    )
      return reject();
  }
  const challenges = [
    submission.maker,
    submission.checker,
    activation.maker,
    activation.checker,
  ].map((actor) => actor.stepUpChallengeId);
  if (new Set(challenges).size !== 4) return reject();
}
export function encodeIdentityAuthorityEnvelope(value: IdentityAuthorityEnvelope): Buffer {
  const map = wire('Envelope', value);
  validEnvelope(value);
  return encodeCbor(map);
}
export function decodeIdentityAuthorityEnvelope(bytes: Buffer): IdentityAuthorityEnvelope {
  const value = fromWire('Envelope', decodeCbor(bytes)) as IdentityAuthorityEnvelope;
  if (!encodeIdentityAuthorityEnvelope(value).equals(bytes)) return reject();
  return value;
}

/** Structural comparison only. The transaction owner must separately prove and
 * fence current Platform/issuer/parent/role/assignment/epoch admission. */
export function assertEnvelopeScopeNarrowing(parent: EnvelopeScope, child: EnvelopeScope): boolean {
  wire('Scope', parent);
  wire('Scope', child);
  validScope(parent);
  validScope(child);
  for (const kind of ['administration', 'runtime'] as const) {
    const before = parent[kind] as unknown as Record<string, string[]>;
    const after = child[kind] as unknown as Record<string, string[]>;
    for (const key of Object.keys(before)) {
      const bound = new Set(before[key]);
      if (after[key]!.some((value) => !bound.has(value))) return reject();
    }
  }
  if (
    BigInt(child.validFromNs) < BigInt(parent.validFromNs) ||
    BigInt(child.validUntilNs) > BigInt(parent.validUntilNs) ||
    (parent.makerCheckerRequired && !child.makerCheckerRequired) ||
    (parent.stepUpRequired && !child.stepUpRequired) ||
    child.onwardDelegationDepth > parent.onwardDelegationDepth
  )
    return reject();
  return !encodeCbor(wire('Scope', parent)).equals(encodeCbor(wire('Scope', child)));
}
export function assertEnvelopeProposalNarrowing(
  parent: IdentityAuthorityEnvelope,
  child: EnvelopeProposal,
): void {
  const parentBytes = encodeIdentityAuthorityEnvelope(parent);
  const original = decodeEnvelopeProposal(parent.proposalBytes);
  encodeEnvelopeProposal(child);
  const ref = child.issuer.parent;
  if (
    ref === null ||
    ref.envelopeId !== original.envelopeId ||
    ref.activeVersion !== parent.activation.activeVersion ||
    ref.semanticRevision !== original.semanticRevision ||
    ref.artifactDigest !== authorityEnvelopeDigest(parentBytes) ||
    ref.authorityEpoch !== original.authorityEpoch ||
    ref.delegationEpoch !== original.delegationEpoch
  )
    return reject();
  if (child.issuance === 'ROTATION') {
    if (child.participantId !== original.participantId) return reject();
    assertEnvelopeScopeNarrowing(original.usable, child.usable);
    assertEnvelopeScopeNarrowing(original.grantable, child.grantable);
  } else if (child.issuance === 'CHILD') {
    const usableStrict = assertEnvelopeScopeNarrowing(original.grantable, child.usable);
    const grantableStrict = assertEnvelopeScopeNarrowing(original.grantable, child.grantable);
    if (
      (!usableStrict && !grantableStrict) ||
      child.usable.onwardDelegationDepth >= original.grantable.onwardDelegationDepth ||
      child.grantable.onwardDelegationDepth >= original.grantable.onwardDelegationDepth
    )
      return reject();
  } else return reject();
}
