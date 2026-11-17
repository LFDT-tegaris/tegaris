import { expect, it } from 'vitest';
import { sha256 } from '../configuration/digest.js';
import { rpcProvenance, type RpcProvenance } from './rpc-provenance-contract.js';
import { rpcRetirementWitness } from './projection-deletion-contracts.js';
import { rpcProjectionClosedBy, rpcRetirementIdentity } from './rpc-retirement.js';

const id = '018f0000-0000-7000-8000-000000000101',
  digest = sha256('binding');
const base = {
  integrity: 'AEAD_CHAIN_VERIFIED_AT_CUSTODY',
  activationIntegrity: 'ACTIVATION_COSE_VERIFIED_AT_CUSTODY',
  authority: 'NONE',
  currentAuthority: 'NOT_ESTABLISHED',
  providerEffect: 'NOT_ESTABLISHED',
  chainFinality: 'NOT_ESTABLISHED',
  decisionId: id,
  targetRuntimeId: id,
  spoolId: 'rpc',
  sourceSequence: '1',
  sourceDigest: sha256('reserve'),
  capsuleDigest: digest,
  reservedAtNs: '1',
  occurredAtNs: '1',
  transition: {
    phase: 'RESERVED',
    traceId: null,
    requestDigest: digest,
    decisionDigest: null,
    responseDigest: null,
    authorityBindingDigest: null,
    sourceScopeDigest: null,
    operationId: null,
    pcCode: null,
    decisionEffect: null,
    boundary: null,
    sourceSegmentId: 'segment',
    sourceRecordDigest: digest,
    admittedAtNs: '1',
  },
  activation: {
    operationId: id,
    attemptId: id,
    configurationWorkId: id,
    generationId: id,
    generationDigest: digest,
    receiptDigest: digest,
    signerId: 'runtime',
    verificationKeyDigest: digest,
  },
};
function record(
  phase: RpcProvenance['transition']['phase'],
  effect: RpcProvenance['transition']['decisionEffect'] = null,
) {
  const source = phase.startsWith('SOURCE_READ_'),
    decision = ['COMMITTED', 'RELEASED'].includes(phase);
  return rpcProvenance.parse({
    ...base,
    sourceSequence: phase === 'RESERVED' ? '1' : '2',
    sourceDigest: sha256(phase),
    transition: {
      ...base.transition,
      phase,
      decisionEffect: effect,
      decisionDigest: decision ? digest : null,
      pcCode: decision ? 'PC-RUNTIME-0000' : null,
      responseDigest: ['RELEASED', 'SOURCE_READ_RELEASED', 'OPERATION_STATUS_RELEASED'].includes(
        phase,
      )
        ? digest
        : null,
      sourceScopeDigest: source ? digest : null,
      authorityBindingDigest: source || phase === 'OPERATION_STATUS_RELEASED' ? digest : null,
      operationId: phase === 'OPERATION_STATUS_RELEASED' ? id : null,
    },
  });
}
function witness(p: RpcProvenance) {
  return rpcRetirementWitness.parse({
    identityDigest: rpcRetirementIdentity(p),
    terminalEvidenceId: `urn:openpc:resource:${id}`,
    terminalRecordId: `rpc:source:${p.sourceSequence}`,
    terminalSequence: p.sourceSequence,
    terminalSourceDigest: p.sourceDigest,
    terminalProjectionDigest: sha256(p),
    terminalOccurredAtNs: p.occurredAtNs,
    terminalPhase: p.transition.phase,
    terminalEffect: p.transition.decisionEffect,
    terminalDecisionDigest: p.transition.decisionDigest,
    sourceScopeDigest: p.transition.sourceScopeDigest,
    authorityBindingDigest: p.transition.authorityBindingDigest,
  });
}

it('binds read completion and terminal no-forward outcomes without granting chain finality', () => {
  const reserve = record('RESERVED'),
    committed = record('COMMITTED', 'ALLOW_FORWARD'),
    release = record('RELEASED');
  release.sourceSequence = '3';
  const closed = witness(release);
  for (const p of [reserve, committed, release])
    expect(rpcProjectionClosedBy(p, closed)).toBe(true);
  for (const effect of ['DENY_TERMINAL', 'AUTHORIZED_EMPTY', 'WITHHOLD_STALE'] as const) {
    const denied = record('COMMITTED', effect);
    expect(rpcProjectionClosedBy(reserve, witness(denied))).toBe(true);
    expect(rpcProjectionClosedBy(denied, witness(denied))).toBe(true);
  }
  const interrupted = record('INTERRUPTED');
  expect(rpcProjectionClosedBy(reserve, witness(interrupted))).toBe(true);
  expect(rpcProjectionClosedBy(interrupted, witness(interrupted))).toBe(true);
  expect(release.chainFinality).toBe('NOT_ESTABLISHED');
});

it('rejects unrelated, stale, conflicting, status and ambiguous-write completion claims', () => {
  const release = record('RELEASED'),
    closed = witness(release);
  for (const p of [record('OPERATION_STATUS_RELEASED'), record('COMMITTED', 'WRITE_AMBIGUITY')])
    expect(rpcProjectionClosedBy(p, closed)).toBe(false);
  for (const changed of [
    { ...record('RESERVED'), decisionId: id.replace('101', '102') },
    { ...record('RESERVED'), capsuleDigest: sha256('changed') },
    { ...record('RESERVED'), reservedAtNs: '2' },
    { ...record('RESERVED'), sourceSequence: '3' },
    {
      ...record('RESERVED'),
      activation: { ...release.activation, receiptDigest: sha256('other') },
    },
    {
      ...record('COMMITTED', 'ALLOW_FORWARD'),
      transition: {
        ...record('COMMITTED', 'ALLOW_FORWARD').transition,
        decisionDigest: sha256('other'),
      },
    },
  ])
    expect(rpcProjectionClosedBy(changed, closed)).toBe(false);
  expect(
    rpcProjectionClosedBy(release, { ...closed, terminalProjectionDigest: sha256('forged') }),
  ).toBe(false);
});

it('requires the exact source-read authority and does not close an unrelated reservation', () => {
  const started = record('SOURCE_READ_STARTED'),
    released = record('SOURCE_READ_RELEASED');
  released.sourceSequence = '3';
  const closed = witness(released);
  expect(rpcProjectionClosedBy(started, closed)).toBe(true);
  expect(rpcProjectionClosedBy(released, closed)).toBe(true);
  expect(rpcProjectionClosedBy(record('RESERVED'), closed)).toBe(false);
  expect(
    rpcProjectionClosedBy(started, { ...closed, authorityBindingDigest: sha256('other') }),
  ).toBe(false);
  expect(rpcProjectionClosedBy(started, { ...closed, sourceScopeDigest: sha256('other') })).toBe(
    false,
  );
});
