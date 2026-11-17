import type { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import type { RpcProvenance } from './rpc-provenance-contract.js';
import { rpcRetirementWitness } from './projection-deletion-contracts.js';

export function rpcRetirementIdentity(p: RpcProvenance) {
  return sha256([
    p.decisionId,
    p.targetRuntimeId,
    p.spoolId,
    p.capsuleDigest,
    p.reservedAtNs,
    p.transition.requestDigest,
    p.activation,
  ]);
}

export function rpcProjectionClosedBy(
  p: RpcProvenance,
  witness: z.infer<typeof rpcRetirementWitness>,
) {
  const w = rpcRetirementWitness.parse(witness),
    t = p.transition;
  if (
    w.identityDigest !== rpcRetirementIdentity(p) ||
    BigInt(w.terminalSequence) < BigInt(p.sourceSequence) ||
    BigInt(w.terminalOccurredAtNs) < BigInt(p.occurredAtNs)
  )
    return false;
  const noForward = w.terminalPhase === 'COMMITTED' && w.terminalEffect !== null;
  const ownTerminal =
    w.terminalSourceDigest === p.sourceDigest &&
    w.terminalProjectionDigest === sha256(p) &&
    w.terminalSequence === p.sourceSequence &&
    w.terminalPhase === t.phase;
  switch (t.phase) {
    case 'RESERVED':
      return w.terminalPhase === 'INTERRUPTED' || w.terminalPhase === 'RELEASED' || noForward;
    case 'SOURCE_READ_STARTED':
      return (
        w.terminalPhase === 'SOURCE_READ_RELEASED' &&
        w.sourceScopeDigest === t.sourceScopeDigest &&
        w.authorityBindingDigest === t.authorityBindingDigest
      );
    case 'COMMITTED':
      return t.decisionEffect === 'ALLOW_FORWARD'
        ? w.terminalPhase === 'RELEASED' && w.terminalDecisionDigest === t.decisionDigest
        : ownTerminal && noForward && w.terminalEffect === t.decisionEffect;
    case 'INTERRUPTED':
    case 'RELEASED':
    case 'SOURCE_READ_RELEASED':
      return ownTerminal;
    default:
      return false;
  }
}
