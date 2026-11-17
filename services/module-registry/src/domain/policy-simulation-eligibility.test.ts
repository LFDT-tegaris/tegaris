import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
vi.mock('./digest.js', () => ({
  pcCbor1: (value: unknown) => ({ bytes: Buffer.from(JSON.stringify(value)) }),
}));
import { isReleaseSimulation, releaseSimulationSql } from './policy-simulation-eligibility.js';

function completedDenial() {
  const inputBytes = Buffer.from('immutable complete evaluator input');
  const inputDigest = createHash('sha256').update(inputBytes).digest();
  const projection = {
    evaluatorIdentity: 'PC-POLICY-EVALUATOR-1/PC-CBOR-1',
    truthState: 'DENIED',
    permissions: [],
    obligations: [],
    conflicts: [],
    explanationCodes: ['TYPED_RPC_POLICY_DENY'],
    inputDigest: inputDigest.toString('hex'),
  };
  const resultBytes = Buffer.from(JSON.stringify(projection));
  const resultDigest = createHash('sha256').update(resultBytes).digest();
  return {
    truthState: 'DENIED',
    authorityLabel: 'SIMULATION_ONLY',
    inputDigest,
    resultDigest,
    resultDocument: {
      ...projection,
      inputBytes: inputBytes.toString('hex'),
      resultBytes: resultBytes.toString('hex'),
      resultDigest: resultDigest.toString('hex'),
    },
  };
}

describe('release simulation eligibility', () => {
  it('preserves existing successful simulation and requires simulation-only authority', () => {
    expect(isReleaseSimulation({ truthState: 'SUCCESS', authorityLabel: 'SIMULATION_ONLY' })).toBe(
      true,
    );
    expect(isReleaseSimulation({ truthState: 'SUCCESS', authorityLabel: 'EXECUTION' })).toBe(false);
  });
  it('accepts canonical complete explicit RPC denial without granting permission', () => {
    const input = completedDenial();
    expect(isReleaseSimulation(input)).toBe(true);
    expect(input.resultDocument.truthState).toBe('DENIED');
    expect(input.resultDocument.permissions).toEqual([]);
  });
  it.each(['DENIED', 'STALE', 'PARTIAL', 'CONFLICTING', 'AUTHORIZED_EMPTY'])(
    'rejects %s without explicit complete denial provenance',
    (truthState) => {
      expect(
        isReleaseSimulation({ ...completedDenial(), truthState, resultDocument: undefined }),
      ).toBe(false);
    },
  );
  it('rejects generic invocation denial, permissions, conflicts and missing obligations', () => {
    for (const changed of [
      { explanationCodes: ['TYPED_CONTRACT_DENY'] },
      { permissions: ['eth_call'] },
      { conflicts: ['overlap'] },
      { obligations: ['MISSING_ROLE'] },
    ]) {
      const input = completedDenial();
      expect(
        isReleaseSimulation({ ...input, resultDocument: { ...input.resultDocument, ...changed } }),
      ).toBe(false);
    }
  });
  it('rejects substituted input, result digest, canonical bytes and projection', () => {
    const input = completedDenial();
    for (const changed of [
      { inputBytes: '00' },
      { resultBytes: '00' },
      { resultDigest: 'ff'.repeat(32) },
      { truthState: 'SUCCESS' },
      { evaluatorIdentity: 'untrusted' },
    ]) {
      expect(
        isReleaseSimulation({ ...input, resultDocument: { ...input.resultDocument, ...changed } }),
      ).toBe(false);
    }
    expect(isReleaseSimulation({ ...input, resultDigest: Buffer.alloc(32) })).toBe(false);
  });
  it('selects explicit evaluator evidence without accepting generic denial or unsafe aliases', () => {
    expect(releaseSimulationSql('simulation')).toContain('TYPED_RPC_POLICY_DENY');
    expect(releaseSimulationSql('simulation')).toContain('simulation.result_digest');
    expect(() => releaseSimulationSql('simulation;select')).toThrow();
  });
});
