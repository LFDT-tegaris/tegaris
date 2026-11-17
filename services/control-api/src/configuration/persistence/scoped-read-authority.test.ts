import type { Pool } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { ScopedConfigurationRead, type ReadContext } from './scoped-read.js';

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const authority = {
  participantId: id(101),
  privacyDomainId: id(201),
  principalId: id(111),
  sessionId: id(701),
  sessionEpoch: '1',
  participantEpoch: '1',
  principalEpoch: '1',
  assignmentId: id(801),
  assignmentEpoch: '1',
  authorityEnvelopeId: id(901),
  authorityEpoch: '2',
  delegationEpoch: '1',
  evidenceKind: 'READ_CONTEXT',
  evidenceCbor: Buffer.alloc(0),
  evidenceDigest: Buffer.alloc(0),
  coseSign1: Buffer.alloc(0),
} as const;
const context: ReadContext = {
  authorization: authority,
  actionIntentId: 'ACT-PROVIDER_PROFILES_READ_COLLECTION-V1',
  resourceType: 'provider-profiles',
  resourceId: id(101),
};
function fixture(change: Readonly<Record<string, string | undefined>> = {}, rowCount = 1) {
  const live = { ...authority, assignmentRowVersion: authority.assignmentEpoch, ...change };
  const statements: string[] = [];
  const query = vi.fn(async (sql: string) => {
    statements.push(sql);
    if (sql.startsWith('with recursive authority_chain'))
      return { rowCount, rows: rowCount === 0 ? [] : [live] };
    if (sql.includes('select 1 from control.action_intent')) return { rowCount: 1, rows: [{}] };
    return { rowCount: 0, rows: [] };
  });
  const release = vi.fn();
  const pool = { connect: vi.fn(async () => ({ query, release })) } as unknown as Pool;
  const read = vi.fn(async () => 'visible current data');
  return { owner: new ScopedConfigurationRead(pool), statements, read, release };
}
describe('authority at the durable configuration read boundary', () => {
  it('resolves live authority inside the actual read snapshot before returning data', async () => {
    const f = fixture();
    await expect(f.owner.execute(context, f.read)).resolves.toBe('visible current data');
    expect(f.read).toHaveBeenCalledOnce();
    expect(f.statements.find((sql) => sql.startsWith('with recursive'))).toContain(
      'platform_authority_epoch',
    );
    expect(f.statements.at(-1)).toBe('commit');
    expect(f.release).toHaveBeenCalledOnce();
  });
  it.each([
    { sessionEpoch: '2' },
    { authorityEpoch: '1' },
    { principalEpoch: '2' },
    { participantEpoch: '2' },
    { assignmentRowVersion: '2' },
    { delegationEpoch: '2' },
  ])('rejects changed authority %j before exposing data', async (change) => {
    const f = fixture(change);
    await expect(f.owner.execute(context, f.read)).rejects.toThrow('PC-AUTH-0005');
    expect(f.read).not.toHaveBeenCalled();
    expect(f.statements.at(-1)).toBe('rollback');
    expect(f.statements).not.toContain('commit');
  });
  it.each([0, 2])('rejects unavailable or ambiguous live authority (%i)', async (rowCount) => {
    const f = fixture({}, rowCount);
    await expect(f.owner.execute(context, f.read)).rejects.toThrow('PC-AUTH-0005');
    expect(f.read).not.toHaveBeenCalled();
  });
});
