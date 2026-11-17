import { controlMutationForAction } from '@openpc/security-kernel';
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { identityGovernanceOperations } from './principal-operations.js';
import { signingCandidateConstraintSql } from '../db/signing-candidate-catalog.js';

describe('Identity public governance and shared authorization catalogue', () => {
  it('carries the current authorization catalogue into the generated database constraint', async () => {
    const root = new URL('../../../../migrations/postgres/identity/meta/', import.meta.url);
    const journal = JSON.parse(await readFile(new URL('_journal.json', root), 'utf8')) as {
      entries: { idx: number }[];
    };
    const latest = journal.entries.at(-1)!;
    const snapshot = JSON.parse(
      await readFile(new URL(`${String(latest.idx).padStart(4, '0')}_snapshot.json`, root), 'utf8'),
    ) as { tables: Record<string, { checkConstraints: Record<string, { value: string }> }> };
    expect(
      snapshot.tables['control.mutation_candidate']?.checkConstraints
        .mutation_candidate_catalog_operation_ck?.value,
    ).toBe(signingCandidateConstraintSql);
  });
  it.each(identityGovernanceOperations.filter((operation) => operation.makerCheckerRequired))(
    'admits the exact declared protection requirements for $id',
    (operation) => {
      expect(controlMutationForAction(operation.actionIntentId, operation.id)).toMatchObject({
        catalogOperationId: operation.id,
        actionIntentId: operation.actionIntentId,
        makerCheckerRequired: operation.makerCheckerRequired,
        stepUpRequired: operation.webauthnStepUpRequired,
      });
    },
  );
});
