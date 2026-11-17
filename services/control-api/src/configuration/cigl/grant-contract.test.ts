import { expect, it } from 'vitest';
import { ciglDependencyBundleSchema } from './dependency-contract.js';
import {
  ciglGrantSubjectSchema,
  createCiglGrantSchema,
  changeCiglGrantSchema,
} from './grant-contract.js';

const id = '019963de-8824-7000-8000-000000000001';
const command = {
  actionIntentId: 'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'ab'.repeat(32)}`,
  reason: 'Review the target method grant.',
  expectedRuntimeBindingRevision: '1',
  expectedMethodRevision: '1',
  definition: {
    runtimeBindingId: `urn:openpc:resource:${id}`,
    selector: '0xa9059cbb',
    subject: { kind: 'ANY_AUTHENTICATED' },
    surface: 'RAW_SUBMISSION',
    effect: 'ALLOW',
  },
};

it('keeps the explicit Any principal distinct from every typed principal identifier', () => {
  expect(ciglGrantSubjectSchema.safeParse({ kind: 'ANY_AUTHENTICATED' }).success).toBe(true);
  expect(ciglGrantSubjectSchema.safeParse({ kind: 'ANY_AUTHENTICATED', id }).success).toBe(false);
  for (const kind of ['ROLE', 'WORKLOAD', 'USER', 'GROUP', 'PARTICIPANT']) {
    const typedId = ['ROLE', 'WORKLOAD'].includes(kind)
      ? `urn:openpc:${kind.toLowerCase()}:${id}`
      : id;
    expect(ciglGrantSubjectSchema.safeParse({ kind, id: typedId }).success).toBe(true);
    for (const value of [
      undefined,
      null,
      '',
      '*',
      'ANY_AUTHENTICATED',
      `urn:openpc:resource:${id}`,
      typedId.replace('-7000-', '-4000-'),
      typedId.replace(/0/g, '-'),
    ])
      expect(ciglGrantSubjectSchema.safeParse({ kind, id: value }).success).toBe(false);
  }
  expect(
    ciglGrantSubjectSchema.safeParse({ kind: 'ROLE', id: `urn:openpc:workload:${id}` }).success,
  ).toBe(false);
});

it('reviews only exact action choices and leaves subject, surface and path derivation to the owner', () => {
  const bundle = {
    profileId: `urn:openpc:resource:${id}`,
    profileRevision: '1',
    profileDigest: command.actionIntentDigest,
    graphDigest: command.actionIntentDigest,
    policyGenerationDigest: command.actionIntentDigest,
    participantEpoch: '1',
    capability: 'EXECUTE_TRANSACTION',
    dependencies: [{ actionDigest: command.actionIntentDigest, grant: { kind: 'GENERATE' } }],
  };
  expect(ciglDependencyBundleSchema.safeParse(bundle).success).toBe(true);
  expect(
    ciglDependencyBundleSchema.safeParse({
      ...bundle,
      dependencies: [...bundle.dependencies, ...bundle.dependencies],
    }).success,
  ).toBe(false);
  for (const field of [
    'subject',
    'surface',
    'runtimeBindingId',
    'relationshipPath',
    'ready',
    'active',
  ])
    expect(
      ciglDependencyBundleSchema.safeParse({
        ...bundle,
        dependencies: [{ ...bundle.dependencies[0], [field]: 'forged' }],
      }).success,
    ).toBe(false);
  const mutation = {
    actionIntentId: 'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: command.actionIntentDigest,
    reason: 'Import reviewed nested-only grants.',
    targetRef: `urn:openpc:resource:${id}`,
    expectedRevision: '1',
    status: 'ACTIVE',
    dependencyBundle: bundle,
  };
  expect(changeCiglGrantSchema.safeParse(mutation).success).toBe(true);
  expect(changeCiglGrantSchema.safeParse({ ...mutation, status: 'DISABLED' }).success).toBe(false);
});

it('binds a grant to exact method revisions without caller-supplied status or profile authority', () => {
  expect(createCiglGrantSchema.safeParse(command).success).toBe(true);
  for (const field of [
    'status',
    'profileId',
    'ready',
    'participantId',
    'actorPrincipalId',
    'grantDigest',
  ]) {
    expect(createCiglGrantSchema.safeParse({ ...command, [field]: 'ACTIVE' }).success).toBe(false);
    expect(
      createCiglGrantSchema.safeParse({
        ...command,
        definition: { ...command.definition, [field]: 'ACTIVE' },
      }).success,
    ).toBe(false);
  }
  for (const runtimeBindingId of [id, `urn:openpc:role:${id}`])
    expect(
      createCiglGrantSchema.safeParse({
        ...command,
        definition: { ...command.definition, runtimeBindingId },
      }).success,
    ).toBe(false);
  for (const expectedMethodRevision of ['0', '01', '18446744073709551616', '-1'])
    expect(createCiglGrantSchema.safeParse({ ...command, expectedMethodRevision }).success).toBe(
      false,
    );
  const update = {
    actionIntentId: 'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1',
    targetRef: `urn:openpc:resource:${id}`,
    actionIntentDigest: command.actionIntentDigest,
    reason: command.reason,
    expectedRevision: '1',
    status: 'DISABLED',
  };
  expect(changeCiglGrantSchema.safeParse(update).success).toBe(true);
  expect(changeCiglGrantSchema.safeParse({ ...update, targetRef: undefined }).success).toBe(false);
  expect(
    changeCiglGrantSchema.safeParse({ ...update, definition: command.definition }).success,
  ).toBe(false);
  expect(changeCiglGrantSchema.safeParse({ ...update, status: 'DELETED' }).success).toBe(false);
});
