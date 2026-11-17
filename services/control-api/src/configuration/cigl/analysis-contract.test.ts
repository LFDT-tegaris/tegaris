import { readFileSync } from 'node:fs';
import { expect, it } from 'vitest';
import {
  createCiglAnalysisSchema,
  completeCiglAnalysisSchema,
  reviewCiglAnalysisSchema,
  ciglAnalysisDefinitionSchema,
} from './analysis-contract.js';
import { ciglGrantDefinitionSchema } from './grant-contract.js';
import { activateCiglProfilesSchema } from './activation-contract.js';

it('keeps documented console examples valid against their field schemas', () => {
  const guide = readFileSync(
    new URL('../../../../../docs/user-guide/contract-interactions.md', import.meta.url),
    'utf8',
  );
  const example = (heading: string): unknown => {
    const section = guide.split(`### ${heading}\n`)[1];
    if (!section) throw new Error(`Missing documented example: ${heading}`);
    const json = /```json\s*\n([\s\S]*?)\n```/u.exec(section)?.[1];
    if (!json) throw new Error(`Missing JSON example: ${heading}`);
    return JSON.parse(json);
  };
  const analysis = example('Analysis definition');
  expect(ciglAnalysisDefinitionSchema.parse(analysis)).toEqual(analysis);
  const grant = example('Method grant definition');
  expect(ciglGrantDefinitionSchema.parse(grant)).toEqual(grant);
  const profiles = example('Compiled profile selections');
  expect(activateCiglProfilesSchema.shape.profiles.parse(profiles)).toEqual(profiles);
});

const id = '019963de-8824-7000-8000-000000000001';
const ref = `urn:openpc:resource:${id}`;
const digest = `sha256:${'ab'.repeat(32)}`;
const command = {
  actionIntentId: 'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1',
  actionIntentDigest: digest,
  reason: 'Review live method interactions',
  definition: {
    targetRuntimeId: ref,
    expectedGenerationDigest: digest,
    runtimeBindingId: ref,
    contractMethodPolicyId: ref,
    expectedRuntimeBindingRevision: '1',
    expectedMethodRevision: '1',
    workloadId: `urn:openpc:workload:${id}`,
    transactionHash: `0x${'12'.repeat(32)}`,
    expiresInSeconds: 300,
  },
};
it('binds action review to the observed revision without accepting a profile or permissions', () => {
  const input = {
    actionIntentId: 'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1',
    actionIntentDigest: digest,
    reason: 'Review discovered actions',
    targetRef: ref,
    expectedRevision: '2',
    review: {
      analysisDigest: digest,
      actions: [{ actionDigest: digest, maximumValue: Array(32).fill(0) }],
      program: null,
    },
  };
  expect(reviewCiglAnalysisSchema.safeParse(input).success).toBe(true);
  for (const change of [
    { expectedRevision: '1' },
    { targetRef: undefined },
    { profile: { active: true } },
    { runtimePermission: 'ALLOW' },
  ])
    expect(reviewCiglAnalysisSchema.safeParse({ ...input, ...change }).success).toBe(false);
  for (const maximumValue of [[], Array(32).fill(-1), Array(32).fill(256), Array(31).fill(0)])
    expect(
      reviewCiglAnalysisSchema.safeParse({
        ...input,
        review: { ...input.review, actions: [{ actionDigest: digest, maximumValue }] },
      }).success,
    ).toBe(false);
});
it('accepts only bounded job references, never transaction bytes or caller-produced authority', () => {
  expect(createCiglAnalysisSchema.safeParse(command).success).toBe(true);
  for (const field of [
    'signedTransaction',
    'frames',
    'analysis',
    'ready',
    'capsuleDigest',
    'participantId',
    'verificationKey',
  ]) {
    expect(createCiglAnalysisSchema.safeParse({ ...command, [field]: 'supplied' }).success).toBe(
      false,
    );
    expect(
      createCiglAnalysisSchema.safeParse({
        ...command,
        definition: { ...command.definition, [field]: 'supplied' },
      }).success,
    ).toBe(false);
  }
  for (const change of [
    { expiresInSeconds: 29 },
    { expiresInSeconds: 901 },
    { expiresInSeconds: 30.5 },
    { workloadId: ref },
    { targetRuntimeId: id },
    { expectedMethodRevision: '01' },
    { transactionHash: digest },
  ])
    expect(
      createCiglAnalysisSchema.safeParse({
        ...command,
        definition: { ...command.definition, ...change },
      }).success,
    ).toBe(false);
});
it('requires an exact target and immutable first revision for signed observation import', () => {
  const complete = {
    actionIntentId: 'ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1',
    actionIntentDigest: digest,
    reason: 'Retain verified observation',
    targetRef: ref,
    expectedRevision: '1',
    signedReceipt: '0x0102',
  };
  expect(completeCiglAnalysisSchema.safeParse(complete).success).toBe(true);
  for (const change of [
    { targetRef: undefined },
    { expectedRevision: '2' },
    { signedReceipt: '0102' },
    { signedReceipt: '0x0' },
    { signedReceipt: `0x${'00'.repeat(2_097_153)}` },
    { analysis: { ready: true } },
    { verificationKey: 'forged' },
  ])
    expect(completeCiglAnalysisSchema.safeParse({ ...complete, ...change }).success).toBe(false);
});
