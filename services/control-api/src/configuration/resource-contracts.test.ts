import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { createPolicySetSchema } from '../../../module-registry/src/policy-set-contract.js';

import {
  createIndexerProfileSchema,
  createProjectionPlanSchema,
  createRuntimeTargetSchema,
  operationResponseSchema,
  signingOperationResultSchema,
  providerQualificationSchema,
  digestSchema,
  uuidSchema,
  openPcUrnSchema,
} from './resource-contracts.js';

const digest = `sha256:${'a'.repeat(64)}`;
const resourceId = '018f0000-0000-7000-8000-000000000301';
const resourceUrn = `urn:openpc:resource:${resourceId}`;
const envelope = {
  participantId: 'urn:openpc:participant:018f0000-0000-7000-8000-000000000101',
  actionIntentId: 'ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1',
  actionIntentDigest: digest,
  reason: 'adversarial validation',
};
const commandEnvelope = {
  actionIntentId: 'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',
  actionIntentDigest: digest,
  reason: 'adversarial validation',
};

describe('provider, indexer and runtime target input contracts', () => {
  it('rejects padding and every trailing line terminator at the shared identity boundary', () => {
    for (const [schema, value] of [
      [digestSchema, digest],
      [uuidSchema, resourceId],
      [openPcUrnSchema, resourceUrn],
    ] as const) {
      expect(schema.parse(value)).toBe(value);
      for (const padding of [' ', '\t', '\n', '\r', '\r\n', '\u2028', '\u2029']) {
        expect(schema.safeParse(value + padding).success).toBe(false);
        expect(schema.safeParse(padding + value).success).toBe(false);
      }
    }
  });
  it('keeps the canonical policy-set nullable field explicit and the draft input closed', () => {
    const request = {
      ...envelope,
      actionIntentId: 'ACT-POLICY_SETS_CREATE_RESOURCE-V1',
      name: 'Policy draft',
      activeVersionDigest: null,
    };
    expect(createPolicySetSchema.parse(request)).toEqual(request);
    for (const invalid of [
      { activeVersionDigest: undefined },
      { activeVersionDigest: '' },
      { state: 'ACTIVE' },
      { revision: '1' },
      { name: ' ' },
      { name: 'x'.repeat(161) },
    ])
      expect(createPolicySetSchema.safeParse({ ...request, ...invalid }).success).toBe(false);
    const canonical = JSON.parse(
      readFileSync(
        new URL('../../../../schemas/json/control-api.schema.json', import.meta.url),
        'utf8',
      ),
    ).$defs.CreatePolicySetRequest;
    expect(Object.keys(createPolicySetSchema.shape).sort()).toEqual(canonical.required.toSorted());
  });
  it('accepts only the exact indexer engine vocabulary and semantic version', () => {
    const valid = {
      ...envelope,
      engine: 'CLIENT_INDEXER',
      engineVersion: '1.2.3',
      methodProfileDigest: digest,
    };
    expect(createIndexerProfileSchema.safeParse(valid).success).toBe(true);
    expect(
      createIndexerProfileSchema.safeParse({ ...valid, engine: 'AUTHORITATIVE' }).success,
    ).toBe(false);
    expect(
      createIndexerProfileSchema.safeParse({ ...valid, engineVersion: 'latest' }).success,
    ).toBe(false);
    expect(createIndexerProfileSchema.safeParse({ ...valid, extension: true }).success).toBe(false);
  });

  it('distinguishes omitted nullable runtime digests from malformed digests', () => {
    const valid = {
      ...envelope,
      desiredGenerationDigest: null,
      activeGenerationDigest: null,
      xdsVersionDigest: null,
      observedAt: '2026-09-10T00:00:00.000000Z',
    };
    expect(createRuntimeTargetSchema.safeParse(valid).success).toBe(true);
    expect(
      createRuntimeTargetSchema.safeParse({ ...valid, desiredGenerationDigest: 'sha256:abc' })
        .success,
    ).toBe(false);
    expect(
      createRuntimeTargetSchema.safeParse({ ...valid, xdsVersionDigest: undefined }).success,
    ).toBe(false);
  });

  it('binds a provider command target to the resource under authorization', () => {
    const valid = {
      ...commandEnvelope,
      expectedRevision: '1',
      targetRef: resourceUrn,
      inputDigest: digest,
    };
    expect(providerQualificationSchema.safeParse(valid).success).toBe(true);
    expect(
      providerQualificationSchema.safeParse({
        ...valid,
        targetRef: '018f0000-0000-7000-8000-000000000302',
      }).success,
    ).toBe(false);
  });

  it('rejects caller-asserted projection readiness', () => {
    const valid = {
      actionIntentId: 'ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1',
      actionIntentDigest: digest,
      reason: 'adversarial validation',
      indexerProfileId: resourceUrn,
      planDigest: digest,
      readiness: 'UNKNOWN',
    };
    expect(createProjectionPlanSchema.safeParse(valid).success).toBe(true);
    expect(createProjectionPlanSchema.safeParse({ ...valid, readiness: 'READY' }).success).toBe(
      false,
    );
  });

  it('validates the frozen operation response primitives and rejects extensions', () => {
    const valid = {
      operationId: resourceId,
      resourceRef: resourceUrn,
      actionIntentId: 'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',
      intentDigest: digest,
      idempotencyKey: 'provider-qualify-0001',
      state: 'ACCEPTED',
      truthState: 'UNKNOWN',
      createdAt: '2026-09-10T00:00:00.000000Z',
      updatedAt: '2026-09-10T00:00:00.000000Z',
      revision: '1',
    };
    expect(operationResponseSchema.safeParse(valid).success).toBe(true);
    const canonical = JSON.parse(
      readFileSync(
        new URL('../../../../schemas/json/signing-key-rotation.schema.json', import.meta.url),
        'utf8',
      ),
    ).$defs.OperationResult;
    expect(signingOperationResultSchema.shape.kind.options).toEqual(canonical.properties.kind.enum);
    for (const kind of canonical.properties.kind.enum) {
      const signingResult = {
        kind,
        retryable: false,
        originalOperationId: resourceId,
        attemptId: resourceId,
        observationDigest: digest,
      };
      expect(operationResponseSchema.parse({ ...valid, signingResult }).signingResult).toEqual(
        signingResult,
      );
    }
    for (const signingResult of [
      { kind: 'ARBITRARY', retryable: false },
      { kind: 'AUTHORITY_RENEWED' },
      { kind: 'AUTHORITY_RENEWED', retryable: false, secret: true },
      { kind: 'AUTHORITY_RENEWED', retryable: false, attemptId: crypto.randomUUID() },
      { kind: 'AUTHORITY_RENEWED', retryable: false, code: 'ARBITRARY' },
    ])
      expect(operationResponseSchema.safeParse({ ...valid, signingResult }).success).toBe(false);
    expect(operationResponseSchema.safeParse({ ...valid, extension: true }).success).toBe(false);
    expect(
      operationResponseSchema.safeParse({ ...valid, operationId: crypto.randomUUID() }).success,
    ).toBe(false);
  });
});
