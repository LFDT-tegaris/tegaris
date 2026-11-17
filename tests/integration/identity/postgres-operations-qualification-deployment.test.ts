import { expect, it } from 'vitest';
import { z } from 'zod';
// @ts-expect-error The existing native runtime fixture family executes JS directly.
import * as nativeFixture from '../local-runtime/qualification-deployment-cases.mjs';
const {
  qualificationDeploymentCaseNames,
  qualificationDeploymentClientArguments,
  runQualificationDeploymentCase,
} = nativeFixture;
import { qualificationDeploymentRequestSchema } from '../../../services/control-api/src/configuration/operations/qualification-deployment-observation.js';
const names = z.array(z.string()).length(6).parse(qualificationDeploymentCaseNames);
const integration =
  process.env.OPENPC_I02_ADMIN_DATABASE_URL && process.env.OPENPC_I02_RUNTIME_DATABASE_URL
    ? it
    : it.skip;
it('deployment native dispatch has six distinct required cases and no caller readiness preflight', () => {
  expect(new Set(names).size).toBe(6);
  expect(
    z.array(z.string().max(2048)).length(2).parse(qualificationDeploymentClientArguments)[0],
  ).toBe('-e');
  expect(
    qualificationDeploymentRequestSchema.safeParse({ current: true, qualification: 'ACTIVE' })
      .success,
  ).toBe(false);
});
for (const name of names)
  integration(
    'native deployment ' + name,
    async () => {
      const result: z.infer<typeof output> = await runQualificationDeploymentCase(name);
      expect(output.parse(result)).toEqual({
        name,
        result: 'PASS',
        claim: 'NATIVE_OBSERVATION_ONLY',
      });
    },
    180000,
  );
const output = z.strictObject({
  name: z.string(),
  result: z.literal('PASS'),
  claim: z.literal('NATIVE_OBSERVATION_ONLY'),
});
