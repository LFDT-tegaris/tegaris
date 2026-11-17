import { z } from 'zod';
import { realpath, lstat } from 'node:fs/promises';
import { parseConfigurationJson } from './installation-config-inputs.mjs';
import {
  qualificationObserverFileSchema as path,
  readQualificationObserverFile,
} from '../../services/identity-service/src/domain/qualification-observer-client.ts';
import {
  qualificationDeploymentSelectionSchema,
  qualificationDeploymentIntentSchema,
} from './qualification-deployment-observation.mjs';
import { qualificationKeySelectionSchema } from '../../services/control-api/src/configuration/operations/qualification-key-custody.ts';
const fileSet = z.strictObject({ caFile: path, certificateFile: path, privateKeyFile: path });
export const installationQualificationInputSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    repositoryRoot: path,
    identityConnectionFile: path,
    ownerConnectionFile: path,
    tls: fileSet,
    listen: z.strictObject({
      address: z.ipv4().refine((v) => v !== '0.0.0.0'),
      port: z.number().int().min(1).max(65535),
    }),
    deployment: z.strictObject({
      selection: qualificationDeploymentSelectionSchema,
      intent: qualificationDeploymentIntentSchema,
    }),
    keyOriginal: z
      .strictObject({ selection: qualificationKeySelectionSchema, attemptId: z.uuidv7() })
      .optional(),
    resources: z.strictObject({
      memoryGiB: z.number().int().min(1).max(2),
      externalMemoryGiB: z.number().min(0).max(16).multipleOf(0.125),
      peakDiskGiB: z.number().int().min(1).max(40),
    }),
    drainTimeoutMs: z.number().int().min(35000).max(45000),
  })
  .superRefine((v, c) => {
    if (
      v.identityConnectionFile === v.ownerConnectionFile ||
      v.tls.privateKeyFile === v.tls.certificateFile ||
      (v.keyOriginal &&
        (v.keyOriginal.selection.participantId !== v.deployment.selection.participantId ||
          v.keyOriginal.selection.privacyDomainId !== v.deployment.selection.privacyDomainId))
    )
      c.addIssue({ code: 'custom', message: 'Installation observer input rejected' });
  });
export async function readInstallationQualificationInputs(file) {
  const raw = await readQualificationObserverFile(file, 16384);
  try {
    const input = installationQualificationInputSchema.parse(parseConfigurationJson(raw, 16384));
    const directory = await lstat(input.repositoryRoot);
    if (
      !directory.isDirectory() ||
      directory.isSymbolicLink() ||
      (await realpath(input.repositoryRoot)) !== input.repositoryRoot
    )
      throw new Error('QUALIFICATION_OBSERVER_INPUT_REJECTED');
    return input;
  } finally {
    raw.fill(0);
  }
}
export function parseInstallationQualificationArguments(args) {
  if (
    args.length !== 2 ||
    !['--serve', '--read-deployment-original', '--read-key-original'].includes(args[0])
  )
    throw new Error('QUALIFICATION_OBSERVER_ARGUMENT_REJECTED');
  return { mode: args[0], inputFile: path.parse(args[1]) };
}
