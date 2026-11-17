import { z } from 'zod';
import { configurationCoreCommand } from '../core-command.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';
import { digestSchema } from '../resource-contracts.js';
import type { CiglGrantDefinition } from './grant-contract.js';

export function validateCiglGrant(
  grantId: string,
  definition: CiglGrantDefinition,
  status: 'ACTIVE' | 'DISABLED',
) {
  try {
    const grant = {
      grantId,
      ...definition,
      runtimeBindingId: definition.runtimeBindingId.slice('urn:openpc:resource:'.length),
      selector: [...Buffer.from(definition.selector.slice(2), 'hex')],
      status,
    };
    return z
      .strictObject({
        identity: z.literal('PC-CIGL-GRANT-1'),
        authority: z.literal('NONE'),
        grantDigest: digestSchema,
      })
      .parse(configurationCoreCommand('VALIDATE_CIGL_GRANT', grant));
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
}
