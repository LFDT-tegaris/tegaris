import { z } from 'zod';
import { configurationCoreCommand } from '../core-command.js';
import { ConfigurationRepositoryError } from '../persistence/types.js';
import { digestSchema } from '../resource-contracts.js';
import {
  ciglSettingsArtifactFields,
  ciglSettingsDefinitionSchema,
  type CiglSettingsDefinition,
} from './settings-contract.js';

export function validateCiglSettings(definition: CiglSettingsDefinition) {
  try {
    return z
      .strictObject({
        identity: z.literal('PC-CIGL-SETTINGS-1'),
        authority: z.literal('NONE'),
        definition: ciglSettingsDefinitionSchema,
        definitionDigest: digestSchema,
      })
      .parse(configurationCoreCommand('VALIDATE_CIGL_SETTINGS', definition));
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
}

export function encodeCiglSettingsSource(source: {
  settingsId: string;
  participantId: string;
  privacyDomainId: string;
  publicationOperationId: string;
  publicationAuthorityDigest: string;
  definitionDigest: string;
  definition: CiglSettingsDefinition;
}) {
  try {
    const artifact = z
      .strictObject({
        identity: z.literal('PC-CIGL-SETTINGS-SOURCE-1'),
        authority: z.literal('NONE'),
        ...ciglSettingsArtifactFields,
      })
      .parse(
        configurationCoreCommand('ENCODE_CIGL_SETTINGS_SOURCE', {
          ...source,
          publicationAuthorityDigest: source.publicationAuthorityDigest.slice(7),
          definitionDigest: source.definitionDigest.slice(7),
        }),
      );
    return {
      configurationArtifactCbor: artifact.configurationArtifactCbor,
      configurationArtifactDigest: artifact.configurationArtifactDigest,
    };
  } catch {
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
}
