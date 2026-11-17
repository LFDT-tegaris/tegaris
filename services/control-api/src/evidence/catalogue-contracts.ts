import { z } from 'zod';
import { resourceUrnSchema, participantUrnSchema } from '../configuration/resource-contracts.js';
import { digest, evidenceClass, sequence } from './segment.js';

const timestamp = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u);
export const evidenceRecordView = z.strictObject({
  evidenceId: resourceUrnSchema,
  participantId: participantUrnSchema,
  evidenceClass,
  recordDigest: digest,
  sequence,
  state: z.enum(['ADMITTED', 'EXPORT_PENDING', 'EXPORTED', 'HELD', 'QUARANTINED']),
  occurredAt: timestamp,
  revision: sequence,
  createdAt: timestamp,
  updatedAt: timestamp,
});
