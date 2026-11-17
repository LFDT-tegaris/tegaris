import { authorityEnvelopeDigest, decodeEnvelopeProposal } from '@openpc/security-kernel';
import { z } from 'zod';
import { envelopeScopeSchema } from '@openpc/participant-service/contracts';
import { ContractError } from './domain/errors.js';

const uint64 = z.string().regex(/^(0|[1-9][0-9]{0,19})$/u);

/** Filtered review data, never a canonical signing document or authority grant.
 * The outer candidateDigest binds the original private canonical proposal. */
export const envelopeApprovalCandidateSchema = z.strictObject({
  schema: z.literal('pc.identity.authority-envelope-review'),
  schemaVersion: z.literal(1),
  envelopeId: z.uuid(),
  participantId: z.uuid(),
  semanticRevision: uint64,
  participantEpoch: uint64,
  authorityEpoch: uint64,
  delegationEpoch: uint64,
  issuance: z.enum(['PLATFORM_ROOT', 'CHILD', 'ROTATION']),
  usable: envelopeScopeSchema,
  grantable: envelopeScopeSchema,
});

export function projectEnvelopeApprovalCandidate(bytes: Buffer, candidateDigest: string) {
  try {
    if (authorityEnvelopeDigest(bytes) !== candidateDigest) throw new Error('Digest mismatch');
    const proposal = decodeEnvelopeProposal(bytes);
    return envelopeApprovalCandidateSchema.parse({
      schema: 'pc.identity.authority-envelope-review',
      schemaVersion: 1,
      envelopeId: proposal.envelopeId,
      participantId: proposal.participantId,
      semanticRevision: proposal.semanticRevision,
      participantEpoch: proposal.participantEpoch,
      authorityEpoch: proposal.authorityEpoch,
      delegationEpoch: proposal.delegationEpoch,
      issuance: proposal.issuance,
      usable: proposal.usable,
      grantable: proposal.grantable,
    });
  } catch {
    throw new ContractError('PC-POLICY-2001');
  }
}
