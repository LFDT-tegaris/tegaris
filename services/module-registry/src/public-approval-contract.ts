import { createHash } from 'node:crypto';
import { z } from 'zod';
import { canonicalJson } from './domain/canonical-json.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const subject = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );

/** Subject resolution remains authoritative. The optional reservation references
 * a server-owned name receipt; it supplies neither a subject selector nor authority. */
export const createApprovalSchema = z.strictObject({
  actionIntentId: z.literal('ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'),
  candidateDigest: digest,
  makerSubjectRef: subject,
  checkerSubjectRef: subject.nullable(),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
  resourceReservationId: z
    .string()
    .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u)
    .optional(),
});

/** Fresh submission WebAuthn binds the exact parsed approval-request body.
 * candidateDigest is the proposal's digest; actionIntentDigest identifies the
 * registered action. Neither is the digest of this submission intent. */
export function approvalCreateIntent(input: unknown) {
  const request = createApprovalSchema.parse(input);
  return {
    request,
    actionIntentId: request.actionIntentId,
    resourceId: request.makerSubjectRef.slice('urn:openpc:resource:'.length),
    intentDigest: `sha256:${createHash('sha256').update(canonicalJson(request)).digest('hex')}`,
  };
}
