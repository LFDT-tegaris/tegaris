import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { resourceUrnSchema } from '../configuration/resource-contracts.js';
import { digest, EvidenceCustodyError, type EvidenceScope } from './segment.js';

/** AF-08's closed FactCandidateAdmitted event; no event grants current readiness. */
export const factAdmissionDelivery = z.strictObject({
  specversion: z.literal('1.0'),
  id: z.uuidv7(),
  source: z.literal('urn:openpc:service:LS-FACT-BRIDGE'),
  type: z.literal('io.openpc.fact.candidate.admitted.v1'),
  subject: resourceUrnSchema.regex(/^urn:openpc:resource:/u),
  time: z.iso.datetime({ precision: 6 }),
  datacontenttype: z.literal('application/json'),
  dataschema: z.literal(
    'https://schemas.openpc.local/event-payloads.schema.json#/$defs/FactCandidateAdmitted',
  ),
  participantid: resourceUrnSchema.regex(/^urn:openpc:participant:/u),
  privacydomainid: resourceUrnSchema.regex(/^urn:openpc:privacy-domain:/u),
  correlationid: z.uuidv7(),
  authoritygeneration: digest,
  sequence: z
    .string()
    .regex(/^[1-9][0-9]{0,19}$/u)
    .refine((value) => BigInt(value) <= 18446744073709551615n),
  datadigest: digest,
  data: z.strictObject({
    candidateId: resourceUrnSchema.regex(/^urn:openpc:resource:/u),
    factArtifactId: resourceUrnSchema.regex(/^urn:openpc:resource:/u),
    artifactDigest: digest,
    sourceProfileDigest: digest,
    sourceNeutral: z.literal(true),
  }),
});
export type FactAdmissionDelivery = z.infer<typeof factAdmissionDelivery>;

/** Only used after the native owner has verified the original Fact and producer row. */
export function bindFactAdmissionDelivery(
  input: unknown,
  scope: EvidenceScope,
  candidateId: string,
  factId: string,
): FactAdmissionDelivery {
  const parsed = factAdmissionDelivery.safeParse(input);
  if (!parsed.success) throw new EvidenceCustodyError('INTEGRITY');
  const event = parsed.data;
  if (
    event.participantid !== `urn:openpc:participant:${scope.participantId}` ||
    event.privacydomainid !== `urn:openpc:privacy-domain:${scope.privacyDomainId}` ||
    `urn:openpc:fact:${event.id}` !== factId ||
    event.subject !== `urn:openpc:resource:${candidateId}` ||
    event.correlationid !== candidateId ||
    event.data.candidateId !== event.subject ||
    event.data.factArtifactId !== event.subject ||
    event.datadigest !== sha256(event.data)
  )
    throw new EvidenceCustodyError('INTEGRITY');
  return event;
}
