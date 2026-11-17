import { expect, it } from 'vitest';
import { EvidenceCustodyError } from './segment.js';
import { sha256 } from '../configuration/digest.js';
import { bindFactAdmissionDelivery } from './fact-delivery-contract.js';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const scope = { participantId: id(1), privacyDomainId: id(2), streamId: id(3) };
const candidate = id(4),
  fact = id(5);
const data = {
  candidateId: `urn:openpc:resource:${candidate}`,
  factArtifactId: `urn:openpc:resource:${candidate}`,
  artifactDigest: `sha256:${'12'.repeat(32)}`,
  sourceProfileDigest: `sha256:${'34'.repeat(32)}`,
  sourceNeutral: true,
};
const event = {
  specversion: '1.0',
  id: fact,
  source: 'urn:openpc:service:LS-FACT-BRIDGE',
  type: 'io.openpc.fact.candidate.admitted.v1',
  subject: data.candidateId,
  time: '2026-09-24T00:00:00.000001Z',
  datacontenttype: 'application/json',
  dataschema:
    'https://schemas.openpc.local/event-payloads.schema.json#/$defs/FactCandidateAdmitted',
  participantid: `urn:openpc:participant:${scope.participantId}`,
  privacydomainid: `urn:openpc:privacy-domain:${scope.privacyDomainId}`,
  correlationid: candidate,
  authoritygeneration: `sha256:${'56'.repeat(32)}`,
  sequence: '9007199254740993',
  datadigest: sha256(data),
  data,
};
const bind = (input: unknown) =>
  bindFactAdmissionDelivery(input, scope, candidate, `urn:openpc:fact:${fact}`);
it('preserves the original event identity and exact sequence without implying readiness', () => {
  expect(bind(event)).toEqual(event);
  expect(bind(structuredClone(event))).toEqual(event);
});
it('rejects substituted scope, Fact, candidate, event family and payload or added authority', () => {
  for (const patch of [
    { id: id(6) },
    { participantid: `urn:openpc:participant:${id(6)}` },
    { privacydomainid: `urn:openpc:privacy-domain:${id(6)}` },
    { subject: `urn:openpc:resource:${id(6)}` },
    { correlationid: id(6) },
    { type: 'io.openpc.fact.shard.published.v1' },
    { ready: true },
    { data: { ...data, sourceNeutral: false } },
    { data: { ...data, artifactDigest: `sha256:${'99'.repeat(32)}` } },
    { sequence: '01' },
    { sequence: '0' },
    { sequence: 1 },
    { sequence: '18446744073709551616' },
  ])
    expect(() => bind({ ...event, ...patch })).toThrow(EvidenceCustodyError);
  const substituted = { ...data, factArtifactId: `urn:openpc:resource:${id(6)}` };
  expect(() => bind({ ...event, data: substituted, datadigest: sha256(substituted) })).toThrow(
    EvidenceCustodyError,
  );
});
