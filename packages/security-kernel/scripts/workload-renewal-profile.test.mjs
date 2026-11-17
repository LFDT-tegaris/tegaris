import { describe, expect, it } from 'vitest';
import {
  preservedIdentityAllocations,
  workloadRenewalRegistration,
} from './workload-renewal-profile.mjs';

const definition = () => ({
  name: 'pc.identity.workload-renewal.request',
  typeName: 'WorkloadRenewalRequestV1',
  schemaId: 24038,
  schemaVersion: 1,
  semanticVersion: '1.0.0',
  ownerLane: 'LANE-IDENTITY',
  extensionAuthority: 'POST_C17_R1_COORDINATOR_ADOPTION',
  purpose: { name: 'pc.cose.identity.workload-renewal-request.v1', code: 375 },
  cose: {
    algorithm: 'ES256',
    signatureProfileVersion: 2,
    contentType: 'application/pc+cbor',
    externalAadHex: '7063706c616e653a636f73652d7369676e313a763200',
  },
  types: {},
});
describe('renewal allocation with preserved branch ownership', () => {
  it.each(preservedIdentityAllocations)(
    'rejects occupied or reserved schema $schemaId without local producer source',
    (reservation) => {
      expect(() =>
        workloadRenewalRegistration({ ...definition(), schemaId: reservation.schemaId }, []),
      ).toThrow('reserved');
      expect(() =>
        workloadRenewalRegistration(
          { ...definition(), purpose: { name: 'new', code: reservation.purposeCode } },
          [],
        ),
      ).toThrow('reserved');
    },
  );
  it('rejects supplied immutable registry and canonical union collisions', () => {
    const d = definition();
    const { entry } = workloadRenewalRegistration(d, []);
    expect(workloadRenewalRegistration(d, [entry]).entry).toEqual(entry);
    for (const field of [
      'schemaId',
      'purposeCode',
      'purpose',
      'typeName',
      'schemaDigest',
      'signatureContextRule',
      'projectionRefs',
    ])
      expect(() =>
        workloadRenewalRegistration(d, [
          { ...entry, [field]: field === 'projectionRefs' ? [] : 'changed' },
        ]),
      ).toThrow();
    expect(() => workloadRenewalRegistration(d, [entry, entry])).toThrow();
    for (const other of [
      { name: d.name },
      { schemaId: d.schemaId },
      { purpose: { code: d.purpose.code } },
      { typeName: d.typeName },
    ])
      expect(() => workloadRenewalRegistration(d, [], [other])).toThrow('collision');
    expect(() => workloadRenewalRegistration({ ...d, changedSemantics: true }, [entry])).toThrow(
      'drift',
    );
  });
  it('rejects a different producer relabeled under preserved ownership', () => {
    const reserved = preservedIdentityAllocations[0];
    expect(() =>
      workloadRenewalRegistration(definition(), [
        { ...reserved, typeName: 'WorkloadRenewalRequestV1' },
      ]),
    ).toThrow('ownership drift');
  });
  it('keeps successor proof distinct from admitted Identity policy authorization', () => {
    const request = definition();
    const authorization = {
      ...request,
      name: 'pc.identity.workload-renewal.policy-authorization',
      typeName: 'WorkloadRenewalPolicyAuthorizationV1',
      schemaId: 24039,
      purpose: { name: 'pc.cose.identity.workload-renewal-policy-authorization.v1', code: 376 },
    };
    const { entry } = workloadRenewalRegistration(request, []);
    const registered = workloadRenewalRegistration(authorization, [entry]);
    expect(registered.entry.purposeCode).not.toBe(entry.purposeCode);
    expect(registered.entry.signatureContextRule).toContain('ADMITTED_CURRENT_IDENTITY_KEY');
    expect(entry.signatureContextRule).toContain('PROOF_ONLY');
    expect(() =>
      workloadRenewalRegistration({ ...request, purpose: authorization.purpose }, []),
    ).toThrow('mismatch');
  });
});
