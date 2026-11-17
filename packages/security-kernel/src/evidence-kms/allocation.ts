/** Reserved canonical identities only. Definitions, installed provider authority,
 * signing/verification and key custody require their separately admitted owners.
 * These identifiers alone confer no authority and enroll no schema definition. */
export const evidenceKmsAllocations = Object.freeze([
  Object.freeze({
    schemaId: 24015,
    schemaVersion: 1,
    semanticVersion: '1.0.0',
    purposeCode: 352,
    purpose: 'pc.cose.evidence-kms-profile.v1',
    typeName: 'EvidenceKmsProfileV1',
    ownerLane: 'LANE-CONTROL',
    projectionRef: 'schemas/canonical/evidence-kms-profile-v1.json',
  } as const),
  Object.freeze({
    schemaId: 24016,
    schemaVersion: 1,
    semanticVersion: '1.0.0',
    purposeCode: 353,
    purpose: 'pc.cose.evidence-wrapped-key-record.v1',
    typeName: 'EvidenceWrappedKeyRecordV1',
    ownerLane: 'LANE-CONTROL',
    projectionRef: 'schemas/canonical/evidence-wrapped-key-record-v1.json',
  } as const),
  Object.freeze({
    schemaId: 24017,
    schemaVersion: 1,
    semanticVersion: '1.0.0',
    purposeCode: 354,
    purpose: 'pc.cose.evidence-kms-receipt.v1',
    typeName: 'EvidenceKmsReceiptV1',
    ownerLane: 'LANE-CONTROL',
    projectionRef: 'schemas/canonical/evidence-kms-receipt-v1.json',
  } as const),
] as const);

export type EvidenceKmsAllocation = (typeof evidenceKmsAllocations)[number];

/** Shared generator preflight reserves identities without a fabricated digest or
 * placeholder registry entry. Admission remains an explicit generator dispatch
 * after all three definitions and their verifier have been reviewed/integrated. */
export function assertEvidenceKmsAllocations(entries: readonly unknown[]): void {
  for (const allocation of evidenceKmsAllocations) {
    let matches = 0;
    for (const value of entries) {
      if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('Invalid schema registry entry');
      const entry = value as Record<string, unknown>;
      if (
        entry.schemaId !== allocation.schemaId &&
        entry.purposeCode !== allocation.purposeCode &&
        entry.purpose !== allocation.purpose &&
        entry.typeName !== allocation.typeName
      )
        continue;
      matches++;
      if (
        matches !== 1 ||
        entry.schemaId !== allocation.schemaId ||
        entry.purposeCode !== allocation.purposeCode ||
        entry.purpose !== allocation.purpose ||
        entry.typeName !== allocation.typeName ||
        entry.schemaVersion !== allocation.semanticVersion ||
        entry.ownerLane !== allocation.ownerLane ||
        !Array.isArray(entry.projectionRefs) ||
        entry.projectionRefs.length !== 1 ||
        entry.projectionRefs[0] !== allocation.projectionRef
      )
        throw new Error('Evidence KMS canonical allocation collision');
    }
  }
}
