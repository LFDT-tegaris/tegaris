import { decodeAdmittedReceipt } from '@openpc/security-kernel';
import type { BusinessReceiptSigningCapability } from './business-receipt-signer.js';
import {
  businessSigningPurpose,
  BusinessSigningProviderUnknown,
  validateBusinessProviderObservation,
  type BusinessSigningProvider,
  type BusinessProviderRequest,
} from './business-signing-provider.js';

export function createProviderBusinessReceiptSigner(
  provider: BusinessSigningProvider,
  callerWorkloadCredentialId: string,
): BusinessReceiptSigningCapability {
  return {
    async sign({ payload, trust }) {
      const receipt = decodeAdmittedReceipt(payload);
      if (trust.workloadCredentialId !== callerWorkloadCredentialId)
        throw new BusinessSigningProviderUnknown();
      const request: BusinessProviderRequest = {
        method: 'SIGN_RECEIPT',
        participantId: trust.participantId,
        privacyDomainId: trust.privacyDomainId,
        workloadCredentialId: trust.workloadCredentialId,
        callerWorkloadCredentialId,
        environmentId: trust.environmentId,
        secretClass: trust.secretClass,
        purpose: businessSigningPurpose,
        reference: trust.secretReference,
        version: trust.secretVersion,
        expectedFingerprint: trust.signerId,
        attemptId: receipt.receiptId,
        operationId: receipt.operationId,
        payloadHex: payload.toString('hex'),
      };
      // The owning DB transaction retains its key fence while signing. No retry after
      // an ambiguous transport result; rollback exposes neither a receipt nor an event.
      const observation = await provider.perform(request);
      validateBusinessProviderObservation(request, observation);
      const descriptor = observation.descriptor;
      if (
        observation.outcome !== 'SUCCEEDED' ||
        observation.resultHex === null ||
        descriptor === null ||
        descriptor.publicKeySpkiHex !== trust.publicKeySpkiDer.toString('hex') ||
        BigInt(descriptor.validFromNs) !== trust.validFromNs ||
        BigInt(descriptor.validUntilNs) !== trust.validUntilNs
      )
        throw new BusinessSigningProviderUnknown();
      return Buffer.from(observation.resultHex, 'hex');
    },
  };
}
