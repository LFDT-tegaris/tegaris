import type { PolicySemanticDocument } from './policy-semantics.js';

// Wire types only; pc-policy-core owns validation, compilation and evaluation.
export type VisibilitySelector =
  | {
      readonly kind: 'STATE_READ';
      readonly contractMethodPolicyId: string;
      readonly revision: string;
    }
  | {
      readonly kind: 'EVENT';
      readonly runtimeBindingId: string;
      readonly bindingRevision: string;
      readonly abiDigest: string;
      readonly eventSignature: string;
    }
  | {
      readonly kind: 'TRANSACTION' | 'RECEIPT';
      readonly runtimeBindingId: string;
      readonly bindingRevision: string;
    }
  | {
      readonly kind: 'DISCLOSURE';
      readonly profileId: string;
      readonly profileDigest: string;
      readonly dataClassId: string;
    };

export interface VisibilityPolicy {
  readonly policyId: string;
  readonly selector: VisibilitySelector;
  readonly mode: 'STATIC' | 'DYNAMIC';
  readonly effect: 'ALLOW' | 'DENY';
  readonly subject:
    | { readonly kind: 'PRINCIPAL'; readonly principalId: string }
    | { readonly kind: 'WORKLOAD'; readonly workloadId: string };
  readonly purpose: string;
  readonly requiredRoles: readonly string[];
  readonly dimensions: readonly ('EXISTENCE' | 'METADATA' | 'PAYLOAD' | 'EVIDENCE' | 'EXPORT')[];
  readonly fields: readonly string[];
  readonly conditions: NonNullable<PolicySemanticDocument['factConditions']>;
}

/** Configuration-owner projection, never accepted from policy authoring. */
export interface AdmittedVisibilityResource {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly selector: VisibilitySelector;
  readonly availableFields: readonly string[];
  readonly contractBinding?: {
    readonly chainId: string;
    readonly networkId: string;
    readonly genesisDigest: string;
    readonly contractAddress: string;
    readonly codeDigest: string;
    readonly abiDigest: string;
    readonly canonicalAbi: readonly unknown[];
  };
}
