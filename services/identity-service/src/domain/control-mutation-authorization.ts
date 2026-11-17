/** Shared identity-owned authorization input for control mutations. */
interface ControlMutationAuthority {
  readonly sessionId: string;
  readonly sessionEpoch?: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
  readonly principalEpoch: string;
  readonly checkerPrincipalId?: string;
  readonly approvalRequestId?: string;
  readonly mfaChallengeId?: string;
  readonly webauthnSessionId?: string;
  readonly webauthnSignerCredentialId?: string;
  readonly participantEpoch: string;
  readonly authorityEnvelopeId: string;
  readonly authorityEpoch: string;
  readonly delegationEpoch: string;
  readonly assignmentId: string;
  readonly assignmentEpoch: string;
  readonly webauthnAssertionBindingDigest?: Buffer;
  readonly webauthnEvidenceCbor?: Buffer;
  readonly webauthnEvidenceDigest?: Buffer;
  readonly webauthnCoseSign1?: Buffer;
  readonly evidenceCbor: Buffer;
  readonly evidenceDigest: Buffer;
  readonly coseSign1: Buffer;
}

export type MutationAuthorization = ControlMutationAuthority &
  (
    | {
        readonly evidenceKind: 'USER_WEBAUTHN';
        readonly signerCredentialId: string;
        readonly signerKeyDigest?: never;
      }
    | {
        readonly evidenceKind: 'IDENTITY_RUNTIME';
        readonly signerKeyDigest: Buffer;
        readonly signerCredentialId?: never;
      }
    | {
        readonly evidenceKind: 'IDENTITY_RUNTIME_STEP_UP';
        readonly signerKeyDigest: Buffer;
        readonly signerCredentialId?: never;
        readonly mfaChallengeId: string;
        readonly webauthnSessionId: string;
        readonly webauthnSignerCredentialId: string;
        readonly webauthnAssertionBindingDigest: Buffer;
        readonly webauthnEvidenceCbor: Buffer;
        readonly webauthnEvidenceDigest: Buffer;
        readonly webauthnCoseSign1: Buffer;
      }
    | {
        readonly evidenceKind: 'READ_CONTEXT';
        readonly signerCredentialId?: never;
        readonly signerKeyDigest?: never;
      }
  );
