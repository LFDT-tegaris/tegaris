import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { encodeCbor } from '../../../../packages/security-kernel/src/business-transition/cbor.js';
import {
  decodePolicyArtifactPayload,
  encodePolicyArtifactPayload,
  policyArtifactCoseContext,
} from './policy-artifact.js';
import { pcCbor1 } from './digest.js';
import { ContractError } from './errors.js';
import { policySemanticSchemaDigest, validatePolicySemantics } from './policy-semantics.js';

/** Compiler integrity only. Versions still need independent approval, release
 * and activation. No signing key or owner-supplied readiness enters the UI. */
export interface PolicyArtifactCompilerSigner {
  readonly publicKeySpkiDer: Buffer;
  sign(payload: Buffer): Buffer;
}

export function createPolicyArtifactCompilerSigner(
  privateKeyPem: string,
): PolicyArtifactCompilerSigner {
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
    throw new Error('Policy compiler key rejected');
  const publicKeySpkiDer = createPublicKey(key).export({ format: 'der', type: 'spki' });
  return {
    publicKeySpkiDer,
    sign(payload) {
      decodePolicyArtifactPayload(payload);
      const headers = encodeCbor(
        new Map<number, number | string | Buffer>([
          [1, -7],
          [3, 'application/openpc+cbor'],
          [4, createHash('sha256').update(publicKeySpkiDer).digest()],
          [1001, policyArtifactCoseContext.schemaId],
          [1002, policyArtifactCoseContext.purpose],
        ]),
      );
      const signature = sign(
        'sha256',
        encodeCbor(['Signature1', headers, Buffer.alloc(0), payload]),
        { key, dsaEncoding: 'ieee-p1363' },
      );
      return Buffer.concat([
        Buffer.from([0xd2]),
        encodeCbor([headers, new Map(), payload, signature]),
      ]);
    },
  };
}

export function compilePolicyArtifact(
  input: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly policyId: string;
    readonly semanticVersion: string;
    readonly semanticDocument: unknown;
  },
  signer: PolicyArtifactCompilerSigner,
) {
  const semantic = validatePolicySemantics(input.semanticDocument);
  if (
    semantic.document.participantId !== input.participantId ||
    semantic.document.privacyDomainId !== input.privacyDomainId
  )
    throw new ContractError('PC-POLICY-2004');
  const dependencyClosureDigest = pcCbor1(semantic.document.moduleBindings).digest;
  // Preserve the deployed v1 schema identity; the optional typed families are
  // additive. Admission still checks their closed Rust types and real inputs.
  const policySchemaDigest = policySemanticSchemaDigest();
  const payloadCbor = encodePolicyArtifactPayload({
    participantId: `urn:openpc:participant:${input.participantId}`,
    privacyDomainId: `urn:openpc:privacy-domain:${input.privacyDomainId}`,
    policySetId: `urn:openpc:policy-set:${input.policyId}`,
    semanticVersion: input.semanticVersion,
    policySchemaDigest,
    semanticDigest: semantic.digest,
    semanticBytesDigest: semantic.digest,
    dependencyClosureDigest,
  });
  return {
    semanticDocument: semantic.document,
    semanticCbor: semantic.bytes,
    policySchemaDigest,
    dependencyClosureDigest,
    payloadCbor,
    coseSign1: signer.sign(payloadCbor),
  };
}
