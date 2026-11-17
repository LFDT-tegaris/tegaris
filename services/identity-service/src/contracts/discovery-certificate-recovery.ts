import { createHash, createPublicKey } from 'node:crypto';
import { z } from 'zod';
import {
  platformRecoveryEnrollment,
  platformRecoveryAdministrationCommand,
  platformRecoverySourceView,
  platformRecoveryDraftView,
  platformRecoveryReceiptView,
  platformRecoveryOperations,
  independentRecoveryEnrollmentCustody,
  rootExpiryPlatformRecoveryEnrollment,
} from './platform-recovery.js';
import { recoveryLifetimeSettings } from '../domain/platform-recovery-lifetimes.js';

const id = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const epoch = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);

/** Separately enrolled transport recovery purpose. A target's membership in
 * administration scope never authorizes its workload principal or certificate. */
export const discoveryCertificateRecovery = z
  .strictObject({
    purpose: z.literal('DISCOVERY_CERTIFICATE_REPLACEMENT'),
    targetId: id,
    targetRevision: revision,
    workloadPrincipalId: id,
    workloadPrincipalEpoch: revision,
    predecessorCredentialId: id,
    predecessorRevision: revision,
    predecessorEpoch: revision,
    predecessorFingerprint: digest,
    predecessorPublicKeyDigest: digest,
    predecessorNotAfter: z.iso.datetime({ offset: true }),
    issuer: z.string().min(1).max(256),
    successorCredentialId: id,
    successorPublicKeySpkiDer: z.string().min(24).max(8192),
    successorPublicKeyDigest: digest,
  })
  .superRefine((value, ctx) => {
    let publicKeyMatches = false;
    try {
      const bytes = Buffer.from(value.successorPublicKeySpkiDer, 'base64');
      const key = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
      publicKeyMatches =
        bytes.toString('base64') === value.successorPublicKeySpkiDer &&
        Buffer.from(key.export({ format: 'der', type: 'spki' })).equals(bytes) &&
        `sha256:${createHash('sha256').update(bytes).digest('hex')}` ===
          value.successorPublicKeyDigest;
    } catch {
      // Invalid public material is a structural denial; never expose parser details.
    }
    if (
      !publicKeyMatches ||
      new Set([
        value.targetId,
        value.workloadPrincipalId,
        value.predecessorCredentialId,
        value.successorCredentialId,
      ]).size !== 4
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid discovery certificate recovery binding' });
  });

export type DiscoveryCertificateRecovery = z.infer<typeof discoveryCertificateRecovery>;

/** New immutable enrollment identity; the original handoff parser rejects it.
 * This is explicit installation trust, not a larger administrative Root scope. */
export const expiredDiscoveryCertificateRecoveryEnrollment = z
  .strictObject({
    ...platformRecoveryEnrollment.shape,
    schema: z.literal('pc.identity.discovery-certificate-recovery-enrollment'),
    certificateRecovery: discoveryCertificateRecovery,
  })
  .superRefine((value, ctx) => {
    const actors = [
      ...value.administratorPrincipalIds,
      value.recoveryPrincipal.principalId,
      ...value.custodians.map((v) => v.principalId),
    ];
    if (
      !independentRecoveryEnrollmentCustody(value) ||
      actors.includes(value.certificateRecovery.workloadPrincipalId)
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Discovery recovery requires independent human custody',
      });
  });

/** A distinct local source discriminator preserves V1 bytes and purpose. The
 * shared source contract only validates receipt references; the owning reader
 * must authenticate every receipt and the original administrator rows. */
export const rootExpiryDiscoveryCertificateRecoveryEnrollment = z
  .strictObject({
    ...z
      .strictObject(rootExpiryPlatformRecoveryEnrollment.shape)
      .omit({ uneffectedPredecessor: true }).shape,
    schema: z.literal('pc.identity.discovery-certificate-recovery-enrollment'),
    assurance: z.literal('LOCAL_QA_VIRTUAL_AUTHENTICATOR'),
    certificateRecovery: discoveryCertificateRecovery,
  })
  .superRefine((value, ctx) => {
    const { certificateRecovery, ...source } = value;
    if (
      !rootExpiryPlatformRecoveryEnrollment.safeParse({
        ...source,
        schema: 'pc.identity.platform-recovery-enrollment',
      }).success ||
      [
        ...value.administratorPrincipalIds,
        value.recoveryPrincipal.principalId,
        ...value.custodians.map((v) => v.principalId),
      ].includes(certificateRecovery.workloadPrincipalId)
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid local receipt recovery custody' });
  });

export const discoveryCertificateRecoveryEnrollment = z.discriminatedUnion('schemaVersion', [
  expiredDiscoveryCertificateRecoveryEnrollment,
  rootExpiryDiscoveryCertificateRecoveryEnrollment,
]);

const administrator = z.strictObject({
  principalId: id,
  principalEpoch: epoch,
  roleId: id,
  roleRevision: revision,
  roleDigest: digest,
  riskClasses: z
    .array(z.enum(['BREAK_GLASS', 'HIGH', 'LOW', 'STANDARD']))
    .min(1)
    .max(4),
});

/** The case contains no Root successor, new admin envelope or runtime input.
 * Existing roles bound the eventual maker/checker lease independently. */
export const discoveryCertificateRecoveryIntent = z
  .strictObject({
    schema: z.literal('pc.identity.discovery-certificate-recovery-intent'),
    schemaVersion: z.union([z.literal(1), z.literal(2)]),
    recoveryId: id,
    enrollmentId: id,
    enrollmentRevision: revision,
    enrollmentDigest: digest,
    certificateRecovery: discoveryCertificateRecovery,
    administrators: z.tuple([administrator, administrator]),
    validFrom: z.iso.datetime({ offset: true }),
    validUntil: z.iso.datetime({ offset: true }),
    lifetimes: recoveryLifetimeSettings,
  })
  .superRefine((value, ctx) => {
    if (
      value.administrators[0].principalId === value.administrators[1].principalId ||
      Date.parse(value.validUntil) <= Date.parse(value.validFrom) ||
      Date.parse(value.validUntil) - Date.parse(value.validFrom) > value.lifetimes.leaseMs
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid discovery recovery case' });
  });

export type DiscoveryCertificateRecoveryEnrollment = z.infer<
  typeof discoveryCertificateRecoveryEnrollment
>;
export type DiscoveryCertificateRecoveryIntent = z.infer<typeof discoveryCertificateRecoveryIntent>;

/** Parsed by the existing approval owner. Version-two local custody permits
 * only this exact command; an ordinary approval replacement cannot borrow it. */
export const discoveryApprovalResumeReason =
  'Resume the retained Discovery certificate rotation with fresh custody and independent approval.';

export const discoveryApprovalResume = z.strictObject({
  command: z.literal('RESUME'),
  actionIntentId: z.literal('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  expectedRevision: revision,
  predecessorCandidateId: id,
  expectedAttempt: z.string().regex(/^[1-9][0-9]*$/u),
  candidateDigest: digest,
  reason: z.string().min(1).max(1024),
});
export type DiscoveryApprovalResume = z.infer<typeof discoveryApprovalResume>;
export const discoveryApprovalResumePurpose = discoveryApprovalResume.extend({
  approvalRequestId: z
    .string()
    .regex(
      /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    ),
});
export type DiscoveryApprovalResumePurpose = z.infer<typeof discoveryApprovalResumePurpose>;

export const discoveryCertificateRotationCandidateSchema = z.strictObject({
  replacedCredentialId: z.uuidv7(),
  credentialId: z.uuidv7(),
  publicKeySpkiDer: z
    .string()
    .min(24)
    .max(8192)
    .refine((value) => Buffer.from(value, 'base64').toString('base64') === value),
});

/** Exact existing ID-OP-WORKLOAD-ROTATE candidate. No new mutation dialect. */
export function discoveryCertificateRotationCandidate(binding: DiscoveryCertificateRecovery) {
  const selected = discoveryCertificateRecovery.parse(binding);
  return {
    replacedCredentialId: selected.predecessorCredentialId,
    credentialId: selected.successorCredentialId,
    publicKeySpkiDer: selected.successorPublicKeySpkiDer,
  };
}

/** Shared proof/closure structure, with a preparation-free creation command. */
export const discoveryCertificateRecoveryCommand = z.discriminatedUnion('kind', [
  platformRecoveryAdministrationCommand.options[0],
  z.strictObject({ kind: z.literal('CREATE') }),
  platformRecoveryAdministrationCommand.options[2],
  platformRecoveryAdministrationCommand.options[3],
  platformRecoveryAdministrationCommand.options[4],
  platformRecoveryAdministrationCommand.options[5],
]);

export const discoveryCertificateRecoveryOperations = platformRecoveryOperations
  .filter(
    (operation) =>
      operation.command !== 'ROTATION_CREATE' && operation.command !== 'ROTATION_ADVANCE',
  )
  .map((operation) => ({
    ...operation,
    id: operation.id.replace('PLATFORM-RECOVERY', 'DISCOVERY-CERTIFICATE-RECOVERY'),
  }));

export const discoveryCertificateRecoverySourceView = z.strictObject({
  enrollmentId: id,
  assurance: platformRecoverySourceView.shape.assurance,
  authority: z.literal('NONE'),
  lifetimes: recoveryLifetimeSettings,
  source: platformRecoverySourceView.shape.source,
  certificateRecovery: discoveryCertificateRecovery,
});
export const discoveryCertificateRecoveryDraftView = z.strictObject({
  ...platformRecoveryDraftView.shape,
  intent: discoveryCertificateRecoveryIntent,
});
const certificateAuthority = z.literal('DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY');
export const discoveryCertificateRecoveryCompletion = z.strictObject({
  issuanceId: id,
  operationId: id,
  predecessorCredentialId: id,
  successorCredentialId: id,
  certificateFingerprint: digest,
});
export const discoveryCertificateRecoveryReceiptView = z
  .strictObject({
    ...platformRecoveryReceiptView.shape,
    intent: discoveryCertificateRecoveryIntent,
    authority: z.union([z.literal('NONE'), certificateAuthority]),
    activation: platformRecoveryReceiptView.shape.activation
      .unwrap()
      .extend({ authority: certificateAuthority })
      .optional(),
    completion: discoveryCertificateRecoveryCompletion.optional(),
  })
  .superRefine((value, ctx) => {
    const completion = value.completion;
    if (
      (value.state === 'COMPLETED') !== Boolean(completion) ||
      (['ACTIVE', 'COMPLETED'].includes(value.state) && !value.activation) ||
      (value.authority === 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY' && value.state !== 'ACTIVE') ||
      (value.activation &&
        (value.activation.recoveryId !== value.recoveryId ||
          value.activation.enrollmentId !== value.enrollmentId ||
          value.activation.intentDigest !== value.intentDigest)) ||
      (completion &&
        (value.authority !== 'NONE' ||
          completion.predecessorCredentialId !==
            value.intent.certificateRecovery.predecessorCredentialId ||
          completion.successorCredentialId !==
            value.intent.certificateRecovery.successorCredentialId ||
          completion.operationId === value.activation?.operationId))
    )
      ctx.addIssue({ code: 'custom', message: 'Invalid discovery completion custody' });
  });
