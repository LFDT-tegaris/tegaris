import { z } from 'zod';

const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const action = z.string().regex(/^ACT-[A-Z0-9_]+-[A-Z0-9]+$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);

export const reservationBindingSchema = z.strictObject({
  purpose: z.enum(['APPROVAL_REQUEST', 'POLICY_ACTIVATION_OCCURRENCE']),
  businessActionIntentId: action,
  businessResourceId: uuid,
  expectedBusinessRevision: revision,
  checkerPrincipalId: uuid.nullable(),
});

export const createAdministrationReservationSchema = reservationBindingSchema
  .extend({
    command: z.literal('RESERVE_RESOURCE_NAME'),
    predecessorOperationId: uuid.optional(),
    makerSubjectRef: z
      .string()
      .regex(
        /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
      ),
    actionIntentId: z.enum([
      'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
      'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1',
    ]),
    actionIntentDigest: digest,
  })
  .superRefine((value, context) => {
    if (value.actionIntentId !== reservationAction(value.purpose))
      context.addIssue({
        code: 'custom',
        message: 'Reservation purpose does not match creation action',
      });
    if (
      value.purpose === 'POLICY_ACTIVATION_OCCURRENCE' &&
      (value.businessActionIntentId !== 'ACT-POLICY_ACTIVATE_RELEASE-V1' ||
        value.checkerPrincipalId === null)
    )
      context.addIssue({
        code: 'custom',
        message: 'Activation reservation requires a checker and activation intent',
      });
  });

export const administrationReservationSchema = reservationBindingSchema.extend({
  kind: z.literal('ADMINISTRATION_RESOURCE_NAME'),
  version: z.literal(1),
  operationId: uuid,
  predecessorOperationId: uuid.optional(),
  reservedResourceId: uuid,
  participantId: uuid,
  privacyDomainId: uuid,
  makerPrincipalId: uuid,
  createdAt: z.iso.datetime(),
  validUntil: z.iso.datetime(),
  authorityEffect: z.literal('NONE'),
  requiresFreshAuthority: z.literal(true),
});

export type ReservationBinding = z.infer<typeof reservationBindingSchema>;
export type AdministrationReservation = z.infer<typeof administrationReservationSchema>;

export function reservationAction(purpose: ReservationBinding['purpose']) {
  return purpose === 'APPROVAL_REQUEST'
    ? 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1'
    : 'ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1';
}
