import { z } from 'zod';
import { platformScopeSourceSchema } from '../../../../../../services/participant-service/src/contracts/platform-scope-readback';
import {
  platformScopeReplacementPreparation,
  platformScopeSupersession,
} from '../../../../../../services/participant-service/src/contracts/platform-scope-replacement';

const id = z.uuidv7();
const finiteIds = z
  .array(
    z.union([
      id,
      z
        .string()
        .regex(
          /^urn:openpc:self-session:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
        ),
    ]),
  )
  .min(1)
  .max(256)
  .refine((values) => new Set(values).size === values.length);
const actions = z
  .array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u))
  .min(1)
  .max(256)
  .refine((values) => new Set(values).size === values.length);

export function platformAdministratorLifetimeSettings(
  environment: Readonly<Record<string, string | undefined>> = process.env,
) {
  const configuredMaximum = environment.OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_MAX_SECONDS || undefined;
  const configuredDefault = environment.OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_SECONDS || undefined;
  if (
    (configuredMaximum !== undefined || configuredDefault !== undefined) &&
    (environment.OPENPC_LOCAL_RUNTIME !== '1' ||
      environment.OPENPC_LOCAL_RUNTIME_QA_FIXTURE !== '1')
  )
    throw new Error('Explicit disposable QA is required for administrator lifetime settings');
  const duration = (raw: string | undefined, fallback: number) => {
    if (raw === undefined) return fallback;
    if (!/^[1-9][0-9]*$/u.test(raw)) throw new Error('Invalid administrator lifetime setting');
    const value = Number(raw);
    if (!Number.isSafeInteger(value) || value < 60 || value > 86400)
      throw new Error('Administrator lifetime setting outside supported bounds');
    return value;
  };
  const maximumSeconds = duration(configuredMaximum, 3600);
  const defaultSeconds = duration(configuredDefault, Math.min(3600, maximumSeconds));
  if (defaultSeconds > maximumSeconds)
    throw new Error('Administrator default lifetime exceeds the configured maximum');
  return { minimumSeconds: 60, maximumSeconds, defaultSeconds };
}
export const administratorSelection = z.strictObject({
  principalId: id,
  roleId: id,
  envelopeId: id,
  assignmentId: id,
  actionIntentIds: actions,
  resourceIds: finiteIds,
});
export const ceilingPreparationSelection = z.strictObject({
  platformContextId: id,
  replacementId: id,
  supersedes: platformScopeSupersession.optional(),
  administrators: z.array(administratorSelection).length(2),
  terminalActionIntentIds: actions.optional(),
  lifetimeSeconds: z.number().int().min(60).max(86400),
  reason: z.string().trim().min(10).max(1024),
});
export const roleBindingPreviewSchema = z.strictObject({
  participantId: id,
  roleId: id,
  roleRef: z.string().regex(/^urn:openpc:role:[0-9a-f-]{36}$/u),
  revision: z.string().regex(/^[1-9][0-9]{0,19}$/u),
  roleDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  actionIntentIds: actions,
});

/** This builds an explicit product-extension intent from authorized readback.
 * Existing narrowing, credential validity and current-root checks remain with
 * the governed owner; browser review never establishes runtime readiness. */
export function buildCeilingPreparation(
  selection: z.infer<typeof ceilingPreparationSelection>,
  source: z.infer<typeof platformScopeSourceSchema>,
  roles: z.infer<typeof roleBindingPreviewSchema>[],
  makerPrincipalId: string,
  environment: Readonly<Record<string, string | undefined>> = process.env,
) {
  selection = ceilingPreparationSelection.parse(selection);
  if (selection.lifetimeSeconds > platformAdministratorLifetimeSettings(environment).maximumSeconds)
    throw new Error('Requested administrator lifetime exceeds the configured maximum');
  source = platformScopeSourceSchema.parse(source);
  roles = roles.map((role) => roleBindingPreviewSchema.parse(role));
  if (
    source.state !== 'ACTIVE' ||
    (source.pending === null
      ? selection.supersedes !== undefined
      : !selection.supersedes ||
        selection.supersedes.replacementId !== source.pending ||
        selection.supersedes.expectedRevision !== source.pendingIntent?.expectedRevision ||
        selection.supersedes.successorDigest !== source.pendingIntent?.successorDigest ||
        source.pendingAdministrationExpiresAtNs === null ||
        source.pendingAdministrationExpiresAtNs === undefined ||
        BigInt(source.pendingAdministrationExpiresAtNs) > BigInt(source.now)) ||
    source.root.platformContextId !== selection.platformContextId ||
    source.epoch !== source.root.platformAuthorityEpoch ||
    selection.administrators[0]!.principalId !== makerPrincipalId ||
    selection.administrators[1]!.principalId === makerPrincipalId
  )
    throw new Error('Current Platform source and distinct administration are required');
  const now = BigInt(source.now);
  // The existing public assignment owner accepts ISO/Date millisecond bounds.
  // Declare the same exact interval for envelope and assignment; never round
  // the source expiry upward or fabricate a future notBefore.
  const milliseconds = 1_000_000n;
  const from = (now / milliseconds) * milliseconds;
  const requestedUntil = now + BigInt(selection.lifetimeSeconds) * 1_000_000_000n;
  const sourceUntil = BigInt(source.root.grantable.validUntilNs);
  const until = (
    ((requestedUntil < sourceUntil ? requestedUntil : sourceUntil) / milliseconds) *
    milliseconds
  ).toString();
  if (BigInt(until) <= now || BigInt(source.root.grantable.validFromNs) > from)
    throw new Error('Platform source has no live bounded interval');
  const participantId = source.root.ownerParticipantId;
  const privacyDomainId = source.root.installationPrivacyDomainId;
  const plannedIds = [
    participantId,
    selection.platformContextId,
    selection.replacementId,
    ...selection.administrators.flatMap((admin) => [
      admin.principalId,
      admin.roleId,
      admin.envelopeId,
      admin.assignmentId,
    ]),
  ];
  const unique = (values: string[]) => [...new Set(values)].sort();
  const administrators = selection.administrators.map((admin) => {
    const matches = roles.filter(
      (role) => role.participantId === participantId && role.roleId === admin.roleId,
    );
    const role = matches[0];
    if (
      matches.length !== 1 ||
      !role ||
      role.roleRef !== `urn:openpc:role:${admin.roleId}` ||
      admin.actionIntentIds.some((action) => !role.actionIntentIds.includes(action))
    )
      throw new Error('Selected role does not bind the requested administration');
    const scope = {
      administration: {
        participantIds: [participantId],
        privacyDomainIds: [privacyDomainId],
        resourceIds: unique([...admin.resourceIds, ...plannedIds]),
        dataClasses: [],
        targetProfileIds: [],
        riskClasses: ['HIGH', 'LOW'] as const,
        actionIntentIds: unique(admin.actionIntentIds),
      },
      runtime: {
        participantIds: [],
        privacyDomainIds: [],
        resourceIds: [],
        dataClasses: [],
        targetProfileIds: [],
        riskClasses: [],
        capabilityIds: [],
      },
      validFromNs: from.toString(),
      validUntilNs: until,
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
    };
    return {
      principalId: admin.principalId,
      roleId: admin.roleId,
      envelopeId: admin.envelopeId,
      assignmentId: admin.assignmentId,
      expectedRoleRevision: role.revision,
      roleDigest: role.roleDigest,
      usable: scope,
      grantable: structuredClone(scope),
    };
  });
  const successorScope = {
    ...structuredClone(source.root.grantable),
    administration: {
      ...administrators[0]!.usable.administration,
      actionIntentIds: unique([
        ...administrators.flatMap((admin) => admin.usable.administration.actionIntentIds),
        ...(selection.terminalActionIntentIds ?? []),
      ]),
      resourceIds: unique(
        administrators.flatMap((admin) => admin.usable.administration.resourceIds),
      ),
    },
    // Terminal authority retains its original lifetime; temporary administrator
    // grants remain independently bounded by the requested interval above.
    validFromNs: source.root.grantable.validFromNs,
    validUntilNs: source.root.grantable.validUntilNs,
    makerCheckerRequired: false,
    stepUpRequired: false,
    onwardDelegationDepth: 0,
  };
  return platformScopeReplacementPreparation.parse({
    schema: 'pc.identity.platform-scope-replacement',
    schemaVersion: 1,
    replacementId: selection.replacementId,
    platformContextId: selection.platformContextId,
    expectedRootRevision: source.revision,
    predecessorEpoch: source.epoch,
    predecessorDigest: source.root.platformAuthorityDigest,
    successorScope,
    ...(selection.supersedes ? { supersedes: selection.supersedes } : {}),
    administrators,
    affectedTargets: source.affectedTargets,
    reason: selection.reason,
  });
}
