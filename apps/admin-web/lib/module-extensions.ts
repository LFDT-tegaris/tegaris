import { z } from 'zod';
import { moduleUiContributionSchema } from '@openpc/ui-extensions';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const resource = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => /^[1-9][0-9]{0,19}$/u.test(value) && BigInt(value) <= 18446744073709551615n);
export const moduleExtensionEndpoint = '/api/v1/ui/module-extensions';
export const moduleExtensionEventName = 'module-extensions';
export const moduleExtensionQuery = z.strictObject({
  routeId: z.string().regex(/^ROUTE-[A-Z0-9-]+$/u),
  objectRef: resource.optional(),
});
export const moduleExtensionBinding = z.strictObject({
  actorKey: digest,
  participantId: uuid,
  privacyDomainId: uuid,
  /** Equality token for exact current owner inputs. Never grants permission. */
  observationKey: digest,
});
export const moduleExtensionEntry = z.strictObject({
  moduleId: z.string().regex(/^pc\.[a-z0-9.-]+$/u),
  moduleRef: resource,
  moduleVersion: z
    .string()
    .regex(
      /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u,
    ),
  moduleDigest: digest,
  moduleRevision: revision,
  uiManifestDigest: digest,
  contribution: moduleUiContributionSchema,
});
/** Feature presentation projection. No secrets, manifest signature, arbitrary
 * data, supplied component code, enabled flags or authority capabilities. */
export const moduleExtensionSnapshot = z
  .strictObject({
    kind: z.literal('MODULE_EXTENSIONS'),
    query: moduleExtensionQuery,
    binding: moduleExtensionBinding,
    entries: z
      .array(moduleExtensionEntry)
      .refine(
        (values) =>
          new Set(values.map((value) => value.contribution.contributionId)).size === values.length,
      ),
  })
  .superRefine((snapshot, context) => {
    const modules = new Map<string, string>();
    const refs = new Map<string, string>();
    for (const entry of snapshot.entries) {
      const identity = JSON.stringify([
        entry.moduleRef,
        entry.moduleVersion,
        entry.moduleDigest,
        entry.moduleRevision,
        entry.uiManifestDigest,
      ]);
      if (
        (modules.has(entry.moduleId) && modules.get(entry.moduleId) !== identity) ||
        (refs.has(entry.moduleRef) && refs.get(entry.moduleRef) !== entry.moduleId)
      ) {
        context.addIssue({ code: 'custom', message: 'Ambiguous module observation' });
      }
      modules.set(entry.moduleId, identity);
      refs.set(entry.moduleRef, entry.moduleId);
    }
  });
export type ModuleExtensionSnapshot = z.infer<typeof moduleExtensionSnapshot>;
export type ModuleExtensionEntry = z.infer<typeof moduleExtensionEntry>;
export type ModuleExtensionBinding = z.infer<typeof moduleExtensionBinding>;
const moduleObservation = moduleExtensionEntry.omit({ contribution: true });
export const moduleExtensionObservation = z.strictObject({
  binding: moduleExtensionBinding,
  modules: z
    .array(moduleObservation)
    .refine(
      (values) =>
        new Set(values.map((value) => value.moduleId)).size === values.length &&
        new Set(values.map((value) => value.moduleRef)).size === values.length,
    ),
});
export const moduleExtensionEvent = moduleExtensionObservation.extend({
  type: z.enum(['CURRENT', 'INVALIDATED', 'REOBSERVE']),
});
/** Explicit equality inputs, never a timestamp, new lifecycle generation or ACK. */
export function moduleExtensionObservationOf(
  snapshot: ModuleExtensionSnapshot,
): z.infer<typeof moduleExtensionObservation> {
  const modules = new Map(
    snapshot.entries.map((entry) => [
      entry.moduleId,
      moduleObservation.parse(entryWithoutContribution(entry)),
    ]),
  );
  return {
    binding: snapshot.binding,
    modules: [...modules.values()].sort((a, b) =>
      a.moduleId < b.moduleId ? -1 : a.moduleId > b.moduleId ? 1 : 0,
    ),
  };
}
function entryWithoutContribution(entry: ModuleExtensionEntry) {
  return {
    moduleId: entry.moduleId,
    moduleRef: entry.moduleRef,
    moduleVersion: entry.moduleVersion,
    moduleDigest: entry.moduleDigest,
    moduleRevision: entry.moduleRevision,
    uiManifestDigest: entry.uiManifestDigest,
  };
}
export function sameModuleExtensionObservation(
  a: z.infer<typeof moduleExtensionObservation>,
  b: z.infer<typeof moduleExtensionObservation>,
): boolean {
  const canonical = (value: z.infer<typeof moduleExtensionObservation>) =>
    JSON.stringify({
      binding: moduleExtensionBinding.parse(value.binding),
      modules: value.modules
        .map((entry) => moduleObservation.parse(entry))
        .sort((x, y) => (x.moduleId < y.moduleId ? -1 : x.moduleId > y.moduleId ? 1 : 0)),
    });
  return canonical(a) === canonical(b);
}
export const moduleExtensionOriginalOperation = z.strictObject({
  requestId: uuid,
  operationId: uuid.optional(),
});
export type ModuleExtensionOriginalOperation = z.infer<typeof moduleExtensionOriginalOperation>;

export function moduleExtensionQueryString(query: z.infer<typeof moduleExtensionQuery>): string {
  const parsed = moduleExtensionQuery.parse(query);
  return new URLSearchParams({
    routeId: parsed.routeId,
    ...(parsed.objectRef ? { objectRef: parsed.objectRef } : {}),
  }).toString();
}

export function sameModuleExtensionQuery(
  a: ModuleExtensionSnapshot['query'],
  b: ModuleExtensionSnapshot['query'],
): boolean {
  return a.routeId === b.routeId && a.objectRef === b.objectRef;
}
