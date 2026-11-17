import { bindGovernedProjectionConsumer } from './consumer-port.js';
import { canonicalJson } from './canonical.js';
import { ExplorerContinuationCustody } from './continuation-custody.js';
import { requireDisclosureContext, fenceDisclosureContext } from './disclosure-context.js';
import { evaluateDisclosure, withDisclosureFacts } from './disclosure-policy.js';
import { createHttpGovernedProjectionConsumer } from './http-consumer.js';
import type { PrivacyExplorerPreparedExecution } from './http-delivery.js';
import { narrowIntent } from './narrowing.js';
import { preauthorize } from './preauthorization.js';
import type { RegisteredExplorerProfile } from './profile-registration.js';
import { redactProjection } from './redaction.js';
import { createProjectionRequest } from './request.js';
import {
  createPrivacyExplorerService,
  requirePrivacyExplorerAuthenticReadResult,
  type PrivacyExplorerReadInput,
} from './service.js';
import type { PrivacyExplorerTransportProfile } from './transport-profile.js';

export const createDisclosureExecution =
  (
    key: Uint8Array,
    transport: (profile: RegisteredExplorerProfile) => PrivacyExplorerTransportProfile,
  ) =>
  async (input: PrivacyExplorerReadInput): Promise<PrivacyExplorerPreparedExecution> => {
    const binding = requireDisclosureContext(input.context);
    const boundary = createProjectionRequest(
      narrowIntent(preauthorize(input.context, input.purposeAction), input.profile, input.query),
      input.seed,
    );
    if (canonicalJson(binding.intent) !== canonicalJson(boundary.request))
      throw new Error('Privacy Explorer request changed');
    const vault = new ExplorerContinuationCustody(key, binding.scope, {
      queryDigest: boundary.request.queryDigest,
      profileDigest: input.profile.digest,
      authorityGeneration: binding.authorityGeneration,
      factGeneration: binding.factGeneration,
      identityGeneration: binding.identityGeneration,
    });
    let externalCursor: string | null = null;
    if (input.query.page.cursor !== null) {
      externalCursor = await binding.custody.transaction(async (client) => {
        await fenceDisclosureContext(client, binding);
        return vault.consume(client, input.query.page.cursor!, input.context.occurrenceId);
      });
    }
    const sourceBoundary = createProjectionRequest(
      narrowIntent(preauthorize(input.context, input.purposeAction), input.profile, {
        ...input.query,
        page: { ...input.query.page, cursor: externalCursor },
      }),
      input.seed,
    );
    const http = createHttpGovernedProjectionConsumer(transport(input.profile));
    const consumer = bindGovernedProjectionConsumer(input.profile, {
      readGovernedProjection(request, context, control) {
        if (
          canonicalJson(request) !== canonicalJson(boundary.request) ||
          canonicalJson(context) !== canonicalJson(boundary.context)
        )
          throw new Error('Privacy Explorer request changed');
        return http.readGovernedProjection(sourceBoundary.request, sourceBoundary.context, control);
      },
      verifyEvidenceReference: (request, context, control) =>
        http.verifyEvidenceReference(request, context, control),
    });
    const service = createPrivacyExplorerService(
      consumer,
      binding.custody,
      async (projection) =>
        binding.custody.transaction(async (client) => {
          const generations = await fenceDisclosureContext(client, binding);
          await evaluateDisclosure(client, binding.actor, boundary.request, generations);
          if (input.signal?.aborted) throw new Error('Privacy Explorer interrupted');
          const cursor =
            projection.projection.page.cursor === null
              ? null
              : await vault.retain(
                  client,
                  input.context.occurrenceId,
                  projection.projection.page.cursor,
                  input.profile.maximumDeadlineAt,
                );
          return redactProjection(projection, {
            // DISCLOSURE selectors govern this exact registered class/query. Each
            // returned record receives the locally evaluated field intersection.
            fieldsForRecord: () => boundary.request.projectionFields,
            recordReference: (id) => vault.recordReference(id),
            cursor,
          });
        }),
      sourceBoundary,
    );
    return Object.freeze({
      service,
      close: () => binding.custody.interrupt(input.context.occurrenceId),
      evidenceSink: binding.custody.evidenceSink(),
      release: async (result, enqueue) => {
        requirePrivacyExplorerAuthenticReadResult(result);
        if (result.disposition !== 'RELEASED')
          throw new Error('Privacy Explorer release suppressed');
        try {
          await binding.custody.transaction(async (client, commit) => {
            const generations = await fenceDisclosureContext(client, binding);
            await withDisclosureFacts(
              generations,
              binding.actor.principalId,
              async (facts, revalidate, assertHeld) => {
                await evaluateDisclosure(
                  client,
                  binding.actor,
                  boundary.request,
                  generations,
                  facts,
                );
                if (input.signal?.aborted || Date.now() >= Date.parse(input.seed.deadlineAt))
                  throw new Error('Privacy Explorer interrupted');
                await binding.custody.claim(client, boundary, result.evidence);
                await revalidate();
                await commit();
                assertHeld();
                if (input.signal?.aborted || Date.now() >= Date.parse(input.seed.deadlineAt))
                  throw new Error('Privacy Explorer interrupted');
                // No await between durable authorization and the guarded enqueue.
                enqueue();
              },
            );
          });
        } catch (error) {
          await binding.custody.interrupt(input.context.occurrenceId).catch(() => undefined);
          throw error;
        }
      },
    });
  };
