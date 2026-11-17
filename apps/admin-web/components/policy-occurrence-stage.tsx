'use client';

import { useRef, useState } from 'react';
import { z } from 'zod';
import type { policyActivationPreviewSchema } from '../../../services/module-registry/src/policy-activation-preview';

type Preview = z.infer<typeof policyActivationPreviewSchema>;
type Review = { stageReviewToken: string; preview: Preview };

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/u);
const resourceRef = z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u);
// The owning preview module also imports Node crypto; keep this decoder browser-safe.
const previewReadSchema = z
  .strictObject({
    releaseBundleId: resourceRef,
    releaseRevision: revision,
    policyVersionId: z.uuidv7(),
    targetGenerationDigest: digest,
    dependencyClosureDigest: digest,
    simulationId: z.uuidv7(),
    simulationInputDigest: digest,
    simulationResultDigest: digest,
    factGenerationDigest: digest,
    matchedTargetCount: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
    totalTargetCount: revision,
    targets: z
      .array(
        z
          .strictObject({
            targetId: z.uuidv7(),
            expectedRevision: revision,
            expectedPredecessorDigest: digest.nullable(),
            configurationDigest: digest,
            providerProfileId: z.uuidv7(),
            projectionPlanId: z.uuidv7(),
            configuredMatch: z.boolean(),
          })
          .refine((target) => !target.configuredMatch || target.expectedPredecessorDigest !== null),
      )
      .min(1)
      .max(256),
    activationPreviewDigest: digest,
  })
  .refine(
    (preview) =>
      preview.totalTargetCount === String(preview.targets.length) &&
      preview.matchedTargetCount ===
        String(preview.targets.filter((target) => target.configuredMatch).length),
  ) satisfies z.ZodType<Preview>;
const reviewReadSchema = z.object({
  stageReviewToken: z.string().min(80).max(65536),
  preview: previewReadSchema,
});
const operationReadSchema = z.object({
  operationId: z.uuid(),
  actionIntentId: z.literal('ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1'),
  intentDigest: z.literal(
    'sha256:ab25e0e1acc4faa65753906943f99e359ef60e4f90cd70f8cfb72bfd4e9c0dfd',
  ),
  idempotencyKey: z.string().min(16).max(128),
  resourceRef,
  revision: z.literal('1'),
  state: z.literal('ACCEPTED'),
  truthState: z.literal('SUCCESS'),
  createdAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u),
  updatedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u),
});
class OccurrenceStageFailure extends Error {}
function httpFailure(status: number): string {
  if (status === 400 || status === 422)
    return 'The policy staging request was invalid. Review the inputs before retrying.';
  if (status === 401 || status === 403 || status === 404)
    return 'Policy staging was not authorized. Refresh the authenticated context before continuing.';
  if (status === 409 || status === 412 || status === 428)
    return 'The policy staging context changed. Read back the original operation before retrying.';
  return 'The policy staging owner is unavailable. Read back the original operation before retrying.';
}
const responseFailure =
  'The policy staging response could not be confirmed. Read back the original operation before retrying.';
const previewFailure =
  'The policy staging preview could not be confirmed. Refresh before continuing.';
const stageFailure =
  'The staging result could not be confirmed. Read back the original operation before retrying.';

async function command<T>(body: unknown, schema: z.ZodType<T>): Promise<T> {
  const isReview = Object.is(schema, reviewReadSchema);
  const response = await fetch('/api/v1/ui/policy-release-workbench', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new OccurrenceStageFailure(httpFailure(response.status));
  if (
    response.status !== (isReview ? 201 : 202) ||
    response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() !==
      'application/json'
  )
    throw new OccurrenceStageFailure(responseFailure);
  const value: unknown = await response.json().catch(() => undefined);
  if (
    isReview &&
    value !== null &&
    typeof value === 'object' &&
    'stageReviewToken' in value &&
    typeof value.stageReviewToken === 'string' &&
    value.stageReviewToken.length > 65536
  )
    throw new OccurrenceStageFailure(
      'This preview exceeds the supported staging limit. Staging is unavailable.',
    );
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new OccurrenceStageFailure(responseFailure);
  return parsed.data;
}

/** Staging records intent only. Fresh governance and activation are separate. */
export function PolicyOccurrenceStage() {
  const [review, setReview] = useState<Review>();
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState('');
  const draftGeneration = useRef(0);
  async function preview(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const requestGeneration = draftGeneration.current;
    setPending(true);
    setReview(undefined);
    setMessage('');
    try {
      const result = await command<Review>(
        {
          command: 'PREVIEW_OCCURRENCE',
          releaseId: form.get('releaseId'),
          expectedRevision: form.get('expectedRevision'),
          reason: form.get('reason'),
          resourceReservationId: String(form.get('resourceReservationId') ?? '') || undefined,
        },
        reviewReadSchema,
      );
      if (requestGeneration !== draftGeneration.current) return;
      if (
        result.preview.releaseBundleId !== `urn:openpc:resource:${String(form.get('releaseId'))}` ||
        result.preview.releaseRevision !== form.get('expectedRevision')
      )
        throw new OccurrenceStageFailure(responseFailure);
      setReview(result);
    } catch (error) {
      if (requestGeneration === draftGeneration.current)
        setMessage(error instanceof OccurrenceStageFailure ? error.message : previewFailure);
    } finally {
      setPending(false);
    }
  }
  async function stage() {
    if (!review) return;
    setPending(true);
    setMessage('');
    try {
      const operation = await command(
        {
          command: 'STAGE_OCCURRENCE',
          stageReviewToken: review.stageReviewToken,
        },
        operationReadSchema,
      );
      setMessage(
        `Occurrence: ${operation.resourceRef}. ${operation.truthState}; activation still requires fresh approval.`,
      );
    } catch (error) {
      setMessage(error instanceof OccurrenceStageFailure ? error.message : stageFailure);
    } finally {
      setPending(false);
    }
  }
  return (
    <section aria-labelledby="fresh-occurrence-title" className="mt-8 rounded border p-4">
      <h2 id="fresh-occurrence-title" className="text-lg font-semibold">
        Prepare a target activation
      </h2>
      <p>
        Reuse a published release with current target revisions and predecessors. Staging does not
        activate the policy.
      </p>
      <form
        onSubmit={(event) => void preview(event)}
        onChange={() => {
          draftGeneration.current++;
          setReview(undefined);
        }}
        className="mt-3 grid gap-3"
      >
        <label>
          Published release ID
          <input
            className="block w-full rounded border p-2"
            name="releaseId"
            disabled={pending}
            required
          />
        </label>
        <label>
          Release revision
          <input
            className="block rounded border p-2"
            name="expectedRevision"
            disabled={pending}
            pattern="[1-9][0-9]*"
            required
          />
        </label>
        <label>
          Activation reservation operation ID
          <input
            className="block w-full rounded border p-2"
            name="resourceReservationId"
            disabled={pending}
          />
        </label>
        <label>
          Staging reason
          <input
            className="block w-full rounded border p-2"
            name="reason"
            disabled={pending}
            minLength={10}
            maxLength={1024}
            required
          />
        </label>
        <button className="rounded border p-2" disabled={pending} type="submit">
          Review current activation targets
        </button>
      </form>
      {review ? (
        <div className="mt-3 space-y-2">
          <p>
            Release revision {review.preview.releaseRevision}; configuration matches{' '}
            {review.preview.matchedTargetCount}/{review.preview.totalTargetCount}. Configuration
            match does not prove runtime permission.
          </p>
          <ul>
            {review.preview.targets.map((target) => (
              <li key={target.targetId}>
                Target {target.targetId}: revision {target.expectedRevision}; predecessor{' '}
                {target.expectedPredecessorDigest ?? 'none'}.
              </li>
            ))}
          </ul>
          <p className="break-all">Preview digest: {review.preview.activationPreviewDigest}</p>
          <button
            className="rounded border p-2"
            disabled={pending}
            onClick={() => void stage()}
            type="button"
          >
            Stage reviewed activation
          </button>
        </div>
      ) : null}
      {message ? (
        <p role="status" className="mt-3 break-all">
          {message}
        </p>
      ) : null}
    </section>
  );
}
