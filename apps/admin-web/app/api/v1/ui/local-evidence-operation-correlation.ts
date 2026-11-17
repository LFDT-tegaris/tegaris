import { NextResponse, type NextRequest } from 'next/server';
import { evidenceProvenanceView } from '../../../../../../services/control-api/src/evidence/provenance-contracts';
import {
  evidenceOperationQuery,
  projectEvidenceOperation,
} from '../../../../lib/evidence-operation-correlation';
import {
  authenticated,
  hasJsonContentType,
  localRuntimeConfig,
  safeProblem,
  type IdentitySession,
} from './local-runtime';
import { digest, ownerFailure, publicHeaders } from './local-governance-api';

const timeoutMs = 15000;
const provenanceBytes = 256 * 1024;
const operationBytes = 16 * 1024;
function actorKey(session: IdentitySession) {
  // Identical to the existing Evidence Workbench binding, so its current view
  // can supply the selector without another bootstrap or private authority.
  return digest({
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    sessionId: session.sessionId,
    principalId: session.principalId,
    contextEpoch: session.contextEpoch,
  });
}
function admitted(session: IdentitySession | undefined): session is IdentitySession {
  return !!session && session.contextMode === 'PARTICIPANT' && !!session.privacyDomainId;
}
function authorityIdentity(session: IdentitySession) {
  return digest({
    actorKey: actorKey(session),
    role: session.role,
    sessionEpoch: session.sessionEpoch ?? null,
    participantEpoch: session.participantEpoch ?? null,
    principalEpoch: session.principalEpoch ?? null,
    assignmentId: session.assignmentId ?? null,
    assignmentRowVersion: session.assignmentRowVersion ?? null,
    authorityEnvelopeId: session.authorityEnvelopeId ?? null,
    authorityEpoch: session.authorityEpoch ?? null,
    delegationEpoch: session.delegationEpoch ?? null,
  });
}
function within<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const aborted = () => {
      cleanup();
      reject(new Error('Read unavailable'));
    };
    const cleanup = () => signal.removeEventListener('abort', aborted);
    signal.addEventListener('abort', aborted, { once: true });
    work.then(
      (value) => {
        cleanup();
        if (signal.aborted) aborted();
        else resolve(value);
      },
      () => {
        cleanup();
        reject(new Error('Read unavailable'));
      },
    );
    if (signal.aborted) aborted();
  });
}
async function boundedJson(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<unknown> {
  const length = response.headers.get('content-length');
  if (
    !hasJsonContentType(response.headers.get('content-type')) ||
    !response.body ||
    (length !== null && (!/^(0|[1-9][0-9]*)$/u.test(length) || BigInt(length) > BigInt(maxBytes)))
  ) {
    void response.body?.cancel().catch(() => undefined);
    throw new Error('Read unavailable');
  }
  const reader = response.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await within(reader.read(), signal);
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes) throw new Error('Read unavailable');
      parts.push(chunk.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) {
      bytes.set(part, offset);
      offset += part.byteLength;
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } finally {
    void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export async function readEvidenceOperationCorrelation(request: NextRequest) {
  const signal = AbortSignal.any([request.signal, AbortSignal.timeout(timeoutMs)]);
  const entries = [...request.nextUrl.searchParams];
  const query = evidenceOperationQuery.safeParse(Object.fromEntries(entries));
  if (!query.success || new Set(entries.map(([key]) => key)).size !== entries.length)
    return safeProblem('PC-DATA-6004', request);
  try {
    const runtime = await within(localRuntimeConfig(), signal);
    if (!runtime) return safeProblem('PC-INTEGRATION-5001', request);
    const session = await within(authenticated(request, runtime), signal);
    if (!admitted(session) || actorKey(session) !== query.data.actorKey)
      return safeProblem('PC-AUTH-0005', request);
    const read = async (path: string, limit: number) => {
      signal.throwIfAborted();
      const response = await within(
        fetch(`${runtime.publicApiUrl}/api/v1/${path}`, {
          method: 'GET',
          cache: 'no-store',
          redirect: 'error',
          signal,
          headers: publicHeaders(runtime, session),
        }),
        signal,
      );
      if (response.status !== 200 || response.redirected) {
        void response.body?.cancel().catch(() => undefined);
        return ownerFailure(response.status === 200 ? undefined : response, request);
      }
      return boundedJson(response, limit, signal);
    };
    const raw = await read(
      `evidence-records/${encodeURIComponent(query.data.evidenceId)}/provenance`,
      provenanceBytes,
    );
    if (raw instanceof Response) return raw;
    const provenance = evidenceProvenanceView.parse(raw);
    if (
      provenance.evidenceId !== query.data.evidenceId ||
      provenance.participantId !== `urn:openpc:participant:${session.participantId}` ||
      provenance.privacyDomainId !== session.privacyDomainId ||
      provenance.status !== 'VERIFIED_BUSINESS_TRANSITION' ||
      !provenance.business
    )
      return safeProblem('PC-INTEGRATION-5001', request);
    // Only the verified owner response chooses the second resource. Neither a
    // browser-supplied operation ID nor receipt possession can authorize it.
    const operationId = provenance.business.operationId.slice('urn:openpc:operation:'.length);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(operationId))
      return safeProblem('PC-INTEGRATION-5001', request);
    const operation = await read(`operations/${operationId}`, operationBytes);
    if (operation instanceof Response) return operation;
    const result = projectEvidenceOperation(query.data, provenance, operation);
    const current = await within(authenticated(request, runtime), signal);
    if (!admitted(current) || authorityIdentity(current) !== authorityIdentity(session))
      return safeProblem('PC-AUTH-0005', request);
    signal.throwIfAborted();
    return NextResponse.json(result, { headers: { 'Cache-Control': 'no-store' } });
  } catch {
    return safeProblem('PC-INTEGRATION-5001', request);
  }
}
