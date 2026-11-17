import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import {
  abiArtifactResponseSchema,
  runtimeBindingResponseSchema,
  functionSignature,
  selectorFor,
} from '../../../../../../services/control-api/src/configuration/contract-assets';
import { contractMethodChoicesSchema } from '../../../../lib/contract-method-choices';
import {
  inspectionActorKey,
  methodPolicyReference,
} from '../../../../lib/contract-method-inspection';
import {
  authenticated,
  localRuntimeConfig,
  localOwnerFetch,
  responseIds,
  safeProblem,
} from './local-runtime';
import { isResponse, ownerJson, publicHeaders } from './local-governance-api';
import { sha256 } from '../../../../../../services/control-api/src/configuration/digest';

export async function readContractMethodChoices(request: NextRequest) {
  const ids = responseIds(request);
  const diagnostic = new NextRequest(request.url, {
    headers: { 'X-Request-ID': ids.requestId, 'X-Correlation-ID': ids.correlationId },
  });
  const pairs = [...request.nextUrl.searchParams];
  const query = z.strictObject({ bindingId: z.string() }).safeParse(Object.fromEntries(pairs));
  const bindingId = query.success && methodPolicyReference(query.data.bindingId);
  if (!bindingId || pairs.length !== 1) return safeProblem('PC-DATA-6004', diagnostic);
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) return safeProblem('PC-INTEGRATION-5001', diagnostic);
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId)
    return safeProblem('PC-AUTH-0005', diagnostic);
  const actor = {
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextEpoch: session.contextEpoch,
  };
  async function read<T>(collection: string, reference: string, schema: z.ZodType<T>) {
    const response = await localOwnerFetch(
      `${runtime!.publicApiUrl}/api/v1/${collection}/${encodeURIComponent(reference)}`,
      {
        method: 'GET',
        cache: 'no-store',
        headers: publicHeaders(runtime!, session!, ids),
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]),
      },
    ).catch(() => undefined);
    return ownerJson(response, schema, diagnostic);
  }
  const binding = await read('contract-runtime-bindings', bindingId, runtimeBindingResponseSchema);
  if (isResponse(binding)) return binding;
  if (binding.runtimeBindingId !== bindingId || binding.state !== 'BOUND')
    return safeProblem('PC-INTEGRATION-5001', diagnostic);
  const abi = await read('abi-artifacts', binding.abiArtifactId, abiArtifactResponseSchema);
  if (isResponse(abi)) return abi;
  if (
    abi.abiArtifactId !== binding.abiArtifactId ||
    abi.abiDigest !== binding.abiDigest ||
    sha256(abi.canonicalAbi) !== abi.abiDigest
  )
    return safeProblem('PC-INTEGRATION-5001', diagnostic);
  const methods = [];
  for (const item of abi.canonicalAbi) {
    if (item.type !== 'function') continue;
    const signature = functionSignature(item);
    if (!signature) return safeProblem('PC-INTEGRATION-5001', diagnostic);
    methods.push({
      signature,
      selector: selectorFor(signature),
      effect: ['view', 'pure'].includes(item.stateMutability) ? 'READ' : 'WRITE',
    });
  }
  const view = contractMethodChoicesSchema.safeParse({
    actor,
    runtimeBindingId: bindingId,
    abiArtifactId: abi.abiArtifactId,
    abiDigest: abi.abiDigest,
    methods,
  });
  if (!view.success) return safeProblem('PC-INTEGRATION-5001', diagnostic);
  const current = await authenticated(request, runtime);
  if (
    !current ||
    current.contextMode !== 'PARTICIPANT' ||
    !current.privacyDomainId ||
    inspectionActorKey({ ...current, privacyDomainId: current.privacyDomainId }) !==
      inspectionActorKey(actor)
  )
    return safeProblem('PC-AUTH-0005', diagnostic);
  return NextResponse.json(view.data, {
    headers: {
      'Cache-Control': 'no-store',
      'X-Request-ID': ids.requestId,
      'X-Correlation-ID': ids.correlationId,
    },
  });
}
