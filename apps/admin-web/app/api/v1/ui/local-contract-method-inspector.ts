import { NextResponse, NextRequest } from 'next/server';
import { z } from 'zod';
import {
  contractMethodPolicyResponseSchema,
  runtimeBindingResponseSchema,
  logicalContractResponseSchema,
  argumentRuleVersionResponseSchema,
} from '../../../../../../services/control-api/src/configuration/contract-assets';
import {
  contractMethodInspectionSchema,
  inspectionActorKey,
  inspectionReferencesMatch,
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

/** GET-only composition of existing authorized public resource readers. */
export async function readContractMethodInspection(request: NextRequest) {
  const ids = responseIds(request);
  const diagnosticRequest = new NextRequest(request.url, {
    headers: { 'X-Request-ID': ids.requestId, 'X-Correlation-ID': ids.correlationId },
  });
  const started = Date.now();
  const log = (stage: string, result: string, upstreamStatus = 0) => {
    process.stderr.write(
      `OPENPC_CONTRACT_METHOD_INSPECTOR|stage=${stage}|result=${result}|upstream_status=${upstreamStatus}|request_id=${ids.requestId}|correlation_id=${ids.correlationId}|elapsed_ms=${Date.now() - started}\n`,
    );
  };
  const runtime = await localRuntimeConfig().catch(() => undefined);
  if (!runtime) {
    log('runtime', 'unavailable');
    return safeProblem('PC-INTEGRATION-5001', diagnosticRequest);
  }
  const session = await authenticated(request, runtime);
  if (!session || session.contextMode !== 'PARTICIPANT' || !session.privacyDomainId) {
    log('context', 'unavailable');
    return safeProblem('PC-AUTH-0005', diagnosticRequest);
  }
  const pairs = [...request.nextUrl.searchParams];
  const query = z.strictObject({ methodPolicyId: z.string() }).safeParse(Object.fromEntries(pairs));
  const methodRef = query.success && methodPolicyReference(query.data.methodPolicyId);
  if (!methodRef || pairs.length !== 1) {
    log('selection', 'invalid');
    return safeProblem('PC-DATA-6004', diagnosticRequest);
  }
  const actor = {
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextEpoch: session.contextEpoch,
  };
  async function read<T>(collection: string, ref: string, schema: z.ZodType<T>, stage: string) {
    const response = await localOwnerFetch(
      `${runtime!.publicApiUrl}/api/v1/${collection}/${encodeURIComponent(ref)}`,
      {
        method: 'GET',
        cache: 'no-store',
        headers: publicHeaders(runtime!, session!, ids),
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]),
      },
    ).catch(() => undefined);
    const value = await ownerJson(response, schema, diagnosticRequest);
    log(stage, isResponse(value) ? 'unavailable' : 'loaded', response?.status);
    return value;
  }
  const method = await read(
    'contract-method-policies',
    methodRef,
    contractMethodPolicyResponseSchema,
    'method',
  );
  if (isResponse(method)) return method;
  if (method.contractMethodPolicyId !== methodRef) {
    log('method', 'reference-mismatch');
    return safeProblem('PC-INTEGRATION-5001', diagnosticRequest);
  }
  const binding = await read(
    'contract-runtime-bindings',
    method.runtimeBindingId,
    runtimeBindingResponseSchema,
    'binding',
  );
  if (isResponse(binding)) return binding;
  const contract = await read(
    'logical-contract-assets',
    binding.logicalContractId,
    logicalContractResponseSchema,
    'contract',
  );
  if (isResponse(contract)) return contract;
  const argumentRules =
    method.argumentRuleVersionId === null
      ? null
      : await read(
          'typed-argument-rule-versions',
          method.argumentRuleVersionId,
          argumentRuleVersionResponseSchema,
          'argument-rules',
        );
  if (isResponse(argumentRules)) return argumentRules;
  const view = contractMethodInspectionSchema.safeParse({
    actor,
    method,
    binding,
    contract,
    argumentRules:
      argumentRules === null
        ? null
        : {
            ...argumentRules,
            rules: argumentRules.rules.map((rule) => ({
              ...rule,
              // Normalize only validated booleans; integer strings stay exact.
              values: rule.values.map((value) =>
                typeof value === 'boolean' ? String(value) : value,
              ),
            })),
          },
  });
  if (!view.success || !inspectionReferencesMatch(view.data)) {
    log('projection', 'reference-mismatch');
    return safeProblem('PC-INTEGRATION-5001', diagnosticRequest);
  }
  const current = await authenticated(request, runtime);
  if (
    !current ||
    !current.privacyDomainId ||
    current.contextMode !== 'PARTICIPANT' ||
    inspectionActorKey({ ...current, privacyDomainId: current.privacyDomainId }) !==
      inspectionActorKey(actor)
  ) {
    log('context', 'changed');
    return safeProblem('PC-AUTH-0005', diagnosticRequest);
  }
  log('complete', 'loaded');
  return NextResponse.json(view.data, {
    headers: {
      'Cache-Control': 'no-store',
      'X-Request-ID': ids.requestId,
      'X-Correlation-ID': ids.correlationId,
    },
  });
}
