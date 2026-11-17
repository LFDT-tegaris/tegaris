import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import {
  abiArtifactResponseSchema,
  logicalContractResponseSchema,
  runtimeBindingResponseSchema,
  contractMethodPolicyResponseSchema,
} from '../../../../../../services/control-api/src/configuration/contract-assets';
import { collectionResponseSchema } from '../../../../../../services/control-api/src/configuration/resource-contracts';
import { contractCatalogueKind, contractCataloguePage } from '../../../../lib/contract-catalogue';
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

const querySchema = z.strictObject({
  kind: contractCatalogueKind,
  search: z.string().trim().max(160).default(''),
  parentId: z.string().optional(),
  cursor: z
    .string()
    .max(2048)
    .regex(/^pc2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u)
    .optional(),
});
const collections = {
  abis: ['abi-artifacts', 'abiDigest'],
  contracts: ['logical-contract-assets', 'displayName'],
  bindings: ['contract-runtime-bindings', 'contractAddress'],
  methods: ['contract-method-policies', 'canonicalSignature'],
} as const;

/** Read-only display projection. Every collection is admitted by its native owner. */
export async function readContractCatalogue(request: NextRequest) {
  const ids = responseIds(request);
  const diagnostic = new NextRequest(request.url, {
    headers: { 'X-Request-ID': ids.requestId, 'X-Correlation-ID': ids.correlationId },
  });
  const pairs = [...request.nextUrl.searchParams];
  const parsed = querySchema.safeParse(Object.fromEntries(pairs));
  if (!parsed.success || new Set(pairs.map(([key]) => key)).size !== pairs.length)
    return safeProblem('PC-DATA-6004', diagnostic);
  const query = parsed.data;
  const parent = query.parentId === undefined ? undefined : methodPolicyReference(query.parentId);
  if (
    query.parentId !== undefined &&
    (!parent || !['bindings', 'methods'].includes(query.kind) || query.search !== '')
  )
    return safeProblem('PC-DATA-6004', diagnostic);
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
  const [collection, searchField] = collections[query.kind];
  const nativeQuery = new URLSearchParams({ limit: '25', sort: '-updatedAt' });
  if (parent)
    nativeQuery.set(
      'filter',
      `${query.kind === 'bindings' ? 'logicalContractId' : 'runtimeBindingId'}:eq:${parent.slice(-36)}`,
    );
  else if (query.search !== '') nativeQuery.set('filter', `${searchField}:prefix:${query.search}`);
  if (query.cursor) nativeQuery.set('cursor', query.cursor);
  const response = await localOwnerFetch(
    `${runtime.publicApiUrl}/api/v1/${collection}?${nativeQuery}`,
    {
      method: 'GET',
      cache: 'no-store',
      headers: publicHeaders(runtime, session, ids),
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(15_000)]),
    },
  ).catch(() => undefined);
  const schema = {
    abis: collectionResponseSchema(abiArtifactResponseSchema),
    contracts: collectionResponseSchema(logicalContractResponseSchema),
    bindings: collectionResponseSchema(runtimeBindingResponseSchema),
    methods: collectionResponseSchema(contractMethodPolicyResponseSchema),
  }[query.kind];
  const native = await ownerJson<z.infer<typeof schema>>(response, schema, diagnostic);
  if (isResponse(native)) return native;
  if (
    native.completeness !== 'COMPLETE' ||
    native.total === null ||
    native.authorizedEmpty !== (native.items.length === 0) ||
    native.items.length > 25
  )
    return safeProblem('PC-INTEGRATION-5001', diagnostic);
  const items = native.items.map((item) => {
    const common = { revision: item.revision, createdAt: item.createdAt };
    if ('logicalName' in item)
      return {
        ...common,
        id: item.logicalContractId,
        label: item.displayName,
        logicalName: item.logicalName,
      };
    if ('canonicalSignature' in item)
      return {
        ...common,
        id: item.contractMethodPolicyId,
        label: item.canonicalSignature,
        runtimeBindingId: item.runtimeBindingId,
        abiArtifactId: item.abiArtifactId,
        selector: item.selector,
        effect: item.effect,
        state: item.state,
        approvalRequirement: item.approvalRequirement,
        mfaRequirement: item.mfaRequirement,
      };
    if ('contractAddress' in item)
      return {
        ...common,
        id: item.runtimeBindingId,
        label: item.contractAddress,
        logicalContractId: item.logicalContractId,
        abiArtifactId: item.abiArtifactId,
        contractAddress: item.contractAddress,
        abiDigest: item.abiDigest,
        chainId: item.chainId,
        networkId: item.networkId,
        state: item.state,
      };
    const functions = item.canonicalAbi.filter((value) => value.type === 'function');
    const names = [...new Set(functions.map((value) => value.name))];
    const label = names.length
      ? `${names.slice(0, 2).join(' · ')}${names.length > 2 ? ` + ${names.length - 2} more` : ''}`
      : 'ABI without callable methods';
    return {
      ...common,
      id: item.abiArtifactId,
      label,
      abiDigest: item.abiDigest,
      source: item.provenance.source,
      functions: functions.length,
    };
  });
  const projected = contractCataloguePage.safeParse({ ...native, kind: query.kind, actor, items });
  if (!projected.success) return safeProblem('PC-INTEGRATION-5001', diagnostic);
  if (
    projected.data.items.some((item) => {
      if (parent)
        return 'logicalContractId' in item
          ? item.logicalContractId !== parent
          : 'runtimeBindingId' in item
            ? item.runtimeBindingId !== parent
            : true;
      const value = query.kind === 'abis' && 'abiDigest' in item ? item.abiDigest : item.label;
      return !value.startsWith(query.search);
    }) ||
    BigInt(projected.data.total) < BigInt(projected.data.items.length)
  )
    return safeProblem('PC-INTEGRATION-5001', diagnostic);
  const current = await authenticated(request, runtime);
  if (
    !current ||
    current.contextMode !== 'PARTICIPANT' ||
    !current.privacyDomainId ||
    inspectionActorKey({ ...current, privacyDomainId: current.privacyDomainId }) !==
      inspectionActorKey(actor)
  )
    return safeProblem('PC-AUTH-0005', diagnostic);
  return NextResponse.json(projected.data, {
    headers: {
      'Cache-Control': 'no-store',
      'X-Request-ID': ids.requestId,
      'X-Correlation-ID': ids.correlationId,
    },
  });
}
