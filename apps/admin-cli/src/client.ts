import { z } from 'zod';
import { uuidV7 } from '../../../services/module-registry/src/domain/operation-id.js';
import {
  operationResponseSchema,
  runtimeTargetResponseSchema,
} from '../../../services/control-api/src/configuration/resource-contracts.js';
import { deploymentIntentResponseSchema } from '../../../services/control-api/src/configuration/deployment/intent-contract.js';
import { deploymentSubmissionResponseSchema } from '../../../services/control-api/src/configuration/deployment/submission-contract.js';
import { nativeValueAuthorizationResponseSchema } from '../../../services/control-api/src/configuration/native-value/contract.js';
import { ciglAnalysisResponseSchema } from '../../../services/control-api/src/configuration/cigl/analysis-contract.js';
import { ciglGrantResponseSchema } from '../../../services/control-api/src/configuration/cigl/grant-contract.js';
import { ciglSettingsResponseSchema } from '../../../services/control-api/src/configuration/cigl/settings-contract.js';

export class CliError extends Error {
  constructor(
    readonly code:
      'INPUT' | 'AUTHENTICATION' | 'CONTEXT' | 'TRANSPORT' | 'RESPONSE' | 'DENIED' | 'STALE',
    readonly problem?: { code: string; status: number; truthState?: string; retryable?: boolean },
  ) {
    super(code);
  }
}

export function responseError(status: number, value: unknown): CliError {
  const parsed = z
    .object({
      code: z.string().regex(/^PC-[A-Z]+-[0-9]{4}$/u),
      status: z.literal(status),
      truthState: z
        .string()
        .regex(/^[A-Z_]{1,40}$/u)
        .optional(),
      retryable: z.boolean().optional(),
    })
    .safeParse(value);
  return new CliError(
    status === 401
      ? 'AUTHENTICATION'
      : [403, 404].includes(status)
        ? 'DENIED'
        : [409, 412].includes(status)
          ? 'STALE'
          : status === 422
            ? 'INPUT'
            : 'RESPONSE',
    parsed.success ? parsed.data : undefined,
  );
}

export const configSchema = z
  .strictObject({
    apiUrl: z.url(),
    participantId: z.uuid(),
    privacyDomainId: z.uuid(),
    sessionFile: z.string().min(1).optional(),
    browserProfile: z.string().min(1).optional(),
    loginHint: z.string().min(1).max(256).optional(),
    localDevelopment: z.boolean().default(false),
  })
  .refine((value) => Boolean(value.sessionFile) !== Boolean(value.browserProfile));
export type CliConfig = z.infer<typeof configSchema>;

export const sessionFileSchema = z.strictObject({
  origin: z.url(),
  sessionToken: z.string().regex(/^[0-9a-f-]{36}\.[0-9a-f-]{36}$/u),
});

const sessionView = z.object({
  principalId: z.uuid(),
  participantId: z.uuid(),
  privacyDomainId: z.uuid().optional(),
  contextMode: z.enum(['PLATFORM', 'PARTICIPANT']),
  state: z.enum([
    'AUTHENTICATING',
    'ACTIVE',
    'STEP_UP_REQUIRED',
    'REVOKED',
    'EXPIRED',
    'COMPROMISED',
  ]),
});

export const resources = {
  'operation': {
    collection: 'operations',
    schema: operationResponseSchema,
    urn: false,
    identity: 'operationId',
  },
  'runtime-target': {
    collection: 'runtime-targets',
    schema: runtimeTargetResponseSchema,
    urn: true,
    identity: 'targetId',
  },
  'deployment-intent': {
    collection: 'deployment-intents',
    schema: deploymentIntentResponseSchema,
    urn: true,
    identity: 'deploymentIntentId',
  },
  'deployment-submission': {
    collection: 'deployment-submissions',
    schema: deploymentSubmissionResponseSchema,
    urn: true,
    identity: 'deploymentSubmissionId',
  },
  'native-value': {
    collection: 'native-value-authorizations',
    schema: nativeValueAuthorizationResponseSchema,
    urn: true,
    identity: 'nativeValueAuthorizationId',
  },
  'cigl-analysis': {
    collection: 'cigl-analyses',
    schema: ciglAnalysisResponseSchema,
    urn: true,
    identity: 'analysisId',
  },
  'cigl-grant': {
    collection: 'cigl-grants',
    schema: ciglGrantResponseSchema,
    urn: true,
    identity: 'grantId',
  },
  'cigl-settings': {
    collection: 'cigl-settings',
    schema: ciglSettingsResponseSchema,
    urn: true,
    identity: 'ciglSettingsId',
  },
} as const;
export type ResourceKind = keyof typeof resources;

/** Credentials are bound to one configured origin. Redirects never receive them. */
export function apiOrigin(config: CliConfig): string {
  const url = new URL(config.apiUrl);
  if (
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash ||
    (url.protocol !== 'https:' &&
      !(
        config.localDevelopment &&
        url.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
      ))
  )
    throw new CliError('INPUT');
  return url.origin;
}

async function boundedJson(response: Response): Promise<unknown> {
  if (
    !response.headers.get('content-type')?.toLowerCase().includes('application/json') ||
    !response.body
  )
    throw new CliError('RESPONSE');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.length;
      if (size > 4 * 1024 * 1024) throw new CliError('RESPONSE');
      chunks.push(chunk.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new CliError('RESPONSE');
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

export class AdministrationClient {
  readonly origin: string;
  constructor(
    readonly config: CliConfig,
    private readonly sessionToken: string,
    private readonly transport: typeof fetch = fetch,
  ) {
    this.origin = apiOrigin(config);
    if (!sessionFileSchema.shape.sessionToken.safeParse(sessionToken).success)
      throw new CliError('AUTHENTICATION');
  }

  private async get(path: string): Promise<unknown> {
    const requestId = uuidV7();
    let response: Response;
    try {
      response = await this.transport(`${this.origin}${path}`, {
        method: 'GET',
        redirect: 'error',
        cache: 'no-store',
        signal: AbortSignal.timeout(15_000),
        headers: {
          'Cookie': `__Host-openpc_session=${this.sessionToken}`,
          'OpenPC-API-Version': '1',
          'OpenPC-Participant-ID': `urn:openpc:participant:${this.config.participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${this.config.privacyDomainId}`,
          'X-Request-ID': requestId,
          'X-Correlation-ID': requestId,
          'Origin': this.origin,
        },
      });
    } catch {
      throw new CliError('TRANSPORT');
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      // Never print upstream error text, URLs, headers or hidden identifiers.
      throw new CliError(
        response.status === 401
          ? 'AUTHENTICATION'
          : [403, 404].includes(response.status)
            ? 'DENIED'
            : 'RESPONSE',
      );
    }
    return boundedJson(response);
  }

  async session() {
    const parsed = sessionView.safeParse(await this.get('/api/v1/session'));
    if (!parsed.success || parsed.data.state !== 'ACTIVE') throw new CliError('AUTHENTICATION');
    if (
      parsed.data.contextMode !== 'PARTICIPANT' ||
      parsed.data.participantId !== this.config.participantId ||
      parsed.data.privacyDomainId !== this.config.privacyDomainId
    )
      throw new CliError('CONTEXT');
    return parsed.data;
  }

  async read(kind: ResourceKind, reference: string) {
    const resource = resources[kind];
    const id = reference.replace(/^urn:openpc:(?:resource|operation):/u, '');
    if (
      !z.uuid().safeParse(id).success ||
      (reference.includes(':') &&
        reference !== `urn:openpc:${resource.urn ? 'resource' : 'operation'}:${id}`)
    )
      throw new CliError('INPUT');
    // Validate live identity/context on every poll, including after a restart.
    await this.session();
    const parsed = resource.schema.safeParse(
      await this.get(
        `/api/v1/${resource.collection}/${encodeURIComponent(resource.urn ? `urn:openpc:resource:${id}` : id)}`,
      ),
    );
    if (!parsed.success) throw new CliError('RESPONSE');
    if (
      (parsed.data as Record<string, unknown>)[resource.identity] !==
      (resource.urn ? `urn:openpc:resource:${id}` : id)
    )
      throw new CliError('RESPONSE');
    return parsed.data;
  }
}
