import {
  actionIntents,
  personas,
  routes,
  truthStates,
  type ActionIntent,
  type PersonaId,
  type TruthState,
} from './registry';
import {
  safeProblemRelations,
  type AuthorizedAction,
  type ProcessSnapshot,
  type SafeProblem,
  type UiEvent,
} from './contracts';

const digest = `sha256:${'0'.repeat(64)}`;
const observedAt = '2026-09-06T00:00:00.000000Z';

export interface LocalUiFixture {
  readonly enabled: boolean;
  readonly persona?: string;
  readonly state?: string;
  readonly intent?: string;
  readonly contextEpoch?: string;
  readonly locale?: string;
  readonly timeZone?: string;
  readonly density?: string;
  readonly theme?: string;
}

export interface BffResult<T> {
  readonly status: number;
  readonly body: T;
}

function safeProblem(
  code: keyof typeof safeProblemRelations,
  title: string,
): BffResult<SafeProblem> {
  const relation = safeProblemRelations[code];
  return {
    status: relation.status,
    body: {
      type: relation.problemType,
      code,
      status: relation.status,
      title,
      traceId: '00000000-0000-7000-8000-000000000002',
      truthState: relation.truthState,
      retryable: relation.retryable,
    },
  };
}

function isPersona(value: string | undefined): value is PersonaId {
  return Boolean(value && (personas as readonly string[]).includes(value));
}

function isState(value: string | undefined): value is TruthState {
  return Boolean(value && (truthStates as readonly string[]).includes(value));
}

function isIntent(value: string | undefined): value is ActionIntent {
  return Boolean(value && (actionIntents as readonly string[]).includes(value));
}

function authorize(domain: string, fixture: LocalUiFixture): BffResult<SafeProblem> | undefined {
  const route = findRouteByDomain(domain);
  if (!route) return safeProblem('PC-AUTH-0005', 'The requested process was not found.');
  if (!fixture.enabled) {
    return safeProblem('PC-INTEGRATION-5001', 'The requested process is unavailable.');
  }
  if (!isPersona(fixture.persona) || fixture.persona !== route.primaryPersonaId) {
    return safeProblem('PC-AUTH-0005', 'The requested process was not found.');
  }
  if (!isState(fixture.state) || !isIntent(fixture.intent)) {
    return safeProblem('PC-DATA-6004', 'The process fixture is invalid.');
  }
  return undefined;
}

function findRouteByDomain(domain: string) {
  return routes.find((route) => route.domain === domain);
}

function actionFor(domain: string, intent: ActionIntent): AuthorizedAction | undefined {
  if (intent === 'VIEW') return undefined;
  return {
    actionIntentId: `ACT-UI_${domain.replaceAll('-', '_').toUpperCase()}_${intent}-V1`,
    actionIntentDigest: digest,
    operationId: `commandUi${domain
      .replaceAll('-', ' ')
      .replace(/(?:^| )(\w)/g, (_, c) => c.toUpperCase())
      .replaceAll(' ', '')}${intent.replaceAll('_', '')}`,
    method: 'POST',
    path: `/api/v1/ui/process-domains/${domain}/actions/${intent.toLowerCase().replaceAll('_', '-')}`,
    riskClass: 'STANDARD',
    stepUp: 'NONE',
    idempotency: 'KEY_UNTIL_TERMINAL',
    etagRequired: true,
  };
}

export function readProcessSnapshot(
  domain: string,
  fixture: LocalUiFixture,
): BffResult<ProcessSnapshot | SafeProblem> {
  const denied = authorize(domain, fixture);
  if (denied) return denied;
  const route = findRouteByDomain(domain);
  if (!route || !isState(fixture.state) || !isIntent(fixture.intent)) {
    return safeProblem('PC-DATA-6004', 'The process fixture is invalid.');
  }
  const action = actionFor(domain, fixture.intent);
  const truthState = fixture.persona === route.primaryPersonaId ? fixture.state : 'DENIED';
  return {
    status: 200,
    body: {
      snapshotId: '00000000-0000-7000-8000-000000000001',
      routeId: route.id,
      processDomainId: route.processDomainId,
      contextDigest: digest,
      authorityGeneration: fixture.contextEpoch ?? '1',
      policyGeneration: fixture.contextEpoch ?? '1',
      truthState,
      scope: { plane: 'PLATFORM', participantId: null, privacyDomainId: null },
      freshness: { observedAt, state: truthState === 'STALE' ? 'STALE' : 'CURRENT' },
      completeness: truthState === 'PARTIAL' ? 'PARTIAL' : 'COMPLETE',
      items: [],
      authorizedActions: action ? [action] : [],
      evidenceRefs: [],
      observedAt,
    },
  };
}

export function invokeProcessAction(
  domain: string,
  intentPath: string,
  fixture: LocalUiFixture,
  request: {
    readonly csrfToken?: string;
    readonly idempotencyKey?: string;
    readonly etag?: string;
    readonly actionIntentId?: string;
    readonly actionIntentDigest?: string;
  },
): BffResult<Record<string, never> | SafeProblem> {
  const denied = authorize(domain, fixture);
  if (denied) return denied;
  if (!isIntent(fixture.intent) || fixture.intent === 'VIEW') {
    return safeProblem('PC-AUTH-0005', 'The requested process action was not found.');
  }
  const action = actionFor(domain, fixture.intent);
  if (
    !action ||
    intentPath !== fixture.intent.toLowerCase().replaceAll('_', '-') ||
    request.csrfToken !== 'local-fixture-csrf' ||
    !request.idempotencyKey ||
    request.etag !== '"local-fixture-etag"' ||
    request.actionIntentId !== action.actionIntentId ||
    request.actionIntentDigest !== action.actionIntentDigest
  ) {
    return safeProblem('PC-DATA-6004', 'The process action request is invalid.');
  }
  return { status: 200, body: {} };
}

export function processEvents(fixture: LocalUiFixture): BffResult<UiEvent | SafeProblem> {
  if (!fixture.enabled || !isPersona(fixture.persona) || !isState(fixture.state)) {
    return safeProblem('PC-INTEGRATION-5001', 'The process event stream is unavailable.');
  }
  return { status: 200, body: { type: 'snapshot-invalidated' } };
}
