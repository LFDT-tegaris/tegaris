export const truthStates = [
  'SUCCESS',
  'AUTHORIZED_EMPTY',
  'DENIED',
  'LOADING',
  'UNKNOWN',
  'UNAVAILABLE',
  'STALE',
  'REORG',
  'PARTIAL',
  'CONFLICTING',
  'DEGRADED',
  'FAILED',
  'RETRY_ELIGIBLE',
  'FAILOVER_ELIGIBLE',
  'WRITE_AMBIGUITY',
  'RECOVERY',
  'ROLLBACK',
  'RETIREMENT',
  'UNINSTALL',
  'DECOMMISSION',
] as const;

export type TruthState = (typeof truthStates)[number];

export const actionIntents = [
  'VIEW',
  'CREATE_REGISTER',
  'QUALIFY_ADMIT',
  'ACTIVATE_USE',
  'REVIEW_CHANGE',
  'DEGRADE_INCIDENT',
  'RETRY',
  'FAILOVER',
  'RECONCILE_WRITE',
  'RECOVER',
  'ROLLBACK',
  'RETIRE',
  'UNINSTALL',
  'DECOMMISSION',
] as const;

export type ActionIntent = (typeof actionIntents)[number];

export interface RouteDefinition {
  readonly id: string;
  readonly path: string;
  readonly domain: string;
  readonly processDomainId: string;
  readonly primaryPersonaId: PersonaId;
  readonly destination: 'HOME' | 'GOVERN' | 'CONFIGURE' | 'OPERATE' | 'DEVELOP';
  readonly title: string;
}

export const personas = [
  'AUTHENTICATED_END_USER',
  'PLATFORM_ADMINISTRATOR',
  'PARTICIPANT_ADMINISTRATOR',
  'DELEGATED_ADMINISTRATOR',
  'POLICY_AUTHOR',
  'POLICY_APPROVER',
  'APPLICATION_WORKLOAD_OPERATOR',
  'RUNTIME_TRANSACTION_USER',
  'PRIVACY_VISIBILITY_USER',
  'AUDITOR_COMPLIANCE_REVIEWER',
  'EVIDENCE_CUSTODIAN',
  'SECURITY_INCIDENT_RESPONDER',
  'SRE_OPERATIONS_SUPPORT',
  'MULTI_RPC_PROVIDER_OPERATOR',
  'CLIENT_INDEXER_OPERATOR',
  'FACT_BRIDGE_SOURCE_OPERATOR',
  'DEPLOYMENT_MODULE_RELEASE_OPERATOR',
  'SEPARATE_OPENEXPLORER_OPERATOR',
] as const;

export type PersonaId = (typeof personas)[number];

const primaryPersonaByDomain: Readonly<Record<string, PersonaId>> = {
  'client-indexer-compatibility': 'CLIENT_INDEXER_OPERATOR',
  'config-import-export-settings': 'PLATFORM_ADMINISTRATOR',
  'deployment-contract': 'DEPLOYMENT_MODULE_RELEASE_OPERATOR',
  'evidence-audit-export': 'EVIDENCE_CUSTODIAN',
  'fact-source-projection-bridge': 'FACT_BRIDGE_SOURCE_OPERATOR',
  'governance-conformance-claims': 'AUDITOR_COMPLIANCE_REVIEWER',
  'ha-dr-recovery': 'SRE_OPERATIONS_SUPPORT',
  'identity-credential-access-review': 'AUDITOR_COMPLIANCE_REVIEWER',
  'login-context-session': 'AUTHENTICATED_END_USER',
  'membership-group-role-delegation': 'DELEGATED_ADMINISTRATOR',
  'module-lifecycle': 'DEPLOYMENT_MODULE_RELEASE_OPERATOR',
  'multi-rpc-provider': 'MULTI_RPC_PROVIDER_OPERATOR',
  'openexplorer-separate-product': 'SEPARATE_OPENEXPLORER_OPERATOR',
  'participant-lifecycle': 'PARTICIPANT_ADMINISTRATOR',
  'performance-capacity-backpressure': 'SRE_OPERATIONS_SUPPORT',
  'platform-administration': 'PLATFORM_ADMINISTRATOR',
  'policy-approve-release-activate-rollback': 'POLICY_APPROVER',
  'policy-author-compose-simulate': 'POLICY_AUTHOR',
  'privacy-explorer-integration': 'PRIVACY_VISIBILITY_USER',
  'rpc-read-write-transaction': 'RUNTIME_TRANSACTION_USER',
  'search-saved-views': 'AUTHENTICATED_END_USER',
  'security-privacy-incident': 'SECURITY_INCIDENT_RESPONDER',
  'support-diagnostics': 'SRE_OPERATIONS_SUPPORT',
  'visibility-event-disclosure': 'PRIVACY_VISIBILITY_USER',
};

function processDomainId(domain: string): string {
  return domain.replaceAll('-', '_').toUpperCase();
}

function registeredRoute(
  definition: Omit<RouteDefinition, 'processDomainId' | 'primaryPersonaId'>,
): RouteDefinition {
  const primaryPersonaId = primaryPersonaByDomain[definition.domain];
  if (!primaryPersonaId) throw new Error(`Unregistered UI process domain: ${definition.domain}`);
  return { ...definition, processDomainId: processDomainId(definition.domain), primaryPersonaId };
}

export const routes: readonly RouteDefinition[] = [
  registeredRoute({
    id: 'ROUTE-LOGIN-CONTEXT-SESSION',
    path: '/home/session',
    domain: 'login-context-session',
    destination: 'HOME',
    title: 'Session and context',
  }),
  registeredRoute({
    id: 'ROUTE-PLATFORM-ADMINISTRATION',
    path: '/govern/platform',
    domain: 'platform-administration',
    destination: 'GOVERN',
    title: 'Platform administration',
  }),
  registeredRoute({
    id: 'ROUTE-PARTICIPANT-LIFECYCLE',
    path: '/govern/participants',
    domain: 'participant-lifecycle',
    destination: 'GOVERN',
    title: 'Participant lifecycle',
  }),
  registeredRoute({
    id: 'ROUTE-MEMBERSHIP-GROUP-ROLE-DELEGATION',
    path: '/govern/memberships',
    domain: 'membership-group-role-delegation',
    destination: 'GOVERN',
    title: 'Memberships and roles',
  }),
  registeredRoute({
    id: 'ROUTE-IDENTITY-CREDENTIAL-ACCESS-REVIEW',
    path: '/govern/access',
    domain: 'identity-credential-access-review',
    destination: 'GOVERN',
    title: 'Access review',
  }),
  registeredRoute({
    id: 'ROUTE-POLICY-AUTHOR-COMPOSE-SIMULATE',
    path: '/configure/policies',
    domain: 'policy-author-compose-simulate',
    destination: 'CONFIGURE',
    title: 'Policy authoring',
  }),
  registeredRoute({
    id: 'ROUTE-POLICY-APPROVE-RELEASE-ACTIVATE-ROLLBACK',
    path: '/govern/policy-releases',
    domain: 'policy-approve-release-activate-rollback',
    destination: 'GOVERN',
    title: 'Policy releases',
  }),
  registeredRoute({
    id: 'ROUTE-RPC-READ-WRITE-TRANSACTION',
    path: '/operate/rpc-transactions',
    domain: 'rpc-read-write-transaction',
    destination: 'OPERATE',
    title: 'RPC transactions',
  }),
  registeredRoute({
    id: 'ROUTE-VISIBILITY-EVENT-DISCLOSURE',
    path: '/govern/visibility',
    domain: 'visibility-event-disclosure',
    destination: 'GOVERN',
    title: 'Visibility disclosure',
  }),
  registeredRoute({
    id: 'ROUTE-DEPLOYMENT-CONTRACT',
    path: '/develop/deployments',
    domain: 'deployment-contract',
    destination: 'DEVELOP',
    title: 'Deployments',
  }),
  registeredRoute({
    id: 'ROUTE-MULTI-RPC-PROVIDER',
    path: '/operate/multi-rpc',
    domain: 'multi-rpc-provider',
    destination: 'OPERATE',
    title: 'Multi-RPC providers',
  }),
  registeredRoute({
    id: 'ROUTE-CLIENT-INDEXER-COMPATIBILITY',
    path: '/develop/client-indexers',
    domain: 'client-indexer-compatibility',
    destination: 'DEVELOP',
    title: 'Client and indexer compatibility',
  }),
  registeredRoute({
    id: 'ROUTE-FACT-SOURCE-PROJECTION-BRIDGE',
    path: '/operate/facts',
    domain: 'fact-source-projection-bridge',
    destination: 'OPERATE',
    title: 'Fact source projection',
  }),
  registeredRoute({
    id: 'ROUTE-PRIVACY-EXPLORER-INTEGRATION',
    path: '/operate/privacy-explorer',
    domain: 'privacy-explorer-integration',
    destination: 'OPERATE',
    title: 'Privacy Explorer',
  }),
  registeredRoute({
    id: 'ROUTE-OPENEXPLORER-SEPARATE-PRODUCT',
    path: '/develop/openexplorer-boundary',
    domain: 'openexplorer-separate-product',
    destination: 'DEVELOP',
    title: 'OpenExplorer boundary',
  }),
  registeredRoute({
    id: 'ROUTE-EVIDENCE-AUDIT-EXPORT',
    path: '/operate/evidence',
    domain: 'evidence-audit-export',
    destination: 'OPERATE',
    title: 'Evidence audit',
  }),
  registeredRoute({
    id: 'ROUTE-SECURITY-PRIVACY-INCIDENT',
    path: '/operate/incidents',
    domain: 'security-privacy-incident',
    destination: 'OPERATE',
    title: 'Security and privacy incidents',
  }),
  registeredRoute({
    id: 'ROUTE-PERFORMANCE-CAPACITY-BACKPRESSURE',
    path: '/operate/capacity',
    domain: 'performance-capacity-backpressure',
    destination: 'OPERATE',
    title: 'Capacity and backpressure',
  }),
  registeredRoute({
    id: 'ROUTE-HA-DR-RECOVERY',
    path: '/operate/recovery',
    domain: 'ha-dr-recovery',
    destination: 'OPERATE',
    title: 'Recovery',
  }),
  registeredRoute({
    id: 'ROUTE-CONFIG-IMPORT-EXPORT-SETTINGS',
    path: '/configure/settings',
    domain: 'config-import-export-settings',
    destination: 'CONFIGURE',
    title: 'Settings',
  }),
  registeredRoute({
    id: 'ROUTE-MODULE-LIFECYCLE',
    path: '/develop/modules',
    domain: 'module-lifecycle',
    destination: 'DEVELOP',
    title: 'Module lifecycle',
  }),
  registeredRoute({
    id: 'ROUTE-SUPPORT-DIAGNOSTICS',
    path: '/operate/support',
    domain: 'support-diagnostics',
    destination: 'OPERATE',
    title: 'Support diagnostics',
  }),
  registeredRoute({
    id: 'ROUTE-SEARCH-SAVED-VIEWS',
    path: '/home/search',
    domain: 'search-saved-views',
    destination: 'HOME',
    title: 'Search and saved views',
  }),
  registeredRoute({
    id: 'ROUTE-GOVERNANCE-CONFORMANCE-CLAIMS',
    path: '/govern/conformance',
    domain: 'governance-conformance-claims',
    destination: 'GOVERN',
    title: 'Conformance claims',
  }),
];

export const redirects: Readonly<Record<string, string>> = {
  '/': '/home',
  '/home': '/home/session',
  '/govern': '/govern/conformance',
  '/configure': '/configure/policies',
  '/operate': '/operate/support',
  '/develop': '/develop/modules',
};

export function findRoute(pathname: string): RouteDefinition | undefined {
  return routes.find((route) => route.path === pathname);
}
