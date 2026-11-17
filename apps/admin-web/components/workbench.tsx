'use client';

import { useQuery } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowLeftRight,
  Building2,
  CheckCircle2,
  CircleHelp,
  ClipboardList,
  EyeOff,
  FileCode2,
  FlaskConical,
  LoaderCircle,
  Menu,
  Network,
  ShieldAlert,
  ShieldCheck,
  UserRound,
} from 'lucide-react';
import Link from 'next/link';
import { BrandLogo } from './brand-logo';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { useContext, useEffect, useId, useRef, useState } from 'react';
import { CentralSessionContext } from './central-session-context';
import { Link as AriaLink } from 'react-aria-components';
import { z } from 'zod';

import {
  BffProblem,
  readSessionBootstrap,
  readSnapshot,
  routes,
  type RouteDefinition,
  type TruthState,
  type UiSessionBootstrap,
} from '@openpc/ui-shell';

import { ActionPanel } from './action-panel';
import { WorkspaceStatus, type WorkspaceStatusProps } from './workspace-status';
import { WorkflowDetails } from './workflow-details';
import { EvaluationContext } from './evaluation-context';
import { LocalSessionSurface } from './local-session';
import { ParticipantRoleWorkflow } from './participant-role-workflow';
import { ParticipantGrantWorkflow } from './participant-grant-workflow';
import { PrincipalWorkflow } from './principal-workflow';
import { GroupWorkflow } from './group-workflow';
import { InvitationWorkflow } from './invitation-workflow';
import { InvitationAcceptanceWorkflow } from './invitation-acceptance';
import { ParticipantBootstrapWorkflow } from './participant-bootstrap';
import { DirectoryWorkflow } from './directory-workflow';
import { AccessReviewWorkflow } from './access-review-workflow';
import { accessReviewTarget } from '../lib/access-review';
import { WorkloadWorkflow } from './workload-workflow';
import { CredentialWorkflow } from './credential-workflow';
import { RecoveryWorkflow } from './recovery-workflow';
import { ParticipantEnvelopeWorkflow } from './participant-envelope-workflow';
import { RpcPlatformAccess } from './rpc-platform-access';
import { PlatformRecoveryWorkflow } from './platform-recovery-workflow';
import { PlatformCeilingWorkflow } from './platform-ceiling-workflow';
import { RpcParticipantAccess } from './rpc-participant-access';
import { PolicyComposer } from './policy-composer';
import { VisibilityWorkflow } from './visibility-workflow';
import { PolicyReleaseWorkflow } from './policy-release-workflow';
import { SetupWorkflow } from './setup-workflow';
import { TransactionWorkflow } from './transaction-workflow';
import { FactWorkflow } from './fact-workflow';
import { PrivacyExplorerWorkflow } from './privacy-explorer-workflow';
import { EvidenceWorkflow } from './evidence-workflow';
import { NotificationWorkflow } from './notifications/notification-workflow';
import { NotificationEndpointWorkflow } from './notifications/notification-endpoint-workflow';
import { WorkItemWorkflow } from './work-items/work-item-workflow';

const evaluationDestinations = [
  {
    label: 'Account & workspace',
    href: '/home/session',
    icon: UserRound,
    detail: 'Manage account security and choose your working context.',
  },
  {
    label: 'Organizations & access',
    href: '/govern/participants',
    icon: Building2,
    relatedPaths: ['/govern/memberships', '/govern/access'],
    detail: 'Manage organizations, users, roles and access.',
  },
  {
    label: 'Networks & providers',
    href: '/operate/multi-rpc',
    icon: Network,
    detail: 'Manage network connections and check provider health.',
  },
  {
    label: 'Contracts & ABI',
    href: '/develop/modules',
    icon: FileCode2,
    relatedPaths: ['/develop/deployments'],
    detail: 'Register contracts, ABIs and network bindings.',
  },
  {
    label: 'Policies',
    href: '/configure/policies',
    icon: ShieldCheck,
    detail: 'Define permissions and review policy versions.',
  },
  {
    label: 'Simulation',
    href: '/configure/policies?view=simulation',
    icon: FlaskConical,
    detail: 'Test policy decisions without changing active permissions.',
  },
  {
    label: 'Approvals & releases',
    href: '/govern/policy-releases',
    icon: CheckCircle2,
    detail: 'Review changes and track publication and activation.',
  },
  {
    label: 'Contract interactions',
    href: '/operate/rpc-transactions',
    icon: ArrowLeftRight,
    detail: 'Read permitted contract methods and prepare governed transactions.',
  },
  {
    label: 'Data & event privacy',
    href: '/operate/privacy-explorer',
    icon: EyeOff,
    relatedPaths: ['/govern/visibility'],
    detail: 'Inspect the data and events available in your current privacy context.',
  },
  {
    label: 'Evidence & operations',
    href: '/operate/evidence',
    icon: ClipboardList,
    relatedPaths: ['/operate/support', '/operate/recovery'],
    detail: 'Review decisions, export approved evidence and manage recovery.',
  },
] as const;

const destinations = [
  { label: 'Home', href: '/home' },
  { label: 'Govern', href: '/govern' },
  { label: 'Configure', href: '/configure' },
  { label: 'Operate', href: '/operate' },
  { label: 'Contracts', href: '/develop' },
] as const;

export const i08PreferenceTransitionEvent = 'openpc:i08-preference-transition';
const i08ValidationToken = /^[A-Za-z0-9:_-]{1,512}$/;

interface TransitionBound<T> {
  readonly transitionToken: string | null;
  readonly value: T;
}

function truthClass(state: TruthState): string {
  if (state === 'SUCCESS') return 'border-[color:var(--success)] text-[color:var(--success)]';
  if (state === 'DENIED' || state === 'FAILED' || state === 'WRITE_AMBIGUITY')
    return 'border-[color:var(--danger)] text-[color:var(--danger)]';
  return 'border-[color:var(--warning)] text-[color:var(--warning)]';
}

function TruthIcon({ state }: { readonly state: TruthState }) {
  if (state === 'SUCCESS') return <CheckCircle2 aria-hidden size={20} />;
  if (state === 'LOADING')
    return (
      <LoaderCircle aria-hidden className="animate-spin motion-reduce:animate-none" size={20} />
    );
  if (state === 'DENIED' || state === 'FAILED') return <ShieldAlert aria-hidden size={20} />;
  return <AlertTriangle aria-hidden size={20} />;
}

export function Workbench({
  route,
  evaluationUi = false,
}: Readonly<{ route: RouteDefinition; evaluationUi?: boolean }>) {
  const centralized = useContext(CentralSessionContext);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();
  const validationToken = searchParams.get('i08-validation');
  const policyView = evaluationUi
    ? searchParams.get('view') === 'simulation'
      ? 'simulation'
      : 'author'
    : 'all';
  const currentEvaluation = evaluationDestinations.find((item) => {
    const [path, query] = item.href.split('?');
    return (
      (path === pathname ||
        ('relatedPaths' in item && item.relatedPaths.some((value) => value === pathname))) &&
      (query
        ? searchParams.get('view') === 'simulation'
        : !(pathname === '/configure/policies' && searchParams.get('view') === 'simulation'))
    );
  });
  const workItemJourney =
    route.domain === 'support-diagnostics' && searchParams.get('view') === 'work-items';
  const notificationJourney =
    route.domain === 'login-context-session' && searchParams.get('view') === 'notifications';
  const notificationEndpointJourney =
    route.domain === 'login-context-session' &&
    searchParams.get('view') === 'notification-endpoints';
  const participantJourney = route.domain === 'participant-lifecycle';
  const participantRpcJourney = participantJourney && searchParams.get('view') === 'rpc-access';
  const requestedHandoffPhase = searchParams.get('phase');
  const handoffPhase =
    requestedHandoffPhase === 'envelopes' || requestedHandoffPhase === 'assignments'
      ? requestedHandoffPhase
      : 'ceiling';
  const factJourney = route.domain === 'fact-source-projection-bridge';
  const explorerJourney = route.domain === 'privacy-explorer-integration';
  const evidenceJourney = route.domain === 'evidence-audit-export';
  const providerSetupJourney = route.domain === 'multi-rpc-provider';
  const networkView =
    searchParams.get('view') === 'runtime'
      ? 'runtime'
      : searchParams.get('view') === 'profiles'
        ? 'profiles'
        : 'providers';
  const runtimeSetupJourney = route.domain === 'config-import-export-settings';
  const navigationId = useId();
  const [navigationOpen, setNavigationOpen] = useState(false);
  const navigationHeader = useRef<HTMLElement>(null);
  const navigationToggle = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!navigationOpen) return;
    const closeOutside = (event: PointerEvent) => {
      if (event.target instanceof Node && !navigationHeader.current?.contains(event.target))
        setNavigationOpen(false);
    };
    document.addEventListener('pointerdown', closeOutside);
    return () => document.removeEventListener('pointerdown', closeOutside);
  }, [navigationOpen]);
  const moduleJourney = route.domain === 'module-lifecycle';
  const deploymentJourney = route.domain === 'deployment-contract';
  const transactionJourney = route.domain === 'rpc-read-write-transaction';
  const policyReleaseJourney = route.processDomainId === 'POLICY_APPROVE_RELEASE_ACTIVATE_ROLLBACK';
  const roleJourney = route.domain === 'membership-group-role-delegation';
  const principalJourney = roleJourney && searchParams.get('view') === 'principals';
  const groupJourney = roleJourney && searchParams.get('view') === 'groups';
  const invitationJourney = roleJourney && searchParams.get('view') === 'invitations';
  const invitationAcceptanceJourney =
    roleJourney && searchParams.get('view') === 'invitation-acceptance';
  const directoryJourney = roleJourney && searchParams.get('view') === 'directory';
  const workloadJourney = roleJourney && searchParams.get('view') === 'workloads';
  const credentialJourney = roleJourney && searchParams.get('view') === 'credentials';
  const recoveryJourney = roleJourney && searchParams.get('view') === 'recovery';
  const grantJourney = roleJourney && searchParams.get('view') === 'grants';
  const accessReviewJourney =
    route.domain === 'identity-credential-access-review' ||
    (roleJourney && searchParams.get('view') === 'access-review');
  const rpcAccessJourney = roleJourney && searchParams.get('view') === 'rpc-access';
  const initialGrant = accessReviewTarget.safeParse({
    id: searchParams.get('grantId'),
    kind: searchParams.get('kind'),
  });
  const initialPrincipal = z.uuid().safeParse(searchParams.get('principalId'));
  const initialEnvelope = z.uuid().safeParse(searchParams.get('authorityEnvelopeId'));
  const initialRole = z
    .string()
    .regex(/^urn:openpc:role:[0-9a-f-]{36}$/u)
    .safeParse(searchParams.get('roleId'));
  const initialCapabilities = (searchParams.get('capabilityIds') ?? '')
    .split(',')
    .filter((value) => ['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION'].includes(value));
  const initialResources = searchParams.get('resourceIds') ?? undefined;
  const customJourney =
    providerSetupJourney ||
    runtimeSetupJourney ||
    workItemJourney ||
    notificationJourney ||
    notificationEndpointJourney ||
    moduleJourney ||
    evidenceJourney ||
    explorerJourney ||
    factJourney ||
    participantJourney ||
    policyReleaseJourney ||
    roleJourney ||
    accessReviewJourney ||
    deploymentJourney ||
    transactionJourney;
  const snapshotJourney = !customJourney && !(evaluationUi && route.path === '/home/session');
  const query = useQuery({
    queryKey: ['ui-process', route.id, validationToken],
    queryFn: async ({
      signal,
    }): Promise<TransitionBound<Awaited<ReturnType<typeof readSnapshot>>>> => ({
      transitionToken: validationToken,
      value: await readSnapshot(route.domain, signal),
    }),
    enabled: snapshotJourney,
  });
  const session = useQuery({
    queryKey: ['ui-session-bootstrap', validationToken],
    queryFn: async ({ signal }): Promise<TransitionBound<UiSessionBootstrap>> => ({
      transitionToken: validationToken,
      value: await readSessionBootstrap(signal),
    }),
  });

  useEffect(() => headingRef.current?.focus(), [route.id]);

  useEffect(() => {
    if (validationToken === null) return;
    const transition = (event: Event) => {
      if (!(event instanceof CustomEvent)) return;
      const nextToken = (event.detail as { readonly validationToken?: unknown } | null)
        ?.validationToken;
      if (typeof nextToken !== 'string' || !i08ValidationToken.test(nextToken)) return;
      const nextParameters = new URLSearchParams(searchParams.toString());
      nextParameters.set('i08-validation', nextToken);
      router.replace(`${pathname}?${nextParameters.toString()}`, { scroll: false });
    };
    window.addEventListener(i08PreferenceTransitionEvent, transition);
    return () => window.removeEventListener(i08PreferenceTransitionEvent, transition);
  }, [pathname, router, searchParams, validationToken]);

  const snapshot = query.data?.value;
  const sessionBootstrap = session.data?.value;
  const transitionReady =
    (!snapshotJourney || query.data?.transitionToken === validationToken) &&
    session.data?.transitionToken === validationToken;
  const problem = query.error instanceof BffProblem ? query.error.problem : undefined;

  return (
    <div
      className={`${evaluationUi ? 'evaluation-workbench ' : ''}min-h-screen bg-[color:var(--canvas)]`}
      data-density={sessionBootstrap?.density ?? 'comfortable'}
      data-i08-session-transition-token={session.data?.transitionToken ?? ''}
      data-i08-snapshot-transition-token={query.data?.transitionToken ?? ''}
      data-i08-transition-ready={transitionReady ? 'true' : 'false'}
      data-locale={sessionBootstrap?.locale ?? 'en-US'}
      data-theme={sessionBootstrap?.theme ?? 'light'}
      data-time-zone={sessionBootstrap?.timeZone ?? 'UTC'}
    >
      <a
        className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-10 focus:bg-[color:var(--surface)] focus:p-3"
        href="#workbench-main"
      >
        Skip to main content
      </a>
      {evaluationUi ? (
        <header
          ref={navigationHeader}
          className="evaluation-sidebar"
          onKeyDown={(event) => {
            if (
              event.key !== 'Escape' ||
              !navigationOpen ||
              event.defaultPrevented ||
              event.nativeEvent.isComposing
            )
              return;
            event.preventDefault();
            setNavigationOpen(false);
            navigationToggle.current?.focus();
          }}
        >
          <Link className="evaluation-brand" href="/home/session">
            <BrandLogo light />
            <small>Application Layer Privacy</small>
          </Link>
          <button
            ref={navigationToggle}
            type="button"
            className="evaluation-navigation-toggle"
            aria-expanded={navigationOpen}
            aria-controls={navigationId}
            onClick={() => setNavigationOpen((open) => !open)}
          >
            <Menu aria-hidden size={18} />
            <span>
              Navigation
              <span className="evaluation-current-destination">
                {currentEvaluation?.label ?? 'Workspace'}
              </span>
            </span>
          </button>
          <nav id={navigationId} aria-label="Primary navigation" data-expanded={navigationOpen}>
            {[
              { label: 'Workspace', paths: ['/home/session', '/govern/participants'] },
              {
                label: 'Policy management',
                paths: [
                  '/develop/modules',
                  '/configure/policies',
                  '/configure/policies?view=simulation',
                  '/govern/policy-releases',
                ],
              },
              {
                label: 'Operations',
                paths: [
                  '/operate/multi-rpc',
                  '/operate/rpc-transactions',
                  '/operate/privacy-explorer',
                  '/operate/evidence',
                ],
              },
            ].map((group) => (
              <div className="evaluation-navigation-group" key={group.label}>
                <p className="evaluation-label">{group.label}</p>
                {group.paths.map((path) => {
                  const item = evaluationDestinations.find(
                    (destination) => destination.href === path,
                  )!;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      aria-current={currentEvaluation === item ? 'page' : undefined}
                      onClick={() => setNavigationOpen(false)}
                    >
                      <span className="evaluation-navigation-icon">
                        <item.icon aria-hidden size={18} />
                      </span>
                      <span>{item.label}</span>
                    </Link>
                  );
                })}
              </div>
            ))}
          </nav>
          <div className="evaluation-release-note">
            <ShieldCheck aria-hidden size={16} />
            <p>Application privacy</p>
          </div>
        </header>
      ) : (
        <header className="border-b border-[color:var(--border)] bg-[color:var(--surface)]">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 p-4">
            <Link className="font-semibold" href="/home">
              Tegaris
            </Link>
            <nav aria-label="Primary navigation" className="flex flex-wrap gap-3">
              {destinations.map((item) => (
                <AriaLink href={item.href} key={item.href}>
                  {item.label}
                </AriaLink>
              ))}
            </nav>
            <Link className="underline" href="/operate/support?view=work-items">
              Work items
            </Link>
            <Link className="underline" href="/home/session?view=notifications">
              Notifications
            </Link>
            <Link className="underline" href="/home/session?view=notification-endpoints">
              Notification endpoints
            </Link>
            <Link className="underline" href="/home/session">
              Session / Sign out
            </Link>
            <div
              aria-label="Current context"
              className="text-sm text-[color:var(--muted)]"
              role="region"
            >
              Current workspace
            </div>
          </div>
        </header>
      )}
      <div aria-live="polite" className="sr-only" role="status"></div>
      <main className="mx-auto max-w-7xl p-4 sm:p-6" id="workbench-main" tabIndex={-1}>
        {centralized ? (
          <LocalSessionSurface appearance="menu" />
        ) : (
          evaluationUi && <EvaluationContext routeKey={`${pathname}:${validationToken ?? ''}`} />
        )}
        <header className="console-page-header">
          <p className="evaluation-eyebrow text-sm text-[color:var(--muted)]">
            {evaluationUi ? 'Tegaris / Application Layer Privacy' : route.destination}
          </p>
          <h1 className="mt-1 text-3xl font-semibold" ref={headingRef} tabIndex={-1}>
            {currentEvaluation?.label ?? route.title}
          </h1>
          <p className="mt-2 max-w-3xl text-[color:var(--muted)]">
            {currentEvaluation?.detail ??
              'Available actions depend on your current session and permissions.'}
          </p>
        </header>
        <section
          aria-live="polite"
          aria-atomic="true"
          className="mt-6"
          aria-label="Process status"
          hidden={!customJourney && !snapshotJourney}
        >
          {participantJourney ? (
            <>
              <nav
                aria-label={evaluationUi ? 'Organization administration' : 'Participant governance'}
                className="feature-navigation flex flex-wrap gap-4"
              >
                <Link
                  href="/govern/participants"
                  aria-current={
                    ![
                      'first-administrator',
                      'rpc-access',
                      'platform-recovery',
                      'platform-ceiling',
                    ].includes(searchParams.get('view') ?? '')
                      ? 'page'
                      : undefined
                  }
                >
                  {evaluationUi ? 'Authority requests' : 'Participant envelopes'}
                </Link>
                <Link
                  href="/govern/participants?view=first-administrator"
                  aria-current={
                    searchParams.get('view') === 'first-administrator' ? 'page' : undefined
                  }
                >
                  {evaluationUi ? 'Register organization' : 'Create Participant'}
                </Link>
                <Link className="underline" href="/govern/memberships?view=principals">
                  Users & access
                </Link>
                <Link
                  href="/govern/participants?view=rpc-access"
                  aria-current={searchParams.get('view') === 'rpc-access' ? 'page' : undefined}
                >
                  {evaluationUi ? 'RPC access' : 'Participant RPC assignments'}
                </Link>
                <Link
                  href="/govern/participants?view=platform-recovery"
                  aria-current={
                    searchParams.get('view') === 'platform-recovery' ? 'page' : undefined
                  }
                >
                  {evaluationUi ? 'Administration recovery' : 'Platform administration recovery'}
                </Link>
                <Link
                  href="/govern/participants?view=platform-ceiling"
                  aria-current={
                    searchParams.get('view') === 'platform-ceiling' ? 'page' : undefined
                  }
                >
                  {evaluationUi ? 'Authority handover' : 'Platform ceiling handoff'}
                </Link>
              </nav>
              {searchParams.get('view') === 'platform-recovery' ? (
                <PlatformRecoveryWorkflow />
              ) : searchParams.get('view') === 'platform-ceiling' ? (
                <>
                  <nav
                    aria-label="Platform handoff steps"
                    className="feature-navigation my-4 flex flex-wrap gap-4"
                  >
                    <Link
                      className="underline"
                      href="/govern/participants?view=platform-ceiling"
                      aria-current={handoffPhase === 'ceiling' ? 'page' : undefined}
                    >
                      Ceiling recovery
                    </Link>
                    <Link
                      className="underline"
                      href="/govern/participants?view=platform-ceiling&phase=envelopes"
                      aria-current={handoffPhase === 'envelopes' ? 'page' : undefined}
                    >
                      Administrator envelopes
                    </Link>
                    <Link
                      className="underline"
                      href="/govern/participants?view=platform-ceiling&phase=assignments"
                      aria-current={handoffPhase === 'assignments' ? 'page' : undefined}
                    >
                      Administrator assignments
                    </Link>
                  </nav>
                  {handoffPhase === 'envelopes' ? (
                    <RpcPlatformAccess handoffOnly />
                  ) : handoffPhase === 'assignments' ? (
                    <ParticipantGrantWorkflow platformHandoff />
                  ) : (
                    <PlatformCeilingWorkflow />
                  )}
                </>
              ) : searchParams.get('view') === 'first-administrator' ? (
                <ParticipantBootstrapWorkflow />
              ) : participantRpcJourney ? (
                <RpcPlatformAccess />
              ) : (
                <ParticipantEnvelopeWorkflow evaluationUi={evaluationUi} />
              )}
            </>
          ) : null}
          {roleJourney ? (
            <nav aria-label="Membership governance" className="membership-navigation">
              <Link
                href="/govern/memberships"
                aria-current={
                  !principalJourney &&
                  !grantJourney &&
                  !recoveryJourney &&
                  !credentialJourney &&
                  !workloadJourney &&
                  !groupJourney &&
                  !directoryJourney &&
                  !invitationJourney &&
                  !invitationAcceptanceJourney &&
                  !accessReviewJourney &&
                  !rpcAccessJourney
                    ? 'page'
                    : undefined
                }
              >
                Roles
              </Link>
              <Link
                href="/govern/memberships?view=principals"
                aria-current={principalJourney ? 'page' : undefined}
              >
                Users and principals
              </Link>
              <Link
                href="/govern/memberships?view=grants"
                aria-current={grantJourney ? 'page' : undefined}
              >
                Assignments and delegation
              </Link>
              <Link
                href="/govern/memberships?view=recovery"
                aria-current={recoveryJourney ? 'page' : undefined}
              >
                Account recovery
              </Link>
              <Link
                href="/govern/memberships?view=credentials"
                aria-current={credentialJourney ? 'page' : undefined}
              >
                Authenticators
              </Link>
              <Link
                href="/govern/memberships?view=workloads"
                aria-current={workloadJourney ? 'page' : undefined}
              >
                Workload certificates
              </Link>
              <Link
                href="/govern/memberships?view=groups"
                aria-current={groupJourney ? 'page' : undefined}
              >
                Groups
              </Link>
              <Link
                href="/govern/memberships?view=directory"
                aria-current={directoryJourney ? 'page' : undefined}
              >
                Directory
              </Link>
              <Link
                href="/govern/memberships?view=invitations"
                aria-current={invitationJourney ? 'page' : undefined}
              >
                Invitations
              </Link>
              <Link href="/govern/access" aria-current={accessReviewJourney ? 'page' : undefined}>
                Access review
              </Link>
              <Link
                href="/govern/memberships?view=rpc-access"
                aria-current={rpcAccessJourney ? 'page' : undefined}
              >
                RPC access
              </Link>
            </nav>
          ) : null}
          {roleJourney &&
          !principalJourney &&
          !grantJourney &&
          !recoveryJourney &&
          !credentialJourney &&
          !workloadJourney &&
          !directoryJourney &&
          !invitationJourney &&
          !invitationAcceptanceJourney &&
          !groupJourney &&
          !accessReviewJourney &&
          !rpcAccessJourney ? (
            <ParticipantRoleWorkflow />
          ) : null}
          {principalJourney ? <PrincipalWorkflow /> : null}
          {recoveryJourney ? <RecoveryWorkflow /> : null}
          {credentialJourney ? <CredentialWorkflow /> : null}
          {groupJourney ? <GroupWorkflow /> : null}
          {directoryJourney ? <DirectoryWorkflow /> : null}
          {invitationJourney ? <InvitationWorkflow /> : null}
          {invitationAcceptanceJourney ? <InvitationAcceptanceWorkflow /> : null}
          {workloadJourney ? <WorkloadWorkflow /> : null}
          {grantJourney ? (
            <ParticipantGrantWorkflow
              key={
                initialGrant.success
                  ? initialGrant.data.id
                  : initialPrincipal.success
                    ? initialPrincipal.data
                    : 'grants'
              }
              initialGrant={initialGrant.success ? initialGrant.data : undefined}
              initialPrincipalId={initialPrincipal.success ? initialPrincipal.data : undefined}
              initialAuthorityEnvelopeId={
                initialEnvelope.success ? initialEnvelope.data : undefined
              }
              initialRoleId={initialRole.success ? initialRole.data : undefined}
              initialCapabilityIds={initialCapabilities}
              initialResourceIds={initialResources}
            />
          ) : null}
          {accessReviewJourney ? <AccessReviewWorkflow /> : null}
          {rpcAccessJourney ? <RpcParticipantAccess /> : null}
          {policyReleaseJourney ? (
            <PolicyReleaseWorkflow
              showSessionControls={!evaluationUi}
              evaluationUi={evaluationUi}
              activeTask={
                searchParams.get('view') === 'activation-renewal'
                  ? 'activation-renewal'
                  : 'releases'
              }
            />
          ) : null}
          {providerSetupJourney ? (
            <>
              <nav className="feature-navigation" aria-label="Network setup views">
                <Link
                  href="/operate/multi-rpc"
                  aria-current={networkView === 'providers' ? 'page' : undefined}
                >
                  Providers
                </Link>
                <Link
                  href="/operate/multi-rpc?view=runtime"
                  aria-current={networkView === 'runtime' ? 'page' : undefined}
                >
                  Runtime targets
                </Link>
                <Link
                  href="/operate/multi-rpc?view=profiles"
                  aria-current={networkView === 'profiles' ? 'page' : undefined}
                >
                  Permission profiles
                </Link>
              </nav>
              {networkView === 'providers' ? (
                <SetupWorkflow
                  kind="providers"
                  showSessionControls={!evaluationUi}
                  evaluationUi={evaluationUi}
                />
              ) : networkView === 'profiles' ? (
                <TransactionWorkflow mode="profiles" showSessionControls={!evaluationUi} />
              ) : (
                <SetupWorkflow
                  kind="runtime"
                  showSessionControls={!evaluationUi}
                  evaluationUi={evaluationUi}
                />
              )}
            </>
          ) : null}
          {runtimeSetupJourney ? (
            <>
              <SetupWorkflow kind="runtime" />
              <SetupWorkflow kind="indexers" showSessionControls={false} />
              <SetupWorkflow kind="projections" showSessionControls={false} />
              <SetupWorkflow kind="projection-validation" showSessionControls={false} />
              <SetupWorkflow kind="runtime-activation" showSessionControls={false} />
              <TransactionWorkflow mode="runtime" showSessionControls={false} />
            </>
          ) : null}
          {moduleJourney ? (
            <TransactionWorkflow mode="modules" showSessionControls={!evaluationUi} />
          ) : null}
          {deploymentJourney ? (
            <>
              <TransactionWorkflow mode="deployment" />
              <TransactionWorkflow mode="wallets" />
            </>
          ) : null}
          {transactionJourney ? (
            <TransactionWorkflow
              mode="cigl"
              showSessionControls={!evaluationUi}
              collapseRecoveryControls={evaluationUi}
            />
          ) : null}
          {factJourney ? <FactWorkflow /> : null}
          {explorerJourney ? (
            <PrivacyExplorerWorkflow
              evaluationUi={evaluationUi}
              showSessionControls={!evaluationUi}
            />
          ) : null}
          {evidenceJourney ? (
            <EvidenceWorkflow showSessionControls={!evaluationUi} evaluationUi={evaluationUi} />
          ) : null}
          {workItemJourney ? <WorkItemWorkflow /> : null}
          {notificationJourney ? <NotificationWorkflow /> : null}
          {notificationEndpointJourney ? <NotificationEndpointWorkflow /> : null}
          {snapshotJourney && query.isLoading && (
            <Status
              state="LOADING"
              detail={
                evaluationUi
                  ? 'Getting the information available in your workspace…'
                  : 'Loading the current server-authorized process state.'
              }
              productUi={evaluationUi}
            />
          )}
          {snapshotJourney &&
            problem &&
            (evaluationUi ? (
              <WorkspaceStatus
                state={problem.truthState}
                title={problem.status === 404 ? 'Page not available' : undefined}
                detail={
                  problem.status === 404 || problem.truthState === 'DENIED'
                    ? 'This page is not available in your current workspace. Check your account and workspace access, or contact your administrator.'
                    : 'The workspace could not be loaded. Check the connection and try again.'
                }
                support={{ code: problem.code, traceId: problem.traceId }}
                onRetry={problem.retryable ? () => void query.refetch() : undefined}
                retrying={query.isFetching}
              >
                <Link className="workspace-entry-link" href="/home/session">
                  Account & workspace
                </Link>
              </WorkspaceStatus>
            ) : (
              <Status state="UNAVAILABLE" detail={`${problem.title} (${problem.code})`} />
            ))}
          {snapshotJourney && query.error && !problem && (
            <Status
              state="UNAVAILABLE"
              detail={
                evaluationUi
                  ? 'The workspace could not be loaded. Check the connection and try again.'
                  : 'The process could not be loaded safely.'
              }
              productUi={evaluationUi}
              onRetry={() => void query.refetch()}
              retrying={query.isFetching}
            />
          )}
          {snapshotJourney && snapshot && (
            <SnapshotView
              key={validationToken ?? route.id}
              policyView={policyView}
              evaluationUi={evaluationUi}
              onMutation={() => query.refetch()}
              session={sessionBootstrap}
              snapshot={snapshot}
            />
          )}
        </section>
        {!customJourney && (!evaluationUi || route.path === '/home/session') && (
          <LocalSessionSurface showAccountSettings={route.path === '/home/session'} />
        )}
      </main>
    </div>
  );
}

function Status({
  productUi = false,
  ...props
}: Readonly<WorkspaceStatusProps & { productUi?: boolean }>) {
  if (productUi) return <WorkspaceStatus {...props} />;
  const { state, detail } = props;
  return (
    <div className={`flex items-start gap-3 rounded border p-4 ${truthClass(state)}`}>
      <TruthIcon state={state} />
      <div>
        <strong>{state.replaceAll('_', ' ')}</strong>
        <p className="mt-1">{detail}</p>
      </div>
    </div>
  );
}

function SnapshotView({
  snapshot,
  session,
  onMutation,
  policyView = 'all',
  evaluationUi = false,
}: Readonly<{
  snapshot: Awaited<ReturnType<typeof readSnapshot>>;
  session?: UiSessionBootstrap;
  onMutation: () => Promise<unknown>;
  policyView?: 'all' | 'author' | 'simulation';
  evaluationUi?: boolean;
}>) {
  const visibilityAuthoring = snapshot.routeId === 'ROUTE-VISIBILITY-EVENT-DISCLOSURE';
  const policyAuthoring =
    snapshot.processDomainId === 'POLICY_AUTHOR_COMPOSE_SIMULATE' || visibilityAuthoring;
  return (
    <div className="space-y-6">
      {!policyAuthoring ? (
        <Status
          state={snapshot.truthState}
          productUi={evaluationUi}
          detail={`The server reported ${snapshot.completeness.toLowerCase()} data with ${snapshot.freshness.state.toLowerCase()} freshness.`}
        />
      ) : null}
      <WorkflowDetails
        enabled={evaluationUi && policyAuthoring}
        summary={`Policy context · ${snapshot.freshness.state.toLowerCase()} · ${snapshot.completeness.toLowerCase()}`}
        expanded={snapshot.freshness.state !== 'CURRENT' || snapshot.completeness !== 'COMPLETE'}
      >
        <section
          aria-labelledby="process-details"
          className="rounded border border-[color:var(--border)] bg-[color:var(--surface)] p-4"
        >
          <h2 className="text-xl font-semibold" id="process-details">
            {policyAuthoring ? 'Policy authoring context' : 'Authorized process details'}
          </h2>
          <dl className="mt-4 grid gap-4 md:grid-cols-2">
            <div>
              <dt className="font-medium">Scope</dt>
              <dd className="text-[color:var(--muted)]">{snapshot.scope.plane}</dd>
            </div>
            {policyAuthoring && snapshot.scope.participantId ? (
              <div>
                <dt className="font-medium">Participant</dt>
                <dd className="break-all text-[color:var(--muted)]">
                  {snapshot.scope.participantId.slice(
                    snapshot.scope.participantId.lastIndexOf(':') + 1,
                  )}
                </dd>
              </div>
            ) : null}
            {policyAuthoring && snapshot.scope.privacyDomainId ? (
              <div>
                <dt className="font-medium">Privacy domain</dt>
                <dd className="break-all text-[color:var(--muted)]">
                  {snapshot.scope.privacyDomainId.slice(
                    snapshot.scope.privacyDomainId.lastIndexOf(':') + 1,
                  )}
                </dd>
              </div>
            ) : null}
            <div>
              <dt className="font-medium">Freshness</dt>
              <dd className="text-[color:var(--muted)]">{snapshot.freshness.state}</dd>
            </div>
            <div>
              <dt className="font-medium">Completeness</dt>
              <dd className="text-[color:var(--muted)]">{snapshot.completeness}</dd>
            </div>
            <div>
              <dt className="font-medium">Observed at</dt>
              <dd className="text-[color:var(--muted)]">
                <time data-time-zone={session?.timeZone} dateTime={snapshot.observedAt}>
                  {new Intl.DateTimeFormat(session?.locale, {
                    dateStyle: 'medium',
                    timeStyle: 'medium',
                    localeMatcher: 'best fit',
                    timeZone: session?.timeZone,
                  }).format(new Date(snapshot.observedAt))}
                </time>
              </dd>
            </div>
          </dl>
          {!policyAuthoring && snapshot.items.length > 0 && (
            <div
              className="mt-6 overflow-x-auto"
              role="region"
              aria-label="Authorized process items"
              tabIndex={0}
            >
              <table className="min-w-full border-collapse">
                <thead>
                  <tr className="text-left">
                    <th className="border-b p-2">Resource</th>
                    <th className="border-b p-2">Truth</th>
                    <th className="border-b p-2">Observed</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshot.items.map((item) => (
                    <tr key={item.resourceRef}>
                      <th className="border-b p-2 text-left font-medium break-all">
                        {item.resourceRef}
                      </th>
                      <td className="border-b p-2">{item.truthState}</td>
                      <td className="border-b p-2">
                        <time dateTime={item.observedAt}>
                          {new Intl.DateTimeFormat(undefined, {
                            dateStyle: 'medium',
                            timeStyle: 'medium',
                          }).format(new Date(item.observedAt))}
                        </time>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </WorkflowDetails>
      {visibilityAuthoring ? (
        <VisibilityWorkflow
          actions={snapshot.authorizedActions}
          authorityContextKey={`${snapshot.contextDigest}:${snapshot.authorityGeneration}`}
          key={`${snapshot.contextDigest}:${snapshot.authorityGeneration}`}
          participantRef={snapshot.scope.participantId ?? ''}
        />
      ) : snapshot.processDomainId === 'POLICY_AUTHOR_COMPOSE_SIMULATE' ? (
        <PolicyComposer
          view={policyView}
          actions={snapshot.authorizedActions}
          authorityContextKey={`${snapshot.contextDigest}:${snapshot.authorityGeneration}`}
          key={`${snapshot.contextDigest}:${snapshot.authorityGeneration}`}
          participantRef={snapshot.scope.participantId ?? ''}
        />
      ) : (
        <ActionPanel
          actions={snapshot.authorizedActions}
          onCompleted={onMutation}
          session={session}
        />
      )}
      {!evaluationUi && (
        <aside
          className="rounded border border-[color:var(--border)] p-4"
          aria-label="Process help"
        >
          <CircleHelp aria-hidden className="mr-2 inline" size={18} />
          Actions appear only when the current server-authorized snapshot declares them.{' '}
          {routes.length} registered process routes are available.
        </aside>
      )}
    </div>
  );
}
