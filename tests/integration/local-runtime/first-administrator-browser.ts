import { execFileSync } from 'node:child_process';
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { z } from 'zod';
import {
  firstAdministratorChange,
  firstAdministratorCreate,
} from '../../../apps/admin-web/lib/first-administrator-contract.js';
import { Pool } from 'pg';
import { chromium, expect, type BrowserContext, type Page } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { recoveryBrowserActors } from './recovery-browser-fixture.js';
const [secretRoot, evidenceRoot, identityContainer, project] = process.argv.slice(2);
if (!secretRoot || !evidenceRoot || !identityContainer || !project)
  throw new Error('First administrator browser arguments missing');
const resumePath = process.env.OPENPC_FIRST_ADMINISTRATOR_RESUME_CUSTODY;
const storageSchema = z.object({
  cookies: z.array(
    z.object({
      name: z.string(),
      value: z.string(),
      domain: z.string(),
      path: z.string(),
      expires: z.number(),
      httpOnly: z.boolean(),
      secure: z.boolean(),
      sameSite: z.enum(['Strict', 'Lax', 'None']),
    }),
  ),
  origins: z.array(
    z.object({
      origin: z.string(),
      localStorage: z.array(z.object({ name: z.string(), value: z.string() })),
    }),
  ),
});
const resumeSchema = z.object({
  actors: z
    .array(
      z.object({
        credentials: z.array(
          z
            .object({
              credentialId: z.string().min(1),
              isResidentCredential: z.boolean(),
              privateKey: z.string().min(1),
              signCount: z.number().int().nonnegative(),
              rpId: z.string().optional(),
              userHandle: z.string().optional(),
              largeBlob: z.string().optional(),
            })
            .passthrough(),
        ),
        storage: storageSchema,
        url: z.string(),
        sessionStorage: z.record(z.string(), z.string()),
      }),
    )
    .length(4),
  observations: z.array(
    z.object({
      input: z.object({ command: z.string() }).passthrough(),
      result: z.record(z.string(), z.unknown()),
    }),
  ),
});
let resumed: z.infer<typeof resumeSchema> | undefined;
let resumeClaimPending = false;
let resumeApprovedRotation = false;
let originalClaimSessionId: string | undefined;
let originalApprovedRotation:
  { reviewToken: string; candidateDigest: string; approvalRequestId: string } | undefined;
if (resumePath) {
  if (!resolve(resumePath).startsWith(resolve(evidenceRoot) + sep))
    throw new Error('Resume custody must belong to the retained evidence root');
  const info = await lstat(resumePath),
    parent = await lstat(dirname(resumePath));
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    (info.mode & 0o777) !== 0o600 ||
    info.uid !== process.getuid?.() ||
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    (parent.mode & 0o777) !== 0o700
  )
    throw new Error('Resume custody must be an owned private file');
  resumed = resumeSchema.parse(JSON.parse(await readFile(resumePath, 'utf8')));
  if (
    resumed.actors[0]?.credentials.length !== 1 ||
    resumed.actors[1]?.credentials.length !== 1 ||
    resumed.actors[2]?.credentials.length !== 0 ||
    resumed.actors[3]?.credentials.length !== 0 ||
    ![11, 19].includes(resumed.observations.length)
  )
    throw new Error(
      'This resume accepts only the original pre-recipient or approved-rotation checkpoint',
    );
  resumeApprovedRotation = resumed.observations.length === 19;
  if (resumeApprovedRotation)
    expect(resumed.observations.slice(11).map((entry) => entry.input.command)).toEqual([
      'SESSION',
      'SESSION',
      'READ_CUSTODY',
      'PREPARE_CHANGE',
      'SUBMIT',
      'REVIEW',
      'APPROVE',
      'READ_ORIGINAL',
    ]);
}
const artifacts = process.env.OPENPC_BROWSER_ARTIFACT_ROOT ?? evidenceRoot;
await mkdir(artifacts, { recursive: true });
const privateRoot = join(artifacts, 'private-first-administrator');
await mkdir(privateRoot, { mode: 0o700 });
const custodyPath = join(privateRoot, 'browser-custody.json');
await writeFile(custodyPath, JSON.stringify({ actors: [], observations: [] }), {
  mode: 0o600,
  flag: 'wx',
});
const browser = await chromium.launch({ headless: true }),
  contexts: BrowserContext[] = [];
const actors: {
  context: BrowserContext;
  page: Page;
  cdp: Awaited<ReturnType<BrowserContext['newCDPSession']>>;
  authenticatorId: string;
}[] = [];
const observations: { input: unknown; result: unknown }[] = [...(resumed?.observations ?? [])];
async function preserveBrowserCustody() {
  const saved = [];
  for (const actor of actors) {
    const credentials = await actor.cdp.send('WebAuthn.getCredentials', {
      authenticatorId: actor.authenticatorId,
    });
    saved.push({
      credentials: credentials.credentials,
      storage: await actor.context.storageState(),
      url: actor.page.url(),
      sessionStorage:
        actor.page.url() === 'about:blank'
          ? {}
          : await actor.page.evaluate(() =>
              Object.fromEntries(
                Object.entries(sessionStorage).filter(([key]) => key.startsWith('openpc:')),
              ),
            ),
    });
  }
  await writeFile(custodyPath, JSON.stringify({ actors: saved, observations }), { mode: 0o600 });
}
const database = new Pool({
  host: '127.0.0.1',
  port: 55432,
  user: 'openpc_control',
  database: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
const endpoint = '/api/v1/ui/participant-bootstrap',
  url = 'http://localhost:8080/govern/participants?view=first-administrator';
async function actor(saved?: z.infer<typeof resumeSchema>['actors'][number]) {
  const context = await browser.newContext(saved ? { storageState: saved.storage } : {});
  contexts.push(context);
  const page = await context.newPage(),
    cdp = await context.newCDPSession(page);
  page.on('response', (response) => {
    if (response.status() >= 400 && new URL(response.url()).origin === 'http://localhost:8080')
      process.stdout.write(
        `OPENPC_FIRST_ADMIN_HTTP|status=${response.status()}|path=${new URL(response.url()).pathname}\n`,
      );
  });
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  });
  if (saved) {
    for (const credential of saved.credentials)
      await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
    await page.goto('http://localhost:8080/home/session');
    await page.evaluate((values) => {
      for (const [key, value] of Object.entries(values)) sessionStorage.setItem(key, value);
    }, saved.sessionStorage);
    const previous = new URL(saved.url);
    const returnTo =
      previous.origin === 'http://localhost:8080' &&
      ['/govern/participants', '/govern/memberships'].includes(previous.pathname)
        ? `http://localhost:8080${previous.pathname}?${new URLSearchParams({ view: previous.searchParams.get('view') ?? '' })}`
        : 'http://localhost:8080/home/session';
    await page.goto(returnTo);
  }
  const actor = { context, page, cdp, authenticatorId };
  actors.push(actor);
  await preserveBrowserCustody();
  return actor;
}
async function command(page: Page, input: unknown) {
  const result = await page.evaluate(
    async ({ endpoint, input }) => {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      return { status: response.status, body: await response.json() };
    },
    { endpoint, input },
  );
  observations.push({ input, result });
  await preserveBrowserCustody();
  return result;
}
async function clickCommand(page: Page, name: string, commandName: string) {
  const waiting = page.waitForResponse(
    (response) =>
      response.url().endsWith(endpoint) &&
      response.request().postDataJSON()?.command === commandName,
    { timeout: 30000 },
  );
  await page.getByRole('button', { name, exact: true }).click();
  const response = await waiting,
    value = await response.json();
  observations.push({ input: response.request().postDataJSON(), result: value });
  await preserveBrowserCustody();
  expect(response.ok(), JSON.stringify(value)).toBe(true);
  return value;
}
async function issueApproved(
  page: Page,
  custodyChange = false,
  expected?: { reviewToken: string; candidateDigest: string; approvalRequestId: string },
) {
  if (expected) {
    const saved = await page.evaluate(() =>
      JSON.parse(sessionStorage.getItem('openpc:first-admin-review') ?? 'null'),
    );
    expect(saved?.review?.reviewToken).toBe(expected.reviewToken);
    expect(saved?.review?.candidateDigest).toBe(expected.candidateDigest);
    expect(saved?.approvalId).toBe(expected.approvalRequestId);
  }
  const original = await clickCommand(
    page,
    custodyChange ? 'Check original custody-change status' : 'Check original invitation status',
    'READ_ORIGINAL',
  );
  expect(original.state).toBe('NOT_CONSUMED');
  expect(original.proposalState).toBe('APPROVED');
  if (expected) {
    expect(original.candidateDigest).toBe(expected.candidateDigest);
    expect((observations.at(-1)?.input as { reviewToken?: string }).reviewToken).toBe(
      expected.reviewToken,
    );
    await page.route(`**${endpoint}`, async (route) => {
      const input = route.request().postDataJSON();
      if (
        input?.command === 'COMMIT' &&
        (input.reviewToken !== expected.reviewToken ||
          input.approvalRequestId !== expected.approvalRequestId)
      ) {
        await route.abort('blockedbyclient');
        return;
      }
      await route.continue();
    });
  }
  try {
    return await clickCommand(
      page,
      custodyChange ? 'Verify and apply custody change' : 'Verify and issue invitation',
      'COMMIT',
    );
  } finally {
    if (expected) await page.unroute(`**${endpoint}`);
  }
}
async function platform(name: string) {
  const result = await actor(),
    page = result.page;
  await page.goto(url);
  await page.getByRole('combobox', { name: 'Account role', exact: true }).selectOption('viewer');
  await page.getByLabel('OIDC account hint (optional)', { exact: true }).fill(name);
  await page
    .getByLabel('Require fresh authentication after account recovery', { exact: true })
    .check();
  await page.getByRole('button', { name: 'Sign in with local OIDC', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Set up your authenticator' })).toBeVisible();
  await page.getByRole('button', { name: 'Register authenticator', exact: true }).click();
  await expect(page.getByLabel('Saved registration', { exact: true })).toContainText('COMPLETED');
  await clickCommand(page, 'Verify Platform authenticator', 'SESSION');
  await expect(
    page.getByRole('status').filter({ hasText: 'Platform authenticator verified.' }),
  ).toBeVisible();
  return result;
}
async function approveCandidate(
  page: Page,
  candidate: { candidate: { participantId: string }; candidateDigest: string },
  approvalRequestId: string,
) {
  await page
    .getByLabel('Proposed Participant ID', { exact: true })
    .fill(candidate.candidate.participantId);
  await page
    .getByLabel('First-administrator candidate digest', { exact: true })
    .fill(candidate.candidateDigest);
  await page
    .getByLabel('First-administrator approval request ID', { exact: true })
    .fill(approvalRequestId);
  await clickCommand(page, 'Load first-administrator approval', 'REVIEW');
  await clickCommand(page, 'Approve first administration with authenticator', 'APPROVE');
  await expect(
    page.getByRole('status').filter({ hasText: 'Independent approval recorded.' }),
  ).toBeVisible();
}
// Initial Platform trust and external authenticators only. Every proposal,
// approval, invitation, identity proof and durable grant uses its public owner.
try {
  const maker = resumed ? await actor(resumed.actors[0]) : await platform('recovery-maker'),
    checker = resumed ? await actor(resumed.actors[1]) : await platform('recovery-checker');
  const page = maker.page;
  const prepareNewParticipant = async () => {
    for (const [label, value] of [
      ['New Participant name', 'First administrator browser Participant'],
      ['First administrator name', 'Invited first administrator'],
      ['Administrator identity provider issuer', 'http://oidc-emulator:3006'],
      ['Exact administrator account subject', recoveryBrowserActors['recovery-subject']],
      ['Administrator identity provider audience', 'openpc-local-workbench'],
      ['Independent Platform checker ID', recoveryBrowserActors['recovery-checker']],
      [
        'Reason for creating this Participant',
        'Create this Participant through real independently approved first administration.',
      ],
    ])
      await page.getByLabel(label!, { exact: true }).fill(value!);
    return clickCommand(page, 'Prepare first-administrator review', 'PREPARE');
  };
  let prepared: {
    candidate: z.infer<typeof firstAdministratorCreate>;
    candidateDigest: string;
    reviewToken: string;
  };
  let participantId: string;
  let first: z.infer<typeof firstAdministratorCreate>['firstAdministrator'];
  let link: string;
  if (resumed) {
    const original = resumed.observations.find((value) => value.input.command === 'PREPARE');
    prepared = z
      .object({
        candidate: firstAdministratorCreate,
        candidateDigest: z.string(),
        reviewToken: z.string(),
      })
      .parse(original?.result);
    participantId = prepared.candidate.participantId;
    first = prepared.candidate.firstAdministrator;
    const issued = z
      .object({
        operationId: z.uuid(),
        participantId: z.uuid(),
        state: z.literal('PROVISIONING'),
        invitationLink: z.url(),
      })
      .parse(
        resumed.observations.find(
          (value) => value.input.command === 'COMMIT' && value.result.state === 'PROVISIONING',
        )?.result,
      );
    expect(issued.participantId).toBe(participantId);
    link = issued.invitationLink;
    const client = await database.connect();
    try {
      await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
      expect(
        (await client.query('SHOW transaction_read_only')).rows[0]?.transaction_read_only,
      ).toBe('on');
      expect(
        (
          await client.query(
            'select state,authority_epoch::text from control.participant where participant_id=$1',
            [participantId],
          )
        ).rows,
      ).toEqual([{ state: 'PROVISIONING', authority_epoch: '0' }]);
      expect(
        (
          await client.query(
            'select count(*)::int count from control.assignment where participant_id=$1',
            [participantId],
          )
        ).rows[0]?.count,
      ).toBe(0);
      const custody = (
        await client.query(
          `select custody.state,participant.row_version::text revision,invitation.token_version::text,custody.candidate_membership_id,custody.candidate_session_id,
             principal.state principal_state,principal.authority_epoch::text principal_epoch,
             session.state session_state,session.idle_expires_at>clock_timestamp() and session.absolute_expires_at>clock_timestamp() session_live
           from control.participant_bootstrap_custody custody
           join control.participant participant on participant.participant_id=custody.participant_id
           join control.participant_invitation invitation on invitation.participant_id=custody.participant_id and invitation.invitation_id=custody.invitation_id
           left join control.principal principal on principal.participant_id=custody.participant_id and principal.principal_id=custody.candidate_membership_id
           left join control.session session on session.participant_id=custody.participant_id and session.principal_id=custody.candidate_membership_id and session.session_id=custody.candidate_session_id
           where custody.participant_id=$1 and custody.mandate_id=$2 and custody.invitation_id=$3`,
          [participantId, first.mandateId, first.invitationId],
        )
      ).rows;
      expect(custody).toHaveLength(1);
      expect(custody[0].token_version).toBe('1');
      expect(['ACTIVE', 'CLAIM_PENDING']).toContain(custody[0].state);
      resumeClaimPending = custody[0].state === 'CLAIM_PENDING';
      if (resumeClaimPending) {
        originalClaimSessionId = z.uuid().parse(custody[0].candidate_session_id);
        expect(custody[0].principal_state).toBe('PROVISIONED');
        expect(custody[0].principal_epoch).toBe('0');
        expect(custody[0].session_state).toBe('ACTIVE');
        if (!resumeApprovedRotation) expect(custody[0].session_live).toBe(true);
        expect(
          (
            await client.query(
              'select membership_id from control.participant_membership where participant_id=$1',
              [participantId],
            )
          ).rows,
        ).toEqual([{ membership_id: custody[0].candidate_membership_id }]);
      } else expect(custody[0].candidate_membership_id).toBeNull();
      expect(
        (
          await client.query(
            'select count(*)::int count from control.participant_membership where participant_id=$1',
            [participantId],
          )
        ).rows[0]?.count,
      ).toBe(resumeClaimPending ? 1 : 0);
      expect(
        (
          await client.query(
            'select count(*)::int count from control.mutation_candidate where resource_id=$1 and consumed_operation_id=$2',
            [participantId, issued.operationId],
          )
        ).rows[0]?.count,
      ).toBe(1);
      if (resumeApprovedRotation) {
        expect(resumeClaimPending).toBe(true);
        const change = z
          .object({
            candidate: firstAdministratorChange,
            candidateDigest: z.string(),
            reviewToken: z.string().min(1),
          })
          .parse(resumed.observations[14]?.result);
        const approval = z
          .object({ approvalRequestId: z.uuid() })
          .parse(resumed.observations[15]?.result);
        expect(change.candidate.change.mutation).toBe('ROTATE');
        expect(change.candidate.participantId).toBe(participantId);
        expect(change.candidate.mandateId).toBe(first.mandateId);
        expect(change.candidate.invitationId).toBe(first.invitationId);
        expect(change.candidate.tokenVersion).toBe('1');
        expect(change.candidate.expectedRevision).toBe(custody[0].revision);
        originalApprovedRotation = {
          reviewToken: change.reviewToken,
          candidateDigest: change.candidateDigest,
          approvalRequestId: approval.approvalRequestId,
        };
        const pending = await client.query(
          `select candidate.state,candidate.consumed_operation_id,
            candidate.expires_at>clock_timestamp() and approval.expires_at>clock_timestamp() live,
            approval.state approval_state
           from control.mutation_candidate candidate join control.approval_request approval
            on approval.participant_id=candidate.participant_id and approval.privacy_domain_id=candidate.privacy_domain_id
             and approval.subject_id=candidate.mutation_candidate_id and approval.subject_digest=candidate.candidate_digest
             and approval.subject_version=candidate.expected_revision and approval.maker_principal_id=candidate.maker_principal_id
           where candidate.resource_id=$1 and candidate.candidate_digest=decode($2,'hex')
            and candidate.catalog_operation_id='ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE'
            and approval.approval_request_id=$3`,
          [participantId, change.candidateDigest.slice(7), approval.approvalRequestId],
        );
        expect(pending.rows).toEqual([
          {
            state: 'APPROVED',
            consumed_operation_id: null,
            live: true,
            approval_state: 'APPROVED',
          },
        ]);
        process.stdout.write(
          'OPENPC_FIRST_ADMIN_RESUME|original-rotation-approved-unconsumed-live|no-new-proposal\n',
        );
      }
      for (const original of resumed.observations.filter(
        (entry) => entry.input.command === 'SESSION',
      )) {
        const actor = z
          .object({ participantId: z.uuid(), principalId: z.uuid(), sessionId: z.uuid() })
          .parse(original.result.actor);
        const authority = (
          await client.query(
            `select state,context_mode,idle_expires_at>clock_timestamp() and absolute_expires_at>clock_timestamp() live,
             step_up_verified_at>=clock_timestamp()-interval '5 minutes' fresh_step_up
           from control.session where participant_id=$1 and principal_id=$2 and session_id=$3`,
            [actor.participantId, actor.principalId, actor.sessionId],
          )
        ).rows;
        expect(authority).toHaveLength(1);
        expect(authority[0].state).toBe('ACTIVE');
        expect(authority[0].context_mode).toBe('PLATFORM');
        expect(authority[0].live).toBe(true);
        process.stdout.write(
          `OPENPC_FIRST_ADMIN_AUTHORITY|original-session-live|fresh_step_up=${authority[0].fresh_step_up === true}\n`,
        );
      }
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
    for (const [current, principal] of [
      [maker, recoveryBrowserActors['recovery-maker']],
      [checker, recoveryBrowserActors['recovery-checker']],
    ] as const) {
      const session = await current.page.evaluate(async () =>
        (await fetch('/api/v1/ui/local-session', { cache: 'no-store' })).json(),
      );
      expect(session.authenticated).toBe(true);
      expect(session.principalId).toBe(principal);
      expect(session.contextMode).toBe('PLATFORM');
    }
    process.stdout.write(
      'OPENPC_FIRST_ADMIN_RESUME|original-native-effect-and-identities|no-creation-replay\n',
    );
  } else {
    prepared = await prepareNewParticipant();
    participantId = prepared.candidate.participantId;
    first = prepared.candidate.firstAdministrator;
    expect(
      (await command(checker.page, { command: 'SUBMIT', reviewToken: prepared.reviewToken }))
        .status,
    ).toBeGreaterThanOrEqual(400);
    const submitted = await clickCommand(page, 'Request first-administrator approval', 'SUBMIT'),
      approvalRequestId = submitted.approvalRequestId;
    expect(
      (
        await command(page, {
          command: 'COMMIT',
          reviewToken: prepared.reviewToken,
          approvalRequestId,
        })
      ).status,
    ).toBeGreaterThanOrEqual(400);
    await page.reload();
    await expect(page.getByLabel('Prepared first administration', { exact: true })).toContainText(
      participantId,
    );
    await checker.page.getByLabel('Proposed Participant ID', { exact: true }).fill(participantId);
    await checker.page
      .getByLabel('First-administrator candidate digest', { exact: true })
      .fill(prepared.candidateDigest);
    await checker.page
      .getByLabel('First-administrator approval request ID', { exact: true })
      .fill(approvalRequestId);
    const reviewed = await clickCommand(
      checker.page,
      'Load first-administrator approval',
      'REVIEW',
    );
    expect(reviewed.proposal.candidateDigest).toBe(prepared.candidateDigest);
    await clickCommand(checker.page, 'Approve first administration with authenticator', 'APPROVE');
    await expect(
      checker.page.getByRole('status').filter({ hasText: 'Independent approval recorded.' }),
    ).toBeVisible();
    const issued = await issueApproved(page);
    expect(issued.state).toBe('PROVISIONING');
    link = await page
      .getByLabel('First-administrator invitation link', { exact: true })
      .inputValue();
    const replay = await command(page, {
      command: 'COMMIT',
      reviewToken: prepared.reviewToken,
      approvalRequestId,
    });
    expect(replay.body.operationId).toBe(issued.operationId);
    const target = await database.query(
      'select state,authority_epoch::text from control.participant where participant_id=$1',
      [participantId],
    );
    expect(target.rows[0]).toEqual({ state: 'PROVISIONING', authority_epoch: '0' });
  }
  const wrong = await actor(resumed?.actors[2]);
  const recipient = await actor(resumed?.actors[3]);
  if (!resumeClaimPending) {
    await wrong.page.goto(link);
    await wrong.page
      .getByLabel('Identity account hint (optional)', { exact: true })
      .fill('recovery-executor');
    await wrong.page
      .getByRole('button', { name: 'Verify identity and accept', exact: true })
      .click();
    await expect(
      wrong.page
        .locator('section[aria-labelledby="invitation-acceptance-heading"]')
        .getByRole('alert'),
    ).toContainText('We could not verify this invitation. Reopen the latest invitation link');
    expect(new URL(wrong.page.url()).pathname).toBe('/govern/memberships');
    expect(
      (
        await database.query(
          'select state from control.participant_bootstrap_custody where mandate_id=$1',
          [first.mandateId],
        )
      ).rows,
    ).toEqual([{ state: 'ACTIVE' }]);
    expect(
      (
        await database.query(
          'select count(*)::int count from control.participant_membership where participant_id=$1',
          [participantId],
        )
      ).rows[0].count,
    ).toBe(0);
  }
  if (!resumeClaimPending) {
    await recipient.page.goto(link);
    await expect.poll(() => new URL(recipient.page.url()).hash === '').toBe(true);
    await recipient.page
      .getByLabel('Identity account hint (optional)', { exact: true })
      .fill('recovery-subject');
    await recipient.page
      .getByRole('button', { name: 'Verify identity and accept', exact: true })
      .click();
  } else
    process.stdout.write(
      'OPENPC_FIRST_ADMIN_RESUME|original-claim-pending-receipt|no-recipient-proof-replay\n',
    );
  if (!resumeApprovedRotation) {
    await expect(
      recipient.page.getByRole('button', {
        name: 'Register administrator authenticator',
        exact: true,
      }),
    ).toBeVisible();
    const originalReceipt = await recipient.page.evaluate(async () =>
      (await fetch('/api/v1/ui/invitation-proof', { cache: 'no-store' })).json(),
    );
    expect(originalReceipt.firstAdministrator).toBe(true);
    expect(originalReceipt.acceptance).toMatchObject({
      participantId,
      invitationId: first.invitationId,
      privacyDomainId: first.privacyDomainId,
      tokenVersion: '1',
      roleIntent: { authorityGranted: false },
    });
  }
  expect(
    (
      await database.query(
        'select count(*)::int count from control.assignment where participant_id=$1',
        [participantId],
      )
    ).rows[0].count,
  ).toBe(0);
  for (const current of [maker, checker]) {
    const [verified] = await Promise.all([
      current.page.waitForResponse(
        (response) =>
          response.url().endsWith('/api/v1/ui/webauthn/assertion/verify') &&
          response.request().method() === 'POST',
      ),
      clickCommand(current.page, 'Verify Platform authenticator', 'SESSION'),
    ]);
    expect(verified.ok()).toBe(true);
    await expect(
      current.page.getByRole('status').filter({ hasText: 'Platform authenticator verified.' }),
    ).toBeVisible();
    await preserveBrowserCustody();
  }
  await page
    .getByLabel('Participant with outstanding first administration', { exact: true })
    .fill(participantId);
  const beforeRotation = await clickCommand(
    page,
    'Read first-administrator custody',
    'READ_CUSTODY',
  );
  if (!resumeApprovedRotation) {
    await page
      .getByRole('combobox', { name: /^First-administrator custody change/u })
      .selectOption('ROTATE');
    await page
      .getByLabel('Reason for changing first-administrator custody', { exact: true })
      .fill('Recover this exact invitation with a new link before its original deadline.');
    const change = await clickCommand(page, 'Prepare custody change', 'PREPARE_CHANGE');
    const changeApproval = await clickCommand(
      page,
      'Request first-administrator approval',
      'SUBMIT',
    );
    await approveCandidate(checker.page, change, changeApproval.approvalRequestId);
  }
  const rotated = await issueApproved(page, true, originalApprovedRotation);
  expect(rotated.state).toBe('ACTIVE');
  if (originalApprovedRotation) {
    const consumed = await database.query(
      `select consumed_operation_id from control.mutation_candidate
       where resource_id=$1 and candidate_digest=decode($2,'hex')
        and catalog_operation_id='ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE'`,
      [participantId, originalApprovedRotation.candidateDigest.slice(7)],
    );
    expect(consumed.rows).toEqual([{ consumed_operation_id: rotated.operationId }]);
    const revoked = await database.query(
      'select state,revoked_reason from control.session where participant_id=$1 and session_id=$2',
      [participantId, originalClaimSessionId],
    );
    expect(revoked.rows).toEqual([
      { state: 'REVOKED', revoked_reason: 'first-administrator-custody-rotated' },
    ]);
  }
  const afterRotation = await clickCommand(
    page,
    'Read first-administrator custody',
    'READ_CUSTODY',
  );
  expect(afterRotation.expiresAt).toBe(beforeRotation.expiresAt);
  expect(afterRotation.tokenVersion).toBe('2');
  if (resumeApprovedRotation) await recipient.page.reload();
  else
    await recipient.page
      .getByRole('button', { name: 'Refresh administrator acceptance', exact: true })
      .click();
  await expect(
    recipient.page
      .locator('section[aria-labelledby="invitation-acceptance-heading"]')
      .getByRole('alert'),
  ).toBeVisible();
  await recipient.page.goto(rotated.invitationLink);
  await recipient.page
    .getByLabel('Identity account hint (optional)', { exact: true })
    .fill('recovery-subject');
  await recipient.page
    .getByRole('button', { name: 'Verify identity and accept', exact: true })
    .click();
  await expect(
    recipient.page.getByRole('button', {
      name: 'Register administrator authenticator',
      exact: true,
    }),
  ).toBeVisible();
  await recipient.page
    .getByRole('button', { name: 'Register administrator authenticator', exact: true })
    .click();
  await expect(
    recipient.page.getByRole('button', { name: 'Accept Participant administration', exact: true }),
  ).toBeVisible();
  await recipient.page
    .getByRole('button', { name: 'Accept Participant administration', exact: true })
    .click();
  await expect(
    recipient.page.getByRole('heading', {
      name: 'Participant administration accepted',
      exact: true,
    }),
  ).toBeVisible();
  expect(
    (
      await database.query(
        'select state,authority_epoch::text from control.participant where participant_id=$1',
        [participantId],
      )
    ).rows[0],
  ).toEqual({ state: 'ACTIVE', authority_epoch: '1' });
  expect(
    (
      await database.query(
        'select count(*)::int count from control.assignment where participant_id=$1',
        [participantId],
      )
    ).rows[0].count,
  ).toBe(1);
  expect(
    (
      await database.query(
        'select state,closed_at is not null closed from control.participant_bootstrap_custody where mandate_id=$1',
        [first.mandateId],
      )
    ).rows[0],
  ).toEqual({ state: 'ACCEPTED', closed: true });
  const owned = execFileSync(
    'docker',
    [
      'inspect',
      '--format',
      '{{index .Config.Labels "com.docker.compose.project"}}',
      identityContainer,
    ],
    { encoding: 'utf8' },
  ).trim();
  if (owned !== project) throw new Error('Identity container belongs to a different owner');
  execFileSync('docker', ['restart', identityContainer], { stdio: 'ignore', timeout: 60000 });
  await expect
    .poll(
      () =>
        execFileSync(
          'docker',
          ['inspect', '--format', '{{.State.Health.Status}}', identityContainer],
          { encoding: 'utf8' },
        ).trim(),
      { timeout: 30000 },
    )
    .toBe('healthy');
  await recipient.page.reload();
  await expect(
    recipient.page.getByRole('heading', {
      name: 'Participant administration accepted',
      exact: true,
    }),
  ).toBeVisible();
  await recipient.page
    .getByRole('combobox', { name: 'Account role', exact: true })
    .selectOption('viewer');
  await recipient.page
    .getByLabel('OIDC account hint (optional)', { exact: true })
    .fill('recovery-subject');
  await recipient.page
    .getByRole('button', { name: 'Sign in with local OIDC', exact: true })
    .click();
  await expect(
    recipient.page.getByRole('heading', { name: 'Set up your authenticator' }),
  ).toBeVisible();
  await recipient.page
    .getByRole('combobox', { name: 'Organization workspace', exact: true })
    .selectOption(first.privacyDomainId);
  await recipient.page
    .getByRole('button', {
      name: 'Verify and enter workspace',
      exact: true,
    })
    .click();
  await expect
    .poll(async () =>
      recipient.page.evaluate(
        async () => (await (await fetch('/api/v1/ui/local-session')).json()).contextMode,
      ),
    )
    .toBe('PARTICIPANT');
  const selected = await recipient.page.evaluate(
    async () => await (await fetch('/api/v1/ui/local-session')).json(),
  );
  expect(selected.participantId).toBe(participantId);
  const refresh = recipient.page.getByRole('button', {
    name: 'Refresh administrator acceptance',
    exact: true,
  });
  await refresh.focus();
  await expect(refresh).toBeFocused();
  await recipient.page.keyboard.press('Enter');
  const terminalCandidate = await prepareNewParticipant();
  const terminalApproval = await clickCommand(
    page,
    'Request first-administrator approval',
    'SUBMIT',
  );
  await approveCandidate(checker.page, terminalCandidate, terminalApproval.approvalRequestId);
  const terminalInvitation = await issueApproved(page);
  await page
    .getByLabel('Participant with outstanding first administration', { exact: true })
    .fill(terminalCandidate.candidate.participantId);
  await clickCommand(page, 'Read first-administrator custody', 'READ_CUSTODY');
  await page
    .getByRole('combobox', { name: /^First-administrator custody change/u })
    .selectOption('REVOKE');
  await page
    .getByLabel('Reason for changing first-administrator custody', { exact: true })
    .fill('Permanently revoke this pending first administration without activating any access.');
  const revocation = await clickCommand(page, 'Prepare custody change', 'PREPARE_CHANGE');
  const revokeApproval = await clickCommand(page, 'Request first-administrator approval', 'SUBMIT');
  await approveCandidate(checker.page, revocation, revokeApproval.approvalRequestId);
  const revoked = await issueApproved(page, true);
  expect(revoked.state).toBe('CANCELLED');
  await page.reload();
  await page
    .getByLabel('Participant with outstanding first administration', { exact: true })
    .fill(terminalCandidate.candidate.participantId);
  const terminal = await clickCommand(page, 'Read first-administrator custody', 'READ_CUSTODY');
  expect(terminal.state).toBe('CANCELLED');
  await expect(
    page.getByRole('button', { name: 'Prepare custody change', exact: true }),
  ).toBeDisabled();
  await wrong.page.goto(terminalInvitation.invitationLink);
  await wrong.page
    .getByLabel('Identity account hint (optional)', { exact: true })
    .fill('recovery-subject');
  await wrong.page.getByRole('button', { name: 'Verify identity and accept', exact: true }).click();
  await expect(
    wrong.page
      .locator('section[aria-labelledby="invitation-acceptance-heading"]')
      .getByRole('alert'),
  ).toBeVisible();
  expect(
    (
      await database.query(
        `select state,authority_epoch::text,(select count(*)::int from control.assignment where participant_id=$1) grants from control.participant where participant_id=$1`,
        [terminalCandidate.candidate.participantId],
      )
    ).rows,
  ).toEqual([{ state: 'PROVISIONING', authority_epoch: '0', grants: 0 }]);
  for (const [name, current, selector] of [
    ['first-admin-creation', page, '[aria-label="First Participant administrator"]'],
    ['first-admin-accepted', recipient.page, '[aria-label="First-administrator acceptance"]'],
  ] as const) {
    expect(
      (await new AxeBuilder({ page: current }).include(selector).analyze()).violations,
    ).toEqual([]);
    await current.locator(selector).screenshot({ path: join(artifacts, `${name}-desktop.png`) });
    await current.setViewportSize({ width: 360, height: 800 });
    expect(await current.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await current.locator(selector).screenshot({ path: join(artifacts, `${name}-mobile.png`) });
  }
  // A second tab shares cookies, but not sessionStorage. Revocation must hide
  // this tab's already-rendered private review without requiring a reload.
  await expect(page.getByLabel('Prepared first administration', { exact: true })).toBeVisible();
  const secondTab = await maker.context.newPage();
  await secondTab.goto(url);
  await secondTab.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByLabel('Prepared first administration', { exact: true })).toHaveCount(0);
  await expect(secondTab.getByRole('button', { name: 'Sign out', exact: true })).toHaveCount(0);
  await page.reload();
  await expect(page.getByLabel('Prepared first administration', { exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => sessionStorage.getItem('openpc:first-admin-review'))).toBeNull();
  await secondTab.close();
  process.stdout.write(
    'OPENPC_FIRST_ADMINISTRATOR_BROWSER|PASS|public_creation=governed|rotation=original_deadline|revocation=terminal|recipient=exact_oidc|acceptance=webauthn|grant=one|restart=durable|cross_tab=private_state_cleared|custody=retained|axe=clean|reflow=360\n',
  );
} catch (error) {
  for (let index = 0; index < contexts.length; index++) {
    const page = contexts[index]?.pages()[0];
    if (page)
      await page
        .screenshot({ path: join(artifacts, `first-admin-failure-${index}.png`), fullPage: true })
        .catch(() => undefined);
  }
  throw error;
} finally {
  try {
    await preserveBrowserCustody();
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
    await browser.close();
    await database.end();
  }
}
