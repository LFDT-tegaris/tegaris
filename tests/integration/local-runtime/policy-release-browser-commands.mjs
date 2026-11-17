import assert from 'node:assert/strict';
import { expect } from '@playwright/test';

export async function command(page, buttonName, expectedCommand) {
  process.stdout.write(`OPENPC_POLICY_RELEASE_BROWSER_STAGE|${expectedCommand}\n`);
  const exchanges = [];
  const recordResponse = (candidate) => {
    const request = candidate.request();
    const path = new URL(candidate.url()).pathname;
    if (path.startsWith('/api/v1/ui/webauthn/') || path === '/api/v1/ui/policy-release-workbench') {
      exchanges.push({ method: request.method(), path, status: candidate.status() });
    }
  };
  const recordFailure = (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/api/v1/ui/webauthn/') || path === '/api/v1/ui/policy-release-workbench') {
      exchanges.push({
        method: request.method(),
        path,
        failure: request.failure()?.errorText ?? 'unknown',
      });
    }
  };
  page.on('response', recordResponse);
  page.on('requestfailed', recordFailure);
  let response;
  try {
    [response] = await Promise.all([
      page.waitForResponse((candidate) => {
        if (
          candidate.request().method() !== 'POST' ||
          new URL(candidate.url()).pathname !== '/api/v1/ui/policy-release-workbench'
        )
          return false;
        try {
          return candidate.request().postDataJSON()?.command === expectedCommand;
        } catch {
          return false;
        }
      }),
      page.getByRole('button', { name: buttonName, exact: true }).click({ noWaitAfter: true }),
    ]);
  } catch (error) {
    const diagnostics = await page.evaluate(() => ({
      status: Array.from(document.querySelectorAll('[role="status"]')).map((node) =>
        node.textContent?.trim(),
      ),
      body: document.body.innerText.slice(0, 4_000),
    }));
    throw new Error(
      `Policy command ${expectedCommand} did not reach its BFF: ${JSON.stringify({ exchanges, diagnostics })}`,
      { cause: error },
    );
  } finally {
    page.off('response', recordResponse);
    page.off('requestfailed', recordFailure);
  }
  assert.ok(response.ok(), JSON.stringify({ command: expectedCommand, status: response.status() }));
  return response.json();
}

export function policyReferenceForm(page) {
  return page.locator('form').filter({
    has: page.getByRole('button', { name: 'Load policy workflow', exact: true }),
  });
}

export async function loadReferences(page, references) {
  const form = policyReferenceForm(page);
  for (const [label, value] of [
    ['Approval ID', references.approvalId],
    ['Release ID', references.releaseId],
    ['Activation ID', references.occurrenceId],
  ]) {
    const field = form.getByLabel(label, { exact: true });
    await field.fill(value ?? '');
  }
  const button = form.getByRole('button', { name: 'Load policy workflow', exact: true });
  await button.click();
  // Activation also polls this URL. Its already-running response is not the
  // result of the user's explicit read. Observe this form's completed result;
  // a denied manual read never produces the success status.
  await expect(button).toBeEnabled();
  await expect(
    page.getByRole('status').filter({ hasText: /^Authoritative workflow state loaded\.$/u }),
  ).toBeVisible();
}
