import assert from 'node:assert/strict';
import { selectPolicyVersion } from './evaluation-ui-browser.mjs';

export async function fillSourceSimulation(page, request) {
  await page.getByLabel('Policy family', { exact: true }).selectOption('SOURCE');
  for (const [label, field] of [
    ['Indexer profile ID', 'indexerProfileId'],
    ['Projection plan ID', 'projectionPlanId'],
    ['First block', 'rangeStart'],
    ['Last block', 'rangeEnd'],
    ['Maximum response bytes', 'maximumResponseBytes'],
  ])
    await page.getByLabel(label, { exact: true }).fill(String(request[field]));
  await page.getByLabel('Source data class', { exact: true }).selectOption(request.dataClass);
}

export async function simulateSourcePolicy(page, request, versionId) {
  await selectPolicyVersion(page, versionId);
  await fillSourceSimulation(page, request);
  const results = [];
  for (const [dataClass, truth] of [
    [request.dataClass, 'SUCCESS'],
    ['FULL_BLOCK_TRANSACTIONS', 'DENIED'],
  ]) {
    await page.getByLabel('Source data class', { exact: true }).selectOption(dataClass);
    const responsePromise = page.waitForResponse(
      (response) =>
        response.request().method() === 'POST' &&
        new URL(response.url()).pathname ===
          '/api/v1/ui/process-domains/policy-author-compose-simulate/actions/simulate',
    );
    await page.getByRole('button', { name: 'Run simulation', exact: true }).click();
    const response = await responsePromise;
    assert.equal(response.status(), 201, 'Source simulation owner must return a completed result');
    const result = await response.json();
    assert.equal(result.authorityLabel, 'SIMULATION_ONLY');
    assert.equal(result.evaluation.truthState, truth);
    await page
      .getByRole('region', { name: 'Simulation result' })
      .getByText(truth, { exact: true })
      .waitFor();
    results.push(result);
  }
  return results;
}
