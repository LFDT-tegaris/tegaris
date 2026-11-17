import assert from 'node:assert/strict';

/** Native Value is approved independently before any deployment preparation.
 * All transitions below use the rendered Workbench and its public owners. */
export async function authorizeNativeValue({
  govern,
  actors,
  intentFields,
  walletId,
  scenario,
  sendCount,
}) {
  await govern({
    ...actors,
    label: 'Prepare deployment',
    fields: intentFields,
    reason: `Deny positive deployment value without Native Value authorization (${scenario}).`,
    expectedExecutionStatus: 400,
  });
  assert.equal(await sendCount(), 0);
  const issued = await govern({
    ...actors,
    label: 'Authorize Native Value',
    reason: `Independently authorize one exact workload endowment (${scenario}).`,
    fields: {
      'Wallet binding reference': `urn:openpc:resource:${walletId}`,
      'Execution workload reference (optional)':
        'urn:openpc:workload:018f0000-0000-7000-8000-000000000191',
      'Chain ID': '31337',
      'Network ID': 'openpc-local',
      'Genesis digest': `sha256:${'11'.repeat(32)}`,
      'Amount mode': 'EXACT',
      'Amount in wei': '10',
      'Valid until (UTC timestamp)': new Date(Date.now() + 240_000).toISOString(),
    },
  });
  assert.equal(issued.completed.result.state, 'UNUSED');
  assert.equal(issued.completed.result.runtimePermission, 'NONE');
  const document = JSON.parse(
    Buffer.from(issued.completed.result.authorizationDocument.slice(2), 'hex').toString('utf8'),
  );
  assert.equal(document.oneUse, true);
  assert.equal(document.used, false);
  assert.equal(document.maxAmountWei, '10');
  assert.equal(await sendCount(), 0);
  return issued;
}

export async function readConsumedNativeValue({ readApproval, maker, issued }) {
  const current = await readApproval(maker, issued.approvalId);
  assert.equal(current.result.state, 'CONSUMED');
  assert.equal(current.result.runtimePermission, 'NONE');
  assert.equal(
    current.result.issuedAuthorizationDigest,
    issued.completed.result.authorizationDigest,
  );
  assert.notEqual(current.result.authorizationDigest, issued.completed.result.authorizationDigest);
  const document = JSON.parse(
    Buffer.from(current.result.authorizationDocument.slice(2), 'hex').toString('utf8'),
  );
  assert.equal(document.oneUse, true);
  assert.equal(document.used, true);
  assert.equal(document.maxAmountWei, '10');
  return current.result;
}
