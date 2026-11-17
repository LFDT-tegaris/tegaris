import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { validatePolicySemantics } from '../../../services/module-registry/src/domain/policy-semantics.ts';
import { sha256CanonicalJson } from '../../../services/control-api/src/privacy-explorer/canonical.ts';
import { assertExplorerProjectionRequest } from '../../../services/control-api/src/contracts/privacy-explorer-adapter.ts';
import { validateExplorerProfile } from '../../../services/control-api/src/privacy-explorer/profile-registration.ts';

const [mode, evidence, fixture, session] = process.argv.slice(2);
const load = async (name) => JSON.parse(await readFile(join(evidence, name), 'utf8'));
const save = (name, value) => writeFile(join(evidence, name), JSON.stringify(value));
const profileFile = process.env.OPENPC_EXPLORER_PROFILE_FILE ?? 'explorer-profile-resource.json';
const storageFile = process.env.OPENPC_EXPLORER_STORAGE_FILE ?? 'explorer-storage.json';
assert.ok(
  ['explorer-profile-resource.json', 'explorer-functional-profile-resource.json'].includes(
    profileFile,
  ),
);
assert.ok(['explorer-storage.json', 'explorer-functional-storage.json'].includes(storageFile));
const explorerActions = [
  'ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1',
  'ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1',
  'ACT-PRIVACY_EXPLORER_PROFILES_READ_RESOURCE-V1',
  'ACT-PRIVACY_EXPLORER_READ_PROJECTION-V1',
  'ACT-PRIVACY_EXPLORER_READ_OCCURRENCE-V1',
].sort();
if (mode === 'functional-profile') {
  const { digest: _, ...original } = JSON.parse(
    await readFile(join(fixture, 'profile.json'), 'utf8'),
  );
  void _;
  // A terminal registration stays revoked. The functional browser gets a
  // distinct public registration against the same qualified external transport.
  const definition = { ...original, id: 'local-governed-explorer-functional' };
  const profile = validateExplorerProfile({
    ...definition,
    digest: sha256CanonicalJson(definition),
  });
  await save('explorer-functional-profile-definition.json', profile);
  await writeFile(join(fixture, 'profile.json'), JSON.stringify(profile));
} else if (mode === 'assignment') {
  process.stdout.write(
    JSON.stringify({
      assignmentId: '018f0000-0000-7000-8000-000000000140',
      principalId: '018f0000-0000-7000-8000-000000000111',
      roleId: 'urn:openpc:role:018f0000-0000-7000-8000-000000000805',
      authorityEnvelopeId: '018f0000-0000-7000-8000-000000000139',
      scopeDigest: `sha256:${'b8'.repeat(32)}`,
      privacyDomainIds: ['018f0000-0000-7000-8000-000000000201'],
      actionIntentIds: explorerActions,
      capabilityIds: [],
      resourceIds: ['*'],
      riskClasses: ['LOW', 'STANDARD', 'HIGH'],
      validFrom: new Date(Date.now() - 30_000).toISOString(),
      validUntil: '2030-01-01T00:00:00.000Z',
      makerCheckerRequired: true,
      stepUpRequired: false,
      onwardDelegationDepth: 0,
    }),
  );
} else if (mode === 'assignment-readback') {
  const expected = await load('explorer-assignment-current.json');
  const response = await fetch(
    `http://127.0.0.1:8080/v1/participants/018f0000-0000-7000-8000-000000000101/assignments/${expected.id}`,
    {
      headers: {
        'authorization': `Bearer ${session}`,
        'openpc-privacy-domain-id':
          'urn:openpc:privacy-domain:018f0000-0000-7000-8000-000000000201',
      },
      signal: AbortSignal.timeout(5_000),
    },
  );
  assert.equal(response.status, 200);
  const current = (await response.json()).effect;
  assert.deepEqual(current, expected);
  assert.equal(current.state, 'ACTIVE');
  assert.equal(current.makerCheckerRequired, true);
  assert.deepEqual([...current.actionIntentIds].sort(), explorerActions);
  assert.equal(current.roleId, 'urn:openpc:role:018f0000-0000-7000-8000-000000000805');
  assert.ok(Date.parse(current.validUntil) > Date.now());
  process.stdout.write(
    'OPENPC_EXPLORER_AUTHORITY|PASS|public-assignment|exact-five-actions|current-readback\n',
  );
} else if (mode === 'policy' || mode === 'policy-cutover') {
  // Retain the publicly acquired Fact and its source/contract/RPC policy. No
  // intermediate policy, approval, activation or Fact state is seeded here.
  const previous = await load('typed-policy-inputs.json');
  const registration = await load(profileFile);
  const policy = {
    policyId: '018f0000-0000-7000-8000-000000000c01',
    mode: 'STATIC',
    effect: 'ALLOW',
    subject: { kind: 'PRINCIPAL', principalId: '018f0000-0000-7000-8000-000000000111' },
    purpose: 'AUDIT',
    // Exercise the exact role URN persisted by the public assignment owner.
    requiredRoles: ['urn:openpc:role:018f0000-0000-7000-8000-000000000805'],
    conditions: [],
    selector: {
      kind: 'DISCLOSURE',
      profileId: registration.registrationId.split(':').at(-1),
      profileDigest: registration.profileDigest,
      dataClassId: 'CLASS-READ',
    },
    dimensions: ['EXISTENCE', 'EXPORT', 'PAYLOAD'],
    fields: mode === 'policy-cutover' ? ['PEF-A'] : ['PEF-A', 'PEF-B'],
  };
  const semanticDocument = {
    ...previous.semanticDocument,
    visibilityPolicies: [
      ...previous.semanticDocument.visibilityPolicies.filter(
        (entry) => entry.policyId !== policy.policyId,
      ),
      policy,
    ].sort((left, right) => left.policyId.localeCompare(right.policyId)),
  };
  const semantic = validatePolicySemantics(semanticDocument);
  await save('typed-policy-inputs.json', {
    ...previous,
    semanticVersion: `12.${Number(process.env.OPENPC_VISIBILITY_SOURCE_GENERATION)}.${mode === 'policy-cutover' ? 1 : 0}`,
    semanticDocument,
    semanticDigest: `sha256:${semantic.digest.toString('hex')}`,
    // Recheck the preserved state-read semantics under the governance actor.
    // The real Explorer request selects its own action-bound role below.
  });
} else {
  const base = 'http://127.0.0.1:8080';
  const path = '/api/v1/ui/privacy-explorer';
  const storage = await load(storageFile);
  const cookies = storage.cookies.filter(
    (cookie) => cookie.name === 'openpc_local_runtime_session' && cookie.domain === 'localhost',
  );
  assert.equal(cookies.length, 1, 'real OIDC BFF session required');
  if (mode === 'session' && cookies[0].httpOnly && cookies[0].expires * 1000 <= Date.now())
    process.exit(75);
  assert.ok(cookies[0].httpOnly && cookies[0].expires * 1000 > Date.now());
  const headers = {
    'cookie': `${cookies[0].name}=${cookies[0].value}`,
    'origin': base,
    'content-type': 'application/json',
  };
  const call = async (suffix = '', body) => {
    const response = await fetch(`${base}${path}${suffix}`, {
      method: body ? 'POST' : 'GET',
      headers,
      redirect: 'error',
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(45_000),
    });
    assert.equal(response.headers.get('cache-control'), 'no-store');
    return { status: response.status, body: await response.json() };
  };
  const setMode = (value) => writeFile(join(fixture, 'mode'), value);
  const registration = await load(profileFile);
  const profilePath = `?profileRef=${encodeURIComponent(registration.registrationId)}`;
  if (mode === 'session') {
    const response = await fetch(`${base}/api/v1/ui/local-session`, { headers });
    const current = await response.json();
    assert.equal(response.status, 200);
    if (current.authenticated === false) process.exit(75);
    assert.equal(current.authenticated, true);
    assert.equal(current.contextMode, 'PARTICIPANT');
    assert.equal(current.participantId, '018f0000-0000-7000-8000-000000000101');
    assert.equal(current.privacyDomainId, '018f0000-0000-7000-8000-000000000201');
    const selected = await call(profilePath);
    assert.equal(selected.status, 200, JSON.stringify(selected.body));
    assert.deepEqual(selected.body.profile, registration);
    process.stdout.write(
      'OPENPC_EXPLORER_SESSION|PASS|retained-oidc-context-current|public-profile-read\n',
    );
    process.exit(0);
  }
  const view = await call(profilePath);
  assert.equal(view.status, 200, JSON.stringify(view.body));
  assert.deepEqual(view.body.profile, registration);
  const intent = (overrides = {}) => ({
    actorKey: view.body.actorKey,
    profileRef: registration.registrationId,
    purpose: 'AUDIT',
    dataClassId: 'CLASS-READ',
    projectionFields: ['PEF-A'],
    filters: [],
    limit: 2,
    cursor: null,
    occurrenceId: randomUUID(),
    ...overrides,
  });
  const publicProjection = async (input) => {
    assert.ok(session, 'current authenticated public session required');
    const profile = registration.profile;
    const scope = {
      participantId: view.body.actor.participantId,
      privacyDomainId: view.body.actor.privacyDomainId,
      platformId: profile.sourceBinding.platformId,
      workloadId: profile.sourceBinding.workloadId,
      action: 'read',
    };
    const query = {
      purpose: input.purpose,
      subject: `urn:openpc:principal:${view.body.actor.principalId}`,
      resource: input.profileRef,
      action: 'read',
      scope,
      operationId: 'PXI-READ-GOVERNED-PROJECTION/v1',
      semanticOperationVersion: '1.0.0',
      dataClassId: input.dataClassId,
      filters: input.filters,
      page: { limit: input.limit },
      projectionFields: input.projectionFields,
      exportProfileDigest: profile.digest,
    };
    const { exportProfileDigest: _, ...fields } = query;
    void _;
    const request = assertExplorerProjectionRequest({
      ...fields,
      operationVersion: 'v1',
      schemaVersion: '1.0',
      issuedAt: new Date().toISOString(),
      page: { limit: input.limit, cursor: input.cursor },
      exportProfile: profile,
      queryDigest: sha256CanonicalJson(query),
      occurrence: { requestId: input.occurrenceId, correlationId: randomUUID() },
    });
    const response = await fetch(`${base}/v1/privacy-explorer/projections:read`, {
      method: 'POST',
      headers: {
        'Cookie': `__Host-openpc_session=${session}`,
        'Content-Type': 'application/json',
        'Origin': base,
        'OpenPC-API-Version': '1',
        'OpenPC-Participant-ID': `urn:openpc:participant:${scope.participantId}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${scope.privacyDomainId}`,
        'X-Request-ID': randomUUID(),
        'X-Correlation-ID': randomUUID(),
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(40_000),
    });
    assert.equal(
      response.headers.get('cache-control'),
      'no-store',
      `public status ${response.status}`,
    );
    return { status: response.status, body: await response.json() };
  };
  const noProtected = (value) => {
    const bytes = JSON.stringify(value);
    for (const forbidden of ['explorer-visible-canary', 'external-record-', 'external-next-page'])
      assert.ok(!bytes.includes(forbidden), 'closed response exposed external data');
  };
  const status = async (id, expected = 'RELEASE_AUTHORIZED') => {
    const result = await call(`?occurrenceId=${id}`);
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.occurrence.state, expected);
    assert.equal(result.body.occurrence.clientReceipt, 'UNKNOWN');
    noProtected(result);
    return result.body;
  };
  if (mode === 'functional-inputs') {
    for (const value of [[], { unexpected: true }]) {
      const rejected = await call(
        '',
        intent({ filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value }] }),
      );
      assert.equal(rejected.status, 400);
      assert.equal(rejected.body.code, 'PC-DATA-6004');
      noProtected(rejected);
    }
    process.stdout.write('OPENPC_EXPLORER_INPUTS|PASS|invalid-filter|safe-api-denial\n');
  } else if (mode === 'readback') {
    const accepted = await load('explorer-accepted.json');
    assert.deepEqual(await status(accepted.occurrenceId), accepted.status);
    process.stdout.write(
      'OPENPC_EXPLORER_RESTART|PASS|durable-claim|no-payload-replay|client-receipt-unknown\n',
    );
  } else if (['paused-revoke', 'paused-policy', 'paused-fact'].includes(mode)) {
    await setMode('PAUSE');
    const request = intent();
    const result = await publicProjection(request);
    assert.notEqual(result.status, 200);
    noProtected(result);
    await status(request.occurrenceId, 'INTERRUPTED');
    process.stdout.write(
      `OPENPC_EXPLORER_PAUSED_RESULT|OBSERVED|kind=${mode}|interrupted|no-protected-release\n`,
    );
  } else if (mode === 'fences') {
    if (process.env.OPENPC_EXPLORER_REUSE_CONCURRENCY !== '1') {
      await setMode('COMPLETE');
      const request = intent();
      const results = await Promise.all([call('', request), call('', request)]);
      assert.equal(
        results.filter((result) => result.status === 200).length,
        1,
        JSON.stringify(results),
      );
      noProtected(results.find((result) => result.status !== 200));
      await status(request.occurrenceId);
      process.stdout.write('OPENPC_EXPLORER_CONCURRENCY|PASS|one-release|one-durable-claim\n');
    }
    if (process.env.OPENPC_EXPLORER_REUSE_UNKNOWN !== '1') {
      await setMode('UNKNOWN');
      const unknown = await call('', intent());
      assert.equal(unknown.status, 200, JSON.stringify(unknown.body));
      assert.equal(unknown.body.result.outcome, 'UNKNOWN');
      assert.deepEqual(unknown.body.result.records, []);
      assert.deepEqual(unknown.body.result.page, { cursor: null, gapFree: false });
      noProtected(unknown);
    }
    await setMode('PARTIAL');
    const partial = await publicProjection(intent());
    assert.equal(partial.status, 200, JSON.stringify(partial.body));
    assert.match(partial.body.page.cursor, /^pec1\.[A-Za-z0-9_-]{43}$/u);
    await save('explorer-stale-cursor.json', { cursor: partial.body.page.cursor });
    await setMode('COMPLETE');
    process.stdout.write(
      'OPENPC_EXPLORER_FENCES|PASS|unknown-without-data-or-absence-claim|opaque-cursor-prepared\n',
    );
  } else if (mode === 'stale-cursor') {
    const { cursor } = await load('explorer-stale-cursor.json');
    await setMode('COMPLETE');
    const [result, current] = await Promise.all([
      publicProjection(intent({ cursor })),
      publicProjection(intent()),
    ]);
    assert.notEqual(result.status, 200);
    noProtected(result);
    // The same still-allowed field succeeds with the new generation. This
    // distinguishes invalidation from denial or expiry of all current access.
    assert.equal(current.status, 200, JSON.stringify(current.body));
    assert.equal(current.body.outcome, 'COMPLETE');
    process.stdout.write(
      'OPENPC_EXPLORER_POLICY|PASS|stale-continuation-closed|new-generation-allowed\n',
    );
  } else if (mode === 'recovered') {
    await setMode('COMPLETE');
    const request = intent();
    const result = await publicProjection(request);
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.outcome, 'COMPLETE');
    assert.deepEqual(
      result.body.records.map((record) => record.fields),
      [[{ fieldId: 'PEF-A', value: 'explorer-visible-canary' }]],
    );
    await status(request.occurrenceId);
    process.stdout.write(
      'OPENPC_EXPLORER_RECOVERY|PASS|fresh-public-replacement|protected-release|authorized-readback\n',
    );
  } else if (mode === 'read') {
    await setMode('COMPLETE');
    const request = intent();
    const allowed = await call('', request);
    assert.equal(allowed.status, 200, JSON.stringify(allowed.body));
    assert.equal(allowed.body.result.outcome, 'COMPLETE');
    assert.deepEqual(
      allowed.body.result.records.map((row) => row.fields),
      [[{ fieldId: 'PEF-A', value: 'explorer-visible-canary' }]],
    );
    assert.match(allowed.body.result.records[0].id, /^per1\.[A-Za-z0-9_-]+$/u);
    const receipt = await status(request.occurrenceId);
    await save('explorer-accepted.json', { occurrenceId: request.occurrenceId, status: receipt });
    const repeated = await call('', request);
    assert.notEqual(repeated.status, 200);
    noProtected(repeated);
    for (const changed of [
      { purpose: 'UNAUTHORIZED_PURPOSE' },
      { projectionFields: ['PEF-HIDDEN'] },
      { actorKey: `sha256:${'0'.repeat(64)}` },
      { cursor: `pec1.${'a'.repeat(43)}` },
    ]) {
      const rejected = await call('', intent(changed));
      assert.notEqual(rejected.status, 200);
      noProtected(rejected);
    }
    await setMode('EMPTY');
    const empty = await call('', intent());
    assert.equal(empty.status, 200, JSON.stringify(empty.body));
    assert.equal(empty.body.result.outcome, 'COMPLETE');
    assert.deepEqual(empty.body.result.records, []);
    await setMode('PARTIAL');
    const partial = await call('', intent());
    assert.equal(partial.status, 200, JSON.stringify(partial.body));
    const cursor = partial.body.result.page.cursor;
    assert.match(cursor, /^pec1\.[A-Za-z0-9_-]{43}$/u);
    const next = await call('', intent({ cursor }));
    assert.equal(next.status, 200, JSON.stringify(next.body));
    assert.equal(next.body.result.page.cursor, null);
    assert.notEqual(next.body.result.records[0].id, partial.body.result.records[0].id);
    const replay = await call('', intent({ cursor }));
    assert.notEqual(replay.status, 200);
    noProtected(replay);
    for (const failure of ['WRONG_DIGEST', 'MALFORMED', 'OVERSIZED', 'REORG']) {
      await setMode(failure);
      const failed = await call('', intent());
      assert.notEqual(failed.status, 200, failure);
      noProtected(failed);
    }
    await setMode('COMPLETE');
    process.stdout.write(
      'OPENPC_EXPLORER_API|PASS|oidc-context|governed-profile-policy|mutual-tls|local-fields|opaque-records-cursor|single-claim|safe-failures\n',
    );
  } else throw new Error('Unknown Explorer journey mode');
}
