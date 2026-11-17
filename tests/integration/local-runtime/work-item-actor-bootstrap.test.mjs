import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import {
  workItemActorBootstrapInputs,
  validateWorkItemActorCatalogue,
} from './deployment-intent-actors.mjs';

// Only the existing installer's pure input/preflight path is exercised here.
// No database/bootstrap effects, authentication, browser or receipt is simulated.
const participant = '018f0000-0000-7000-8000-000000000101';
const rootPrivacy = '018f0000-0000-7000-8000-000000000201';
const selectedPrivacy = '018f0000-0000-7000-8000-000000006201';
const args = [
  '/tmp/work-item-bootstrap-secrets',
  '/tmp/work-item-bootstrap-evidence',
  participant,
  'bootstrap-work-items',
  selectedPrivacy,
];
const journeyActions = [
  'ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
  'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
  'ACT-OPERATIONS_UPDATE_CLAIM-V1',
  'ACT-OPERATIONS_UPDATE_COMPLETE-V1',
  'ACT-WORK_ITEMS_READ_COLLECTION-V1',
  'ACT-WORK_ITEMS_READ_RESOURCE-V1',
  'ACT-OPERATIONS_READ_OPERATION-V1',
];
const entryActions = [
  'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
  'ACT-IDENTITY_CREATE_SESSION-V1',
  'ACT-IDENTITY_DELETE_SESSION-V1',
  'ACT-IDENTITY_UPDATE_STEP_UP-V1',
];
const installer = fileURLToPath(new URL('./deployment-intent-actors.mjs', import.meta.url));
function preflight(input) {
  return JSON.parse(
    execFileSync(process.execPath, [installer, ...input], {
      encoding: 'utf8',
      timeout: 10000,
    }),
  );
}

test('work-item mode requires explicit selected scope and bounded arguments', () => {
  const input = workItemActorBootstrapInputs(args);
  assert.equal(input.participantId, participant);
  assert.equal(input.privacyDomainId, selectedPrivacy);
  assert.equal(input.preflight, false);
  assert.equal(workItemActorBootstrapInputs([...args, '--preflight']).preflight, true);
  for (const invalid of [
    args.slice(0, 4),
    [...args, rootPrivacy],
    [...args, rootPrivacy, '--preflight'],
    [...args, '--authenticate'],
    ['relative', ...args.slice(1)],
    [args[0], 'relative', ...args.slice(2)],
    [args[0] + '\0', ...args.slice(1)],
    [...args.slice(0, 2), 'invalid', ...args.slice(3)],
    [...args.slice(0, 4), selectedPrivacy + '\n'],
    [...args.slice(0, 4), '*'],
  ])
    assert.throws(() => workItemActorBootstrapInputs(invalid));
});

test('identities and key names are isolated without any pre-established business or authentication result', () => {
  const input = workItemActorBootstrapInputs(args);
  const ids = Object.values(input.actors).flatMap(Object.values);
  assert.equal(ids.length, 8);
  assert.equal(new Set(ids).size, 8);
  for (const id of ids) assert.match(id, /^018f0019-0000-7000-8000-[0-9]{12}$/u);
  for (const name of ['maker', 'checker']) {
    assert.deepEqual(Object.keys(input.actors[name]).sort(), [
      'assignmentId',
      'credentialId',
      'envelopeId',
      'principalId',
    ]);
    assert.equal(input.keyPaths[name], `${args[0]}/work-item-${name}-webauthn.pk8`);
  }
  assert.equal(input.actorFile, `${args[1]}/deployment-intent-actors.json`);
  input.actors.maker.principalId = 'tampered';
  input.actions.push('invented');
  assert.notEqual(workItemActorBootstrapInputs(args).actors.maker.principalId, 'tampered');
  assert.deepEqual(workItemActorBootstrapInputs(args).actions, journeyActions);
});

test('journey authority stays selected-scope while initial session trust establishes an alternate context', () => {
  const input = workItemActorBootstrapInputs(args);
  assert.deepEqual(input.actions, journeyActions);
  assert.deepEqual(input.entryActions, entryActions);
  assert.equal(
    input.actions.some((id) => input.entryActions.includes(id)),
    false,
  );
  assert.deepEqual(input.entryPrivacyDomains, [rootPrivacy, selectedPrivacy]);
  assert.equal(input.bootstrapEntryPrivacyDomain, undefined);
  const root = workItemActorBootstrapInputs([...args.slice(0, 4), rootPrivacy]);
  assert.equal(root.bootstrapEntryPrivacyDomain, '018f0019-0000-7000-8000-000000000201');
  assert.deepEqual(root.entryPrivacyDomains, [rootPrivacy, root.bootstrapEntryPrivacyDomain]);
  assert.equal(root.privacyDomainId, rootPrivacy);
  assert.deepEqual(root.actions, journeyActions);
});

test('the actual installer preflight selects work-item actors, actions, entry bindings and paths without services', () => {
  const output = preflight([...args, '--preflight']);
  const input = workItemActorBootstrapInputs(args);
  assert.equal(output.participantId, participant);
  assert.deepEqual(output.privacyDomainIds, [selectedPrivacy]);
  assert.deepEqual(output.actors, input.actors);
  assert.deepEqual(output.actions, journeyActions);
  assert.deepEqual(output.entryActions, entryActions);
  assert.deepEqual(output.entryPrivacyDomains, input.entryPrivacyDomains);
  const root = preflight([...args.slice(0, 4), rootPrivacy, '--preflight']);
  assert.equal(root.bootstrapEntryPrivacyDomain, root.entryPrivacyDomains[1]);
  assert.deepEqual(output.keyPaths, input.keyPaths);
  const primary = new Set(Object.values(output.actors).flatMap(Object.values));
  const entry = Object.values(output.entryAuthorities).flatMap(Object.values);
  assert.equal(new Set(entry).size, 4);
  for (const id of entry) assert.ok(!primary.has(id));
});

test('existing notification and deployment preflight modes keep their actor allocation', () => {
  for (const [mode, prefix] of [
    ['bootstrap-notifications', '018f0018'],
    ['bootstrap', '018f0000'],
  ]) {
    const previous = [
      args[0],
      args[1],
      participant,
      mode,
      rootPrivacy,
      mode === 'bootstrap-notifications' ? '018f0018-0000-7000-8000-000000000201' : selectedPrivacy,
    ];
    assert.equal(workItemActorBootstrapInputs(previous), undefined);
    const output = preflight([...previous, '--preflight']);
    assert.equal(output.actors.maker.principalId, `${prefix}-0000-7000-8000-000000000141`);
    assert.equal(output.actors.checker.principalId, `${prefix}-0000-7000-8000-000000000142`);
    assert.equal(output.actions, undefined);
    if (mode === 'bootstrap-notifications') {
      assert.deepEqual(output.privacyDomainIds, [rootPrivacy]);
      assert.deepEqual(output.entryPrivacyDomains, ['018f0018-0000-7000-8000-000000000201']);
      assert.deepEqual(output.entryActions, [
        'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        'ACT-IDENTITY_CREATE_SESSION-V1',
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      ]);
    } else {
      assert.equal(output.privacyDomainIds, null);
      assert.equal(output.entryActions, undefined);
    }
  }
});

// Read the existing migration's registered action tuples as the independent input
// to the production preflight validator, including its security/disclosure fields.
async function registeredCatalogue() {
  const source = await readFile(
    new URL('../../../deploy/compose/local/migrate.sh', import.meta.url),
    'utf8',
  );
  const names = new Set([...journeyActions, ...entryActions]);
  return [
    ...source.matchAll(
      /^\s*\('([^']+)','([^']+)','([^']+)','([^']+)',(true|false),(true|false),(true|false),'([^']+)','([^']+)','([^']+)'\)[,;]?$/gmu,
    ),
  ]
    .filter((match) => names.has(match[1]))
    .map((match) => ({
      action_intent_id: match[1],
      resource_type: match[2],
      operation_class: match[3],
      risk_class: match[4],
      maker_checker_required: match[5] === 'true',
      step_up_required: match[6] === 'true',
      idempotency_required: match[7] === 'true',
      existence_disclosure: match[8],
      payload_disclosure: match[9],
      evidence_class: match[10],
    }));
}

test('installed action tuples must match the authoritative migration, including singular claim namespace', async () => {
  const rows = await registeredCatalogue();
  assert.equal(rows.length, 11);
  validateWorkItemActorCatalogue(rows);
  validateWorkItemActorCatalogue([...rows].reverse());
  const claim = rows.find((row) => row.action_intent_id === 'ACT-OPERATIONS_UPDATE_CLAIM-V1');
  assert.equal(claim.resource_type, 'work-item');
});

test('missing, duplicated, broadened or incompatible action catalogue entries fail closed', async () => {
  const rows = await registeredCatalogue();
  assert.throws(() => validateWorkItemActorCatalogue(rows.slice(1)));
  assert.throws(() => validateWorkItemActorCatalogue([...rows, rows[0]]));
  assert.throws(() => validateWorkItemActorCatalogue([rows[0], ...rows.slice(0, -1)]));
  for (const [field, value] of Object.entries({
    action_intent_id: 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1',
    resource_type: 'work-item',
    operation_class: 'DELETE',
    risk_class: 'HIGH',
    maker_checker_required: true,
    step_up_required: true,
    idempotency_required: false,
    existence_disclosure: 'FULL',
    payload_disclosure: 'AUTHORIZED_FULL',
    evidence_class: 'UPDATE_WORK_ITEM',
  })) {
    const changed = rows.map((row) =>
      row.action_intent_id === journeyActions[0] ? { ...row, [field]: value } : row,
    );
    assert.throws(() => validateWorkItemActorCatalogue(changed), field);
  }
});
