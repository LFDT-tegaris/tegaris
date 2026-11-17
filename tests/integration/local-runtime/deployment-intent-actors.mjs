import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { verifyInstalledRuntimeSource } from './runtime-source-bootstrap.mjs';

const fixtureUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const entryPrivacy = '018f0000-0000-7000-8000-000000000201';

/** Initial external authenticator trust only. Never writes session freshness,
 * an approval, enrollment result or a business effect. Retained keys are exact. */
export async function installInitialAuthenticatorTrust(client, input) {
  for (const field of ['participantId', 'principalId', 'credentialId'])
    assert.match(input[field], fixtureUuid);
  const publicKey = createPublicKey({ key: input.publicKey, format: 'der', type: 'spki' });
  assert.equal(publicKey.asymmetricKeyType, 'ec');
  assert.equal(publicKey.asymmetricKeyDetails.namedCurve, 'prime256v1');
  assert(
    (
      await client.query(
        'select current_user=session_user and rolsuper allowed from pg_roles where rolname=session_user',
      )
    ).rows[0].allowed,
  );
  const principal = await client.query(
    "select 1 from control.principal where participant_id=$1 and principal_id=$2 and state='ACTIVE' and kind in ('USER','PLATFORM_OPERATOR')",
    [input.participantId, input.principalId],
  );
  assert.equal(principal.rowCount, 1);
  const existing = await client.query(
    "select credential_id,public_key_spki_der,state from control.credential where participant_id=$1 and principal_id=$2 and kind='WEBAUTHN'",
    [input.participantId, input.principalId],
  );
  if (existing.rowCount) {
    assert.equal(existing.rowCount, 1);
    assert.equal(existing.rows[0].credential_id, input.credentialId);
    assert.deepEqual(existing.rows[0].public_key_spki_der, input.publicKey);
    assert.equal(existing.rows[0].state, 'ACTIVE');
    return;
  }
  await client.query(
    "insert into control.credential(credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,state,credential_epoch,authenticator_sign_count,valid_from) values($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1,0,clock_timestamp())",
    [
      input.credentialId,
      input.participantId,
      input.principalId,
      createHash('sha256').update(input.publicKey).digest(),
      input.publicKey,
    ],
  );
}
// Exact registered tuples from deploy/compose/local/migrate.sh. This corpus checks
// installed catalogue compatibility; it never inserts or repairs action authority.
const workItemCatalogue = [
  [
    'ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
    'work-items',
    'CREATE',
    'STANDARD',
    true,
    'AUTHORIZED_ONLY',
    'REDACTED',
    'CREATE_WORK_ITEMS',
  ],
  [
    'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
    'work-items',
    'UPDATE',
    'STANDARD',
    true,
    'AUTHORIZED_ONLY',
    'REDACTED',
    'UPDATE_WORK_ITEMS',
  ],
  [
    'ACT-OPERATIONS_UPDATE_CLAIM-V1',
    'work-item',
    'UPDATE',
    'STANDARD',
    true,
    'AUTHORIZED_ONLY',
    'REDACTED',
    'UPDATE_WORK_ITEM',
  ],
  [
    'ACT-OPERATIONS_UPDATE_COMPLETE-V1',
    'work-item',
    'UPDATE',
    'STANDARD',
    true,
    'AUTHORIZED_ONLY',
    'REDACTED',
    'UPDATE_WORK_ITEM',
  ],
  [
    'ACT-WORK_ITEMS_READ_COLLECTION-V1',
    'work-items',
    'READ',
    'LOW',
    false,
    'FULL',
    'AUTHORIZED_FULL',
    'READ_WORK_ITEMS',
  ],
  [
    'ACT-WORK_ITEMS_READ_RESOURCE-V1',
    'work-items',
    'READ',
    'LOW',
    false,
    'FULL',
    'AUTHORIZED_FULL',
    'READ_WORK_ITEMS',
  ],
  [
    'ACT-OPERATIONS_READ_OPERATION-V1',
    'operations',
    'READ',
    'LOW',
    false,
    'AUTHORIZED_ONLY',
    'AUTHORIZED_FULL',
    'READ_OPERATIONS',
  ],
  [
    'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    'policy',
    'READ',
    'STANDARD',
    false,
    'AUTHORIZED_ONLY',
    'REDACTED',
    'POLICY_EVALUATION',
  ],
  [
    'ACT-IDENTITY_CREATE_SESSION-V1',
    'session',
    'CREATE',
    'STANDARD',
    true,
    'AUTHORIZED_ONLY',
    'REDACTED',
    'SESSION_MUTATION',
  ],
  [
    'ACT-IDENTITY_DELETE_SESSION-V1',
    'session',
    'DELETE',
    'STANDARD',
    true,
    'AUTHORIZED_ONLY',
    'REDACTED',
    'SESSION_MUTATION',
  ],
  [
    'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    'identity',
    'UPDATE',
    'HIGH',
    true,
    'AUTHORIZED_ONLY',
    'REDACTED',
    'IDENTITY_MUTATION',
  ],
];

/** Import-safe input contract consumed by this installer, without SQL or browser startup. */
export function workItemActorBootstrapInputs(args) {
  if (args[3] !== 'bootstrap-work-items') return undefined;
  assert.ok(
    args.length === 5 || (args.length === 6 && args[5] === '--preflight'),
    'Work-item bootstrap requires one explicit privacy domain',
  );
  const [secretRoot, evidenceRoot, participantId, , privacyDomainId] = args;
  for (const root of [secretRoot, evidenceRoot])
    assert.ok(typeof root === 'string' && isAbsolute(root) && !root.includes('\0'));
  for (const id of [participantId, privacyDomainId])
    assert.ok(typeof id === 'string' && id === id.trim() && fixtureUuid.test(id));
  const actors = Object.fromEntries(
    ['maker', 'checker'].map((name, index) => [
      name,
      {
        principalId: `018f0019-0000-7000-8000-00000000014${index + 1}`,
        envelopeId: `018f0019-0000-7000-8000-000000000${index === 0 ? '151' : '161'}`,
        assignmentId: `018f0019-0000-7000-8000-000000000${index === 0 ? '152' : '162'}`,
        credentialId: `018f0019-0000-7000-8000-00000000094${index + 6}`,
      },
    ]),
  );
  return {
    participantId,
    privacyDomainId,
    preflight: args[5] === '--preflight',
    actors,
    actions: workItemCatalogue.slice(0, 7).map(([id]) => id),
    entryActions: workItemCatalogue.slice(7).map(([id]) => id),
    // Fresh root-scope actors bootstrap one isolated entry context atomically
    // with initial trust. Work-item authority remains selected-scope only.
    bootstrapEntryPrivacyDomain:
      privacyDomainId === entryPrivacy ? '018f0019-0000-7000-8000-000000000201' : undefined,
    entryPrivacyDomains: [
      entryPrivacy,
      privacyDomainId === entryPrivacy ? '018f0019-0000-7000-8000-000000000201' : privacyDomainId,
    ],
    keyPaths: Object.fromEntries(
      ['maker', 'checker'].map((name) => [
        name,
        join(secretRoot, `work-item-${name}-webauthn.pk8`),
      ]),
    ),
    actorFile: join(evidenceRoot, 'deployment-intent-actors.json'),
  };
}

/** Same initial-identity installer, with a read-only receipt/operation intersection.
 * The checker deliberately has no operation read grant at any authority layer. */
export function evidenceCorrelationActorBootstrapInputs(args) {
  if (args[3] !== 'bootstrap-evidence-correlation') return undefined;
  const input = workItemActorBootstrapInputs(
    args.map((value, index) => (index === 3 ? 'bootstrap-work-items' : value)),
  );
  for (const actor of Object.values(input.actors))
    for (const field of Object.keys(actor))
      actor[field] = actor[field].replace(/^018f0019/u, '018f0022');
  input.bootstrapEntryPrivacyDomain = input.bootstrapEntryPrivacyDomain?.replace(
    /^018f0019/u,
    '018f0022',
  );
  input.entryPrivacyDomains = input.entryPrivacyDomains.map((id) =>
    id.replace(/^018f0019/u, '018f0022'),
  );
  const reads = [
    'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
    'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
  ];
  input.actions = [...reads, 'ACT-OPERATIONS_READ_OPERATION-V1'];
  input.actorActions = { maker: [...input.actions], checker: reads };
  input.keyPaths = Object.fromEntries(
    Object.keys(input.actors).map((name) => [
      name,
      join(args[0], `evidence-correlation-${name}-webauthn.pk8`),
    ]),
  );
  return input;
}

export function validateWorkItemActorCatalogue(rows) {
  assert.equal(
    rows.length,
    workItemCatalogue.length,
    'Work-item/session catalogue must be complete and unique',
  );
  for (const [
    id,
    resource,
    operation,
    risk,
    idempotency,
    existence,
    payload,
    evidence,
  ] of workItemCatalogue) {
    const selected = rows.filter((row) => row.action_intent_id === id);
    assert.equal(selected.length, 1, 'Each registered action must occur exactly once');
    assert.deepEqual(selected[0], {
      action_intent_id: id,
      resource_type: resource,
      operation_class: operation,
      risk_class: risk,
      maker_checker_required: false,
      step_up_required: false,
      idempotency_required: idempotency,
      existence_disclosure: existence,
      payload_disclosure: payload,
      evidence_class: evidence,
    });
  }
}

async function main() {
  const correlationActors = evidenceCorrelationActorBootstrapInputs(process.argv.slice(2));
  const isolatedActors = correlationActors ?? workItemActorBootstrapInputs(process.argv.slice(2));

  // Initial trust for an isolated USER maker/checker pair. No approvals, step-up
  // results, sessions, wallet bindings, intents or other business effects are seeded.
  const [secretRoot, evidenceRoot, participantId, mode, selectedPrivacy, sixthArgument] =
    process.argv.slice(2);
  const foreignPrivacy = isolatedActors ? undefined : sixthArgument;
  for (const privacy of [selectedPrivacy, foreignPrivacy].filter((value) => value !== undefined))
    assert.match(privacy, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  const notificationMode = mode === 'bootstrap-notifications';
  const notificationEntryPrivacy = '018f0018-0000-7000-8000-000000000201';
  if (notificationMode) {
    assert.ok(
      selectedPrivacy === undefined || selectedPrivacy === '018f0000-0000-7000-8000-000000000201',
    );
    assert.ok(foreignPrivacy === undefined || foreignPrivacy === notificationEntryPrivacy);
  }
  const runtimeBootstrap = mode === 'bootstrap-runtime-context';
  const runtimeEntry = mode === 'bootstrap-runtime-entry';
  const sourceHolds = mode === 'bootstrap-evidence-source-holds';
  const holdSelectors = mode === 'bootstrap-evidence-hold-selectors' || sourceHolds;
  const storeRetirement = mode === 'bootstrap-evidence-store-retirement';
  const retentionSearch = mode === 'bootstrap-evidence-retention-search';
  const projectionDeletion = mode === 'bootstrap-evidence-projection-deletion' || retentionSearch;
  if (retentionSearch) {
    assert.equal(selectedPrivacy, '018f0021-0000-7000-8000-000000000201');
    assert.ok(foreignPrivacy);
    assert.notEqual(selectedPrivacy, foreignPrivacy);
  }
  const remoteProtected = mode === 'bootstrap-evidence-remote-protected';
  const rawDeletion = mode === 'bootstrap-evidence-raw-deletion' || remoteProtected;
  const protectedEvidence = mode === 'bootstrap-evidence-protected' || rawDeletion;
  const rpcEvidence =
    mode === 'bootstrap-evidence-rpc' || protectedEvidence || projectionDeletion || storeRetirement;
  const rpcEntry = mode === 'bootstrap-evidence-rpc-entry';
  const deletionBatch = mode === 'bootstrap-evidence-deletion-batch';
  const rejectionDeletion = mode === 'bootstrap-evidence-rejection-deletion';
  const deletionMode =
    mode === 'bootstrap-evidence-deletion' ||
    deletionBatch ||
    rawDeletion ||
    projectionDeletion ||
    storeRetirement;
  const evidenceMode = [
    'bootstrap-evidence-protected',
    'bootstrap-evidence-raw-deletion',
    'bootstrap-evidence-remote-protected',
    'bootstrap-evidence-projection-deletion',
    'bootstrap-evidence-retention-search',
    'bootstrap-evidence-store-retirement',
    'bootstrap-evidence',
    'bootstrap-evidence-rpc',
    'bootstrap-evidence-rpc-entry',
    'bootstrap-evidence-holds',
    'bootstrap-evidence-hold-selectors',
    'bootstrap-evidence-source-holds',
    'bootstrap-retention',
    'bootstrap-evidence-deletion',
    'bootstrap-evidence-deletion-batch',
    'bootstrap-evidence-rejection-deletion',
  ].includes(mode);
  const actorLabel = isolatedActors
    ? correlationActors
      ? 'Evidence correlation'
      : 'Work item'
    : notificationMode
      ? 'Notification'
      : storeRetirement
        ? 'Store retirement'
        : projectionDeletion
          ? retentionSearch
            ? 'Retention search'
            : 'Projection deletion'
          : rawDeletion
            ? remoteProtected
              ? 'Remote protected proof'
              : 'Raw proof deletion'
            : sourceHolds
              ? 'Evidence source hold'
              : holdSelectors
                ? 'Evidence hold selector'
                : protectedEvidence
                  ? 'Protected proof'
                  : runtimeBootstrap
                    ? 'Runtime bootstrap'
                    : rpcEvidence
                      ? 'RPC evidence'
                      : rejectionDeletion
                        ? 'Evidence rejection deletion'
                        : deletionMode
                          ? deletionBatch
                            ? 'Evidence deletion batch'
                            : 'Evidence deletion'
                          : mode === 'bootstrap-retention'
                            ? 'Retention policy'
                            : mode === 'bootstrap-evidence-holds'
                              ? 'Evidence hold'
                              : evidenceMode
                                ? 'Evidence'
                                : 'Deployment';
  const keyPrefix = isolatedActors
    ? 'work-item'
    : notificationMode
      ? 'notification'
      : storeRetirement
        ? 'store-retirement'
        : projectionDeletion
          ? retentionSearch
            ? 'retention-search'
            : 'projection-deletion'
          : rawDeletion
            ? remoteProtected
              ? 'remote-protected-proof'
              : 'raw-proof-deletion'
            : sourceHolds
              ? 'evidence-source-holds'
              : holdSelectors
                ? 'evidence-hold-selectors'
                : protectedEvidence
                  ? 'protected-proof'
                  : runtimeBootstrap
                    ? 'runtime-bootstrap'
                    : rpcEvidence
                      ? 'rpc-evidence'
                      : rejectionDeletion
                        ? 'evidence-rejection-deletion'
                        : deletionMode
                          ? deletionBatch
                            ? 'evidence-deletion-batch'
                            : 'evidence-deletion'
                          : mode === 'bootstrap-retention'
                            ? 'retention-policy'
                            : mode === 'bootstrap-evidence-holds'
                              ? 'evidence-hold'
                              : evidenceMode
                                ? 'evidence'
                                : 'deployment';
  const evidenceActions = isolatedActors
    ? isolatedActors.actions
    : notificationMode
      ? [
          'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1',
          'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1',
          'ACT-NOTIFICATIONS_READ_RESOURCE-V1',
          'ACT-NOTIFICATIONS_READ_COLLECTION-V1',
          'ACT-NOTIFICATION_ENDPOINTS_READ_COLLECTION-V1',
          'ACT-NOTIFICATION_ENDPOINTS_READ_RESOURCE-V1',
          'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
          'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
          'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
        ]
      : runtimeBootstrap
        ? [
            'ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1',
            'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
            'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1',
            'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
            'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',
            'ACT-RETENTION_POLICIES_READ_RESOURCE-V1',
          ]
        : evidenceMode
          ? [
              ...(projectionDeletion ? ['ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1'] : []),
              ...(protectedEvidence
                ? [
                    'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1',
                    'ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1',
                    'ACT-PROTECTED_PROOF_ACCESS_CONSUME_RESOURCE-V1',
                    'ACT-PROTECTED_PROOFS_READ_SOURCE-V1',
                    'ACT-PROTECTED_PROOFS_READ_RESOURCE-V1',
                    'ACT-PROTECTED_PROOFS_READ_COLLECTION-V1',
                    'ACT-PROTECTED_PROOF_ACCESS_READ_RESOURCE-V1',
                    'ACT-PROTECTED_PROOF_ACCESS_READ_COLLECTION-V1',
                  ]
                : []),
              'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
              'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
              'ACT-EVIDENCE_EXPORTS_CREATE_RESOURCE-V1',
              'ACT-EVIDENCE_EXPORTS_UPDATE_RESOURCE-V1',
              'ACT-EVIDENCE_EXPORTS_READ_COLLECTION-V1',
              'ACT-EVIDENCE_EXPORTS_READ_RESOURCE-V1',
              'ACT-EVIDENCE_EXPORT_RECORDS-V1',
              'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
              'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
              ...(holdSelectors || projectionDeletion
                ? [
                    'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
                    'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1',
                  ]
                : []),
              'ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1',
              'ACT-EVIDENCE_HOLDS_READ_COLLECTION-V1',
              ...(deletionMode || rejectionDeletion
                ? [
                    storeRetirement
                      ? 'ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1'
                      : rawDeletion
                        ? 'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1'
                        : deletionBatch
                          ? 'ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1'
                          : 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1',
                    'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
                    'ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1',
                  ]
                : []),
              ...(mode === 'bootstrap-retention' || deletionMode || rejectionDeletion
                ? [
                    'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',
                    'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1',
                    'ACT-RETENTION_POLICIES_READ_RESOURCE-V1',
                    'ACT-RETENTION_POLICIES_READ_COLLECTION-V1',
                  ]
                : []),
            ]
          : [];
  const initialOnly = [
    'bootstrap-work-items',
    'bootstrap-evidence-correlation',
    'bootstrap-notifications',
    'bootstrap-evidence-hold-selectors',
    'bootstrap-evidence-source-holds',
    'bootstrap-evidence-protected',
    'bootstrap-evidence-raw-deletion',
    'bootstrap-evidence-remote-protected',
    'bootstrap-evidence-projection-deletion',
    'bootstrap-evidence-retention-search',
    'bootstrap-evidence-store-retirement',
    'bootstrap',
    'bootstrap-runtime-context',
    'bootstrap-runtime-entry',
    'bootstrap-runtime-source-trust',
    'bootstrap-runtime-read-trust',
    'bootstrap-runtime-fact-trust',
    'bootstrap-evidence-deletion-entry',
    'bootstrap-review',
    'bootstrap-evidence',
    'bootstrap-evidence-rpc',
    'bootstrap-evidence-rpc-entry',
    'bootstrap-evidence-holds',
    'bootstrap-retention',
    'bootstrap-evidence-deletion',
    'bootstrap-evidence-deletion-batch',
    'bootstrap-evidence-rejection-deletion',
  ].includes(mode);
  const isolatedPrivacy = isolatedActors
    ? [selectedPrivacy]
    : notificationMode
      ? ['018f0000-0000-7000-8000-000000000201']
      : sourceHolds
        ? ['018f0000-0000-7000-8000-000000000201', selectedPrivacy]
        : protectedEvidence
          ? [
              ...new Set([
                selectedPrivacy ?? '018f0000-0000-7000-8000-000000000201',
                foreignPrivacy ?? '018f0000-0000-7000-8000-000000000201',
              ]),
            ]
          : runtimeBootstrap
            ? [selectedPrivacy]
            : rpcEvidence
              ? [
                  selectedPrivacy ?? '018f0000-0000-7000-8000-000000000201',
                  foreignPrivacy ?? '018f0000-0000-7000-8000-000000006201',
                ]
              : rejectionDeletion
                ? ['018f0000-0000-7000-8000-000000000201', '018f0000-0000-7000-8000-000000006201']
                : deletionMode
                  ? ['018f0000-0000-7000-8000-000000004201']
                  : null;
  if (rpcEvidence && !protectedEvidence) assert.notEqual(isolatedPrivacy[0], isolatedPrivacy[1]);
  if (sourceHolds) {
    assert.ok(selectedPrivacy, 'Source hold actors require an existing child privacy context');
    assert.notEqual(selectedPrivacy, isolatedPrivacy[0]);
  }
  if (runtimeBootstrap) {
    assert.ok(selectedPrivacy, 'Bootstrap requires an explicit new privacy context');
    assert.notEqual(selectedPrivacy, '018f0000-0000-7000-8000-000000000201');
  }
  let actors = {
    maker: {
      principalId: '018f0000-0000-7000-8000-000000000141',
      envelopeId: '018f0000-0000-7000-8000-000000000151',
      assignmentId: '018f0000-0000-7000-8000-000000000152',
      credentialId: '018f0000-0000-7000-8000-000000000946',
    },
    checker: {
      principalId: '018f0000-0000-7000-8000-000000000142',
      envelopeId: '018f0000-0000-7000-8000-000000000161',
      assignmentId: '018f0000-0000-7000-8000-000000000162',
      credentialId: '018f0000-0000-7000-8000-000000000947',
    },
  };
  if (evidenceMode || runtimeBootstrap || notificationMode) {
    // Separate initial identities keep the evidence journey independent of the
    // later deployment journey in the same full runtime acceptance.
    for (const actor of Object.values(actors)) {
      for (const field of ['principalId', 'envelopeId', 'assignmentId', 'credentialId'])
        actor[field] = notificationMode
          ? actor[field].replace(/^018f0000/u, '018f0018')
          : storeRetirement
            ? actor[field].replace(/^018f0000/u, '018f0020')
            : projectionDeletion
              ? actor[field].replace(/^018f0000/u, retentionSearch ? '018f0021' : '018f0014')
              : rawDeletion
                ? actor[field].replace(/^018f0000/u, '018f0013')
                : holdSelectors
                  ? actor[field].replace(/^018f0000/u, sourceHolds ? '018f0012' : '018f0011')
                  : actor[field].slice(0, -4) +
                    String(
                      Number(actor[field].slice(-4)) +
                        (runtimeBootstrap
                          ? 8000
                          : protectedEvidence
                            ? 9000
                            : rpcEvidence
                              ? 7000
                              : rejectionDeletion
                                ? 6000
                                : deletionMode
                                  ? deletionBatch
                                    ? 5000
                                    : 4000
                                  : mode === 'bootstrap-retention'
                                    ? 3000
                                    : mode === 'bootstrap-evidence-holds'
                                      ? 2000
                                      : 1000),
                    );
    }
  }
  if (isolatedActors) actors = isolatedActors.actors;
  function entryAuthorityId(id) {
    assert.match(id, fixtureUuid);
    assert.match(id.slice(-4), /^\d{4}$/u);
    const value = Number(id.slice(-4)) + 100;
    assert.ok(value <= 9999);
    return id.slice(0, -4) + String(value).padStart(4, '0');
  }
  const entryAuthorities = Object.fromEntries(
    Object.entries(actors).map(([name, actor]) => {
      for (const id of Object.values(actor)) assert.match(id, fixtureUuid);
      const result = {
        envelopeId: entryAuthorityId(actor.envelopeId),
        assignmentId: entryAuthorityId(actor.assignmentId),
      };
      for (const id of Object.values(result)) assert.match(id, fixtureUuid);
      return [name, result];
    }),
  );
  function validateContextEntryActor(actor) {
    assert.ok(
      (isolatedActors
        ? Object.values(isolatedActors.actors).map((item) => item.principalId)
        : notificationMode
          ? ['018f0018-0000-7000-8000-000000000141', '018f0018-0000-7000-8000-000000000142']
          : storeRetirement
            ? ['018f0020-0000-7000-8000-000000000141', '018f0020-0000-7000-8000-000000000142']
            : projectionDeletion
              ? retentionSearch
                ? ['018f0021-0000-7000-8000-000000000141', '018f0021-0000-7000-8000-000000000142']
                : ['018f0014-0000-7000-8000-000000000141', '018f0014-0000-7000-8000-000000000142']
              : rawDeletion
                ? ['018f0013-0000-7000-8000-000000000141', '018f0013-0000-7000-8000-000000000142']
                : protectedEvidence
                  ? ['018f0000-0000-7000-8000-000000009141', '018f0000-0000-7000-8000-000000009142']
                  : rpcEvidence || rpcEntry
                    ? [
                        '018f0000-0000-7000-8000-000000007141',
                        '018f0000-0000-7000-8000-000000007142',
                      ]
                    : runtimeBootstrap || runtimeEntry
                      ? [
                          '018f0000-0000-7000-8000-000000008141',
                          '018f0000-0000-7000-8000-000000008142',
                        ]
                      : deletionBatch
                        ? [
                            '018f0000-0000-7000-8000-000000005141',
                            '018f0000-0000-7000-8000-000000005142',
                          ]
                        : [
                            '018f0000-0000-7000-8000-000000004141',
                            '018f0000-0000-7000-8000-000000004142',
                          ]
      ).includes(actor.principalId),
    );
  }
  if (isolatedActors?.preflight || process.argv[8] === '--preflight') {
    assert.ok(initialOnly, 'Only initial actor definitions have a pure preflight');
    if (storeRetirement || retentionSearch || notificationMode)
      for (const actor of Object.values(actors)) validateContextEntryActor(actor);
    assert.match(participantId, fixtureUuid);
    process.stdout.write(
      JSON.stringify({
        participantId,
        actorLabel,
        privacyDomainIds: isolatedPrivacy,
        actors,
        entryAuthorities,
        ...(runtimeBootstrap ? { actions: evidenceActions } : {}),
        ...(notificationMode
          ? {
              entryPrivacyDomains: [notificationEntryPrivacy],
              entryActions: [
                'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
                'ACT-IDENTITY_CREATE_SESSION-V1',
                'ACT-IDENTITY_UPDATE_STEP_UP-V1',
              ],
            }
          : {}),
        ...(isolatedActors
          ? {
              actions: isolatedActors.actions,
              ...(correlationActors ? { actorActions: correlationActors.actorActions } : {}),
              entryActions: isolatedActors.entryActions,
              entryPrivacyDomains: isolatedActors.entryPrivacyDomains,
              bootstrapEntryPrivacyDomain: isolatedActors.bootstrapEntryPrivacyDomain,
              keyPaths: isolatedActors.keyPaths,
            }
          : {}),
      }) + '\n',
    );
    return;
  }
  if (isolatedActors) await assert.rejects(readFile(isolatedActors.actorFile), { code: 'ENOENT' });
  const [
    { Pool },
    { chromium },
    { decodeBffSession },
    { authenticate, virtualAuthenticator },
    { localOperationId },
  ] = await Promise.all([
    import('pg'),
    import('@playwright/test'),
    import('../../../apps/admin-web/app/api/v1/ui/local-runtime.ts'),
    import('./participant-workbench-browser.mjs'),
    import('../../../services/identity-service/src/domain/local-operation-id.ts'),
  ]);
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  const client = await pool.connect();
  let browser;
  let factTrust;
  let factScenario;
  let committed = false;
  const createdKeyPaths = [];
  async function bootstrapContextEntryAuthority() {
    for (const actor of Object.values(actors)) {
      validateContextEntryActor(actor);
      const entryEnvelope = entryAuthorityId(actor.envelopeId);
      const entryAssignment = entryAuthorityId(actor.assignmentId);
      const actions = isolatedActors?.entryActions ?? [
        'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        'ACT-IDENTITY_CREATE_SESSION-V1',
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
      ];
      const entryDomains = isolatedActors?.entryPrivacyDomains ?? [
        notificationMode ? notificationEntryPrivacy : entryPrivacy,
      ];
      let entryRole;
      if (isolatedActors || notificationMode) {
        if (isolatedActors) assert.deepEqual(actions, isolatedActors.entryActions);
        entryRole = localOperationId();
        await client.query(
          `insert into control.authority_role
        (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
        values($1::uuid,$2::uuid,'urn:openpc:role:'||$1::text,'Local work-item session entry',$3::text[],'BOOTSTRAP',$4::uuid)`,
          [entryRole, participantId, actions, actor.principalId],
        );
      }
      if (rpcEvidence || rpcEntry) {
        const covered = await client.query(
          `select 1 from control.assignment a join control.authority_envelope e using(participant_id,authority_envelope_id)
         where a.participant_id=$1 and a.assignment_id=$2 and a.principal_id=$3
          and a.state='ACTIVE' and e.state='ACTIVE'
          and '018f0000-0000-7000-8000-000000000201'=any(a.privacy_domain_ids)
          and '018f0000-0000-7000-8000-000000000201'=any(e.privacy_domain_ids)
          and $4::text[]<@a.action_intent_ids and $4::text[]<@e.action_intent_ids`,
          [participantId, actor.assignmentId, actor.principalId, actions],
        );
        // The primary grant can already own root-context entry. A second matching
        // grant makes Identity's exact-cardinality authorization fail closed.
        if (covered.rowCount === 1) {
          const duplicate = await client.query(
            'select 1 from control.assignment where participant_id=$1 and assignment_id=$2',
            [participantId, entryAssignment],
          );
          assert.equal(
            duplicate.rowCount,
            0,
            'RPC initial trust has duplicate context-entry authority',
          );
          continue;
        }
      }
      if (rpcEntry) {
        const existing = await client.query(
          `select a.principal_id,a.privacy_domain_ids,a.action_intent_ids,
         a.maker_checker_required,a.step_up_required,a.state,
         e.privacy_domain_ids envelope_privacy,e.action_intent_ids envelope_actions,
         e.maker_checker_required envelope_approval,e.step_up_required envelope_step_up,e.state envelope_state
         from control.assignment a join control.authority_envelope e using(participant_id,authority_envelope_id)
         where a.participant_id=$1 and a.assignment_id=$2 and e.authority_envelope_id=$3`,
          [participantId, entryAssignment, entryEnvelope],
        );
        if (existing.rowCount) {
          assert.deepEqual(existing.rows, [
            {
              principal_id: actor.principalId,
              privacy_domain_ids: ['018f0000-0000-7000-8000-000000000201'],
              action_intent_ids: actions,
              maker_checker_required: false,
              step_up_required: false,
              state: 'ACTIVE',
              envelope_privacy: ['018f0000-0000-7000-8000-000000000201'],
              envelope_actions: actions,
              envelope_approval: false,
              envelope_step_up: false,
              envelope_state: 'ACTIVE',
            },
          ]);
          continue;
        }
      }
      await client.query(
        `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
      authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
      risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
      select $1::text::uuid,participant_id,principal_id,maker_principal_id,checker_principal_id,1,1,'ACTIVE',clock_timestamp()-interval '1 hour',
      semantic_cbor,sha256(convert_to($1::text,'UTF8')),cose_sign1,$4::text[],
      $3::text[],resource_ids,case when $5::boolean then array['STANDARD','HIGH'] else risk_classes end,false,false,0 from control.authority_envelope where authority_envelope_id=$2`,
        [
          entryEnvelope,
          actor.envelopeId,
          actions,
          entryDomains,
          !!isolatedActors || notificationMode,
        ],
      );
      await client.query(
        `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,
      valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id)
      select $1,participant_id,principal_id,$2,1,scope_digest,valid_during,'ACTIVE',principal_id,$5::text[],
      $4::text[],resource_ids,case when $7::boolean then array['STANDARD','HIGH'] else risk_classes end,false,false,0,
      coalesce('urn:openpc:role:'||$6::text,role_id) from control.assignment where assignment_id=$3`,
        [
          entryAssignment,
          entryEnvelope,
          actor.assignmentId,
          actions,
          entryDomains,
          entryRole ?? null,
          !!isolatedActors || notificationMode,
        ],
      );
    }
  }
  async function bootstrapRuntimeSourceTrust() {
    assert.ok(selectedPrivacy);
    assert.notEqual(selectedPrivacy, '018f0000-0000-7000-8000-000000000201');
    assert.equal(actors.maker.principalId, '018f0000-0000-7000-8000-000000008141');
    assert.equal(actors.checker.principalId, '018f0000-0000-7000-8000-000000008142');
    const active = await client.query(
      'select 1 from control.policy_generation where participant_id=$1 and privacy_domain_id=$2 limit 1',
      [participantId, selectedPrivacy],
    );
    assert.equal(
      active.rowCount,
      0,
      'Initial source trust is only for a context with no policy generations',
    );
    const id = '018f0000-0000-7000-8000-000000008381';
    // Initial grantability only. The independently approved public assignment
    // narrows this envelope to the actual source and workload after registration.
    await client.query(
      `insert into control.authority_envelope(
    authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
    authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,semantic_digest,cose_sign1,
    privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
    select $1::uuid,participant_id,$2::uuid,$2::uuid,$3::uuid,authority_epoch,delegation_epoch,'ACTIVE',clock_timestamp(),null,
    semantic_cbor,sha256(convert_to($1::text,'UTF8')),cose_sign1,array[$4::text],array['ACT-RUNTIME_READ_RPC-V1'],
    array['*'],array['LOW'],false,false,0 from control.authority_envelope
    where authority_envelope_id='018f0000-0000-7000-8000-000000000125' and participant_id=$5::uuid
    on conflict(authority_envelope_id) do nothing`,
      [id, actors.maker.principalId, actors.checker.principalId, selectedPrivacy, participantId],
    );
    const row = (
      await client.query(
        `select principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
    maker_checker_required,step_up_required,onward_delegation_depth,state from control.authority_envelope
    where authority_envelope_id=$1 and participant_id=$2`,
        [id, participantId],
      )
    ).rows;
    assert.deepEqual(row, [
      {
        principal_id: actors.maker.principalId,
        privacy_domain_ids: [selectedPrivacy],
        action_intent_ids: ['ACT-RUNTIME_READ_RPC-V1'],
        resource_ids: ['*'],
        risk_classes: ['LOW'],
        maker_checker_required: false,
        step_up_required: false,
        onward_delegation_depth: 0,
        state: 'ACTIVE',
      },
    ]);
    actors.maker.sourceEnvelopeId = id;
  }

  async function bootstrapRuntimeReadTrust(factAdmission = false) {
    assert.ok(selectedPrivacy);
    assert.notEqual(selectedPrivacy, '018f0000-0000-7000-8000-000000000201');
    assert.equal(actors.maker.principalId, '018f0000-0000-7000-8000-000000008141');
    assert.equal(actors.checker.principalId, '018f0000-0000-7000-8000-000000008142');
    for (const actor of Object.values(actors)) {
      const authority = await client.query(
        `select privacy_domain_ids from control.assignment where participant_id=$1 and principal_id=$2
       and 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1'=any(action_intent_ids) and state='ACTIVE'`,
        [participantId, actor.principalId],
      );
      assert.deepEqual(authority.rows, [{ privacy_domain_ids: [selectedPrivacy] }]);
    }
    const id = factAdmission ? factScenario.envelopeId : '018f0000-0000-7000-8000-000000008382';
    const actionIds = factAdmission ? ['ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1'] : [];
    const capabilities = factAdmission ? [] : ['CALL_RESULT_DISCLOSURE'];
    const risks = [factAdmission ? 'STANDARD' : 'LOW'];
    const existing = await client.query(
      'select 1 from control.authority_envelope where authority_envelope_id=$1',
      [id],
    );
    if (existing.rowCount === 0) {
      const discovery = JSON.parse(
        await readFile(join(evidenceRoot, 'discovery-credential-input.json'), 'utf8'),
      );
      assert.equal(discovery.privacyDomainId, selectedPrivacy);
      const grants = await client.query(
        `select 1 from control.assignment where participant_id=$1 and $2=any(privacy_domain_ids)
       and (not $6::boolean or principal_id=$3)
       and (action_intent_ids && $4::text[] or runtime_capability_ids && $5::text[])
       and (not $6::boolean or resource_ids && $7::text[]) limit 1`,
        [
          participantId,
          selectedPrivacy,
          discovery.principalId,
          actionIds,
          capabilities,
          factAdmission,
          factAdmission ? [factTrust.resourceId, factTrust.resourceId.slice(-36), '*'] : [],
        ],
      );
      assert.equal(grants.rowCount, 0, 'Initial trust cannot replace prior workload authority');
      // Only initial grantability. The source policy/grant remains immutable and
      // cannot authorize invocation or Fact admission. A public, independently
      // approved assignment must bind the actual workload and resource.
      await client.query(
        `insert into control.authority_envelope(
       authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
       authority_epoch,delegation_epoch,state,valid_from,valid_until,semantic_cbor,semantic_digest,cose_sign1,
       privacy_domain_ids,action_intent_ids,runtime_capability_ids,resource_ids,risk_classes,
       maker_checker_required,step_up_required,onward_delegation_depth,platform_context_id,platform_authority_epoch)
       select $1::uuid,participant_id,$2::uuid,$2::uuid,$3::uuid,authority_epoch,delegation_epoch,'ACTIVE',
       coalesce($11::timestamptz,clock_timestamp()),$12::timestamptz,semantic_cbor,sha256(convert_to($1::text,'UTF8')),cose_sign1,
       array[$4::text],$6::text[],$7::text[],$13::text[],$8::text[],false,false,0,
       coalesce($10::uuid,platform_context_id),case when $10::uuid is null then platform_authority_epoch else 1 end
       from control.authority_envelope where authority_envelope_id=$9::uuid
       and participant_id=$5::uuid`,
        [
          id,
          actors.maker.principalId,
          actors.checker.principalId,
          selectedPrivacy,
          participantId,
          actionIds,
          capabilities,
          risks,
          factAdmission
            ? '018f0000-0000-7000-8000-000000000136'
            : '018f0000-0000-7000-8000-000000000123',
          factAdmission ? factTrust.platformContextId : null,
          factAdmission ? factTrust.validFrom : null,
          factAdmission ? factTrust.validUntil : null,
          factAdmission ? [factTrust.resourceId] : ['*'],
        ],
      );
    }
    const row = await client.query(
      `select principal_id,privacy_domain_ids,action_intent_ids,runtime_capability_ids,resource_ids,risk_classes,
     maker_checker_required,step_up_required,onward_delegation_depth,state,
     platform_context_id,platform_authority_epoch::text
     from control.authority_envelope where authority_envelope_id=$1 and participant_id=$2`,
      [id, participantId],
    );
    assert.deepEqual(row.rows, [
      {
        principal_id: actors.maker.principalId,
        privacy_domain_ids: [selectedPrivacy],
        action_intent_ids: actionIds,
        runtime_capability_ids: capabilities,
        resource_ids: factAdmission ? [factTrust.resourceId] : ['*'],
        risk_classes: risks,
        maker_checker_required: false,
        step_up_required: false,
        onward_delegation_depth: 0,
        state: 'ACTIVE',
        platform_context_id: factAdmission ? factTrust.platformContextId : null,
        platform_authority_epoch: factAdmission ? '1' : null,
      },
    ]);
    if (factAdmission) {
      const times = (
        await client.query(
          'select valid_from,valid_until from control.authority_envelope where authority_envelope_id=$1',
          [id],
        )
      ).rows[0];
      assert.equal(times.valid_from.toISOString(), factTrust.validFrom);
      assert.equal(times.valid_until.toISOString(), factTrust.validUntil);
      const { readCurrentPlatformScope } =
        await import('../../../services/identity-service/src/db/platform-envelope-scope.ts');
      const { factInitialScope } = await import('./runtime-fact-initial-trust.mjs');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-PARTICIPANT_CREATE_MEMBER-V1',false)",
        [participantId, selectedPrivacy],
      );
      const current = await readCurrentPlatformScope(client, factTrust.platformContextId, '1');
      assert.equal(current.platformAuthorityDigest, factTrust.platformAuthorityDigest);
      assert.deepEqual(
        current.grantable,
        factInitialScope(Date.parse(factTrust.validFrom), factTrust.resourceId),
      );
      const generation = Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2);
      const retained = actors.maker.factPlatformTrustByGeneration ?? {};
      if (actors.maker.factPlatformTrust) {
        assert.equal(
          actors.maker.factPlatformTrust.platformContextId,
          '018f0000-0000-7000-8000-000000008384',
        );
        retained[2] ??= actors.maker.factPlatformTrust;
      }
      if (retained[generation]) assert.deepEqual(retained[generation], factTrust);
      else retained[generation] = factTrust;
      actors.maker.factPlatformTrustByGeneration = retained;
      if (generation === 2) actors.maker.factPlatformTrust = factTrust;
    }
    if (!factAdmission) actors.maker.readEnvelopeId = id;
    else if (Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2) === 2)
      actors.maker.factEnvelopeId = id;
  }

  async function grantRuntimeAuthority() {
    // Separate initial grantability. The workload receives no assignment or
    // delegation here; those transitions use the public Participant owner.
    const publication = JSON.parse(
      await readFile(join(evidenceRoot, 'configuration-deployment-policy-resource.json'), 'utf8'),
    );
    assert.equal(publication.definition.requiredRoles.length, 1);
    const role = publication.definition.requiredRoles[0];
    const existingRole = await client.query(
      'select authority_role_id from control.authority_role where participant_id=$1 and role_id=$2',
      [participantId, role],
    );
    assert.equal(existingRole.rowCount, 1);
    const envelopeId = localOperationId(),
      assignmentId = localOperationId();
    actors.maker.runtimeAssignmentId = assignmentId;
    await client.query(
      `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,
    authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,
    maker_checker_required,step_up_required,onward_delegation_depth,runtime_capability_ids)
    values($1,$2,$3,$3,1,1,'ACTIVE',clock_timestamp()-interval '1 hour',$4,$5,$4,ARRAY['018f0000-0000-7000-8000-000000000201'],ARRAY[]::text[],ARRAY['*'],ARRAY['HIGH'],false,false,1,
      ARRAY['SIGNED_TRANSACTION_SUBMISSION','OPERATION_STATUS_DISCLOSURE'])`,
      [
        envelopeId,
        participantId,
        actors.maker.principalId,
        Buffer.from([0x80]),
        createHash('sha256').update(envelopeId).digest(),
      ],
    );
    await client.query(
      `insert into control.assignment(assignment_id,participant_id,principal_id,role_id,authority_envelope_id,delegation_epoch,scope_digest,
    privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,valid_during,state,created_by_principal_id,runtime_capability_ids)
    values($1,$2,$3,$4,$5,1,$6,ARRAY['018f0000-0000-7000-8000-000000000201'],ARRAY[]::text[],ARRAY['*'],ARRAY['HIGH'],false,false,1,
      tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),'ACTIVE',$3,ARRAY['SIGNED_TRANSACTION_SUBMISSION','OPERATION_STATUS_DISCLOSURE'])`,
      [
        assignmentId,
        participantId,
        actors.maker.principalId,
        role,
        envelopeId,
        createHash('sha256').update(assignmentId).digest(),
      ],
    );
  }
  try {
    if (mode === 'bootstrap-evidence-deletion-entry' || runtimeEntry || rpcEntry) {
      actors = JSON.parse(
        await readFile(join(evidenceRoot, 'deployment-intent-actors.json'), 'utf8'),
      );
      await client.query('BEGIN');
      if (runtimeEntry || rpcEntry)
        for (const actor of Object.values(actors))
          assert.equal(actor.privacyDomainId, selectedPrivacy);
      await bootstrapContextEntryAuthority();
      await client.query('COMMIT');
      committed = true;
    } else if (
      [
        'bootstrap-runtime-source-trust',
        'bootstrap-runtime-read-trust',
        'bootstrap-runtime-fact-trust',
      ].includes(mode)
    ) {
      actors = JSON.parse(
        await readFile(join(evidenceRoot, 'deployment-intent-actors.json'), 'utf8'),
      );
      if (mode === 'bootstrap-runtime-fact-trust') {
        const { installRuntimeFactInitialTrust, factTrustScenario } =
          await import('./runtime-fact-initial-trust.mjs');
        const generation = Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2);
        assert.ok(Number.isSafeInteger(generation) && generation >= 2);
        factScenario = factTrustScenario(generation);
        const suffix = generation === 2 ? '' : `-${generation}`;
        const { candidateId } = JSON.parse(
          await readFile(join(evidenceRoot, `rpc-acquisition${suffix}/candidate.json`), 'utf8'),
        );
        factTrust = await installRuntimeFactInitialTrust(
          client,
          evidenceRoot,
          participantId,
          selectedPrivacy,
          `urn:openpc:resource:${candidateId}`,
          generation,
        );
      }
      await client.query('BEGIN');
      if (mode === 'bootstrap-runtime-source-trust') await bootstrapRuntimeSourceTrust();
      else await bootstrapRuntimeReadTrust(mode === 'bootstrap-runtime-fact-trust');
      await client.query('COMMIT');
      committed = true;
      await writeFile(join(evidenceRoot, 'deployment-intent-actors.json'), JSON.stringify(actors), {
        mode: 0o600,
      });
    } else if (mode === 'authenticate' || mode === 'grant-runtime') {
      actors = JSON.parse(
        await readFile(join(evidenceRoot, 'deployment-intent-actors.json'), 'utf8'),
      );
      if (mode === 'grant-runtime') {
        assert.equal(actors.maker.runtimeAssignmentId, undefined);
        await client.query('BEGIN');
        await grantRuntimeAuthority();
        await client.query('COMMIT');
        committed = true;
        await writeFile(
          join(evidenceRoot, 'deployment-intent-actors.json'),
          JSON.stringify(actors),
          {
            mode: 0o600,
          },
        );
      }
    } else {
      await client.query('BEGIN');
      if (notificationMode) {
        // Initial alternate context only. Endpoint operations and sessions must
        // still be created through their supported public owners.
        const created = await client.query(
          `insert into control.privacy_domain
           (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
           select $1,$2,'Local notification alternate entry',placement_profile,residency_profile,'ACTIVE'
           from control.privacy_domain where participant_id=$2
           and privacy_domain_id='018f0000-0000-7000-8000-000000000201' and state='ACTIVE'`,
          [notificationEntryPrivacy, participantId],
        );
        assert.equal(created.rowCount, 1, 'Notification entry requires its active initial context');
      }
      if (isolatedActors) {
        const catalogue = await client.query(
          `select action_intent_id,resource_type,operation_class,risk_class,
        maker_checker_required,step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class
        from control.action_intent where action_intent_id=any($1::text[]) for share`,
          [[...isolatedActors.actions, ...isolatedActors.entryActions]],
        );
        if (correlationActors) {
          assert.deepEqual(
            catalogue.rows.map((row) => row.action_intent_id).sort(),
            [...isolatedActors.actions, ...isolatedActors.entryActions].sort(),
          );
          for (const row of catalogue.rows.filter((row) =>
            isolatedActors.actions.includes(row.action_intent_id),
          )) {
            assert.equal(row.operation_class, 'READ');
            assert.equal(row.maker_checker_required, false);
            assert.equal(row.step_up_required, false);
          }
        } else validateWorkItemActorCatalogue(catalogue.rows);
        if (isolatedActors.bootstrapEntryPrivacyDomain) {
          // Initial context trust only, before either actor exists. No operation,
          // Work Item, approval, session or other journey effect is established.
          const created = await client.query(
            `insert into control.privacy_domain
            (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
            select $1,$2,'Local work-item alternate entry',placement_profile,residency_profile,'ACTIVE'
            from control.privacy_domain where participant_id=$2 and privacy_domain_id=$3 and state='ACTIVE'`,
            [isolatedActors.bootstrapEntryPrivacyDomain, participantId, selectedPrivacy],
          );
          assert.equal(
            created.rowCount,
            1,
            'Work-item initial entry context needs its active parent',
          );
        }
        const domains = await client.query(
          `select privacy_domain_id::text id from control.privacy_domain
        where participant_id=$1 and privacy_domain_id=any($2::uuid[]) and state='ACTIVE' for share`,
          [participantId, isolatedActors.entryPrivacyDomains],
        );
        assert.deepEqual(
          domains.rows.map((row) => row.id).sort(),
          [...isolatedActors.entryPrivacyDomains].sort(),
          'Work-item actors require existing selected and entry privacy domains',
        );
        const templates = await client.query(
          `select 1 from control.authority_envelope e join control.assignment a
        using(participant_id,authority_envelope_id) where e.participant_id=$1
        and e.authority_envelope_id='018f0000-0000-7000-8000-000000000121'
        and a.assignment_id='018f0000-0000-7000-8000-000000000122' and e.state='ACTIVE' and a.state='ACTIVE' for share`,
          [participantId],
        );
        assert.equal(
          templates.rowCount,
          1,
          'Initial trust template must belong to the selected participant',
        );
      } else if (deletionBatch) {
        const existing = await client.query(
          `select 1 from control.privacy_domain where participant_id=$1 and privacy_domain_id=$2 and state='ACTIVE'`,
          [participantId, isolatedPrivacy[0]],
        );
        assert.equal(
          existing.rowCount,
          1,
          'Batch actors require the existing deletion privacy domain',
        );
      } else if (retentionSearch) {
        const foreign = await client.query(
          `select 1 from control.privacy_domain where participant_id=$1 and privacy_domain_id=$2 and state='ACTIVE'`,
          [participantId, foreignPrivacy],
        );
        assert.equal(foreign.rowCount, 1, 'Retention search requires an existing foreign context');
        const created = await client.query(
          `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
           select $1,$2,'Isolated retention-policy search',placement_profile,residency_profile,'ACTIVE'
           from control.privacy_domain where participant_id=$2
           and privacy_domain_id='018f0000-0000-7000-8000-000000000201' and state='ACTIVE'`,
          [selectedPrivacy, participantId],
        );
        assert.equal(
          created.rowCount,
          1,
          'Retention search requires the initial placement template',
        );
      } else if (rpcEvidence || sourceHolds || notificationMode) {
        for (const privacy of isolatedPrivacy) {
          const existing = await client.query(
            `select 1 from control.privacy_domain where participant_id=$1 and privacy_domain_id=$2 and state='ACTIVE'`,
            [participantId, privacy],
          );
          assert.equal(
            existing.rowCount,
            1,
            'RPC evidence actors require existing exact privacy contexts',
          );
        }
      } else if (rejectionDeletion) {
        await client.query(
          `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
         select $1,$2,'Rejection deletion isolation check',placement_profile,residency_profile,'ACTIVE' from control.privacy_domain
         where participant_id=$2 and privacy_domain_id='018f0000-0000-7000-8000-000000000201'`,
          [isolatedPrivacy[1], participantId],
        );
      } else if (runtimeBootstrap) {
        // The actual host source installer owns this fresh root context. Never
        // attach runtime actors to the legacy 201 root or overwrite its pins.
        await verifyInstalledRuntimeSource(client, secretRoot, participantId, isolatedPrivacy[0]);
      } else if (isolatedPrivacy) {
        await client.query(
          `insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
         select $1,$2,$3,placement_profile,residency_profile,'ACTIVE' from control.privacy_domain
         where participant_id=$2 and privacy_domain_id='018f0000-0000-7000-8000-000000000201'`,
          [
            isolatedPrivacy[0],
            participantId,
            runtimeBootstrap ? 'Isolated runtime bootstrap' : 'Isolated local evidence deletion',
          ],
        );
      }
      for (const [name, actor] of Object.entries(actors)) {
        await client.query(
          `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'USER',$3,'ACTIVE',1)`,
          [actor.principalId, participantId, `${actorLabel} ${name}`],
        );
        await client.query('insert into control.identity_subject(identity_subject_id) values($1)', [
          actor.principalId,
        ]);
        await client.query(
          'insert into control.participant_membership(membership_id,participant_id,identity_subject_id) values($1,$2,$1)',
          [actor.principalId, participantId],
        );
      }
      for (const [name, actor] of Object.entries(actors)) {
        const keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' });
        actor.privateKeyPath =
          isolatedActors?.keyPaths[name] ?? join(secretRoot, `${keyPrefix}-${name}-webauthn.pk8`);
        await writeFile(
          actor.privateKeyPath,
          keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
          { flag: 'wx', mode: 0o400 },
        );
        createdKeyPaths.push(actor.privateKeyPath);
        await client.query(
          `insert into control.authority_envelope(authority_envelope_id,participant_id,principal_id,maker_principal_id,checker_principal_id,
      authority_epoch,delegation_epoch,state,valid_from,semantic_cbor,semantic_digest,cose_sign1,privacy_domain_ids,action_intent_ids,resource_ids,
      risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
      select $1::text::uuid,participant_id,$2::uuid,$3::uuid,$4::uuid,1,1,'ACTIVE',clock_timestamp()-interval '1 hour',semantic_cbor,sha256(convert_to($1::text,'UTF8')),cose_sign1,
      coalesce($6::text[],privacy_domain_ids),case when $7::boolean then $5::text[] else array(select distinct value from unnest(action_intent_ids||$5::text[]) value) end,
      resource_ids,case when $7::boolean then array['LOW','STANDARD'] else risk_classes end,not $7::boolean,not $7::boolean,0 from control.authority_envelope
      where authority_envelope_id='018f0000-0000-7000-8000-000000000121'`,
          [
            actor.envelopeId,
            actor.principalId,
            actors.maker.principalId,
            actors.checker.principalId,
            correlationActors?.actorActions[name] ?? evidenceActions,
            isolatedPrivacy,
            !!isolatedActors,
          ],
        );
        const evidenceRole =
          evidenceMode || runtimeBootstrap || notificationMode || isolatedActors
            ? localOperationId()
            : null;
        actor.privacyDomainId =
          selectedPrivacy ?? isolatedPrivacy?.[0] ?? '018f0000-0000-7000-8000-000000000201';
        if (evidenceRole)
          await client.query(
            `insert into control.authority_role
        (authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
        select $1::uuid,participant_id,'urn:openpc:role:'||$1::text,$4::text,
          action_intent_ids,'BOOTSTRAP',$2 from control.authority_envelope where authority_envelope_id=$3`,
            [
              evidenceRole,
              actor.principalId,
              actor.envelopeId,
              correlationActors
                ? 'Local evidence correlation reader'
                : isolatedActors
                  ? 'Local work-item operator'
                  : 'Local evidence custodian',
            ],
          );
        await client.query(
          `insert into control.assignment(assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,
      valid_during,state,created_by_principal_id,privacy_domain_ids,action_intent_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth,role_id)
      select $1,participant_id,$2,$3,1,scope_digest,tstzrange(clock_timestamp()-interval '1 hour',null,'[)'),'ACTIVE',$2,coalesce($6::text[],privacy_domain_ids),
      case when $7::boolean then $4::text[] else array(select distinct value from unnest(action_intent_ids||$4::text[]) value) end,
      resource_ids,case when $7::boolean then array['LOW','STANDARD'] else risk_classes end,not $7::boolean,not $7::boolean,0,
      coalesce('urn:openpc:role:'||$5::text,role_id) from control.assignment where assignment_id='018f0000-0000-7000-8000-000000000122'`,
          [
            actor.assignmentId,
            actor.principalId,
            actor.envelopeId,
            correlationActors?.actorActions[name] ?? evidenceActions,
            evidenceRole,
            isolatedPrivacy,
            !!isolatedActors,
          ],
        );
        await client.query(
          `insert into control.credential(credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,state,credential_epoch${isolatedActors ? '' : ',authenticator_sign_count'},valid_from)
      values($1,$2,$3,'WEBAUTHN',$4,$5,'ACTIVE',1${isolatedActors ? '' : ',0'},clock_timestamp()-interval '1 hour')`,
          [
            actor.credentialId,
            participantId,
            actor.principalId,
            createHash('sha256').update(publicKey).digest(),
            publicKey,
          ],
        );
        await client.query(
          `insert into control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from)
      values($1,$2::text::uuid,'OIDC_SUBJECT','http://oidc-emulator:3006',$2::text,'openpc-local-workbench','ACTIVE',1,clock_timestamp()-interval '1 hour')`,
          [participantId, actor.principalId],
        );
      }
      if (deletionMode || runtimeBootstrap || rpcEvidence || isolatedActors || notificationMode)
        await bootstrapContextEntryAuthority();
      if (runtimeBootstrap) await bootstrapRuntimeSourceTrust();
      if (
        ![
          'bootstrap-work-items',
          'bootstrap-evidence-correlation',
          'bootstrap-review',
          'bootstrap-runtime-context',
          'bootstrap-evidence-protected',
          'bootstrap-evidence-raw-deletion',
          'bootstrap-evidence-remote-protected',
          'bootstrap-evidence-projection-deletion',
          'bootstrap-evidence-retention-search',
          'bootstrap-evidence-store-retirement',
          'bootstrap-evidence',
          'bootstrap-evidence-rpc',
          'bootstrap-evidence-holds',
          'bootstrap-evidence-hold-selectors',
          'bootstrap-evidence-source-holds',
          'bootstrap-retention',
          'bootstrap-evidence-deletion',
          'bootstrap-evidence-deletion-batch',
          'bootstrap-evidence-rejection-deletion',
        ].includes(mode) &&
        (process.env.OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY === '1' ||
          process.env.OPENPC_LOCAL_RUNTIME_CIGL_ONLY === '1')
      )
        await grantRuntimeAuthority();
      await client.query('COMMIT');
      committed = true;
      await writeFile(join(evidenceRoot, 'deployment-intent-actors.json'), JSON.stringify(actors), {
        mode: 0o600,
        ...(isolatedActors ? { flag: 'wx' } : {}),
      });
    }
    if (!initialOnly) {
      browser = await chromium.launch({ headless: true });
      for (const actor of Object.values(actors)) {
        const context = await browser.newContext();
        const page = await context.newPage();
        const current = await client.query(
          "select public_key_digest as digest,authenticator_sign_count::text as count from control.credential where credential_id=$1 and principal_id=$2 and state='ACTIVE'",
          [actor.credentialId, actor.principalId],
        );
        const key = createPublicKey({
          key: await readFile(actor.privateKeyPath),
          format: 'der',
          type: 'pkcs8',
        }).export({ format: 'der', type: 'spki' });
        assert.equal(current.rowCount, 1);
        assert.deepEqual(createHash('sha256').update(key).digest(), current.rows[0].digest);
        await virtualAuthenticator(
          context,
          page,
          actor.credentialId,
          actor.privateKeyPath,
          current.rows[0].count,
        );
        // The external IdP supplies the account identity; PKCE, state, nonce,
        // signature, issuer, audience and the real internal mapping remain checked.
        await page.route('http://127.0.0.1:53006/authorize?*', async (route) => {
          const url = new URL(route.request().url());
          url.searchParams.set('openpc_test_subject', actor.principalId);
          url.searchParams.set('openpc_test_principal_id', actor.principalId);
          await route.continue({ url: url.href });
        });
        await authenticate(page, 'viewer', selectedPrivacy ?? actor.privacyDomainId, {
          expectedPrincipalId: actor.principalId,
        });
        const session = await page.evaluate(async () =>
          (await fetch('/api/v1/ui/local-session')).json(),
        );
        assert.equal(session.principalId, actor.principalId);
        const cookie = (await context.cookies()).find(
          (value) => value.name === 'openpc_local_runtime_session',
        );
        const cookieKey = Buffer.from(
          (await readFile(join(secretRoot, 'bff_cookie_key.txt'), 'utf8')).trim(),
        );
        actor.sessionToken = decodeBffSession(cookie?.value, cookieKey)?.sessionToken;
        assert.ok(actor.sessionToken);
        const count = await client.query(
          'select authenticator_sign_count::text as count from control.credential where credential_id=$1',
          [actor.credentialId],
        );
        actor.nextSignCount = String(Number(count.rows[0].count) + 1);
        await context.close();
      }
      await writeFile(join(evidenceRoot, 'deployment-intent-actors.json'), JSON.stringify(actors), {
        mode: 0o600,
      });
    }
    process.stdout.write(
      initialOnly
        ? 'OPENPC_DEPLOYMENT_ACTORS|INITIAL_TRUST_ONLY\n'
        : 'OPENPC_DEPLOYMENT_ACTORS|PASS|isolated-users|oidc-pkce|webauthn|participant-context\n',
    );
  } finally {
    await browser?.close();
    if (!committed && mode !== 'authenticate')
      await Promise.all(createdKeyPaths.map((path) => unlink(path).catch(() => {})));
    await client.query('ROLLBACK').catch(() => {});
    client.release();
    await pool.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  await main();
