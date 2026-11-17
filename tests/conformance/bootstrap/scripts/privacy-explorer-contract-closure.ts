import { createHash } from 'node:crypto';

export type HashRow = Readonly<{ path: string; sha256: string }>;

export const byteCompare = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;
export const sha256 = (bytes: string | Uint8Array) =>
  createHash('sha256').update(bytes).digest('hex');

export const existingTypeScriptJsonSchemaOutputs = [
  'generated/typescript/json-schema/action-intent-registry.d.ts',
  'generated/typescript/json-schema/adapter-interface.d.ts',
  'generated/typescript/json-schema/authority-context.d.ts',
  'generated/typescript/json-schema/control-api.d.ts',
  'generated/typescript/json-schema/error-registry.d.ts',
  'generated/typescript/json-schema/event-envelope.d.ts',
  'generated/typescript/json-schema/event-payloads.d.ts',
  'generated/typescript/json-schema/jsonrpc-runtime.d.ts',
  'generated/typescript/json-schema/problem.d.ts',
  'generated/typescript/json-schema/shared-primitives.d.ts',
  'generated/typescript/json-schema/sse-subscription.d.ts',
  'generated/typescript/json-schema/ui-bff.d.ts',
] as const;

// Live signing lifecycle contracts extend these public outputs; unrelated predecessor outputs remain sealed.
export const signingTypeScriptOutputs = [
  'generated/typescript/json-schema/signing-key-rotation.d.ts',
] as const;
export const signingChangedContractOutputs: readonly string[] = [
  ...signingTypeScriptOutputs,
  'generated/typescript/json-schema/control-api.d.ts',
  'generated/typescript/json-schema/event-payloads.d.ts',
  'generated/typescript/openapi/index.ts',
  'generated/typescript/openapi/sdk.gen.ts',
  'generated/typescript/openapi/types.gen.ts',
];

export const protectedOpenApiOutputs = [
  'generated/typescript/openapi/client.gen.ts',
  'generated/typescript/openapi/client/client.gen.ts',
  'generated/typescript/openapi/client/index.ts',
  'generated/typescript/openapi/client/types.gen.ts',
  'generated/typescript/openapi/client/utils.gen.ts',
  'generated/typescript/openapi/core/auth.gen.ts',
  'generated/typescript/openapi/core/bodySerializer.gen.ts',
  'generated/typescript/openapi/core/params.gen.ts',
  'generated/typescript/openapi/core/pathSerializer.gen.ts',
  'generated/typescript/openapi/core/queryKeySerializer.gen.ts',
  'generated/typescript/openapi/core/serverSentEvents.gen.ts',
  'generated/typescript/openapi/core/types.gen.ts',
  'generated/typescript/openapi/core/utils.gen.ts',
  'generated/typescript/openapi/index.ts',
  'generated/typescript/openapi/sdk.gen.ts',
  'generated/typescript/openapi/types.gen.ts',
] as const;

export const protectedOpenApiSha256ByPath = Object.freeze({
  'generated/typescript/openapi/client.gen.ts':
    '11888b753b0176fce45a47c81753c80206c391e27f8b365023c812a76312a212',
  'generated/typescript/openapi/client/client.gen.ts':
    '426ff1c11a0dee9bac79568e2b2093ef697cf3828dfe9dba5258a31d3e38568d',
  'generated/typescript/openapi/client/index.ts':
    'acd2b749181050a8297f24ac3db4f3941ca0a66c049e5b984f29f0e98c8329f8',
  'generated/typescript/openapi/client/types.gen.ts':
    '8a353b3ee2450c26415ec2816491cf4e82262a87597180f1b97dd989c9102f96',
  'generated/typescript/openapi/client/utils.gen.ts':
    'f21c22bd8f37a0d0fa4008c4d70bb7e7a4b74afa8c5b9d05dda9b39f1c89424c',
  'generated/typescript/openapi/core/auth.gen.ts':
    '4b4aca5bd9b2c43a112bb74617295278d84f86360ada71a8db57f09cd0c254f4',
  'generated/typescript/openapi/core/bodySerializer.gen.ts':
    'c9739bff031dce1781a56ab9072791d4bd52bd0896cc989d4ad1cd03f71b282b',
  'generated/typescript/openapi/core/params.gen.ts':
    '097c75f6e269c6c8680641091832a69b38e8828e8ee8465318d32a177593330f',
  'generated/typescript/openapi/core/pathSerializer.gen.ts':
    '6e80a19627d36fd2a9e8daee113713b2e047d107d42ead9b4a9ab344690b998c',
  'generated/typescript/openapi/core/queryKeySerializer.gen.ts':
    'adc570c9357a08624cce81dc503abd8d8ff60a76d25bd4d3a4afbe349d82d1f0',
  'generated/typescript/openapi/core/serverSentEvents.gen.ts':
    '09dc8417b03b92849cc7582d2c8e5a610cc002d447a93b0cef721dcdbd09ff12',
  'generated/typescript/openapi/core/types.gen.ts':
    '11742d13e9417ed7f71e78e6062873c83340beeae766666a04a3e56726bc3567',
  'generated/typescript/openapi/core/utils.gen.ts':
    'ef50364c77d213864515776ee4abaf2f3a1a309d106c2db000e2fc4b6080e78c',
  'generated/typescript/openapi/index.ts':
    '6222a4a8efdab5065050a1c754fe11b6360563a2c994815bc0858756c47cf94c',
  'generated/typescript/openapi/sdk.gen.ts':
    'f9b397f3f19400fc52a7bcf46fff7350c05157e59d9bde933689b325b932f8a3',
  'generated/typescript/openapi/types.gen.ts':
    '1bd0c1d8f0d0bcba1d480808b9612302bce475317f22854c3d064a5591f06b0f',
});
export const expectedProtectedOpenApiDigest =
  '66e493710b7764d18a35de13c651c0b88607139f6d5da121fc15c38be09bc987';

export const privacyTypeScriptOutputs = [
  'generated/typescript/json-schema/privacy-explorer.d.ts',
  'generated/typescript/json-schema/privacy-explorer.validator.mjs',
  'generated/typescript/privacy-explorer/execution-registry.ts',
] as const;
export const privacyRustOutputs = [
  'generated/rust/json-schema/openpc_contracts.rs',
  'generated/rust/json-schema/mod.rs',
  'generated/rust/privacy-explorer/execution_registry.rs',
  'generated/rust/privacy-explorer/mod.rs',
] as const;
export const privacyApiClientOutputs = [
  'packages/api-client/generated/privacy-explorer/client.gen.ts',
  'packages/api-client/generated/privacy-explorer/client/client.gen.ts',
  'packages/api-client/generated/privacy-explorer/client/index.ts',
  'packages/api-client/generated/privacy-explorer/client/types.gen.ts',
  'packages/api-client/generated/privacy-explorer/client/utils.gen.ts',
  'packages/api-client/generated/privacy-explorer/core/auth.gen.ts',
  'packages/api-client/generated/privacy-explorer/core/bodySerializer.gen.ts',
  'packages/api-client/generated/privacy-explorer/core/params.gen.ts',
  'packages/api-client/generated/privacy-explorer/core/pathSerializer.gen.ts',
  'packages/api-client/generated/privacy-explorer/core/queryKeySerializer.gen.ts',
  'packages/api-client/generated/privacy-explorer/core/serverSentEvents.gen.ts',
  'packages/api-client/generated/privacy-explorer/core/types.gen.ts',
  'packages/api-client/generated/privacy-explorer/core/utils.gen.ts',
  'packages/api-client/generated/privacy-explorer/index.ts',
  'packages/api-client/generated/privacy-explorer/sdk.gen.ts',
  'packages/api-client/generated/privacy-explorer/types.gen.ts',
] as const;
export const rustStagedOutputs = [
  'generated/rust/proto/mod.rs',
  'generated/rust/proto/openpc.common.v1.rs',
  'generated/rust/proto/openpc.control.v1.rs',
  'generated/rust/proto/openpc.evidence.v1.rs',
  'generated/rust/proto/openpc.facts.v1.rs',
  'generated/rust/proto/openpc.fleet.v1.rs',
  'generated/rust/proto/openpc.runtime.v1.rs',
  ...privacyRustOutputs,
] as const;

export const generatorDescriptors = Object.freeze({
  json2ts: {
    name: 'json-schema-to-typescript',
    version: '15.0.4',
    argv: [
      'pnpm',
      'exec',
      'json2ts',
      '--input',
      '<schema>',
      '--output',
      '<external-staging-output>',
      '--cwd',
      'schemas/json',
      '--unknownAny',
    ],
    optionalArgv: {
      'event-payloads.schema.json': ['--unreachableDefinitions'],
      'signing-key-rotation.schema.json': ['--unreachableDefinitions'],
    },
  },
  openapiControl: {
    name: '@hey-api/openapi-ts',
    version: '0.99.0',
    argv: [
      'pnpm',
      'exec',
      'openapi-ts',
      '--input',
      'schemas/openapi/openpc-control-api.openapi.yaml',
      '--output',
      '<external-staging-output>',
      '--client',
      '@hey-api/client-fetch',
      '--no-log-file',
      '--silent',
    ],
  },
  openapiPrivacy: {
    name: '@hey-api/openapi-ts',
    version: '0.99.0',
    argv: [
      'pnpm',
      'exec',
      'openapi-ts',
      '--input',
      'schemas/openapi/openpc-privacy-explorer.openapi.yaml',
      '--output',
      '<external-staging-output>',
      '--client',
      '@hey-api/client-fetch',
      '--no-log-file',
      '--silent',
    ],
  },
  rust: {
    name: 'pc-contracts generate-rust-contracts',
    version: 'pc-contracts 2.0.0 / typify 0.7.0',
    argv: [
      'cargo',
      'run',
      '--locked',
      '-p',
      'pc-contracts',
      '--bin',
      'generate-rust-contracts',
      '--',
      '--output-root',
      '<external-staging-root>',
    ],
  },
  contractTree: {
    name: 'I07 contract closure generator',
    version: '1.0',
    argv: [
      'node',
      'scripts/contracts/run-with-toolchain.mjs',
      'run-tsx',
      'tests/conformance/bootstrap/scripts/generate-typescript-contracts.ts',
    ],
  },
});

export const pathOrderedChecksumRows = (files: Readonly<Record<string, string>>) =>
  Object.entries(files)
    .sort(([left], [right]) => byteCompare(left, right))
    .map(([path, digest]) => `${digest}  ${path}`);
export const canonicalPathOrderedDigest = (files: Readonly<Record<string, string>>) =>
  sha256(`${pathOrderedChecksumRows(files).join('\n')}\n`);
export const assertExactSet = (
  actual: readonly string[],
  expected: readonly string[],
  label: string,
) => {
  const left = [...actual].sort(byteCompare);
  const right = [...expected].sort(byteCompare);
  if (JSON.stringify(left) !== JSON.stringify(right))
    throw new Error(`${label}: exact set mismatch`);
};
export const assertExactHashes = (
  actual: readonly HashRow[],
  expected: Readonly<Record<string, string>>,
  label: string,
) => {
  assertExactSet(
    actual.map(({ path }) => path),
    Object.keys(expected),
    label,
  );
  for (const { path, sha256: digest } of actual)
    if (expected[path] !== digest) throw new Error(`${label}: hash mismatch for ${path}`);
};
export const hashRows = (files: readonly Readonly<{ path: string; bytes: Uint8Array }>[]) =>
  files
    .map(({ path, bytes }) => ({ path, sha256: sha256(bytes) }))
    .sort((a, b) => byteCompare(a.path, b.path));
export const assertSafeRelativePath = (path: string) => {
  if (
    !path ||
    path.startsWith('/') ||
    path.includes('\\') ||
    path.split('/').some((part) => part === '' || part === '.' || part === '..')
  )
    throw new Error(`unsafe repository-relative path: ${path}`);
  return path;
};

export const expectedExecutionRegistrySha256 =
  'b3f4add1e544fce666bb69aafde8f4b36d1fd51ba6b0700537ed293386bc2d5a';
const EXPECTED_STATES = [
  'OPEN',
  'CONTEXT_BOUND',
  'PREAUTHORIZED',
  'INTENT_NARROWED',
  'REQUEST_READY',
  'READ_IN_FLIGHT_NO_RAW',
  'RESPONSE_CAPTURED_RAW_LIVE',
  'PROJECTION_VALIDATED_RAW_LIVE',
  'PROJECTION_REDACTED_RAW_LIVE',
  'OUTCOME_SELECTED_RAW_LIVE',
  'OUTCOME_READY_NO_RAW',
  'OUTCOME_READY_RAW_DISPOSED',
  'CANCEL_PENDING_NO_RAW',
  'CANCEL_PENDING_RAW_LIVE',
  'RELEASED',
  'CANCELLED_CLOSED',
  'EVIDENCE_SEALED',
] as const;
const EXPECTED_RAW_EFFECTS = new Set([
  'UNCHANGED',
  'NEVER_CREATED',
  'NEVER_CREATED_TO_LIVE',
  'LIVE',
  'LIVE_TO_DISPOSED',
  'DISPOSED',
  'REQUIRES_NEVER_CREATED_OR_DISPOSED',
]);
const EXPECTED_DELIVERY_EFFECTS = new Set(['UNCHANGED', 'SUPPRESSED', 'RELEASED']);
const EXPECTED_ADAPTER_EFFECTS = new Set([
  'NONE',
  'NOT_STARTED',
  'DISPATCH_STARTED',
  'RAW_OWNER_CAPTURED',
  'RAW_OWNER_RETAINED',
  'DISPATCH_RECONCILED',
  'RAW_OWNER_DISPOSED',
  'COMPLETION_RECORDED',
  'CANCEL_REQUESTED',
  'DELIVERY_SUPPRESSED',
  'EVIDENCE_ASSEMBLED',
]);
const RESULT_LAWS = Object.freeze({
  'RESULT-COMPLETE': ['COMPLETE', 'TRUE', 'RECORDS_ALLOWED', 'GAP_FREE'],
  'RESULT-PARTIAL': ['PARTIAL', 'PARTIAL', 'RECORDS_ALLOWED', 'PARTIAL_EXPLICIT'],
  'RESULT-UNKNOWN': ['UNKNOWN', 'UNKNOWN', 'RECORDS_EMPTY', 'COMPLETENESS_UNPROVEN'],
  'RESULT-UNAVAILABLE': ['UNAVAILABLE', 'UNAVAILABLE', 'RECORDS_EMPTY', 'SOURCE_UNAVAILABLE'],
} as const);
const DISPOSITION_KINDS = new Set([
  'COMMON_TERMINAL_DENIAL',
  'CONDITION',
  'INTERNAL',
  'NONE',
  'RESULT',
]);
const APPLICATION_EVENTS = new Set([
  'ABSENCE_WITHOUT_COMPLETE_PROOF',
  'BIND_LOCAL_CONTEXT',
  'CANCEL_AFTER_BYTES',
  'CANCEL_AFTER_DISPOSAL',
  'CANCEL_AFTER_NO_RAW_READY',
  'CANCEL_AFTER_OUTCOME_SELECTION',
  'CANCEL_AFTER_REDACTION',
  'CANCEL_AFTER_VALIDATION',
  'CANCEL_BEFORE_DISPATCH',
  'CANCEL_DURING_READ',
  'CANCEL_LATE_EVIDENCE',
  'CANCEL_LATE_RELEASED',
  'CAPTURE_BYTES',
  'CAPTURE_LATE_BYTES',
  'CLOSE_CANCELLED',
  'CONFLICTING_OBSERVATIONS',
  'CREATE_REQUEST',
  'CURSOR_PARTIAL',
  'DATA_CLASS_UNSUPPORTED',
  'DEADLINE_EXPIRED',
  'DIRECT_BROWSER_ATTEMPT',
  'DISPOSAL_UNPROVEN',
  'DISPOSE_RAW',
  'ENVELOPE_INVALID',
  'EVIDENCE_MISMATCH',
  'EVIDENCE_MISSING',
  'FIELD_UNSUPPORTED',
  'GAP_PARTIAL',
  'JSON_PARSE_FAILED',
  'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS',
  'METHOD_ABSENT',
  'NARROW_INTENT',
  'OCCURRENCE_CONFLICT',
  'ORDER_PARTIAL',
  'PARAMETER_FORBIDDEN',
  'PARAMETER_INVALID',
  'PREAUTHORIZE',
  'PRIVACY_PROJECTION_IMPOSSIBLE',
  'PRODUCT_DRIFT',
  'PROFILE_NOT_ADMITTED',
  'PROFILE_RETIRED',
  'QUERY_UNSUPPORTED',
  'RECONCILE_NO_BYTES',
  'REDACTION_IMPOSSIBLE',
  'REDACT_PROJECTION',
  'REGISTERED_SAFE_PROBLEM_RETURNED',
  'RELEASE',
  'RELEASE_DRIFT',
  'REORG_OBSERVATION',
  'REPLAY_DETECTED',
  'RESPONSE_BINDING_INVALID',
  'RESPONSE_INTEGRITY_INVALID',
  'RESPONSE_SCHEMA_INVALID',
  'SELECT_COMPLETE',
  'SELECT_PARTIAL',
  'SELECT_UNAVAILABLE',
  'SELECT_UNKNOWN',
  'SOURCE_UNAVAILABLE',
  'STALE_OBSERVATION',
  'START_READ',
  'TERMINAL_DENIAL',
  'TRUST_DRIFT',
  'VALIDATE_PROJECTION',
  'VERSION_INVALID',
]);
const APPLICATION_GUARDS = new Set([
  ...Array.from(
    { length: 37 },
    (_, index) => `CLASSIFIED_AS_CA_${String(index + 1).padStart(3, '0')}`,
  ),
  'DELIVERY_PENDING',
  'DELIVERY_SUPPRESSED',
  'DISPATCH_STARTED_NO_BYTES',
  'EXACT_REGISTERED_SAFE_PROBLEM',
  'EXACT_SOURCE_STATE',
  'IDENTITY_OCCURRENCE_DIGESTS_REVISION_AND_UNIQUENESS_MATCH',
  'IMMUTABLE_EVIDENCE_EXISTS',
  'IMMUTABLE_RELEASE_EXISTS',
  'RAW_OWNER_LIVE',
]);
const RETAINED_FACT_IDS = new Set([
  'BYTES_CAPTURED',
  'CANCELLED_AFTER_DISPATCH_NO_RAW',
  'CANCELLED_AFTER_RAW',
  'CANCELLED_BEFORE_DISPATCH',
  'CANCELLED_STATE_UNCHANGED',
  'CANCEL_PENDING',
  'COMPLETE',
  'CONTEXT_BOUND',
  'DENIED',
  'EVIDENCE_SEALED',
  'INTENT_NARROWED',
  'NO_OP_AFTER_IMMUTABLE_EVIDENCE',
  'NO_OP_AFTER_IMMUTABLE_RELEASE',
  'OUTCOME_READY',
  'PARTIAL',
  'PREAUTHORIZED',
  'READ_STARTED',
  'REDACTED',
  'RELEASED',
  'RELEASED_STATE_UNCHANGED',
  'REQUEST_READY',
  'SAFE_PROBLEM_NO_RAW',
  'SAFE_PROBLEM_RAW_RETAINED',
  'SUPPRESSED',
  'UNAVAILABLE',
  'UNKNOWN',
  'VALIDATED_NO_AUTHORITY',
]);
const NO_EFFECT_IDS = new Set([
  'NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT',
  'STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED',
]);
const MUTATED_FIELD_IDS = new Set([
  'cancellationTiming',
  'completenessProof',
  'cursorOrder',
  'deadlineAt',
  'eventId',
  'evidenceIdentity',
  'guardId',
  'immutableDeliveryState',
  'observationFreshness',
  'occurrenceId',
  'profileDigest',
  'queryDigest',
  'rawDisposalProof',
  'redactionFeasibility',
  'requestEnvelope',
  'responseDigest',
  'responseIdentity',
  'responseSchemaVersion',
  'sourceAvailability',
]);
const REPEATED_LIFECYCLE_EVENTS = new Set(['CLOSE_CANCELLED', 'DISPOSE_RAW', 'RELEASE']);
const REPEATED_CONDITION_EVENTS = new Set([
  'DISPOSAL_UNPROVEN',
  'EVIDENCE_MISMATCH',
  'EVIDENCE_MISSING',
]);
const LIFECYCLE_EVENTS = new Set([
  'BIND_LOCAL_CONTEXT',
  'CAPTURE_BYTES',
  'CAPTURE_LATE_BYTES',
  'CLOSE_CANCELLED',
  'CREATE_REQUEST',
  'DISPOSE_RAW',
  'NARROW_INTENT',
  'PREAUTHORIZE',
  'RECONCILE_NO_BYTES',
  'REDACT_PROJECTION',
  'REGISTERED_SAFE_PROBLEM_RETURNED',
  'RELEASE',
  'SELECT_COMPLETE',
  'SELECT_PARTIAL',
  'SELECT_UNAVAILABLE',
  'SELECT_UNKNOWN',
  'START_READ',
  'TERMINAL_DENIAL',
  'VALIDATE_PROJECTION',
]);
const CANCELLATION_EVENTS = new Set([
  'CANCEL_AFTER_BYTES',
  'CANCEL_AFTER_DISPOSAL',
  'CANCEL_AFTER_NO_RAW_READY',
  'CANCEL_AFTER_OUTCOME_SELECTION',
  'CANCEL_AFTER_REDACTION',
  'CANCEL_AFTER_VALIDATION',
  'CANCEL_BEFORE_DISPATCH',
  'CANCEL_DURING_READ',
  'CANCEL_LATE_EVIDENCE',
  'CANCEL_LATE_RELEASED',
]);

const TOP_KEYS = [
  'version',
  'designId',
  'sourceAnchors',
  'adapterMethods',
  'states',
  'rawStates',
  'deliveryStates',
  'resultDefinitions',
  'operationDefinitions',
  'conditionDefinitions',
  'lifecycleApplications',
  'conditionApplications',
  'cancellationApplications',
  'contributionApplications',
  'nonGoals',
] as const;
const SOURCE_ANCHOR_KEYS = [
  'id',
  'authorityClass',
  'artifactPath',
  'artifactSha256',
  'clauseId',
] as const;
const RESULT_DEFINITION_KEYS = [
  'id',
  'authorityClass',
  'designId',
  'sourceAnchorIds',
  'outcome',
  'truthState',
  'recordLawId',
  'cursorLawId',
  'authorityEffectId',
] as const;
const OPERATION_DEFINITION_KEYS = [
  'id',
  'authorityClass',
  'designId',
  'sourceAnchorIds',
  'ownerId',
  'inputTypeIds',
  'outputDispositionKinds',
  'constructorId',
  'validatorId',
  'consumerId',
] as const;
const ADAPTER_METHOD_KEYS = [
  'name',
  'requestType',
  'responseType',
  'deadline',
  'idempotency',
  'retry',
  'cancellation',
  'error',
  'constructorId',
  'validatorId',
  'consumerId',
] as const;
const CONDITION_DEFINITION_KEYS = [
  'id',
  'tupleAuthorityClass',
  'publicTitleAuthorityClass',
  'designId',
  'sourceAnchorIds',
  'code',
  'httpStatus',
  'jsonRpcCode',
  'grpcStatus',
  'truthState',
  'retryable',
  'disclosure',
  'publicTitle',
] as const;
const APPLICATION_KEYS = [
  'id',
  'authorityClass',
  'designId',
  'sourceAnchorIds',
  'operationId',
  'fromStateId',
  'eventId',
  'guardId',
  'toStateId',
  'rawStateEffectId',
  'deliveryEffectId',
  'adapterEffectId',
  'retainedFactId',
  'disposition',
  'rejectingBranchId',
  'noEffectId',
  'admittedInputTypeIds',
  'ownerId',
  'constructorId',
  'validatorId',
  'consumerId',
  'positiveVectorId',
  'negativeVector',
] as const;
const APPLICATION_FAMILIES = [
  'lifecycleApplications',
  'conditionApplications',
  'cancellationApplications',
  'contributionApplications',
] as const;
const EXACT_COUNTS = Object.freeze({
  sourceAnchors: 6,
  adapterMethods: 2,
  states: 17,
  rawStates: 3,
  deliveryStates: 3,
  resultDefinitions: 4,
  operationDefinitions: 9,
  conditionDefinitions: 16,
  lifecycleApplications: 22,
  conditionApplications: 37,
  cancellationApplications: 10,
  contributionApplications: 2,
  nonGoals: 12,
});
const EXPECTED_SOURCE_IDENTITIES = Object.freeze({
  'SA-AF22': [
    'SPECIFICATIONS/FACTS/explorer-fact-profile.md',
    'a51402d686780069f24ac1b6b8dad84b1e4153486daf4fde7154991990bdba40',
    'AF-22 sections 1-5',
  ],
  'SA-ADAPTER-REGISTRY': [
    'SPECIFICATIONS/INTERFACES/adapter-interface-registry.yaml',
    'bdef9896af38924ded713eb31f1e3c05faa6df077a3fdac539b657139f71be18',
    'adapters[adapterId=ADAPTER-EXPLORER-CONSUMER-V1]',
  ],
  'SA-SDK-EXPLORER': [
    'SPECIFICATIONS/INTERFACES/sdk-and-adapter-interfaces.md',
    'a9f1799a988d9da8f15837601df1a2e91f56e19b76ba761d701b3212240a63c6',
    'ExplorerConsumerAdapterV1',
  ],
  'SA-AD-SR04-013': [
    'GOVERNANCE/decision-and-supersession-map.jsonl',
    '397c0becca904297e172141d8bfe18712b255b05d0bd1b3f0f187da15680aae1',
    'decisionId=AD-SR04-013-PRIVACY-EXPLORER',
  ],
  'SA-ERROR-REGISTRY': [
    'SPECIFICATIONS/INTERFACES/error-registry.yaml',
    '7ac6a80aa97a75fc271e903028d289b25613470bea7b57dc92ecdf72a9eb19b9',
    'entries[code=PC-*]',
  ],
  'SA-PRIV-EXPLORER-011': [
    'QUALITY/privacy-controls.jsonl',
    'dc30ca3894c30aa14949173fb245dd229556150bcf24fe0708801b939b1bacad',
    'controlId=PRIV-EXPLORER-011',
  ],
} as const);
const EXPECTED_CONDITION_TUPLES = Object.freeze({
  'EXP-COND-001': [
    'PC-INTEGRATION-5002',
    409,
    -32052,
    'FAILED_PRECONDITION',
    'FAILED',
    false,
    'AUTHORIZED_DETAIL',
    'Request validation failed',
  ],
  'EXP-COND-002': [
    'PC-RUNTIME-3009',
    502,
    -32009,
    'FAILED_PRECONDITION',
    'FAILED',
    false,
    'NON_LEAKING_INVARIANT',
    'The service is unavailable',
  ],
  'EXP-COND-003': [
    'PC-OPS-9004',
    409,
    -32094,
    'FAILED_PRECONDITION',
    'PARTIAL',
    false,
    'AUTHORIZED_DETAIL',
    'Partial result',
  ],
  'EXP-COND-004': [
    'PC-INTEGRATION-5001',
    503,
    -32051,
    'UNAVAILABLE',
    'UNAVAILABLE',
    true,
    'NON_LEAKING_INVARIANT',
    'The service is unavailable',
  ],
  'EXP-COND-005': [
    'PC-FACT-4002',
    412,
    -32032,
    'FAILED_PRECONDITION',
    'STALE',
    false,
    'NON_LEAKING_INVARIANT',
    'The resource changed',
  ],
  'EXP-COND-006': [
    'PC-FACT-4003',
    409,
    -32033,
    'ABORTED',
    'REORG',
    false,
    'NON_LEAKING_INVARIANT',
    'The resource changed',
  ],
  'EXP-COND-007': [
    'PC-RUNTIME-3011',
    409,
    -32011,
    'FAILED_PRECONDITION',
    'CONFLICTING',
    false,
    'NON_LEAKING_INVARIANT',
    'The request conflicts with current state',
  ],
  'EXP-COND-008': [
    'PC-RUNTIME-3008',
    409,
    -32008,
    'FAILED_PRECONDITION',
    'FAILED',
    false,
    'NON_LEAKING_INVARIANT',
    'The request could not be completed',
  ],
  'EXP-PARSE': [
    'PC-DATA-6001',
    400,
    -32700,
    'INVALID_ARGUMENT',
    'FAILED',
    false,
    'NON_LEAKING_INVARIANT',
    'Malformed JSON',
  ],
  'EXP-ENVELOPE': [
    'PC-DATA-6002',
    400,
    -32600,
    'INVALID_ARGUMENT',
    'FAILED',
    false,
    'NON_LEAKING_INVARIANT',
    'Invalid request',
  ],
  'EXP-BROWSER': [
    'PC-DATA-6003',
    404,
    -32601,
    'NOT_FOUND',
    'DENIED',
    false,
    'NON_LEAKING_INVARIANT',
    'Resource is unavailable',
  ],
  'EXP-PARAMETER': [
    'PC-DATA-6004',
    400,
    -32602,
    'INVALID_ARGUMENT',
    'FAILED',
    false,
    'NON_LEAKING_INVARIANT',
    'Request validation failed',
  ],
  'EXP-REPLAY': [
    'PC-RUNTIME-3007',
    409,
    -32007,
    'ABORTED',
    'FAILED',
    false,
    'NON_LEAKING_INVARIANT',
    'Replay rejected',
  ],
  'EXP-DEADLINE': [
    'PC-OPS-9003',
    504,
    -32093,
    'DEADLINE_EXCEEDED',
    'FAILED',
    false,
    'NON_LEAKING_INVARIANT',
    'The service is unavailable',
  ],
  'EXP-EVIDENCE': [
    'PC-RUNTIME-3010',
    503,
    -32010,
    'FAILED_PRECONDITION',
    'FAILED',
    false,
    'NON_LEAKING_INVARIANT',
    'The request could not be completed',
  ],
  'EXP-ABSENCE': [
    'PC-FACT-4001',
    409,
    -32031,
    'FAILED_PRECONDITION',
    'UNKNOWN',
    false,
    'NON_LEAKING_INVARIANT',
    'Result unknown',
  ],
});
const PROBLEM_TUPLE_FIELDS = [
  'code',
  'httpStatus',
  'jsonRpcCode',
  'grpcStatus',
  'truthState',
  'retryable',
  'disclosure',
  'publicTitle',
] as const;
const EXPECTED_HTTP_BOUNDARY_PROBLEM_TUPLES = Object.freeze([
  [
    'PC-AUTH-0001',
    401,
    -32041,
    'UNAUTHENTICATED',
    'DENIED',
    false,
    'NON_LEAKING_INVARIANT',
    'Resource is unavailable',
  ],
  [
    'PC-RUNTIME-3001',
    403,
    -32001,
    'PERMISSION_DENIED',
    'DENIED',
    false,
    'NON_LEAKING_INVARIANT',
    'Resource is unavailable',
  ],
] as const);
const EXPECTED_CONDITION_COVERAGE = Object.freeze({
  'EXP-COND-001': 7,
  'EXP-COND-002': 3,
  'EXP-COND-003': 3,
  'EXP-COND-004': 1,
  'EXP-COND-005': 1,
  'EXP-COND-006': 1,
  'EXP-COND-007': 1,
  'EXP-COND-008': 3,
  'EXP-PARSE': 1,
  'EXP-ENVELOPE': 2,
  'EXP-BROWSER': 2,
  'EXP-PARAMETER': 2,
  'EXP-REPLAY': 2,
  'EXP-DEADLINE': 1,
  'EXP-EVIDENCE': 6,
  'EXP-ABSENCE': 1,
} as const);

const object = (value: unknown, label: string): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`${label}: expected object`);
  return value as Record<string, unknown>;
};
const array = (value: unknown, label: string) => {
  if (!Array.isArray(value)) throw new Error(`${label}: expected array`);
  return value;
};
const exactKeys = (value: Record<string, unknown>, keys: readonly string[], label: string) =>
  assertExactSet(Object.keys(value), keys, `${label} keys`);
const strings = (value: unknown, label: string) => {
  const values = array(value, label);
  if (values.some((entry) => typeof entry !== 'string' || entry === ''))
    throw new Error(`${label}: expected non-empty string array`);
  return values as string[];
};
const unique = (values: readonly string[], label: string) => {
  if (new Set(values).size !== values.length) throw new Error(`${label}: duplicate value`);
};
const requireString = (row: Record<string, unknown>, key: string, label: string) => {
  if (typeof row[key] !== 'string' || row[key] === '')
    throw new Error(`${label}.${key}: expected non-empty string`);
};
const exactCount = (registry: Record<string, unknown>, key: keyof typeof EXACT_COUNTS) => {
  const value = array(registry[key], `registry.${key}`);
  if (value.length !== EXACT_COUNTS[key])
    throw new Error(`registry.${key}: expected ${EXACT_COUNTS[key]} rows`);
  return value;
};
const validateSourceReferences = (
  row: Record<string, unknown>,
  label: string,
  sourceIds: ReadonlySet<string>,
) => {
  const refs = strings(row.sourceAnchorIds, `${label}.sourceAnchorIds`);
  unique(refs, `${label}.sourceAnchorIds`);
  if (refs.length === 0 || refs.some((id) => !sourceIds.has(id)))
    throw new Error(`${label}: dangling source anchor`);
};
const validateDisposition = (
  value: unknown,
  label: string,
  conditionIds: ReadonlySet<string>,
  resultIds: ReadonlySet<string>,
) => {
  const disposition = object(value, label);
  const kind = disposition.kind;
  if (kind === 'CONDITION') {
    exactKeys(disposition, ['kind', 'conditionDefinitionId'], label);
    if (!conditionIds.has(String(disposition.conditionDefinitionId)))
      throw new Error(`${label}: dangling condition definition`);
  } else if (kind === 'RESULT') {
    exactKeys(disposition, ['kind', 'resultDefinitionId'], label);
    if (!resultIds.has(String(disposition.resultDefinitionId)))
      throw new Error(`${label}: dangling result definition`);
  } else if (kind === 'COMMON_TERMINAL_DENIAL') {
    exactKeys(disposition, ['kind', 'commonDenialDefinitionId'], label);
    if (disposition.commonDenialDefinitionId !== 'PC-RUNTIME-3001')
      throw new Error(`${label}: unknown common denial`);
  } else if (kind === 'INTERNAL') {
    exactKeys(disposition, ['kind', 'internalDispositionId'], label);
    requireString(disposition, 'internalDispositionId', label);
  } else if (kind === 'NONE') {
    exactKeys(disposition, ['kind'], label);
  } else {
    throw new Error(`${label}: unknown disposition kind`);
  }
  return disposition;
};

const expectedNegativeField = (family: string, row: Record<string, unknown>) => {
  const eventId = String(row.eventId);
  if (family === 'lifecycleApplications')
    return eventId === 'REGISTERED_SAFE_PROBLEM_RETURNED'
      ? 'responseIdentity'
      : row.guardId === 'EXACT_SOURCE_STATE'
        ? 'eventId'
        : 'guardId';
  if (family === 'cancellationApplications')
    return eventId.startsWith('CANCEL_LATE_') ? 'immutableDeliveryState' : 'cancellationTiming';
  if (family === 'contributionApplications') return 'rawDisposalProof';
  if (eventId === 'DISPOSAL_UNPROVEN') return 'rawDisposalProof';
  if (eventId === 'ABSENCE_WITHOUT_COMPLETE_PROOF') return 'completenessProof';
  if (eventId === 'DEADLINE_EXPIRED') return 'deadlineAt';
  if (eventId === 'REPLAY_DETECTED' || eventId === 'OCCURRENCE_CONFLICT') return 'occurrenceId';
  if (eventId === 'EVIDENCE_MISMATCH' || eventId === 'EVIDENCE_MISSING') return 'evidenceIdentity';
  if (eventId === 'RESPONSE_BINDING_INVALID') return 'responseIdentity';
  if (eventId === 'RESPONSE_SCHEMA_INVALID') return 'responseSchemaVersion';
  if (eventId === 'RESPONSE_INTEGRITY_INVALID') return 'responseDigest';
  if (eventId === 'SOURCE_UNAVAILABLE') return 'sourceAvailability';
  if (
    eventId === 'STALE_OBSERVATION' ||
    eventId === 'REORG_OBSERVATION' ||
    eventId === 'CONFLICTING_OBSERVATIONS'
  )
    return 'observationFreshness';
  if (eventId === 'CURSOR_PARTIAL' || eventId === 'ORDER_PARTIAL' || eventId === 'GAP_PARTIAL')
    return 'cursorOrder';
  if (eventId === 'PRIVACY_PROJECTION_IMPOSSIBLE' || eventId === 'REDACTION_IMPOSSIBLE')
    return 'redactionFeasibility';
  if (
    eventId === 'PROFILE_NOT_ADMITTED' ||
    eventId === 'PROFILE_RETIRED' ||
    eventId === 'PRODUCT_DRIFT' ||
    eventId === 'RELEASE_DRIFT' ||
    eventId === 'TRUST_DRIFT'
  )
    return 'profileDigest';
  if (
    eventId === 'QUERY_UNSUPPORTED' ||
    eventId === 'FIELD_UNSUPPORTED' ||
    eventId === 'DATA_CLASS_UNSUPPORTED' ||
    eventId === 'PARAMETER_FORBIDDEN' ||
    eventId === 'PARAMETER_INVALID'
  )
    return 'queryDigest';
  return 'requestEnvelope';
};

const expectedApplicationGuard = (family: string, row: Record<string, unknown>) => {
  const eventId = String(row.eventId);
  if (family === 'conditionApplications')
    return `CLASSIFIED_AS_${String(row.id).replace('CA-', 'CA_')}`;
  if (family === 'lifecycleApplications')
    return eventId === 'REGISTERED_SAFE_PROBLEM_RETURNED'
      ? 'EXACT_REGISTERED_SAFE_PROBLEM'
      : eventId === 'RELEASE'
        ? 'DELIVERY_PENDING'
        : eventId === 'CLOSE_CANCELLED'
          ? 'DELIVERY_SUPPRESSED'
          : 'EXACT_SOURCE_STATE';
  if (family === 'contributionApplications')
    return 'IDENTITY_OCCURRENCE_DIGESTS_REVISION_AND_UNIQUENESS_MATCH';
  if (eventId === 'CANCEL_DURING_READ') return 'DISPATCH_STARTED_NO_BYTES';
  if (
    eventId === 'CANCEL_AFTER_BYTES' ||
    eventId === 'CANCEL_AFTER_VALIDATION' ||
    eventId === 'CANCEL_AFTER_REDACTION' ||
    eventId === 'CANCEL_AFTER_OUTCOME_SELECTION'
  )
    return 'RAW_OWNER_LIVE';
  if (eventId === 'CANCEL_LATE_RELEASED') return 'IMMUTABLE_RELEASE_EXISTS';
  if (eventId === 'CANCEL_LATE_EVIDENCE') return 'IMMUTABLE_EVIDENCE_EXISTS';
  return 'DELIVERY_PENDING';
};

const expectedRetainedFact = (family: string, row: Record<string, unknown>) => {
  const eventId = String(row.eventId);
  if (family === 'lifecycleApplications') {
    if (eventId === 'DISPOSE_RAW')
      return row.fromStateId === 'OUTCOME_SELECTED_RAW_LIVE'
        ? 'OUTCOME_READY'
        : 'CANCELLED_AFTER_RAW';
    return (
      {
        BIND_LOCAL_CONTEXT: 'CONTEXT_BOUND',
        PREAUTHORIZE: 'PREAUTHORIZED',
        TERMINAL_DENIAL: 'DENIED',
        NARROW_INTENT: 'INTENT_NARROWED',
        CREATE_REQUEST: 'REQUEST_READY',
        START_READ: 'READ_STARTED',
        CAPTURE_BYTES: 'BYTES_CAPTURED',
        VALIDATE_PROJECTION: 'VALIDATED_NO_AUTHORITY',
        REDACT_PROJECTION: 'REDACTED',
        REGISTERED_SAFE_PROBLEM_RETURNED: 'SAFE_PROBLEM_NO_RAW',
        SELECT_COMPLETE: 'COMPLETE',
        SELECT_PARTIAL: 'PARTIAL',
        SELECT_UNKNOWN: 'UNKNOWN',
        SELECT_UNAVAILABLE: 'UNAVAILABLE',
        RECONCILE_NO_BYTES: 'CANCELLED_AFTER_DISPATCH_NO_RAW',
        CAPTURE_LATE_BYTES: 'CANCELLED_AFTER_RAW',
        RELEASE: 'RELEASED',
        CLOSE_CANCELLED: 'SUPPRESSED',
      } as Record<string, string>
    )[eventId];
  }
  if (family === 'contributionApplications') return 'EVIDENCE_SEALED';
  if (family === 'conditionApplications') {
    if (row.rawStateEffectId === 'LIVE') return 'SAFE_PROBLEM_RAW_RETAINED';
    return row.toStateId === 'RELEASED'
      ? 'RELEASED_STATE_UNCHANGED'
      : row.rawStateEffectId === 'REQUIRES_NEVER_CREATED_OR_DISPOSED'
        ? 'CANCELLED_STATE_UNCHANGED'
        : 'SAFE_PROBLEM_NO_RAW';
  }
  if (eventId === 'CANCEL_BEFORE_DISPATCH') return 'CANCELLED_BEFORE_DISPATCH';
  if (eventId === 'CANCEL_AFTER_NO_RAW_READY') return 'CANCELLED_AFTER_DISPATCH_NO_RAW';
  if (eventId === 'CANCEL_AFTER_DISPOSAL') return 'CANCELLED_AFTER_RAW';
  if (eventId === 'CANCEL_LATE_RELEASED') return 'NO_OP_AFTER_IMMUTABLE_RELEASE';
  if (eventId === 'CANCEL_LATE_EVIDENCE') return 'NO_OP_AFTER_IMMUTABLE_EVIDENCE';
  return 'CANCEL_PENDING';
};

export type RegistrySummary = Readonly<{
  sourceAnchors: number;
  operations: number;
  conditions: number;
  results: number;
  lifecycleApplications: number;
  conditionApplications: number;
  cancellationApplications: number;
  contributionApplications: number;
  reachableStates: number;
  semanticSha256: string;
}>;

export type ProblemUnionSummary = Readonly<{
  tuples: number;
  conditionTuples: number;
  httpBoundaryTuples: number;
}>;

export const validatePrivacyExplorerProblemUnion = (
  schemaValue: unknown,
  registryValue: unknown,
): ProblemUnionSummary => {
  const schema = object(schemaValue, 'Privacy Explorer schema');
  const definitions = object(schema.$defs, 'Privacy Explorer schema.$defs');
  const problem = object(definitions.PrivacyExplorerProblemV1, 'PrivacyExplorerProblemV1');
  exactKeys(
    problem,
    ['type', 'additionalProperties', 'required', 'properties', 'oneOf'],
    'PrivacyExplorerProblemV1',
  );
  if (problem.type !== 'object' || problem.additionalProperties !== false)
    throw new Error('PrivacyExplorerProblemV1: object closure drift');
  assertExactSet(
    strings(problem.required, 'PrivacyExplorerProblemV1.required'),
    PROBLEM_TUPLE_FIELDS,
    'PrivacyExplorerProblemV1 required fields',
  );
  const properties = object(problem.properties, 'PrivacyExplorerProblemV1.properties');
  exactKeys(properties, PROBLEM_TUPLE_FIELDS, 'PrivacyExplorerProblemV1.properties');
  for (const field of PROBLEM_TUPLE_FIELDS) {
    const definition = object(properties[field], `PrivacyExplorerProblemV1.properties.${field}`);
    exactKeys(definition, ['type'], `PrivacyExplorerProblemV1.properties.${field}`);
    const expectedType =
      field === 'httpStatus' || field === 'jsonRpcCode'
        ? 'integer'
        : field === 'retryable'
          ? 'boolean'
          : 'string';
    if (definition.type !== expectedType)
      throw new Error(`PrivacyExplorerProblemV1.properties.${field}: type drift`);
  }

  const actualTuples = array(problem.oneOf, 'PrivacyExplorerProblemV1.oneOf').map(
    (variant, index) => {
      const row = object(variant, `PrivacyExplorerProblemV1.oneOf[${index}]`);
      exactKeys(row, ['properties'], `PrivacyExplorerProblemV1.oneOf[${index}]`);
      const variantProperties = object(
        row.properties,
        `PrivacyExplorerProblemV1.oneOf[${index}].properties`,
      );
      exactKeys(
        variantProperties,
        PROBLEM_TUPLE_FIELDS,
        `PrivacyExplorerProblemV1.oneOf[${index}].properties`,
      );
      return PROBLEM_TUPLE_FIELDS.map((field) => {
        const constant = object(
          variantProperties[field],
          `PrivacyExplorerProblemV1.oneOf[${index}].properties.${field}`,
        );
        exactKeys(
          constant,
          ['const'],
          `PrivacyExplorerProblemV1.oneOf[${index}].properties.${field}`,
        );
        return constant.const;
      });
    },
  );
  const registry = object(registryValue, 'registry');
  const conditionDefinitions = array(
    registry.conditionDefinitions,
    'registry.conditionDefinitions',
  ).map((entry, index) => {
    const row = object(entry, `registry.conditionDefinitions[${index}]`);
    return PROBLEM_TUPLE_FIELDS.map((field) => row[field]);
  });
  const expectedTuples = [...EXPECTED_HTTP_BOUNDARY_PROBLEM_TUPLES, ...conditionDefinitions];
  assertExactSet(
    actualTuples.map((tuple) => JSON.stringify(tuple)),
    expectedTuples.map((tuple) => JSON.stringify(tuple)),
    'PrivacyExplorerProblemV1 schema/registry tuple closure',
  );
  unique(
    actualTuples.map((tuple) => String(tuple[0])),
    'PrivacyExplorerProblemV1 codes',
  );
  return {
    tuples: actualTuples.length,
    conditionTuples: conditionDefinitions.length,
    httpBoundaryTuples: EXPECTED_HTTP_BOUNDARY_PROBLEM_TUPLES.length,
  };
};

export const validatePrivacyExplorerOpenApiSource = (source: string) => {
  const operationIds = [...source.matchAll(/^ {6}operationId: (.+)$/gm)].map((match) => match[1]);
  assertExactSet(
    operationIds,
    ['readPrivacyExplorerProjection', 'readPrivacyExplorerOccurrence'],
    'Privacy Explorer operation IDs',
  );
  const paths = [...source.matchAll(/^ {2}(\/.+):$/gm)].map((match) => match[1]);
  assertExactSet(
    paths,
    ['/v1/privacy-explorer/projections:read', '/v1/privacy-explorer/occurrences/{occurrenceId}'],
    'Privacy Explorer paths',
  );
  const methods = [...source.matchAll(/^ {4}(get|post|put|patch|delete):$/gm)].map(
    (match) => match[1],
  );
  assertExactSet(methods, ['post', 'get'], 'Privacy Explorer methods');
  const section = (path: string) => source.split(`  ${path}:\n`)[1]?.split(/^ {2}\//m)[0] ?? '';
  const projection = section('/v1/privacy-explorer/projections:read');
  const occurrence = section('/v1/privacy-explorer/occurrences/{occurrenceId}');
  const statuses = [...projection.matchAll(/^ {8}'([0-9]{3})':$/gm)].map((match) => match[1]);
  assertExactSet(
    statuses,
    ['200', '400', '401', '403', '404', '409', '412', '502', '503', '504'],
    'Privacy Explorer response statuses',
  );
  if (
    !/'200':[\s\S]*?\$ref: \.\.\/json\/privacy-explorer\.schema\.json#\/\$defs\/PrivacyExplorerResultV1[\s\S]*?'400':/.test(
      projection,
    )
  )
    throw new Error('Privacy Explorer 200 response must expose only PrivacyExplorerResultV1');
  const problemRefs = [
    ...projection.matchAll(
      /\$ref: \.\.\/json\/privacy-explorer\.schema\.json#\/\$defs\/PrivacyExplorerProblemV1/g,
    ),
  ];
  if (problemRefs.length !== 9)
    throw new Error('Privacy Explorer error responses must use the generated exact problem union');
  const occurrenceStatuses = [...occurrence.matchAll(/^ {8}'([0-9]{3})':$/gm)].map(
    (match) => match[1],
  );
  assertExactSet(
    occurrenceStatuses,
    ['200', '403'],
    'Privacy Explorer occurrence response statuses',
  );
  if (
    !/'200':[\s\S]*?\$ref: \.\.\/json\/privacy-explorer\.schema\.json#\/\$defs\/PrivacyExplorerOccurrenceV1[\s\S]*?'403':[\s\S]*?\$ref: \.\.\/json\/privacy-explorer\.schema\.json#\/\$defs\/PrivacyExplorerProblemV1/.test(
      occurrence,
    )
  )
    throw new Error(
      'Privacy Explorer occurrence readback must expose only authorized metadata or the exact problem union',
    );
  return {
    operations: operationIds.length,
    paths: paths.length,
    statuses: statuses.length + occurrenceStatuses.length,
  };
};

export const validateExecutionRegistryRelations = (value: unknown): RegistrySummary => {
  const registry = object(value, 'registry');
  exactKeys(registry, TOP_KEYS, 'registry');
  if (registry.version !== '2.0') throw new Error('registry.version: expected 2.0');
  if (registry.designId !== 'I07-G2-B1-V1')
    throw new Error('registry.designId: unexpected receiving design');

  for (const key of Object.keys(EXACT_COUNTS) as Array<keyof typeof EXACT_COUNTS>)
    exactCount(registry, key);

  const states = strings(registry.states, 'registry.states');
  const rawStates = strings(registry.rawStates, 'registry.rawStates');
  const deliveryStates = strings(registry.deliveryStates, 'registry.deliveryStates');
  unique(states, 'registry.states');
  unique(rawStates, 'registry.rawStates');
  unique(deliveryStates, 'registry.deliveryStates');
  assertExactSet(states, EXPECTED_STATES, 'lifecycle states');
  assertExactSet(rawStates, ['NEVER_CREATED', 'LIVE', 'DISPOSED'], 'raw states');
  assertExactSet(deliveryStates, ['PENDING', 'SUPPRESSED', 'RELEASED'], 'delivery states');

  const sourceAnchors = registry.sourceAnchors as Array<Record<string, unknown>>;
  const sourceIds = new Set<string>();
  sourceAnchors.forEach((entry, index) => {
    const row = object(entry, `sourceAnchors[${index}]`);
    exactKeys(row, SOURCE_ANCHOR_KEYS, `sourceAnchors[${index}]`);
    for (const key of SOURCE_ANCHOR_KEYS) requireString(row, key, `sourceAnchors[${index}]`);
    if (row.authorityClass !== 'C17_NORMATIVE')
      throw new Error(`sourceAnchors[${index}]: authority drift`);
    const expected =
      EXPECTED_SOURCE_IDENTITIES[String(row.id) as keyof typeof EXPECTED_SOURCE_IDENTITIES];
    if (
      !expected ||
      row.artifactPath !== expected[0] ||
      row.artifactSha256 !== expected[1] ||
      row.clauseId !== expected[2]
    )
      throw new Error(`sourceAnchors[${index}]: source identity drift`);
    sourceIds.add(String(row.id));
  });
  unique([...sourceIds], 'source anchor IDs');

  const adapterMethods = registry.adapterMethods as Array<Record<string, unknown>>;
  adapterMethods.forEach((entry, index) => {
    const row = object(entry, `adapterMethods[${index}]`);
    exactKeys(row, ADAPTER_METHOD_KEYS, `adapterMethods[${index}]`);
    for (const key of ADAPTER_METHOD_KEYS) requireString(row, key, `adapterMethods[${index}]`);
  });
  const methodSemantics = adapterMethods.map((row) => [
    row.name,
    row.requestType,
    row.responseType,
    row.deadline,
    row.idempotency,
    row.retry,
  ]);
  if (
    JSON.stringify(methodSemantics) !==
    JSON.stringify([
      [
        'readGovernedProjection',
        'ExplorerProjectionRequestV1',
        'ExplorerProjectionResultV1',
        'CALLER_AND_EXPORT_PROFILE',
        'SAFE_BY_CURSOR_AND_QUERY_DIGEST',
        'BOUNDED_READ_RETRY',
      ],
      [
        'verifyEvidenceReference',
        'EvidenceReferenceV1',
        'EvidenceVerificationResultV1',
        'CALLER',
        'SAFE_BY_DIGEST',
        'NONE_AUTOMATIC',
      ],
    ])
  )
    throw new Error('adapterMethods: C17 ExplorerConsumerAdapterV1 semantic drift');
  const executableRegistryRows = [
    ...(registry.operationDefinitions as Array<Record<string, unknown>>),
    ...(registry.lifecycleApplications as Array<Record<string, unknown>>),
    ...(registry.conditionApplications as Array<Record<string, unknown>>),
    ...(registry.cancellationApplications as Array<Record<string, unknown>>),
    ...(registry.contributionApplications as Array<Record<string, unknown>>),
  ];
  if (
    executableRegistryRows.some((row) =>
      /ExplorerFactSourceProfileV1|ExplorerCandidatePageV1|LANE-FACTS|LS-FACT-BRIDGE/.test(
        JSON.stringify(row),
      ),
    )
  )
    throw new Error('executable registry leaks a LANE-FACTS owner or type');
  const operationById = new Map(
    (registry.operationDefinitions as Array<Record<string, unknown>>).map((row) => [
      String(row.id),
      row,
    ]),
  );
  if (
    JSON.stringify(operationById.get('PXI-NARROW-INTENT/v1')?.inputTypeIds) !==
      JSON.stringify([
        'PrivacyExplorerPreauthorizedIntentV1',
        'PrivacyExplorerExportProfileV1',
        'PrivacyExplorerFilterPageV1',
      ]) ||
    JSON.stringify(operationById.get('PXI-CREATE-PROJECTION-REQUEST/v1')?.inputTypeIds) !==
      JSON.stringify(['PrivacyExplorerNarrowedIntentV1', 'AdapterCallContextSeedV1']) ||
    adapterMethods.find((row) => row.name === 'verifyEvidenceReference')?.constructorId !==
      'createEvidenceVerificationBoundary'
  )
    throw new Error('consumer-owned constructor/input identity drift');

  const resultDefinitions = registry.resultDefinitions as Array<Record<string, unknown>>;
  const resultIds = new Set<string>();
  resultDefinitions.forEach((entry, index) => {
    const row = object(entry, `resultDefinitions[${index}]`);
    exactKeys(row, RESULT_DEFINITION_KEYS, `resultDefinitions[${index}]`);
    for (const key of RESULT_DEFINITION_KEYS.filter((key) => key !== 'sourceAnchorIds'))
      requireString(row, key, `resultDefinitions[${index}]`);
    validateSourceReferences(row, `resultDefinitions[${index}]`, sourceIds);
    if (row.authorityClass !== 'RECEIVING_INTERNAL_DESIGN' || row.designId !== registry.designId)
      throw new Error(`resultDefinitions[${index}]: design authority drift`);
    if (row.authorityEffectId !== 'NO_AUTHORITY')
      throw new Error(`resultDefinitions[${index}]: authority promotion`);
    const expectedLaw = RESULT_LAWS[String(row.id) as keyof typeof RESULT_LAWS];
    if (
      !expectedLaw ||
      JSON.stringify([row.outcome, row.truthState, row.recordLawId, row.cursorLawId]) !==
        JSON.stringify(expectedLaw)
    )
      throw new Error(`resultDefinitions[${index}]: outcome/record/cursor law drift`);
    resultIds.add(String(row.id));
  });
  unique([...resultIds], 'result definition IDs');

  const operationDefinitions = registry.operationDefinitions as Array<Record<string, unknown>>;
  const operationIds = new Set<string>();
  operationDefinitions.forEach((entry, index) => {
    const row = object(entry, `operationDefinitions[${index}]`);
    exactKeys(row, OPERATION_DEFINITION_KEYS, `operationDefinitions[${index}]`);
    for (const key of OPERATION_DEFINITION_KEYS.filter(
      (key) =>
        key !== 'sourceAnchorIds' && key !== 'inputTypeIds' && key !== 'outputDispositionKinds',
    ))
      requireString(row, key, `operationDefinitions[${index}]`);
    validateSourceReferences(row, `operationDefinitions[${index}]`, sourceIds);
    unique(strings(row.inputTypeIds, `operationDefinitions[${index}].inputTypeIds`), 'input types');
    const outputKinds = strings(
      row.outputDispositionKinds,
      `operationDefinitions[${index}].outputDispositionKinds`,
    );
    unique(outputKinds, 'output disposition kinds');
    if (outputKinds.length === 0 || outputKinds.some((kind) => !DISPOSITION_KINDS.has(kind)))
      throw new Error(`operationDefinitions[${index}]: unknown output disposition kind`);
    if (row.authorityClass !== 'RECEIVING_INTERNAL_DESIGN' || row.designId !== registry.designId)
      throw new Error(`operationDefinitions[${index}]: design authority drift`);
    if (row.ownerId !== 'LS-CONTROL-API')
      throw new Error(`operationDefinitions[${index}]: owner drift`);
    operationIds.add(String(row.id));
  });
  unique([...operationIds], 'operation definition IDs');

  const conditionDefinitions = registry.conditionDefinitions as Array<Record<string, unknown>>;
  const conditionIds = new Set<string>();
  conditionDefinitions.forEach((entry, index) => {
    const row = object(entry, `conditionDefinitions[${index}]`);
    exactKeys(row, CONDITION_DEFINITION_KEYS, `conditionDefinitions[${index}]`);
    for (const key of CONDITION_DEFINITION_KEYS.filter(
      (key) =>
        key !== 'sourceAnchorIds' &&
        key !== 'httpStatus' &&
        key !== 'jsonRpcCode' &&
        key !== 'retryable',
    ))
      requireString(row, key, `conditionDefinitions[${index}]`);
    validateSourceReferences(row, `conditionDefinitions[${index}]`, sourceIds);
    if (
      row.tupleAuthorityClass !== 'C17_NORMATIVE' ||
      row.publicTitleAuthorityClass !== 'RECEIVING_INTERNAL_DESIGN' ||
      row.designId !== registry.designId ||
      !Number.isInteger(row.httpStatus) ||
      !Number.isInteger(row.jsonRpcCode) ||
      typeof row.retryable !== 'boolean'
    )
      throw new Error(`conditionDefinitions[${index}]: invalid authority or tuple type`);
    const expectedTuple =
      EXPECTED_CONDITION_TUPLES[String(row.id) as keyof typeof EXPECTED_CONDITION_TUPLES];
    if (
      !expectedTuple ||
      JSON.stringify([
        row.code,
        row.httpStatus,
        row.jsonRpcCode,
        row.grpcStatus,
        row.truthState,
        row.retryable,
        row.disclosure,
        row.publicTitle,
      ]) !== JSON.stringify(expectedTuple)
    )
      throw new Error('conditionDefinitions[' + index + ']: exact C17 tuple drift');
    conditionIds.add(String(row.id));
  });
  unique([...conditionIds], 'condition definition IDs');

  const allApplicationIds: string[] = [];
  const edges: Array<[string, string]> = [];
  const conditionCoverage = new Map<string, number>();
  const resultCoverage = new Map<string, number>();
  const operationApplications = new Map<string, string[]>([...operationIds].map((id) => [id, []]));
  const operationDispositionKinds = new Map<string, Set<string>>(
    [...operationIds].map((id) => [id, new Set<string>()]),
  );
  const lifecycleEventCounts = new Map<string, number>();
  const conditionEventCounts = new Map<string, number>();
  const expectedRawEffects = EXPECTED_RAW_EFFECTS;
  const expectedDeliveryEffects = EXPECTED_DELIVERY_EFFECTS;
  const expectedAdapterEffects = EXPECTED_ADAPTER_EFFECTS;

  for (const family of APPLICATION_FAMILIES) {
    const rows = registry[family] as Array<Record<string, unknown>>;
    rows.forEach((entry, index) => {
      const label = `${family}[${index}]`;
      const row = object(entry, label);
      exactKeys(row, APPLICATION_KEYS, label);
      for (const key of APPLICATION_KEYS.filter(
        (key) =>
          key !== 'sourceAnchorIds' &&
          key !== 'disposition' &&
          key !== 'admittedInputTypeIds' &&
          key !== 'negativeVector',
      ))
        requireString(row, key, label);
      validateSourceReferences(row, label, sourceIds);
      if (row.authorityClass !== 'RECEIVING_INTERNAL_DESIGN' || row.designId !== registry.designId)
        throw new Error(`${label}: design authority drift`);
      if (!operationIds.has(String(row.operationId)))
        throw new Error(`${label}: dangling operation definition`);
      if (!states.includes(String(row.fromStateId)) || !states.includes(String(row.toStateId)))
        throw new Error(`${label}: dangling state`);
      if (
        !expectedRawEffects.has(String(row.rawStateEffectId)) ||
        !expectedDeliveryEffects.has(String(row.deliveryEffectId)) ||
        !expectedAdapterEffects.has(String(row.adapterEffectId))
      )
        throw new Error(`${label}: unknown effect ID`);
      if (
        !APPLICATION_EVENTS.has(String(row.eventId)) ||
        !APPLICATION_GUARDS.has(String(row.guardId)) ||
        !RETAINED_FACT_IDS.has(String(row.retainedFactId)) ||
        !NO_EFFECT_IDS.has(String(row.noEffectId))
      )
        throw new Error(`${label}: closed application vocabulary drift`);
      if (
        row.guardId !== expectedApplicationGuard(family, row) ||
        row.retainedFactId !== expectedRetainedFact(family, row) ||
        row.noEffectId !==
          (family === 'cancellationApplications'
            ? 'NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT'
            : 'STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED')
      )
        throw new Error(`${label}: application relation law drift`);
      if (
        family === 'contributionApplications' &&
        row.eventId !== 'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS'
      )
        throw new Error(`${label}: contribution event law drift`);
      if (
        family === 'conditionApplications' &&
        (LIFECYCLE_EVENTS.has(String(row.eventId)) ||
          CANCELLATION_EVENTS.has(String(row.eventId)) ||
          row.eventId === 'MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS')
      )
        throw new Error(`${label}: condition event family drift`);
      const operation = operationDefinitions.find((entry) => entry.id === row.operationId);
      if (!operation) throw new Error(label + ': missing owning operation');
      if (
        JSON.stringify(strings(row.admittedInputTypeIds, label + '.admittedInputTypeIds')) !==
          JSON.stringify(operation.inputTypeIds) ||
        row.ownerId !== operation.ownerId ||
        row.constructorId !== operation.constructorId ||
        row.validatorId !== operation.validatorId ||
        row.consumerId !== operation.consumerId
      )
        throw new Error(label + ': ownership tuple drift');
      const negative = object(row.negativeVector, label + '.negativeVector');
      exactKeys(
        negative,
        ['id', 'mutatedFieldId', 'expectedRejectingBranchId'],
        label + '.negativeVector',
      );
      requireString(negative, 'id', label + '.negativeVector');
      requireString(negative, 'mutatedFieldId', label + '.negativeVector');
      requireString(negative, 'expectedRejectingBranchId', label + '.negativeVector');
      if (
        !MUTATED_FIELD_IDS.has(String(negative.mutatedFieldId)) ||
        negative.mutatedFieldId !== expectedNegativeField(family, row)
      )
        throw new Error(label + ': negative vector field law drift');
      if (
        row.positiveVectorId !== String(row.id) + ':POSITIVE' ||
        negative.id !== String(row.id) + ':NEGATIVE' ||
        negative.expectedRejectingBranchId !== row.rejectingBranchId
      )
        throw new Error(label + ': vector closure drift');
      const disposition = validateDisposition(
        row.disposition,
        `${label}.disposition`,
        conditionIds,
        resultIds,
      );
      if (family === 'conditionApplications') {
        if (disposition.kind !== 'CONDITION')
          throw new Error(`${label}: condition application lacks condition disposition`);
        const conditionId = String(disposition.conditionDefinitionId);
        conditionCoverage.set(conditionId, (conditionCoverage.get(conditionId) ?? 0) + 1);
      } else if (disposition.kind === 'CONDITION') {
        throw new Error(`${label}: condition disposition outside condition applications`);
      }
      if (disposition.kind === 'RESULT') {
        const resultId = String(disposition.resultDefinitionId);
        resultCoverage.set(resultId, (resultCoverage.get(resultId) ?? 0) + 1);
      }
      if (family === 'lifecycleApplications')
        lifecycleEventCounts.set(
          String(row.eventId),
          (lifecycleEventCounts.get(String(row.eventId)) ?? 0) + 1,
        );
      if (family === 'conditionApplications')
        conditionEventCounts.set(
          String(row.eventId),
          (conditionEventCounts.get(String(row.eventId)) ?? 0) + 1,
        );
      allApplicationIds.push(String(row.id));
      operationApplications.get(String(row.operationId))?.push(String(row.id));
      operationDispositionKinds.get(String(row.operationId))?.add(String(disposition.kind));
      edges.push([String(row.fromStateId), String(row.toStateId)]);
    });
  }

  unique(allApplicationIds, 'application IDs');
  unique(
    [...sourceIds, ...resultIds, ...operationIds, ...conditionIds, ...allApplicationIds],
    'global registry IDs',
  );

  for (const [conditionId, expectedCount] of Object.entries(EXPECTED_CONDITION_COVERAGE))
    if (conditionCoverage.get(conditionId) !== expectedCount)
      throw new Error(`condition application coverage drift: ${conditionId}`);
  if ([...conditionIds].some((id) => !conditionCoverage.has(id)))
    throw new Error('orphan condition definition');
  if ([...resultIds].some((id) => !resultCoverage.has(id)))
    throw new Error('orphan result definition');

  for (const operationId of operationIds)
    if ((operationApplications.get(operationId) ?? []).length === 0)
      throw new Error('orphan operation definition: ' + operationId);
  for (const operation of operationDefinitions) {
    const declared = strings(
      operation.outputDispositionKinds,
      `operationDefinitions[${operation.id}].outputDispositionKinds`,
    );
    assertExactSet(
      declared,
      [...(operationDispositionKinds.get(String(operation.id)) ?? new Set<string>())],
      `operationDefinitions[${operation.id}]: output disposition closure`,
    );
  }
  for (const [eventId, count] of lifecycleEventCounts)
    if (
      (REPEATED_LIFECYCLE_EVENTS.has(eventId) && count !== 2) ||
      (!REPEATED_LIFECYCLE_EVENTS.has(eventId) && count !== 1)
    )
      throw new Error(`lifecycle event cardinality drift: ${eventId}`);
  if (
    lifecycleEventCounts.size !==
    EXACT_COUNTS.lifecycleApplications - REPEATED_LIFECYCLE_EVENTS.size
  )
    throw new Error('lifecycle event cardinality closure drift');
  for (const [eventId, count] of conditionEventCounts)
    if (
      (REPEATED_CONDITION_EVENTS.has(eventId) && count !== 2) ||
      (!REPEATED_CONDITION_EVENTS.has(eventId) && count !== 1)
    )
      throw new Error(`condition event cardinality drift: ${eventId}`);
  if (
    conditionEventCounts.size !==
    EXACT_COUNTS.conditionApplications - REPEATED_CONDITION_EVENTS.size
  )
    throw new Error('condition event cardinality closure drift');

  const ca006 = (registry.conditionApplications as Array<Record<string, unknown>>).find(
    (row) => row.id === 'CA-006',
  );
  if (
    !ca006 ||
    ca006.operationId !== 'PXI-REDACT-PROJECTION/v1' ||
    ca006.fromStateId !== 'PROJECTION_VALIDATED_RAW_LIVE' ||
    ca006.eventId !== 'REDACTION_IMPOSSIBLE' ||
    ca006.toStateId !== 'OUTCOME_SELECTED_RAW_LIVE' ||
    ca006.rawStateEffectId !== 'LIVE' ||
    ca006.adapterEffectId !== 'RAW_OWNER_RETAINED' ||
    object(ca006.disposition, 'CA-006.disposition').conditionDefinitionId !== 'EXP-COND-001'
  )
    throw new Error('CA-006: redaction failure safe-problem join drift');
  const exp001 = conditionDefinitions.find((row) => row.id === 'EXP-COND-001');
  if (!exp001 || exp001.code !== 'PC-INTEGRATION-5002')
    throw new Error('CA-006: redaction condition public disposition drift');
  if (
    (registry.lifecycleApplications as Array<Record<string, unknown>>).some(
      (row) => row.id === 'PXT-014' || row.eventId === 'REDACTION_FAILURE',
    )
  )
    throw new Error('contradictory PXT-014 redaction representation remains');

  for (const row of registry.conditionApplications as Array<Record<string, unknown>>) {
    const disposition = object(row.disposition, `${row.id}.disposition`);
    if (disposition.kind !== 'CONDITION')
      throw new Error(`${row.id}: public success reachable from condition application`);
  }
  for (const row of registry.contributionApplications as Array<Record<string, unknown>>) {
    if (
      row.toStateId !== 'EVIDENCE_SEALED' ||
      row.rawStateEffectId !== 'REQUIRES_NEVER_CREATED_OR_DISPOSED'
    )
      throw new Error(`${row.id}: evidence/raw-state law drift`);
  }
  for (const row of registry.cancellationApplications as Array<Record<string, unknown>>) {
    if (
      String(row.fromStateId).includes('RAW_LIVE') &&
      row.rawStateEffectId !== 'LIVE' &&
      row.rawStateEffectId !== 'UNCHANGED'
    )
      throw new Error(`${row.id}: cancellation raw ownership drift`);
    if (
      (row.fromStateId === 'RELEASED' || row.fromStateId === 'EVIDENCE_SEALED') &&
      (row.fromStateId !== row.toStateId ||
        row.rawStateEffectId !== 'UNCHANGED' ||
        row.deliveryEffectId !== 'UNCHANGED' ||
        row.adapterEffectId !== 'NONE')
    )
      throw new Error(`${row.id}: late cancellation is not an exact no-op`);
  }
  for (const row of registry.lifecycleApplications as Array<Record<string, unknown>>) {
    if (
      row.toStateId === 'RELEASED' &&
      !(
        row.deliveryEffectId === 'RELEASED' &&
        (row.rawStateEffectId === 'NEVER_CREATED' || row.rawStateEffectId === 'DISPOSED')
      )
    )
      throw new Error(`${row.id}: release before raw safety closure`);
  }

  const reachable = new Set(['OPEN']);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [from, to] of edges)
      if (reachable.has(from) && !reachable.has(to)) {
        reachable.add(to);
        changed = true;
      }
  }
  for (const state of states)
    if (!reachable.has(state)) throw new Error(`unreachable state: ${state}`);

  const semanticSha256 = sha256(JSON.stringify(registry));

  return {
    sourceAnchors: sourceAnchors.length,
    operations: operationDefinitions.length,
    conditions: conditionDefinitions.length,
    results: resultDefinitions.length,
    lifecycleApplications: (registry.lifecycleApplications as unknown[]).length,
    conditionApplications: (registry.conditionApplications as unknown[]).length,
    cancellationApplications: (registry.cancellationApplications as unknown[]).length,
    contributionApplications: (registry.contributionApplications as unknown[]).length,
    reachableStates: reachable.size,
    semanticSha256,
  };
};

export const validateExecutionRegistry = (value: unknown): RegistrySummary => {
  const summary = validateExecutionRegistryRelations(value);
  if (summary.semanticSha256 !== expectedExecutionRegistrySha256)
    throw new Error('registry: final integrity digest mismatch');
  return summary;
};

assertExactSet(
  Object.keys(protectedOpenApiSha256ByPath),
  protectedOpenApiOutputs,
  'protected OpenAPI constant',
);
if (canonicalPathOrderedDigest(protectedOpenApiSha256ByPath) !== expectedProtectedOpenApiDigest)
  throw new Error('protected OpenAPI digest constant mismatch');
