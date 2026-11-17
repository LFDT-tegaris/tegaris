export const transactionKinds = [
  'wallet-binding',
  'provider-profile',
  'indexer-admission',
  'provider-observation-renewal',
  'runtime-activation',
  'runtime-profile-binding',
  'policy-activation-renewal',
  'provider-qualification',
  'protected-proof-retention',
  'protected-proof-access',
  'module-registration',
  'module-install',
  'module-enable',
  'contract-abi',
  'contract-asset',
  'contract-binding',
  'contract-method',
  'evidence-export',
  'evidence-deletion',
  'evidence-deletion-runtime',
  'evidence-deletion-fact',
  'evidence-deletion-candidate',
  'evidence-deletion-batch',
  'evidence-deletion-continuation',
  'evidence-deletion-raw',
  'evidence-deletion-raw-continuation',
  'evidence-deletion-search',
  'evidence-deletion-normalized',
  'evidence-deletion-projection-continuation',
  'evidence-hold',
  'evidence-hold-release',
  'evidence-participant-hold',
  'evidence-participant-hold-release',
  'retention-policy',
  'retention-policy-retire',
  'deployment-policy',
  'deployment-intent',
  'deployment-submission',
  'native-value',
  'cigl-analysis',
  'cigl-observation',
  'cigl-review',
  'cigl-grant',
  'cigl-grant-status',
  'cigl-settings',
  'cigl-activation',
] as const;
export type TransactionKind = (typeof transactionKinds)[number];
export interface TransactionField {
  name: string;
  label: string;
  json?: boolean;
  multiline?: boolean;
  optional?: boolean;
  choices?: string[];
}
export interface TransactionForm {
  label: string;
  help: string;
  fields: TransactionField[];
}
const target: TransactionField = { name: 'targetRef', label: 'Resource reference' };
const revision: TransactionField = { name: 'expectedRevision', label: 'Expected revision' };
export const transactionForms: Record<TransactionKind, TransactionForm> = {
  'runtime-profile-binding': {
    label: 'Bind a permission profile',
    help: 'Choose an unactivated runtime target and its permission profile name. An independent checker approves the binding. Workload permissions and runtime activation are managed separately.',
    fields: [
      { name: 'runtimeTargetRef', label: 'Runtime target' },
      { name: 'targetRevision', label: 'Selected target revision' },
      { name: 'targetProfileId', label: 'Permission profile name' },
    ],
  },
  'policy-activation-renewal': {
    label: 'Renew activation of the published policy',
    help: 'Review the current authority epoch, successful simulation and exact target predecessors for an unexecuted occurrence. Independent approval and fresh authentication activate the existing compiled policy without changing its semantics. The original release approval remains historical evidence.',
    fields: [target, revision],
  },
  'wallet-binding': {
    label: 'Bind a wallet address',
    help: 'Associate a public wallet address with an active subject in the selected Participant. Independent approval and fresh authentication are required. This association grants no transaction permission. Never enter a private key.',
    fields: [
      { name: 'walletBindingId', label: 'New wallet binding ID (UUIDv7)' },
      { name: 'subjectId', label: 'Active subject ID (UUIDv7)' },
      { name: 'chainId', label: 'Chain ID' },
      { name: 'walletAddress', label: 'Public wallet address (lowercase 0x)' },
    ],
  },
  'runtime-activation': {
    label: 'Activate runtime configuration',
    help: 'Read the current target and review its eligible configuration digest. Independent approval requests activation; read the target again to confirm actual active state. Missing policy, provider, indexer or module prerequisites prevent activation.',
    fields: [target, revision],
  },
  'indexer-admission': {
    label: 'Admit a chain reader',
    help: 'Independent approval and fresh authentication admit the exact reader profile. Read its operation and profile again to confirm native qualification. Admission does not grant contract access.',
    fields: [
      target,
      revision,
      { name: 'inputDigest', label: 'Reader profile artifact digest (sha256)' },
    ],
  },
  'provider-profile': {
    label: 'Register a provider',
    help: 'Register an endpoint secret reference and its expected behavior fingerprint. Independent approval and fresh authentication are required. Registration grants no runtime authority; qualification is separate.',
    fields: [
      { name: 'chainId', label: 'Chain ID' },
      { name: 'endpointSecretRef', label: 'Endpoint secret reference' },
      { name: 'behaviorFingerprint', label: 'Expected behavior fingerprint (sha256)' },
    ],
  },
  'provider-qualification': {
    label: 'Qualify a provider',
    help: 'Qualify the exact provider revision after a fresh observation has moved it to SHADOW. Approval admits asynchronous work; read the provider again to confirm the outcome.',
    fields: [
      target,
      revision,
      { name: 'inputDigest', label: 'Qualification input digest (sha256)' },
    ],
  },
  'provider-observation-renewal': {
    label: 'Renew provider observation',
    help: 'Review the current provider and retain its behavior fingerprint. Independent approval and fresh authentication return it to REGISTERED for a new observation. Wait for SHADOW before requesting qualification. Renewal does not grant runtime authority.',
    fields: [target, revision],
  },
  'evidence-deletion-runtime': {
    label: 'Retire a withdrawn runtime artifact',
    help: 'Review the next original input under the runtime retention policy. Independent approval and fresh authentication are required. Holds, references, archive custody and native withdrawal are checked again before deletion; the signed archive remains retained.',
    fields: [
      { name: 'retentionPolicyId', label: 'Runtime retention policy reference' },
      {
        name: 'previousDeletionJobId',
        label: 'Previous retirement result reference',
        optional: true,
      },
    ],
  },
  'evidence-deletion-candidate': {
    label: 'Retire a candidate projection payload',
    help: 'Choose a catalogued candidate manifest, installed target and candidate retention policy. Independent approval and fresh authentication admit an attempt. The native owner checks current source conditions before the signed physical outcome confirms deletion. Original custody, identity and lineage remain retained.',
    fields: [
      { name: 'evidenceId', label: 'Candidate manifest evidence reference' },
      { name: 'hostDigest', label: 'Selected installed target digest' },
      { name: 'retentionPolicyId', label: 'Candidate retention policy reference' },
    ],
  },
  'evidence-deletion-fact': {
    label: 'Retire an admitted Fact payload',
    help: 'Choose a catalogued Fact, installed target and Fact retention policy. The service derives the exact native row. Independent approval and fresh authentication admit an attempt; the signed physical outcome separately confirms deletion. Custody, identity and lineage remain retained.',
    fields: [
      { name: 'evidenceId', label: 'Fact evidence reference' },
      { name: 'hostDigest', label: 'Selected installed target digest' },
      { name: 'retentionPolicyId', label: 'Fact retention policy reference' },
    ],
  },
  'evidence-deletion-search': {
    label: 'Delete search projections',
    help: 'Review up to 16 supported authentication or retention-policy receipt catalogue rows. Each approved batch retires one row after its own search retention policy and all preservation and reference checks pass. Original receipts, business state and archived evidence retain their separate lifetimes.',
    fields: [{ name: 'evidenceId', label: 'Starting catalogue evidence reference' }],
  },
  'evidence-deletion-normalized': {
    label: 'Delete normalized evidence projections',
    help: 'Review up to 16 derived RPC or Fact records. RPC records require archived completion evidence. Facts require verified historical lineage and complete source checkpoints. Unfinished requests, unresolved references and open gaps or reorgs stay protected. Each approved batch retires one projection while preserving original evidence and required lineage.',
    fields: [{ name: 'evidenceId', label: 'Starting evidence reference' }],
  },
  'evidence-deletion-projection-continuation': {
    label: 'Continue projection deletion',
    help: 'Read the previous signed result and review the next fixed target. Current policy, holds, references and archive checkpoints are rechecked. Each projection needs independent approval and fresh authentication.',
    fields: [{ name: 'deletionJobId', label: 'Previous projection deletion result' }],
  },
  'evidence-deletion-raw': {
    label: 'Delete retained protected proof ciphertext',
    help: 'Review an ordered selection of up to 16 retained protected proofs. Each approved batch removes one encrypted local copy under its own raw-source retention policy. Original Identity assertions, immutable proof metadata, access history and archives retain their separate lifetimes.',
    fields: [{ name: 'objectRef', label: 'Starting protected object reference' }],
  },
  'evidence-deletion-raw-continuation': {
    label: 'Continue protected proof deletion',
    help: 'Read the preceding signed raw-proof deletion result. The service rechecks the next exact object, source, references, holds, retention and archive checkpoints. Each object needs independent approval and fresh authentication.',
    fields: [{ name: 'deletionJobId', label: 'Previous protected proof deletion result' }],
  },
  'protected-proof-retention': {
    label: 'Retain a protected Identity proof',
    help: 'Select a catalogued authentication occurrence. Review its exact Identity assertion provenance and retention deadline with an independent checker. Raw proof bytes remain separate from the ordinary catalogue and exports.',
    fields: [
      { name: 'evidenceId', label: 'Authentication evidence reference' },
      { name: 'purpose', label: 'Protected retention purpose' },
      { name: 'caseReference', label: 'Case reference' },
      { name: 'retainUntil', label: 'Retain until (UTC, six fractional digits)' },
    ],
  },
  'protected-proof-access': {
    label: 'Request protected proof access',
    help: 'An independent checker approves the exact object version, purpose, case and recipient. Fresh authentication binds access to your current session for at most five minutes. Delivery can be consumed once; a lost response cannot be downloaded again.',
    fields: [
      { name: 'objectRef', label: 'Protected object reference' },
      { name: 'purpose', label: 'Protected access purpose' },
      { name: 'caseReference', label: 'Case reference' },
      { name: 'expiresAt', label: 'Access expires at (UTC, within five minutes)' },
    ],
  },
  'contract-abi': {
    label: 'Import contract ABI',
    help: 'Choose an ABI JSON file or paste the original array. File selection records the filename and selection time. Review the file and reason; change its provenance under Source details when needed. Import does not grant method access.',
    fields: [
      { name: 'abiSource', label: 'Original ABI JSON array', multiline: true },
      {
        name: 'source',
        label: 'Source type',
        choices: ['LOCAL_FIXTURE', 'SOURCE_REPOSITORY', 'AUTHENTICATED_REGISTRY'],
      },
      { name: 'locator', label: 'Source location or artifact reference' },
      { name: 'retrievedAt', label: 'Source retrieved at (UTC timestamp)' },
    ],
  },
  'contract-asset': {
    label: 'Register logical contract',
    help: 'Create a named contract asset in the current Participant and privacy domain after independent approval. Bind its actual deployed code and ABI separately.',
    fields: [
      { name: 'logicalName', label: 'Logical contract name' },
      { name: 'displayName', label: 'Display name' },
    ],
  },
  'contract-binding': {
    label: 'Bind deployed contract and ABI',
    help: 'Bind an approved logical contract to its actual network, deployed address, code digest and imported ABI. Use the planned UUID already admitted by the Platform RPC envelope. This registration does not grant user access or deploy code.',
    fields: [
      { name: 'resourceId', label: 'Planned runtime binding ID (UUIDv7)' },
      { name: 'logicalContractId', label: 'Logical contract resource reference' },
      { name: 'chainId', label: 'Chain ID' },
      { name: 'networkId', label: 'Network ID' },
      { name: 'genesisDigest', label: 'Genesis digest' },
      { name: 'contractAddress', label: 'Deployed contract address' },
      { name: 'codeDigest', label: 'Deployed code digest' },
      { name: 'abiArtifactId', label: 'Imported ABI resource reference' },
      { name: 'abiDigest', label: 'Canonical ABI digest from import readback' },
      { name: 'abiVersion', label: 'ABI version' },
      { name: 'proxyAddress', label: 'Proxy address, if applicable', optional: true },
      {
        name: 'implementationAddress',
        label: 'Implementation address, if applicable',
        optional: true,
      },
      {
        name: 'implementationCodeDigest',
        label: 'Implementation code digest, if applicable',
        optional: true,
      },
      {
        name: 'transactionPolicy',
        label: 'Transaction policy JSON, if required',
        json: true,
        optional: true,
      },
    ],
  },
  'contract-method': {
    label: 'Register contract method policy',
    help: 'Review one exact ABI method, its required roles and execution requirements. Independent approval activates this method policy in the current scope. User role assignments, wallet bindings and runtime policy activation remain separate requirements.',
    fields: [
      { name: 'runtimeBindingId', label: 'Contract runtime binding reference' },
      { name: 'abiArtifactId', label: 'Imported ABI resource reference' },
      { name: 'abiDigest', label: 'Canonical ABI digest' },
      {
        name: 'canonicalSignature',
        label: 'Canonical method signature, for example setValue(uint256)',
      },
      { name: 'effect', label: 'Method effect', choices: ['READ', 'WRITE'] },
      { name: 'requiredRoles', label: 'Required role names (JSON array)', json: true },
      {
        name: 'approvalRequirement',
        label: 'Execution approval',
        choices: ['NONE', 'SINGLE', 'MAKER_CHECKER'],
      },
      { name: 'mfaRequirement', label: 'Execution authentication', choices: ['NONE', 'WEBAUTHN'] },
      {
        name: 'environments',
        label: 'Allowed environments (JSON array: LOCAL, DEVELOPMENT, TEST or PRODUCTION)',
        json: true,
      },
      {
        name: 'argumentRuleVersionId',
        label: 'Existing argument rule version reference',
        optional: true,
      },
      { name: 'rpcMethodPolicyDigest', label: 'RPC method policy digest' },
      { name: 'nestedCallSetDigest', label: 'Nested call set digest' },
    ],
  },
  'module-install': {
    label: 'Install a module release',
    help: 'Read the registered release and review its exact revision. Independent approval installs the module with its verified dependencies; activation is separate.',
    fields: [target, revision],
  },
  'module-enable': {
    label: 'Activate an installed module',
    help: 'Read the installed release and review its exact revision. Independent approval activates the verified module and configuration. Required dependencies must already be active.',
    fields: [target, revision],
  },
  'module-registration': {
    label: 'Register a module release',
    help: 'Review the exact signed release and request independent approval. Registration preserves the release and its dependencies; installation and activation are separate actions.',
    fields: [
      { name: 'name', label: 'Module name' },
      { name: 'semanticVersion', label: 'Exact version' },
      { name: 'manifestDigest', label: 'Manifest digest' },
      { name: 'supportProfile', label: 'Support profile', choices: ['R1'] },
    ],
  },
  'evidence-deletion-batch': {
    label: 'Start a local deletion sequence',
    help: 'Select a catalogue record to review an ordered selection of up to 16 local ciphertext objects. Each batch deletes one complete object after independent approval and fresh authentication. The signed result fixes the next target; source records, metadata and archives retain their own lifetimes.',
    fields: [{ name: 'evidenceId', label: 'Starting evidence record reference' }],
  },
  'evidence-deletion-continuation': {
    label: 'Continue local deletion',
    help: 'Enter the preceding signed deletion result. The service resolves the next object and rechecks policy, holds and archive coverage. Review and approve each batch separately; recover uncertain results through the original operation.',
    fields: [{ name: 'deletionJobId', label: 'Previous deletion result reference' }],
  },
  'evidence-deletion': {
    label: 'Delete a local evidence payload',
    help: 'Select a record in the evidence catalogue or enter its reference. The service resolves its complete ciphertext object and checks the active policy, holds and archive coverage. Independent approval and fresh authentication are required. Source records, custody metadata and other stored copies keep their separate lifetimes.',
    fields: [{ name: 'evidenceId', label: 'Evidence record reference' }],
  },
  'retention-policy': {
    label: 'Activate a retention policy version',
    help: 'Set explicit requirements for one data class in the current privacy domain. Retire its previous version first, then name that predecessor. Activation does not request deletion.',
    fields: [
      {
        name: 'dataClass',
        label: 'Retained data class',
        choices: [
          'RAW_SOURCE_BODY',
          'NORMALIZED_JSON_PROJECTION',
          'SEARCH_PROJECTION',
          'RUNTIME_ARTIFACT',
          'ADMITTED_FACT',
          'CANDIDATE_PROJECTION',
          'AUDIT_EVIDENCE',
          'NOTIFICATION_PAYLOAD',
          'OUTBOX_INBOX',
          'IDENTITY_RECORD',
        ],
      },
      { name: 'policyVersion', label: 'Retention policy version' },
      { name: 'predecessorPolicyId', label: 'Previous retention policy reference', optional: true },
      { name: 'retentionPeriodMs', label: 'Retention period in milliseconds' },
      { name: 'localGraceMs', label: 'Local grace in milliseconds' },
      {
        name: 'sinkQuorum',
        label: 'Required durable sink acknowledgements',
        choices: ['0', '1', '2', '3', '4', '5', '6', '7', '8'],
      },
      {
        name: 'deletionMode',
        label: 'Deletion mode',
        choices: ['ROW_DELETE', 'PROJECTION_DELETE', 'IDENTIFIER_ALIAS', 'CRYPTO_SHRED'],
      },
      {
        name: 'makerCheckerRequired',
        label: 'Require independent deletion approval',
        choices: ['true', 'false'],
      },
    ],
  },
  'retention-policy-retire': {
    label: 'Retire a retention policy version',
    help: 'Close this exact active version after independent approval and fresh authentication. Preserve its history; a successor needs its own approved activation.',
    fields: [target, revision],
  },
  'evidence-hold': {
    label: 'Preserve evidence under a hold',
    help: 'Preserve matching evidence in the current privacy domain, including future matches. An active rule blocks deletion while sink coverage is pending. A separate checker must approve it.',
    fields: [
      { name: 'holdKind', label: 'Hold kind', choices: ['LEGAL', 'REGULATORY', 'INCIDENT'] },
      {
        name: 'selectorType',
        label: 'Evidence to preserve',
        choices: [
          'PRIVACY_DOMAIN',
          'SEQUENCE_RANGE',
          'DIGEST',
          'PROJECTION',
          'FACT_TYPE_KEY',
          'BLOCK_RANGE',
          'GENERATION',
        ],
      },
      { name: 'streamId', label: 'Evidence stream to preserve' },
      { name: 'fromSequence', label: 'First sequence to preserve' },
      {
        name: 'throughSequence',
        label: 'Last sequence; leave blank for future records',
        optional: true,
      },
      { name: 'recordDigest', label: 'Receipt digest' },
      { name: 'projectionId', label: 'Projection reference' },
      {
        name: 'factType',
        label: 'Fact type',
        choices: ['CONTRACT_STATE_CALL', 'RELATIONSHIP', 'EXTERNAL_DECISION'],
      },
      { name: 'factProfileId', label: 'Fact profile reference' },
      {
        name: 'factKeyDigest',
        label: 'Fact key digest; leave blank for every key in this profile',
        optional: true,
      },
      { name: 'chainId', label: 'Chain ID' },
      { name: 'genesisDigest', label: 'Genesis digest' },
      { name: 'fromBlock', label: 'First block to preserve' },
      { name: 'throughBlock', label: 'Last block; leave blank for future blocks', optional: true },
      {
        name: 'generationKind',
        label: 'Generation kind',
        choices: ['RUNTIME_CONFIGURATION', 'CANONICAL_FACT'],
      },
      { name: 'generationId', label: 'Runtime configuration generation reference' },
      { name: 'canonicalGeneration', label: 'Canonical Fact generation number' },
    ],
  },
  'evidence-participant-hold': {
    label: 'Preserve evidence across a Participant',
    help: 'Requires an explicit Participant-wide preservation grant in the Participant root context and an independent checker. Preserves existing and future evidence across its privacy domains. It grants no access to that evidence.',
    fields: [
      { name: 'holdKind', label: 'Hold kind', choices: ['LEGAL', 'REGULATORY', 'INCIDENT'] },
    ],
  },
  'evidence-participant-hold-release': {
    label: 'Release a Participant-wide evidence hold',
    help: 'Use the root context and explicit Participant-wide release grant. An independent checker and fresh authentication are required. Release does not delete evidence.',
    fields: [target, revision],
  },
  'evidence-hold-release': {
    label: 'Release an evidence hold',
    help: 'Release the exact active hold after independent approval and fresh authentication. Release does not delete evidence or remove other holds.',
    fields: [target, revision],
  },
  'evidence-export': {
    label: 'Export selected evidence',
    help: 'Review the exact stored record range. A separate checker and fresh authentication are required before the export can run.',
    fields: [target, revision, { name: 'inputDigest', label: 'Selected request digest' }],
  },
  'deployment-policy': {
    label: 'Publish deployment policy',
    help: 'Specify the exact init code, runtime code hash, named creation route and transaction limits. Publication requires separate policy activation before use.',
    fields: [{ name: 'definition', label: 'Deployment policy definition', json: true }],
  },
  'deployment-intent': {
    label: 'Prepare deployment',
    help: 'Prepare the exact unsigned transaction against a published policy, wallet and active runtime target. Preparation grants no permission to send.',
    fields: [
      { name: 'deploymentPolicyId', label: 'Deployment policy reference' },
      { name: 'runtimeTargetId', label: 'Runtime target reference' },
      { name: 'walletBindingId', label: 'Wallet binding reference' },
      { name: 'executionWorkloadId', label: 'Execution workload reference', optional: true },
      {
        name: 'nativeValueAuthorizationId',
        label: 'Native Value authorization reference',
        optional: true,
      },
      { name: 'signingPayload', label: 'Unsigned transaction bytes', multiline: true },
    ],
  },
  'deployment-submission': {
    label: 'Submit signed deployment',
    help: 'Submit the exact signed transaction for a prepared intent. A replacement requires its own prepared intent, approval and predecessor operation reference. An uncertain result must be read back before any new submission.',
    fields: [
      { name: 'deploymentIntentId', label: 'Deployment intent reference' },
      { name: 'signedTransaction', label: 'Signed transaction bytes', multiline: true },
      { name: 'predecessorOperationId', label: 'Predecessor operation reference', optional: true },
    ],
  },
  'native-value': {
    label: 'Authorize Native Value',
    help: 'Review a separate one-use endowment authorization for this wallet and executor. This does not submit a transaction.',
    fields: [
      { name: 'walletBindingId', label: 'Wallet binding reference' },
      { name: 'executionWorkloadId', label: 'Execution workload reference', optional: true },
      { name: 'chainId', label: 'Chain ID' },
      { name: 'networkId', label: 'Network ID' },
      { name: 'genesisDigest', label: 'Genesis digest' },
      { name: 'amountMode', label: 'Amount mode', choices: ['EXACT', 'MAXIMUM'] },
      { name: 'maxAmountWei', label: 'Amount in wei' },
      { name: 'validUntil', label: 'Valid until (UTC timestamp)' },
    ],
  },
  'cigl-analysis': {
    label: 'Create interaction analysis',
    help: 'Bind the analysis to the exact transaction hash, workload, runtime generation, method and source revisions.',
    fields: [{ name: 'definition', label: 'Analysis definition', json: true }],
  },
  'cigl-observation': {
    label: 'Record signed observation',
    help: 'Attach the actual target-signed analysis receipt. The owner verifies the receipt and its exact source bindings.',
    fields: [
      target,
      revision,
      { name: 'signedReceipt', label: 'Signed analysis receipt', multiline: true },
    ],
  },
  'cigl-review': {
    label: 'Review interaction actions',
    help: 'Select exact observed action digests and maximum values. An approved review queues profile compilation; it does not activate the profile.',
    fields: [target, revision, { name: 'review', label: 'Action review definition', json: true }],
  },
  'cigl-grant': {
    label: 'Create method grant',
    help: 'Name the method, subject, surface and effect. A shared grant starts disabled and requires explicit activation.',
    fields: [
      { name: 'definition', label: 'Method grant definition', json: true },
      { name: 'expectedRuntimeBindingRevision', label: 'Expected runtime binding revision' },
      { name: 'expectedMethodRevision', label: 'Expected method revision' },
    ],
  },
  'cigl-grant-status': {
    label: 'Change method grant status',
    help: 'Activate or disable the exact revision. Disabling a source grant invalidates dependent runtime authority.',
    fields: [
      target,
      revision,
      { name: 'status', label: 'Grant status', choices: ['ACTIVE', 'DISABLED'] },
      { name: 'dependencyBundle', label: 'Verified dependency bundle', json: true, optional: true },
    ],
  },
  'cigl-settings': {
    label: 'Publish interaction settings',
    help: 'Publish explicit mode, bounded trace limits and supported preflight/post-mine behavior. Unsupported assurance settings are rejected.',
    fields: [{ name: 'definition', label: 'Interaction settings definition', json: true }],
  },
  'cigl-activation': {
    label: 'Activate compiled profiles',
    help: 'Select exact compiled profile revisions and source digests for the current runtime generation. For renewal, include the approved activation occurrence, its revision and policy generation digest. Read back the actual target state after activation.',
    fields: [
      target,
      revision,
      { name: 'expectedGenerationDigest', label: 'Expected generation digest' },
      { name: 'participantEpoch', label: 'Participant epoch' },
      { name: 'profiles', label: 'Compiled profile selections', json: true },
      { name: 'policyRenewal', label: 'Approved policy renewal', json: true, optional: true },
    ],
  },
};

export function transactionFields(
  kind: TransactionKind,
  values: Record<string, string>,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const field of visibleTransactionFields(kind, values)) {
    const text =
      kind === 'contract-abi' && field.name === 'abiSource'
        ? (values[field.name] ?? '')
        : (values[field.name] ?? '').trim();
    if (!text && field.optional) continue;
    if (!text) throw new Error(`${field.label} is required.`);
    try {
      result[field.name] = field.json ? JSON.parse(text) : text;
    } catch {
      throw new Error(`${field.label} must be valid JSON.`);
    }
  }
  if (kind === 'retention-policy') {
    if (!['true', 'false'].includes(String(result.makerCheckerRequired)))
      throw new Error('Choose whether independent deletion approval is required.');
    const { predecessorPolicyId, ...policy } = result;
    return {
      predecessorPolicyId: predecessorPolicyId ?? null,
      policy: {
        ...policy,
        sinkQuorum: Number(policy.sinkQuorum),
        makerCheckerRequired: policy.makerCheckerRequired === 'true',
      },
    };
  }
  if (kind === 'evidence-participant-hold')
    return { holdKind: result.holdKind, selector: { type: 'PARTICIPANT' } };
  if (kind === 'evidence-hold') {
    const selector = {
      type: result.selectorType,
      ...(result.selectorType === 'SEQUENCE_RANGE'
        ? {
            streamId: result.streamId,
            fromSequence: result.fromSequence,
            throughSequence: result.throughSequence ?? null,
          }
        : {}),
      ...(result.selectorType === 'DIGEST' ? { recordDigest: result.recordDigest } : {}),
      ...(result.selectorType === 'PROJECTION' ? { projectionId: result.projectionId } : {}),
      ...(result.selectorType === 'FACT_TYPE_KEY'
        ? {
            factType: result.factType,
            factProfileId: result.factProfileId,
            factKeyDigest: result.factKeyDigest ?? null,
          }
        : {}),
      ...(result.selectorType === 'BLOCK_RANGE'
        ? {
            chainId: result.chainId,
            genesisDigest: result.genesisDigest,
            fromBlock: result.fromBlock,
            throughBlock: result.throughBlock ?? null,
          }
        : {}),
      ...(result.selectorType === 'GENERATION'
        ? {
            generation:
              result.generationKind === 'CANONICAL_FACT'
                ? {
                    kind: result.generationKind,
                    factProfileId: result.factProfileId,
                    canonicalGeneration: result.canonicalGeneration,
                  }
                : { kind: result.generationKind, generationId: result.generationId },
          }
        : {}),
    };
    return { holdKind: result.holdKind, selector };
  }
  return result;
}

export function visibleTransactionFields(kind: TransactionKind, values: Record<string, string>) {
  return transactionForms[kind].fields.filter(
    (field) =>
      kind !== 'evidence-hold' ||
      ['holdKind', 'selectorType'].includes(field.name) ||
      (values.selectorType === 'SEQUENCE_RANGE' &&
        ['streamId', 'fromSequence', 'throughSequence'].includes(field.name)) ||
      (values.selectorType === 'DIGEST' && field.name === 'recordDigest') ||
      (values.selectorType === 'PROJECTION' && field.name === 'projectionId') ||
      (values.selectorType === 'FACT_TYPE_KEY' &&
        ['factType', 'factProfileId', 'factKeyDigest'].includes(field.name)) ||
      (values.selectorType === 'BLOCK_RANGE' &&
        ['chainId', 'genesisDigest', 'fromBlock', 'throughBlock'].includes(field.name)) ||
      (values.selectorType === 'GENERATION' &&
        (field.name === 'generationKind' ||
          (values.generationKind === 'CANONICAL_FACT'
            ? ['factProfileId', 'canonicalGeneration'].includes(field.name)
            : field.name === 'generationId'))),
  );
}
