// @generated from schemas/json/privacy-explorer.schema.json; do not edit.
export const privacyExplorerExecutionRegistry = {
  "version": "2.0",
  "designId": "I07-G2-B1-V1",
  "sourceAnchors": [
    {
      "id": "SA-AF22",
      "authorityClass": "C17_NORMATIVE",
      "artifactPath": "SPECIFICATIONS/FACTS/explorer-fact-profile.md",
      "artifactSha256": "a51402d686780069f24ac1b6b8dad84b1e4153486daf4fde7154991990bdba40",
      "clauseId": "AF-22 sections 1-5"
    },
    {
      "id": "SA-ADAPTER-REGISTRY",
      "authorityClass": "C17_NORMATIVE",
      "artifactPath": "SPECIFICATIONS/INTERFACES/adapter-interface-registry.yaml",
      "artifactSha256": "bdef9896af38924ded713eb31f1e3c05faa6df077a3fdac539b657139f71be18",
      "clauseId": "adapters[adapterId=ADAPTER-EXPLORER-CONSUMER-V1]"
    },
    {
      "id": "SA-SDK-EXPLORER",
      "authorityClass": "C17_NORMATIVE",
      "artifactPath": "SPECIFICATIONS/INTERFACES/sdk-and-adapter-interfaces.md",
      "artifactSha256": "a9f1799a988d9da8f15837601df1a2e91f56e19b76ba761d701b3212240a63c6",
      "clauseId": "ExplorerConsumerAdapterV1"
    },
    {
      "id": "SA-AD-SR04-013",
      "authorityClass": "C17_NORMATIVE",
      "artifactPath": "GOVERNANCE/decision-and-supersession-map.jsonl",
      "artifactSha256": "397c0becca904297e172141d8bfe18712b255b05d0bd1b3f0f187da15680aae1",
      "clauseId": "decisionId=AD-SR04-013-PRIVACY-EXPLORER"
    },
    {
      "id": "SA-ERROR-REGISTRY",
      "authorityClass": "C17_NORMATIVE",
      "artifactPath": "SPECIFICATIONS/INTERFACES/error-registry.yaml",
      "artifactSha256": "7ac6a80aa97a75fc271e903028d289b25613470bea7b57dc92ecdf72a9eb19b9",
      "clauseId": "entries[code=PC-*]"
    },
    {
      "id": "SA-PRIV-EXPLORER-011",
      "authorityClass": "C17_NORMATIVE",
      "artifactPath": "QUALITY/privacy-controls.jsonl",
      "artifactSha256": "dc30ca3894c30aa14949173fb245dd229556150bcf24fe0708801b939b1bacad",
      "clauseId": "controlId=PRIV-EXPLORER-011"
    }
  ],
  "adapterMethods": [
    {
      "name": "readGovernedProjection",
      "requestType": "ExplorerProjectionRequestV1",
      "responseType": "ExplorerProjectionResultV1",
      "deadline": "CALLER_AND_EXPORT_PROFILE",
      "idempotency": "SAFE_BY_CURSOR_AND_QUERY_DIGEST",
      "retry": "BOUNDED_READ_RETRY",
      "cancellation": "NO_NEW_EFFECT_AFTER_CANCELLATION_EXACT_OCCURRENCE",
      "error": "ONLY_REGISTERED_SAFE_PROBLEM_OR_TYPED_AMBIGUITY",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateReadGovernedProjectionBoundary",
      "consumerId": "validateProjection"
    },
    {
      "name": "verifyEvidenceReference",
      "requestType": "EvidenceReferenceV1",
      "responseType": "EvidenceVerificationResultV1",
      "deadline": "CALLER",
      "idempotency": "SAFE_BY_DIGEST",
      "retry": "NONE_AUTOMATIC",
      "cancellation": "NO_NEW_EFFECT_AFTER_CANCELLATION_EXACT_OCCURRENCE",
      "error": "ONLY_REGISTERED_SAFE_PROBLEM_OR_TYPED_AMBIGUITY",
      "constructorId": "createEvidenceVerificationBoundary",
      "validatorId": "validateEvidenceReferenceBoundaryAndResult",
      "consumerId": "verifyEvidenceReference"
    }
  ],
  "states": [
    "OPEN",
    "CONTEXT_BOUND",
    "PREAUTHORIZED",
    "INTENT_NARROWED",
    "REQUEST_READY",
    "READ_IN_FLIGHT_NO_RAW",
    "RESPONSE_CAPTURED_RAW_LIVE",
    "PROJECTION_VALIDATED_RAW_LIVE",
    "PROJECTION_REDACTED_RAW_LIVE",
    "OUTCOME_SELECTED_RAW_LIVE",
    "OUTCOME_READY_NO_RAW",
    "OUTCOME_READY_RAW_DISPOSED",
    "CANCEL_PENDING_NO_RAW",
    "CANCEL_PENDING_RAW_LIVE",
    "RELEASED",
    "CANCELLED_CLOSED",
    "EVIDENCE_SEALED"
  ],
  "rawStates": [
    "NEVER_CREATED",
    "LIVE",
    "DISPOSED"
  ],
  "deliveryStates": [
    "PENDING",
    "SUPPRESSED",
    "RELEASED"
  ],
  "resultDefinitions": [
    {
      "id": "RESULT-COMPLETE",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "outcome": "COMPLETE",
      "truthState": "TRUE",
      "recordLawId": "RECORDS_ALLOWED",
      "cursorLawId": "GAP_FREE",
      "authorityEffectId": "NO_AUTHORITY"
    },
    {
      "id": "RESULT-PARTIAL",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "outcome": "PARTIAL",
      "truthState": "PARTIAL",
      "recordLawId": "RECORDS_ALLOWED",
      "cursorLawId": "PARTIAL_EXPLICIT",
      "authorityEffectId": "NO_AUTHORITY"
    },
    {
      "id": "RESULT-UNKNOWN",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "outcome": "UNKNOWN",
      "truthState": "UNKNOWN",
      "recordLawId": "RECORDS_EMPTY",
      "cursorLawId": "COMPLETENESS_UNPROVEN",
      "authorityEffectId": "NO_AUTHORITY"
    },
    {
      "id": "RESULT-UNAVAILABLE",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "outcome": "UNAVAILABLE",
      "truthState": "UNAVAILABLE",
      "recordLawId": "RECORDS_EMPTY",
      "cursorLawId": "SOURCE_UNAVAILABLE",
      "authorityEffectId": "NO_AUTHORITY"
    }
  ],
  "operationDefinitions": [
    {
      "id": "PXI-BIND-LOCAL-CONTEXT/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-PRIV-EXPLORER-011"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "TerminalAuthorizationV1"
      ],
      "outputDispositionKinds": [
        "INTERNAL",
        "CONDITION"
      ],
      "constructorId": "bindLocalContext",
      "validatorId": "validateTerminalAuthorization",
      "consumerId": "preauthorize"
    },
    {
      "id": "PXI-PREAUTHORIZE/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-PRIV-EXPLORER-011"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "PrivacyExplorerLocalContextV1",
        "RegisteredPurposeActionV1"
      ],
      "outputDispositionKinds": [
        "INTERNAL",
        "COMMON_TERMINAL_DENIAL"
      ],
      "constructorId": "preauthorize",
      "validatorId": "validateRegisteredPurposeAction",
      "consumerId": "narrowIntent"
    },
    {
      "id": "PXI-NARROW-INTENT/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "PrivacyExplorerPreauthorizedIntentV1",
        "PrivacyExplorerExportProfileV1",
        "PrivacyExplorerFilterPageV1"
      ],
      "outputDispositionKinds": [
        "INTERNAL",
        "CONDITION"
      ],
      "constructorId": "narrowIntent",
      "validatorId": "validateBoundedFilterPage",
      "consumerId": "createProjectionRequest"
    },
    {
      "id": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-ADAPTER-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "outputDispositionKinds": [
        "INTERNAL",
        "CONDITION"
      ],
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection"
    },
    {
      "id": "PXI-READ-GOVERNED-PROJECTION/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "outputDispositionKinds": [
        "INTERNAL",
        "CONDITION"
      ],
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection"
    },
    {
      "id": "PXI-VALIDATE-PROJECTION/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "outputDispositionKinds": [
        "INTERNAL",
        "CONDITION"
      ],
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection"
    },
    {
      "id": "PXI-REDACT-PROJECTION/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "PrivacyExplorerValidatedProjectionV1"
      ],
      "outputDispositionKinds": [
        "INTERNAL",
        "CONDITION"
      ],
      "constructorId": "redactProjection",
      "validatorId": "validateFieldAllowlistAndPrivacy",
      "consumerId": "releaseResult"
    },
    {
      "id": "PXI-RELEASE-RESULT/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "outputDispositionKinds": [
        "RESULT",
        "INTERNAL"
      ],
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer"
    },
    {
      "id": "PXI-RECORD-EVIDENCE/v1",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-PRIV-EXPLORER-011"
      ],
      "ownerId": "LS-CONTROL-API",
      "inputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "outputDispositionKinds": [
        "INTERNAL",
        "CONDITION"
      ],
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink"
    }
  ],
  "conditionDefinitions": [
    {
      "id": "EXP-COND-001",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-INTEGRATION-5002",
      "httpStatus": 409,
      "jsonRpcCode": -32052,
      "grpcStatus": "FAILED_PRECONDITION",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "AUTHORIZED_DETAIL",
      "publicTitle": "Request validation failed"
    },
    {
      "id": "EXP-COND-002",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-RUNTIME-3009",
      "httpStatus": 502,
      "jsonRpcCode": -32009,
      "grpcStatus": "FAILED_PRECONDITION",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "The service is unavailable"
    },
    {
      "id": "EXP-COND-003",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-OPS-9004",
      "httpStatus": 409,
      "jsonRpcCode": -32094,
      "grpcStatus": "FAILED_PRECONDITION",
      "truthState": "PARTIAL",
      "retryable": false,
      "disclosure": "AUTHORIZED_DETAIL",
      "publicTitle": "Partial result"
    },
    {
      "id": "EXP-COND-004",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-INTEGRATION-5001",
      "httpStatus": 503,
      "jsonRpcCode": -32051,
      "grpcStatus": "UNAVAILABLE",
      "truthState": "UNAVAILABLE",
      "retryable": true,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "The service is unavailable"
    },
    {
      "id": "EXP-COND-005",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-FACT-4002",
      "httpStatus": 412,
      "jsonRpcCode": -32032,
      "grpcStatus": "FAILED_PRECONDITION",
      "truthState": "STALE",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "The resource changed"
    },
    {
      "id": "EXP-COND-006",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-FACT-4003",
      "httpStatus": 409,
      "jsonRpcCode": -32033,
      "grpcStatus": "ABORTED",
      "truthState": "REORG",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "The resource changed"
    },
    {
      "id": "EXP-COND-007",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-RUNTIME-3011",
      "httpStatus": 409,
      "jsonRpcCode": -32011,
      "grpcStatus": "FAILED_PRECONDITION",
      "truthState": "CONFLICTING",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "The request conflicts with current state"
    },
    {
      "id": "EXP-COND-008",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-RUNTIME-3008",
      "httpStatus": 409,
      "jsonRpcCode": -32008,
      "grpcStatus": "FAILED_PRECONDITION",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "The request could not be completed"
    },
    {
      "id": "EXP-PARSE",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-DATA-6001",
      "httpStatus": 400,
      "jsonRpcCode": -32700,
      "grpcStatus": "INVALID_ARGUMENT",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "Malformed JSON"
    },
    {
      "id": "EXP-ENVELOPE",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY"
      ],
      "code": "PC-DATA-6002",
      "httpStatus": 400,
      "jsonRpcCode": -32600,
      "grpcStatus": "INVALID_ARGUMENT",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "Invalid request"
    },
    {
      "id": "EXP-BROWSER",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "code": "PC-DATA-6003",
      "httpStatus": 404,
      "jsonRpcCode": -32601,
      "grpcStatus": "NOT_FOUND",
      "truthState": "DENIED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "Resource is unavailable"
    },
    {
      "id": "EXP-PARAMETER",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "code": "PC-DATA-6004",
      "httpStatus": 400,
      "jsonRpcCode": -32602,
      "grpcStatus": "INVALID_ARGUMENT",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "Request validation failed"
    },
    {
      "id": "EXP-REPLAY",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-ADAPTER-REGISTRY"
      ],
      "code": "PC-RUNTIME-3007",
      "httpStatus": 409,
      "jsonRpcCode": -32007,
      "grpcStatus": "ABORTED",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "Replay rejected"
    },
    {
      "id": "EXP-DEADLINE",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-ADAPTER-REGISTRY"
      ],
      "code": "PC-OPS-9003",
      "httpStatus": 504,
      "jsonRpcCode": -32093,
      "grpcStatus": "DEADLINE_EXCEEDED",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "The service is unavailable"
    },
    {
      "id": "EXP-EVIDENCE",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "code": "PC-RUNTIME-3010",
      "httpStatus": 503,
      "jsonRpcCode": -32010,
      "grpcStatus": "FAILED_PRECONDITION",
      "truthState": "FAILED",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "The request could not be completed"
    },
    {
      "id": "EXP-ABSENCE",
      "tupleAuthorityClass": "C17_NORMATIVE",
      "publicTitleAuthorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-AF22"
      ],
      "code": "PC-FACT-4001",
      "httpStatus": 409,
      "jsonRpcCode": -32031,
      "grpcStatus": "FAILED_PRECONDITION",
      "truthState": "UNKNOWN",
      "retryable": false,
      "disclosure": "NON_LEAKING_INVARIANT",
      "publicTitle": "Result unknown"
    }
  ],
  "lifecycleApplications": [
    {
      "id": "PXT-001",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-BIND-LOCAL-CONTEXT/v1",
      "fromStateId": "OPEN",
      "eventId": "BIND_LOCAL_CONTEXT",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "CONTEXT_BOUND",
      "rawStateEffectId": "UNCHANGED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "CONTEXT_BOUND",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CONTEXT_BOUND"
      },
      "rejectingBranchId": "PXT-001:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "TerminalAuthorizationV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "bindLocalContext",
      "validatorId": "validateTerminalAuthorization",
      "consumerId": "preauthorize",
      "positiveVectorId": "PXT-001:POSITIVE",
      "negativeVector": {
        "id": "PXT-001:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-001:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-002",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-PREAUTHORIZE/v1",
      "fromStateId": "CONTEXT_BOUND",
      "eventId": "PREAUTHORIZE",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "PREAUTHORIZED",
      "rawStateEffectId": "UNCHANGED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "PREAUTHORIZED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "PREAUTHORIZED"
      },
      "rejectingBranchId": "PXT-002:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerLocalContextV1",
        "RegisteredPurposeActionV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "preauthorize",
      "validatorId": "validateRegisteredPurposeAction",
      "consumerId": "narrowIntent",
      "positiveVectorId": "PXT-002:POSITIVE",
      "negativeVector": {
        "id": "PXT-002:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-002:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-003",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-PREAUTHORIZE/v1",
      "fromStateId": "CONTEXT_BOUND",
      "eventId": "TERMINAL_DENIAL",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "DENIED",
      "disposition": {
        "kind": "COMMON_TERMINAL_DENIAL",
        "commonDenialDefinitionId": "PC-RUNTIME-3001"
      },
      "rejectingBranchId": "PXT-003:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerLocalContextV1",
        "RegisteredPurposeActionV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "preauthorize",
      "validatorId": "validateRegisteredPurposeAction",
      "consumerId": "narrowIntent",
      "positiveVectorId": "PXT-003:POSITIVE",
      "negativeVector": {
        "id": "PXT-003:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-003:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-004",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-NARROW-INTENT/v1",
      "fromStateId": "PREAUTHORIZED",
      "eventId": "NARROW_INTENT",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "INTENT_NARROWED",
      "rawStateEffectId": "UNCHANGED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "INTENT_NARROWED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "INTENT_NARROWED"
      },
      "rejectingBranchId": "PXT-004:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerPreauthorizedIntentV1",
        "PrivacyExplorerExportProfileV1",
        "PrivacyExplorerFilterPageV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "narrowIntent",
      "validatorId": "validateBoundedFilterPage",
      "consumerId": "createProjectionRequest",
      "positiveVectorId": "PXT-004:POSITIVE",
      "negativeVector": {
        "id": "PXT-004:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-004:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-006",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "CREATE_REQUEST",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "REQUEST_READY",
      "rawStateEffectId": "UNCHANGED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "REQUEST_READY",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "REQUEST_READY"
      },
      "rejectingBranchId": "PXT-006:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "PXT-006:POSITIVE",
      "negativeVector": {
        "id": "PXT-006:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-006:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-008",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "REQUEST_READY",
      "eventId": "START_READ",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "READ_IN_FLIGHT_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "DISPATCH_STARTED",
      "retainedFactId": "READ_STARTED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "READ_STARTED"
      },
      "rejectingBranchId": "PXT-008:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXT-008:POSITIVE",
      "negativeVector": {
        "id": "PXT-008:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-008:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-010",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "READ_IN_FLIGHT_NO_RAW",
      "eventId": "CAPTURE_BYTES",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "rawStateEffectId": "NEVER_CREATED_TO_LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_CAPTURED",
      "retainedFactId": "BYTES_CAPTURED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "BYTES_CAPTURED"
      },
      "rejectingBranchId": "PXT-010:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXT-010:POSITIVE",
      "negativeVector": {
        "id": "PXT-010:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-010:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-011",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "VALIDATE_PROJECTION",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "PROJECTION_VALIDATED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "VALIDATED_NO_AUTHORITY",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "VALIDATED_NO_AUTHORITY"
      },
      "rejectingBranchId": "PXT-011:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "PXT-011:POSITIVE",
      "negativeVector": {
        "id": "PXT-011:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-011:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-013",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-REDACT-PROJECTION/v1",
      "fromStateId": "PROJECTION_VALIDATED_RAW_LIVE",
      "eventId": "REDACT_PROJECTION",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "PROJECTION_REDACTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "REDACTED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "REDACTED"
      },
      "rejectingBranchId": "PXT-013:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerValidatedProjectionV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "redactProjection",
      "validatorId": "validateFieldAllowlistAndPrivacy",
      "consumerId": "releaseResult",
      "positiveVectorId": "PXT-013:POSITIVE",
      "negativeVector": {
        "id": "PXT-013:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-013:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-015",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "PROJECTION_REDACTED_RAW_LIVE",
      "eventId": "SELECT_COMPLETE",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "COMPLETE",
      "disposition": {
        "kind": "RESULT",
        "resultDefinitionId": "RESULT-COMPLETE"
      },
      "rejectingBranchId": "PXT-015:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-015:POSITIVE",
      "negativeVector": {
        "id": "PXT-015:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-015:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-016",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "PROJECTION_REDACTED_RAW_LIVE",
      "eventId": "SELECT_PARTIAL",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "PARTIAL",
      "disposition": {
        "kind": "RESULT",
        "resultDefinitionId": "RESULT-PARTIAL"
      },
      "rejectingBranchId": "PXT-016:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-016:POSITIVE",
      "negativeVector": {
        "id": "PXT-016:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-016:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-017",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "PROJECTION_REDACTED_RAW_LIVE",
      "eventId": "SELECT_UNKNOWN",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "UNKNOWN",
      "disposition": {
        "kind": "RESULT",
        "resultDefinitionId": "RESULT-UNKNOWN"
      },
      "rejectingBranchId": "PXT-017:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-017:POSITIVE",
      "negativeVector": {
        "id": "PXT-017:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-017:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-018",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "PROJECTION_REDACTED_RAW_LIVE",
      "eventId": "SELECT_UNAVAILABLE",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "UNAVAILABLE",
      "disposition": {
        "kind": "RESULT",
        "resultDefinitionId": "RESULT-UNAVAILABLE"
      },
      "rejectingBranchId": "PXT-018:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-018:POSITIVE",
      "negativeVector": {
        "id": "PXT-018:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-018:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-019",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "CANCEL_PENDING_NO_RAW",
      "eventId": "RECONCILE_NO_BYTES",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "DISPATCH_RECONCILED",
      "retainedFactId": "CANCELLED_AFTER_DISPATCH_NO_RAW",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCELLED_AFTER_DISPATCH_NO_RAW"
      },
      "rejectingBranchId": "PXT-019:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXT-019:POSITIVE",
      "negativeVector": {
        "id": "PXT-019:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-019:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-020",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "CANCEL_PENDING_NO_RAW",
      "eventId": "CAPTURE_LATE_BYTES",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "CANCEL_PENDING_RAW_LIVE",
      "rawStateEffectId": "NEVER_CREATED_TO_LIVE",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "RAW_OWNER_CAPTURED",
      "retainedFactId": "CANCELLED_AFTER_RAW",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCELLED_AFTER_RAW"
      },
      "rejectingBranchId": "PXT-020:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXT-020:POSITIVE",
      "negativeVector": {
        "id": "PXT-020:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-020:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-021",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "CANCEL_PENDING_RAW_LIVE",
      "eventId": "DISPOSE_RAW",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "OUTCOME_READY_RAW_DISPOSED",
      "rawStateEffectId": "LIVE_TO_DISPOSED",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "RAW_OWNER_DISPOSED",
      "retainedFactId": "CANCELLED_AFTER_RAW",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCELLED_AFTER_RAW"
      },
      "rejectingBranchId": "PXT-021:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXT-021:POSITIVE",
      "negativeVector": {
        "id": "PXT-021:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-021:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-022",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "eventId": "DISPOSE_RAW",
      "guardId": "EXACT_SOURCE_STATE",
      "toStateId": "OUTCOME_READY_RAW_DISPOSED",
      "rawStateEffectId": "LIVE_TO_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_DISPOSED",
      "retainedFactId": "OUTCOME_READY",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "OUTCOME_READY"
      },
      "rejectingBranchId": "PXT-022:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-022:POSITIVE",
      "negativeVector": {
        "id": "PXT-022:NEGATIVE",
        "mutatedFieldId": "eventId",
        "expectedRejectingBranchId": "PXT-022:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-023",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "OUTCOME_READY_NO_RAW",
      "eventId": "RELEASE",
      "guardId": "DELIVERY_PENDING",
      "toStateId": "RELEASED",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "RELEASED",
      "adapterEffectId": "COMPLETION_RECORDED",
      "retainedFactId": "RELEASED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "RELEASED"
      },
      "rejectingBranchId": "PXT-023:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-023:POSITIVE",
      "negativeVector": {
        "id": "PXT-023:NEGATIVE",
        "mutatedFieldId": "guardId",
        "expectedRejectingBranchId": "PXT-023:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-024",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AD-SR04-013",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "OUTCOME_READY_RAW_DISPOSED",
      "eventId": "RELEASE",
      "guardId": "DELIVERY_PENDING",
      "toStateId": "RELEASED",
      "rawStateEffectId": "DISPOSED",
      "deliveryEffectId": "RELEASED",
      "adapterEffectId": "COMPLETION_RECORDED",
      "retainedFactId": "RELEASED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "RELEASED"
      },
      "rejectingBranchId": "PXT-024:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-024:POSITIVE",
      "negativeVector": {
        "id": "PXT-024:NEGATIVE",
        "mutatedFieldId": "guardId",
        "expectedRejectingBranchId": "PXT-024:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-025",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "OUTCOME_READY_NO_RAW",
      "eventId": "CLOSE_CANCELLED",
      "guardId": "DELIVERY_SUPPRESSED",
      "toStateId": "CANCELLED_CLOSED",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "COMPLETION_RECORDED",
      "retainedFactId": "SUPPRESSED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "SUPPRESSED"
      },
      "rejectingBranchId": "PXT-025:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-025:POSITIVE",
      "negativeVector": {
        "id": "PXT-025:NEGATIVE",
        "mutatedFieldId": "guardId",
        "expectedRejectingBranchId": "PXT-025:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-026",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "OUTCOME_READY_RAW_DISPOSED",
      "eventId": "CLOSE_CANCELLED",
      "guardId": "DELIVERY_SUPPRESSED",
      "toStateId": "CANCELLED_CLOSED",
      "rawStateEffectId": "DISPOSED",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "COMPLETION_RECORDED",
      "retainedFactId": "SUPPRESSED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "SUPPRESSED"
      },
      "rejectingBranchId": "PXT-026:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXT-026:POSITIVE",
      "negativeVector": {
        "id": "PXT-026:NEGATIVE",
        "mutatedFieldId": "guardId",
        "expectedRejectingBranchId": "PXT-026:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXT-027",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER",
        "SA-ERROR-REGISTRY"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "READ_IN_FLIGHT_NO_RAW",
      "eventId": "REGISTERED_SAFE_PROBLEM_RETURNED",
      "guardId": "EXACT_REGISTERED_SAFE_PROBLEM",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "DISPATCH_RECONCILED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "SAFE_PROBLEM_NO_RAW"
      },
      "rejectingBranchId": "PXT-027:UNREGISTERED_OR_CROSS_TUPLE_PROBLEM",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXT-027:POSITIVE",
      "negativeVector": {
        "id": "PXT-027:NEGATIVE",
        "mutatedFieldId": "responseIdentity",
        "expectedRejectingBranchId": "PXT-027:UNREGISTERED_OR_CROSS_TUPLE_PROBLEM"
      }
    }
  ],
  "conditionApplications": [
    {
      "id": "CA-001",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "PROFILE_NOT_ADMITTED",
      "guardId": "CLASSIFIED_AS_CA_001",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-001"
      },
      "rejectingBranchId": "CA-001:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "CA-001:POSITIVE",
      "negativeVector": {
        "id": "CA-001:NEGATIVE",
        "mutatedFieldId": "profileDigest",
        "expectedRejectingBranchId": "CA-001:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-002",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-NARROW-INTENT/v1",
      "fromStateId": "PREAUTHORIZED",
      "eventId": "QUERY_UNSUPPORTED",
      "guardId": "CLASSIFIED_AS_CA_002",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-001"
      },
      "rejectingBranchId": "CA-002:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerPreauthorizedIntentV1",
        "PrivacyExplorerExportProfileV1",
        "PrivacyExplorerFilterPageV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "narrowIntent",
      "validatorId": "validateBoundedFilterPage",
      "consumerId": "createProjectionRequest",
      "positiveVectorId": "CA-002:POSITIVE",
      "negativeVector": {
        "id": "CA-002:NEGATIVE",
        "mutatedFieldId": "queryDigest",
        "expectedRejectingBranchId": "CA-002:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-003",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-NARROW-INTENT/v1",
      "fromStateId": "PREAUTHORIZED",
      "eventId": "FIELD_UNSUPPORTED",
      "guardId": "CLASSIFIED_AS_CA_003",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-001"
      },
      "rejectingBranchId": "CA-003:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerPreauthorizedIntentV1",
        "PrivacyExplorerExportProfileV1",
        "PrivacyExplorerFilterPageV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "narrowIntent",
      "validatorId": "validateBoundedFilterPage",
      "consumerId": "createProjectionRequest",
      "positiveVectorId": "CA-003:POSITIVE",
      "negativeVector": {
        "id": "CA-003:NEGATIVE",
        "mutatedFieldId": "queryDigest",
        "expectedRejectingBranchId": "CA-003:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-004",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-NARROW-INTENT/v1",
      "fromStateId": "PREAUTHORIZED",
      "eventId": "DATA_CLASS_UNSUPPORTED",
      "guardId": "CLASSIFIED_AS_CA_004",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-001"
      },
      "rejectingBranchId": "CA-004:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerPreauthorizedIntentV1",
        "PrivacyExplorerExportProfileV1",
        "PrivacyExplorerFilterPageV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "narrowIntent",
      "validatorId": "validateBoundedFilterPage",
      "consumerId": "createProjectionRequest",
      "positiveVectorId": "CA-004:POSITIVE",
      "negativeVector": {
        "id": "CA-004:NEGATIVE",
        "mutatedFieldId": "queryDigest",
        "expectedRejectingBranchId": "CA-004:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-005",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "PRIVACY_PROJECTION_IMPOSSIBLE",
      "guardId": "CLASSIFIED_AS_CA_005",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-001"
      },
      "rejectingBranchId": "CA-005:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "CA-005:POSITIVE",
      "negativeVector": {
        "id": "CA-005:NEGATIVE",
        "mutatedFieldId": "redactionFeasibility",
        "expectedRejectingBranchId": "CA-005:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-006",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-REDACT-PROJECTION/v1",
      "fromStateId": "PROJECTION_VALIDATED_RAW_LIVE",
      "eventId": "REDACTION_IMPOSSIBLE",
      "guardId": "CLASSIFIED_AS_CA_006",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-001"
      },
      "rejectingBranchId": "CA-006:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerValidatedProjectionV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "redactProjection",
      "validatorId": "validateFieldAllowlistAndPrivacy",
      "consumerId": "releaseResult",
      "positiveVectorId": "CA-006:POSITIVE",
      "negativeVector": {
        "id": "CA-006:NEGATIVE",
        "mutatedFieldId": "redactionFeasibility",
        "expectedRejectingBranchId": "CA-006:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-007",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "PROFILE_RETIRED",
      "guardId": "CLASSIFIED_AS_CA_007",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-001"
      },
      "rejectingBranchId": "CA-007:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "CA-007:POSITIVE",
      "negativeVector": {
        "id": "CA-007:NEGATIVE",
        "mutatedFieldId": "profileDigest",
        "expectedRejectingBranchId": "CA-007:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-008",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "RESPONSE_BINDING_INVALID",
      "guardId": "CLASSIFIED_AS_CA_008",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-002"
      },
      "rejectingBranchId": "CA-008:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-008:POSITIVE",
      "negativeVector": {
        "id": "CA-008:NEGATIVE",
        "mutatedFieldId": "responseIdentity",
        "expectedRejectingBranchId": "CA-008:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-009",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "RESPONSE_SCHEMA_INVALID",
      "guardId": "CLASSIFIED_AS_CA_009",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-002"
      },
      "rejectingBranchId": "CA-009:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-009:POSITIVE",
      "negativeVector": {
        "id": "CA-009:NEGATIVE",
        "mutatedFieldId": "responseSchemaVersion",
        "expectedRejectingBranchId": "CA-009:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-010",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "RESPONSE_INTEGRITY_INVALID",
      "guardId": "CLASSIFIED_AS_CA_010",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-002"
      },
      "rejectingBranchId": "CA-010:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-010:POSITIVE",
      "negativeVector": {
        "id": "CA-010:NEGATIVE",
        "mutatedFieldId": "responseDigest",
        "expectedRejectingBranchId": "CA-010:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-011",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "CURSOR_PARTIAL",
      "guardId": "CLASSIFIED_AS_CA_011",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-003"
      },
      "rejectingBranchId": "CA-011:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-011:POSITIVE",
      "negativeVector": {
        "id": "CA-011:NEGATIVE",
        "mutatedFieldId": "cursorOrder",
        "expectedRejectingBranchId": "CA-011:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-012",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "ORDER_PARTIAL",
      "guardId": "CLASSIFIED_AS_CA_012",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-003"
      },
      "rejectingBranchId": "CA-012:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-012:POSITIVE",
      "negativeVector": {
        "id": "CA-012:NEGATIVE",
        "mutatedFieldId": "cursorOrder",
        "expectedRejectingBranchId": "CA-012:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-013",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "GAP_PARTIAL",
      "guardId": "CLASSIFIED_AS_CA_013",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-003"
      },
      "rejectingBranchId": "CA-013:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-013:POSITIVE",
      "negativeVector": {
        "id": "CA-013:NEGATIVE",
        "mutatedFieldId": "cursorOrder",
        "expectedRejectingBranchId": "CA-013:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-014",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22",
        "SA-ADAPTER-REGISTRY"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "READ_IN_FLIGHT_NO_RAW",
      "eventId": "SOURCE_UNAVAILABLE",
      "guardId": "CLASSIFIED_AS_CA_014",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "DISPATCH_RECONCILED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-004"
      },
      "rejectingBranchId": "CA-014:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "CA-014:POSITIVE",
      "negativeVector": {
        "id": "CA-014:NEGATIVE",
        "mutatedFieldId": "sourceAvailability",
        "expectedRejectingBranchId": "CA-014:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-015",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "STALE_OBSERVATION",
      "guardId": "CLASSIFIED_AS_CA_015",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-005"
      },
      "rejectingBranchId": "CA-015:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-015:POSITIVE",
      "negativeVector": {
        "id": "CA-015:NEGATIVE",
        "mutatedFieldId": "observationFreshness",
        "expectedRejectingBranchId": "CA-015:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-016",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "REORG_OBSERVATION",
      "guardId": "CLASSIFIED_AS_CA_016",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-006"
      },
      "rejectingBranchId": "CA-016:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-016:POSITIVE",
      "negativeVector": {
        "id": "CA-016:NEGATIVE",
        "mutatedFieldId": "observationFreshness",
        "expectedRejectingBranchId": "CA-016:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-017",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "CONFLICTING_OBSERVATIONS",
      "guardId": "CLASSIFIED_AS_CA_017",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-007"
      },
      "rejectingBranchId": "CA-017:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-017:POSITIVE",
      "negativeVector": {
        "id": "CA-017:NEGATIVE",
        "mutatedFieldId": "observationFreshness",
        "expectedRejectingBranchId": "CA-017:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-018",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "PRODUCT_DRIFT",
      "guardId": "CLASSIFIED_AS_CA_018",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-008"
      },
      "rejectingBranchId": "CA-018:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "CA-018:POSITIVE",
      "negativeVector": {
        "id": "CA-018:NEGATIVE",
        "mutatedFieldId": "profileDigest",
        "expectedRejectingBranchId": "CA-018:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-019",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "RELEASE_DRIFT",
      "guardId": "CLASSIFIED_AS_CA_019",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-008"
      },
      "rejectingBranchId": "CA-019:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "CA-019:POSITIVE",
      "negativeVector": {
        "id": "CA-019:NEGATIVE",
        "mutatedFieldId": "profileDigest",
        "expectedRejectingBranchId": "CA-019:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-020",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-AF22"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "TRUST_DRIFT",
      "guardId": "CLASSIFIED_AS_CA_020",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-COND-008"
      },
      "rejectingBranchId": "CA-020:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "CA-020:POSITIVE",
      "negativeVector": {
        "id": "CA-020:NEGATIVE",
        "mutatedFieldId": "profileDigest",
        "expectedRejectingBranchId": "CA-020:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-021",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY"
      ],
      "operationId": "PXI-BIND-LOCAL-CONTEXT/v1",
      "fromStateId": "OPEN",
      "eventId": "JSON_PARSE_FAILED",
      "guardId": "CLASSIFIED_AS_CA_021",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-PARSE"
      },
      "rejectingBranchId": "CA-021:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "TerminalAuthorizationV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "bindLocalContext",
      "validatorId": "validateTerminalAuthorization",
      "consumerId": "preauthorize",
      "positiveVectorId": "CA-021:POSITIVE",
      "negativeVector": {
        "id": "CA-021:NEGATIVE",
        "mutatedFieldId": "requestEnvelope",
        "expectedRejectingBranchId": "CA-021:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-022",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY"
      ],
      "operationId": "PXI-BIND-LOCAL-CONTEXT/v1",
      "fromStateId": "OPEN",
      "eventId": "ENVELOPE_INVALID",
      "guardId": "CLASSIFIED_AS_CA_022",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-ENVELOPE"
      },
      "rejectingBranchId": "CA-022:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "TerminalAuthorizationV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "bindLocalContext",
      "validatorId": "validateTerminalAuthorization",
      "consumerId": "preauthorize",
      "positiveVectorId": "CA-022:POSITIVE",
      "negativeVector": {
        "id": "CA-022:NEGATIVE",
        "mutatedFieldId": "requestEnvelope",
        "expectedRejectingBranchId": "CA-022:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-023",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY"
      ],
      "operationId": "PXI-BIND-LOCAL-CONTEXT/v1",
      "fromStateId": "OPEN",
      "eventId": "VERSION_INVALID",
      "guardId": "CLASSIFIED_AS_CA_023",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-ENVELOPE"
      },
      "rejectingBranchId": "CA-023:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "TerminalAuthorizationV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "bindLocalContext",
      "validatorId": "validateTerminalAuthorization",
      "consumerId": "preauthorize",
      "positiveVectorId": "CA-023:POSITIVE",
      "negativeVector": {
        "id": "CA-023:NEGATIVE",
        "mutatedFieldId": "requestEnvelope",
        "expectedRejectingBranchId": "CA-023:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-024",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-BIND-LOCAL-CONTEXT/v1",
      "fromStateId": "OPEN",
      "eventId": "DIRECT_BROWSER_ATTEMPT",
      "guardId": "CLASSIFIED_AS_CA_024",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-BROWSER"
      },
      "rejectingBranchId": "CA-024:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "TerminalAuthorizationV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "bindLocalContext",
      "validatorId": "validateTerminalAuthorization",
      "consumerId": "preauthorize",
      "positiveVectorId": "CA-024:POSITIVE",
      "negativeVector": {
        "id": "CA-024:NEGATIVE",
        "mutatedFieldId": "requestEnvelope",
        "expectedRejectingBranchId": "CA-024:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-025",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY"
      ],
      "operationId": "PXI-BIND-LOCAL-CONTEXT/v1",
      "fromStateId": "OPEN",
      "eventId": "METHOD_ABSENT",
      "guardId": "CLASSIFIED_AS_CA_025",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-BROWSER"
      },
      "rejectingBranchId": "CA-025:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "TerminalAuthorizationV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "bindLocalContext",
      "validatorId": "validateTerminalAuthorization",
      "consumerId": "preauthorize",
      "positiveVectorId": "CA-025:POSITIVE",
      "negativeVector": {
        "id": "CA-025:NEGATIVE",
        "mutatedFieldId": "requestEnvelope",
        "expectedRejectingBranchId": "CA-025:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-026",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-NARROW-INTENT/v1",
      "fromStateId": "PREAUTHORIZED",
      "eventId": "PARAMETER_INVALID",
      "guardId": "CLASSIFIED_AS_CA_026",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-PARAMETER"
      },
      "rejectingBranchId": "CA-026:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerPreauthorizedIntentV1",
        "PrivacyExplorerExportProfileV1",
        "PrivacyExplorerFilterPageV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "narrowIntent",
      "validatorId": "validateBoundedFilterPage",
      "consumerId": "createProjectionRequest",
      "positiveVectorId": "CA-026:POSITIVE",
      "negativeVector": {
        "id": "CA-026:NEGATIVE",
        "mutatedFieldId": "queryDigest",
        "expectedRejectingBranchId": "CA-026:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-027",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-NARROW-INTENT/v1",
      "fromStateId": "PREAUTHORIZED",
      "eventId": "PARAMETER_FORBIDDEN",
      "guardId": "CLASSIFIED_AS_CA_027",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-PARAMETER"
      },
      "rejectingBranchId": "CA-027:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerPreauthorizedIntentV1",
        "PrivacyExplorerExportProfileV1",
        "PrivacyExplorerFilterPageV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "narrowIntent",
      "validatorId": "validateBoundedFilterPage",
      "consumerId": "createProjectionRequest",
      "positiveVectorId": "CA-027:POSITIVE",
      "negativeVector": {
        "id": "CA-027:NEGATIVE",
        "mutatedFieldId": "queryDigest",
        "expectedRejectingBranchId": "CA-027:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-028",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-ADAPTER-REGISTRY"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "REPLAY_DETECTED",
      "guardId": "CLASSIFIED_AS_CA_028",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-REPLAY"
      },
      "rejectingBranchId": "CA-028:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "CA-028:POSITIVE",
      "negativeVector": {
        "id": "CA-028:NEGATIVE",
        "mutatedFieldId": "occurrenceId",
        "expectedRejectingBranchId": "CA-028:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-029",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-ADAPTER-REGISTRY"
      ],
      "operationId": "PXI-CREATE-PROJECTION-REQUEST/v1",
      "fromStateId": "INTENT_NARROWED",
      "eventId": "OCCURRENCE_CONFLICT",
      "guardId": "CLASSIFIED_AS_CA_029",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-REPLAY"
      },
      "rejectingBranchId": "CA-029:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerNarrowedIntentV1",
        "AdapterCallContextSeedV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "createProjectionRequest",
      "validatorId": "validateRequestAndAdapterContext",
      "consumerId": "readGovernedProjection",
      "positiveVectorId": "CA-029:POSITIVE",
      "negativeVector": {
        "id": "CA-029:NEGATIVE",
        "mutatedFieldId": "occurrenceId",
        "expectedRejectingBranchId": "CA-029:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-030",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-ADAPTER-REGISTRY"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "READ_IN_FLIGHT_NO_RAW",
      "eventId": "DEADLINE_EXPIRED",
      "guardId": "CLASSIFIED_AS_CA_030",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "DISPATCH_RECONCILED",
      "retainedFactId": "SAFE_PROBLEM_NO_RAW",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-DEADLINE"
      },
      "rejectingBranchId": "CA-030:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "CA-030:POSITIVE",
      "negativeVector": {
        "id": "CA-030:NEGATIVE",
        "mutatedFieldId": "deadlineAt",
        "expectedRejectingBranchId": "CA-030:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-031",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "RELEASED",
      "eventId": "EVIDENCE_MISSING",
      "guardId": "CLASSIFIED_AS_CA_031",
      "toStateId": "RELEASED",
      "rawStateEffectId": "REQUIRES_NEVER_CREATED_OR_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "RELEASED_STATE_UNCHANGED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-EVIDENCE"
      },
      "rejectingBranchId": "CA-031:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "CA-031:POSITIVE",
      "negativeVector": {
        "id": "CA-031:NEGATIVE",
        "mutatedFieldId": "evidenceIdentity",
        "expectedRejectingBranchId": "CA-031:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-032",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "RELEASED",
      "eventId": "EVIDENCE_MISMATCH",
      "guardId": "CLASSIFIED_AS_CA_032",
      "toStateId": "RELEASED",
      "rawStateEffectId": "REQUIRES_NEVER_CREATED_OR_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "RELEASED_STATE_UNCHANGED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-EVIDENCE"
      },
      "rejectingBranchId": "CA-032:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "CA-032:POSITIVE",
      "negativeVector": {
        "id": "CA-032:NEGATIVE",
        "mutatedFieldId": "evidenceIdentity",
        "expectedRejectingBranchId": "CA-032:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-033",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "RELEASED",
      "eventId": "DISPOSAL_UNPROVEN",
      "guardId": "CLASSIFIED_AS_CA_033",
      "toStateId": "RELEASED",
      "rawStateEffectId": "REQUIRES_NEVER_CREATED_OR_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "RELEASED_STATE_UNCHANGED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-EVIDENCE"
      },
      "rejectingBranchId": "CA-033:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "CA-033:POSITIVE",
      "negativeVector": {
        "id": "CA-033:NEGATIVE",
        "mutatedFieldId": "rawDisposalProof",
        "expectedRejectingBranchId": "CA-033:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-034",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "CANCELLED_CLOSED",
      "eventId": "EVIDENCE_MISSING",
      "guardId": "CLASSIFIED_AS_CA_034",
      "toStateId": "CANCELLED_CLOSED",
      "rawStateEffectId": "REQUIRES_NEVER_CREATED_OR_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "CANCELLED_STATE_UNCHANGED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-EVIDENCE"
      },
      "rejectingBranchId": "CA-034:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "CA-034:POSITIVE",
      "negativeVector": {
        "id": "CA-034:NEGATIVE",
        "mutatedFieldId": "evidenceIdentity",
        "expectedRejectingBranchId": "CA-034:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-035",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "CANCELLED_CLOSED",
      "eventId": "EVIDENCE_MISMATCH",
      "guardId": "CLASSIFIED_AS_CA_035",
      "toStateId": "CANCELLED_CLOSED",
      "rawStateEffectId": "REQUIRES_NEVER_CREATED_OR_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "CANCELLED_STATE_UNCHANGED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-EVIDENCE"
      },
      "rejectingBranchId": "CA-035:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "CA-035:POSITIVE",
      "negativeVector": {
        "id": "CA-035:NEGATIVE",
        "mutatedFieldId": "evidenceIdentity",
        "expectedRejectingBranchId": "CA-035:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-036",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "CANCELLED_CLOSED",
      "eventId": "DISPOSAL_UNPROVEN",
      "guardId": "CLASSIFIED_AS_CA_036",
      "toStateId": "CANCELLED_CLOSED",
      "rawStateEffectId": "REQUIRES_NEVER_CREATED_OR_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "CANCELLED_STATE_UNCHANGED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-EVIDENCE"
      },
      "rejectingBranchId": "CA-036:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "CA-036:POSITIVE",
      "negativeVector": {
        "id": "CA-036:NEGATIVE",
        "mutatedFieldId": "rawDisposalProof",
        "expectedRejectingBranchId": "CA-036:UNDECLARED_OR_INVALID"
      }
    },
    {
      "id": "CA-037",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ERROR-REGISTRY",
        "SA-AF22"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "ABSENCE_WITHOUT_COMPLETE_PROOF",
      "guardId": "CLASSIFIED_AS_CA_037",
      "toStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "RAW_OWNER_RETAINED",
      "retainedFactId": "SAFE_PROBLEM_RAW_RETAINED",
      "disposition": {
        "kind": "CONDITION",
        "conditionDefinitionId": "EXP-ABSENCE"
      },
      "rejectingBranchId": "CA-037:UNDECLARED_OR_INVALID",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "CA-037:POSITIVE",
      "negativeVector": {
        "id": "CA-037:NEGATIVE",
        "mutatedFieldId": "completenessProof",
        "expectedRejectingBranchId": "CA-037:UNDECLARED_OR_INVALID"
      }
    }
  ],
  "cancellationApplications": [
    {
      "id": "PXC-001",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "REQUEST_READY",
      "eventId": "CANCEL_BEFORE_DISPATCH",
      "guardId": "DELIVERY_PENDING",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "NOT_STARTED",
      "retainedFactId": "CANCELLED_BEFORE_DISPATCH",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCELLED_BEFORE_DISPATCH"
      },
      "rejectingBranchId": "PXC-001:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXC-001:POSITIVE",
      "negativeVector": {
        "id": "PXC-001:NEGATIVE",
        "mutatedFieldId": "cancellationTiming",
        "expectedRejectingBranchId": "PXC-001:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-002",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "READ_IN_FLIGHT_NO_RAW",
      "eventId": "CANCEL_DURING_READ",
      "guardId": "DISPATCH_STARTED_NO_BYTES",
      "toStateId": "CANCEL_PENDING_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "CANCEL_REQUESTED",
      "retainedFactId": "CANCEL_PENDING",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCEL_PENDING"
      },
      "rejectingBranchId": "PXC-002:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXC-002:POSITIVE",
      "negativeVector": {
        "id": "PXC-002:NEGATIVE",
        "mutatedFieldId": "cancellationTiming",
        "expectedRejectingBranchId": "PXC-002:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-003",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-READ-GOVERNED-PROJECTION/v1",
      "fromStateId": "RESPONSE_CAPTURED_RAW_LIVE",
      "eventId": "CANCEL_AFTER_BYTES",
      "guardId": "RAW_OWNER_LIVE",
      "toStateId": "CANCEL_PENDING_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "CANCEL_REQUESTED",
      "retainedFactId": "CANCEL_PENDING",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCEL_PENDING"
      },
      "rejectingBranchId": "PXC-003:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "ExplorerProjectionRequestV1",
        "AdapterCallContextV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "readGovernedProjection",
      "validatorId": "validateAdapterCallBoundary",
      "consumerId": "validateProjection",
      "positiveVectorId": "PXC-003:POSITIVE",
      "negativeVector": {
        "id": "PXC-003:NEGATIVE",
        "mutatedFieldId": "cancellationTiming",
        "expectedRejectingBranchId": "PXC-003:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-004",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-VALIDATE-PROJECTION/v1",
      "fromStateId": "PROJECTION_VALIDATED_RAW_LIVE",
      "eventId": "CANCEL_AFTER_VALIDATION",
      "guardId": "RAW_OWNER_LIVE",
      "toStateId": "CANCEL_PENDING_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "CANCEL_REQUESTED",
      "retainedFactId": "CANCEL_PENDING",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCEL_PENDING"
      },
      "rejectingBranchId": "PXC-004:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "ExplorerProjectionResultV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "validateProjection",
      "validatorId": "validateIdentityScopeOrderAndTruth",
      "consumerId": "redactProjection",
      "positiveVectorId": "PXC-004:POSITIVE",
      "negativeVector": {
        "id": "PXC-004:NEGATIVE",
        "mutatedFieldId": "cancellationTiming",
        "expectedRejectingBranchId": "PXC-004:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-005",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-REDACT-PROJECTION/v1",
      "fromStateId": "PROJECTION_REDACTED_RAW_LIVE",
      "eventId": "CANCEL_AFTER_REDACTION",
      "guardId": "RAW_OWNER_LIVE",
      "toStateId": "CANCEL_PENDING_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "CANCEL_REQUESTED",
      "retainedFactId": "CANCEL_PENDING",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCEL_PENDING"
      },
      "rejectingBranchId": "PXC-005:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "PrivacyExplorerValidatedProjectionV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "redactProjection",
      "validatorId": "validateFieldAllowlistAndPrivacy",
      "consumerId": "releaseResult",
      "positiveVectorId": "PXC-005:POSITIVE",
      "negativeVector": {
        "id": "PXC-005:NEGATIVE",
        "mutatedFieldId": "cancellationTiming",
        "expectedRejectingBranchId": "PXC-005:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-006",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "OUTCOME_SELECTED_RAW_LIVE",
      "eventId": "CANCEL_AFTER_OUTCOME_SELECTION",
      "guardId": "RAW_OWNER_LIVE",
      "toStateId": "CANCEL_PENDING_RAW_LIVE",
      "rawStateEffectId": "LIVE",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "CANCEL_REQUESTED",
      "retainedFactId": "CANCEL_PENDING",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCEL_PENDING"
      },
      "rejectingBranchId": "PXC-006:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXC-006:POSITIVE",
      "negativeVector": {
        "id": "PXC-006:NEGATIVE",
        "mutatedFieldId": "cancellationTiming",
        "expectedRejectingBranchId": "PXC-006:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-007",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "OUTCOME_READY_NO_RAW",
      "eventId": "CANCEL_AFTER_NO_RAW_READY",
      "guardId": "DELIVERY_PENDING",
      "toStateId": "OUTCOME_READY_NO_RAW",
      "rawStateEffectId": "NEVER_CREATED",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "DELIVERY_SUPPRESSED",
      "retainedFactId": "CANCELLED_AFTER_DISPATCH_NO_RAW",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCELLED_AFTER_DISPATCH_NO_RAW"
      },
      "rejectingBranchId": "PXC-007:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXC-007:POSITIVE",
      "negativeVector": {
        "id": "PXC-007:NEGATIVE",
        "mutatedFieldId": "cancellationTiming",
        "expectedRejectingBranchId": "PXC-007:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-008",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "OUTCOME_READY_RAW_DISPOSED",
      "eventId": "CANCEL_AFTER_DISPOSAL",
      "guardId": "DELIVERY_PENDING",
      "toStateId": "OUTCOME_READY_RAW_DISPOSED",
      "rawStateEffectId": "DISPOSED",
      "deliveryEffectId": "SUPPRESSED",
      "adapterEffectId": "DELIVERY_SUPPRESSED",
      "retainedFactId": "CANCELLED_AFTER_RAW",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "CANCELLED_AFTER_RAW"
      },
      "rejectingBranchId": "PXC-008:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXC-008:POSITIVE",
      "negativeVector": {
        "id": "PXC-008:NEGATIVE",
        "mutatedFieldId": "cancellationTiming",
        "expectedRejectingBranchId": "PXC-008:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-009",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-RELEASE-RESULT/v1",
      "fromStateId": "RELEASED",
      "eventId": "CANCEL_LATE_RELEASED",
      "guardId": "IMMUTABLE_RELEASE_EXISTS",
      "toStateId": "RELEASED",
      "rawStateEffectId": "UNCHANGED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "NO_OP_AFTER_IMMUTABLE_RELEASE",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "NO_OP_AFTER_IMMUTABLE_RELEASE"
      },
      "rejectingBranchId": "PXC-009:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "PrivacyExplorerRedactedProjectionV1",
        "SafeProblemV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "releaseResult",
      "validatorId": "validateClosedOutcome",
      "consumerId": "lifecycleReducer",
      "positiveVectorId": "PXC-009:POSITIVE",
      "negativeVector": {
        "id": "PXC-009:NEGATIVE",
        "mutatedFieldId": "immutableDeliveryState",
        "expectedRejectingBranchId": "PXC-009:UNDECLARED_CANCELLATION"
      }
    },
    {
      "id": "PXC-010",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-ADAPTER-REGISTRY",
        "SA-SDK-EXPLORER"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "EVIDENCE_SEALED",
      "eventId": "CANCEL_LATE_EVIDENCE",
      "guardId": "IMMUTABLE_EVIDENCE_EXISTS",
      "toStateId": "EVIDENCE_SEALED",
      "rawStateEffectId": "UNCHANGED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "NONE",
      "retainedFactId": "NO_OP_AFTER_IMMUTABLE_EVIDENCE",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "NO_OP_AFTER_IMMUTABLE_EVIDENCE"
      },
      "rejectingBranchId": "PXC-010:UNDECLARED_CANCELLATION",
      "noEffectId": "NO_UNDECLARED_STATE_RAW_DELIVERY_OR_EVIDENCE_EFFECT",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "PXC-010:POSITIVE",
      "negativeVector": {
        "id": "PXC-010:NEGATIVE",
        "mutatedFieldId": "immutableDeliveryState",
        "expectedRejectingBranchId": "PXC-010:UNDECLARED_CANCELLATION"
      }
    }
  ],
  "contributionApplications": [
    {
      "id": "PXE-001",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "RELEASED",
      "eventId": "MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS",
      "guardId": "IDENTITY_OCCURRENCE_DIGESTS_REVISION_AND_UNIQUENESS_MATCH",
      "toStateId": "EVIDENCE_SEALED",
      "rawStateEffectId": "REQUIRES_NEVER_CREATED_OR_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "EVIDENCE_ASSEMBLED",
      "retainedFactId": "EVIDENCE_SEALED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "EVIDENCE_SEALED"
      },
      "rejectingBranchId": "PXE-001:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "PXE-001:POSITIVE",
      "negativeVector": {
        "id": "PXE-001:NEGATIVE",
        "mutatedFieldId": "rawDisposalProof",
        "expectedRejectingBranchId": "PXE-001:UNDECLARED_TRANSITION"
      }
    },
    {
      "id": "PXE-002",
      "authorityClass": "RECEIVING_INTERNAL_DESIGN",
      "designId": "I07-G2-B1-V1",
      "sourceAnchorIds": [
        "SA-PRIV-EXPLORER-011"
      ],
      "operationId": "PXI-RECORD-EVIDENCE/v1",
      "fromStateId": "CANCELLED_CLOSED",
      "eventId": "MATCH_ADAPTER_AND_COMPLETION_CONTRIBUTIONS",
      "guardId": "IDENTITY_OCCURRENCE_DIGESTS_REVISION_AND_UNIQUENESS_MATCH",
      "toStateId": "EVIDENCE_SEALED",
      "rawStateEffectId": "REQUIRES_NEVER_CREATED_OR_DISPOSED",
      "deliveryEffectId": "UNCHANGED",
      "adapterEffectId": "EVIDENCE_ASSEMBLED",
      "retainedFactId": "EVIDENCE_SEALED",
      "disposition": {
        "kind": "INTERNAL",
        "internalDispositionId": "EVIDENCE_SEALED"
      },
      "rejectingBranchId": "PXE-002:UNDECLARED_TRANSITION",
      "noEffectId": "STATE_DELIVERY_RAW_AND_ADAPTER_UNCHANGED",
      "admittedInputTypeIds": [
        "PrivacyExplorerAdapterContributionV1",
        "PrivacyExplorerCompletionContributionV1",
        "PrivacyExplorerRawStateWitnessV1"
      ],
      "ownerId": "LS-CONTROL-API",
      "constructorId": "assembleEvidence",
      "validatorId": "validateMatchingContributionsAndRawState",
      "consumerId": "evidenceSink",
      "positiveVectorId": "PXE-002:POSITIVE",
      "negativeVector": {
        "id": "PXE-002:NEGATIVE",
        "mutatedFieldId": "rawDisposalProof",
        "expectedRejectingBranchId": "PXE-002:UNDECLARED_TRANSITION"
      }
    }
  ],
  "nonGoals": [
    "ExternalDecisionAdapter",
    "COM-022",
    "Fact Bridge",
    "fact admission",
    "provider routing",
    "fallback",
    "browser",
    "redirect",
    "raw node",
    "managed SubQuery",
    "I06 semantics",
    "CandidateStore"
  ]
} as const;
