// @generated from schemas/json/privacy-explorer.schema.json; do not edit.
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

export const privacyExplorerSchema = {
  "$id": "https://schemas.openpc.local/privacy-explorer.schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "OpenPC Privacy Explorer contracts v1",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "schemaVersion": {
      "const": "1.0"
    },
    "request": {
      "$ref": "#/$defs/ExplorerProjectionRequestV1"
    },
    "adapterContext": {
      "$ref": "#/$defs/AdapterCallContextV1"
    },
    "adapterResult": {
      "$ref": "#/$defs/ExplorerProjectionResultV1"
    },
    "result": {
      "$ref": "#/$defs/PrivacyExplorerResultV1"
    },
    "occurrence": {
      "$ref": "#/$defs/PrivacyExplorerOccurrenceV1"
    },
    "evidence": {
      "$ref": "#/$defs/PrivacyExplorerEvidenceDigestRecordV1"
    },
    "evidenceReference": {
      "$ref": "#/$defs/EvidenceReferenceV1"
    },
    "evidenceVerification": {
      "$ref": "#/$defs/EvidenceVerificationResultV1"
    },
    "problem": {
      "$ref": "#/$defs/PrivacyExplorerProblemV1"
    }
  },
  "required": [
    "schemaVersion"
  ],
  "$defs": {
    "Digest": {
      "type": "string",
      "pattern": "^sha256:[0-9a-f]{64}$"
    },
    "OccurrenceId": {
      "type": "string",
      "format": "uuid"
    },
    "BoundedString": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "PrivacyExplorerExportProfileV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "version",
        "digest",
        "operationVersions",
        "allowedFieldIds",
        "allowedFilterIds",
        "maximumPageSize",
        "responseSchemaVersion",
        "maximumFreshnessAgeMilliseconds",
        "provenanceProfileDigest",
        "privacyProjectionId",
        "redactionProfileId",
        "evidenceClassId",
        "maximumDeadlineAt",
        "maximumReadAttempts",
        "retryBackoffMilliseconds"
      ],
      "properties": {
        "id": {
          "$ref": "#/$defs/BoundedString"
        },
        "version": {
          "$ref": "#/$defs/BoundedString"
        },
        "digest": {
          "$ref": "#/$defs/Digest"
        },
        "sourceBinding": {
          "$ref": "#/$defs/PrivacyExplorerSourceBindingV1"
        },
        "operationVersions": {
          "type": "array",
          "minItems": 9,
          "maxItems": 9,
          "uniqueItems": true,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "operationId",
              "version",
              "acceptedDataClassIds"
            ],
            "properties": {
              "operationId": {
                "$ref": "#/$defs/BoundedString"
              },
              "version": {
                "$ref": "#/$defs/BoundedString"
              },
              "acceptedDataClassIds": {
                "$ref": "#/$defs/BoundedStringSet"
              }
            }
          }
        },
        "allowedFieldIds": {
          "type": "array",
          "minItems": 1,
          "maxItems": 64,
          "uniqueItems": true,
          "items": {
            "$ref": "#/$defs/RegisteredFieldId"
          }
        },
        "allowedFilterIds": {
          "type": "array",
          "minItems": 1,
          "maxItems": 32,
          "uniqueItems": true,
          "items": {
            "type": "string",
            "pattern": "^PEFILTER-[A-Z0-9-]{1,64}$"
          }
        },
        "maximumPageSize": {
          "type": "integer",
          "minimum": 1,
          "maximum": 200
        },
        "responseSchemaVersion": {
          "const": "1.0"
        },
        "maximumFreshnessAgeMilliseconds": {
          "type": "integer",
          "minimum": 0,
          "maximum": 31536000000
        },
        "provenanceProfileDigest": {
          "$ref": "#/$defs/Digest"
        },
        "privacyProjectionId": {
          "$ref": "#/$defs/BoundedString"
        },
        "redactionProfileId": {
          "$ref": "#/$defs/BoundedString"
        },
        "evidenceClassId": {
          "$ref": "#/$defs/BoundedString"
        },
        "maximumDeadlineAt": {
          "type": "string",
          "format": "date-time"
        },
        "maximumReadAttempts": {
          "type": "integer",
          "minimum": 1,
          "maximum": 4
        },
        "retryBackoffMilliseconds": {
          "type": "array",
          "maxItems": 3,
          "items": {
            "type": "integer",
            "minimum": 0,
            "maximum": 60000
          }
        }
      }
    },
    "PrivacyExplorerSourceBindingV1": {
      "type": "object",
      "additionalProperties": false,
      "description": "Governed exact source and local scope binding. Required by the live disclosure owner; older profiles without this binding remain ineligible for live delivery.",
      "required": [
        "platformId",
        "workloadId",
        "accessClassIds",
        "productId",
        "instanceId",
        "releaseVersion",
        "buildDigest",
        "adapterVersion",
        "transportProfileId",
        "egressPolicyId",
        "trustAnchorId",
        "clientIdentityId"
      ],
      "properties": {
        "platformId": {
          "$ref": "#/$defs/BoundedString"
        },
        "workloadId": {
          "type": "string",
          "format": "uuid"
        },
        "accessClassIds": {
          "type": "array",
          "minItems": 1,
          "maxItems": 32,
          "uniqueItems": true,
          "items": {
            "type": "string",
            "pattern": "^ACCESS-[A-Z0-9-]{1,64}$"
          }
        },
        "productId": {
          "$ref": "#/$defs/BoundedString"
        },
        "instanceId": {
          "$ref": "#/$defs/BoundedString"
        },
        "releaseVersion": {
          "$ref": "#/$defs/BoundedString"
        },
        "buildDigest": {
          "$ref": "#/$defs/Digest"
        },
        "adapterVersion": {
          "const": "1.0.0"
        },
        "transportProfileId": {
          "type": "string",
          "pattern": "^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}@v[1-9][0-9]*$"
        },
        "egressPolicyId": {
          "type": "string",
          "pattern": "^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}@v[1-9][0-9]*$"
        },
        "trustAnchorId": {
          "type": "string",
          "pattern": "^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}@v[1-9][0-9]*$"
        },
        "clientIdentityId": {
          "type": "string",
          "pattern": "^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}@v[1-9][0-9]*$"
        }
      }
    },
    "PrivacyExplorerOccurrenceV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "occurrenceId",
        "state",
        "executionState",
        "revision",
        "deadlineAt",
        "clientReceipt",
        "evidenceReference"
      ],
      "properties": {
        "occurrenceId": {
          "type": "string",
          "format": "uuid"
        },
        "state": {
          "enum": [
            "OPEN",
            "SUPPRESSED",
            "INTERRUPTED",
            "RELEASE_AUTHORIZED"
          ]
        },
        "executionState": {
          "$ref": "#/$defs/BoundedString"
        },
        "revision": {
          "type": "integer",
          "minimum": 0,
          "maximum": 128
        },
        "deadlineAt": {
          "type": "string",
          "format": "date-time"
        },
        "clientReceipt": {
          "const": "UNKNOWN"
        },
        "evidenceReference": {
          "oneOf": [
            {
              "$ref": "#/$defs/Digest"
            },
            {
              "type": "null"
            }
          ]
        }
      }
    },
    "BoundedStringSet": {
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "uniqueItems": true,
      "items": {
        "$ref": "#/$defs/BoundedString"
      }
    },
    "ExplorerProjectionRequestV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "semanticOperationVersion",
        "schemaVersion",
        "issuedAt",
        "purpose",
        "subject",
        "resource",
        "action",
        "scope",
        "operationId",
        "operationVersion",
        "dataClassId",
        "filters",
        "page",
        "projectionFields",
        "exportProfile",
        "queryDigest",
        "occurrence"
      ],
      "properties": {
        "operationVersion": {
          "const": "v1"
        },
        "schemaVersion": {
          "const": "1.0"
        },
        "issuedAt": {
          "type": "string",
          "format": "date-time"
        },
        "purpose": {
          "$ref": "#/$defs/BoundedString"
        },
        "subject": {
          "$ref": "#/$defs/BoundedString"
        },
        "resource": {
          "$ref": "#/$defs/BoundedString"
        },
        "action": {
          "$ref": "#/$defs/BoundedString"
        },
        "scope": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "participantId",
            "privacyDomainId",
            "platformId",
            "workloadId",
            "action"
          ],
          "properties": {
            "participantId": {
              "$ref": "#/$defs/BoundedString"
            },
            "privacyDomainId": {
              "$ref": "#/$defs/BoundedString"
            },
            "platformId": {
              "$ref": "#/$defs/BoundedString"
            },
            "workloadId": {
              "$ref": "#/$defs/BoundedString"
            },
            "action": {
              "$ref": "#/$defs/BoundedString"
            }
          }
        },
        "operationId": {
          "$ref": "#/$defs/BoundedString"
        },
        "semanticOperationVersion": {
          "$ref": "#/$defs/BoundedString"
        },
        "dataClassId": {
          "$ref": "#/$defs/BoundedString"
        },
        "filters": {
          "type": "array",
          "maxItems": 32,
          "uniqueItems": true,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "fieldId",
              "filterId",
              "value"
            ],
            "properties": {
              "fieldId": {
                "$ref": "#/$defs/RegisteredFieldId"
              },
              "filterId": {
                "type": "string",
                "pattern": "^PEFILTER-[A-Z0-9-]{1,64}$"
              },
              "value": {
                "$ref": "#/$defs/ScalarValue"
              }
            }
          }
        },
        "page": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "limit",
            "cursor"
          ],
          "properties": {
            "limit": {
              "type": "integer",
              "minimum": 1,
              "maximum": 200
            },
            "cursor": {
              "oneOf": [
                {
                  "type": "string",
                  "maxLength": 1024
                },
                {
                  "type": "null"
                }
              ]
            }
          }
        },
        "projectionFields": {
          "type": "array",
          "minItems": 1,
          "maxItems": 64,
          "uniqueItems": true,
          "items": {
            "$ref": "#/$defs/RegisteredFieldId"
          }
        },
        "exportProfile": {
          "$ref": "#/$defs/PrivacyExplorerExportProfileV1"
        },
        "queryDigest": {
          "$ref": "#/$defs/Digest"
        },
        "occurrence": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "requestId",
            "correlationId"
          ],
          "properties": {
            "requestId": {
              "$ref": "#/$defs/OccurrenceId"
            },
            "correlationId": {
              "$ref": "#/$defs/OccurrenceId"
            }
          }
        }
      }
    },
    "AdapterCallContextV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "authorizationDigest",
        "profileDigest",
        "authorizationContextId",
        "authorizationContextEpoch",
        "accessClassIds",
        "scopeDigest",
        "deadlineAt",
        "idempotencyDigest",
        "occurrenceId",
        "auditCorrelationId",
        "cancellation",
        "reconciliation"
      ],
      "properties": {
        "authorizationDigest": {
          "$ref": "#/$defs/Digest"
        },
        "profileDigest": {
          "$ref": "#/$defs/Digest"
        },
        "authorizationContextId": {
          "$ref": "#/$defs/OccurrenceId"
        },
        "authorizationContextEpoch": {
          "type": "integer",
          "minimum": 0,
          "maximum": 9007199254740991
        },
        "accessClassIds": {
          "type": "array",
          "minItems": 1,
          "maxItems": 32,
          "uniqueItems": true,
          "items": {
            "type": "string",
            "pattern": "^ACCESS-[A-Z0-9-]{1,64}$"
          }
        },
        "scopeDigest": {
          "$ref": "#/$defs/Digest"
        },
        "deadlineAt": {
          "type": "string",
          "format": "date-time"
        },
        "idempotencyDigest": {
          "$ref": "#/$defs/Digest"
        },
        "occurrenceId": {
          "$ref": "#/$defs/OccurrenceId"
        },
        "auditCorrelationId": {
          "$ref": "#/$defs/OccurrenceId"
        },
        "cancellation": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "mode",
            "occurrenceId"
          ],
          "properties": {
            "mode": {
              "const": "NO_NEW_EFFECT_AFTER_CANCELLATION"
            },
            "occurrenceId": {
              "$ref": "#/$defs/OccurrenceId"
            }
          }
        },
        "reconciliation": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "mode",
            "occurrenceId"
          ],
          "properties": {
            "mode": {
              "const": "EXACT_OCCURRENCE"
            },
            "occurrenceId": {
              "$ref": "#/$defs/OccurrenceId"
            }
          }
        }
      }
    },
    "ExplorerProjectionResultV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "schemaVersion",
        "requestDigest",
        "profileDigest",
        "responseDigest",
        "provenanceDigest",
        "observedAt",
        "records",
        "page",
        "completeness",
        "freshness",
        "conflict"
      ],
      "properties": {
        "schemaVersion": {
          "const": "1.0"
        },
        "requestDigest": {
          "$ref": "#/$defs/Digest"
        },
        "profileDigest": {
          "$ref": "#/$defs/Digest"
        },
        "responseDigest": {
          "$ref": "#/$defs/Digest"
        },
        "provenanceDigest": {
          "$ref": "#/$defs/Digest"
        },
        "observedAt": {
          "type": "string",
          "format": "date-time"
        },
        "records": {
          "type": "array",
          "maxItems": 200,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "id",
              "fields"
            ],
            "properties": {
              "id": {
                "$ref": "#/$defs/BoundedString"
              },
              "fields": {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": true,
                "items": {
                  "type": "object",
                  "additionalProperties": false,
                  "required": [
                    "fieldId",
                    "value"
                  ],
                  "properties": {
                    "fieldId": {
                      "$ref": "#/$defs/RegisteredFieldId"
                    },
                    "value": {
                      "$ref": "#/$defs/ScalarValue"
                    }
                  }
                }
              }
            }
          }
        },
        "page": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "cursor",
            "gapFree"
          ],
          "properties": {
            "cursor": {
              "oneOf": [
                {
                  "type": "string",
                  "maxLength": 1024
                },
                {
                  "type": "null"
                }
              ]
            },
            "gapFree": {
              "type": "boolean"
            }
          }
        },
        "completeness": {
          "enum": [
            "COMPLETE",
            "PARTIAL",
            "UNKNOWN",
            "UNAVAILABLE"
          ]
        },
        "freshness": {
          "enum": [
            "FRESH",
            "STALE",
            "UNKNOWN"
          ]
        },
        "conflict": {
          "enum": [
            "NONE",
            "CONFLICT",
            "REORG"
          ]
        }
      }
    },
    "PrivacyExplorerResultV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "schemaVersion",
        "outcome",
        "truthState",
        "requestDigest",
        "profileDigest",
        "queryDigest",
        "resultDigest",
        "records",
        "page"
      ],
      "properties": {
        "schemaVersion": {
          "const": "1.0"
        },
        "outcome": {
          "enum": [
            "COMPLETE",
            "PARTIAL",
            "UNKNOWN",
            "UNAVAILABLE"
          ]
        },
        "truthState": {
          "enum": [
            "TRUE",
            "PARTIAL",
            "UNKNOWN",
            "UNAVAILABLE"
          ]
        },
        "requestDigest": {
          "$ref": "#/$defs/Digest"
        },
        "profileDigest": {
          "$ref": "#/$defs/Digest"
        },
        "queryDigest": {
          "$ref": "#/$defs/Digest"
        },
        "resultDigest": {
          "$ref": "#/$defs/Digest"
        },
        "records": {
          "type": "array",
          "maxItems": 200,
          "items": {
            "$ref": "#/$defs/PrivacyExplorerReleasedRecordV1"
          }
        },
        "page": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "cursor",
            "gapFree"
          ],
          "properties": {
            "cursor": {
              "oneOf": [
                {
                  "type": "string",
                  "maxLength": 1024
                },
                {
                  "type": "null"
                }
              ]
            },
            "gapFree": {
              "type": "boolean"
            }
          }
        }
      }
    },
    "PrivacyExplorerEvidenceDigestRecordV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "occurrenceId",
        "correlationId",
        "authorizationDigest",
        "contextDigest",
        "scopeDigest",
        "requestDigest",
        "profileDigest",
        "queryDigest",
        "responseDigest",
        "validationDigest",
        "redactionDigest",
        "outcome",
        "resultDigest",
        "rawState"
      ],
      "properties": {
        "occurrenceId": {
          "$ref": "#/$defs/OccurrenceId"
        },
        "correlationId": {
          "$ref": "#/$defs/OccurrenceId"
        },
        "authorizationDigest": {
          "$ref": "#/$defs/Digest"
        },
        "contextDigest": {
          "$ref": "#/$defs/Digest"
        },
        "scopeDigest": {
          "$ref": "#/$defs/Digest"
        },
        "requestDigest": {
          "$ref": "#/$defs/Digest"
        },
        "profileDigest": {
          "$ref": "#/$defs/Digest"
        },
        "queryDigest": {
          "$ref": "#/$defs/Digest"
        },
        "responseDigest": {
          "$ref": "#/$defs/Digest"
        },
        "validationDigest": {
          "$ref": "#/$defs/Digest"
        },
        "redactionDigest": {
          "$ref": "#/$defs/Digest"
        },
        "outcome": {
          "enum": [
            "COMPLETE",
            "PARTIAL",
            "UNKNOWN",
            "UNAVAILABLE",
            "DENIED",
            "FAILED",
            "CANCELLED_BEFORE_DISPATCH",
            "CANCELLED_AFTER_DISPATCH_NO_RAW",
            "CANCELLED_AFTER_RAW"
          ]
        },
        "resultDigest": {
          "$ref": "#/$defs/Digest"
        },
        "rawState": {
          "enum": [
            "NEVER_CREATED",
            "DISPOSED"
          ]
        }
      }
    },
    "EvidenceReferenceV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "schemaVersion",
        "referenceDigest",
        "evidenceDigest",
        "occurrenceId",
        "profileDigest"
      ],
      "properties": {
        "schemaVersion": {
          "const": "1.0"
        },
        "referenceDigest": {
          "$ref": "#/$defs/Digest"
        },
        "evidenceDigest": {
          "$ref": "#/$defs/Digest"
        },
        "occurrenceId": {
          "$ref": "#/$defs/OccurrenceId"
        },
        "profileDigest": {
          "$ref": "#/$defs/Digest"
        }
      }
    },
    "EvidenceVerificationResultV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "schemaVersion",
        "referenceDigest",
        "evidenceDigest",
        "verified",
        "verificationDigest"
      ],
      "properties": {
        "schemaVersion": {
          "const": "1.0"
        },
        "referenceDigest": {
          "$ref": "#/$defs/Digest"
        },
        "evidenceDigest": {
          "$ref": "#/$defs/Digest"
        },
        "verified": {
          "type": "boolean"
        },
        "verificationDigest": {
          "$ref": "#/$defs/Digest"
        }
      }
    },
    "PrivacyExplorerProblemV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "code",
        "httpStatus",
        "jsonRpcCode",
        "grpcStatus",
        "truthState",
        "retryable",
        "disclosure",
        "publicTitle"
      ],
      "properties": {
        "code": {
          "type": "string"
        },
        "httpStatus": {
          "type": "integer"
        },
        "jsonRpcCode": {
          "type": "integer"
        },
        "grpcStatus": {
          "type": "string"
        },
        "truthState": {
          "type": "string"
        },
        "retryable": {
          "type": "boolean"
        },
        "disclosure": {
          "type": "string"
        },
        "publicTitle": {
          "type": "string"
        }
      },
      "oneOf": [
        {
          "properties": {
            "code": {
              "const": "PC-AUTH-0001"
            },
            "httpStatus": {
              "const": 401
            },
            "jsonRpcCode": {
              "const": -32041
            },
            "grpcStatus": {
              "const": "UNAUTHENTICATED"
            },
            "truthState": {
              "const": "DENIED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "Resource is unavailable"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-RUNTIME-3001"
            },
            "httpStatus": {
              "const": 403
            },
            "jsonRpcCode": {
              "const": -32001
            },
            "grpcStatus": {
              "const": "PERMISSION_DENIED"
            },
            "truthState": {
              "const": "DENIED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "Resource is unavailable"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-INTEGRATION-5002"
            },
            "httpStatus": {
              "const": 409
            },
            "jsonRpcCode": {
              "const": -32052
            },
            "grpcStatus": {
              "const": "FAILED_PRECONDITION"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "AUTHORIZED_DETAIL"
            },
            "publicTitle": {
              "const": "Request validation failed"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-RUNTIME-3009"
            },
            "httpStatus": {
              "const": 502
            },
            "jsonRpcCode": {
              "const": -32009
            },
            "grpcStatus": {
              "const": "FAILED_PRECONDITION"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "The service is unavailable"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-OPS-9004"
            },
            "httpStatus": {
              "const": 409
            },
            "jsonRpcCode": {
              "const": -32094
            },
            "grpcStatus": {
              "const": "FAILED_PRECONDITION"
            },
            "truthState": {
              "const": "PARTIAL"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "AUTHORIZED_DETAIL"
            },
            "publicTitle": {
              "const": "Partial result"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-INTEGRATION-5001"
            },
            "httpStatus": {
              "const": 503
            },
            "jsonRpcCode": {
              "const": -32051
            },
            "grpcStatus": {
              "const": "UNAVAILABLE"
            },
            "truthState": {
              "const": "UNAVAILABLE"
            },
            "retryable": {
              "const": true
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "The service is unavailable"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-FACT-4002"
            },
            "httpStatus": {
              "const": 412
            },
            "jsonRpcCode": {
              "const": -32032
            },
            "grpcStatus": {
              "const": "FAILED_PRECONDITION"
            },
            "truthState": {
              "const": "STALE"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "The resource changed"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-FACT-4003"
            },
            "httpStatus": {
              "const": 409
            },
            "jsonRpcCode": {
              "const": -32033
            },
            "grpcStatus": {
              "const": "ABORTED"
            },
            "truthState": {
              "const": "REORG"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "The resource changed"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-RUNTIME-3011"
            },
            "httpStatus": {
              "const": 409
            },
            "jsonRpcCode": {
              "const": -32011
            },
            "grpcStatus": {
              "const": "FAILED_PRECONDITION"
            },
            "truthState": {
              "const": "CONFLICTING"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "The request conflicts with current state"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-RUNTIME-3008"
            },
            "httpStatus": {
              "const": 409
            },
            "jsonRpcCode": {
              "const": -32008
            },
            "grpcStatus": {
              "const": "FAILED_PRECONDITION"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "The request could not be completed"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-DATA-6001"
            },
            "httpStatus": {
              "const": 400
            },
            "jsonRpcCode": {
              "const": -32700
            },
            "grpcStatus": {
              "const": "INVALID_ARGUMENT"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "Malformed JSON"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-DATA-6002"
            },
            "httpStatus": {
              "const": 400
            },
            "jsonRpcCode": {
              "const": -32600
            },
            "grpcStatus": {
              "const": "INVALID_ARGUMENT"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "Invalid request"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-DATA-6003"
            },
            "httpStatus": {
              "const": 404
            },
            "jsonRpcCode": {
              "const": -32601
            },
            "grpcStatus": {
              "const": "NOT_FOUND"
            },
            "truthState": {
              "const": "DENIED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "Resource is unavailable"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-DATA-6004"
            },
            "httpStatus": {
              "const": 400
            },
            "jsonRpcCode": {
              "const": -32602
            },
            "grpcStatus": {
              "const": "INVALID_ARGUMENT"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "Request validation failed"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-RUNTIME-3007"
            },
            "httpStatus": {
              "const": 409
            },
            "jsonRpcCode": {
              "const": -32007
            },
            "grpcStatus": {
              "const": "ABORTED"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "Replay rejected"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-OPS-9003"
            },
            "httpStatus": {
              "const": 504
            },
            "jsonRpcCode": {
              "const": -32093
            },
            "grpcStatus": {
              "const": "DEADLINE_EXCEEDED"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "The service is unavailable"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-RUNTIME-3010"
            },
            "httpStatus": {
              "const": 503
            },
            "jsonRpcCode": {
              "const": -32010
            },
            "grpcStatus": {
              "const": "FAILED_PRECONDITION"
            },
            "truthState": {
              "const": "FAILED"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "The request could not be completed"
            }
          }
        },
        {
          "properties": {
            "code": {
              "const": "PC-FACT-4001"
            },
            "httpStatus": {
              "const": 409
            },
            "jsonRpcCode": {
              "const": -32031
            },
            "grpcStatus": {
              "const": "FAILED_PRECONDITION"
            },
            "truthState": {
              "const": "UNKNOWN"
            },
            "retryable": {
              "const": false
            },
            "disclosure": {
              "const": "NON_LEAKING_INVARIANT"
            },
            "publicTitle": {
              "const": "Result unknown"
            }
          }
        }
      ]
    },
    "RegisteredFieldId": {
      "type": "string",
      "pattern": "^PEF-[A-Z0-9-]{1,64}$"
    },
    "ScalarValue": {
      "oneOf": [
        {
          "type": "string",
          "maxLength": 256
        },
        {
          "type": "integer",
          "minimum": -9007199254740991,
          "maximum": 9007199254740991
        },
        {
          "type": "boolean"
        },
        {
          "type": "null"
        }
      ]
    },
    "PrivacyExplorerReleasedRecordV1": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "fields"
      ],
      "properties": {
        "id": {
          "$ref": "#/$defs/BoundedString"
        },
        "fields": {
          "type": "array",
          "maxItems": 64,
          "uniqueItems": true,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
              "fieldId",
              "value"
            ],
            "properties": {
              "fieldId": {
                "$ref": "#/$defs/RegisteredFieldId"
              },
              "value": {
                "$ref": "#/$defs/ScalarValue"
              }
            }
          }
        }
      }
    }
  },
  "x-openpc-executionRegistry": {
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
  }
};
const ajv = new Ajv2020({ allErrors: true, strict: true });
ajv.addKeyword({ keyword: 'x-openpc-executionRegistry', schemaType: 'object', valid: true });
addFormats(ajv);
ajv.addSchema(privacyExplorerSchema);
const orderedUnique = (values, key) => Array.isArray(values) && values.every((value, index) => index === 0 || key(values[index - 1]) < key(value));
const canonicalScalar = (value) => JSON.stringify(value);
const filterKey = (entry) => `${entry.fieldId}\u0000${entry.filterId}\u0000${canonicalScalar(entry.value)}`;
const profileRelations = (value) => value.operationVersions.length === 9 && orderedUnique(value.operationVersions, (entry) => entry.operationId) && value.operationVersions.every((entry) => orderedUnique(entry.acceptedDataClassIds, (dataClassId) => dataClassId)) && orderedUnique(value.allowedFieldIds, (entry) => entry) && orderedUnique(value.allowedFilterIds, (entry) => entry) && value.retryBackoffMilliseconds.length === value.maximumReadAttempts - 1 && value.retryBackoffMilliseconds.every((delay, index) => index === 0 || value.retryBackoffMilliseconds[index - 1] <= delay);
const requestRelations = (value) => {
  const operation = value.exportProfile.operationVersions.find((entry) => entry.operationId === value.operationId && entry.version === value.semanticOperationVersion);
  return profileRelations(value.exportProfile) && value.scope.action === value.action && Boolean(operation?.acceptedDataClassIds.includes(value.dataClassId)) && value.page.limit <= value.exportProfile.maximumPageSize && orderedUnique(value.filters, filterKey) && orderedUnique(value.projectionFields, (entry) => entry) && value.projectionFields.every((fieldId) => value.exportProfile.allowedFieldIds.includes(fieldId)) && value.filters.every((filter) => value.projectionFields.includes(filter.fieldId) && value.exportProfile.allowedFilterIds.includes(filter.filterId));
};
const recordOrder = (value) => orderedUnique(value.records, (entry) => entry.id) && value.records.every((record) => orderedUnique(record.fields, (entry) => entry.fieldId));
const outcomeTruth = { COMPLETE: 'TRUE', PARTIAL: 'PARTIAL', UNKNOWN: 'UNKNOWN', UNAVAILABLE: 'UNAVAILABLE' };
const resultRelations = (value) => {
  if (!recordOrder(value) || outcomeTruth[value.outcome] !== value.truthState) return false;
  if (value.outcome === 'COMPLETE') return value.page.gapFree === true && value.page.cursor === null;
  if (value.outcome === 'PARTIAL') return value.page.gapFree === false || value.page.cursor !== null;
  return value.records.length === 0 && value.page.gapFree === false && value.page.cursor === null;
};
const extraChecks = {
  PrivacyExplorerExportProfileV1: profileRelations,
  ExplorerProjectionRequestV1: requestRelations,
  AdapterCallContextV1: (value) => orderedUnique(value.accessClassIds, (entry) => entry) && value.cancellation.occurrenceId === value.occurrenceId && value.reconciliation.occurrenceId === value.occurrenceId,
  ExplorerProjectionResultV1: recordOrder,
  PrivacyExplorerResultV1: resultRelations,
};
const withChecks = (base, extra = () => true) => {
  const validate = (value) => {
    const valid = base(value) && extra(value);
    validate.errors = valid ? null : (base.errors ?? [{ keyword: 'x-openpc-order-or-relation', message: 'ordering or cross-field relation failed' }]);
    return valid;
  };
  validate.errors = null;
  return validate;
};
const baseValidatePrivacyExplorerDocument = ajv.getSchema("https://schemas.openpc.local/privacy-explorer.schema.json");
if (!baseValidatePrivacyExplorerDocument) throw new Error('Privacy Explorer root validator was not compiled');
export const validatePrivacyExplorerDocument = withChecks(baseValidatePrivacyExplorerDocument, (value) => (!value.request || requestRelations(value.request)) && (!value.result || resultRelations(value.result)) && (!value.request || !value.result || (value.request.exportProfile.digest === value.result.profileDigest && value.request.queryDigest === value.result.queryDigest)));
const baseValidateAdapterCallContextV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/AdapterCallContextV1" });
export const validateAdapterCallContextV1 = withChecks(baseValidateAdapterCallContextV1, extraChecks.AdapterCallContextV1);
const baseValidateBoundedString = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/BoundedString" });
export const validateBoundedString = withChecks(baseValidateBoundedString, extraChecks.BoundedString);
const baseValidateBoundedStringSet = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/BoundedStringSet" });
export const validateBoundedStringSet = withChecks(baseValidateBoundedStringSet, extraChecks.BoundedStringSet);
const baseValidateDigest = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/Digest" });
export const validateDigest = withChecks(baseValidateDigest, extraChecks.Digest);
const baseValidateEvidenceReferenceV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/EvidenceReferenceV1" });
export const validateEvidenceReferenceV1 = withChecks(baseValidateEvidenceReferenceV1, extraChecks.EvidenceReferenceV1);
const baseValidateEvidenceVerificationResultV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/EvidenceVerificationResultV1" });
export const validateEvidenceVerificationResultV1 = withChecks(baseValidateEvidenceVerificationResultV1, extraChecks.EvidenceVerificationResultV1);
const baseValidateExplorerProjectionRequestV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/ExplorerProjectionRequestV1" });
export const validateExplorerProjectionRequestV1 = withChecks(baseValidateExplorerProjectionRequestV1, extraChecks.ExplorerProjectionRequestV1);
const baseValidateExplorerProjectionResultV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/ExplorerProjectionResultV1" });
export const validateExplorerProjectionResultV1 = withChecks(baseValidateExplorerProjectionResultV1, extraChecks.ExplorerProjectionResultV1);
const baseValidateOccurrenceId = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/OccurrenceId" });
export const validateOccurrenceId = withChecks(baseValidateOccurrenceId, extraChecks.OccurrenceId);
const baseValidatePrivacyExplorerEvidenceDigestRecordV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/PrivacyExplorerEvidenceDigestRecordV1" });
export const validatePrivacyExplorerEvidenceDigestRecordV1 = withChecks(baseValidatePrivacyExplorerEvidenceDigestRecordV1, extraChecks.PrivacyExplorerEvidenceDigestRecordV1);
const baseValidatePrivacyExplorerExportProfileV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/PrivacyExplorerExportProfileV1" });
export const validatePrivacyExplorerExportProfileV1 = withChecks(baseValidatePrivacyExplorerExportProfileV1, extraChecks.PrivacyExplorerExportProfileV1);
const baseValidatePrivacyExplorerOccurrenceV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/PrivacyExplorerOccurrenceV1" });
export const validatePrivacyExplorerOccurrenceV1 = withChecks(baseValidatePrivacyExplorerOccurrenceV1, extraChecks.PrivacyExplorerOccurrenceV1);
const baseValidatePrivacyExplorerProblemV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/PrivacyExplorerProblemV1" });
export const validatePrivacyExplorerProblemV1 = withChecks(baseValidatePrivacyExplorerProblemV1, extraChecks.PrivacyExplorerProblemV1);
const baseValidatePrivacyExplorerReleasedRecordV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/PrivacyExplorerReleasedRecordV1" });
export const validatePrivacyExplorerReleasedRecordV1 = withChecks(baseValidatePrivacyExplorerReleasedRecordV1, extraChecks.PrivacyExplorerReleasedRecordV1);
const baseValidatePrivacyExplorerResultV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/PrivacyExplorerResultV1" });
export const validatePrivacyExplorerResultV1 = withChecks(baseValidatePrivacyExplorerResultV1, extraChecks.PrivacyExplorerResultV1);
const baseValidatePrivacyExplorerSourceBindingV1 = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/PrivacyExplorerSourceBindingV1" });
export const validatePrivacyExplorerSourceBindingV1 = withChecks(baseValidatePrivacyExplorerSourceBindingV1, extraChecks.PrivacyExplorerSourceBindingV1);
const baseValidateRegisteredFieldId = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/RegisteredFieldId" });
export const validateRegisteredFieldId = withChecks(baseValidateRegisteredFieldId, extraChecks.RegisteredFieldId);
const baseValidateScalarValue = ajv.compile({ $ref: "https://schemas.openpc.local/privacy-explorer.schema.json#/$defs/ScalarValue" });
export const validateScalarValue = withChecks(baseValidateScalarValue, extraChecks.ScalarValue);
