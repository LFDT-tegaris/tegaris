import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

const implementationPlanHash = '0d955672a57b3556155fbb4309ccff839e166410bd9b2ff1098a23f19869afb2';
const c17ArchiveHash = '36242402f8ace4b1cff124385b0be45e8e2a2c1fed9ceb980be2644052309ed5';
const gate2PlanHash = '55aa9d29247c89016c68f75b68a2d0f18a6e0c5957994496f451e28ddda886e3';
const defaults = Object.freeze({
  calls: Object.freeze([]),
  retries: 0,
  evidence: Object.freeze({
    count: 0,
    digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
    identities: Object.freeze([]),
  }),
  audit: Object.freeze([]),
  events: Object.freeze([]),
  publicResponses: Object.freeze([]),
  order: Object.freeze([]),
  cleanup: Object.freeze({ apps: 0, endpoints: 0, timers: 0, sockets: 0 }),
});

const owners = Object.freeze({
  route: Object.freeze({
    ownerInput: 'public Control API request bytes plus server-held context/profile',
    constructor: 'strict JSON admission and governed request reconstruction',
    validator: 'B02 admission plus B01/B03 result and receipt validators',
    consumer: 'public API client through Control API route',
    retainedFact: 'safe public result/problem plus measured sink/event counters',
  }),
  endpoint: Object.freeze({
    ownerInput: 'closed endpoint vector and TLS peer identity',
    constructor: 'ownVectors and ephemeral trust constructor',
    validator: 'exact DER, TLS, method, path, header, body and budget validator',
    consumer: 'B01 HTTPS consumer or hostile direct client',
    retainedFact: 'bounded call record and terminal resource counts',
  }),
  immutable: Object.freeze({
    ownerInput: 'accepted Gate2 and sealed P00 immutable identities',
    constructor: 'fixed hash and consumer join',
    validator: 'exact digest and negative-space validator',
    consumer: 'Gate3 composed route and verifier',
    retainedFact: 'immutable reuse identity and NOT_PROVEN_OPEN claim ceiling',
  }),
});

const define = (
  id,
  title,
  requirement,
  owner,
  expected = {},
  disposition = 'EXECUTED',
  authority = 'C17',
) => {
  const requirementSource =
    authority === 'C17'
      ? `C17_ARCHIVE_36242402#I07_AF32_${requirement}`
      : 'governance/audits/I07_GATE2_OUTPUTS_AND_CONTRACTS_CAUSAL_PLAN_20260904.md#R01-R21';
  return Object.freeze({
    id,
    title,
    requirement,
    requirementSource,
    requirementHash: authority === 'C17' ? c17ArchiveHash : gate2PlanHash,
    implementationPlanHash,
    disposition,
    ...owners[owner],
    expected: Object.freeze({ ...defaults, ...expected }),
  });
};

const deepFreeze = (value) => {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
};

const expectedResults = deepFreeze({
  'B04-001': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-002': {
    calls: [
      {
        path: '/v1/privacy-explorer/evidence:verify',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:cd081ea5bf6c6161b46c74e5c9efcfacb30c321d416bf293d9e0353c52141b38',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-003': {
    calls: [
      {
        path: '/v1/privacy-explorer/evidence:verify',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:cd081ea5bf6c6161b46c74e5c9efcfacb30c321d416bf293d9e0353c52141b38',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-004': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-005': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:d717d2e279e69ea3ce7e7d85e4d187099d80f11f29c975de8f793303407640a6',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'PARTIAL',
          resultDigest: 'sha256:ef7642dcd32b85fb778fcba424096a9ae20b9b774fca3bf0f4e3c02ba6eda5cc',
          recordDigest: 'sha256:e26636b9971d148775daaf627e99350481d8ed5aafd702378e669b1bc6c16eb9',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:d6650224b06b1b5b8cf00e768578d6d5735e13d9f9bc456c59c96c9fc45cc5e5',
        outcome: 'PARTIAL',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-006': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:2e73bf07c6296e7010ee34a54a7e056c819628f206d4d01ca5fabb42b4fb6315',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNKNOWN',
          resultDigest: 'sha256:336e8827b3deb930ff5fd28b277cc43460f58bd7e15e2b19c0e8bd186a2338fe',
          recordDigest: 'sha256:1500b76e4fd8f26f20809b0336bf6937ee9061a12585d73c056994d7a9b241f1',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:9e780bdb630190aa9c73666a818a9b1def025df13e53d4772cbca39881e4ed89',
        outcome: 'UNKNOWN',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-007': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:b5beffb3b21dba636ec398accd5e241370b4a63d2d09294d83b99833a723746b',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:128ba912a4218ab118b5abfe6342cd43d6ce06c110a2a623ea689b17260d4fd0',
          recordDigest: 'sha256:e27e21370544ef15d8b6d74b63920403e65109f1b4bc8d9d35ae70ed9ad5b972',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:aaf54c452e41af9f5897ebe347ab6009d1f506ddefccf5845da9ee8c6b71b035',
        outcome: 'UNAVAILABLE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-008': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-009': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-010': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-011': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-012': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 1,
    evidence: {
      count: 1,
      digest: 'sha256:46fa14ab51b05c57203c56643cdf229985f0a4632455484574689fa873cd5824',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
          recordDigest: 'sha256:9594d4d79745a18f65d3275922adb1357c1b599f09f41b5650c6e1f2c4b22715',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
        code: 'PC-INTEGRATION-5001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-013': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 1,
    evidence: {
      count: 1,
      digest: 'sha256:46fa14ab51b05c57203c56643cdf229985f0a4632455484574689fa873cd5824',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
          recordDigest: 'sha256:9594d4d79745a18f65d3275922adb1357c1b599f09f41b5650c6e1f2c4b22715',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
        code: 'PC-INTEGRATION-5001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-014': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 1,
    evidence: {
      count: 1,
      digest: 'sha256:46fa14ab51b05c57203c56643cdf229985f0a4632455484574689fa873cd5824',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
          recordDigest: 'sha256:9594d4d79745a18f65d3275922adb1357c1b599f09f41b5650c6e1f2c4b22715',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
        code: 'PC-INTEGRATION-5001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-015': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 1,
    evidence: {
      count: 1,
      digest: 'sha256:46fa14ab51b05c57203c56643cdf229985f0a4632455484574689fa873cd5824',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
          recordDigest: 'sha256:9594d4d79745a18f65d3275922adb1357c1b599f09f41b5650c6e1f2c4b22715',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
        code: 'PC-INTEGRATION-5001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-016': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 1,
    evidence: {
      count: 1,
      digest: 'sha256:46fa14ab51b05c57203c56643cdf229985f0a4632455484574689fa873cd5824',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
          recordDigest: 'sha256:9594d4d79745a18f65d3275922adb1357c1b599f09f41b5650c6e1f2c4b22715',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
        code: 'PC-INTEGRATION-5001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-017': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [{ phase: 'ADMISSION_REJECTED', attemptId: 'VALID_UUID_V4' }],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
    ],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-018': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [{ phase: 'ADMISSION_REJECTED', attemptId: 'VALID_UUID_V4' }],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-019': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [{ phase: 'ADMISSION_REJECTED', attemptId: 'VALID_UUID_V4' }],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-020': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [{ phase: 'ADMISSION_REJECTED', attemptId: 'VALID_UUID_V4' }],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-021': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-022': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-023': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-024': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [{ phase: 'ADMISSION_REJECTED', attemptId: 'VALID_UUID_V4' }],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-025': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [{ phase: 'ADMISSION_REJECTED', attemptId: 'VALID_UUID_V4' }],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-026': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [{ phase: 'ADMISSION_REJECTED', attemptId: 'VALID_UUID_V4' }],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-027': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-028': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-029': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-030': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-031': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-032': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-033': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-034': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-035': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-036': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-037': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-038': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-039': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-040': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-041': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-042': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-043': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-044': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-045': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-046': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-047': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-048': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-049': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-050': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-051': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-052': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-053': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-054': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-055': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:62649d3a6a701199d9fc5e598ed29b2baf4fb4e040c3875dbeb22690fa08a32f',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-056': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-057': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [
      {
        phase: 'EXECUTION_REJECTED',
        attemptId: 'VALID_UUID_V4',
        occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
      },
    ],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'SERVICE_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-058': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-059': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'EVIDENCE_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'EVIDENCE_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-060': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'EVIDENCE_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'EVIDENCE_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-061': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'EVIDENCE_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'EVIDENCE_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-062': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'AUDIT_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-063': {
    calls: [],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:46fa14ab51b05c57203c56643cdf229985f0a4632455484574689fa873cd5824',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
          recordDigest: 'sha256:9594d4d79745a18f65d3275922adb1357c1b599f09f41b5650c6e1f2c4b22715',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
        code: 'PC-INTEGRATION-5001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-064': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-065': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-066': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:898fb896291540bb80f142275f97fc7909737ffcdfb90385329ae0ee070bb46b',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:ab77c175e75bc3b460db844309ed27a2c10e859ec514d23feece15fc6566cd79',
          recordDigest: 'sha256:b733eb2bf6e7ece4202b982dfdfc0032ff466f77d44ea01d8ec991a6fdb44206',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 502,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:ab77c175e75bc3b460db844309ed27a2c10e859ec514d23feece15fc6566cd79',
        code: 'PC-RUNTIME-3009',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-067': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:898fb896291540bb80f142275f97fc7909737ffcdfb90385329ae0ee070bb46b',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:ab77c175e75bc3b460db844309ed27a2c10e859ec514d23feece15fc6566cd79',
          recordDigest: 'sha256:b733eb2bf6e7ece4202b982dfdfc0032ff466f77d44ea01d8ec991a6fdb44206',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 502,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:ab77c175e75bc3b460db844309ed27a2c10e859ec514d23feece15fc6566cd79',
        code: 'PC-RUNTIME-3009',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-068': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:f1d0ce175bcaa8e6e570058969b6e423a44e95607424bf3bcd7fa7f521a00a4c',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:fcf93a8c210d4ffa2dda47bb9fc37c7f6e54a8222ebdd07fffcbe90451dbacbb',
          recordDigest: 'sha256:2ce305e035e1fa02a5f20d45b3aa2ee1ae6525a1baf4f2c0c5c4a60c18bbba1f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 409,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:fcf93a8c210d4ffa2dda47bb9fc37c7f6e54a8222ebdd07fffcbe90451dbacbb',
        code: 'PC-RUNTIME-3011',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-069': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:a7d04a625db1bd6b0fc5382e674f1636beebbac2b4a5f807c2d411cc3235c35e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'CANCELLED_AFTER_DISPATCH_NO_RAW',
          resultDigest: 'sha256:3e70ad744b88c7f09d8f556831709d2efccce94a61d91d83a670b1ac24855c49',
          recordDigest: 'sha256:d3aad2365189ee60e265040295995c0f956483ee33d0d43ee4285e983d88099f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-070': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-071': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:2ce4d152dc17fab5190d0d390f4ede3396fb5a63a84bb69864ee5cd37be8e807',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:a8d2023fabd9d2fb1b84e282aef9e5d0f9704d89fe366193397d96f9f8261206',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:3711ca7b6f63ecf6963932b5e66563fd633548f5d306bda9cc0552d6875f8acf',
          recordDigest: 'sha256:c831064411411c51b642e952c568e4a4ccccb3aed9cc1b3c1a360a2f41a643f4',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:c249b4a3772f7dc55f4fcd2cfefa5af865ba1b491306c61a81da6c30d1bc4c6d',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-072': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:5ef008ddf39920915bce997ba4b70e136a2f7ea6211819ab9eac35780df60b57',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:151884b859fc7a98c4caf5984d58dbe1c968675ba62b99b75972de5f64c3a53f',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:83561b262c535861d685fde01ea2036881f7a9cdda2ef3b9de0e017c910b2e7f',
          recordDigest: 'sha256:b29a707602fa3c537e6c8b3e9cbb4296a45c8062a2a34a0f4cbce1e06938d5e1',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:1217a7580fda37b1bb3c82941021702ecea4c56a513e29ff5394a1490a5fdc4e',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-073': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:becc22501eaccad44964ca8402328faf712f8b9a5d2c5f60274545b60ea25ba2',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:441f6fca8e8bd48564dd9070cd82c12ef973364fe55a80f9b292f4d1eeb234c8',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:0cb1ac3009779f8d2c7f07ec7ea48dc82c49cf6e60456f7cf8a703a8ac6d0ddc',
          recordDigest: 'sha256:d4d570ed5b00c7eb94f578d0cb264de9b2270b12bd919b25a062689da6c1a985',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:63b618973c69f898a26872e32b2b1f970e0f326ea2f341013257e633c9a68fc1',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-074': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:543168a7d7c327e7959c62f071aebdfb487fe57d62c3a9ec74edaeba1f705d5e',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:4353e06765917323c078261746e88f515079640ff5c44ea688113f07d5de3243',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:deee04f89aaf7b29502281d6640fe2de355350ba023bb1599a839b597c96979b',
          recordDigest: 'sha256:39ff0b0d04d7dd3489ba4d7f020f6f1e348f0d85d6be2839efe6238bcee83c60',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:3bc20b9805552c944ced971cd51b928b3db3141af3e14280fd59a5d7f6cd7d63',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-075': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:ebfbdd926f8c25f44918231f40c57ddc9c99c2eae967b315d9c2bc3e331b71cd',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:1bdeff25920058f57c86cf5942b3e6bf19537d06e47a1416db381a7a8a64291b',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:50b5cd06ca46beb5533b12e121bb262bcd811ec0e738162ee30191e25c434dcf',
          recordDigest: 'sha256:7fe57939fbc6f67646a4f2c299411a5202c83a2aced06aa751b3d9fd127bb9a9',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:e5793bbe83b4ecb8a574ebe7e50889913a8a6fa17bf1fd484d19397f4bc58d37',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-076': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:e7ea2ccc415e90f71bc6a74ffe0aa2fe76cb1f3b94a2377e96ca902be5d7dce8',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:fb9cbc5dce515721a09e92dbd3abc88f49296991bbb90cb931f12bbeb353bdd4',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:e8a29e04bff33f5c769c28b11e3be2d068753c4014bb5efe84ae76273542462d',
          recordDigest: 'sha256:e795c2949a85c32fcb8c68f6e89c41de19aa9028858e98e28002caac1d1e88c3',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:9404b6ee4077b644cf58e8794353ce128bf8178a6a67c71c46950f055335feb6',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-077': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:f4a467020aae58e2639316b590b11652eb321fc311191dfc6a1ab235fd414596',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:2ea74631cbf8ae8712344f651526f426baf0ca3be9179f8571d906e54000ec60',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:3130784b8cd9c837ccb47409f79399cd68fcf9848aae7ae49886558264ffa232',
          recordDigest: 'sha256:7fb0d400cd5aaa618f1259fb1eccca244218937c72e78a947b00240fb97e28b0',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:16745f50e36bcb8df7d2c889da34b5decc386194867427dec0df6aec0fc36f9b',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-078': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:1b75ca8379cf4b295387a55a1ee0bbd709b3860bfcb8737ecb656eb32faa1086',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:6aa70c29c6c2c734f158c221f9f6b46cafecb0388af0d82e9adf79a380ef8cb9',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:7d26f2ad495f38a329d23baa5ac564982ae1a68a23bfdce4604523175ae6515a',
          recordDigest: 'sha256:b6389ce83e87666531ab3fc85f8588fef4878a5ed6290d6e63be9e310570e4fd',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:dbba26b483e8e2e6975df8c915ace7ed6d06bc091d24889d5039cd3f512b8477',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-079': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 0, endpoints: 0, timers: 0, sockets: 0 },
  },
  'B04-080': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-081': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-082': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-083': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-084': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [{ phase: 'ADMISSION_SUPPRESSED', attemptId: 'VALID_UUID_V4' }],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-085': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'AUDIT_FAILURE',
      },
    ],
    publicResponses: [],
    order: [],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-086': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'EXECUTION_REJECTED',
        attemptId: 'VALID_UUID_V4',
        occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
      },
    ],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'SERVICE_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-087': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-088': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: { apps: 1, endpoints: 1, timers: 0, sockets: 0 },
  },
  'B04-089': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-090': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:1edced82c8b151be99cf975dba606da950a10efed9d3717cf6bbf994ed6515d8',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:ab77c175e75bc3b460db844309ed27a2c10e859ec514d23feece15fc6566cd79',
          recordDigest: 'sha256:1120f8963dcf467fa9e03adb95d1ce168d79caabc97a64ac0caa70310787777e',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 502,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:ab77c175e75bc3b460db844309ed27a2c10e859ec514d23feece15fc6566cd79',
        code: 'PC-RUNTIME-3009',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-091': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-092': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:1edced82c8b151be99cf975dba606da950a10efed9d3717cf6bbf994ed6515d8',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:ab77c175e75bc3b460db844309ed27a2c10e859ec514d23feece15fc6566cd79',
          recordDigest: 'sha256:1120f8963dcf467fa9e03adb95d1ce168d79caabc97a64ac0caa70310787777e',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 502,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:ab77c175e75bc3b460db844309ed27a2c10e859ec514d23feece15fc6566cd79',
        code: 'PC-RUNTIME-3009',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-093': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-094': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 1,
    evidence: {
      count: 1,
      digest: 'sha256:46fa14ab51b05c57203c56643cdf229985f0a4632455484574689fa873cd5824',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
          recordDigest: 'sha256:9594d4d79745a18f65d3275922adb1357c1b599f09f41b5650c6e1f2c4b22715',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
        code: 'PC-INTEGRATION-5001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-095': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-096': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-097': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-098': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-099': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-100': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-101': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-102': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:7e98387e98b3f3e72c8817dc2984c8a14abbbc84e76086d4e590629b56c43d8e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'FAILED',
          resultDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
          recordDigest: 'sha256:0cb4133c59f03763b2ef6362cf9b11d31a604a4262fdef18813f06d42247d76f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5efab02ab8afe0f76e142b37d5cf2a4505d29996e508c95ed4a388f9d7fd8134',
        code: 'PC-DATA-6001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-103': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-104': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-105': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-107': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-108': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-109': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-110': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-111': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-112': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-113': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-114': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-115': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-116': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-117': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-118': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-119': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 400,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:dc8944e54be789a0dba725fe64777b30edfacc713d73df958b0517d5f184614f',
        code: 'PC-DATA-6002',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-121': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-123': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-124': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 0,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-125': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 0,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-126': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 0,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-127': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 0,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-128': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 0,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-130': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 0,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-131': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'EVIDENCE_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'EVIDENCE_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: ['EVIDENCE_ACCEPTED', 'CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-133': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'AUDIT_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-134': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'AUDIT_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-135': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'AUDIT_FAILURE',
      },
    ],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-136': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'AUDIT_FAILURE',
      },
    ],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-137': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'AUDIT_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-138': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'AUDIT_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'AUDIT_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:48b513263690228cc2f5edb5c57e83fccbda7520d126c55e80301d9b5edc951e',
        code: 'PC-RUNTIME-3010',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-106': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
    ],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-120': {
    calls: [],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:0beadfb134d4852c8152816ec097d05bd64c1539ec1505f5925b9b1fbc1925c3',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'UNAVAILABLE',
          resultDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
          recordDigest: 'sha256:d41d88ddd1e25ebf9f776ab53232daf19345da607578bf313e2c49b2dda99cac',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 503,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:5c5584b7639bb10ad37c32c592a572db0aee469b000e21858dd2a142f3e8c775',
        code: 'PC-INTEGRATION-5001',
      },
    ],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-122': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
      {
        phase: 'ADMISSION_REJECTED',
        attemptId: 'VALID_UUID_V4',
      },
    ],
    events: [
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
      {
        profileState: 'NOT_ADMITTED',
        outcomeClass: 'SAFE_PROBLEM',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
      {
        statusCode: 401,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:9b8e8119b4c594ee07faa7ab53b752dc3cfb0229f989b22a4bf2a613130e5a21',
        code: 'PC-AUTH-0001',
      },
    ],
    order: [],
    cleanup: {
      apps: 2,
      endpoints: 2,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-129': {
    calls: [],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 0,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-132': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'EVIDENCE_FAILURE',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'EVIDENCE_FAILURE',
      },
    ],
    publicResponses: [
      {
        statusCode: 409,
        contentType: 'application/problem+json; charset=utf-8',
        bodyDigest: 'sha256:71a759ea3038f54a3122f468b4b894fb88ec7cc30a134148c07b0faf72ad6726',
        code: 'PC-RUNTIME-3007',
      },
    ],
    order: ['CONTROL_API_RESPONSE'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-139': {
    calls: [],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:9fcf583019b93e15700ac3ed30ea19aec9fcb06e3922c3e7b3c7da48027eb947',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'CANCELLED_BEFORE_DISPATCH',
          resultDigest: 'sha256:6f9d451986ec8dfd1a7fb7007198e5e609b951f8c82b3865f5c9dd5000750382',
          recordDigest: 'sha256:e49733e796f2976fdea75c12e9eea20b9d9a7af056fea051d1e8715b270b7f73',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-140': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
      {
        path: '/v1/privacy-explorer/evidence:verify',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:cd081ea5bf6c6161b46c74e5c9efcfacb30c321d416bf293d9e0353c52141b38',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:a7d04a625db1bd6b0fc5382e674f1636beebbac2b4a5f807c2d411cc3235c35e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'CANCELLED_AFTER_DISPATCH_NO_RAW',
          resultDigest: 'sha256:3e70ad744b88c7f09d8f556831709d2efccce94a61d91d83a670b1ac24855c49',
          recordDigest: 'sha256:d3aad2365189ee60e265040295995c0f956483ee33d0d43ee4285e983d88099f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: {
      apps: 2,
      endpoints: 2,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-141': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:a7d04a625db1bd6b0fc5382e674f1636beebbac2b4a5f807c2d411cc3235c35e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'CANCELLED_AFTER_DISPATCH_NO_RAW',
          resultDigest: 'sha256:3e70ad744b88c7f09d8f556831709d2efccce94a61d91d83a670b1ac24855c49',
          recordDigest: 'sha256:d3aad2365189ee60e265040295995c0f956483ee33d0d43ee4285e983d88099f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-142': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 0,
      digest: 'sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
      identities: [],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: [],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-143': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-144': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-145': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:04f853c0116a2e2b8cfeeed9e34e108aee403481cf769e6d432ae9d805d4cdcc',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'COMPLETE',
          resultDigest: 'sha256:8f1d4cc52b3fa7a1394750a96477fbb18413e70c0a8f9c8de03c0f6638d46686',
          recordDigest: 'sha256:23d377458b864dee9f87f58009351a6c685be196625fe65cc757acf1e663f5ea',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'RELEASED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [
      {
        statusCode: 200,
        contentType: 'application/json; charset=utf-8',
        bodyDigest: 'sha256:f67b56370516350b0e4ec9b8d5540b232750f063956ee819b453ddc0b699d273',
        outcome: 'COMPLETE',
      },
    ],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
  'B04-146': {
    calls: [
      {
        path: '/v1/privacy-explorer/projection:read',
        method: 'POST',
        contentType: 'application/json',
        tlsProtocol: 'TLSv1.3',
        clientCommonName: 'openpc-i07-gate3-client',
        bodyDigest: 'sha256:9061b78aa8819ccb652c297ebfe9e7709a89d9ad902f98ab179f48eb60c183ce',
      },
    ],
    retries: 0,
    evidence: {
      count: 1,
      digest: 'sha256:a7d04a625db1bd6b0fc5382e674f1636beebbac2b4a5f807c2d411cc3235c35e',
      identities: [
        {
          occurrenceId: '123e4567-e89b-42d3-a456-426614174101',
          outcome: 'CANCELLED_AFTER_DISPATCH_NO_RAW',
          resultDigest: 'sha256:3e70ad744b88c7f09d8f556831709d2efccce94a61d91d83a670b1ac24855c49',
          recordDigest: 'sha256:d3aad2365189ee60e265040295995c0f956483ee33d0d43ee4285e983d88099f',
        },
      ],
    },
    audit: [],
    events: [
      {
        correlationId: '123e4567-e89b-42d3-a456-426614174102',
        profileState: 'ADMITTED',
        outcomeClass: 'SUPPRESSED',
        durationMilliseconds: 'NON_NEGATIVE_INTEGER',
        errorClass: 'NONE',
      },
    ],
    publicResponses: [],
    order: ['EVIDENCE_ACCEPTED'],
    cleanup: {
      apps: 1,
      endpoints: 1,
      timers: 0,
      sockets: 0,
    },
  },
});

const caseSpecifications = Object.freeze([
  Object.freeze({
    id: 'B04-001',
    title:
      'uses the API client through Control API, real mTLS transport, and evidence-before-delivery',
    requirement: 'G3-03_G3-05_G3-07_G3-11_G3-13_G3-16_G3-17_G3-18',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-002',
    title: 'executes evidence verification once on its distinct fixed path without retry',
    requirement: 'G3-04_VERIFY_POSITIVE',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-003',
    title: 'rejects an invalid evidence verification response without retry',
    requirement: 'G3-04_VERIFY_NEGATIVE',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-004',
    title: 'preserves the explicit COMPLETE outcome through the actual API client',
    requirement: 'G3-10_COMPLETE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-005',
    title: 'preserves the explicit PARTIAL outcome through the actual API client',
    requirement: 'G3-10_PARTIAL',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-006',
    title: 'preserves the explicit UNKNOWN outcome through the actual API client',
    requirement: 'G3-10_UNKNOWN',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-007',
    title: 'preserves the explicit UNAVAILABLE outcome through the actual API client',
    requirement: 'G3-10_UNAVAILABLE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-008',
    title: 'contains the malformed JSON Explorer response as a non-leaking registered problem',
    requirement: 'G3-09_MALFORMED_JSON',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-009',
    title: 'contains the duplicate member Explorer response as a non-leaking registered problem',
    requirement: 'G3-09_DUPLICATE_MEMBER',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-010',
    title: 'contains the invalid UTF-8 Explorer response as a non-leaking registered problem',
    requirement: 'G3-09_INVALID_UTF_8',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-011',
    title: 'contains the empty body Explorer response as a non-leaking registered problem',
    requirement: 'G3-09_EMPTY_BODY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-012',
    title: 'contains the wrong content type Explorer response as a non-leaking registered problem',
    requirement: 'G3-09_WRONG_CONTENT_TYPE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-013',
    title:
      'contains the undeclared success status Explorer response as a non-leaking registered problem',
    requirement: 'G3-09_UNDECLARED_SUCCESS_STATUS',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-014',
    title: 'contains the redirect Explorer response as a non-leaking registered problem',
    requirement: 'G3-09_REDIRECT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-015',
    title: 'contains the oversized body Explorer response as a non-leaking registered problem',
    requirement: 'G3-09_OVERSIZED_BODY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-016',
    title: 'preserves an exact registered Explorer problem without retry or raw detail',
    requirement: 'G3-09_G3-13_REGISTERED_PROBLEM',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-017',
    title: 'rejects an unauthenticated public request before egress',
    requirement: 'G3-01_UNAUTHENTICATED',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-018',
    title: 'rejects server-context-mismatched subject hidden-subject before egress',
    requirement: 'G3-01_CONTEXT_HIDDEN_SUBJECT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-019',
    title: 'rejects server-context-mismatched subject nonexistent-subject before egress',
    requirement: 'G3-01_CONTEXT_NONEXISTENT_SUBJECT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-020',
    title: 'rejects the field-isolated issuedAt mutation with zero fetch',
    requirement: 'G3-02_G3-05_G3-06_FIELD_ISSUEDAT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-021',
    title: 'rejects the field-isolated scope.chainId mutation with zero fetch',
    requirement: 'G3-02_G3-05_G3-06_FIELD_SCOPE_CHAINID',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-022',
    title: 'rejects the field-isolated queryDigest mutation with zero fetch',
    requirement: 'G3-02_G3-05_G3-06_FIELD_QUERYDIGEST',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-023',
    title: 'rejects the field-isolated occurrenceId mutation with zero fetch',
    requirement: 'G3-02_G3-05_G3-06_FIELD_OCCURRENCEID',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-024',
    title: 'rejects the nested duplicate root schemaVersion member with zero fetch',
    requirement: 'G3-02_G3-06_DUPLICATE_ROOT_SCHEMAVERSION',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-025',
    title: 'rejects the nested duplicate subject member with zero fetch',
    requirement: 'G3-02_G3-06_DUPLICATE_SUBJECT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-026',
    title: 'rejects the nested duplicate scope participantId member with zero fetch',
    requirement: 'G3-02_G3-06_DUPLICATE_SCOPE_PARTICIPANTID',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-027',
    title: 'keeps the exact nine-operation registry structural',
    requirement: 'G3-05_NINE_OPERATION_REGISTRY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-028',
    title: 'rejects the duplicate operation registry mutation before fetch',
    requirement: 'G3-05_REGISTRY_DUPLICATE_OPERATION',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-029',
    title: 'rejects the missing operation registry mutation before fetch',
    requirement: 'G3-05_REGISTRY_MISSING_OPERATION',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-030',
    title: 'rejects the wrong operation version registry mutation before fetch',
    requirement: 'G3-05_REGISTRY_WRONG_OPERATION_VERSION',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-031',
    title: 'rejects the wrong data class registry mutation before fetch',
    requirement: 'G3-05_REGISTRY_WRONG_DATA_CLASS',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-032',
    title: 'rejects undeclared method/path /unknown without consuming a vector',
    requirement: 'G3-07_UNKNOWN_PATH',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-033',
    title:
      'rejects undeclared method/path /v1/privacy-explorer/projection:read?escape=1 without consuming a vector',
    requirement: 'G3-03_G3-07_QUERY_ESCAPE',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-034',
    title:
      'rejects undeclared method/path /v1/privacy-explorer/evidence:verify without consuming a vector',
    requirement: 'G3-04_WRONG_METHOD',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-035',
    title: 'rejects an absent client certificate before endpoint application handling',
    requirement: 'G3-17_ABSENT_CLIENT',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-036',
    title: 'rejects an undeclared envelope without consuming the declared read vector',
    requirement: 'G3-07_EXACT_BODY',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-037',
    title: 'rejects a CA-signed but unadmitted client identity before HTTP handling',
    requirement: 'G3-17_WRONG_CLIENT_IDENTITY',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-038',
    title: 'rejects a CA-signed same-CN certificate with a different key before HTTP handling',
    requirement: 'G3-17_EXACT_CLIENT_DER',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-039',
    title: 'rejects untrusted client CA before vector consumption',
    requirement: 'G3-17_UNTRUSTED_CLIENT_CA',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-040',
    title: 'rejects TLS downgrade before vector consumption',
    requirement: 'G3-17_TLS_DOWNGRADE',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-041',
    title: 'rejects wrong server SAN before vector consumption',
    requirement: 'G3-17_WRONG_SERVER_SAN',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-042',
    title: 'rejects plain HTTP before endpoint vector consumption',
    requirement: 'G3-17_HTTPS_ONLY',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-043',
    title: 'exposes only the exact loopback server SAN',
    requirement: 'G3-17_EXACT_LOOPBACK_SAN',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-044',
    title: 'rejects a proxied endpoint vector without invoking its traps',
    requirement: 'G3-17_VECTOR_PROXY',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-045',
    title: 'rejects an accessor endpoint vector before reading the accessor',
    requirement: 'G3-17_VECTOR_ACCESSOR',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-046',
    title: 'rejects a hostile endpoint vector prototype',
    requirement: 'G3-17_VECTOR_PROTOTYPE',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-047',
    title: 'rejects an extra endpoint vector field',
    requirement: 'G3-17_VECTOR_EXTRA',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-048',
    title: 'rejects an omitted endpoint vector field',
    requirement: 'G3-17_VECTOR_OMISSION',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-049',
    title: 'rejects a proxied byte vector without invoking its traps',
    requirement: 'G3-17_BYTE_PROXY',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-050',
    title: 'rejects a byte-array subclass before invoking its iterator',
    requirement: 'G3-17_BYTE_SUBCLASS',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-051',
    title: 'rejects an own symbol on endpoint byte vectors',
    requirement: 'G3-17_BYTE_SYMBOL',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-052',
    title: 'rejects an own byte-vector iterator before invoking it',
    requirement: 'G3-17_BYTE_ITERATOR',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-053',
    title: 'rejects an absent B01 Accept header without consuming the vector',
    requirement: 'G3-17_B01_ACCEPT_HEADER',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-054',
    title: 'rejects a forbidden authorization header without consuming the vector',
    requirement: 'G3-17_B01_AUTHORIZATION_ABSENCE',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-055',
    title: 'copies request and response bytes before caller mutation',
    requirement: 'G3-17_IMMUTABLE_BYTE_COPY',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-056',
    title: 'returns the original append-once evidence receipt on exact sink replay',
    requirement: 'G3-11_SINK_EXACT_REPLAY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-057',
    title: 'suppresses an exact public replay after one accepted evidence write',
    requirement: 'G3-11_PUBLIC_REPLAY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-058',
    title: 'retains the first occurrence and returns conflict for different evidence',
    requirement: 'G3-11_CONFLICT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-059',
    title: 'fails closed when the evidence sink mode is REJECT',
    requirement: 'G3-11_SINK_REJECT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-060',
    title: 'fails closed when the evidence sink mode is TIMEOUT',
    requirement: 'G3-11_SINK_TIMEOUT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-061',
    title: 'fails closed when the evidence sink mode is MALFORMED',
    requirement: 'G3-11_SINK_MALFORMED',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-062',
    title: 'fails closed when the admission audit rejects',
    requirement: 'G3-12_ADMISSION_AUDIT_REJECT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-063',
    title: 'fails closed when the execution audit rejects after a malformed provider response',
    requirement: 'G3-12_EXECUTION_AUDIT_REJECT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-064',
    title: 'owns and completes the DELAYED response timer/stream mode',
    requirement: 'G3-08_G3-09_DELAYED',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-065',
    title: 'owns and completes the LATE_CHUNKS response timer/stream mode',
    requirement: 'G3-08_G3-09_LATE_CHUNKS',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-066',
    title: 'preserves the registered STALE wire outcome',
    requirement: 'G3-10_STALE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-067',
    title: 'preserves the registered REORG wire outcome',
    requirement: 'G3-10_REORG',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-068',
    title: 'preserves the registered CONFLICT wire outcome',
    requirement: 'G3-10_CONFLICT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-069',
    title: 'cancels a never-settling endpoint and owns every pending timer and socket',
    requirement: 'G3-08_G3-14_NEVER_SETTLE_ABORT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-070',
    title: 'executes registered operation index 0 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_0',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-071',
    title: 'executes registered operation index 1 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_1',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-072',
    title: 'executes registered operation index 2 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_2',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-073',
    title: 'executes registered operation index 3 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_3',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-074',
    title: 'executes registered operation index 4 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_4',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-075',
    title: 'executes registered operation index 5 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_5',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-076',
    title: 'executes registered operation index 6 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_6',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-077',
    title: 'executes registered operation index 7 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_7',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-078',
    title: 'executes registered operation index 8 through the public client and mTLS boundary',
    requirement: 'G3-04_G3-05_OPERATION_8',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-079',
    title: 'closes immutable predecessor, claim-ceiling, telemetry, and full-gate joins',
    requirement: 'R01-R21_G3-15_G3-19_G3-20_G3-21_G3-22_G3-23',
    owner: 'immutable',
    authority: 'GATE2',
  }),
  Object.freeze({
    id: 'B04-080',
    title: 'keeps the private-material root external with mode 0700',
    requirement: 'G3-17_PRIVATE_ROOT_0700',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-081',
    title: 'keeps every private key file at mode 0600',
    requirement: 'G3-17_PRIVATE_KEYS_0600',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-082',
    title: 'zeroes every exposed private-key byte on close',
    requirement: 'G3-17_PRIVATE_BYTES_ZEROED',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-083',
    title: 'removes the private root and all endpoint timers and sockets on close',
    requirement: 'G3-08_G3-17_TERMINAL_CLEANUP',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-084',
    title:
      'audits and emits admission suppression when the client disconnects during session resolution',
    requirement: 'G3-08_G3-12_ADMISSION_SUPPRESSED',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-085',
    title: 'emits audit failure and no response when admission-suppression audit rejects',
    requirement: 'G3-08_G3-12_ADMISSION_SUPPRESSED_AUDIT_FAILURE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-086',
    title: 'audits and emits an exact service failure without provider egress',
    requirement: 'G3-08_G3-12_SERVICE_FAILURE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-087',
    title: 'contains an SYNCHRONOUS event-sink failure after an accepted public result',
    requirement: 'G3-12_EVENT_SINK_SYNCHRONOUS_FAILURE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-088',
    title: 'contains an ASYNCHRONOUS event-sink failure after an accepted public result',
    requirement: 'G3-12_EVENT_SINK_ASYNCHRONOUS_FAILURE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-089',
    title: 'contains trailing JSON bytes as an exact non-leaking problem',
    requirement: 'G3-09_TRAILING_BYTES',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-090',
    title: 'contains an unknown top-level provider member as an exact non-leaking problem',
    requirement: 'G3-09_UNKNOWN_MEMBER',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-091',
    title: 'contains a poisonous provider key as an exact non-leaking problem',
    requirement: 'G3-09_POISONOUS_KEY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-092',
    title: 'keeps a forbidden provider-field canary out of every retained and public sink',
    requirement: 'G3-06_G3-13_FORBIDDEN_FIELD_CANARY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-093',
    title: 'accepts a valid Explorer response at the exact response-byte cap',
    requirement: 'G3-09_RESPONSE_BYTE_CAP_EXACT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-094',
    title: 'contains a controlled many-chunk response-byte overflow without partial release',
    requirement: 'G3-09_RESPONSE_BYTE_CAP_MANY_CHUNK_OVERFLOW',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-095',
    title: 'rejects a duplicate member in the inbound filter object before fetch',
    requirement: 'G3-02_DUPLICATE_INBOUND_FILTER',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-096',
    title: 'rejects a duplicate member in the inbound page object before fetch',
    requirement: 'G3-02_DUPLICATE_INBOUND_PAGE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-097',
    title: 'rejects a duplicate member in the inbound exportProfile object before fetch',
    requirement: 'G3-02_DUPLICATE_INBOUND_PROFILE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-098',
    title: 'rejects a duplicate member in the inbound operation version entry object before fetch',
    requirement: 'G3-02_DUPLICATE_INBOUND_OPERATION',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-099',
    title: 'rejects a duplicate member in the inbound occurrence object before fetch',
    requirement: 'G3-02_DUPLICATE_INBOUND_OCCURRENCE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-100',
    title: 'rejects a duplicate member in the outbound record object',
    requirement: 'G3-09_DUPLICATE_OUTBOUND_RECORD',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-101',
    title: 'rejects a duplicate member in the outbound field object',
    requirement: 'G3-09_DUPLICATE_OUTBOUND_FIELD',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-102',
    title: 'rejects a duplicate member in the outbound page object',
    requirement: 'G3-09_DUPLICATE_OUTBOUND_PAGE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-103',
    title: 'rejects empty session before parsing or provider fetch',
    requirement: 'G3-01_SESSION_EMPTY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-104',
    title: 'rejects duplicate session before parsing or provider fetch',
    requirement: 'G3-01_SESSION_DUPLICATE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-105',
    title: 'rejects malformed session before parsing or provider fetch',
    requirement: 'G3-01_SESSION_MALFORMED',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-106',
    title: 'rejects invalid session before parsing or provider fetch',
    requirement: 'G3-01_SESSION_INVALID',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-107',
    title: 'contains a session resolver failure before parsing or provider fetch',
    requirement: 'G3-01_SESSION_RESOLVER_FAILURE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-108',
    title: 'contains a terminal verifier denial before parsing or provider fetch',
    requirement: 'G3-01_TERMINAL_VERIFIER_DENIAL',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-109',
    title: 'rejects the remaining isolated resource assertion with zero fetch',
    requirement: 'G3-02_CONTEXT_RESOURCE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-110',
    title: 'rejects the remaining isolated scope.participantId assertion with zero fetch',
    requirement: 'G3-02_SCOPE_PARTICIPANT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-111',
    title: 'rejects the remaining isolated scope.privacyDomainId assertion with zero fetch',
    requirement: 'G3-02_SCOPE_PRIVACY_DOMAIN',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-112',
    title: 'rejects the remaining isolated scope.platformId assertion with zero fetch',
    requirement: 'G3-02_SCOPE_PLATFORM',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-113',
    title: 'rejects the remaining isolated scope.workloadId assertion with zero fetch',
    requirement: 'G3-02_SCOPE_WORKLOAD',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-114',
    title: 'rejects the remaining isolated scope.action assertion with zero fetch',
    requirement: 'G3-02_SCOPE_ACTION',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-115',
    title: 'rejects the remaining isolated exportProfile.digest assertion with zero fetch',
    requirement: 'G3-02_PROFILE_DIGEST',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-116',
    title: 'rejects the remaining isolated occurrence.correlationId assertion with zero fetch',
    requirement: 'G3-02_OCCURRENCE_CORRELATION',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-117',
    title: 'rejects the trusted-time future issuedAt boundary with zero fetch',
    requirement: 'G3-02_TIME_FUTURE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-118',
    title: 'rejects the trusted-time stale issuedAt boundary with zero fetch',
    requirement: 'G3-02_TIME_STALE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-119',
    title: 'rejects the trusted-time expired server deadline boundary with zero fetch',
    requirement: 'G3-02_TIME_DEADLINE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-120',
    title: 'rejects a caller cursor reconciliation mutation with zero fetch',
    requirement: 'G3-02_RECONCILIATION_CURSOR',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-121',
    title: 'rejects an already-cancelled public call with zero fetch',
    requirement: 'G3-08_CANCELLED_PRE_ROUTE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-122',
    title: 'returns byte-identical denial for invalid hidden and nonexistent sessions',
    requirement: 'G3-01_G3-13_DENIAL_EQUIVALENCE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-123',
    title: 'successfully redacts every provider-only field and canary from the public result',
    requirement: 'G3-06_G3-13_SUCCESS_REDACTION_CANARY',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-124',
    title: 'rejects a plain HTTP origin before any network call',
    requirement: 'G3-07_G3-17_HTTP_ORIGIN',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-125',
    title: 'rejects a wrong host origin before any network call',
    requirement: 'G3-07_G3-17_WRONG_ORIGIN_HOST',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-126',
    title: 'rejects a fallback transport origin field before any network call',
    requirement: 'G3-07_G3-17_FALLBACK_ABSENT',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-127',
    title: 'rejects a trust-all TLS option before constructing a binding',
    requirement: 'G3-07_G3-17_TRUST_ALL_ABSENT',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-128',
    title: 'rejects optional client authentication material before constructing a binding',
    requirement: 'G3-07_G3-17_OPTIONAL_AUTH_ABSENT',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-129',
    title: 'rejects a forged Host header without consuming a vector',
    requirement: 'G3-07_G3-17_EXACT_HOST',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-130',
    title: 'reports an owned loopback HTTPS-only endpoint network inventory',
    requirement: 'G3-17_OWNED_NETWORK_INVENTORY',
    owner: 'endpoint',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-131',
    title: 'contains a forged evidence receipt before public release',
    requirement: 'G3-11_FORGED_RECEIPT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-132',
    title: 'contains a composed evidence conflict before public release',
    requirement: 'G3-11_COMPOSED_CONFLICT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-133',
    title: 'fails closed when the admission-rejection audit mode is TIMEOUT',
    requirement: 'G3-12_ADMISSION_AUDIT_TIMEOUT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-134',
    title: 'fails closed when the admission-rejection audit mode is MALFORMED',
    requirement: 'G3-12_ADMISSION_AUDIT_MALFORMED',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-135',
    title: 'fails closed when the admission-suppression audit mode is TIMEOUT',
    requirement: 'G3-12_ADMISSION_SUPPRESSION_AUDIT_TIMEOUT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-136',
    title: 'fails closed when the admission-suppression audit mode is MALFORMED',
    requirement: 'G3-12_ADMISSION_SUPPRESSION_AUDIT_MALFORMED',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-137',
    title: 'fails closed when the execution-rejection audit mode is TIMEOUT',
    requirement: 'G3-12_EXECUTION_AUDIT_TIMEOUT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-138',
    title: 'fails closed when the execution-rejection audit mode is MALFORMED',
    requirement: 'G3-12_EXECUTION_AUDIT_MALFORMED',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-139',
    title: 'suppresses cancellation before provider dispatch',
    requirement: 'G3-08_ABORT_BEFORE_DISPATCH',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-140',
    title: 'suppresses cancellation during TLS transport',
    requirement: 'G3-08_ABORT_TLS_CONNECT',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-141',
    title: 'suppresses cancellation after response bytes and before validation',
    requirement: 'G3-08_ABORT_AFTER_BYTES',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-142',
    title: 'suppresses cancellation after validation and before evidence',
    requirement: 'G3-08_ABORT_AFTER_VALIDATION',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-143',
    title: 'suppresses cancellation during evidence acceptance',
    requirement: 'G3-08_ABORT_DURING_EVIDENCE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-144',
    title: 'suppresses after accepted evidence and before public send',
    requirement: 'G3-08_ABORT_AFTER_ACCEPTED_EVIDENCE',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-145',
    title: 'owns transport cleanup when the client disconnects after public bytes are sent',
    requirement: 'G3-08_ABORT_AFTER_SEND',
    owner: 'route',
    authority: 'C17',
  }),
  Object.freeze({
    id: 'B04-146',
    title: 'suppresses a late-chunk transport after the client disconnects',
    requirement: 'G3-08_ABORT_LATE_COMPLETION',
    owner: 'route',
    authority: 'C17',
  }),
]);

export const canonicalAtomicCases = Object.freeze(
  caseSpecifications.map(({ id, title, requirement, owner, authority }) =>
    define(
      id,
      title,
      requirement,
      owner,
      expectedResults[id],
      authority === 'GATE2' ? 'IMMUTABLE_REUSE' : 'EXECUTED',
      authority,
    ),
  ),
);

const canonicalJson = (value) => {
  if (value === null || ['boolean', 'number', 'string'].includes(typeof value))
    return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`;
};

export const computedAtomicCaseDigest = `sha256:${createHash('sha256')
  .update(canonicalJson(canonicalAtomicCases))
  .digest('hex')}`;
export const canonicalAtomicCaseDigest =
  'sha256:788a4df6f6a687e01f64b75da1a81e1d9a49c3a841a68ea0dde0cd83b9c9b373';

const expectedById = new Map(canonicalAtomicCases.map((candidate) => [candidate.id, candidate]));

export const validateCanonicalAtomicCases = () => {
  if (computedAtomicCaseDigest !== canonicalAtomicCaseDigest)
    throw new Error('Gate 3 canonical atomic-case digest mismatch');
  if (canonicalAtomicCases.length !== 146 || expectedById.size !== canonicalAtomicCases.length)
    throw new Error('Gate 3 canonical atomic-case inventory mismatch');
  for (const candidate of canonicalAtomicCases) {
    if (
      Object.keys(candidate).sort().join(',') !==
        'constructor,consumer,disposition,expected,id,implementationPlanHash,ownerInput,requirement,requirementHash,requirementSource,retainedFact,title,validator' ||
      candidate.implementationPlanHash !== implementationPlanHash ||
      ![c17ArchiveHash, gate2PlanHash].includes(candidate.requirementHash)
    )
      throw new Error(`invalid Gate 3 atomic case: ${candidate.id}`);
  }
  return Object.freeze({ cases: canonicalAtomicCases.length, digest: canonicalAtomicCaseDigest });
};

export const validateCanonicalRegistryCandidate = (candidate) => {
  validateCanonicalAtomicCases();
  if (!isDeepStrictEqual(candidate, canonicalAtomicCases))
    throw new Error('Gate 3 canonical registry candidate differs from fixed registry');
  return canonicalAtomicCaseDigest;
};

export const validateGate3Actuals = (actuals) => {
  validateCanonicalAtomicCases();
  if (!Array.isArray(actuals) || actuals.length !== canonicalAtomicCases.length)
    throw new Error('missing, skipped, filtered, or nonexecuting Gate 3 atomic case');
  const seen = new Set();
  const failures = [];
  for (const [index, actual] of actuals.entries()) {
    if (
      !actual ||
      typeof actual !== 'object' ||
      Array.isArray(actual) ||
      Object.keys(actual).sort().join(',') !==
        'audit,calls,cleanup,events,evidence,id,order,publicResponses,retries'
    )
      throw new Error('invalid Gate 3 actual result fields');
    if (seen.has(actual.id)) throw new Error('duplicate Gate 3 atomic execution');
    seen.add(actual.id);
    const expected = expectedById.get(actual.id);
    if (expected !== canonicalAtomicCases[index])
      throw new Error('reordered Gate 3 atomic execution');
    if (!expected || !isDeepStrictEqual(actual, { id: expected.id, ...expected.expected }))
      failures.push(Object.freeze({ id: actual.id, expected: expected?.expected, actual }));
  }
  if (failures.length)
    throw new Error(`Gate 3 atomic result mismatch: ${JSON.stringify(failures)}`);
  return Object.freeze({
    cases: canonicalAtomicCases.length,
    passed: actuals.length,
    digest: canonicalAtomicCaseDigest,
  });
};

export const validateGate3AtomicResult = (id, actual) => {
  validateCanonicalAtomicCases();
  const expected = canonicalAtomicCases.find((candidate) => candidate.id === id);
  if (!expected) throw new Error(`unknown Gate 3 atomic case: ${id}`);
  const complete = Object.freeze(actual);
  if (!isDeepStrictEqual(complete, expected.expected))
    throw new Error(
      `Gate 3 atomic result mismatch: ${JSON.stringify({ id, expected: expected.expected, actual })}`,
    );
  return Object.freeze({ id, digest: canonicalAtomicCaseDigest });
};

export const validateCompletedAtomicCases = (completed) => {
  validateCanonicalAtomicCases();
  const expected = canonicalAtomicCases.map(({ id }) => ({
    id,
    digest: canonicalAtomicCaseDigest,
  }));
  if (!isDeepStrictEqual(completed, expected))
    throw new Error(
      'missing, duplicate, reordered, skipped, filtered, or forged Gate 3 completion',
    );
  return Object.freeze({ cases: completed.length, digest: canonicalAtomicCaseDigest });
};

export const registerGate3AtomicCases = ({ it, afterAll }, execute) => {
  validateCanonicalAtomicCases();
  const completed = [];
  for (const atomicCase of canonicalAtomicCases) {
    it(atomicCase.title, async () => {
      const actual = await execute(atomicCase);
      completed.push(validateGate3AtomicResult(atomicCase.id, actual));
    });
  }
  afterAll(() => validateCompletedAtomicCases(completed));
};
