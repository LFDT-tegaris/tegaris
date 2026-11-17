import {
  deleteRuntimeArtifactBatch,
  runtimeArtifactRetirementPlan,
  runtimeArtifactRetirementPlanInput,
} from './runtime-artifact-deletion-contracts.js';
import { runtimeArtifactRetirementView } from './runtime-artifact-retirement.js';
import { registerProtectedProofRoutes } from './protected-http.js';
import { RuntimeArtifactDispositionRepository } from './runtime-artifact-disposition-repository.js';
import {
  disposeRuntimeArtifactSource,
  runtimeArtifactDispositionPlanInput,
  runtimeArtifactDispositionPlan,
  runtimeArtifactDispositionView,
} from './runtime-artifact-disposition-contract.js';
import { configurationProblem } from '../configuration/problem.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { StoreRetirementRepository, storeRetirementView } from './store-retirement-repository.js';
import {
  admitStoreRetirement,
  storeRetirementPlan,
  storeRetirementPlanInput,
  factRetirementPlanInput,
  factRetirementHosts,
  candidateRetirementPlanInput,
  candidateRetirementHosts,
} from './store-retirement-contracts.js';
import { evidenceProvenanceView } from './provenance-contracts.js';
import {
  deleteLocalEvidenceBatch,
  evidenceDeletionBatchPlan,
  evidenceDeletionResultView,
} from './deletion-continuation-contracts.js';
import { EvidenceDeletionRepository } from './deletion-repository.js';
import { deleteLocalEvidence, localEvidenceDeletionPlan } from './deletion-contracts.js';
import type { FastifyInstance } from 'fastify';
import { resourceRead } from '../configuration/resource-http.js';
import {
  governedResourceMutation,
  governedResourceProposal,
  type ResourceApiOptions,
} from '../configuration/governed-mutation-http.js';
import { collectionResponseSchema } from '../configuration/resource-contracts.js';
import { EvidenceCatalogueRepository, evidenceRecordView } from './catalogue.js';
import { EvidenceExportRepository } from './export-repository.js';
import {
  evidenceExportView,
  evidenceExportSelectionView,
  createEvidenceExportFromSelection,
  createEvidenceExportRequest,
  updateEvidenceExportRequest,
  startEvidenceExportRequest,
  evidenceRecordExportRange,
} from './export-contracts.js';
import { evidenceExportDownload } from './export-artifact.js';
import { EvidenceHoldRepository } from './hold-repository.js';
import { createEvidenceHold, releaseEvidenceHold, evidenceHoldView } from './hold-contracts.js';
import {
  activateRetentionPolicy,
  retireRetentionPolicy,
  retentionPolicyView,
} from './retention-contracts.js';
import { RetentionPolicyRepository } from './retention-repository.js';
import { deleteRawProofBatch, rawProofDeletionPlan } from './raw-deletion-contracts.js';
import { deleteProjectionBatch, projectionDeletionPlan } from './projection-deletion-contracts.js';

export function registerEvidenceRoutes(app: FastifyInstance, options: ResourceApiOptions) {
  registerProtectedProofRoutes(app, options);
  const runtimeSources = new RuntimeArtifactDispositionRepository(options.pool, options);
  app.post('/api/v1/evidence-deletions/runtime-sources/plan', async (request, reply) => {
    const parsed = runtimeArtifactDispositionPlanInput.safeParse(request.body);
    if (!parsed.success)
      return configurationProblem(reply, request, new ConfigurationRepositoryError('PC-DATA-6004'));
    return resourceRead(
      options,
      'evidence-deletions',
      'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
      (context) => runtimeSources.plan(context, parsed.data),
      runtimeArtifactDispositionPlan,
      new Set(),
      'COLLECTION',
      'SINGLE',
    )(request, reply);
  });
  app.post(
    '/api/v1/evidence-deletions/runtime-sources/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
      disposeRuntimeArtifactSource,
    ),
  );
  app.post(
    '/api/v1/evidence-deletions/runtime-sources',
    governedResourceMutation(
      options,
      'CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE',
      disposeRuntimeArtifactSource,
      (context, body) => runtimeSources.dispose(context, body),
    ),
  );
  app.get(
    '/api/v1/evidence-deletions/runtime-sources/:id',
    resourceRead(
      options,
      'evidence-deletions',
      'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
      (context) => runtimeSources.get(context),
      runtimeArtifactDispositionView,
    ),
  );
  const storeRetirements = new StoreRetirementRepository(options.pool, options);
  app.get(
    '/api/v1/evidence-records/:id/candidate-retirement-hosts',
    resourceRead(
      options,
      'evidence-records',
      'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
      (context) => storeRetirements.candidateHosts(context),
      candidateRetirementHosts,
      new Set(),
      'COLLECTION',
    ),
  );
  app.post('/api/v1/evidence-records/:id/candidate-retirement-plan', async (request, reply) => {
    const parsed = candidateRetirementPlanInput.safeParse(request.body);
    if (!parsed.success)
      return configurationProblem(reply, request, new ConfigurationRepositoryError('PC-DATA-6004'));
    return resourceRead(
      options,
      'evidence-records',
      'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
      (context) => storeRetirements.candidatePlan(context, parsed.data),
      storeRetirementPlan,
      new Set(),
      'COLLECTION',
    )(request, reply);
  });
  app.get(
    '/api/v1/evidence-records/:id/fact-retirement-hosts',
    resourceRead(
      options,
      'evidence-records',
      'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
      (context) => storeRetirements.factHosts(context),
      factRetirementHosts,
      new Set(),
      'COLLECTION',
    ),
  );
  app.post('/api/v1/evidence-records/:id/fact-retirement-plan', async (request, reply) => {
    const parsed = factRetirementPlanInput.safeParse(request.body);
    if (!parsed.success)
      return configurationProblem(reply, request, new ConfigurationRepositoryError('PC-DATA-6004'));
    return resourceRead(
      options,
      'evidence-records',
      'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
      (context) => storeRetirements.factPlan(context, parsed.data),
      storeRetirementPlan,
      new Set(),
      'COLLECTION',
    )(request, reply);
  });
  app.post(
    '/api/v1/evidence-deletions/store-retirements/proposals',
    governedResourceProposal(options, 'CFG-OP-ADMIT-STORE-RETIREMENT', admitStoreRetirement),
  );
  app.post(
    '/api/v1/evidence-deletions/store-retirements',
    governedResourceMutation(
      options,
      'CFG-OP-ADMIT-STORE-RETIREMENT',
      admitStoreRetirement,
      (context, body) => storeRetirements.admit(context, body),
    ),
  );
  app.get(
    '/api/v1/evidence-deletions/store-retirements/attempts/:id',
    resourceRead(
      options,
      'evidence-deletions',
      'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
      (context) => storeRetirements.get(context),
      storeRetirementView,
    ),
  );
  app.post('/api/v1/evidence-records/:id/store-retirement-plan', async (request, reply) =>
    resourceRead(
      options,
      'evidence-records',
      'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
      (context) => storeRetirements.plan(context, storeRetirementPlanInput.parse(request.body)),
      storeRetirementPlan,
      new Set(),
      'COLLECTION',
    )(request, reply),
  );
  const deletions = new EvidenceDeletionRepository(options.pool, options);
  app.get(
    '/api/v1/evidence-deletions/:id/runtime-retirement',
    resourceRead(
      options,
      'evidence-deletions',
      'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
      (context) => deletions.runtimeRetirement(context),
      runtimeArtifactRetirementView,
    ),
  );
  app.post('/api/v1/evidence-deletions/runtime-batches/plan', async (request, reply) => {
    const parsed = runtimeArtifactRetirementPlanInput.safeParse(request.body);
    if (!parsed.success)
      return configurationProblem(reply, request, new ConfigurationRepositoryError('PC-DATA-6004'));
    return resourceRead(
      options,
      'evidence-deletions',
      'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
      (context) => deletions.runtimePlan(context, parsed.data),
      runtimeArtifactRetirementPlan,
      new Set(),
      'COLLECTION',
      'SINGLE',
    )(request, reply);
  });
  app.post(
    '/api/v1/evidence-deletions/runtime-batches/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH',
      deleteRuntimeArtifactBatch,
    ),
  );
  app.post(
    '/api/v1/evidence-deletions/runtime-batches',
    governedResourceMutation(
      options,
      'CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH',
      deleteRuntimeArtifactBatch,
      (context, body) => deletions.create(context, body),
    ),
  );
  app.post(
    '/api/v1/evidence-deletions/projection-batches/proposals',
    governedResourceProposal(options, 'CFG-OP-DELETE-PROJECTION-BATCH', deleteProjectionBatch),
  );
  app.post(
    '/api/v1/evidence-deletions/projection-batches',
    governedResourceMutation(
      options,
      'CFG-OP-DELETE-PROJECTION-BATCH',
      deleteProjectionBatch,
      (context, body) => deletions.create(context, body),
    ),
  );
  const projectionHandlers = (
    [
      ['normalized-projection-deletion-plan', 'NORMALIZED_JSON_PROJECTION'],
      ['search-projection-deletion-plan', 'SEARCH_PROJECTION'],
    ] as const
  ).map(
    ([path, dataClass]) =>
      [
        `/api/v1/evidence-records/:id/${path}`,
        resourceRead(
          options,
          'evidence-records',
          'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
          (context) => deletions.projectionPlan(context, dataClass),
          projectionDeletionPlan,
          new Set(),
          'COLLECTION',
        ),
      ] as const,
  );
  app.post(
    '/api/v1/evidence-deletions/raw-batches/proposals',
    governedResourceProposal(options, 'CFG-OP-DELETE-RAW-PROOF-BATCH', deleteRawProofBatch),
  );
  app.post(
    '/api/v1/evidence-deletions/raw-batches',
    governedResourceMutation(
      options,
      'CFG-OP-DELETE-RAW-PROOF-BATCH',
      deleteRawProofBatch,
      (context, body) => deletions.create(context, body),
    ),
  );
  app.post(
    '/api/v1/evidence-deletions/proposals',
    governedResourceProposal(options, 'CFG-OP-DELETE-LOCAL-EVIDENCE', deleteLocalEvidence),
  );
  app.post(
    '/api/v1/evidence-deletions',
    governedResourceMutation(
      options,
      'CFG-OP-DELETE-LOCAL-EVIDENCE',
      deleteLocalEvidence,
      (context, body) => deletions.create(context, body),
    ),
  );
  app.post(
    '/api/v1/evidence-deletions/batches/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH',
      deleteLocalEvidenceBatch,
    ),
  );
  app.post(
    '/api/v1/evidence-deletions/batches',
    governedResourceMutation(
      options,
      'CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH',
      deleteLocalEvidenceBatch,
      (context, body) => deletions.create(context, body),
    ),
  );
  const catalogue = new EvidenceCatalogueRepository(options.pool);
  const exports = new EvidenceExportRepository(options.pool, options);
  const holds = new EvidenceHoldRepository(options.pool, options);
  const policies = new RetentionPolicyRepository(options.pool, options);
  app.post(
    '/api/v1/retention-policies/proposals',
    governedResourceProposal(options, 'CFG-OP-ACTIVATE-RETENTION-POLICY', activateRetentionPolicy),
  );
  app.post(
    '/api/v1/retention-policies',
    governedResourceMutation(
      options,
      'CFG-OP-ACTIVATE-RETENTION-POLICY',
      activateRetentionPolicy,
      (context, body) => policies.activate(context, body),
    ),
  );
  app.post(
    '/api/v1/retention-policies/:id/retire/proposals',
    governedResourceProposal(options, 'CFG-OP-RETIRE-RETENTION-POLICY', retireRetentionPolicy),
  );
  app.post(
    '/api/v1/retention-policies/:id/retire',
    governedResourceMutation(
      options,
      'CFG-OP-RETIRE-RETENTION-POLICY',
      retireRetentionPolicy,
      (context) => policies.retire(context),
    ),
  );
  // Selection chooses a registered operation, never an authority decision. Each
  // handler validates its exact action, candidate, approval and live grant.
  for (const proposal of [false, true]) {
    const createHandlers = [false, true].map((participant) => {
      const operation = participant
        ? 'CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD'
        : 'CFG-OP-CREATE-EVIDENCE-HOLD';
      return proposal
        ? governedResourceProposal(options, operation, createEvidenceHold)
        : governedResourceMutation(options, operation, createEvidenceHold, (context, body) =>
            holds.create(context, body),
          );
    });
    const releaseHandlers = [false, true].map((participant) => {
      const operation = participant
        ? 'CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD'
        : 'CFG-OP-RELEASE-EVIDENCE-HOLD';
      return proposal
        ? governedResourceProposal(options, operation, releaseEvidenceHold)
        : governedResourceMutation(options, operation, releaseEvidenceHold, (context) =>
            holds.release(context),
          );
    });
    app.post(`/api/v1/evidence-holds${proposal ? '/proposals' : ''}`, (request, reply) => {
      const body = request.body;
      const participant =
        typeof body === 'object' &&
        body !== null &&
        'actionIntentId' in body &&
        body.actionIntentId === 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1';
      return createHandlers[participant ? 1 : 0]!(request, reply);
    });
    app.post(
      `/api/v1/evidence-holds/:id/release${proposal ? '/proposals' : ''}`,
      (request, reply) => {
        const body = request.body;
        const participant =
          typeof body === 'object' &&
          body !== null &&
          'actionIntentId' in body &&
          body.actionIntentId === 'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1';
        return releaseHandlers[participant ? 1 : 0]!(request, reply);
      },
    );
  }
  app.post(
    '/api/v1/evidence-exports/from-selection',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-EVIDENCE-EXPORT',
      createEvidenceExportFromSelection,
      (context, body) => exports.create(context, { selection: body.selection }),
    ),
  );
  app.post(
    '/api/v1/evidence-exports',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-EVIDENCE-EXPORT',
      createEvidenceExportRequest,
      (context, body) => exports.create(context, { requestDigest: body.requestDigest }),
    ),
  );
  app.patch(
    '/api/v1/evidence-exports/:id',
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-EVIDENCE-EXPORT',
      updateEvidenceExportRequest,
      (context, body) => exports.update(context, body.replacementDigest),
    ),
  );
  app.post(
    '/api/v1/evidence-exports/:id/export/proposals',
    governedResourceProposal(options, 'CFG-OP-START-EVIDENCE-EXPORT', startEvidenceExportRequest),
  );
  app.post(
    '/api/v1/evidence-exports/:id/export',
    governedResourceMutation(
      options,
      'CFG-OP-START-EVIDENCE-EXPORT',
      startEvidenceExportRequest,
      (context, body) => exports.start(context, body.inputDigest),
    ),
  );
  const handlers = [
    ...projectionHandlers,
    [
      '/api/v1/evidence-deletions/:id/projection-continuation-plan',
      resourceRead(
        options,
        'evidence-deletions',
        'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
        (context) => deletions.projectionPlan(context),
        projectionDeletionPlan,
      ),
    ],
    [
      '/api/v1/protected-proofs/:id/deletion-plan',
      resourceRead(
        options,
        'protected-proofs',
        'ACT-PROTECTED_PROOFS_READ_COLLECTION-V1',
        (context) => deletions.rawPlan(context),
        rawProofDeletionPlan,
        new Set(),
        'COLLECTION',
      ),
    ],
    [
      '/api/v1/evidence-deletions/:id/raw-continuation-plan',
      resourceRead(
        options,
        'evidence-deletions',
        'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
        (context) => deletions.rawPlan(context, true),
        rawProofDeletionPlan,
      ),
    ],
    [
      '/api/v1/evidence-records/:id/deletion-batch-plan',
      resourceRead(
        options,
        'evidence-records',
        'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
        (context) => deletions.batchPlan(context),
        evidenceDeletionBatchPlan,
        new Set(),
        'COLLECTION',
      ),
    ],
    [
      '/api/v1/evidence-deletions/:id/continuation-plan',
      resourceRead(
        options,
        'evidence-deletions',
        'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
        (context) => deletions.batchPlan(context, true),
        evidenceDeletionBatchPlan,
      ),
    ],
    [
      '/api/v1/evidence-records/:id/deletion-plan',
      resourceRead(
        options,
        'evidence-records',
        'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
        (context) => deletions.plan(context),
        localEvidenceDeletionPlan,
      ),
    ],
    [
      '/api/v1/evidence-records/:id/provenance',
      resourceRead(
        options,
        'evidence-records',
        'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
        (context) => catalogue.provenance(context),
        evidenceProvenanceView,
      ),
    ],
    [
      '/api/v1/evidence-deletions',
      resourceRead(
        options,
        'evidence-deletions',
        'ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1',
        (context, request) => deletions.list(context, request!),
        collectionResponseSchema(evidenceDeletionResultView),
        new Set(['state']),
      ),
    ],
    [
      '/api/v1/evidence-deletions/:id',
      resourceRead(
        options,
        'evidence-deletions',
        'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
        (context) => deletions.get(context),
        evidenceDeletionResultView,
      ),
    ],
    [
      '/api/v1/retention-policies',
      resourceRead(
        options,
        'retention-policies',
        'ACT-RETENTION_POLICIES_READ_COLLECTION-V1',
        (context, request) => policies.list(context, request!),
        collectionResponseSchema(retentionPolicyView),
        new Set(['state', 'dataClass']),
      ),
    ],
    [
      '/api/v1/retention-policies/:id',
      resourceRead(
        options,
        'retention-policies',
        'ACT-RETENTION_POLICIES_READ_RESOURCE-V1',
        (context) => policies.get(context),
        retentionPolicyView,
      ),
    ],
    [
      '/api/v1/evidence-holds',
      resourceRead(
        options,
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_READ_COLLECTION-V1',
        (context, request) => holds.list(context, request!),
        collectionResponseSchema(evidenceHoldView),
        new Set(['state', 'holdKind']),
      ),
    ],
    [
      '/api/v1/evidence-holds/:id',
      resourceRead(
        options,
        'evidence-holds',
        'ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1',
        (context) => holds.get(context),
        evidenceHoldView,
      ),
    ],
    [
      '/api/v1/evidence-records/:id/export-range',
      resourceRead(
        options,
        'evidence-records',
        'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
        (context) => catalogue.exportRange(context),
        evidenceRecordExportRange,
      ),
    ],
    [
      '/api/v1/evidence-exports/:id/selection',
      resourceRead(
        options,
        'evidence-exports',
        'ACT-EVIDENCE_EXPORTS_READ_RESOURCE-V1',
        (context) => exports.selection(context),
        evidenceExportSelectionView,
      ),
    ],
    [
      '/api/v1/evidence-exports',
      resourceRead(
        options,
        'evidence-exports',
        'ACT-EVIDENCE_EXPORTS_READ_COLLECTION-V1',
        (context, request) => exports.list(context, request!),
        collectionResponseSchema(evidenceExportView),
        new Set(['state', 'requestDigest']),
      ),
    ],
    [
      '/api/v1/evidence-exports/:id',
      resourceRead(
        options,
        'evidence-exports',
        'ACT-EVIDENCE_EXPORTS_READ_RESOURCE-V1',
        (context) => exports.get(context),
        evidenceExportView,
      ),
    ],
    [
      '/api/v1/evidence-exports/:id/artifact',
      resourceRead(
        options,
        'evidence-exports',
        'ACT-EVIDENCE_EXPORTS_READ_RESOURCE-V1',
        (context) => exports.download(context),
        evidenceExportDownload,
      ),
    ],
    [
      '/api/v1/evidence-records',
      resourceRead(
        options,
        'evidence-records',
        'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
        (context, request) => catalogue.list(context, request!),
        collectionResponseSchema(evidenceRecordView),
        new Set(['evidenceClass', 'recordDigest']),
      ),
    ],
    [
      '/api/v1/evidence-records/:id',
      resourceRead(
        options,
        'evidence-records',
        'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
        (context) => catalogue.get(context),
        evidenceRecordView,
      ),
    ],
  ] as const;
  for (const [path, handler] of handlers)
    app.get(path, async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      return handler(request, reply);
    });
}
