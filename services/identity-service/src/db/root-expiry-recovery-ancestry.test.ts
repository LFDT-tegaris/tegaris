import { expect, it, vi } from 'vitest';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import type { PoolClient } from 'pg';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  encodeEnvelopeScope,
  platformEnvelopeScopePreimage,
  platformEnvelopeScopeExpiryRecoveryPreimage,
  platformEnvelopeScopeExpiryRecoveryDigest,
} from '../../../../packages/security-kernel/src/index.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  localRootExpiryRecoveryEnrollment,
  localRootExpiryRecoveryReceivingTrust,
  localRootExpiryRecoveryIntent,
  type LocalRootExpiryPendingAncestry,
  type LocalRootExpiryPendingWitness,
} from '../contracts/local-root-expiry-recovery.js';
import { localRootExpiryRecoveryFixture } from '../domain/local-root-expiry-recovery.test-fixture.js';
import { localRootExpiryRecoveryCustodyPreimage } from '../domain/local-root-expiry-recovery.js';
import { localRootExpiryRecoveryEvidencePayload } from '../domain/local-root-expiry-recovery-evidence.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../domain/identity-runtime-crypto.js';
import {
  authenticateRootExpiryPendingAncestry,
  readCurrentRootExpiryPendingAncestry,
} from './root-expiry-recovery-ancestry.js';

// Real custody/COSE/canonical codecs over a mocked SQL transport. Installed
// role, RLS, concurrent effects and CAS remain separate native acceptance.
async function fixture(depth = 2) {
  const f = localRootExpiryRecoveryFixture();
  const original = {
    platformContextId: f.root.platformContextId,
    ownerParticipantId: f.root.ownerParticipantId,
    installationPrivacyDomainId: f.root.installationPrivacyDomainId,
    platformAuthorityEpoch: f.root.platformAuthorityEpoch,
    installationDigest: f.root.installationDigest,
    environmentId: f.root.environmentId,
    grantable: f.root.grantable,
  };
  const initialPreimage = platformEnvelopeScopePreimage(original);
  const initialDigest = 'sha256:' + createHash('sha256').update(initialPreimage).digest('hex');
  const pending: LocalRootExpiryPendingWitness = {
    schema: 'pc.identity.local-root-expiry-pending-witness',
    schemaVersion: 1,
    replacementId: id(800),
    replacementRevision: '1',
    predecessorEpoch: original.platformAuthorityEpoch,
    expectedRootRevision: f.enrollment.rootRevision,
    predecessorDigest: initialDigest,
    preparationCandidateId: id(801),
    preparationOperationId: id(802),
    preparationApprovalId: id(803),
    preparationDigest: initialDigest,
    preparationReceiptDigest: initialDigest,
    successorDigest: initialDigest,
    pendingRecordDigest: initialDigest,
    administrationEffectsDigest: initialDigest,
    readinessDigest: initialDigest,
    affectedTargetCount: 0,
  };
  const runtimeKeys = generateKeyPairSync('ed25519');
  const publicDer = runtimeKeys.publicKey.export({ format: 'der', type: 'spki' });
  const verifier = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: runtimeKeys.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicDer,
    trustedPublicKeysSpkiDer: [publicDer],
  });
  const links: Array<{
    enrollment: ReturnType<typeof localRootExpiryRecoveryEnrollment.parse>;
    trust: ReturnType<typeof localRootExpiryRecoveryReceivingTrust.parse>;
    signature: Buffer;
    row: {
      intent: ReturnType<typeof localRootExpiryRecoveryIntent.parse>;
      intent_digest: Buffer;
      state: string;
      row_version: string;
      result: { rootEpoch: string; rootRevision: string; rootDigest: string; operationId: string };
      operation_id: string;
      evidence_cbor: Buffer;
      evidence_digest: Buffer;
      evidence_cose: Buffer;
    };
    scope: Record<string, unknown>;
    proofs: Array<{
      principalId: string;
      principalEpoch: string;
      credentialId: string;
      credentialEpoch: string;
      proofId: string;
      sessionId: string;
      sessionEpoch: string;
      phase: 'REQUEST' | 'APPROVE' | 'ACTIVATE';
      intentDigest: string;
      verifiedAt: Date;
      verifiedProofMaxAgeMs: 300000;
    }>;
  }> = [];
  const receipts: LocalRootExpiryPendingAncestry['receipts'] = [];
  let epoch = pending.predecessorEpoch,
    revision = pending.expectedRootRevision,
    digest = initialDigest;
  const ancestry = () => ({
    schema: 'pc.identity.local-root-expiry-pending-ancestry' as const,
    schemaVersion: 1 as const,
    rootEpoch: epoch,
    rootRevision: revision,
    rootDigest: digest,
    receipts: structuredClone(receipts),
  });
  for (let index = 0; index < depth; index++) {
    const version = index === 0 ? 2 : 3;
    const extra = index === 0 ? { pending } : { pending, rootAncestry: ancestry() };
    const purpose =
      index === 0
        ? 'pc.installation.local-root-expiry-pending-recovery-custody.v2'
        : 'pc.installation.local-root-expiry-pending-ancestry-custody.v3';
    const trust = localRootExpiryRecoveryReceivingTrust.parse({
      ...f.trust,
      custodyTrustId: id(810 + index * 20),
      schemaVersion: version,
      purpose,
      ...extra,
    });
    const enrollment = localRootExpiryRecoveryEnrollment.parse({
      ...f.enrollment,
      enrollmentId: id(811 + index * 20),
      schemaVersion: version,
      purpose,
      ...extra,
      rootEpoch: epoch,
      rootRevision: revision,
      rootDigest: digest,
      custodyTrustId: trust.custodyTrustId,
      custodyTrustDigest: canonicalAuthorizationDigest(trust),
    });
    const signature = sign('sha256', localRootExpiryRecoveryCustodyPreimage(enrollment), {
      key: f.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
    const intent = localRootExpiryRecoveryIntent.parse({
      schema: 'pc.identity.local-root-expiry-recovery-intent',
      schemaVersion: version,
      purpose:
        index === 0
          ? 'LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY'
          : 'LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY',
      ...extra,
      recoveryId: id(812 + index * 20),
      enrollmentId: enrollment.enrollmentId,
      enrollmentRevision: '1',
      enrollmentDigest: canonicalAuthorizationDigest(enrollment),
      sourceParticipantEpoch: '1',
      predecessorEpoch: epoch,
      predecessorRevision: revision,
      predecessorDigest: digest,
      successorScope: {
        ...original.grantable,
        validFromNs: (BigInt(Date.parse(enrollment.successorValidFrom)) * 1000000n).toString(),
        validUntilNs: (BigInt(Date.parse(enrollment.successorValidUntil)) * 1000000n).toString(),
      },
      validFrom: f.now.toISOString(),
      validUntil: new Date(f.now.getTime() + 900000).toISOString(),
    });
    const operation = id(813 + index * 20);
    const value = {
      admission: {
        ...original,
        platformAuthorityEpoch: (BigInt(epoch) + 1n).toString(),
        grantable: intent.successorScope,
      },
      recoveryId: intent.recoveryId,
      activationOperationId: operation,
      enrollmentDigest: intent.enrollmentDigest,
      intentDigest: canonicalAuthorizationDigest(intent),
      predecessorEpoch: epoch,
      predecessorDigest: digest,
    };
    const result = {
      rootEpoch: value.admission.platformAuthorityEpoch,
      rootRevision: (BigInt(revision) + 1n).toString(),
      rootDigest: platformEnvelopeScopeExpiryRecoveryDigest(value),
      operationId: operation,
    };
    const proofs = [
      { signer: enrollment.recoveryPrincipal, phase: 'REQUEST' as const },
      ...enrollment.custodians.map((signer) => ({ signer, phase: 'APPROVE' as const })),
      { signer: enrollment.recoveryPrincipal, phase: 'ACTIVATE' as const },
    ].map((v, i) => ({
      ...v.signer,
      proofId: id(814 + index * 20 + i),
      sessionId: id(818 + index * 20 + i),
      sessionEpoch: '1',
      phase: v.phase,
      intentDigest: canonicalAuthorizationDigest(intent),
      verifiedAt: f.now,
      verifiedProofMaxAgeMs: 300000 as const,
    }));
    const evidence = await verifier.signCanonicalAssertion(
      localRootExpiryRecoveryEvidencePayload(
        enrollment,
        intent,
        operation,
        result,
        proofs,
        BigInt(f.now.getTime()) * 1000000n,
      ),
    );
    const row = {
      intent,
      intent_digest: Buffer.from(canonicalAuthorizationDigest(intent).slice(7), 'hex'),
      state: 'COMPLETED',
      row_version: '4',
      result,
      operation_id: operation,
      evidence_cbor: evidence.evidenceCbor,
      evidence_digest: evidence.evidenceDigest,
      evidence_cose: evidence.coseSign1,
    };
    const scope = {
      ...Object.fromEntries(Object.entries(original).filter(([k]) => k !== 'grantable')),
      platform_context_id: original.platformContextId,
      owner_participant_id: original.ownerParticipantId,
      installation_privacy_domain_id: original.installationPrivacyDomainId,
      platform_authority_epoch: result.rootEpoch,
      environment_id: original.environmentId,
      installation_digest: original.installationDigest,
      activation_operation_id: operation,
      prepare_operation_id: operation,
      recovery_id: intent.recoveryId,
      replacement_id: null,
      predecessor_epoch: epoch,
      predecessor_digest: Buffer.from(digest.slice(7), 'hex'),
      enrollment_digest: Buffer.from(intent.enrollmentDigest.slice(7), 'hex'),
      intent_digest: row.intent_digest,
      scope_cbor: encodeEnvelopeScope(intent.successorScope),
      admission_preimage: platformEnvelopeScopeExpiryRecoveryPreimage(value),
      admission_digest: Buffer.from(result.rootDigest.slice(7), 'hex'),
    };
    links.push({ enrollment, trust, signature, row, scope, proofs });
    receipts.push({
      enrollmentId: enrollment.enrollmentId,
      recoveryId: intent.recoveryId,
      activationOperationId: operation,
      enrollmentDigest: intent.enrollmentDigest,
      intentDigest: canonicalAuthorizationDigest(intent),
      receiptDigest: 'sha256:' + evidence.evidenceDigest.toString('hex'),
      predecessorEpoch: epoch,
      predecessorRevision: revision,
      predecessorDigest: digest,
      ...{
        rootEpoch: result.rootEpoch,
        rootRevision: result.rootRevision,
        rootDigest: result.rootDigest,
      },
    });
    epoch = result.rootEpoch;
    revision = result.rootRevision;
    digest = result.rootDigest;
  }
  const sourceRow = {
    scope_cbor: encodeEnvelopeScope(original.grantable),
    admission_preimage: initialPreimage,
    admission_digest: Buffer.from(initialDigest.slice(7), 'hex'),
    platform_context_id: original.platformContextId,
    owner_participant_id: original.ownerParticipantId,
    installation_privacy_domain_id: original.installationPrivacyDomainId,
    platform_authority_epoch: original.platformAuthorityEpoch,
    environment_id: original.environmentId,
    installation_digest: original.installationDigest,
    predecessor_epoch: null,
    predecessor_digest: null,
    replacement_id: null,
    preparation_operation_id: null,
    recovery_id: null,
    activation_operation_id: null,
    enrollment_digest: null,
    intent_digest: null,
  };
  const query = vi.fn(async (text: string, args: unknown[] = []) => {
    if (text === 'select current_user as role')
      return { rowCount: 1, rows: [{ role: 'openpc_control_owner' }] };
    if (text.includes('metadata->>')) return { rowCount: 1, rows: [sourceRow] };
    if (text.includes('lock_root_expiry_pending_source')) return { rowCount: 1, rows: [{}] };
    if (text.includes('lock_platform_scope_context'))
      return { rowCount: 1, rows: [links.at(-1)!.scope] };
    if (text.includes('select row_version::text revision'))
      return { rowCount: 1, rows: [{ revision, now: new Date(f.now.getTime() + 7200000) }] };
    const link = links.find(
      (v) =>
        args.includes(v.enrollment.enrollmentId) ||
        args.includes(v.enrollment.custodyTrustId) ||
        args.includes(v.row.intent.recoveryId),
    );
    if (!link) throw new Error('Unrecognized SQL fixture query');
    if (text.includes('lock_root_expiry_recovery_enrollment'))
      return {
        rowCount: 1,
        rows: [
          {
            document: link.enrollment,
            document_digest: Buffer.from(
              canonicalAuthorizationDigest(link.enrollment).slice(7),
              'hex',
            ),
            signature: link.signature,
            state: 'ACTIVE',
            row_version: '1',
            trust: link.trust,
            trust_digest: Buffer.from(canonicalAuthorizationDigest(link.trust).slice(7), 'hex'),
            trust_state: 'ACTIVE',
            trust_revision: '1',
            enrollment_created_at: f.now,
            trust_created_at: f.now,
          },
        ],
      };
    if (text.includes('from control.root_expiry_recovery_case'))
      return { rowCount: 1, rows: [link.row] };
    if (text.includes('from control.root_expiry_recovery_proof'))
      return { rowCount: link.proofs.length, rows: link.proofs };
    if (text.includes('from control.root_expiry_recovery_scope'))
      return { rowCount: 1, rows: [link.scope] };
    if (text.includes('from control.outbox_event'))
      return {
        rowCount: 1,
        rows: [
          {
            payload_cbor: link.row.evidence_cbor,
            payload_digest: link.row.evidence_digest,
            cose_sign1: link.row.evidence_cose,
          },
        ],
      };
    if (text.includes('from control.root_expiry_recovery_trust'))
      return { rowCount: 1, rows: [{ custody_trust_id: link.enrollment.custodyTrustId }] };
    throw new Error('Unrecognized SQL fixture query');
  });
  const originalQuery = query.getMockImplementation()!;
  return {
    client: { query } as unknown as PoolClient,
    query,
    originalQuery,
    links,
    sourceRow,
    pending,
    rootAncestry: ancestry(),
    binding: {
      participantId: original.ownerParticipantId,
      privacyDomainId: original.installationPrivacyDomainId,
      platformContextId: original.platformContextId,
      installationDigest: original.installationDigest,
      installationEnvironmentId: original.environmentId,
    },
    verifier,
  };
}
it('authenticates each real custody/COSE receipt and its full ordered prefix without signing or effects', async () => {
  const f = await fixture();
  const verify = vi.fn(f.verifier.verifyCanonicalAssertion);
  const read = await authenticateRootExpiryPendingAncestry(
    f.client,
    f.binding,
    { pending: f.pending, rootAncestry: f.rootAncestry },
    { verifyCanonicalAssertion: verify },
  );
  expect(read.witness.rootAncestry).toEqual(f.rootAncestry);
  expect(verify).toHaveBeenCalledTimes(2);
  expect(
    f.query.mock.calls.every(
      ([text]) => !/\b(?:insert|update|delete)\s+(?:into\s+)?control\./iu.test(text),
    ),
  ).toBe(true);
});
it('requires an installed verifier before observing any history', async () => {
  const f = await fixture();
  await expect(
    authenticateRootExpiryPendingAncestry(
      f.client,
      f.binding,
      { pending: f.pending, rootAncestry: f.rootAncestry },
      undefined!,
    ),
  ).rejects.toThrow();
  expect(f.query).not.toHaveBeenCalled();
});
it.each([
  'signature',
  'custody',
  'proof',
  'permission',
  'preimage',
  'partial',
  'foreign',
  'prefix',
  'outbox',
])('denies changed original ancestry %s', async (failure) => {
  const f = await fixture();
  const first = f.links[0]!;
  if (failure === 'signature')
    first.row.evidence_cose = Buffer.alloc(first.row.evidence_cose.length);
  if (failure === 'custody') first.signature = Buffer.alloc(64);
  if (failure === 'proof') first.proofs[1]!.credentialId = id(999);
  if (failure === 'permission') first.row.intent.successorScope.validUntilNs = '0';
  if (failure === 'preimage') f.sourceRow.admission_preimage = Buffer.from('00', 'hex');
  if (failure === 'partial') first.row.state = 'REQUESTED';
  if (failure === 'foreign') f.binding.platformContextId = id(999);
  if (failure === 'prefix') f.rootAncestry.receipts[1]!.receiptDigest = 'sha256:' + '0'.repeat(64);
  if (failure === 'outbox')
    f.query.mockImplementation(async (text, args = []) => {
      if (text.includes('from control.outbox_event')) return { rowCount: 0, rows: [] };
      return f.originalQuery(text, args);
    });
  await expect(
    authenticateRootExpiryPendingAncestry(
      f.client,
      f.binding,
      { pending: f.pending, rootAncestry: f.rootAncestry },
      f.verifier,
    ),
  ).rejects.toThrow();
});
it('keeps original consumption freshness historical and denies changed current Root at the source fence', async () => {
  const f = await fixture();
  await expect(
    readCurrentRootExpiryPendingAncestry(
      f.client,
      f.binding,
      { pending: f.pending, rootAncestry: f.rootAncestry },
      f.verifier,
    ),
  ).resolves.toEqual({ pending: f.pending, rootAncestry: f.rootAncestry });
  const queries = f.query.mock.calls.map(([text]) => text);
  const lock = queries.findIndex((text) => text.includes('lock_root_expiry_pending_source'));
  const clock = queries.findIndex((text) => text.includes('select row_version::text revision'));
  expect(lock).toBeGreaterThanOrEqual(0);
  expect(clock).toBeGreaterThan(lock);
  expect(queries[clock]).not.toContain('for update');
  const altered = { ...f.rootAncestry, rootRevision: '99' };
  await expect(
    readCurrentRootExpiryPendingAncestry(
      f.client,
      f.binding,
      { pending: f.pending, rootAncestry: altered },
      f.verifier,
    ),
  ).rejects.toThrow();
});
