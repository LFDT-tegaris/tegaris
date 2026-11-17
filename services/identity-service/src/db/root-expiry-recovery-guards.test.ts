import { expect, it, vi } from 'vitest';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import type { PoolClient } from 'pg';
import { authenticateCompletedRootExpiryRecoveryReceipt } from './root-expiry-recovery-command.js';
import { localRootExpiryRecoveryFixture } from '../domain/local-root-expiry-recovery.test-fixture.js';
import { localRootExpiryRecoveryIntent } from '../contracts/local-root-expiry-recovery.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { localRootExpiryRecoveryEvidencePayload } from '../domain/local-root-expiry-recovery-evidence.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../domain/identity-runtime-crypto.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  encodeEnvelopeScope,
  platformEnvelopeScopeExpiryRecoveryDigest,
  platformEnvelopeScopeExpiryRecoveryPreimage,
} from '../../../../packages/security-kernel/src/index.js';
import {
  rootExpiryRecoveryGuardsSql,
  rootExpiryRecoveryGrantsSql,
  rootExpiryAncestryPreambleSql,
} from './root-expiry-recovery-guards.mjs';
import { verifyConditionCases, verifyFunctionGrants } from './function-grants.js';
const { platformScopeCommitGuardsSql } = createRequire(import.meta.url)(
  './platform-scope-commit-guards.mjs',
) as { platformScopeCommitGuardsSql: string };
it('generates valid narrow owner signatures and parenthesized SQL conditions', () => {
  verifyConditionCases(rootExpiryRecoveryGuardsSql);
  expect(() =>
    verifyFunctionGrants(
      rootExpiryRecoveryGuardsSql,
      rootExpiryRecoveryGuardsSql + rootExpiryRecoveryGrantsSql,
    ),
  ).not.toThrow();
});
it('rejects an invalid generated procedure grant before migration', () => {
  expect(() =>
    verifyFunctionGrants(
      rootExpiryRecoveryGuardsSql,
      rootExpiryRecoveryGuardsSql +
        rootExpiryRecoveryGrantsSql +
        'GRANT EXECUTE ON FUNCTION openpc.commit_root_expiry_recovery(uuid) TO openpc_control_runtime;',
    ),
  ).toThrow('Function grant has no matching definition: openpc.commit_root_expiry_recovery(uuid)');
});

async function completedReceiptFixture() {
  const f = localRootExpiryRecoveryFixture();
  const intent = localRootExpiryRecoveryIntent.parse({
    schema: 'pc.identity.local-root-expiry-recovery-intent',
    schemaVersion: 1,
    purpose: 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY',
    recoveryId: id(501),
    enrollmentId: f.enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(f.enrollment),
    sourceParticipantEpoch: '1',
    predecessorEpoch: f.enrollment.rootEpoch,
    predecessorRevision: f.enrollment.rootRevision,
    predecessorDigest: f.enrollment.rootDigest,
    successorScope: {
      ...f.root.grantable,
      validFromNs: (BigInt(Date.parse(f.enrollment.successorValidFrom)) * 1000000n).toString(),
      validUntilNs: (BigInt(Date.parse(f.enrollment.successorValidUntil)) * 1000000n).toString(),
    },
    validFrom: f.now.toISOString(),
    validUntil: new Date(f.now.getTime() + 900000).toISOString(),
  });
  const operationId = id(502);
  const value = {
    admission: {
      platformContextId: f.enrollment.platformContextId,
      ownerParticipantId: f.enrollment.participantId,
      installationPrivacyDomainId: f.enrollment.privacyDomainId,
      platformAuthorityEpoch: (BigInt(f.enrollment.rootEpoch) + 1n).toString(),
      environmentId: f.enrollment.installationEnvironmentId,
      installationDigest: f.enrollment.installationDigest,
      grantable: intent.successorScope,
    },
    recoveryId: intent.recoveryId,
    activationOperationId: operationId,
    enrollmentDigest: intent.enrollmentDigest,
    intentDigest: canonicalAuthorizationDigest(intent),
    predecessorEpoch: f.enrollment.rootEpoch,
    predecessorDigest: f.enrollment.rootDigest,
  };
  const result = {
    rootEpoch: value.admission.platformAuthorityEpoch,
    rootRevision: (BigInt(f.enrollment.rootRevision) + 1n).toString(),
    rootDigest: platformEnvelopeScopeExpiryRecoveryDigest(value),
    operationId,
  };
  const proofs = [
    { signer: f.enrollment.recoveryPrincipal, phase: 'REQUEST' as const },
    ...f.enrollment.custodians.map((signer) => ({ signer, phase: 'APPROVE' as const })),
    { signer: f.enrollment.recoveryPrincipal, phase: 'ACTIVATE' as const },
  ].map((v, i) => ({
    ...v.signer,
    proofId: id(510 + i),
    sessionId: id(520 + i),
    sessionEpoch: '1',
    phase: v.phase,
    intentDigest: canonicalAuthorizationDigest(intent),
    verifiedAt: f.now,
    verifiedProofMaxAgeMs: 300000 as const,
  }));
  const keys = generateKeyPairSync('ed25519');
  const der = keys.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: der,
    trustedPublicKeysSpkiDer: [der],
  });
  const evidence = await signer.signCanonicalAssertion(
    localRootExpiryRecoveryEvidencePayload(
      f.enrollment,
      intent,
      operationId,
      result,
      proofs,
      BigInt(f.now.getTime()) * 1000000n,
    ),
  );
  const read = {
    enrollment: f.enrollment,
    revision: '1',
    state: 'ACTIVE',
    trust: f.trust,
    trustState: 'ACTIVE',
    trustRevision: '1',
    enrollmentCreatedAt: f.now,
    trustCreatedAt: f.now,
    intent,
    proofs,
    row: {
      intent,
      intent_digest: Buffer.from(canonicalAuthorizationDigest(intent).slice(7), 'hex'),
      state: 'COMPLETED',
      row_version: '4',
      result,
      operation_id: operationId,
      evidence_cbor: evidence.evidenceCbor,
      evidence_digest: evidence.evidenceDigest,
      evidence_cose: evidence.coseSign1,
    },
  };
  const scope = {
    activation_operation_id: operationId,
    enrollment_digest: Buffer.from(intent.enrollmentDigest.slice(7), 'hex'),
    intent_digest: Buffer.from(canonicalAuthorizationDigest(intent).slice(7), 'hex'),
    admission_preimage: platformEnvelopeScopeExpiryRecoveryPreimage(value),
    admission_digest: Buffer.from(result.rootDigest.slice(7), 'hex'),
    scope_cbor: encodeEnvelopeScope(intent.successorScope),
  };
  const query = vi.fn(async () => ({ rowCount: 1, rows: [scope] }));
  const client = { query } as unknown as PoolClient;
  return { read, scope, signer, client, query };
}
it('authenticates the complete signed original Root receipt without creating authority or signing again', async () => {
  const f = await completedReceiptFixture();
  const sign = vi.fn();
  const verifier = {
    verifyCanonicalAssertion: f.signer.verifyCanonicalAssertion,
    signCanonicalAssertion: sign,
  };
  expect(await authenticateCompletedRootExpiryRecoveryReceipt(f.client, f.read, verifier)).toBe(
    f.read,
  );
  expect(f.query).toHaveBeenCalledOnce();
  expect(sign).not.toHaveBeenCalled();
  const legacy = f.read.proofs.map(({ verifiedProofMaxAgeMs: _age, ...proof }) => proof);
  const preimage = (proofs: typeof legacy) =>
    localRootExpiryRecoveryEvidencePayload(
      f.read.enrollment,
      f.read.intent,
      f.read.row.operation_id,
      f.read.row.result,
      proofs,
      1_000n,
    );
  expect(preimage(f.read.proofs)).toEqual(preimage(legacy));
  expect(
    preimage(f.read.proofs.map((proof) => ({ ...proof, verifiedProofMaxAgeMs: 3000000 as const }))),
  ).toEqual(preimage(legacy));
});
it.each([
  'not completed',
  'digest',
  'signature',
  'proof',
  'missing approval',
  'duplicate phase',
  'wrong credential',
  'stale proof',
  'operation',
  'result',
  'enrollment binding',
  'scope bytes',
  'preimage',
  'admission digest',
])('denies altered completed Root receipt %s', async (failure) => {
  const f = await completedReceiptFixture();
  if (failure === 'not completed') f.read.row.state = 'REQUESTED';
  if (failure === 'digest') f.read.row.evidence_digest = Buffer.alloc(32);
  if (failure === 'signature')
    f.read.row.evidence_cose = Buffer.alloc(f.read.row.evidence_cose.length);
  if (failure === 'proof') f.read.proofs[0]!.principalId = id(999);
  if (failure === 'missing approval') f.read.proofs.splice(1, 1);
  if (failure === 'duplicate phase') f.read.proofs[3]!.phase = 'REQUEST';
  if (failure === 'wrong credential') f.read.proofs[1]!.credentialId = id(999);
  if (failure === 'stale proof')
    f.read.proofs[0]!.verifiedAt = new Date(f.read.proofs[0]!.verifiedAt.getTime() - 300000);
  if (failure === 'operation') f.read.row.operation_id = id(999);
  if (failure === 'result') f.read.row.result.rootRevision = '99';
  if (failure === 'enrollment binding') f.scope.enrollment_digest = Buffer.alloc(32);
  if (failure === 'scope bytes') f.scope.scope_cbor = Buffer.from('a0', 'hex');
  if (failure === 'preimage') f.scope.admission_preimage = Buffer.from('00', 'hex');
  if (failure === 'admission digest')
    f.scope.admission_digest = createHash('sha256').update('wrong').digest();
  await expect(
    authenticateCompletedRootExpiryRecoveryReceipt(f.client, f.read, f.signer),
  ).rejects.toThrow();
});

it('keeps V3 lineage metadata acyclic and full pending effects mandatory at effect boundaries', () => {
  const leaf = rootExpiryRecoveryGuardsSql
    .split('CREATE OR REPLACE FUNCTION openpc.root_expiry_pending_ancestry(')[1]!
    .split('REVOKE ALL')[0]!;
  expect(leaf).toContain(
    'VOLATILE SECURITY DEFINER SET search_path=pg_catalog,control SET row_security=on',
  );
  expect(leaf).toContain('to_jsonb(actual)=p_pending');
  expect(leaf).toContain('depth>32');
  expect(leaf).toContain('cursor_digest<>pending.predecessor_digest');
  expect(leaf).toContain("ARRAY['validFromNs','validUntilNs']");
  expect(leaf).not.toMatch(
    /control\.(?:outbox_event|assignment|authority_envelope|mutation_evidence|root_expiry_recovery_proof)\b/u,
  );
  expect(rootExpiryAncestryPreambleSql).toContain('BEGIN RETURN NULL; END $$;');
  const neutral = rootExpiryRecoveryGuardsSql
    .split(
      'CREATE OR REPLACE FUNCTION openpc.root_expiry_recovery_installation_source_current(',
    )[1]!
    .split('REVOKE ALL')[0]!;
  expect(neutral).toContain('openpc.root_expiry_pending_ancestry(');
  expect(neutral).not.toContain('read_root_expiry_pending_ancestry_witness(');
  const fence = rootExpiryRecoveryGuardsSql
    .split('CREATE OR REPLACE FUNCTION openpc.root_expiry_recovery_source_current(')[1]!
    .split('REVOKE ALL')[0]!;
  expect(fence).toContain(
    "jsonb_build_object('pending',e.document->'pending','rootAncestry',e.document->'rootAncestry')=",
  );
  expect(fence).toContain('openpc.read_root_expiry_pending_ancestry_witness(');
  expect(rootExpiryRecoveryGuardsSql).toContain('FOR SHARE OF e,t');
  expect(rootExpiryRecoveryGuardsSql).toContain(
    "NEW.intent->'rootAncestry' IS DISTINCT FROM e.document->'rootAncestry'",
  );
  expect(rootExpiryRecoveryGrantsSql).not.toMatch(
    /GRANT (?:UPDATE|INSERT).*root_expiry_recovery_trust/u,
  );
});

it('preserves the full owning readiness observations and normal direct-predecessor admission', () => {
  const extract = (sql: string, name: string) => {
    const marker = `CREATE OR REPLACE FUNCTION openpc.${name}(wanted uuid)`;
    expect(sql.split(marker)).toHaveLength(2);
    const start = sql.indexOf(marker);
    const end = sql.indexOf('\nEND $$;', start);
    expect(end).toBeGreaterThan(start);
    return sql.slice(start, end + 8);
  };
  const normal = extract(platformScopeCommitGuardsSql, 'read_platform_scope_replacement_readiness');
  const historical = extract(
    rootExpiryRecoveryGuardsSql,
    'read_root_expiry_pending_ancestry_readiness',
  );
  const observations = "SELECT coalesce(jsonb_agg(jsonb_build_object('targetId'";
  expect(historical.slice(historical.indexOf(observations))).toBe(
    normal.slice(normal.indexOf(observations)),
  );
  expect(normal).toContain('root.authority_epoch<>r.predecessor_epoch');
  expect(normal).toContain('root.row_version<>r.expected_root_revision');
  expect(historical).toContain("current_user<>'openpc_control_owner'");
  expect(historical).toContain(
    "current_setting('openpc.local_qa_runtime',true) IS DISTINCT FROM '1'",
  );
  expect(historical).toContain(
    'openpc.root_expiry_pending_ancestry(r.platform_context_id,to_jsonb(r)) IS NULL',
  );
  expect(historical).toContain(
    'num_nonnulls(r.commit_operation_id,r.commit_candidate_id,r.commit_approval_id,r.readiness_digest,r.committed_at)<>0',
  );
  expect(historical).toContain(
    "(openpc.business_cbor(head.scope_cbor)->>'4')::numeric<=floor(extract(epoch FROM clock_timestamp())*1000000000)",
  );
  expect(rootExpiryRecoveryGuardsSql).toContain(
    'GRANT EXECUTE ON FUNCTION openpc.read_root_expiry_pending_ancestry_readiness(uuid) TO openpc_control_owner;',
  );
  expect(rootExpiryRecoveryGuardsSql).toContain(
    'readiness:=openpc.read_platform_scope_replacement_readiness(r.replacement_id);',
  );
  expect(rootExpiryRecoveryGuardsSql).toContain(
    'readiness:=openpc.read_root_expiry_pending_ancestry_readiness(r.replacement_id);',
  );
});
