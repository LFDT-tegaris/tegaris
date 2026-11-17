import { beforeEach, expect, it, vi } from 'vitest';
import {
  identityEnvelopeSigningTrustPreimage,
  identityEnvelopeSigningTrustDigest,
} from '@openpc/security-kernel';
import { identityEnvelopeEffectiveProofFixture } from '../../../participant-service/src/identity-envelope-rotation-proof.test-fixture.js';
import { captureIdentityEnvelopeRotationSuccessorSource } from './identity-envelope-rotation-successor-source.js';
const owner = vi.hoisted(() => ({ issuer: vi.fn(), fence: vi.fn() }));
vi.mock('./identity-envelope-rotation-issuer.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./identity-envelope-rotation-issuer.js')>()),
  captureIdentityEnvelopeRotationIssuer: owner.issuer,
}));
vi.mock('./identity-envelope-signing-store.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./identity-envelope-signing-store.js')>()),
  fenceIdentityEnvelopeSigningTrust: owner.fence,
}));
beforeEach(() => vi.resetAllMocks());
function fixture() {
  const f = identityEnvelopeEffectiveProofFixture();
  if (!('kind' in f.input.admission)) throw Error();
  const { enrollment, lease } = f.input.admission;
  const trust = f.input.oldTrust;
  const row = {
    participant_id: trust.participantId,
    privacy_domain_id: trust.privacyDomainId,
    signer_id: trust.signerId,
    environment_id: trust.environmentId,
    public_key_spki_der: trust.publicKeySpkiDer,
    workload_credential_id: trust.workloadCredentialId,
    workload_credential_epoch: trust.workloadCredentialEpoch.toString(),
    key_epoch: trust.keyEpoch.toString(),
    envelope_workload_participant_epoch: trust.workloadParticipantEpoch.toString(),
    envelope_workload_principal_epoch: trust.workloadPrincipalEpoch.toString(),
    valid_from_ns: trust.validFromNs.toString(),
    valid_until_ns: trust.validUntilNs.toString(),
    admission_kind: trust.admissionKind,
    admission_reference: trust.admissionReference,
    admission_digest: trust.admissionDigest,
    secret_class: trust.secretClass,
    secret_reference: trust.secretReference,
    secret_version: trust.secretVersion,
    trust_preimage: identityEnvelopeSigningTrustPreimage(trust),
    trust_digest: Buffer.from(identityEnvelopeSigningTrustDigest(trust).slice(7), 'hex'),
    cutoverAtNs: (f.input.nowNs - 1000000n).toString(),
  };
  let found = true;
  const query = vi.fn(async () => ({ rowCount: found ? 1 : 0, rows: found ? [row] : [] }));
  const selected = { trust: f.trust, recordedAtNs: f.input.nowNs };
  owner.issuer.mockResolvedValue({ issuer: f.input.currentIssuer, recordedAtNs: f.input.nowNs });
  owner.fence.mockResolvedValue(selected);
  const capture = () =>
    captureIdentityEnvelopeRotationSuccessorSource({ query } as never, enrollment, lease);
  return { ...f, enrollment, lease, row, selected, query, capture, missing: () => (found = false) };
}
it('fences actual issuer and selected successor while retaining authenticated old public provenance', async () => {
  const f = fixture();
  expect(await f.capture()).toMatchObject({
    trust: f.input.oldTrust,
    selectedTrust: f.trust,
    cutoverAtNs: BigInt(f.row.cutoverAtNs),
  });
  expect(owner.issuer.mock.invocationCallOrder[0]).toBeLessThan(
    owner.fence.mock.invocationCallOrder[0]!,
  );
  const call = f.query.mock.calls[0] as unknown as [string, unknown[]];
  expect(call[0]).toContain('selection.admission_version=$6');
  expect(call[1][5]).toBe('2');
});
it.each([
  'issuer',
  'selection',
  'missing',
  'old-digest',
  'old-metadata',
  'old-ref',
  'new-ref',
  'expired',
  'future-cutover',
] as const)('rejects %s successor source', async (kind) => {
  const f = fixture();
  if (kind === 'issuer')
    owner.issuer.mockResolvedValue({
      issuer: { ...f.input.currentIssuer, workloadPrincipalEpoch: '3' },
    });
  if (kind === 'selection') owner.fence.mockRejectedValue(Error('no selected live key'));
  if (kind === 'missing') f.missing();
  if (kind === 'old-digest') f.row.trust_digest = Buffer.alloc(32, 9);
  if (kind === 'old-metadata') f.row.envelope_workload_principal_epoch = '99';
  if (kind === 'old-ref') f.enrollment.request.oldReference = 'secret://other/old#1';
  if (kind === 'new-ref')
    f.selected.trust = { ...f.trust, secretReference: 'secret://other/new#2' };
  if (kind === 'expired')
    f.selected.recordedAtNs = BigInt(Date.parse(f.lease.validUntil)) * 1000000n;
  if (kind === 'future-cutover') f.row.cutoverAtNs = (f.selected.recordedAtNs + 1000n).toString();
  await expect(f.capture()).rejects.toThrow();
});
