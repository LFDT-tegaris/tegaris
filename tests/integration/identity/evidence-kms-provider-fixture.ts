import {
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  randomBytes,
  X509Certificate,
} from 'node:crypto';
import { createServer } from 'node:https';
import type { TLSSocket } from 'node:tls';
import {
  encodeEvidenceKmsResponse,
  signEvidenceKmsClaim,
  evidenceKmsAbsentDigest,
  type EvidenceKmsProfileClaims,
  type EvidenceKmsReceiptClaims,
  type EvidenceWrappedKeyClaims,
  type SignedEvidenceKmsClaim,
} from '../../../packages/security-kernel/src/evidence-kms/codec.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import type { EvidenceKmsInstallationInput } from '../../../services/control-api/src/evidence/kms-contracts.js';
import type { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';

const signingKey = () => {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return {
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
    spki: pair.publicKey.export({ type: 'spki', format: 'der' }),
  };
};
/** Only the external KMS/recovery service is simulated. Its KEK is private to
 * this closure; real HTTPS, certificate verification, shared registered signing,
 * immutable provider attempts and actual AES-GCM wrapping remain exercised.
 * This ephemeral fixture cannot qualify production HSM/escrow/storage behavior. */
export async function evidenceKmsProviderFixture(
  tls: Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>,
  scope: {
    environmentId: string;
    participantId: string;
    privacyDomainId: string;
    producerTrustDigest: string;
  },
) {
  const issuer = signingKey(),
    provider = signingKey(),
    recovery = signingKey(),
    kek = randomBytes(32);
  const records = new Map<
    string,
    { requestDigest: string; intentDigest: string; record: SignedEvidenceKmsClaim; wrapped: Buffer }
  >();
  const history = new Map<
    string,
    { requestDigest: string; outcome: 'PROVED' | 'REJECTED' | 'UNKNOWN' }
  >();
  let keyState: EvidenceKmsReceiptClaims['keyState'] = 'CURRENT',
    sequence = 1n,
    floor = 1n;
  let prepareCalls = 0,
    prepareEffects = 0,
    unwrapCalls = 0;
  let loseNext: 'PREPARE' | 'UNWRAP' | undefined;
  let fault: 'STALE' | 'WRONG_NONCE' | 'RECOVERY_WRONG_SIGNER' | undefined;
  let pins: EvidenceKmsInstallationInput;
  let profile: SignedEvidenceKmsClaim;
  const server = createServer(
    {
      ca: tls.server.ca,
      cert: tls.server.certificate,
      key: tls.server.privateKey,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
    async (req, res) => {
      const chunks: Buffer[] = [];
      let material = Buffer.alloc(0),
        encoded: Buffer | undefined;
      try {
        const socket = req.socket as TLSSocket;
        if (
          req.method !== 'POST' ||
          req.url !== '/' ||
          !socket.authorized ||
          socket.getProtocol() !== 'TLSv1.3' ||
          sha256(socket.getPeerCertificate(true).raw) !== sha256(tls.parsed.raw)
        )
          throw new Error();
        let size = 0;
        for await (const chunk of req) {
          if (!Buffer.isBuffer(chunk) || (size += chunk.length) > 32768) throw new Error();
          chunks.push(Buffer.from(chunk));
        }
        const bytes = Buffer.concat(chunks),
          request = JSON.parse(bytes.toString('utf8'));
        if (
          !Buffer.from(canonicalJson(request)).equals(bytes) ||
          request.recipient.participantId !== scope.participantId ||
          request.recipient.privacyDomainId !== scope.privacyDomainId ||
          request.recipient.producerTrustDigest !== scope.producerTrustDigest ||
          request.recipient.installationDigest !== sha256(pins) ||
          !/^[0-9a-f]{64}$/u.test(request.challenge)
        )
          throw new Error();
        const requestDigest = sha256(bytes),
          operation = request.operation as EvidenceKmsReceiptClaims['operation'];
        const exchangeId = operation === 'PREPARE' ? request.attemptId : request.exchangeId;
        let outcome: EvidenceKmsReceiptClaims['outcome'] = 'PROVED';
        let record = records.get(request.attemptId);
        const intentDigest =
          operation === 'PREPARE' ? sha256(request.objectIntent) : request.objectIntentDigest;
        if (operation === 'PREPARE') {
          prepareCalls++;
          if (keyState !== 'CURRENT') outcome = 'REJECTED';
          else if (record && record.requestDigest !== requestDigest) throw new Error();
          else if (!record) {
            const dek = randomBytes(32),
              nonce = randomBytes(12);
            try {
              const cipher = createCipheriv('aes-256-gcm', kek, nonce);
              cipher.setAAD(Buffer.from(intentDigest));
              const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
              const wrapped = Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
              const claims: EvidenceWrappedKeyClaims = {
                ...scopeFields(),
                ...providerFields(),
                attemptId: request.attemptId,
                originalRequestDigest: requestDigest,
                objectIntentDigest: intentDigest,
                profileDigest: pins.profileDigest,
                wrappedKey: wrapped.toString('hex'),
                createdAtMs: Date.now(),
                signerKeyId: sha256(provider.spki),
              };
              record = {
                requestDigest,
                intentDigest,
                wrapped,
                record: signEvidenceKmsClaim(
                  'EvidenceWrappedKeyRecordV1',
                  provider.privateKey,
                  provider.spki,
                  claims,
                ),
              };
              records.set(request.attemptId, record);
              prepareEffects++;
            } finally {
              dek.fill(0);
            }
          }
        } else if (operation === 'READ_ATTEMPT') {
          const prior = history.get(request.readExchangeId ?? request.attemptId);
          if (
            prior &&
            prior.requestDigest !== (request.readRequestDigest ?? request.originalRequestDigest)
          )
            throw new Error();
          outcome = prior?.outcome ?? 'UNKNOWN';
        } else if (operation === 'UNWRAP') {
          unwrapCalls++;
          if (
            !record ||
            record.requestDigest !== request.originalRequestDigest ||
            record.intentDigest !== intentDigest ||
            sha256(record.record.payload) !== request.keyId
          )
            throw new Error();
          if (
            keyState === 'REVOKED' ||
            keyState === 'DESTROYED' ||
            (request.keyUse === 'ENCRYPT' && keyState !== 'CURRENT')
          )
            outcome = 'REJECTED';
          else {
            const cipher = createDecipheriv('aes-256-gcm', kek, record.wrapped.subarray(0, 12));
            cipher.setAAD(Buffer.from(record.intentDigest));
            cipher.setAuthTag(record.wrapped.subarray(12, 28));
            material = Buffer.concat([cipher.update(record.wrapped.subarray(28)), cipher.final()]);
          }
        } else if (operation !== 'STATUS') throw new Error();
        history.set(exchangeId, { requestDigest, outcome });
        const keyId = record ? sha256(record.record.payload) : evidenceKmsAbsentDigest;
        const now = Date.now() - (fault === 'STALE' ? 10000 : 0);
        const common = {
          ...scopeFields(),
          ...providerFields(),
          profileDigest: pins.profileDigest,
          attemptId: request.attemptId,
          exchangeId,
          requestDigest,
          challenge: fault === 'WRONG_NONCE' ? 'f'.repeat(64) : request.challenge,
          objectIntentDigest: intentDigest,
          keyId,
          keyState,
          providerSequence: String(sequence),
          recoveryFloor: String(floor),
          observedAtMs: now,
          validUntilMs: now + 4000,
        };
        const receipt = signEvidenceKmsClaim(
          'EvidenceKmsReceiptV1',
          provider.privateKey,
          provider.spki,
          {
            ...common,
            receiptId: id(),
            operation,
            keyUse: operation === 'UNWRAP' ? request.keyUse : 'NONE',
            outcome,
            materialDigest: material.length ? sha256(material) : evidenceKmsAbsentDigest,
            signerKeyId: sha256(provider.spki),
          },
        );
        const recoverySigner = fault === 'RECOVERY_WRONG_SIGNER' ? provider : recovery;
        const floorReceipt = signEvidenceKmsClaim(
          'EvidenceKmsReceiptV1',
          recoverySigner.privateKey,
          recoverySigner.spki,
          {
            ...common,
            receiptId: id(),
            operation: 'RECOVERY_FLOOR',
            keyUse: 'NONE',
            outcome: 'PROVED',
            materialDigest: evidenceKmsAbsentDigest,
            signerKeyId: sha256(recoverySigner.spki),
          },
        );
        fault = undefined;
        encoded = encodeEvidenceKmsResponse({
          profile,
          receipt,
          record: record?.record ?? { payload: Buffer.alloc(0), cose: Buffer.alloc(0) },
          recovery: floorReceipt,
          material,
        });
        if (loseNext === operation) {
          loseNext = undefined;
          req.socket.destroy();
          return;
        }
        res.writeHead(200, {
          'content-type': 'application/pc+cbor',
          'content-length': encoded.length,
        });
        await new Promise<void>((resolve) => res.end(encoded, resolve));
      } catch {
        if (!res.headersSent) res.writeHead(400);
        res.end();
      } finally {
        material.fill(0);
        encoded?.fill(0);
        for (const chunk of chunks) chunk.fill(0);
      }
    },
  );
  const scopeFields = () => ({
    environmentId: scope.environmentId,
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
  });
  const providerFields = () => ({
    providerId: pins.providerId,
    reference: pins.reference,
    version: pins.version,
    providerKeyId: pins.providerKeyId,
    providerKeyVersion: pins.providerKeyVersion,
    keyEpoch: pins.keyEpoch,
    wrapProfileDigest: pins.wrapProfileDigest,
    policyDigest: pins.policyDigest,
    recoveryProfileDigest: pins.recoveryProfileDigest,
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('KMS fixture listen failed');
    const now = Date.now();
    pins = {
      ...scope,
      installationId: id(),
      owner: 'LS-EVIDENCE-EXPORT',
      secretClass: 'SECRET-EVIDENCE-VAULT',
      reference: 'secret://test-kms/evidence-kek#v1',
      version: 'v1',
      keyEpoch: '1',
      providerId: 'test-kms',
      providerOrigin: `https://127.0.0.1:${address.port}`,
      providerTlsSpkiDigest: sha256(
        new X509Certificate(tls.server.certificate).publicKey.export({
          type: 'spki',
          format: 'der',
        }),
      ),
      profileIssuerSpkiHex: issuer.spki.toString('hex'),
      providerReceiptSpkiHex: provider.spki.toString('hex'),
      recoveryAuthoritySpkiHex: recovery.spki.toString('hex'),
      providerKeyId: 'local-fixture-kek',
      providerKeyVersion: 'v1',
      wrapProfileDigest: sha256('TEST_AES256GCM_WRAP'),
      policyDigest: sha256('TEST_EVIDENCE_ONLY_NONEXPORTABLE_KEK'),
      recoveryProfileDigest: sha256('TEST_EXTERNAL_RECOVERY_FLOOR'),
      profileDigest: evidenceKmsAbsentDigest,
      permissions: ['DECRYPT', 'ENCRYPT'],
      validFromMs: now - 1000,
      validUntilMs: now + 300000,
    };
    const claims: EvidenceKmsProfileClaims = {
      ...scopeFields(),
      ...providerFields(),
      profileId: pins.installationId,
      revision: '1',
      producerTrustDigest: scope.producerTrustDigest,
      owner: pins.owner,
      secretClass: pins.secretClass,
      providerOrigin: pins.providerOrigin,
      providerTlsSpkiDigest: pins.providerTlsSpkiDigest,
      receiptKeyId: sha256(provider.spki),
      recoveryKeyId: sha256(recovery.spki),
      permissions: 'ENCRYPT_AND_DECRYPT',
      kekExportPolicy: 'NON_EXPORTABLE',
      recoveryMode: 'THRESHOLD_ESCROW',
      validFromMs: pins.validFromMs,
      validUntilMs: pins.validUntilMs,
      issuerKeyId: sha256(issuer.spki),
    };
    profile = signEvidenceKmsClaim('EvidenceKmsProfileV1', issuer.privateKey, issuer.spki, claims);
    pins.profileDigest = sha256(profile.cose);
    return {
      pins,
      profile,
      counters: () => ({ prepareCalls, prepareEffects, unwrapCalls }),
      loseNextResponse: (operation: 'PREPARE' | 'UNWRAP') => {
        loseNext = operation;
      },
      nextFault: (value: NonNullable<typeof fault>) => {
        fault = value;
      },
      rotate: () => {
        if (keyState !== 'CURRENT') throw new Error('KMS lifecycle conflict');
        keyState = 'RETAINED';
        floor = ++sequence;
      },
      revoke: () => {
        keyState = 'REVOKED';
        floor = ++sequence;
      },
      async close() {
        server.closeAllConnections();
        await new Promise<void>((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        );
        kek.fill(0);
        issuer.privateKey.fill(0);
        provider.privateKey.fill(0);
        recovery.privateKey.fill(0);
        for (const row of records.values()) row.wrapped.fill(0);
      },
    };
  } catch (error) {
    server.closeAllConnections();
    server.close();
    kek.fill(0);
    issuer.privateKey.fill(0);
    provider.privateKey.fill(0);
    recovery.privateKey.fill(0);
    throw error;
  }
}
