import { writeFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, X509Certificate, type KeyObject } from 'node:crypto';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import type { Pool } from 'pg';
import {
  evidenceKeyId,
  identityEnvelopeContext,
} from '../../../packages/security-kernel/src/index.js';
import { canonicalDefinitionJson } from '../../../packages/security-kernel/src/business-transition/definition.js';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.js';
import { createHttpBusinessSigningProvider } from '../../../services/identity-service/src/domain/http-business-signing-provider.js';
import { createHttpIdentityEnvelopeRotationProvider } from '../../../services/identity-service/src/domain/http-identity-envelope-rotation-provider.js';
import type { HandoverProviderAttempt } from '../../../services/identity-service/src/domain/workload-signing-handover-possession.js';
import {
  businessProviderDescriptorSchema,
  businessProviderPossessionPreimage,
  type BusinessProviderObservation,
} from '../../../services/identity-service/src/domain/business-signing-provider.js';
import {
  identityEnvelopeRotationDescriptorSchema,
  identityEnvelopeRotationPossessionPreimage,
  type IdentityEnvelopeRotationObservation,
} from '../../../services/identity-service/src/domain/identity-envelope-rotation-provider.js';

type Observation = BusinessProviderObservation | IdentityEnvelopeRotationObservation;
type Leaf = { certificate: X509Certificate; pem: Buffer; privateKey: Buffer; publicKey: Buffer };
function signProof(original: HandoverProviderAttempt, privateKey: KeyObject) {
  let preimage: Buffer;
  if (original.purpose === identityEnvelopeContext.purpose) {
    assert.equal(original.request.method, 'PROVE');
    if (original.request.method !== 'PROVE') throw new Error('Expected envelope proof');
    preimage = identityEnvelopeRotationPossessionPreimage(original.request);
  } else {
    if (original.request.method !== 'PROVE') throw new Error('Expected receipt proof');
    preimage = businessProviderPossessionPreimage(original.request);
  }
  return sign('sha256', preimage, { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('hex');
}
/** A genuinely external mTLS provider, with retained original responses and
 * fault controls. It never writes Identity approval, trust or selection rows. */
export async function workloadHandoverProviderFixture(
  admin: Pool | undefined,
  pki: { ca: Buffer; server: Leaf; successor: Leaf },
  attempts: readonly HandoverProviderAttempt[],
  ids: { receipt: string; envelope: string },
) {
  const originals = new Map(attempts.map((attempt) => [attempt.request.attemptId, attempt]));
  const observations = new Map<string, Observation>();
  const performs = new Map<string, number>();
  const failures: unknown[] = [];
  const dispatchFaults = new Map<
    string,
    'DROP_RESPONSE' | 'REJECT' | 'CORRUPT_RESPONSE_SIGNATURE'
  >();
  const keyPairs = new Map<
    string,
    { privateKey: KeyObject; descriptor: NonNullable<Observation['descriptor']> }
  >();
  const lookupFaults = new Map<
    string,
    'ABSENT' | 'UNKNOWN' | 'MALFORMED' | 'CONFLICT' | 'NONCANONICAL'
  >();
  const server = createServer(
    {
      cert: pki.server.pem,
      key: pki.server.privateKey,
      ca: pki.ca,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    },
    async (request, response) => {
      try {
        const socket = request.socket as TLSSocket;
        assert(socket.authorized);
        assert.equal(socket.getProtocol(), 'TLSv1.3');
        assert.deepEqual(socket.getPeerCertificate().raw, pki.successor.certificate.raw);
        const chunks: Buffer[] = [];
        for await (const chunk of request) {
          chunks.push(Buffer.from(chunk));
          assert(Buffer.concat(chunks).length <= 262144);
        }
        const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined;
        const isLookup = request.method === 'GET' || request.url?.endsWith('/lookup');
        const attemptId =
          request.method === 'GET' ? request.url!.split('/').at(-1)! : body.attemptId;
        const original = originals.get(attemptId);
        assert(original);
        const envelope = original.purpose === identityEnvelopeContext.purpose;
        assert.equal(
          request.url,
          envelope
            ? `/v1/identity-envelope-signing/rotation/${isLookup ? 'lookup' : 'perform'}`
            : isLookup
              ? `/v1/business-signing/attempts/${attemptId}`
              : '/v1/business-signing/requests',
        );
        if (body)
          assert.equal(canonicalDefinitionJson(body), canonicalDefinitionJson(original.request));
        const send = (value: unknown) => {
          response.writeHead(200, { 'content-type': 'application/json' });
          response.end(canonicalJson(value));
        };
        if (isLookup) {
          const fault = lookupFaults.get(attemptId);
          if (fault === 'UNKNOWN') {
            response.writeHead(503);
            response.end();
            return;
          }
          if (fault === 'MALFORMED') {
            send({ state: 'OBSERVED', observation: { untrusted: true } });
            return;
          }
          const observed = observations.get(attemptId);
          if (fault === 'NONCANONICAL') {
            response.writeHead(200, { 'content-type': 'application/json' });
            response.end(JSON.stringify({ state: 'OBSERVED', observation: observed }));
            return;
          }
          if (fault === 'ABSENT' || !observed) {
            send(
              envelope
                ? {
                    state: 'NOT_FOUND',
                    attemptId,
                    operationId: original.request.operationId,
                    requestDigest: original.requestDigest,
                  }
                : { state: 'ABSENT', attemptId },
            );
            return;
          }
          send({
            state: 'OBSERVED',
            observation:
              fault === 'CONFLICT'
                ? { ...observed, recordedAtNs: (BigInt(observed.recordedAtNs) + 1000n).toString() }
                : observed,
          });
          return;
        }
        // Independent read proves the actual runtime committed custody before I/O.
        assert(admin, 'A real database is required before any fixture dispatch');
        const saved = await admin.query<{
          attempt: HandoverProviderAttempt;
          dispatches: number;
        }>(
          `select attempt,(select count(*)::integer from control.workload_signing_handover_dispatch d where d.attempt_id=a.attempt_id) dispatches
         from control.workload_signing_handover_attempt a where attempt_id=$1`,
          [attemptId],
        );
        assert.equal(saved.rowCount, 1);
        assert.equal(saved.rows[0]!.dispatches, 1);
        assert.equal(
          canonicalDefinitionJson(saved.rows[0]!.attempt),
          canonicalDefinitionJson(original),
        );
        performs.set(attemptId, (performs.get(attemptId) ?? 0) + 1);
        assert.equal(
          performs.get(attemptId),
          1,
          'Original provider effect dispatched more than once',
        );
        const now = BigInt(Date.now()) * 1000000n;
        const r = original.request;
        assert(['INSPECT', 'PREPARE', 'PROVE'].includes(r.method));
        const keyScope = canonicalDefinitionJson({
          participantId: r.participantId,
          privacyDomainId: r.privacyDomainId,
          environmentId: r.environmentId,
          workloadCredentialId: r.workloadCredentialId,
          purpose: r.purpose,
          reference: r.reference,
          version: r.version,
        });
        let held = keyPairs.get(keyScope);
        if (!held) {
          assert.notEqual(
            r.method,
            'PROVE',
            'A proof must use the key actually prepared by this external provider',
          );
          const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
          const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
          const common = {
            participantId: r.participantId,
            privacyDomainId: r.privacyDomainId,
            environmentId: r.environmentId,
            workloadCredentialId: r.workloadCredentialId,
            secretClass: r.secretClass,
            purpose: r.purpose,
            reference: r.reference,
            version: r.version,
            algorithm: 'ES256' as const,
            publicKeySpkiHex: publicKey.toString('hex'),
            fingerprint: evidenceKeyId(publicKey),
            validFromNs: (now - 1000000000n).toString(),
            validUntilNs: (now + 3600000000000n).toString(),
            state: 'ACTIVE' as const,
            revokedAtNs: null,
            retiredAtNs: null,
          };
          const descriptor =
            original.purpose === identityEnvelopeContext.purpose
              ? identityEnvelopeRotationDescriptorSchema.parse({
                  ...common,
                  purpose: identityEnvelopeContext.purpose,
                  workloadCredentialEpoch: original.request.workloadCredentialEpoch,
                  purposeCode: 371 as const,
                  schemaId: 24034 as const,
                  schemaVersion: 1 as const,
                  schemaDefinitionDigest: original.request.schemaDefinitionDigest,
                  profileId: original.request.profileId,
                  profileVersion: 1 as const,
                  profileDigest: original.request.profileDigest,
                })
              : businessProviderDescriptorSchema.parse(common);
          held = { privateKey: pair.privateKey, descriptor };
          if (dispatchFaults.get(attemptId) !== 'REJECT') keyPairs.set(keyScope, held);
        }
        assert(held);
        if (r.method === 'PROVE') assert.equal(r.expectedFingerprint, held.descriptor.fingerprint);
        const reject = dispatchFaults.get(attemptId) === 'REJECT';
        const observation = {
          schemaVersion: 1,
          providerId: envelope ? ids.envelope : ids.receipt,
          attemptId,
          operationId: r.operationId,
          requestDigest: original.requestDigest,
          method: r.method,
          recordedAtNs: now.toString(),
          outcome: reject ? 'REJECTED' : 'SUCCEEDED',
          reason: reject ? 'KEY_NOT_FOUND' : null,
          descriptor: reject ? null : held.descriptor,
          resultHex: !reject && r.method === 'PROVE' ? signProof(original, held.privateKey) : null,
        } as Observation;
        observations.set(attemptId, observation);
        if (dispatchFaults.get(attemptId) === 'DROP_RESPONSE') {
          response.destroy();
          return;
        }
        send(
          dispatchFaults.get(attemptId) === 'CORRUPT_RESPONSE_SIGNATURE'
            ? { ...observation, resultHex: 'ff'.repeat(64) }
            : observation,
        );
      } catch (error) {
        failures.push(error);
        response.writeHead(500);
        response.end();
      }
    },
  );
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const tls = {
    certificate: pki.successor.pem,
    privateKey: pki.successor.privateKey,
    trustCa: pki.ca,
    timeoutMs: 1000,
  };
  const receipt = createHttpBusinessSigningProvider({ ...tls, origin });
  const envelope = createHttpIdentityEnvelopeRotationProvider({
    ...tls,
    providerOrigin: origin,
    providerTlsSpkiDigest: evidenceKeyId(pki.server.publicKey),
    callerWorkloadKeyDigest: evidenceKeyId(pki.successor.publicKey),
  });
  return {
    providers: { ids, receipt, envelope },
    registerAttempts(values: readonly HandoverProviderAttempt[]) {
      for (const attempt of values) {
        assert(
          !originals.has(attempt.request.attemptId),
          'Original provider command cannot be replaced',
        );
        originals.set(attempt.request.attemptId, attempt);
      }
    },
    dispatchFaults,
    lookupFaults,
    observations,
    performs,
    async savePrivateState(file: string) {
      await writeFile(
        file,
        JSON.stringify({
          requests: [...originals],
          observations: [...observations],
          performs: [...performs],
          keys: [...keyPairs].map(([scope, key]) => ({
            scope,
            descriptor: key.descriptor,
            privateKeyPkcs8Base64: key.privateKey
              .export({ format: 'der', type: 'pkcs8' })
              .toString('base64'),
          })),
        }),
        { mode: 0o600, flag: 'wx' },
      );
    },
    assertHealthy() {
      assert.deepEqual(failures, []);
    },
    async close() {
      receipt.close();
      envelope.close();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}
