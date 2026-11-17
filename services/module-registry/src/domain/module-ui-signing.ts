import { encodeCanonicalCbor, verifyBoundCoseSign1Es256 } from '@openpc/security-kernel';
import { z } from 'zod';
import { pcCbor1, sha256 } from './digest.js';
import { ContractError } from './errors.js';
import type { ModuleReleasePublisherBinding } from '../module-release-catalog.js';

export const moduleUiCoseContext = Object.freeze({
  schemaId: 23001,
  purpose: 'openpc:module-ui-manifest:v1',
});
export const moduleUiRegisteredSchemaDigest =
  'sha256:bf8edcaa7a11c08d6cba257ab02d25bb5196b2e72617e67da99732d1c6ac9233';
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const envelope = z.strictObject({
  encoding: z.literal('PC-CBOR-1'),
  algorithm: z.literal('ES256'),
  schemaId: z.literal(23001),
  schemaVersion: z.literal('1.0.0'),
  schemaDigest: z.literal(moduleUiRegisteredSchemaDigest),
  purpose: z.literal('openpc:module-ui-manifest:v1'),
  coseSign1: z.string(),
});
const identity = z.looseObject({
  moduleId: z.string().min(1),
  moduleVersion: z.string().min(1),
  moduleDigest: digest,
  publisherKeyId: digest,
  signature: envelope,
});
const rejected = () => new ContractError('PC-MODULE-7008');

/** Canonical signed preimage, not full manifest validation or UI admission.
 * The schema owner first validates the complete document. All of its final
 * fields, including the publisher key ID and built module digest, are
 * preserved under semantic-map key 5; only the signature envelope is omitted.
 * Keys 1..4 bind purpose, numeric schema, version and the registered schema
 * digest. Archived conformance placeholder keys/digests are never normalized.
 * Nested semantic JSON uses the existing Rust PC-CBOR-1 owner.
 */
export function moduleUiSemanticPayload(document: unknown): Buffer {
  try {
    const value = identity.parse(document);
    const unsigned = Object.fromEntries(
      Object.entries(value).filter(([key]) => key !== 'signature'),
    );
    const context = encodeCanonicalCbor(
      new Map<number, string | number | Buffer>([
        [1, moduleUiCoseContext.purpose],
        [2, moduleUiCoseContext.schemaId],
        [3, '1.0.0'],
        [4, Buffer.from(moduleUiRegisteredSchemaDigest.slice(7), 'hex')],
      ]),
    );
    // The closed four-entry map uses one initial byte. Append key 5 and the
    // canonical document as a value, not as JSON text or an opaque byte string.
    const result = Buffer.concat([
      Buffer.from([0xa5]),
      context.subarray(1),
      Buffer.from([5]),
      pcCbor1(unsigned).bytes,
    ]);
    if (result.length > 65536) throw rejected();
    return result;
  } catch {
    throw rejected();
  }
}

/** Root-only cryptographic binding. Obtain binding through the deployment
 * catalog's lookupPublisherBinding for the CURRENT public module manifestDigest.
 * A successful check grants no UI capability, certification, installation state
 * or command authority. The loader must also bind its actual compile-time bundle
 * and current module/configuration/context, then reauthorize every backend use.
 */
export function assertModuleUiReleaseSignature(
  document: unknown,
  binding: ModuleReleasePublisherBinding,
): void {
  try {
    const value = identity.parse(document);
    const wire = Buffer.from(value.signature.coseSign1, 'base64');
    if (
      value.moduleDigest !== binding.manifestDigest ||
      value.moduleId !== binding.moduleName ||
      value.moduleVersion !== binding.moduleVersion ||
      value.publisherKeyId !== binding.publisherKeyId ||
      !Buffer.isBuffer(binding.publisherPublicKeySpkiDer) ||
      value.publisherKeyId !== `sha256:${sha256(binding.publisherPublicKeySpkiDer)}` ||
      !Number.isSafeInteger(binding.validUntilMs) ||
      binding.validUntilMs <= Date.now() ||
      wire.length === 0 ||
      wire.toString('base64') !== value.signature.coseSign1 ||
      !verifyBoundCoseSign1Es256(
        binding.publisherPublicKeySpkiDer,
        moduleUiSemanticPayload(value),
        wire,
        moduleUiCoseContext,
      )
    )
      throw rejected();
  } catch {
    throw rejected();
  }
}
