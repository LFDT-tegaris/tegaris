import { canonicalJson, sha256CanonicalJson } from './canonical.js';
import {
  requireTlsClientBinding,
  type TlsClientBinding,
  type TlsDispatchRequest,
  type TlsDispatchResponse,
  type TransportClass,
} from './tls-client-binding.js';
import { requireExactOwnData } from './server-input.js';

export type PrivacyExplorerTransportProfile = Readonly<Record<never, never>>;
export type PrivacyExplorerTransportOperation = 'READ_PROJECTION' | 'VERIFY_EVIDENCE';

const paths: Readonly<Record<PrivacyExplorerTransportOperation, string>> = Object.freeze({
  READ_PROJECTION: '/v1/privacy-explorer/projection:read',
  VERIFY_EVIDENCE: '/v1/privacy-explorer/evidence:verify',
});

type BoundProfile = Readonly<{
  transportClass: TransportClass;
  origin: string;
  exportProfileDigest: string;
  transportProfileId: string;
  egressPolicyId: string;
  requestByteLimit: number;
  responseByteLimit: number;
  maximumJsonDepth: number;
  publicDigest: string;
  dispatch(
    operation: PrivacyExplorerTransportOperation,
    request: Omit<TlsDispatchRequest, 'origin' | 'path'>,
  ): Promise<TlsDispatchResponse>;
}>;
const profiles = new WeakMap<PrivacyExplorerTransportProfile, BoundProfile>();
const digest = /^sha256:[0-9a-f]{64}$/;
const versionedId = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}@v[1-9][0-9]*$/;

const boundedInteger = (value: unknown, maximum: number) => {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum)
    throw new Error('invalid transport limit');
  return value as number;
};

const admittedOrigin = (value: unknown, transportClass: TransportClass) => {
  if (typeof value !== 'string') throw new Error('invalid transport origin');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('invalid transport origin');
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== '' ||
    !url.port ||
    url.origin !== value
  )
    throw new Error('invalid transport origin');
  const port = Number(url.port);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535)
    throw new Error('invalid transport origin');
  if (transportClass === 'LOCAL_DEVELOPMENT') {
    if (url.hostname !== '127.0.0.1' || port < 49_152)
      throw new Error('invalid local transport origin');
  } else if (
    url.hostname === '127.0.0.1' ||
    url.hostname === 'localhost' ||
    url.hostname === '[::1]'
  ) {
    throw new Error('invalid production transport origin');
  }
  return url.origin;
};

export const createPrivacyExplorerTransportProfile = (
  input: Readonly<Record<string, unknown>>,
): PrivacyExplorerTransportProfile => {
  const admitted = requireExactOwnData(
    input,
    [
      'transportClass',
      'origin',
      'exportProfileDigest',
      'transportProfileId',
      'egressPolicyId',
      'requestByteLimit',
      'responseByteLimit',
      'maximumJsonDepth',
      'tlsClientBinding',
    ],
    'transport profile',
  );
  if (admitted.transportClass !== 'LOCAL_DEVELOPMENT' && admitted.transportClass !== 'PRODUCTION')
    throw new Error('invalid transport class');
  if (admitted.transportClass === 'PRODUCTION')
    throw new Error('production transport qualification unavailable');
  const transportClass = admitted.transportClass;
  const origin = admittedOrigin(admitted.origin, transportClass);
  if (
    typeof admitted.exportProfileDigest !== 'string' ||
    !digest.test(admitted.exportProfileDigest)
  )
    throw new Error('invalid export profile digest');
  if (
    typeof admitted.transportProfileId !== 'string' ||
    !versionedId.test(admitted.transportProfileId) ||
    typeof admitted.egressPolicyId !== 'string' ||
    !versionedId.test(admitted.egressPolicyId)
  )
    throw new Error('invalid transport identity');
  const requestByteLimit = boundedInteger(admitted.requestByteLimit, 1_048_576);
  const responseByteLimit = boundedInteger(admitted.responseByteLimit, 16_777_216);
  const maximumJsonDepth = boundedInteger(admitted.maximumJsonDepth, 64);
  const tls = requireTlsClientBinding(admitted.tlsClientBinding as TlsClientBinding);
  if (tls.transportClass !== transportClass) throw new Error('TLS class mismatch');

  const publicFacts = {
    transportClass,
    origin,
    exportProfileDigest: admitted.exportProfileDigest,
    transportProfileId: admitted.transportProfileId,
    egressPolicyId: admitted.egressPolicyId,
    trustAnchorId: tls.trustAnchorId,
    clientIdentityId: tls.clientIdentityId,
    requestByteLimit,
    responseByteLimit,
    maximumJsonDepth,
    method: 'POST',
    paths,
    redirectPolicy: 'REJECT' as const,
    tlsVersion: 'TLSv1.3' as const,
  };
  canonicalJson(publicFacts);
  const facts: BoundProfile = Object.freeze({
    transportClass,
    origin,
    exportProfileDigest: admitted.exportProfileDigest,
    transportProfileId: admitted.transportProfileId,
    egressPolicyId: admitted.egressPolicyId,
    requestByteLimit,
    responseByteLimit,
    maximumJsonDepth,
    publicDigest: sha256CanonicalJson(publicFacts),
    dispatch: (operation, request) =>
      tls.dispatch(Object.freeze({ ...request, origin, path: paths[operation] })),
  });
  const profile = Object.freeze({});
  profiles.set(profile, facts);
  return profile;
};

export const requirePrivacyExplorerTransportProfile = (
  profile: PrivacyExplorerTransportProfile,
): BoundProfile => {
  const facts = profiles.get(profile);
  if (!facts) throw new Error('invalid Privacy Explorer transport profile');
  return facts;
};

export const privacyExplorerTransportProfileDigest = (
  profile: PrivacyExplorerTransportProfile,
): string => requirePrivacyExplorerTransportProfile(profile).publicDigest;
