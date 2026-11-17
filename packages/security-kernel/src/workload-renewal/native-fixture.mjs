import { generateKeyPairSync } from 'node:crypto';
import {
  encodeWorkloadRenewalRequest,
  encodeWorkloadRenewalPolicyAuthorization,
  workloadRenewalDigest,
} from './codec.ts';
import { signWorkloadRenewalCose } from './cose.ts';
import {
  renewalRequestFixture,
  renewalAuthorizationFixture,
  renewalSigningTrustFixture,
} from './fixture.ts';
import {
  workloadRenewalSigningTrustPreimage,
  workloadRenewalSigningTrustDigest,
} from './signing-trust.ts';

const successor = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const identity = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const successorSpki = successor.publicKey.export({ format: 'der', type: 'spki' });
const identitySpki = identity.publicKey.export({ format: 'der', type: 'spki' });
const request = renewalRequestFixture(workloadRenewalDigest(successorSpki));
const requestPayload = encodeWorkloadRenewalRequest(request);
const requestCose = signWorkloadRenewalCose(
  'REQUEST',
  successor.privateKey.export({ format: 'der', type: 'pkcs8' }),
  successorSpki,
  requestPayload,
);
const authorization = renewalAuthorizationFixture(
  requestPayload,
  workloadRenewalDigest(identitySpki),
);
const signingTrust = renewalSigningTrustFixture(identitySpki);
authorization.signer.profileDigest = signingTrust.profileDigest;
authorization.signer.trustDigest = workloadRenewalSigningTrustDigest(signingTrust);
const authorizationPayload = encodeWorkloadRenewalPolicyAuthorization(authorization);
const authorizationCose = signWorkloadRenewalCose(
  'POLICY_AUTHORIZATION',
  identity.privateKey.export({ format: 'der', type: 'pkcs8' }),
  identitySpki,
  authorizationPayload,
);
process.stdout.write(
  JSON.stringify({
    request,
    requestPayload: [...requestPayload],
    requestCose: [...requestCose],
    successorSpki: [...successorSpki],
    authorization: { ...authorization, requestBytes: [...requestPayload] },
    authorizationPayload: [...authorizationPayload],
    authorizationCose: [...authorizationCose],
    identitySpki: [...identitySpki],
    signingTrust: Object.fromEntries(
      Object.entries(signingTrust).map(([name, value]) => [
        name,
        typeof value === 'bigint' ? value.toString() : Buffer.isBuffer(value) ? [...value] : value,
      ]),
    ),
    signingTrustPreimage: [...workloadRenewalSigningTrustPreimage(signingTrust)],
    signingTrustDigest: workloadRenewalSigningTrustDigest(signingTrust),
  }),
);
