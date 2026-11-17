import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { chromium } from '@playwright/test';

const [
  sessionToken,
  sessionRevision,
  credentialId,
  privateKeyPath,
  publicKeySpkiHex,
  actionIntentId,
  resourceId,
  resourceDigest,
  rpIdHash,
  initialSignCountText,
  idempotencyKey,
  actionIntentDigest,
] = process.argv.slice(2);

if (
  !sessionToken?.match(
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  ) ||
  !sessionRevision?.match(/^[1-9][0-9]*$/u) ||
  !credentialId?.match(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u) ||
  !privateKeyPath ||
  !publicKeySpkiHex?.match(/^[0-9a-f]{180,240}$/u) ||
  !actionIntentId?.match(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u) ||
  !resourceId?.match(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u) ||
  !resourceDigest?.match(/^sha256:[0-9a-f]{64}$/u) ||
  !rpIdHash?.match(/^sha256:[0-9a-f]{64}$/u) ||
  !initialSignCountText?.match(/^(?:0|[1-9][0-9]*)$/u) ||
  !idempotencyKey?.match(/^[A-Za-z0-9._~-]{16,128}$/u) ||
  !actionIntentDigest?.match(/^sha256:[0-9a-f]{64}$/u)
) {
  throw new Error('Configuration WebAuthn browser fixture arguments are invalid.');
}

const origin = 'http://localhost:8080';
const initialSignCount = Number(initialSignCountText);
const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.setExtraHTTPHeaders({ Cookie: `__Host-openpc_session=${sessionToken}` });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: false,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      credentialId: Buffer.from(credentialId, 'utf8').toString('base64'),
      isResidentCredential: false,
      rpId: 'localhost',
      privateKey: (await readFile(privateKeyPath)).toString('base64'),
      signCount: initialSignCount,
    },
  });
  let assertions = 0;
  cdp.on('WebAuthn.credentialAsserted', () => {
    assertions += 1;
  });

  await page.goto(`${origin}/api/unknown`);
  const ceremony = await page.evaluate(
    async (input) => {
      const json = async (response) => {
        const text = await response.text();
        if (!response.ok) throw new Error(`${response.status}:${text}`);
        return JSON.parse(text);
      };
      const encode = (value) => {
        let binary = '';
        for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
        return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
      };
      const decode = (value) => {
        const padded = value
          .replaceAll('-', '+')
          .replaceAll('_', '/')
          .padEnd(Math.ceil(value.length / 4) * 4, '=');
        const binary = atob(padded);
        return Uint8Array.from(binary, (character) => character.charCodeAt(0));
      };
      const csrf = await json(
        await fetch('/api/v1/session/csrf', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ actionIntentId: input.actionIntentId }),
        }),
      );
      const challenge = await json(
        await fetch('/v1/identity/webauthn/assertion/challenge', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf.csrfToken },
          body: JSON.stringify({
            actionIntentId: input.actionIntentId,
            resourceId: input.resourceId,
            resourceDigest: input.resourceDigest,
            rpIdHash: input.rpIdHash,
          }),
        }),
      );
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: decode(challenge.challenge),
          rpId: 'localhost',
          allowCredentials: challenge.credentialIds.map((allowedCredentialId) => ({
            id: new TextEncoder().encode(allowedCredentialId),
            type: 'public-key',
          })),
          timeout: 300_000,
          userVerification: 'required',
        },
      });
      if (!(credential instanceof PublicKeyCredential)) {
        throw new Error('The checker authenticator did not return a public-key credential.');
      }
      const assertion = credential.response;
      if (!(assertion instanceof AuthenticatorAssertionResponse)) {
        throw new Error('The checker authenticator returned an invalid assertion.');
      }
      const authenticatorData = new Uint8Array(assertion.authenticatorData);
      const clientData = JSON.parse(new TextDecoder().decode(assertion.clientDataJSON));
      const expectedRpIdHash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode('localhost')),
      );
      const actualSignCount = new DataView(
        authenticatorData.buffer,
        authenticatorData.byteOffset,
        authenticatorData.byteLength,
      ).getUint32(33, false);
      const bindings = {
        credential: new TextDecoder().decode(credential.rawId) === input.credentialId,
        type: clientData.type === 'webauthn.get',
        challenge: clientData.challenge === challenge.challenge,
        origin: clientData.origin === location.origin,
        crossOrigin: clientData.crossOrigin === false,
        length: authenticatorData.length === 37,
        presenceAndVerification: (authenticatorData[32] & 0x05) === 0x05,
        rpId: expectedRpIdHash.every((byte, index) => authenticatorData[index] === byte),
        counter: actualSignCount > input.initialSignCount,
      };
      const failed = Object.entries(bindings)
        .filter(([, matched]) => !matched)
        .map(([name]) => name);
      if (failed.length) {
        throw new Error(
          `The checker authenticator assertion bindings are invalid: ${JSON.stringify({ failed, actualSignCount, initialSignCount: input.initialSignCount })}`,
        );
      }
      return {
        signCount: actualSignCount,
        challenge: challenge.challenge,
        csrfToken: csrf.csrfToken,
        assertion: {
          credentialId: new TextDecoder().decode(credential.rawId),
          authenticatorData: encode(authenticatorData),
          clientDataJson: encode(assertion.clientDataJSON),
          signature: encode(assertion.signature),
        },
      };
    },
    {
      actionIntentId,
      resourceId,
      resourceDigest,
      rpIdHash,
      sessionRevision,
      idempotencyKey,
      credentialId,
      initialSignCount,
    },
  );
  const authenticatorData = Buffer.from(ceremony.assertion.authenticatorData, 'base64url');
  const clientDataJson = Buffer.from(ceremony.assertion.clientDataJson, 'base64url');
  const signature = Buffer.from(ceremony.assertion.signature, 'base64url');
  const publicKey = createPublicKey({
    key: Buffer.from(publicKeySpkiHex, 'hex'),
    format: 'der',
    type: 'spki',
  });
  if (
    !verify(
      'sha256',
      Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJson).digest()]),
      publicKey,
      signature,
    )
  ) {
    throw new Error('The browser assertion signature does not match the database credential key.');
  }
  process.stdout.write('OPENPC_CONFIGURATION_WEBAUTHN_LOCAL_SIGNATURE|PASS\n');
  const result = await page.evaluate(
    async (input) => {
      const response = await fetch('/v1/identity/webauthn/assertion/verify', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Idempotency-Key': input.idempotencyKey,
          'X-CSRF-Token': input.csrfToken,
          'X-OpenPC-Aggregate-Version': input.sessionRevision,
          'OpenPC-Action-Intent-Digest': input.actionIntentDigest,
        },
        body: JSON.stringify({
          actionIntentId: input.actionIntentId,
          resourceId: input.resourceId,
          resourceDigest: input.resourceDigest,
          rpIdHash: input.rpIdHash,
          challenge: input.challenge,
          assertion: JSON.stringify(input.assertion),
        }),
      });
      const text = await response.text();
      if (!response.ok) throw new Error(`${response.status}:${text}`);
      return JSON.parse(text);
    },
    {
      actionIntentId,
      resourceId,
      resourceDigest,
      rpIdHash,
      sessionRevision,
      idempotencyKey,
      actionIntentDigest,
      ...ceremony,
    },
  );
  const storedCredentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  if (
    result.status !== 'verified' ||
    assertions < 1 ||
    assertions !== ceremony.signCount - initialSignCount ||
    storedCredentials.credentials.length !== 1 ||
    storedCredentials.credentials[0]?.signCount !== ceremony.signCount
  ) {
    throw new Error(
      `Configuration WebAuthn browser verification failed: ${JSON.stringify({ result, assertions, credentialCount: storedCredentials.credentials.length, storedSignCount: storedCredentials.credentials[0]?.signCount })}`,
    );
  }
  process.stdout.write(
    `OPENPC_CONFIGURATION_WEBAUTHN_BROWSER|PASS|checker=distinct|assertions=${assertions}|counter=monotonic|user_verification=required\n`,
  );
  await cdp.detach();
  await context.close();
} finally {
  await browser.close();
}
