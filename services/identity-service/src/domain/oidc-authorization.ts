import {
  localQaExecutionTimeoutMs,
  localQaDurationMultiplier,
} from '../../../../packages/security-kernel/src/local-qa-duration-profile.js';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { PoolClient } from 'pg';
import { localOperationId } from './local-operation-id.js';

export interface OidcClientConfiguration {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
}
export interface OidcAuthorization extends OidcClientConfiguration {
  readonly durationProfile?: 'LOCAL_QA_10X';
  readonly expiresAt?: string;
  readonly transactionId: string;
  readonly state: string;
  readonly nonce: string;
  readonly codeChallenge: string;
}
export interface OidcTransactionCustody {
  readonly browserSession: string;
  readonly codeVerifier: string;
}
export interface OidcAuthorizationStart {
  readonly authorization: OidcAuthorization;
  readonly custody: OidcTransactionCustody;
}
export interface OidcExchangeContext extends OidcClientConfiguration {
  readonly codeVerifier: string;
  readonly selectedParticipantId?: string;
  readonly expectedNonceDigest: string;
}
export interface OidcRow {
  purpose: 'SESSION' | 'INVITATION';
  selected_participant_id: string | null;
  transaction_id: string;
  state_digest: Buffer;
  nonce_digest: Buffer;
  code_verifier_digest: Buffer;
  browser_session_digest: Buffer;
  code_challenge: string;
  issuer: string;
  client_id: string;
  redirect_uri: string;
  expires_at: Date;
  consumed_at: Date | null;
}
const sha = (value: string) => createHash('sha256').update(value).digest();
const token = () => randomBytes(32).toString('base64url');

/** The caller owns the transaction so invitation state and proof custody start atomically. */
export async function persistOidcAuthorization(
  client: PoolClient,
  configuration: OidcClientConfiguration,
  now: Date,
  purpose: OidcRow['purpose'],
  selectedParticipantId?: string,
): Promise<OidcAuthorizationStart> {
  const transactionId = localOperationId();
  const expiresAt = new Date(now.getTime() + localQaExecutionTimeoutMs(300_000));
  const state = token(),
    nonce = token(),
    codeVerifier = token(),
    browserSession = token();
  const codeChallenge = sha(codeVerifier).toString('base64url');
  await client.query(
    `insert into control.oidc_transaction
      (transaction_id,state_digest,nonce_digest,code_verifier_digest,browser_session_digest,
       code_challenge,issuer,client_id,redirect_uri,expires_at,selected_participant_id,purpose)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [
      transactionId,
      sha(state),
      sha(nonce),
      sha(codeVerifier),
      sha(browserSession),
      codeChallenge,
      configuration.issuer,
      configuration.clientId,
      configuration.redirectUri,
      expiresAt,
      selectedParticipantId ?? null,
      purpose,
    ],
  );
  return {
    authorization: {
      transactionId,
      state,
      nonce,
      codeChallenge,
      ...configuration,
      expiresAt: expiresAt.toISOString(),
      ...(localQaDurationMultiplier(process.env) === 10
        ? { durationProfile: 'LOCAL_QA_10X' as const }
        : {}),
    },
    custody: { browserSession, codeVerifier },
  };
}

export function matchesOidcCustody(row: OidcRow, custody: OidcTransactionCustody): boolean {
  const browser = sha(custody.browserSession),
    verifier = sha(custody.codeVerifier);
  return (
    row.browser_session_digest.length === browser.length &&
    row.code_verifier_digest.length === verifier.length &&
    timingSafeEqual(row.browser_session_digest, browser) &&
    timingSafeEqual(row.code_verifier_digest, verifier)
  );
}

export function oidcExchangeFromRow(
  row: OidcRow,
  custody: OidcTransactionCustody,
): OidcExchangeContext {
  return {
    codeVerifier: custody.codeVerifier,
    issuer: row.issuer,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    expectedNonceDigest: `sha256:${row.nonce_digest.toString('hex')}`,
    ...(row.selected_participant_id === null
      ? {}
      : { selectedParticipantId: row.selected_participant_id }),
  };
}
