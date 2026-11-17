import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import {
  parseRetirementWire,
  retirementSelection,
  retirementWireBytes,
} from './store-retirement-wire.js';

export const factRetirementSelectionRequest = z.strictObject({
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  candidateId: z.uuidv7(),
  signedFactDigest: z.string().regex(/^[0-9a-f]{64}$/u),
});
const response = factRetirementSelectionRequest.extend({
  identity: z.literal('OPENPC-FACT-RETIREMENT-SELECTION-1'),
  authority: z.literal('ADVISORY_ONLY'),
  result: z.discriminatedUnion('state', [
    z.strictObject({ state: z.literal('SELECTED'), selection: retirementSelection }),
    z.strictObject({ state: z.literal('UNAVAILABLE') }),
  ]),
});

export function parseFactRetirementSelection(
  bytes: Buffer,
  input: z.infer<typeof factRetirementSelectionRequest>,
) {
  const expected = factRetirementSelectionRequest.parse(input);
  const value = response.parse(parseRetirementWire(bytes));
  if (
    value.participantId !== expected.participantId ||
    value.privacyDomainId !== expected.privacyDomainId ||
    value.candidateId !== expected.candidateId ||
    value.signedFactDigest !== expected.signedFactDigest ||
    value.result.state !== 'SELECTED' ||
    value.result.selection.class !== 'ADMITTED_FACT' ||
    value.result.selection.rows.length !== 1 ||
    value.result.selection.rows[0]!.candidate_id !== expected.candidateId ||
    value.result.selection.rows[0]!.signed_fact_digest !== expected.signedFactDigest
  )
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  return value.result.selection;
}

/** Internal connection and signing trust are service configuration. This read
 * derives bytes from the native owner; it never accepts an eligibility claim. */
export async function readFactRetirementSelection(
  input: z.infer<typeof factRetirementSelectionRequest>,
) {
  const request = factRetirementSelectionRequest.parse(input);
  const executable =
    process.env.OPENPC_POLICY_FACT_READER_BIN ??
    fileURLToPath(new URL('../../../../target/debug/policy_fact_reader', import.meta.url));
  const bytes = await new Promise<Buffer>((resolve, reject) => {
    const child = execFile(
      executable,
      ['--retirement-selection'],
      { timeout: 11000, maxBuffer: 1048576, encoding: 'buffer' },
      (error, stdout) => {
        if (error) reject(new ConfigurationRepositoryError('PC-DATA-6007'));
        else resolve(stdout);
      },
    );
    child.stdin?.on('error', () => reject(new ConfigurationRepositoryError('PC-DATA-6007')));
    if (!child.stdin) reject(new ConfigurationRepositoryError('PC-DATA-6007'));
    else child.stdin.end(retirementWireBytes(request));
  });
  return parseFactRetirementSelection(bytes, request);
}
