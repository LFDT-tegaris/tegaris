import { describe, expect, it } from 'vitest';
import {
  isExactSigningSecretReference,
  signingSecretReferenceMaxLength,
} from './secret-reference.js';

describe('signing secret references', () => {
  it('accepts exact opaque versions and the full canonical length bound', () => {
    expect(isExactSigningSecretReference('secret://local/control/evidence#v1.2', 'v1.2')).toBe(
      true,
    );
    const maximum = `secret://${'a'.repeat(32)}/${'x'.repeat(192)}#${'v'.repeat(96)}`;
    expect(maximum.length).toBe(signingSecretReferenceMaxLength);
    expect(isExactSigningSecretReference(maximum, 'v'.repeat(96))).toBe(true);
  });
  it('rejects aliases, missing/mismatched versions, inline material and alternate encodings', () => {
    for (const [reference, version] of [
      ['local-control-evidence', '1'],
      ['secret://local/key', '1'],
      ['secret://local/key#', ''],
      ['secret://local/key#1', '2'],
      ['secret://local/key#latest', 'latest'],
      ['secret://local/key#CURRENT', 'CURRENT'],
      ['secret://local/key#1#2', '1#2'],
      ['secret://local/key#1\n', '1\n'],
      ['secret://local/key#1-2', '1'],
      ['secret://Local/key#1', '1'],
      ['secret://local/key#%31', '%31'],
      ['secret://local/kéy#1', '1'],
      ['secret://local/key#' + 'v'.repeat(97), 'v'.repeat(97)],
      ['-----BEGIN PRIVATE KEY-----', '1'],
      ['data:application/octet-stream;base64,AA==', '1'],
    ])
      expect(isExactSigningSecretReference(reference, version)).toBe(false);
  });
});
