import { identityErrors } from './contracts/catalog.js';

export interface IdentityProblem {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly code: string;
}

export function problemFor(code: (typeof identityErrors)[number][0]): IdentityProblem {
  const descriptor = identityErrors.find(([candidate]) => candidate === code);
  if (descriptor === undefined) {
    throw new Error('identity error catalog is incomplete');
  }
  return {
    type: `urn:openpc:problem:${descriptor[0].toLowerCase()}`,
    title: descriptor[2],
    status: descriptor[1],
    code: descriptor[0],
  };
}
