import { problemFor } from '../errors.js';

export class IdentityKernelError extends Error {
  constructor(readonly code: Parameters<typeof problemFor>[0]) {
    super(code);
  }
}
