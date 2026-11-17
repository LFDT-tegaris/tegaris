export class ParticipantKernelError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = 'ParticipantKernelError';
  }
}
