export function prepareSignedInstallationCandidate(
  sources: unknown,
  pins: unknown,
  signed: { payload: Buffer; cose: Buffer },
  nowMs: number,
  options?: unknown,
): {
  state: 'BLOCKED';
  startupAllowed: false;
  blockers: string[];
  configuration: Record<string, unknown>;
  siteSignature: Record<string, unknown>;
};
