export class InstallationConfigError extends Error {
  constructor(reason: string, code?: string);
  readonly code: string;
  readonly reason: string;
}
export function parseConfigurationJson(
  bytes: Uint8Array,
  maximumBytes?: number,
): Record<string, unknown>;
export function parseNamedProfile(bytes: Uint8Array): Record<string, unknown>;
