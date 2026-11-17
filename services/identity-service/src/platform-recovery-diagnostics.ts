/** Route diagnostics intentionally bypass request/exception serialization. The
 * service otherwise disables automatic HTTP logging to protect login material. */
export function writeRecoveryDiagnostic(diagnostic: Readonly<Record<string, string | undefined>>) {
  const safe = Object.fromEntries(
    [
      'boundary',
      'stage',
      'enrollmentId',
      'command',
      'recoveryId',
      'phase',
      'outcome',
      'errorCode',
      'sqlState',
    ]
      .filter((key) => diagnostic[key] !== undefined)
      .map((key) => [key, diagnostic[key]]),
  );
  const output = `${JSON.stringify(safe)}\n`;
  if (safe.outcome === 'REJECTED') process.stderr.write(output);
  else process.stdout.write(output);
}
