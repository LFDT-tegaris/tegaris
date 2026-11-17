export function controlMigrationGenerationArguments(args: readonly string[]): string[];
export function selectNewControlMigration(
  args: readonly string[],
  migrations: readonly string[],
): string;
export function assertUnprojectedControlMigration(sql: string): void;
