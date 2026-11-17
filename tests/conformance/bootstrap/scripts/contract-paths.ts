import { readdir } from 'node:fs/promises';
import { join } from 'node:path';

export const repositoryRoot = process.cwd();
export const jsonSchemaDirectory = join(repositoryRoot, 'schemas/json');
export const generatedDirectory = join(repositoryRoot, 'generated');

export async function listFiles(
  directory: string,
  suffix: string,
  recursive = false,
): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (recursive && entry.isDirectory()) {
        return listFiles(path, suffix, true);
      }
      return entry.isFile() && entry.name.endsWith(suffix) ? [path] : [];
    }),
  );
  return files.flat().sort();
}
