import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = process.cwd();
const manifest = async (crate: string) =>
  readFile(resolve(root, 'crates', crate, 'Cargo.toml'), 'utf8');

const [primitives, testSupport] = await Promise.all([
  manifest('pc-primitives'),
  manifest('pc-test-support'),
]);

const violations = [
  ['pc-primitives must not depend on pc-contracts', primitives, /pc-contracts/],
  ['pc-primitives must not depend on pc-test-support', primitives, /pc-test-support/],
  ['pc-test-support must not depend on pc-contracts', testSupport, /pc-contracts/],
].filter(([, contents, expression]) => (expression as RegExp).test(contents));

if (violations.length > 0) {
  throw new Error(violations.map(([message]) => message).join('; '));
}
