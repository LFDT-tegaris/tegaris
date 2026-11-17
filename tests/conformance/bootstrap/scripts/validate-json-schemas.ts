import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

import { listFiles, repositoryRoot } from './contract-paths.js';

const schemaDirectory = resolve(repositoryRoot, 'schemas/json');
const schemas = await Promise.all(
  (await listFiles(schemaDirectory, '.schema.json')).map(async (path) =>
    JSON.parse(await readFile(path, 'utf8')),
  ),
);
const validator = new Ajv2020({ allErrors: true, strict: false, validateFormats: true });
addFormats(validator);

for (const schema of schemas) {
  validator.addSchema(schema);
}
for (const schema of schemas) {
  if (!validator.validateSchema(schema)) {
    throw new Error(`Invalid JSON Schema: ${JSON.stringify(validator.errors)}`);
  }
  validator.compile(schema);
}

const contractText = await Promise.all(
  (await listFiles(resolve(repositoryRoot, 'schemas'), '', true)).map((path) =>
    readFile(path, 'utf8'),
  ),
);
const forbiddenSecret =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|(?:api[_-]?key|client_secret|password)\s*[:=]\s*["'][^"']+["']/i;
if (contractText.some((contents) => forbiddenSecret.test(contents))) {
  throw new Error('Contract source contains a possible literal secret.');
}
