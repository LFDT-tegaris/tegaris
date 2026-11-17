import { expect, it, vi } from 'vitest';
import { maxAbiJsonFileBytes, readAbiJsonFile } from './abi-json-file';

const file = (text: string) => {
  const bytes = new TextEncoder().encode(text);
  return { size: bytes.byteLength, arrayBuffer: async () => bytes.buffer };
};

it('preserves the original UTF-8 source bytes for native provenance', async () => {
  const text = ' [\n { "type": "function", "name": "getPaymentInfo" }\n ]\n';
  expect(await readAbiJsonFile(file(text))).toBe(text);
});

it.each(['{}', '[]', '[', '"not an ABI"', '\ufeff[]'])(
  'rejects unsupported ABI file content without returning a replacement: %s',
  async (text) => expect(readAbiJsonFile(file(text))).rejects.toThrow(),
);

it.each([0, -1, maxAbiJsonFileBytes + 1, Number.NaN])(
  'rejects size %s before reading the file',
  async (size) => {
    const arrayBuffer = vi.fn();
    await expect(readAbiJsonFile({ size, arrayBuffer })).rejects.toThrow();
    expect(arrayBuffer).not.toHaveBeenCalled();
  },
);

it('rejects changed size, invalid UTF-8 and excessive ABI entry counts', async () => {
  await expect(readAbiJsonFile({ ...file('[]'), size: 3 })).rejects.toThrow();
  await expect(
    readAbiJsonFile({ size: 2, arrayBuffer: async () => new Uint8Array([0xc3, 0x28]).buffer }),
  ).rejects.toThrow();
  await expect(
    readAbiJsonFile(file(JSON.stringify(Array.from({ length: 4097 }, () => ({}))))),
  ).rejects.toThrow();
});
