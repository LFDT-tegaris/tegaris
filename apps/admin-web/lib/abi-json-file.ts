export const maxAbiJsonFileBytes = 256 * 1024;

export async function readAbiJsonFile(file: Pick<Blob, 'size' | 'arrayBuffer'>): Promise<string> {
  if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > maxAbiJsonFileBytes)
    throw new Error('Invalid ABI file size');
  const bytes = await file.arrayBuffer();
  if (bytes.byteLength !== file.size) throw new Error('ABI file size changed');
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const abi: unknown = JSON.parse(text);
  if (!Array.isArray(abi) || abi.length < 1 || abi.length > 4096)
    throw new Error('Expected an ABI array');
  return text;
}
