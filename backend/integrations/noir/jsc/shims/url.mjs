// node:url fileURLToPath for the worker's own location.
export function fileURLToPath(url) {
  const text = String(url);
  if (!text.startsWith('file://')) throw new TypeError('Not a file URL.');
  return decodeURIComponent(text.slice('file://'.length));
}
