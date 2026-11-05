// node:fs/promises, as much as the engine uses, over the native host.
import { Buffer } from 'buffer';
import { copy } from '../prelude.mjs';
const host = globalThis.__host;
const call = run => new Promise((resolve, reject) => { try { resolve(run()); } catch (error) { reject(error); } });
const stats = info => ({ size: info.size, uid: info.uid, mode: info.mode,
  isFile: () => info.type === 'file', isDirectory: () => info.type === 'directory', isSymbolicLink: () => info.type === 'link' });
export const readFile = (path, options) => call(() => {
  const bytes = Buffer.from(host.readFile(String(path)));
  const encoding = typeof options === 'string' ? options : options?.encoding;
  return encoding ? bytes.toString(encoding) : bytes;
});
export const writeFile = (path, data, options = {}) => call(() => {
  if (options.flag && !['w', 'wx'].includes(options.flag)) throw new Error('Unsupported write flag.');
  host.writeFile(String(path), copy(typeof data === 'string' ? Buffer.from(data, 'utf8') : data), options.flag === 'wx', options.mode ?? 0o666);
});
export const lstat = path => call(() => stats(host.lstat(String(path))));
export const readdir = path => call(() => host.readdir(String(path)));
export const mkdir = (path, options = {}) => call(() => host.mkdir(String(path), Boolean(options.recursive), options.mode ?? 0o777));
export const symlink = (target, path) => call(() => host.symlink(String(target), String(path)));
export const readlink = path => call(() => host.readlink(String(path)));
export const unlink = path => call(() => host.unlink(String(path)));
