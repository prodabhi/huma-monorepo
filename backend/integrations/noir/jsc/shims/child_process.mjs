// node:child_process spawn, as the engine uses it: start once stdin is ended, then one 'data' and one 'close'.
import { Buffer } from 'buffer';
import { copy } from '../prelude.mjs';
const host = globalThis.__host;
class Emitter {
  constructor() { this.handlers = {}; }
  on(name, handler) { (this.handlers[name] ??= []).push(handler); return this; }
  once(name, handler) { const wrapped = (...args) => { this.off(name, wrapped); handler(...args); }; return this.on(name, wrapped); }
  off(name, handler) { this.handlers[name] = (this.handlers[name] ?? []).filter(h => h !== handler); return this; }
  emit(name, ...args) { for (const handler of [...(this.handlers[name] ?? [])]) handler(...args); }
}
export function spawn(executable, args = [], options = {}) {
  const child = new Emitter();
  child.stdout = new Emitter(); child.stderr = new Emitter();
  let started = false;
  child.kill = () => true; // output is collected whole; the caller's size check still rejects it
  child.stdin = Object.assign(new Emitter(), { end(input = Buffer.alloc(0)) {
    if (started) return; started = true;
    host.spawn(String(executable), args.map(String), options.env ?? process.env, copy(input), (failed, code, signal, output) => {
      if (failed) { child.emit('error', new Error('spawn failed')); return; }
      if (output.length) child.stdout.emit('data', Buffer.from(output));
      child.emit('close', signal ? null : code, signal || null);
    });
  } });
  return child;
}
