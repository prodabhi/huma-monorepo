import { mkdirSync, openSync, closeSync, readFileSync, writeFileSync, renameSync, unlinkSync, fsyncSync } from 'node:fs';
import path from 'node:path';

// One writer per directory; every state transition is durable before responding.
// Do not share this local store between hosts. Use transactional storage for deployment.
export class EvidenceStore {
    constructor(directory) {
        mkdirSync(directory, { recursive: true, mode: 0o700 });
        this.directory = directory;
        this.lock = path.join(directory, 'service.lock');
        this.lockFD = openSync(this.lock, 'wx', 0o600);
        writeFileSync(this.lockFD, String(process.pid));
        this.file = path.join(directory, 'state.json');
        try {
            try { this.state = JSON.parse(readFileSync(this.file)); }
            catch (error) { if (error.code !== 'ENOENT') throw error; this.state = { version: 1, keys: {}, challenges: {}, results: {} }; }
            if (this.state.version !== 1 || !this.state.keys || !this.state.challenges || !this.state.results) throw new Error('Invalid evidence store.');
        } catch (error) { this.close(); throw error; }
        this.queue = Promise.resolve();
    }
    save() {
        if (this.failed) throw new Error("Evidence store is unavailable after a failed write.");
        try {
            const temporary = this.file + '.tmp';
            const fd = openSync(temporary, 'w', 0o600);
            try { writeFileSync(fd, JSON.stringify(this.state)); fsyncSync(fd); } finally { closeSync(fd); }
            renameSync(temporary, this.file);
            const directoryFD = openSync(this.directory, 'r');
            try { fsyncSync(directoryFD); } finally { closeSync(directoryFD); }
        } catch (error) { this.failed = true; throw error; }
    }
    exclusive(fn) {
        const result = this.queue.then(() => {
            if (this.failed) throw new Error("Evidence store is unavailable after a failed write.");
            return fn();
        });
        this.queue = result.catch(() => {});
        return result;
    }
    close() { if (this.lockFD !== undefined) { closeSync(this.lockFD); this.lockFD = undefined; unlinkSync(this.lock); } }
}
