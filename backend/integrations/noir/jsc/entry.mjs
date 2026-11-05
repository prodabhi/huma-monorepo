// The engine's worker for macOS's built-in JavaScript engine: set up globals, then run the same worker.mjs Node runs.
// Witnesses are built by the native witness tool, so the engine carries no WebAssembly.
import './prelude.mjs';
await import('./worker.mjs');
