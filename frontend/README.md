# Frontend

Huma's browser application and Node HTTP entry point live here. Run frontend
commands from the repository root with `npm --prefix frontend ...`; local server
configuration belongs in the root `.env.local` file.

## Entry points

| Location | Purpose |
| --- | --- |
| `registry.mjs` | Local and hosted HTTP server (`npm start`) |
| `pages/` | Landing, writer, download and verification pages |
| `write/` | In-browser capture and proof generation |
| `verify-core/` | DOM-free verification shared by browser and Node |
| `share/` | React approval and sharing application |
| `deck/` | React research deck |
| `test/` | Node integration and regression tests |

## Common commands

```sh
npm ci --prefix frontend
npm test --prefix frontend
npm run build --prefix frontend
npm run typecheck --prefix frontend
npm run start:configured --prefix frontend
```

The configured start command reads `../.env.local` from this directory and
serves `http://127.0.0.1:4318` by default. Generated assets are written to
`frontend/dist/` and should be rebuilt from their source directories.
