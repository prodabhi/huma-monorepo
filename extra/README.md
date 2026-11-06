# Extra

The native macOS application and its supporting research/reference material live
here. Keeping these together separates application hosting in `frontend/` and
`backend/` from native packaging and archived experiments.

## Directory guide

| Location | Purpose |
| --- | --- |
| `Package.swift` | Swift package for the macOS app |
| `Sources/Huma/` | Native editor and application UI |
| `Sources/HumaCore/` | Documents, capture, proof and verification core |
| `Sources/HumaScriptHost/` | JavaScriptCore host for the proof engine |
| `Tests/HumaCoreTests/` | Swift unit and integration tests |
| `Resources/` | App metadata, entitlements and packaged assets |
| `docs/` | Product vision and protocol/performance references |
| `experiments/` | Noir, media and archived on-chain research |
| `media/` | Source media kept outside deployable packages |

## Common commands

Run these from the repository root:

```sh
swift build --package-path extra --jobs 2
swift test --package-path extra
```

Building the distributable `.app` also prepares backend proof resources and web
assets; use the end-to-end instructions in the root README for that workflow.
