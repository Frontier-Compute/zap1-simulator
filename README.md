# zap1-simulator

[![ci](https://github.com/Frontier-Compute/zap1-simulator/actions/workflows/ci.yml/badge.svg)](https://github.com/Frontier-Compute/zap1-simulator/actions/workflows/ci.yml)

Interactive ZAP1 lifecycle event simulator.

## What it does

Walk through all 9 ZAP1 event types in order:

1. `PROGRAM_ENTRY` - wallet registration
2. `OWNERSHIP_ATTEST` - operator attestation
3. `CONTRACT_ANCHOR` - hosting contract committed by hash
4. `DEPLOYMENT` - miner installed at facility
5. `HOSTING_PAYMENT` - monthly hosting invoice paid
6. `SHIELD_RENEWAL` - annual privacy shield renewed
7. `TRANSFER` - ownership moved to new wallet
8. `EXIT` - participant exit or hardware release
9. `MERKLE_ROOT` - lifecycle tree root anchored to Zcash

Each step computes a BLAKE2b-256 leaf hash (with `NordicShield_` personalization), then builds a Merkle tree client-side using `NordicShield_MRK` node personalization. The tree visualization updates live as you add leaves.

When all events are done, download a JSON proof bundle containing every leaf hash, the full Merkle tree layers, and the root.

## Hashing backend

Tries to load the `zap1-verify` WASM module at startup. Falls back to a pure JS BLAKE2b-256 implementation if WASM is unavailable. The UI shows which backend is active.

## Run locally

```
npm install
npm run dev
```

Vite dev server starts on `http://localhost:5173`. No backend needed - everything runs in the browser.

## Links

- [ZAP1 protocol spec](https://github.com/Frontier-Compute/zap1/blob/main/ONCHAIN_PROTOCOL.md)
- [zap1-verify crate](https://github.com/Frontier-Compute/zap1-verify)

## License

MIT
