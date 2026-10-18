# @qmoosa/crosschain-tests

QMOOSA Cross-Chain Tests — Multi-Repo Reality Gates, Dual-Chain Invariant Verification & Adversarial Suite.

## Reality Gates
1. **Gate 1 (Archive Integrity):** Verifies SHA-256 hashes of pinned protocol, engine, and sdk tarballs.
2. **Gate 2 (Source Provenance):** Verifies git commit ancestry and HEAD alignment against pinned manifests.
3. **Gate 3 (Canonical Rebuild):** Hermetically rebuilds sibling packages from source and verifies byte-for-byte canonical equality against pinned archives.

## Test Suites
- `npm run test:integration`: Dual-chain atomic swap and mutual claim end-to-end integration flow.
- `npm run test:negative`: 9-point adversarial attack and invalid parameter suite.

## License
MIT
