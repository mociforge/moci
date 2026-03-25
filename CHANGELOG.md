# Changelog

## 0.2.0 — Security Hardening

### Supply chain
- Vendored @noble/hashes keccak_256 and bytesToHex into project source
- @noble/hashes moved from dependencies to devDependencies
- Eliminated runtime npm supply chain dependency for cryptographic functions

### Crypto integrity
- Startup self-test: keccak256 output verified against known test vectors on every launch
- If test fails: CRYPTO_SELF_TEST_FAILED error, system refuses to start

### Device fingerprint
- Device fingerprint now includes hardware-bound machine ID:
  - Linux: /etc/machine-id
  - macOS: IOPlatformSerialNumber
  - Windows: Registry MachineGuid
- Backward compatible: v0.1.0 identities auto-detected, migration available via `moci migrate-fingerprint`
- Fallback to hostname-only fingerprint if hardware ID unavailable

## 0.1.0 (first release)

- MOCI identity generation (Crockford Base32, 6-char suffix, CRC-8)
- Memory ring system (4 rings, 32KB budget, daily promotion)
- 12 memory chain security mechanisms
- Dual-factor verification (key + memory chain)
- MOCI Identity Token (CIT) with per-skill HMAC signing
- Identity lifecycle (suspend / revoke / delete)
- Encrypted export / import with HMAC re-signing
- Structured audit log with tamper detection
- Trust score computation
- Full CLI tool
