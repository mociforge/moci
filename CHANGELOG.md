# Changelog

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
