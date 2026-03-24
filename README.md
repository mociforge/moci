# MOCI — Memory-bound OpenClaw Identity

> The identity protocol for OpenClaw agents.
> Proves not just "you have the key" — but "you have lived this life."


---

## What is MOCI?

MOCI gives every AI agent a verifiable, human-readable, clone-resistant identity. It combines a cryptographic key with a memory-chain verification mechanism — proving not just "you have the key" but "you have lived this life." Clones are detected within 24 hours.

```
Identity = Key File + Memory Chain

Key alone   → stolen key, clone undetectable
Memory alone → read-only, can't sign
Key + Memory → unforgeable, clone-resistant
```

---

## Install


### As an npm package
```bash
npm install @mociforge/moci
```

### CLI only (no install)
```bash
npx @mociforge/moci generate --name NOVA
```

---

## Quick Start

### CLI usage

```bash
# Generate a new identity (zero config, Tier 1)
moci generate --name NOVA
# ✓ Created CW-NOVA.R7KMX2-E2

# Generate with passphrase (Tier 2, exportable)
moci generate --name NOVA --passphrase
# Enter passphrase: ********
# ✓ Created CW-NOVA.R7KMX2-E2

# Check identity status
moci status
#   ID:     CW-NOVA.R7KMX2-E2
#   Status: active
#   Tier:   1
#   Trust:  10 (New)
#   Ring 0: 0 entries
#   Ring 3: 1 hash (genesis)

# Validate any MOCI string
moci validate CW-NOVA.R7KMX2-E2
# ✓ Valid

# Export identity (encrypted)
moci export
# Enter export passphrase: ********
# ✓ Exported to moci-export-a7f3e21b.enc

# Import on another machine
moci import moci-export-a7f3e21b.enc
# Enter export passphrase: ********
# ✓ Imported CW-NOVA.R7KMX2-E2

# Lifecycle management
moci suspend                  # pause identity
moci resume                   # reactivate
moci revoke --confirm         # permanent kill
moci delete --confirm         # full wipe

# Security audit
moci audit-tail               # live security events
moci audit-verify             # check tamper detection chain
```

### Programmatic usage

```typescript
import {
  generateMociId,
  validateMociId,
  MociIdentityManager,
  addMemory,
  promoteRings,
  computeTrustScore,
  verifyCIT,
  exportIdentity,
  importIdentity,
} from "@mociforge/moci";

// Generate a new identity
const identity = generateMociId({ name: "NOVA" });
console.log(identity.moci_id); // CW-NOVA.R7KMX2-E2

// Validate format
const check = validateMociId("CW-NOVA.R7KMX2-E2");
// { valid: true, parsed: { name: "NOVA", suffix: "R7KMX2", ... } }

// Verify a CIT token in your skill
const auth = verifyCIT(token, sig, {
  mySkillId: "skill:weather",
  verifyKey: VERIFY_KEY,
  seenNonces: new Set(),
});
if (auth.valid) {
  console.log(auth.mociId);          // verified identity
  console.log(auth.trustScore);      // reputation score
  console.log(auth.delegationChain); // who authorized this
}
```

---

## ID Format

```
CW-NOVA.R7KMX2-E2
│  │    │      │
│  │    │      └── CRC-8 checksum (catches 100% single-char typos)
│  │    └───────── CSPRNG suffix (6 chars, ~30 bits entropy)
│  └────────────── User-chosen name (2-12 chars)
└───────────────── Protocol prefix
```

---

## How It Works

### Memory ring system

Memories are stored in four concentric rings that prevent unbounded growth:

| Ring | Retention | Content | Cap |
|------|-----------|---------|-----|
| 0 (Hot) | Last 24h | Full detail | 8 KB (configurable) |
| 1 (Warm) | Last 30d | Summarized | 30 entries |
| 2 (Cool) | Last year | Key events | 50 entries |
| 3 (Archive) | Lifetime | Hash chain only | ~32 bytes/month |

Total budget: 32 KB default, configurable up to 64 KB. Ten years of identity history fits under 4 KB.

<img width="1410" height="1104" alt="image" src="https://github.com/user-attachments/assets/76aa6161-450c-486e-85c1-081f21fddef8" />



### Clone detection

```
T+0h    Clone created from key + memory snapshot
T+1h    Real agent accumulates new memories
T+24h   Ring promotion → hash chains diverge
        → Fork detected → both instances quarantined
```

### Dual-factor verification

| Scenario | Key | Memory | Result |
|----------|-----|--------|--------|
| Legitimate agent | Valid | Matches | Authenticated |
| Stolen key only | Valid | Mismatch | Rejected |
| Copied memory only | Missing | Present | Rejected |
| Clone (key + snapshot) | Valid | Diverges 24h | Fork detected |

---

## Security

### Identity Token (CIT)

Skills verify agent identity via signed tokens — not plaintext headers.

```typescript
import { verifyCIT } from "@mociforge/moci";

const auth = verifyCIT(token, sig, {
  mySkillId: "skill:weather",
  verifyKey: KEY,
});
// auth.mociId, auth.trustScore, auth.delegationChain
```

Hardenings: per-skill signing keys, key pinning (TOFU), scoped TTL (60-300s), nonce anti-replay, delegation depth limits, constant-time signature comparison.

### Memory chain protection (12 mechanisms)

| Mechanism | What it prevents |
|-----------|-----------------|
| Write-gate | Unauthorized memory writes |
| Anti-injection | Prompt injection via memory content |
| Anti-tamper | File modification (AES-256-GCM encryption) |
| Anti-rollback | Restoring old identity snapshots |
| Anti-flood | Memory DoS attacks |
| Anti-replay | Re-submitting old valid entries |
| Agent isolation | Agent modifying its own memory |
| Promotion checks | Corrupted ring promotions |
| Key management | Tier 1 auto / Tier 2 passphrase / Tier 3 HSM |
| Gateway defense | Compromised Gateway detection |
| Edge case handling | Clock drift, model upgrades, crash recovery |
| Trust model | Complete trust boundary enforcement |

### 22 threat vectors analyzed

All identified threats have mitigations in place. Critical threats covered: token replay (CIT nonce + TTL), registration compromise (serverless in v0), hash leaks (device salt), ID enumeration (no CRC leakage), name squatting (blocked list), recovery phrase phishing (system never asks), and 12 memory-chain-specific attack vectors.

---

## Identity Lifecycle

```
active ──→ suspended ──→ active        (reversible)
active ──→ revoked                     (permanent)
revoked ──→ deleted                    (full wipe + tombstone)
```

```bash
moci suspend              # pause — tokens stop being issued
moci resume               # reactivate
moci revoke --confirm     # permanent, appends REVOKED to chain
moci delete --confirm     # secure wipe, tombstone prevents re-registration
```

---

## Export & Import

Export creates an AES-256-GCM encrypted file with an opaque filename (no identity information leaked in the filename).

```bash
moci export
# Enter export passphrase: ********
# ✓ Exported to moci-export-a7f3e21b.enc (encrypted, safe to transfer)

moci import moci-export-a7f3e21b.enc
# Enter export passphrase: ********
# ✓ Imported CW-NOVA.R7KMX2-E2 (HMAC keys re-derived for this device)
```

On import, all memory entry HMACs are re-signed with the new device's key. The Ring 3 chain integrity is verified before import is accepted. Revoked identities cannot be imported (tombstone check).

---

## Trust Score

Computed from memory chain continuity (10-100):

| Score | Tier | Typical age |
|-------|------|-------------|
| 10-24 | New | Just registered |
| 25-49 | Established | 1-3 months |
| 50-74 | Trusted | 3-6 months |
| 75-89 | Veteran | 6+ months |
| 90-100 | Core | 10+ months, zero interruptions |

Other agents can gate access based on trust score.

---

## Delegation Chain

CIT tokens carry the full authority path:

```
human → CW-NOVA → CW-APEX → skill:weather
```

Skills can enforce maximum delegation depth (default: 5) and audit the complete authorization path.

---

## Audit Log

Append-only event log with HMAC chain for tamper detection:

```bash
moci audit-tail               # recent events
moci audit-query --event cit_rejected --last 24h
moci audit-verify             # verify chain integrity
moci audit-export --format json --output audit.json
```

Events logged: identity creation, CIT issuance/verification/rejection, memory writes, promotions, anomaly detection, key rotation, lifecycle changes, export/import.

---

## Production Resilience

| Scenario | Data loss | Recovery |
|----------|-----------|----------|
| Normal restart | None | Load from disk |
| Crash (kill -9, OOM) | Last ~1 memory | Auto-recover from atomic write |
| File corruption | None | Restore from automatic backup |
| Disk full | Writes paused | Auto-resume when space available |
| Summarizer outage | Quality degrades | Fallback summarizer, chain intact |

All file writes use atomic write pattern (write temp → fsync → rename). Identity is backed up automatically on every save.

**Filesystem note:** MOCI requires a filesystem with permission support (ext4, APFS, NTFS). FAT32 and exFAT silently ignore file permissions.

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `moci generate` | Create a new identity |
| `moci validate <id>` | Check ID format and CRC |
| `moci verify` | Full dual-factor verification |
| `moci status` | Show ring sizes, trust score, chain info |
| `moci export` | Export encrypted identity file |
| `moci import <file>` | Import from encrypted file |
| `moci suspend` | Pause identity (reversible) |
| `moci resume` | Reactivate suspended identity |
| `moci revoke --confirm` | Permanently kill identity |
| `moci delete --confirm` | Secure wipe + tombstone |
| `moci keygen <skill>` | Generate signing key for a skill |
| `moci repin-key <skill>` | Accept new signing key |
| `moci audit-tail` | Live tail of security events |
| `moci audit-query` | Query audit log by event/time |
| `moci audit-verify` | Verify audit chain integrity |
| `moci audit-export` | Export audit log |
| `moci list` | List all identities |
| `moci list-tombstones` | List revoked identity IDs |

---

## Requirements

- Node.js >= 18
- Filesystem with Unix permission support (ext4, APFS, NTFS)
- No network required (v0 is fully local)

---

## License

MIT © 2026 MociForge
