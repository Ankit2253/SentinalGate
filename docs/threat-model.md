# Threat model

## Assets

- Availability of the firewall host and its management path.
- Integrity of the active ruleset.
- Confidentiality of the API bearer token.
- Integrity and availability of audit events and snapshots.
- Availability of protected hosts behind the forwarding chain.

## Relevant threats and controls

| Threat | Control | Residual limitation |
|---|---|---|
| Command injection through a rule | Strict typed validation; argument-array subprocess calls; no raw nft syntax input | A defect in the renderer or nft itself remains possible |
| Remote API misuse | Loopback binding by default; mandatory token for non-loopback binding; constant-time comparison | Bearer tokens do not provide user-level authorization or rotation workflows |
| Administrator lockout | Loopback and management rules precede custom rules; explicit confirmation; VM-console guidance | A wrong management CIDR can still cause lockout |
| Partial policy deployment | Syntax check and one nftables transaction | Kernel/resource failure can still reject the transaction |
| Log flooding | Rate-limited kernel logging | Traffic is still evaluated; disk retention is left to journald policy |
| Port scanning | Time-window and unique-port detection; temporary nft set | Distributed or slow scans can evade the threshold |
| Forged log content | Only `SG_*` lines are parsed, fields are validated by `Event` | A local privileged attacker can forge kernel-like records or alter the database |
| Compromised dashboard browser | CSP and no third-party assets; token kept in session storage | Host compromise defeats browser-side protections |
| Database tampering | Parameterized SQL and restrictive deployment permissions | Events are not cryptographically signed or shipped off-host |

## Out of scope for version 1.0

- Deep-packet inspection or TLS interception.
- Layer-7 application identification.
- Distributed blocklist synchronization.
- Multi-user roles, SSO, or policy approvals.
- High-availability clustering.
- Cryptographically immutable logs.
- Independent production security certification.

