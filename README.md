# SSH/TLS Auditor

A command-line security audit tool that checks a target server for common SSH and TLS misconfigurations. All checks are implemented in pure Python — no external CLI tools required.

## Prerequisites

- Python 3.7 or later
- pip

Check your Python version:
```bash
python3 --version
```

## Installation

Clone the repository and navigate to the tool directory:
```bash
git clone https://github.com/elin-olsson/ssh-tls-auditor.git
cd ssh-tls-auditor
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 auditor.py <target>
```

Target can be a hostname or an IP address:
```bash
python3 auditor.py 192.168.1.10
python3 auditor.py example.com
```

## What it checks

| Check | How | Pass condition |
|---|---|---|
| Open ports | TCP connect to 22, 80, 443 | Port responds |
| SSH algorithms | Captures server KEXINIT via paramiko | No deprecated algorithms present |
| SSH root login | `auth_none("root")` probe via paramiko | Server rejects root outright |
| TLS versions | TLS handshake per version via `ssl` | 1.2/1.3 supported, 1.0/1.1 disabled |

**SSH algorithm check** — connects to port 22 and reads the full list of algorithms the server advertises in its KEXINIT message (key exchange, ciphers, MACs). Each is marked `[PASS]` if modern or `[FAIL]` if deprecated (e.g. `arcfour`, `3des-cbc`, `hmac-md5`).

**Root login check** — sends a `none`-type auth request for user `root`. If the server responds with a list of accepted auth methods, root login is enabled (`[FAIL]`). If it rejects the request outright, root login is likely disabled (`[PASS]`).

> **Note:** This check can produce a false positive on servers that only accept public key authentication for root (e.g. GitHub). The server responds with `publickey` as an accepted method, which triggers `[FAIL]` — but without a valid key, root access is still not possible. The result should be interpreted in context.

**TLS version check** — attempts a handshake using each TLS version in isolation. TLS 1.2 and 1.3 connecting is a `[PASS]`. TLS 1.0 or 1.1 connecting is a `[FAIL]` — deprecated per RFC 8996 and should be disabled on any server.

## Example output

Running against github.com:

```
╔══════════════════════════════════════╗
  SSH/TLS Auditor — target: github.com
╚══════════════════════════════════════╝

[Port Check]
  [PASS]  Port 22 (SSH) — open
  [PASS]  Port 80 (HTTP) — open
  [PASS]  Port 443 (HTTPS) — open

[SSH Algorithms]
  Key exchange:
  [PASS]  curve25519-sha256
  [PASS]  curve25519-sha256@libssh.org
  [PASS]  diffie-hellman-group-exchange-sha256
  Ciphers:
  [PASS]  chacha20-poly1305@openssh.com
  [PASS]  aes256-gcm@openssh.com
  [PASS]  aes128-gcm@openssh.com
  MACs:
  [PASS]  hmac-sha2-512-etm@openssh.com
  [PASS]  hmac-sha2-256-etm@openssh.com

[SSH Root Login]
  [FAIL]  Root login — enabled — server offered auth methods: publickey

[TLS Version Support]
  [PASS]  TLS 1.0 — not supported by server (correctly disabled)
  [PASS]  TLS 1.1 — not supported by server (correctly disabled)
  [PASS]  TLS 1.2 — supported
  [PASS]  TLS 1.3 — supported

╔══════════════════════════════════════╗
  Summary — 27 checks
  [PASS] 26   [FAIL] 1
  1 issue(s) require attention.
╚══════════════════════════════════════╝
```

## Target comparison

Results from two real targets — a well-hardened server and a deliberately misconfigured one:

| Check | github.com | scanme.nmap.org |
|---|---|---|
| Port 22 (SSH) | PASS | PASS |
| Port 80 (HTTP) | PASS | PASS |
| Port 443 (HTTPS) | PASS | FAIL — closed |
| SSH key exchange | All PASS | 2 FAIL (group14-sha1, group1-sha1) |
| SSH ciphers | All PASS | 8 FAIL (arcfour, 3des-cbc, blowfish, etc.) |
| SSH MACs | All PASS | 4 FAIL (hmac-md5, hmac-sha1, etc.) |
| SSH root login | FAIL — publickey¹ | FAIL — publickey + password |
| TLS 1.0 | PASS — disabled | INFO — port 443 closed |
| TLS 1.1 | PASS — disabled | INFO — port 443 closed |
| TLS 1.2 | PASS — supported | INFO — port 443 closed |
| TLS 1.3 | PASS — supported | INFO — port 443 closed |
| **Total FAIL** | **1** | **18** |

¹ See root login note above — github.com requires a valid key, so this is a false positive in practice.

`scanme.nmap.org` is a server maintained by the Nmap project for testing purposes and is intentionally poorly configured, making it a useful target to verify that the tool correctly identifies weak settings.

## Output legend

| Result | Meaning |
|---|---|
| `[PASS]` | Check passed — no issue found |
| `[FAIL]` | Check failed — misconfiguration or weak setting detected |
| `[INFO]` | Informational — could not determine or version not supported |

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `paramiko` | >= 4.0.0 | SSH connection and algorithm enumeration |
| `ssl` | stdlib | TLS handshake testing |
| `socket` | stdlib | Port connectivity checks |
