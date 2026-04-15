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
python3 auditor.py <target> [<target> ...]
```

Target can be a hostname or an IP address. Multiple targets are scanned in sequence:
```bash
# Single target
python3 auditor.py example.com
python3 auditor.py 192.168.1.10

# Multiple targets
python3 auditor.py host1 host2 192.168.1.10

# Read targets from a file (one per line, # for comments)
python3 auditor.py -f hosts.txt

# Save results to CSV
python3 auditor.py example.com --csv report.csv
python3 auditor.py -f hosts.txt --csv report.csv

# Scan multiple targets in parallel
python3 auditor.py -f hosts.txt --parallel

# Run only specific check groups
python3 auditor.py example.com --only ssh
python3 auditor.py example.com --only tls http

# Adjust connection timeout (default: 5s)
python3 auditor.py example.com --timeout 10
python3 auditor.py -f hosts.txt --parallel --timeout 3
```

### Check groups (`--only`)

| Group | Checks included |
|---|---|
| `ports` | Port 22, 80, 443 |
| `ssh` | SSH algorithms, banner/version, root login, password auth |
| `tls` | TLS versions, certificate trust/expiry/hostname |
| `http` | HTTP → HTTPS redirect, HSTS header |

### hosts.txt format

```
# production servers
example.com
192.168.1.10

# test targets
scanme.nmap.org
```

## What it checks

| Check | How | Pass condition |
|---|---|---|
| Open ports | TCP connect to 22, 80, 443 | Port responds |
| SSH algorithms | Captures server KEXINIT via paramiko | No deprecated algorithms present |
| SSH banner / version | Reads `transport.remote_version` | OpenSSH ≥ 8.0 (or non-OpenSSH) |
| SSH root login | `auth_none("root")` probe via paramiko | Server rejects root outright |
| SSH password auth | `auth_password` probe with fake credentials | Server rejects password method |
| TLS versions | TLS handshake per version via `ssl` | 1.2/1.3 supported, 1.0/1.1 disabled |
| TLS certificate trust | Full chain verification against system CA bundle | Issued by a trusted CA |
| TLS certificate expiry | Parsed from `notAfter` field | Valid for > 90 days |
| TLS hostname match | SAN list (DNS + IP) checked against target | Certificate covers the target |
| HTTP → HTTPS redirect | GET / on port 80, check for 3xx to https:// | Redirects to HTTPS |
| HSTS header | HEAD / on port 443, parse `Strict-Transport-Security` | Present, max-age ≥ 180 days |

**SSH algorithm check** — connects to port 22 and reads the full list of algorithms the server advertises in its KEXINIT message (key exchange, ciphers, MACs). Each is marked `[PASS]` if modern or `[FAIL]` if deprecated (e.g. `arcfour`, `3des-cbc`, `hmac-md5`).

**SSH banner / version check** — reads the server's version string (sent in cleartext before authentication) and always displays it as `[INFO]`. For OpenSSH, the version number is parsed and flagged as `[FAIL]` if below 8.0. Note: Linux distros sometimes backport security patches without bumping the upstream version number — treat a low version as a prompt to verify, not a definitive verdict.

**Root login check** — sends a `none`-type auth request for user `root`. If the server responds with a list of accepted auth methods, root login is enabled (`[FAIL]`). If it rejects the request outright, root login is likely disabled (`[PASS]`).

> **Note:** This check can produce a false positive on servers that only accept public key authentication for root (e.g. GitHub). The server responds with `publickey` as an accepted method, which triggers `[FAIL]` — but without a valid key, root access is still not possible. The result should be interpreted in context.

**SSH password auth check** — sends an `auth_password` request with obviously fake credentials. If the server rejects the password method entirely (`BadAuthenticationType`), password authentication is disabled (`[PASS]`). If it rejects the credentials but accepts the method, password authentication is enabled (`[FAIL]`) and the server is susceptible to brute-force and credential stuffing attacks.

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

[SSH Banner]
  [INFO]  SSH server version — SSH-2.0-3992d52

[SSH Root Login]
  [FAIL]  Root login — enabled — server offered auth methods: publickey

[SSH Password Auth]
  [PASS]  Password authentication — disabled — server does not accept password authentication

[TLS Version Support]
  [PASS]  TLS 1.0 — not supported by server (correctly disabled)
  [PASS]  TLS 1.1 — not supported by server (correctly disabled)
  [PASS]  TLS 1.2 — supported
  [PASS]  TLS 1.3 — supported

[TLS Certificate]
  [PASS]  Certificate trust — issued by Sectigo Limited
  [INFO]  Certificate expiry — expires in 49 day(s) (2026-06-03) — renewal recommended soon
  [PASS]  Hostname match — certificate covers github.com

[HTTP Security]
  [PASS]  HTTP → HTTPS redirect — HTTP 301 → https://github.com/
  [PASS]  HSTS header — max-age=365 days, includeSubDomains

╔══════════════════════════════════════╗
  Summary — 33 checks
  [PASS] 32   [FAIL] 1
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
| SSH banner | INFO — custom banner | FAIL — OpenSSH 6.6.1 (< 8.0) |
| SSH root login | FAIL — publickey¹ | FAIL — publickey + password |
| SSH password auth | PASS — disabled | FAIL — enabled |
| TLS 1.0 | PASS — disabled | INFO — port 443 closed |
| TLS 1.1 | PASS — disabled | INFO — port 443 closed |
| TLS 1.2 | PASS — supported | INFO — port 443 closed |
| TLS 1.3 | PASS — supported | INFO — port 443 closed |
| Certificate trust | PASS — Sectigo Limited | INFO — port 443 closed |
| Certificate expiry | INFO — expires soon | INFO — port 443 closed |
| Hostname match | PASS | INFO — port 443 closed |
| HTTP → HTTPS redirect | PASS — 301 | FAIL — no redirect (HTTP 200) |
| HSTS header | PASS — 365 days | INFO — port 443 closed |
| **Total FAIL** | **1** | **15+** |

¹ See root login note above — github.com requires a valid key, so this is a false positive in practice.

`scanme.nmap.org` is a server maintained by the Nmap project for testing purposes and is intentionally poorly configured, making it a useful target to verify that the tool correctly identifies weak settings.

### Multi-host summary

When scanning more than one target a summary table is printed after all audits:

```
╔══════════════════════════════════════════╗
  Multi-host summary
  Host                      PASS    FAIL   Total
  ────────────────────────────────────────
  github.com                  26       1      27
  scanme.nmap.org             29      18      47
╚══════════════════════════════════════════╝
```

### CSV export

Use `--csv <file>` to save all results to a CSV file. Each row is one check:

```
host,category,check,result,detail
github.com,Port Check,Port 22 (SSH),PASS,open
github.com,SSH Algorithms,curve25519-sha256,PASS,
github.com,SSH Root Login,Root login,FAIL,enabled — server offered auth methods: publickey
...
```

Useful for importing into spreadsheets or filtering with tools like `grep`, `awk`, or pandas.

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
