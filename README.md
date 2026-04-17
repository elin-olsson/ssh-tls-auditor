![SSH/TLS Auditor](github-banner.png)

A command-line security audit tool that checks a target server for common SSH and TLS misconfigurations. Implemented in Python with no external CLI tools required.

## Prerequisites

- Python 3.10 or later
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

# Save results to HTML report
python3 auditor.py example.com --html report.html

# Save results to JSON
python3 auditor.py example.com --json report.json

# Save results to a Markdown report
python3 auditor.py example.com --markdown report.md

# Compare two JSON reports and write a Markdown diff
python3 auditor.py --compare before.json after.json diff.md

# Scan multiple targets in parallel
python3 auditor.py -f hosts.txt --parallel

# Run only specific check groups
python3 auditor.py example.com --only ssh
python3 auditor.py example.com --only tls http

# Adjust connection timeout (default: 5s)
python3 auditor.py example.com --timeout 10
python3 auditor.py -f hosts.txt --parallel --timeout 3

# Scan a network range (CIDR notation)
python3 auditor.py 192.168.1.0/24 --parallel --only ssh
python3 auditor.py 10.0.0.0/28 --parallel --timeout 3

# Only print failed checks (useful in CI/CD)
python3 auditor.py example.com --quiet

# Generate ready-to-paste config fixes for all failures
python3 auditor.py example.com --config

# Continuous monitoring — re-scan every 60 seconds, show only changes
python3 auditor.py example.com --watch 60

# Print a Markdown badge for each target
python3 auditor.py example.com --badge
```

### Check groups (`--only`)

| Group | Checks included |
|---|---|
| `ports` | Port 22, 80, 443 |
| `ssh` | SSH algorithms, banner/version, host key type, root login, password auth, legacy detection |
| `tls` | TLS versions, cipher suites, certificate trust/expiry/hostname/signature/key size |
| `http` | HTTP → HTTPS redirect, HSTS (incl. preload), X-Frame-Options, X-Content-Type-Options, CSP |
| `smtp` | STARTTLS support, weak SMTP ciphers, SMTP certificate validity |
| `ftp` | FTP AUTH TLS support |
| `rdp` | RDP NLA (Network Level Authentication) |

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
| SSH banner / version | Reads `transport.remote_version` | OpenSSH ≥ 8.0; no OS/distro info disclosed |
| SSH host key type | Reads host key via paramiko | ED25519 / ECDSA / RSA ≥ 3072-bit |
| SSH root login | `auth_none("root")` probe via paramiko | Server does not offer password auth for root |
| SSH password auth | `auth_password` probe with fake credentials | Server rejects password method |
| SSH legacy detection | Banner + algorithm fingerprint against device DB | No known legacy device fingerprint |
| CAA records | DNS lookup via `dnspython` | At least one CAA record present |
| DNSSEC | DNSKEY lookup via `dnspython` | DNSKEY records present |
| TLS versions | TLS handshake per version via `ssl` | 1.2/1.3 supported, 1.0/1.1 disabled |
| TLS cipher suites | Handshake with weak-only context | NULL, aNULL, EXPORT, RC4, 3DES, DES, RC2, IDEA all rejected |
| TLS certificate trust | Full chain verification against system CA bundle | Issued by a trusted CA |
| TLS certificate expiry | Parsed from `notAfter` field | Valid for > 90 days |
| TLS hostname match | SAN list (DNS + IP) checked against target | Certificate covers the target |
| TLS cert signature algorithm | DER OID scan of raw certificate | SHA-256 or better (SHA-1 / MD5 = CRITICAL) |
| TLS cert RSA key size | DER modulus length parsed from raw certificate | RSA ≥ 2048-bit (or non-RSA key) |
| HTTP → HTTPS redirect | GET / on port 80, check for 3xx to https:// | Redirects to HTTPS |
| HSTS header | HEAD / on port 443, parse `Strict-Transport-Security` | Present, max-age ≥ 180 days, on preload list |
| X-Frame-Options | HEAD / on port 443 | `DENY` or `SAMEORIGIN` |
| X-Content-Type-Options | HEAD / on port 443 | `nosniff` |
| Content-Security-Policy | HEAD / on port 443 | Present |
| SMTP STARTTLS | EHLO + STARTTLS probe on port 25/587 | STARTTLS advertised and completes successfully |
| SMTP cipher suites | TLS handshake with weak-only context over STARTTLS | Same weak groups as TLS check |
| SMTP certificate | Chain verification + expiry after STARTTLS | Trusted and not expiring |
| FTP AUTH TLS | Connect port 21, send AUTH TLS | Server accepts AUTH TLS |
| RDP NLA | X.224 Connection Request PDU to port 3389 | Server requires Network Level Authentication |

**SSH algorithm check** — connects to port 22 and reads the full list of algorithms the server advertises in its KEXINIT message (key exchange, ciphers, MACs). Each is marked `[PASS]` if modern or `[FAIL]` if deprecated (e.g. `arcfour`, `3des-cbc`, `hmac-md5`).

**SSH banner / version check** — reads the server's version string (sent in cleartext before authentication) and always displays it as `[INFO]`. For OpenSSH, the version number is parsed and flagged as `[FAIL]` if below 8.0. If the banner contains a distro-specific suffix that reveals the OS or package version (e.g. `OpenSSH_9.2p1 Debian-2+deb12u9`), this is flagged as `[WARN]` — it gives an attacker a precise target for known CVEs. Note: Linux distros sometimes backport security patches without bumping the upstream version number — treat a low version as a prompt to verify, not a definitive verdict.

**Root login check** — sends a `none`-type auth request for user `root`. If the server responds with a list of accepted auth methods, root login is enabled (`[FAIL]`). If it rejects the request outright, root login is likely disabled (`[PASS]`).

> **Note:** This check can produce a false positive on servers that only accept public key authentication for root (e.g. GitHub). The server responds with `publickey` as an accepted method, which triggers `[FAIL]` — but without a valid key, root access is still not possible. The result should be interpreted in context.

**SSH host key check** — reads the server's host key type and size. ED25519 and ECDSA keys are always `[PASS]`. RSA keys are checked against the NIST-recommended minimum of 3072 bits — smaller keys are `[FAIL]`. DSA keys are always `[FAIL]` (fixed 1024-bit, deprecated since OpenSSH 7.0).

**SSH password auth check** — sends an `auth_password` request with obviously fake credentials. If the server rejects the password method entirely (`BadAuthenticationType`), password authentication is disabled (`[PASS]`). If it rejects the credentials but accepts the method, password authentication is enabled (`[FAIL]`) and the server is susceptible to brute-force and credential stuffing attacks.

**SSH legacy detection** — fingerprints the server using a combination of its SSH banner string and the algorithm set advertised in KEXINIT. Matches against a built-in database of known device types:

| Device | Match method |
|---|---|
| Dropbear SSH | Banner: `dropbear` |
| Cisco IOS / IOS-XE | Banner: `cisco` + legacy KEX |
| Fortinet FortiGate | Banner: `FGSSH` / `fortissh` |
| Juniper JunOS | Banner: `jnpr` / `junos` |
| HP iLO 2 / iLO 3 (and similar BMCs) | Algorithm fingerprint: SHA-1 KEX only + CBC ciphers + no ECDH/curve25519 |
| Generic legacy embedded firmware | Algorithm fingerprint: group1-sha1 only, nothing modern |

A matched device is reported as `[INFO]` with a remediation note. If the device advertises **only** deprecated key exchange algorithms with no modern alternative, this is reported as `[FAIL]` — the session cannot be made secure regardless of client configuration.

**TLS version check** — attempts a TLS handshake for each version in isolation by forcing both the minimum and maximum version on a fresh SSL context. This ensures only that specific version is negotiated, not the highest mutually supported one. TLS 1.2 and 1.3 are `[PASS]`. TLS 1.0 and 1.1 are `[FAIL]` — deprecated per RFC 8996 and disabled by default in modern browsers and libraries. If a version is not supported by the local Python/OpenSSL build (e.g. TLS 1.0 on hardened systems), the check is reported as `[INFO]`.

**CAA record check** — performs a DNS CAA lookup for the target domain. A CAA record lists which certificate authorities are permitted to issue certificates for the domain — any CA not listed should refuse to issue. Missing CAA records are `[FAIL]`. Skipped for IP address targets.

**TLS cipher suite check** — for each known weak cipher group (NULL, aNULL, EXPORT, RC4, 3DES, DES, RC2, IDEA), a fresh TLS 1.2 context is created that allows *only* that group. If the server completes the handshake it is `[FAIL]` — the weak cipher is accepted. If it refuses, `[PASS]`. Groups not available in the local OpenSSL build are silently skipped. The check is limited to TLS 1.2 because TLS 1.3 cipher selection cannot be controlled via `set_ciphers()` and does not support any of the listed weak groups anyway.

**TLS certificate check** — retrieves the certificate from port 443 and verifies three things:

- **Trust** — the full certificate chain is verified against the system CA bundle (same as what a browser uses). A self-signed or untrusted certificate is `[FAIL]`.
- **Expiry** — the `notAfter` field is parsed and compared to today. Expired or expiring within 30 days is `[FAIL]`. Expiring within 90 days is `[INFO]` — a prompt to plan renewal. Valid beyond 90 days is `[PASS]`.
- **Hostname match** — the certificate's Subject Alternative Names (SANs) are checked against the target. Both DNS names (with wildcard support) and IP addresses are handled. A mismatch is `[FAIL]`.

**HTTP security check** — five checks covering the basics of secure HTTP configuration:

- **HTTP → HTTPS redirect** — sends a `GET /` request on port 80 and checks for a 3xx redirect to an `https://` URL. A missing redirect means traffic can be intercepted in cleartext (`[FAIL]`).
- **HSTS header** — sends a `HEAD /` request on port 443 and checks for a `Strict-Transport-Security` header. The `max-age` must be at least 180 days (15,552,000 seconds) to pass. If the header is present and valid, the tool also queries the [hstspreload.org](https://hstspreload.org) API to check whether the domain is on the browser preload list — domains on the list are protected from the very first visit, before any HSTS header has been seen. HSTS prevents downgrade attacks and cookie hijacking over plain HTTP.
- **X-Frame-Options** — prevents the page from being embedded in an `<iframe>` on another origin. Missing or incorrect values leave the site open to clickjacking attacks. Accepted values: `DENY` or `SAMEORIGIN`.
- **X-Content-Type-Options** — must be set to `nosniff` to prevent browsers from guessing the content type of a response. Without it, browsers may interpret non-script files as JavaScript and execute them.
- **Content-Security-Policy** — restricts which resources (scripts, styles, images) the browser is allowed to load. Checked for presence only — a missing CSP means no protection against XSS and injection attacks.

**TLS certificate signature algorithm check** — fetches the raw DER-encoded certificate from port 443 (without verifying the chain) and scans the OID bytes to identify the signature algorithm. SHA-1 and MD5 signed certificates are `[FAIL]` (`CRITICAL`) — both are cryptographically broken and rejected by modern browsers. SHA-256 and stronger are `[PASS]`. The check runs without any external dependencies by scanning known OID byte sequences directly in the DER data.

**TLS certificate RSA key size check** — also parsed from the raw DER certificate. Locates the RSA public key by finding the `rsaEncryption` OID, then extracts the modulus length. Keys below 2048 bits are `[FAIL]` (`CRITICAL`) — they are within reach of factoring attacks. Keys of 2048 bits or larger are `[PASS]` with the bit size noted. Non-RSA keys (ECDSA, Ed25519) are skipped — their strength is checked differently and is not expressed in key size.

**SMTP/STARTTLS check** — connects to port 25 or 587, sends `EHLO`, and checks whether the server advertises `STARTTLS`. If it does, the tool upgrades the connection and runs three sub-checks: whether the server accepts any weak cipher group (same groups as the TLS check), whether the certificate is trusted, and whether it is close to expiry. A missing STARTTLS offer is `[FAIL]` — credentials and message content would be sent in cleartext.

**FTP AUTH TLS check** — connects to port 21 and attempts to upgrade the connection by sending `AUTH TLS`. If the server responds with `234`, TLS is supported (`[PASS]`). If the command is rejected or the port is closed, it is `[FAIL]` — file transfers would be sent in cleartext.

**RDP NLA check** — sends an X.224 Connection Request PDU to port 3389 with the `PROTOCOL_SSL | PROTOCOL_HYBRID` flags, requesting Network Level Authentication. If the server's response includes `PROTOCOL_HYBRID` in the selected protocols, NLA is required (`[PASS]`). Without NLA, the Windows login screen is presented before authentication — exposing it to credential-spraying attacks and unpatched pre-auth RDP vulnerabilities.

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

[SSH Host Keys]
  [PASS]  Host key type — ED25519 — recommended

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
  Summary — 34 checks
  [PASS] 33   [FAIL] 1
  1 issue(s) require attention.

  Recommended actions:
  • Root login: Set PermitRootLogin no in /etc/ssh/sshd_config and run: sudo systemctl reload sshd
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
| SSH host key | PASS — ED25519 | PASS — ED25519 |
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
host,category,check,result,detail,remediation
github.com,Port Check,Port 22 (SSH),PASS,open,
github.com,SSH Algorithms,curve25519-sha256,PASS,,
github.com,SSH Root Login,Root login,FAIL,enabled — server offered auth methods: publickey,Set PermitRootLogin no ...
...
```

Useful for importing into spreadsheets or filtering with tools like `grep`, `awk`, or pandas.

### HTML report

Use `--html <file>` to generate a self-contained HTML report with colour-coded results and per-failure fix instructions:

```bash
python3 auditor.py example.com --html report.html
```

Open `report.html` in any browser — no internet connection required.

### JSON export

Use `--json <file>` for machine-readable output suitable for scripting or integration with other tools:

```bash
python3 auditor.py example.com --json report.json
```

Output includes a timestamp and an array of result objects with `host`, `category`, `check`, `result`, `detail`, and `remediation` fields.

### Markdown report

Use `--markdown <file>` to generate a Markdown report grouped by host and category:

```bash
python3 auditor.py example.com --markdown report.md
```

Each host section shows the grade, failure count, and a table of failed checks with severity icons. Passed checks are collapsed into a `<details>` block. The output renders well on GitHub, in editors with Markdown preview, and in documentation sites.

### Comparison report

Use `--compare <before> <after> <out>` to diff two JSON reports and produce a Markdown summary of what changed. No scan is performed — the command reads the two files and exits:

```bash
python3 auditor.py --compare before.json after.json diff.md
```

The output groups findings into three sections:

- **Regressions** — failures present in `after` but not in `before`
- **Improvements** — failures present in `before` but resolved in `after`
- **Unchanged** — failures present in both (collapsed)

Useful for tracking remediation progress over time or reviewing the effect of a configuration change.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more checks failed |

Useful in CI/CD pipelines: the tool exits with code 1 if any `[FAIL]` result is found.

### Severity levels and grading

Every failed check is classified as either `[CRIT]` or `[WARN]`:

| Tag | Colour | Examples |
|---|---|---|
| `[CRIT]` | Red | Broken ciphers, expired/untrusted cert, TLS 1.0/1.1, no modern KEX, password auth, root login (password), DSA host key, hostname mismatch, SHA-1/MD5 cert signature, RSA key < 2048-bit |
| `[WARN]` | Yellow | Weak algorithms alongside modern ones, missing security headers, HSTS issues, outdated OpenSSH, CAA/DNSSEC missing, SSH OS/distro disclosure, root login (publickey only) |

Each host receives an **A–F grade** shown in the audit summary and HTML report:

| Grade | Meaning |
|---|---|
| A | No failures |
| B | Warnings only |
| C | 1 critical failure |
| D | 2–3 critical failures |
| F | 4 or more critical failures |

### Watch mode

Use `--watch SECONDS` to continuously re-scan and show only what has changed:

```bash
python3 auditor.py example.com --watch 60
```

After each scan a diff is printed showing new failures and resolved issues. Press Ctrl+C to stop.

### Badges

Use `--badge` to generate a shields.io Markdown badge per target:

```bash
python3 auditor.py example.com --badge
```

Output:
```
![example.com](https://img.shields.io/badge/example.com-A-brightgreen)
```

Embed in a README to show the current security grade at a glance.

### Config generator

Use `--config` to generate ready-to-paste configuration snippets for every failure found:

```bash
python3 auditor.py example.com --config
```

After the audit summary, the tool prints a targeted `sshd_config` section and/or an nginx server block containing only the lines needed to fix the detected issues — weak algorithm lists, missing security headers, redirect rules, and so on. Nothing is written to disk; output goes to stdout so you can review before applying.

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
| `dnspython` | >= 2.0.0 | CAA DNS record lookup |
| `ssl` | stdlib | TLS handshake testing (TLS, SMTP, FTP) |
| `socket` | stdlib | Port connectivity checks (all protocols) |
| `urllib` | stdlib | HSTS preload API query |

---

<p align="center">
  <img src="logo.png" alt="ssh-tls-auditor logo" width="200">
</p>

<p align="center">
  <sub>The banner and logo are &copy; 2026 Elin Olsson — all rights reserved, not covered by the MIT license.</sub>
</p>
