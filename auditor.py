#!/usr/bin/env python3
"""
ssh-tls-auditor — SSH and TLS misconfiguration auditor

Checks one or more target servers for:
  - Open ports (22, 80, 443)
  - SSH algorithms (key exchange, ciphers, MACs)
  - SSH banner / server version
  - SSH root login status
  - SSH password authentication
  - TLS version support (1.0, 1.1, 1.2, 1.3)
  - TLS certificate (trust, expiry, hostname match)
  - HTTP → HTTPS redirect and HSTS header

Usage:
    python3 auditor.py <target> [<target> ...]
    python3 auditor.py -f hosts.txt
    python3 auditor.py example.com 192.168.1.10 --csv report.csv
    python3 auditor.py -f hosts.txt --parallel --timeout 10
    python3 auditor.py example.com --only ssh tls
"""

import argparse
import concurrent.futures
import contextlib
import csv
import datetime
import http.client
import io
import ipaddress
import socket
import ssl
import sys
import threading
import warnings

import paramiko
import paramiko.message


# ── Module-level configuration ─────────────────────────────────────────────────

# Connection timeout in seconds — overridden by --timeout at runtime.
_timeout: int = 5

# Check groups for --only filtering.
CHECK_GROUPS = ("ports", "ssh", "tls", "http")


# ── Thread-local result tracking ───────────────────────────────────────────────
#
# Each thread running run_audit() gets its own host, category, and counts so
# that parallel scans do not clobber each other's state.

_thread_local = threading.local()


def _host() -> str:
    return getattr(_thread_local, "host", "")


def _category() -> str:
    return getattr(_thread_local, "category", "")


def _counts() -> dict[str, int]:
    if not hasattr(_thread_local, "counts"):
        _thread_local.counts = {"pass": 0, "fail": 0}
    return _thread_local.counts


def _reset_counts() -> None:
    _thread_local.counts = {"pass": 0, "fail": 0}


# Shared results list — appended to by all threads. list.append() is atomic
# in CPython (GIL), but we use a lock to be explicit about the intent.
_results: list[dict] = []
_results_lock = threading.Lock()


# ── Result helpers ─────────────────────────────────────────────────────────────

def _record(result: str, label: str, detail: str) -> None:
    row = {
        "host":     _host(),
        "category": _category(),
        "check":    label,
        "result":   result,
        "detail":   detail,
    }
    with _results_lock:
        _results.append(row)


def passed(label: str, detail: str = "") -> None:
    _counts()["pass"] += 1
    _record("PASS", label, detail)
    line = f"  [PASS]  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def failed(label: str, detail: str = "") -> None:
    _counts()["fail"] += 1
    _record("FAIL", label, detail)
    line = f"  [FAIL]  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def info(label: str, detail: str = "") -> None:
    _record("INFO", label, detail)
    line = f"  [INFO]  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


# ── Checks ─────────────────────────────────────────────────────────────────────

def check_open_ports(target: str) -> None:
    """Check whether ports 22, 80, and 443 are open on the target."""
    _thread_local.category = "Port Check"
    print("\n[Port Check]")

    ports = {22: "SSH", 80: "HTTP", 443: "HTTPS"}
    for port, label in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                passed(f"Port {port} ({label})", "open")
            else:
                failed(f"Port {port} ({label})", "closed")
        except socket.gaierror:
            failed(f"Port {port} ({label})", "could not resolve host")
        except socket.timeout:
            failed(f"Port {port} ({label})", "timed out")


def check_ssh_algorithms(target: str) -> None:
    """Connect to SSH and enumerate accepted key exchange, cipher, and MAC algorithms.

    Patches Transport._parse_kex_init to read a copy of the server's KEXINIT packet
    before paramiko processes it. The KEXINIT message lists every algorithm the server
    supports, not just the one that gets negotiated.
    """
    _thread_local.category = "SSH Algorithms"
    print("\n[SSH Algorithms]")

    WEAK_KEX = {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
    }
    WEAK_CIPHERS = {
        "arcfour", "arcfour128", "arcfour256",
        "3des-cbc", "blowfish-cbc", "cast128-cbc",
        "aes128-cbc", "aes192-cbc", "aes256-cbc",
    }
    WEAK_MACS = {
        "hmac-md5", "hmac-md5-96",
        "hmac-sha1", "hmac-sha1-96",
        "umac-64@openssh.com",
    }

    captured: dict[str, list] = {}
    original_parse_kex_init = paramiko.Transport._parse_kex_init

    def capturing_parse_kex_init(self, m):
        copy = paramiko.message.Message(m.asbytes())
        copy.get_bytes(16)
        captured["kex"]     = copy.get_list()
        copy.get_list()
        captured["ciphers"] = copy.get_list()
        copy.get_list()
        captured["macs"]    = copy.get_list()
        original_parse_kex_init(self, m)

    paramiko.Transport._parse_kex_init = capturing_parse_kex_init
    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=_timeout)
    except Exception:
        pass
    finally:
        paramiko.Transport._parse_kex_init = original_parse_kex_init
        if transport:
            transport.close()

    if not captured:
        failed("Could not retrieve algorithm list from server")
        return

    def evaluate(label: str, algos: list, weak_set: set) -> None:
        print(f"  {label}:")
        for algo in algos:
            if algo in weak_set:
                failed(algo, "deprecated")
            else:
                passed(algo)

    evaluate("Key exchange", captured.get("kex", []), WEAK_KEX)
    evaluate("Ciphers",      captured.get("ciphers", []), WEAK_CIPHERS)
    evaluate("MACs",         captured.get("macs", []), WEAK_MACS)


def check_ssh_banner(target: str) -> None:
    """Read the SSH server banner and check the OpenSSH version.

    The server version string (e.g. SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.1)
    is sent in cleartext before authentication. It is always shown as [INFO]
    so the user has context regardless of the outcome.

    For OpenSSH, the version number is parsed and compared against a minimum:
      < 8.0 — [FAIL]: pre-2019 release, likely missing security fixes
      >= 8.0 — [PASS]: current enough for most environments

    Note: Linux distros sometimes backport security patches without bumping
    the upstream version number, so a low version does not always mean
    unpatched. Treat the result as a prompt to verify, not a definitive verdict.

    Non-OpenSSH implementations (Dropbear, custom banners) are reported as
    [INFO] only — no version threshold is applied.
    """
    _thread_local.category = "SSH Banner"
    print("\n[SSH Banner]")

    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=_timeout)
        banner = transport.remote_version or ""
    except Exception as e:
        info("SSH server version", f"could not connect — {e}")
        return
    finally:
        if transport:
            transport.close()

    if not banner:
        info("SSH server version", "no banner received")
        return

    info("SSH server version", banner)

    if "OpenSSH_" not in banner:
        return

    try:
        raw = banner.split("OpenSSH_")[1].split()[0]   # "9.2p1"
        numeric = raw.split("p")[0]                     # "9.2"
        parts = numeric.split(".")
        major = int(parts[0])
    except (IndexError, ValueError):
        info("OpenSSH version", "could not parse version number")
        return

    if major < 8:
        failed("OpenSSH version", f"{raw} — outdated (< 8.0), upgrade recommended")
    else:
        passed("OpenSSH version", f"{raw} — current")


def check_ssh_root_login(target: str) -> None:
    """Probe whether root login is enabled by sending a 'none' auth request.

    auth_none("root") asks the server to authenticate root using the 'none'
    method (no credentials). Two distinct responses are possible:

      BadAuthenticationType — server replied "I won't accept 'none', but here
          are the methods I DO accept (password, publickey, ...)". This means
          the server is actively processing authentication for root. Root login
          is enabled. [FAIL]

      AuthenticationException — server rejected the request outright without
          offering any alternative methods. Root login is likely disabled
          (PermitRootLogin no). [PASS]

    Note: BadAuthenticationType is a subclass of AuthenticationException, so
    it must be caught first.
    """
    _thread_local.category = "SSH Root Login"
    print("\n[SSH Root Login]")

    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=_timeout)
        transport.auth_none("root")
        failed("Root login", "enabled — authenticated as root with no credentials")

    except paramiko.BadAuthenticationType as e:
        methods = ", ".join(e.allowed_types) if e.allowed_types else "unknown"
        failed("Root login", f"enabled — server offered auth methods: {methods}")

    except paramiko.AuthenticationException:
        passed("Root login", "disabled — server rejected auth for root")

    except Exception as e:
        info("Root login", f"could not determine — {e}")

    finally:
        if transport:
            transport.close()


def check_ssh_password_auth(target: str) -> None:
    """Probe whether password authentication is enabled on port 22.

    Sends an auth_password request using an obviously fake username and
    password. Two outcomes are possible:

      BadAuthenticationType — the server rejected the password method outright
          and replied with a list of accepted methods (e.g. publickey only).
          Password authentication is disabled. [PASS]

      AuthenticationException (not BadAuthenticationType) — the server
          accepted the password method but rejected the credentials as wrong.
          Password authentication is enabled. [FAIL]

    Password authentication should be disabled on hardened servers. Key-based
    auth is strictly stronger and immune to brute-force and credential stuffing.

    Note: BadAuthenticationType is a subclass of AuthenticationException, so
    it must be caught first.
    """
    _thread_local.category = "SSH Password Auth"
    print("\n[SSH Password Auth]")

    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=_timeout)
        transport.auth_password("__audit_probe__", "__audit_wrong_pw_12345__")
        failed("Password authentication",
               "enabled — probe credentials unexpectedly authenticated")

    except paramiko.BadAuthenticationType:
        passed("Password authentication",
               "disabled — server does not accept password authentication")

    except paramiko.AuthenticationException:
        failed("Password authentication",
               "enabled — server accepts password authentication")

    except Exception as e:
        info("Password authentication", f"could not determine — {e}")

    finally:
        if transport:
            transport.close()


def check_tls_versions(target: str) -> None:
    """Attempt a TLS handshake for each version against port 443.

    Each version is tested in isolation by setting both minimum_version and
    maximum_version on a fresh SSLContext, forcing the handshake to use only
    that version. TLS 1.0 and 1.1 are deprecated (RFC 8996) and should be
    disabled on any server — a successful handshake for either is a [FAIL].

    Two separate failure modes are distinguished:
      - Local SSL policy blocks the version (Fedora DEFAULT/FUTURE crypto policy
        disables TLS 1.0/1.1 at the OpenSSL level) → context setup raises SSLError
      - Server rejects the version → wrap_socket raises SSLError

    Both are reported as [INFO] not supported since we cannot reach the server
    with that version either way.
    """
    _thread_local.category = "TLS Version Support"
    print("\n[TLS Version Support]")

    versions = [
        (getattr(ssl.TLSVersion, "TLSv1",   None), "TLS 1.0", False),
        (getattr(ssl.TLSVersion, "TLSv1_1", None), "TLS 1.1", False),
        (ssl.TLSVersion.TLSv1_2,                   "TLS 1.2", True),
        (ssl.TLSVersion.TLSv1_3,                   "TLS 1.3", True),
    ]

    for version, label, should_succeed in versions:
        if version is None:
            info(label, "not available in this Python/OpenSSL build")
            continue

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
        except ssl.SSLError:
            info(label, "not testable — disabled by local SSL policy")
            continue

        try:
            with socket.create_connection((target, 443), timeout=_timeout) as raw:
                with ctx.wrap_socket(raw):
                    if should_succeed:
                        passed(label, "supported")
                    else:
                        failed(label, "supported — should be disabled")
        except ssl.SSLError:
            if should_succeed:
                info(label, "not supported by server")
            else:
                passed(label, "not supported by server (correctly disabled)")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            info(label, f"could not reach port 443 — {e}")


def check_tls_certificate(target: str) -> None:
    """Retrieve the TLS certificate from port 443 and check:

      - Trust: chain verified against system CA bundle. SSLCertVerificationError
        (self-signed, expired, unknown CA, etc.) reported as [FAIL] with the
        human-readable reason extracted from the OpenSSL error string.
      - Expiry: [FAIL] if expired or < 30 days, [INFO] if < 90 days.
      - Hostname match: SAN list (DNS + IP) checked against target with
        wildcard support; falls back to CN if no SANs present.

    create_default_context() is used to load the system CA bundle and keep
    CERT_REQUIRED (default), which makes getpeercert() return the full parsed
    certificate dict on a successful handshake.

    check_hostname is disabled in the context so that we can perform the
    hostname check ourselves and produce a more informative error message.
    """
    _thread_local.category = "TLS Certificate"
    print("\n[TLS Certificate]")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False

    cert = None
    try:
        with socket.create_connection((target, 443), timeout=_timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        msg = str(e)
        if "certificate verify failed:" in msg:
            reason = msg.split("certificate verify failed:")[1].split("(")[0].strip()
        else:
            reason = msg
        failed("Certificate trust", reason)
        return
    except ssl.SSLError as e:
        info("TLS Certificate", f"TLS error — {e}")
        return
    except ConnectionRefusedError:
        info("TLS Certificate", "port 443 closed — skipping")
        return
    except (socket.timeout, OSError) as e:
        info("TLS Certificate", f"could not reach port 443 — {e}")
        return

    if not cert:
        info("TLS Certificate", "no certificate data returned")
        return

    # ── Trust ────────────────────────────────────────────────────────────────────
    issuer = dict(x[0] for x in cert.get("issuer", []))
    issuer_name = issuer.get("organizationName") or issuer.get("commonName", "unknown")
    passed("Certificate trust", f"issued by {issuer_name}")

    # ── Expiry ───────────────────────────────────────────────────────────────────
    try:
        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        days_left = (not_after - now).days

        if days_left < 0:
            failed("Certificate expiry",
                   f"expired {abs(days_left)} day(s) ago ({not_after.date()})")
        elif days_left < 30:
            failed("Certificate expiry",
                   f"expires in {days_left} day(s) ({not_after.date()}) — renew immediately")
        elif days_left < 90:
            info("Certificate expiry",
                 f"expires in {days_left} day(s) ({not_after.date()}) — renewal recommended soon")
        else:
            passed("Certificate expiry",
                   f"valid for {days_left} more day(s) (expires {not_after.date()})")
    except (KeyError, ValueError):
        info("Certificate expiry", "could not parse expiry date")

    # ── Hostname match ────────────────────────────────────────────────────────────
    subject = dict(x[0] for x in cert.get("subject", []))
    if _is_ip(target):
        ip_sans = [addr for kind, addr in cert.get("subjectAltName", [])
                   if kind == "IP Address"]
        if target in ip_sans:
            passed("Hostname match", f"certificate covers IP {target}")
        elif ip_sans:
            failed("Hostname match",
                   f"certificate does not cover {target} — IP SANs: {', '.join(ip_sans)}")
        else:
            failed("Hostname match",
                   f"certificate has no IP SANs — does not cover {target}")
    else:
        dns_sans = [name for kind, name in cert.get("subjectAltName", [])
                    if kind == "DNS"]
        if dns_sans:
            if _hostname_matches(target, dns_sans):
                passed("Hostname match", f"certificate covers {target}")
            else:
                preview = ", ".join(dns_sans[:4])
                if len(dns_sans) > 4:
                    preview += f" (+{len(dns_sans) - 4} more)"
                failed("Hostname match",
                       f"certificate does not cover {target} — SANs: {preview}")
        else:
            cn = subject.get("commonName", "")
            if cn and _hostname_matches(target, [cn]):
                passed("Hostname match", f"certificate CN matches {target}")
            else:
                failed("Hostname match",
                       f"certificate CN '{cn}' does not match {target}")


def check_http_security(target: str) -> None:
    """Check HTTP→HTTPS redirect behaviour and HSTS header on port 443.

    HTTP redirect — a GET to port 80 should return a 3xx redirect to an
    https:// URL. Anything else (200, redirect to http, no redirect) is a FAIL.

    HSTS — the Strict-Transport-Security header must be present on the HTTPS
    response. max-age should be at least 180 days (15 552 000 seconds); shorter
    values give browsers too small a window to remember to use HTTPS.
    """
    _thread_local.category = "HTTP Security"
    print("\n[HTTP Security]")

    # ── HTTP → HTTPS redirect ─────────────────────────────────────────────────
    try:
        conn = http.client.HTTPConnection(target, 80, timeout=_timeout)
        conn.request("GET", "/", headers={"Host": target,
                                          "User-Agent": "ssh-tls-auditor"})
        resp = conn.getresponse()
        location = resp.getheader("Location", "")
        if resp.status in (301, 302, 303, 307, 308) and location.lower().startswith("https://"):
            passed("HTTP → HTTPS redirect", f"HTTP {resp.status} → {location}")
        elif resp.status in (301, 302, 303, 307, 308):
            failed("HTTP → HTTPS redirect",
                   f"redirects to non-HTTPS location: {location or '(empty)'}")
        else:
            failed("HTTP → HTTPS redirect",
                   f"no redirect — server returned HTTP {resp.status} on port 80")
        conn.close()
    except ConnectionRefusedError:
        info("HTTP → HTTPS redirect", "port 80 closed — skipping")
    except (socket.timeout, OSError) as e:
        info("HTTP → HTTPS redirect", f"could not reach port 80 — {e}")

    # ── HSTS ──────────────────────────────────────────────────────────────────
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        conn = http.client.HTTPSConnection(target, 443, timeout=_timeout, context=ctx)
        conn.request("HEAD", "/", headers={"Host": target,
                                           "User-Agent": "ssh-tls-auditor"})
        resp = conn.getresponse()
        hsts = resp.getheader("Strict-Transport-Security", "")
        conn.close()

        if not hsts:
            failed("HSTS header", "Strict-Transport-Security not present")
            return

        max_age: int | None = None
        for part in hsts.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass

        include_subdomains = "includesubdomains" in hsts.lower()
        MIN_MAX_AGE = 15_552_000  # 180 days

        if max_age is None:
            failed("HSTS header", f"present but max-age could not be parsed: {hsts}")
        elif max_age < MIN_MAX_AGE:
            days = max_age // 86400
            failed("HSTS header",
                   f"max-age too short — {days} day(s) (minimum recommended: 180 days)")
        else:
            days = max_age // 86400
            detail = f"max-age={days} days"
            if include_subdomains:
                detail += ", includeSubDomains"
            passed("HSTS header", detail)

    except ConnectionRefusedError:
        info("HSTS header", "port 443 closed — skipping")
    except (socket.timeout, OSError, ssl.SSLError) as e:
        info("HSTS header", f"could not reach port 443 — {e}")


# ── TLS / hostname helpers ──────────────────────────────────────────────────────

def _hostname_matches(target: str, names: list[str]) -> bool:
    """Return True if target matches any name in the list.

    Handles exact matches and single-label wildcards (*.example.com).
    Wildcard matching follows RFC 6125: the wildcard covers exactly one label
    and only in the leftmost position.
    """
    target = target.lower()
    for name in names:
        name = name.lower()
        if name == target:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            rest = target[: -len(suffix)]
            if target.endswith(suffix) and "." not in rest:
                return True
    return False


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ── CSV export ─────────────────────────────────────────────────────────────────

def write_csv(path: str) -> None:
    """Write all collected results to a CSV file."""
    fieldnames = ["host", "category", "check", "result", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(_results)
    print(f"Results written to {path}")


# ── Per-host audit ─────────────────────────────────────────────────────────────

def run_audit(target: str, only: set[str] | None = None) -> None:
    """Run all (or a subset of) checks against target and print the results.

    Args:
        target: hostname or IP address to audit.
        only:   set of group names to run (ports / ssh / tls / http).
                None means run all groups.
    """
    _thread_local.host = target
    _reset_counts()

    all_groups = only is None

    title = f"SSH/TLS Auditor — target: {target}"
    width = max(38, len(title) + 2)
    border = "═" * width
    print(f"\n╔{border}╗")
    print(f"  {title}")
    print(f"╚{border}╝")

    if all_groups or "ports" in only:
        check_open_ports(target)
    if all_groups or "ssh" in only:
        check_ssh_algorithms(target)
        check_ssh_banner(target)
        check_ssh_root_login(target)
        check_ssh_password_auth(target)
    if all_groups or "tls" in only:
        check_tls_versions(target)
        check_tls_certificate(target)
    if all_groups or "http" in only:
        check_http_security(target)

    c = _counts()
    total = c["pass"] + c["fail"]
    print(f"\n╔{border}╗")
    print(f"  Summary — {total} checks")
    print(f"  [PASS] {c['pass']}   [FAIL] {c['fail']}")
    if c["fail"] == 0:
        print("  All checks passed.")
    else:
        print(f"  {c['fail']} issue(s) require attention.")
    print(f"╚{border}╝")


def run_audit_buffered(target: str, only: set[str] | None) -> str:
    """Run run_audit() with stdout captured to a string and return it.

    Used by parallel scanning so that each host's output is collected
    complete and then printed in submission order, avoiding interleaved lines.
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run_audit(target, only)
    return buf.getvalue()


# ── Multi-host summary ─────────────────────────────────────────────────────────

def print_multi_summary(targets: list[str]) -> None:
    """Print a condensed per-host table after scanning multiple targets."""
    host_counts: dict[str, dict[str, int]] = {}
    with _results_lock:
        snapshot = list(_results)

    for row in snapshot:
        h = row["host"]
        if h not in host_counts:
            host_counts[h] = {"pass": 0, "fail": 0}
        if row["result"] == "PASS":
            host_counts[h]["pass"] += 1
        elif row["result"] == "FAIL":
            host_counts[h]["fail"] += 1

    col_width = max(len(h) for h in targets) + 2
    border = "═" * (col_width + 26)
    print(f"\n╔{border}╗")
    print("  Multi-host summary")
    print(f"  {'Host':<{col_width}} {'PASS':>6}  {'FAIL':>6}  {'Total':>6}")
    print(f"  {'─' * (col_width + 24)}")
    for h in targets:
        c = host_counts.get(h, {"pass": 0, "fail": 0})
        total = c["pass"] + c["fail"]
        print(f"  {h:<{col_width}} {c['pass']:>6}  {c['fail']:>6}  {total:>6}")
    print(f"╚{border}╝")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSH/TLS misconfiguration auditor",
        epilog=(
            "Examples:\n"
            "  auditor.py example.com\n"
            "  auditor.py host1 host2 host3 --csv results.csv\n"
            "  auditor.py -f hosts.txt --parallel --timeout 10\n"
            "  auditor.py example.com --only ssh tls"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="hostname(s) or IP address(es) to audit",
    )
    parser.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="read targets from a file, one per line (# comments supported)",
    )
    parser.add_argument(
        "--csv",
        metavar="FILE",
        help="write results to a CSV file after all audits complete",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        metavar="SECONDS",
        help="connection timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        choices=list(CHECK_GROUPS),
        metavar="GROUP",
        help=f"run only the specified check group(s): {', '.join(CHECK_GROUPS)}",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="scan multiple targets in parallel (default: sequential)",
    )
    args = parser.parse_args()

    # Apply timeout globally before any checks run.
    global _timeout
    _timeout = args.timeout

    only: set[str] | None = set(args.only) if args.only else None

    targets: list[str] = list(args.targets)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"Error: file not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        parser.print_help()
        sys.exit(1)

    if args.parallel and len(targets) > 1:
        # Each target runs in its own thread with stdout buffered.
        # Futures are submitted in order and printed in order so the output
        # is deterministic regardless of which thread finishes first.
        max_workers = min(len(targets), 20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(run_audit_buffered, t, only) for t in targets]
            for future in futures:
                print(future.result(), end="")
    else:
        for target in targets:
            run_audit(target, only)

    if len(targets) > 1:
        print_multi_summary(targets)

    if args.csv:
        write_csv(args.csv)


if __name__ == "__main__":
    main()
