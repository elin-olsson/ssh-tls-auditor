#!/usr/bin/env python3
"""
ssh-tls-auditor — SSH and TLS misconfiguration auditor

Checks one or more target servers for:
  - Open ports (22, 80, 443)
  - SSH algorithms (key exchange, ciphers, MACs)
  - SSH root login status
  - TLS version support (1.0, 1.1, 1.2, 1.3)

Usage:
    python3 auditor.py <target> [<target> ...]
    python3 auditor.py -f hosts.txt
    python3 auditor.py example.com 192.168.1.10 --csv report.csv
"""

import argparse
import csv
import socket
import ssl
import sys
import warnings

import paramiko
import paramiko.message


# ── Result tracking ────────────────────────────────────────────────────────────

_counts: dict[str, int] = {"pass": 0, "fail": 0}
_results: list[dict] = []
_current_host: str = ""
_current_category: str = ""


def _reset_counts() -> None:
    _counts["pass"] = 0
    _counts["fail"] = 0


# ── Result helpers ─────────────────────────────────────────────────────────────

def _record(result: str, label: str, detail: str) -> None:
    _results.append({
        "host":     _current_host,
        "category": _current_category,
        "check":    label,
        "result":   result,
        "detail":   detail,
    })


def passed(label: str, detail: str = "") -> None:
    _counts["pass"] += 1
    _record("PASS", label, detail)
    line = f"  [PASS]  {label}"
    if detail:
        line += f" — {detail}"
    print(line)


def failed(label: str, detail: str = "") -> None:
    _counts["fail"] += 1
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
    global _current_category
    _current_category = "Port Check"
    print("\n[Port Check]")

    ports = {
        22:  "SSH",
        80:  "HTTP",
        443: "HTTPS",
    }
    for port, label in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
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
    global _current_category
    _current_category = "SSH Algorithms"
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
        # asbytes() returns the full buffer from position 0 regardless of
        # the read cursor — safe to copy without disturbing the original.
        copy = paramiko.message.Message(m.asbytes())
        copy.get_bytes(16)                       # skip 16-byte cookie
        captured["kex"]     = copy.get_list()   # kex algorithms
        copy.get_list()                          # host key algorithms (skip)
        captured["ciphers"] = copy.get_list()   # ciphers client→server
        copy.get_list()                          # ciphers server→client (skip)
        captured["macs"]    = copy.get_list()   # MACs client→server
        original_parse_kex_init(self, m)         # original m is untouched

    paramiko.Transport._parse_kex_init = capturing_parse_kex_init
    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=5)
    except Exception:
        pass  # kexinit may still have been captured before the exception
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
    global _current_category
    _current_category = "SSH Root Login"
    print("\n[SSH Root Login]")

    transport = None
    try:
        transport = paramiko.Transport((target, 22))
        transport.start_client(timeout=5)
        transport.auth_none("root")
        # auth_none succeeded — root logged in with no credentials at all
        failed("Root login", "enabled — authenticated as root with no credentials")

    except paramiko.BadAuthenticationType as e:
        # Server is willing to authenticate root, just wants a different method
        methods = ", ".join(e.allowed_types) if e.allowed_types else "unknown"
        failed("Root login", f"enabled — server offered auth methods: {methods}")

    except paramiko.AuthenticationException:
        # Server rejected root outright — PermitRootLogin no
        passed("Root login", "disabled — server rejected auth for root")

    except Exception as e:
        info("Root login", f"could not determine — {e}")

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
    global _current_category
    _current_category = "TLS Version Support"
    print("\n[TLS Version Support]")

    # (enum value, label, should_succeed)
    # should_succeed=True  → PASS if handshake works, INFO if not
    # should_succeed=False → FAIL if handshake works, PASS if rejected
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

        # Build a context pinned to exactly this TLS version.
        # Suppress deprecation warnings for TLS 1.0/1.1 — we probe them
        # intentionally to check whether the server incorrectly allows them.
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
            with socket.create_connection((target, 443), timeout=5) as raw:
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

def run_audit(target: str) -> None:
    global _current_host
    _current_host = target
    _reset_counts()

    title = f"SSH/TLS Auditor — target: {target}"
    width = max(38, len(title) + 2)
    border = "═" * width
    print(f"\n╔{border}╗")
    print(f"  {title}")
    print(f"╚{border}╝")

    check_open_ports(target)
    check_ssh_algorithms(target)
    check_ssh_root_login(target)
    check_tls_versions(target)

    total = _counts["pass"] + _counts["fail"]
    print(f"\n╔{border}╗")
    print(f"  Summary — {total} checks")
    print(f"  [PASS] {_counts['pass']}   [FAIL] {_counts['fail']}")
    if _counts["fail"] == 0:
        print("  All checks passed.")
    else:
        print(f"  {_counts['fail']} issue(s) require attention.")
    print(f"╚{border}╝")


# ── Multi-host summary ─────────────────────────────────────────────────────────

def print_multi_summary(targets: list[str]) -> None:
    """Print a condensed per-host table after scanning multiple targets."""
    host_counts: dict[str, dict[str, int]] = {}
    for row in _results:
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
    print(f"  {'Multi-host summary'}")
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
            "  auditor.py -f hosts.txt --csv results.csv"
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
    args = parser.parse_args()

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

    for target in targets:
        run_audit(target)

    if len(targets) > 1:
        print_multi_summary(targets)

    if args.csv:
        write_csv(args.csv)


if __name__ == "__main__":
    main()
