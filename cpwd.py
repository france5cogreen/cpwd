"""
cpwd.py — Batch password changer for network devices

USAGE:
    python cpwd.py ip_list.txt [--wet-run] [--workers N] [--log-file FILE] [--output FILE]

OPTIONS:
    ip_list.txt         File with one IP per line (lines starting with # are ignored)
    --wet-run           Actually apply changes (default: dry-run / simulation only)
    --workers N         Parallel threads (default: 4)
    --device-type TYPE  Device type; see supported list below. If omitted: prompted interactively.
    --log-file FILE     Save log to file
    --output FILE       Output report file (default: output_passwords.txt)
    --shared-password   Use a single generated password for all IPs (default: one per IP)
    -v / --version      Show version information
    -h / --help         Show this help

SUPPORTED DEVICE TYPES:
    sonicwall | alcatel | tiesse | cisco | fortios | paloalto | checkpoint | juniper | huawei

NOTES:
    - Default mode is dry-run: no device is touched. Pass --wet-run to make real changes.
    - Verify command syntax for your firmware version before production use.
    - On critical failure (neither old nor new password works), the script attempts rollback
      and opens an interactive SSH shell for manual recovery (Linux only).
"""

__version__ = "1.0.0"

import sys
import time
import threading
import getpass
import secrets
import string
import logging
import argparse
import os
import json
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko


SUPPORTED_DEVICE_TYPES = [
    "sonicwall", "alcatel", "tiesse",
    "cisco", "fortios", "paloalto", "checkpoint", "juniper", "huawei",
]


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging(log_file=None):
    logger = logging.getLogger("cpwd")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger

log = setup_logging()


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------

_CHARS = string.ascii_letters + string.digits + "!@#%^&*()-_=+{}:,.<>?"

def generate_password(length=20):
    """Generate a random password satisfying complexity requirements."""
    while True:
        pwd = "".join(secrets.choice(_CHARS) for _ in range(length))
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in string.punctuation for c in pwd)):
            return pwd


# ---------------------------------------------------------------------------
# Vendor command sets
# NOTE: verify exact syntax against your firmware version before production use.
# ---------------------------------------------------------------------------

def _commands(device_type, username, old_pwd, new_pwd):
    """Return the CLI command sequence to change password from old_pwd to new_pwd.
    Used for both the change and rollback operations."""

    if device_type == "sonicwall":
        return [
            "configure",
            "administration",
            f"admin password old-password {old_pwd} new-password {new_pwd} confirm-password {new_pwd}",
            "exit", "commit", "exit",
        ]

    elif device_type == "alcatel":
        return [
            "enable",
            "configure terminal",
            f"user password {username} {new_pwd}",
            "write memory", "exit",
        ]

    elif device_type == "tiesse":
        return [
            "enable",
            "configure terminal",
            f"username {username} password {new_pwd}",
            "commit", "write", "exit",
        ]

    elif device_type == "cisco":
        # IOS / IOS-XE: privilege-exec then update username secret
        return [
            "enable",
            "configure terminal",
            f"username {username} privilege 15 secret {new_pwd}",
            "end",
            "write memory",
        ]

    elif device_type == "fortios":
        # FortiOS: config system admin
        return [
            "config system admin",
            f"edit {username}",
            f"set password {new_pwd}",
            "end",
        ]

    elif device_type == "paloalto":
        # PAN-OS: set admin password via CLI (> set password works in operational mode)
        return [
            f"set cli pager off",
            f"set password",          # triggers interactive prompt on real devices;
            new_pwd,                  # new password
            new_pwd,                  # confirm
        ]

    elif device_type == "checkpoint":
        # Gaia OS: clish
        return [
            "clish",
            f"set user {username} password-hash",  # Gaia accepts plain via set user <u> password
            # Using the plain-password variant for scripting compatibility:
            f"set user {username} password",
            new_pwd,
            new_pwd,
            "save config",
        ]

    elif device_type == "juniper":
        # Junos: set system login user password
        return [
            "configure",
            f"set system login user {username} authentication plain-text-password",
            new_pwd,   # password prompt
            new_pwd,   # confirmation prompt
            "commit",
            "exit",
        ]

    elif device_type == "huawei":
        # VRP (VRP5 / VRP8): aaa + local-user
        return [
            "system-view",
            "aaa",
            f"local-user {username} password irreversible-cipher {new_pwd}",
            "quit", "quit",
            "save",
            "y",
        ]

    else:
        raise ValueError(f"Unsupported device type: '{device_type}'")


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

_SSH_TIMEOUT = 10
_TCP_TIMEOUT = 5

# Known interactive prompts that require a reply before continuing
_INTERACTIVE_PROMPTS = [
    (b"(yes/no)?", b"yes\n"),
    (b"(yes/no):",  b"yes\n"),
    (b"[yes/no]",   b"yes\n"),
    (b"Password:",  None),   # handled separately in Junos/Checkpoint password flows
]


def host_reachable(ip, port=22):
    try:
        with socket.create_connection((ip, port), timeout=_TCP_TIMEOUT):
            return True
    except OSError:
        return False


def ssh_connect(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=ip, username=username, password=password,
        look_for_keys=False, allow_agent=False,
        timeout=_SSH_TIMEOUT, banner_timeout=_SSH_TIMEOUT, auth_timeout=_SSH_TIMEOUT,
    )
    return client


def _shell_read(shell, timeout=3.0):
    """Read available shell output within timeout seconds."""
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            buf += shell.recv(4096)
        else:
            time.sleep(0.1)
    return buf


def ssh_run_commands(client, commands):
    """Send commands over an interactive shell, handling known prompts."""
    shell = client.invoke_shell()
    time.sleep(0.8)
    for cmd in commands:
        shell.send(cmd + "\n")
        buf = _shell_read(shell, timeout=2.0)
        if buf:
            log.debug("Shell output: %s", buf.decode(errors="replace"))
        for pattern, reply in _INTERACTIVE_PROMPTS:
            if reply and pattern in buf:
                log.debug("Prompt detected '%s' — replying.", pattern.decode())
                shell.send(reply)
                buf2 = _shell_read(shell, timeout=2.0)
                if buf2:
                    log.debug("Post-reply output: %s", buf2.decode(errors="replace"))
                break
    _shell_read(shell, timeout=1.0)  # final flush


def test_login(ip, username, password):
    try:
        c = ssh_connect(ip, username, password)
        c.close()
        return True
    except Exception as exc:
        log.debug("test_login(%s) failed: %s", ip, exc)
        return False


def _test_login_thread(ip, username, password, timeout=20.0):
    """Run test_login in a dedicated thread; joins before returning."""
    result = [None]
    def _run():
        result[0] = test_login(ip, username, password)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        log.warning("[%s] test_login timed out after %.0fs", ip, timeout)
        return None
    return result[0]


def interactive_shell(client):
    """Hand the open SSH session to the operator for manual intervention.
    Linux only (requires tty/termios)."""
    import tty, termios, select
    log.info("Interactive shell opened. Press Ctrl+C to exit.")
    channel = client.invoke_shell()
    old_tty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            r, _, _ = select.select([channel, sys.stdin], [], [], 0.1)
            if channel in r:
                data = channel.recv(1024)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            if sys.stdin in r:
                data = sys.stdin.buffer.read(1)
                if not data:
                    break
                channel.send(data)
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)
    log.info("Interactive shell closed.")


# ---------------------------------------------------------------------------
# Dry-run wrappers
# ---------------------------------------------------------------------------

def _ssh_connect(ip, username, password, dry_run):
    if dry_run:
        log.debug("[DRY-RUN] ssh_connect(%s)", ip)
        class _Dummy:
            def close(self): pass
        return _Dummy()
    return ssh_connect(ip, username, password)


def _ssh_run_commands(client, commands, dry_run):
    if dry_run:
        for cmd in commands:
            log.debug("[DRY-RUN] Would run: %s", cmd)
        return
    ssh_run_commands(client, commands)


def _test_login_wrap(ip, username, password, dry_run):
    if dry_run:
        log.debug("[DRY-RUN] test_login(%s)", ip)
        return False
    return _test_login_thread(ip, username, password)


def _interactive_shell(client, dry_run):
    if dry_run:
        log.info("[DRY-RUN] Interactive shell not available.")
        return
    interactive_shell(client)


# ---------------------------------------------------------------------------
# Per-device logic
# ---------------------------------------------------------------------------

def process_device(ip, device_type, username, old_password, dry_run, new_password=None):
    t_start = time.monotonic()
    result = {
        "ip": ip,
        "status": "",
        "password": "",
        "timestamp": datetime.now().isoformat(),
        "elapsed_s": 0,
    }

    def _done(status, password=""):
        result["status"] = status
        result["password"] = password
        result["elapsed_s"] = round(time.monotonic() - t_start, 1)
        return result

    # TCP pre-check: fail fast if host is unreachable
    if not dry_run:
        log.info("[%s] Checking reachability (TCP:22)...", ip)
        if not host_reachable(ip):
            log.warning("[%s] ✗ host_unreachable", ip)
            return _done("host_unreachable")

    log.info("[%s] Verifying initial login...", ip)
    if not _test_login_wrap(ip, username, old_password, dry_run):
        log.warning("[%s] ✗ initial_login_failed", ip)
        return _done("initial_login_failed")

    if new_password is None:
        new_password = generate_password()

    try:
        client = _ssh_connect(ip, username, old_password, dry_run)
    except Exception as exc:
        log.error("[%s] ✗ connection_error: %s", ip, exc)
        return _done(f"connection_error: {exc}")

    log.info("[%s] Sending password-change commands...", ip)
    try:
        _ssh_run_commands(client, _commands(device_type, username, old_password, new_password), dry_run)
    except Exception as exc:
        client.close()
        log.error("[%s] ✗ change_error: %s", ip, exc)
        return _done(f"change_error: {exc}")

    # Verify new password in a separate thread
    log.info("[%s] Verifying new password...", ip)
    ok_new = _test_login_wrap(ip, username, new_password, dry_run)

    if ok_new is True:
        client.close()
        log.info("[%s] ✓ password changed (%.1fs)", ip, round(time.monotonic() - t_start, 1))
        return _done("ok_password_changed", new_password)

    if ok_new is False:
        log.warning("[%s] New password rejected. Checking old password...", ip)
        ok_old = _test_login_wrap(ip, username, old_password, dry_run)

        if ok_old is True:
            client.close()
            log.warning("[%s] ⚠ Old password still active — no change applied.", ip)
            return _done("warning_password_unchanged", old_password)

        if ok_old is False:
            log.error("[%s] ✗ CRITICAL: neither password works. Attempting rollback...", ip)
            try:
                _ssh_run_commands(client, _commands(device_type, username, new_password, old_password), dry_run)
                log.info("[%s] Rollback sent.", ip)
            except Exception as exc:
                log.error("[%s] Rollback failed: %s", ip, exc)
            _interactive_shell(client, dry_run)
            client.close()
            return _done("CRITICAL_manual_intervention_required")

    # ok_new is None: login test thread timed out
    log.error("[%s] ✗ CRITICAL: password verification timed out — device state unknown.", ip)
    client.close()
    return _done("CRITICAL_timeout_unknown_state")


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def load_ips(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"IP list file not found: {path}")
    ips = [l.strip() for l in open(path, encoding="utf-8") if l.strip() and not l.startswith("#")]
    if not ips:
        raise ValueError(f"No IPs found in {path}")
    return ips


def save_output(results, path="output_passwords.txt"):
    if os.path.exists(path):
        bak = path + f".bak_{int(time.time())}"
        os.rename(path, bak)
        log.info("Previous report backed up: %s", bak)

    ok       = [r for r in results if r["status"] == "ok_password_changed"]
    warn     = [r for r in results if r["status"] == "warning_password_unchanged"]
    down     = [r for r in results if r["status"] == "host_unreachable"]
    critical = [r for r in results if r["status"].startswith("CRITICAL")]
    errors   = [r for r in results if r not in ok and r not in warn and r not in down and r not in critical]

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Generated: {ts}\n")
        f.write("# TREAT AS SECRET\n")
        f.write("=" * 80 + "\n\n")
        f.write("SUMMARY\n")
        f.write(f"  Total processed : {len(results)}\n")
        f.write(f"  ✓ OK            : {len(ok)}\n")
        f.write(f"  ⚠ Warnings      : {len(warn)}\n")
        f.write(f"  ✗ Unreachable   : {len(down)}\n")
        f.write(f"  ✗ Errors        : {len(errors)}\n")
        f.write(f"  ✗ CRITICAL      : {len(critical)}\n")
        f.write("\n" + "=" * 80 + "\n\n")

        def _section(title, lst, show_pwd=False):
            if not lst:
                return
            f.write(f"--- {title} ({len(lst)}) ---\n")
            for r in lst:
                pwd_field = f"  pwd: {r.get('password', '')}" if show_pwd and r.get("password") else ""
                f.write(f"  {r['ip']:<18} {r['status']:<45} {r.get('elapsed_s', '')}s{pwd_field}\n")
            f.write("\n")

        _section("OK — password changed", ok, show_pwd=True)
        _section("WARNING — password unchanged", warn, show_pwd=True)
        _section("UNREACHABLE", down)
        _section("ERRORS", errors)
        _section("CRITICAL — manual intervention required", critical)

    json_path = path.replace(".txt", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"generated": ts, "total": len(results), "results": results},
                  f, indent=2, ensure_ascii=False)

    log.info("TXT report : %s", path)
    log.info("JSON report: %s", json_path)
    log.info("Summary    : %d OK | %d warn | %d down | %d errors | %d CRITICAL",
             len(ok), len(warn), len(down), len(errors), len(critical))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Batch password changer for network devices.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("ip_list", help="File with one IP per line")
    parser.add_argument("--wet-run", action="store_true", default=False,
                        help="Apply changes for real (default: dry-run)")
    parser.add_argument("--workers", type=int, default=4,
                        help="Parallel threads (default: 4)")
    parser.add_argument("--device-type", choices=SUPPORTED_DEVICE_TYPES,
                        help="Device type (prompted interactively if omitted)")
    parser.add_argument("--log-file", default=None,
                        help="Save log to file")
    parser.add_argument("--output", default="output_passwords.txt",
                        help="Output report file (default: output_passwords.txt)")
    parser.add_argument("--shared-password", action="store_true", default=False,
                        help="Use one shared password for all IPs (default: one per IP)")
    parser.add_argument("-v", "--version", action="version",
                        version=f"cpwd {__version__}",
                        help="Show version information")
    args = parser.parse_args()

    dry_run = not args.wet_run

    global log
    log = setup_logging(args.log_file)

    if dry_run:
        log.info("=" * 60)
        log.info("DRY-RUN MODE — no device will be modified")
        log.info("Use --wet-run to apply changes in production")
        log.info("=" * 60)
    else:
        log.warning("WET-RUN MODE — changes will be applied to real devices")

    try:
        ip_list = load_ips(args.ip_list)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)
    log.info("IPs to process: %d", len(ip_list))

    device_type = args.device_type or input(
        f"Device type ({'/'.join(SUPPORTED_DEVICE_TYPES)}): "
    ).lower().strip()
    if device_type not in SUPPORTED_DEVICE_TYPES:
        log.error("Unsupported device type: '%s'", device_type)
        sys.exit(1)

    username = input("Username: ").strip()
    if not username:
        log.error("Username cannot be empty.")
        sys.exit(1)

    old_password = getpass.getpass("Current password: ")
    if not old_password:
        log.error("Password cannot be empty.")
        sys.exit(1)

    shared_pwd = generate_password() if args.shared_password else None
    if shared_pwd:
        log.info("Shared-password mode — same password applied to all IPs.")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_device, ip, device_type, username, old_password, dry_run, shared_pwd): ip
            for ip in ip_list
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                res = future.result()
                results.append(res)
                log.info("[%s] %s", ip, res["status"])
            except Exception as exc:
                log.error("[%s] Unhandled exception: %s", ip, exc)
                results.append({
                    "ip": ip, "status": f"exception: {exc}", "password": "",
                    "timestamp": datetime.now().isoformat(),
                })

    results.sort(key=lambda r: r["ip"])
    save_output(results, args.output)


if __name__ == "__main__":
    main()
