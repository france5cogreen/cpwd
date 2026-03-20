"""
change_pwd.py — Batch password changer for network devices (Cisco, Fortinet, Palo Alto, SonicWall, Alcatel, Tiesse)

USO:
    python change_pwd.py ip_list.txt [--wet-run] [--workers N] [--log-file FILE] [--output FILE]

OPZIONI:
    lista_ip.txt        File con un IP per riga (righe con # ignorate)
    --wet-run           Esegue realmente sui dispositivi (default: dry-run)
    --workers N         Thread paralleli (default: 4)
    --device-type TYPE  sonicwall | alcatel | tiesse (se omesso: chiesto interattivamente)
    --log-file FILE     Salva il log su file
    --output FILE       File di output (default: output_passwords.txt)
    --shared-password   Genera una sola password per tutti gli IP (default: una per IP)
    -h / --help         Mostra questo aiuto
"""

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


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def setup_logging(log_file=None):
    logger = logging.getLogger("change_pwd")
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
# Generazione password
# ---------------------------------------------------------------------------
_CHARS = string.ascii_letters + string.digits + "!@#%^&*()-_=+{}:,.<>?"

def genera_password(lunghezza=20):
    while True:
        pwd = "".join(secrets.choice(_CHARS) for _ in range(lunghezza))
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in string.punctuation for c in pwd)):
            return pwd


# ---------------------------------------------------------------------------
# Comandi vendor  #tmp — verificare sintassi esatta per firmware in uso
# ---------------------------------------------------------------------------
# #tmp — verificare sintassi esatta per firmware in uso
def _comandi(device_type, utente, da_pwd, a_pwd):
    """Unica funzione comandi: da_pwd → a_pwd. Usata sia per cambio che per rollback."""
    if device_type == "sonicwall":
        return ["configure", "administration", f"admin password old-password {da_pwd} new-password {a_pwd} confirm-password {a_pwd}", "exit", "commit", "exit"]
    elif device_type == "alcatel":
        return ["enable", "configure terminal", f"user password {utente} {a_pwd}", "write memory", "exit"]
    elif device_type == "tiesse":
        return ["enable", "configure terminal", f"username {utente} password {a_pwd}", "commit", "write", "exit"]
    else:
        raise ValueError(f"Tipo dispositivo '{device_type}' non supportato.")


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------
_SSH_TIMEOUT = 10
_TCP_TIMEOUT = 5

def host_raggiungibile(ip, porta=22):
    try:
        with socket.create_connection((ip, porta), timeout=_TCP_TIMEOUT):
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
    """Legge l'output disponibile entro timeout secondi."""
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            buf += shell.recv(4096)
        else:
            time.sleep(0.1)
    return buf

# Prompt interattivi noti che richiedono risposta prima di procedere
_INTERACTIVE_PROMPTS = [
    (b"(yes/no)?", b"yes\n"),
    (b"(yes/no):", b"yes\n"),
    (b"[yes/no]",  b"yes\n"),
]

def ssh_run_commands(client, comandi):
    shell = client.invoke_shell()
    time.sleep(0.8)
    for cmd in comandi:
        shell.send(cmd + "\n")
        buf = _shell_read(shell, timeout=2.0)
        if buf:
            log.debug("Output shell: %s", buf.decode(errors="replace"))
        for pattern, reply in _INTERACTIVE_PROMPTS:
            if pattern in buf:
                log.debug("Prompt rilevato '%s' — rispondo yes.", pattern.decode())
                shell.send(reply)
                buf2 = _shell_read(shell, timeout=2.0)
                if buf2:
                    log.debug("Output post-reply: %s", buf2.decode(errors="replace"))
                break
    _shell_read(shell, timeout=1.0)  # flush finale

def test_login(ip, username, password):
    try:
        c = ssh_connect(ip, username, password)
        c.close()
        return True
    except Exception as exc:
        log.debug("test_login(%s) fallito: %s", ip, exc)
        return False

def _test_login_thread(ip, username, password, timeout=20.0):
    """Lancia test_login in un thread separato; il thread è completato prima del ritorno."""
    result = [None]
    def _run():
        result[0] = test_login(ip, username, password)
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout)  # thread 2 si chiude qui prima di procedere
    if t.is_alive():
        log.warning("[%s] test_login timeout dopo %.0fs", ip, timeout)
        return None
    return result[0]

def shell_interattiva(client):
    """Cede la sessione SSH aperta all'operatore.  #tmp — verificare compatibilità su Windows (tty/termios non disponibili)"""
    import tty, termios, select
    log.info("Shell interattiva aperta. Ctrl+C per uscire.")
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
    log.info("Shell interattiva chiusa.")


# ---------------------------------------------------------------------------
# Dry-run wrappers
# ---------------------------------------------------------------------------
def _ssh_connect(ip, username, password, dry_run):
    if dry_run:
        log.debug("[DRY-RUN] ssh_connect(%s)", ip)
        class _D:
            def close(self): pass
        return _D()
    return ssh_connect(ip, username, password)

def _ssh_run_commands(client, comandi, dry_run):
    if dry_run:
        for cmd in comandi:
            log.debug("[DRY-RUN] Eseguirei: %s", cmd)
        return
    ssh_run_commands(client, comandi)

def _test_login_wrap(ip, username, password, dry_run):
    if dry_run:
        log.debug("[DRY-RUN] test_login(%s)", ip)
        return False
    return _test_login_thread(ip, username, password)

def _shell_interattiva(client, dry_run):
    if dry_run:
        log.info("[DRY-RUN] Shell interattiva non disponibile.")
        return
    shell_interattiva(client)


# ---------------------------------------------------------------------------
# Logica per singolo dispositivo
# ---------------------------------------------------------------------------
def process_device(ip, device_type, username, old_password, dry_run, new_password=None):
    t_start = time.monotonic()
    ris = {"ip": ip, "status": "", "password": "", "timestamp": datetime.now().isoformat(), "elapsed_s": 0}

    # Pre-check TCP: fail fast se l'IP è down
    if not dry_run:
        log.info("[%s] Controllo raggiungibilità (TCP:22)...", ip)
        if not host_raggiungibile(ip):
            ris["status"] = "host_non_raggiungibile"
            ris["elapsed_s"] = round(time.monotonic() - t_start, 1)
            log.warning("[%s] ✗ %s", ip, ris["status"])
            return ris

    log.info("[%s] Verifica login iniziale...", ip)
    if not _test_login_wrap(ip, username, old_password, dry_run):
        ris["status"] = "errore_login_iniziale"
        ris["elapsed_s"] = round(time.monotonic() - t_start, 1)
        log.warning("[%s] ✗ %s", ip, ris["status"])
        return ris

    if new_password is None:
        new_password = genera_password()

    try:
        client1 = _ssh_connect(ip, username, old_password, dry_run)
    except Exception as exc:
        ris["status"] = f"errore_connessione: {exc}"
        ris["elapsed_s"] = round(time.monotonic() - t_start, 1)
        log.error("[%s] ✗ %s", ip, ris["status"])
        return ris

    log.info("[%s] Invio comandi cambio password...", ip)
    try:
        _ssh_run_commands(client1, _comandi(device_type, username, old_password, new_password), dry_run)
    except Exception as exc:
        client1.close()
        ris["status"] = f"errore_cambio_password: {exc}"
        ris["elapsed_s"] = round(time.monotonic() - t_start, 1)
        log.error("[%s] ✗ %s", ip, ris["status"])
        return ris

    # Thread 2: testa nuova password — si chiude prima di proseguire
    log.info("[%s] Verifica nuova password (thread separato)...", ip)
    ok_new = _test_login_wrap(ip, username, new_password, dry_run)

    if ok_new is True:
        client1.close()
        ris["status"] = "ok_password_cambiata"
        ris["password"] = new_password
        ris["elapsed_s"] = round(time.monotonic() - t_start, 1)
        log.info("[%s] ✓ Password cambiata con successo (%.1fs)", ip, ris["elapsed_s"])
        return ris

    if ok_new is False:
        log.warning("[%s] Nuova password non accettata. Verifica vecchia password...", ip)
        ok_old = _test_login_wrap(ip, username, old_password, dry_run)

        if ok_old is True:
            client1.close()
            ris["status"] = "password_invariata_vecchia_attiva"
            ris["password"] = old_password
            ris["elapsed_s"] = round(time.monotonic() - t_start, 1)
            log.warning("[%s] ⚠ Vecchia password ancora attiva — nessun cambio effettuato (%.1fs)", ip, ris["elapsed_s"])
            return ris

        if ok_old is False:
            log.error("[%s] ✗ CRITICO: nessuna password funziona. Tentativo rollback...", ip)
            try:
                _ssh_run_commands(client1, _comandi(device_type, username, new_password, old_password), dry_run)
                log.info("[%s] Rollback inviato.", ip)
            except Exception as exc:
                log.error("[%s] Rollback fallito: %s", ip, exc)
            _shell_interattiva(client1, dry_run)
            client1.close()
            ris["status"] = "CRITICO_intervento_manuale_eseguito"
            ris["elapsed_s"] = round(time.monotonic() - t_start, 1)
            return ris

    # ok_new è None: timeout del thread di test
    log.error("[%s] ✗ CRITICO: timeout verifica password — stato dispositivo incerto (%.1fs)", ip, round(time.monotonic() - t_start, 1))
    client1.close()
    ris["status"] = "CRITICO_timeout_stato_incerto"
    ris["elapsed_s"] = round(time.monotonic() - t_start, 1)
    return ris


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------
def load_ips(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"File IP non trovato: {path}")
    ips = [l.strip() for l in open(path, encoding="utf-8") if l.strip() and not l.startswith("#")]
    if not ips:
        raise ValueError(f"Nessun IP in {path}")
    return ips

def save_output(results, path="output_passwords.txt"):
    if os.path.exists(path):
        bak = path + f".bak_{int(time.time())}"
        os.rename(path, bak)
        log.info("Backup precedente: %s", bak)

    # Categorizzazione
    ok      = [r for r in results if r["status"] == "ok_password_cambiata"]
    warn    = [r for r in results if r["status"] in ("password_invariata_vecchia_attiva",)]
    down    = [r for r in results if r["status"] == "host_non_raggiungibile"]
    critici = [r for r in results if r["status"].startswith("CRITICO")]
    errori  = [r for r in results if r not in ok and r not in warn and r not in down and r not in critici]

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Generato: {ts}\n")
        f.write("# TRATTA COME SEGRETO\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"RIEPILOGO\n")
        f.write(f"  Totale elaborati : {len(results)}\n")
        f.write(f"  ✓ OK             : {len(ok)}\n")
        f.write(f"  ⚠ Warning        : {len(warn)}\n")
        f.write(f"  ✗ Non raggiung.  : {len(down)}\n")
        f.write(f"  ✗ Errori         : {len(errori)}\n")
        f.write(f"  ✗ CRITICI        : {len(critici)}\n")
        f.write("\n" + "=" * 80 + "\n\n")

        def _sezione(titolo, lista, mostra_pwd=False):
            if not lista:
                return
            f.write(f"--- {titolo} ({len(lista)}) ---\n")
            for r in lista:
                pwd_field = f"  pwd: {r.get('password','')}" if mostra_pwd and r.get("password") else ""
                f.write(f"  {r['ip']:<18} {r['status']:<45} {r.get('elapsed_s', '')}s{pwd_field}\n")
            f.write("\n")

        _sezione("OK — password cambiata", ok, mostra_pwd=True)
        _sezione("WARNING — password invariata", warn, mostra_pwd=True)
        _sezione("NON RAGGIUNGIBILI", down)
        _sezione("ERRORI", errori)
        _sezione("CRITICI — intervento manuale", critici)

    # JSON strutturato
    json_path = path.replace(".txt", ".json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"generato": ts, "totale": len(results), "risultati": results}, f, indent=2, ensure_ascii=False)

    log.info("Report TXT : %s", path)
    log.info("Report JSON: %s", json_path)
    log.info("Riepilogo  : %d OK | %d warning | %d down | %d errori | %d CRITICI",
             len(ok), len(warn), len(down), len(errori), len(critici))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Cambio password batch su dispositivi di rete.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file_ip", help="File con un IP per riga")
    parser.add_argument("--wet-run", action="store_true", default=False,
                        help="Esegue realmente sui dispositivi (default: dry-run)")
    parser.add_argument("--workers", type=int, default=4, help="Thread paralleli (default: 4)")
    parser.add_argument("--device-type", choices=["sonicwall", "alcatel", "tiesse"],
                        help="Tipo dispositivo (se omesso: chiesto interattivamente)")
    parser.add_argument("--log-file", default=None, help="Salva il log su file")
    parser.add_argument("--output", default="output_passwords.txt", help="File di output")
    parser.add_argument("--shared-password", action="store_true", default=False,
                        help="Genera una sola password per tutti gli IP (default: una per IP)")
    args = parser.parse_args()

    dry_run = not args.wet_run

    global log
    log = setup_logging(args.log_file)

    if dry_run:
        log.info("=" * 60)
        log.info("DRY-RUN ATTIVO — nessun dispositivo verrà modificato")
        log.info("Usa --wet-run per eseguire in produzione")
        log.info("=" * 60)
    else:
        log.warning("WET-RUN ATTIVO — i dispositivi verranno modificati realmente")

    try:
        lista_ip = load_ips(args.file_ip)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        sys.exit(1)
    log.info("IP da elaborare: %d", len(lista_ip))

    device_type = args.device_type or input("Tipo dispositivo (sonicwall/alcatel/tiesse): ").lower().strip()
    if device_type not in ("sonicwall", "alcatel", "tiesse"):
        log.error("Tipo dispositivo '%s' non supportato.", device_type)
        sys.exit(1)

    username = input("Username: ").strip()
    if not username:
        log.error("Username vuoto.")
        sys.exit(1)

    old_password = getpass.getpass("Password attuale: ")
    if not old_password:
        log.error("Password vuota.")
        sys.exit(1)

    shared_pwd = genera_password() if args.shared_password else None
    if shared_pwd:
        log.info("Modalità password condivisa — stessa password per tutti gli IP.")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(process_device, ip, device_type, username, old_password, dry_run, shared_pwd): ip
            for ip in lista_ip
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                res = future.result()
                results.append(res)
                log.info("[%s] %s", ip, res["status"])
            except Exception as exc:
                log.error("[%s] Eccezione non gestita: %s", ip, exc)
                results.append({"ip": ip, "status": f"eccezione: {exc}", "password": "",
                                 "timestamp": datetime.now().isoformat()})

    results.sort(key=lambda r: r["ip"])
    save_output(results, args.output)


if __name__ == "__main__":
    main()
