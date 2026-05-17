#!/usr/bin/env python3
"""
SSH Honeypot Server
Listens for SSH connections and logs all authentication attempts to SQLite.
"""

import socket
import threading
import sqlite3
import logging
import os
import sys
from datetime import datetime

import paramiko

# ── Config ────────────────────────────────────────────────────────────────────
HOST = "0.0.0.0"
PORT = 2222          # Use 22 if running as root; 2222 is safer for dev
DB_PATH = "honeypot.db"
LOG_PATH = "honeypot.log"
SERVER_KEY = "server.key"   # RSA key file (auto-generated if missing)
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS attempts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT NOT NULL,
            ip        TEXT NOT NULL,
            port      INTEGER NOT NULL,
            username  TEXT NOT NULL,
            password  TEXT NOT NULL
        )
    """)
    con.commit()
    con.close()


def log_attempt(ip, port, username, password):
    ts = datetime.utcnow().isoformat(timespec="seconds")
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "INSERT INTO attempts (ts, ip, port, username, password) VALUES (?,?,?,?,?)",
        (ts, ip, port, username, password),
    )
    con.commit()
    con.close()
    logging.info(f"{ip}:{port}  {username!r}  {password!r}")


def get_or_create_host_key():
    if os.path.exists(SERVER_KEY):
        return paramiko.RSAKey(filename=SERVER_KEY)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(SERVER_KEY)
    return key


class HoneypotInterface(paramiko.ServerInterface):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_attempt(self.ip, self.port, username, password)
        return paramiko.AUTH_FAILED   # always deny

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


def handle_connection(client_sock, addr):
    ip, port = addr
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = BANNER
        transport.add_server_key(HOST_KEY)
        server = HoneypotInterface(ip, port)
        transport.start_server(server=server)
        # Wait briefly; attackers usually close after failed auth
        chan = transport.accept(timeout=10)
        if chan:
            chan.close()
    except Exception:
        pass
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass


def main():
    init_db()

    global HOST_KEY
    HOST_KEY = get_or_create_host_key()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((HOST, PORT))
    except PermissionError:
        print(f"[!] Permission denied on port {PORT}. Try sudo or use PORT=2222.")
        sys.exit(1)

    sock.listen(100)
    print(f"[+] SSH Honeypot listening on {HOST}:{PORT}")
    print(f"[+] Logging attempts to  → {DB_PATH}")
    print(f"[+] Raw log              → {LOG_PATH}")
    print("    Press Ctrl+C to stop.\n")

    try:
        while True:
            client_sock, addr = sock.accept()
            t = threading.Thread(
                target=handle_connection,
                args=(client_sock, addr),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[+] Shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
