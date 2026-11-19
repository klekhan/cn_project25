#!/usr/bin/env python3
"""Multi-threaded TCP echo server (victim). Run on h3."""
import argparse
import socket
import threading


def handle(conn, addr):
    with conn:
        conn.settimeout(5)
        try:
            data = conn.recv(1024)
            if data:
                conn.sendall(b'ECHO: ' + data)
        except (socket.timeout, OSError):
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=5000)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(128)
    print('[server] listening on %s:%d' % (args.host, args.port), flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == '__main__':
    main()
