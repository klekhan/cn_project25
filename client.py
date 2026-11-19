#!/usr/bin/env python3
"""Normal TCP client (legit user). Run on h1. Prints OK/FAIL per request."""
import argparse
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='10.0.0.3')
    ap.add_argument('--port', type=int, default=5000)
    ap.add_argument('--interval', type=float, default=1.0, help='seconds between requests')
    ap.add_argument('--count', type=int, default=0, help='0 = run forever')
    args = ap.parse_args()

    n = 0
    while args.count == 0 or n < args.count:
        n += 1
        t0 = time.time()
        try:
            s = socket.create_connection((args.host, args.port), timeout=2)
            s.sendall(('hello #%d' % n).encode())
            reply = s.recv(1024).decode()
            s.close()
            print('%s [client] #%d OK   (%.1f ms) %s' % (
                time.strftime('%H:%M:%S'), n, (time.time() - t0) * 1000, reply), flush=True)
        except OSError as e:
            print('%s [client] #%d FAIL (%s)' % (time.strftime('%H:%M:%S'), n, e), flush=True)
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
