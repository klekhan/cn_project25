#!/usr/bin/env python3
"""Attack simulation: many rapid REAL TCP connections to one port. Run on h2 (lab only)."""
import argparse
import socket
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', default='10.0.0.3')
    ap.add_argument('--port', type=int, default=5000)
    ap.add_argument('--count', type=int, default=300)
    ap.add_argument('--delay', type=float, default=0.01)
    args = ap.parse_args()

    ok = fail = 0
    for i in range(args.count):
        try:
            s = socket.create_connection((args.target, args.port), timeout=0.5)
            s.close()
            ok += 1
        except OSError:
            fail += 1
        time.sleep(args.delay)
    print('[rapid_connect] done: %d connected, %d failed/blocked' % (ok, fail))


if __name__ == '__main__':
    main()
