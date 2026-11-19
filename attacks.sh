#!/bin/bash
# Attack simulations for the lab. Run ONLY from h2 inside Mininet against h3.
#   usage (from h2 xterm):  bash attacks.sh scan | syn-fast | syn-slow | rapid
TARGET=${2:-10.0.0.3}

case "$1" in
  scan)      # Rule 1: port scan (200 ports)
    nmap -sS -Pn -p 1-200 -T4 "$TARGET" ;;
  syn-fast)  # Rule 2: ~100 SYN/s, controlled rate (never use --flood)
    hping3 -S -p 5000 -i u10000 -c 1000 "$TARGET" ;;
  syn-slow)  # Rule 3: ~10 SYN/s half-open, stays under the rate rule
    hping3 -S -p 5000 -i u100000 -c 300 "$TARGET" ;;
  rapid)     # Rule 2 with real sockets
    python3 rapid_connect.py --target "$TARGET" --count 300 --delay 0.01 ;;
  *)
    echo "usage: bash attacks.sh {scan|syn-fast|syn-slow|rapid} [target_ip]" ;;
esac
