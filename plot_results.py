#!/usr/bin/env python3
"""
Make the report graph: new TCP connections (SYN-only packet-ins) per second per
source IP, with a vertical line where each block was installed.
Run after a demo:  python3 plot_results.py     -> results.png
"""
import csv
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def main():
    rate = defaultdict(lambda: defaultdict(int))   # src -> second -> count
    t0 = None
    with open('logs/syn_events.csv') as f:
        for row in csv.DictReader(f):
            ts = float(row['epoch'])
            t0 = ts if t0 is None else min(t0, ts)
            rate[row['src_ip']][int(ts)] += 1
    if t0 is None:
        print('no SYN events logged yet')
        return

    blocks = []
    with open('logs/events.csv') as f:
        for row in csv.DictReader(f):
            blocks.append((float(row['epoch']) - t0, row['src_ip'], row['rule'], row['action']))

    plt.figure(figsize=(10, 5))
    for src, secs in sorted(rate.items()):
        xs = sorted(secs)
        plt.plot([x - t0 for x in xs], [secs[x] for x in xs], marker='o', ms=3, label=src)
    for t, src, rule, action in blocks:
        color = 'red' if action == 'BLOCK' else 'green'
        plt.axvline(t, color=color, linestyle='--')
        plt.text(t, plt.ylim()[1] * 0.9, ' %s %s' % (action, rule), rotation=90,
                 va='top', color=color, fontsize=8)
    plt.xlabel('seconds since first event')
    plt.ylabel('new TCP connections / second')
    plt.title('Connection rate per source with block points')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig('results.png', dpi=150)
    print('saved results.png')

    print('\nDetection summary (from logs/events.csv):')
    for t, src, rule, action in blocks:
        print('  t=%.1fs  %-8s %-12s %s' % (t, action, src, rule))


if __name__ == '__main__':
    main()
