#!/usr/bin/env python3
"""
Project 25: one-terminal demo.

Run from the project folder:
    sudo python3 auto_demo.py
    sudo python3 auto_demo.py --block 60   # block time in seconds (default 30 to keep the demo short)

It starts the controller (as your normal user), builds the Mininet network, runs the
normal traffic and the attacks, and after each step prints what the controller decided,
what the switch's flow table looks like, and what the victim actually received.
"""
import argparse
import os
import pwd
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, HERE)

OUT = os.path.join(HERE, 'logs', 'controller.out')
C = dict(h='\033[1;36m', ok='\033[1;32m', bad='\033[1;31m', dim='\033[2m', y='\033[1;33m', end='\033[0m')
ARGS = None
_seen = [0]


def fix_tty():
    """Mininet leaves the terminal in a mode that makes output 'staircase'; reset it."""
    os.system('stty sane 2>/dev/null')


def banner(t):
    fix_tty()
    print('\n' + C['h'] + '=' * 74 + '\n  ' + t + '\n' + '=' * 74 + C['end'])


def say(t):
    fix_tty()
    print(C['y'] + '>> ' + t + C['end'])


def show(title, text):
    fix_tty()
    print(C['dim'] + '--- ' + title + ' ---' + C['end'])
    print((text or '').rstrip() or '(no output)')


def pause(msg):
    time.sleep(3)


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def read_out():
    try:
        with open(OUT) as f:
            return f.read()
    except OSError:
        return ''


def all_alerts():
    return [l.strip() for l in read_out().splitlines() if 'ALERT' in l]


def new_alerts():
    a = all_alerts()
    fresh = a[_seen[0]:]
    _seen[0] = len(a)
    return fresh


def drop_rules():
    return sh("ovs-ofctl -O OpenFlow13 dump-flows s1 | grep 'priority=100'")


def wait_alert(word, timeout):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if any(word in a for a in all_alerts()[_seen[0]:]):
            return True
        time.sleep(0.5)
    return False


def wait_unblocked(block):
    t0 = time.time()
    say('Waiting for the block on 10.0.0.2 to expire (hard timeout = %d s) ...' % block)
    while 'actions=drop' in drop_rules() and time.time() - t0 < block + 20:
        time.sleep(3)
    time.sleep(2)


def start_controller(user, block):
    mgr = os.path.join(pwd.getpwnam(user).pw_dir, 'ids-venv', 'bin', 'osken-manager')
    if not os.path.exists(mgr):
        sys.exit('Controller not found at %s. Run: bash setup.sh' % mgr)
    sh('sudo -u %s mkdir -p logs' % user)
    cmd = ("sudo -u %s sh -c 'IDS_BLOCK_SECONDS=%d exec %s ids_controller.py > logs/controller.out 2>&1'"
           % (user, block, mgr))
    return subprocess.Popen(cmd, shell=True, cwd=HERE)


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument('--auto', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--block', type=int, default=30, help='block duration in seconds (default 30)')
    ARGS = ap.parse_args()

    if os.geteuid() != 0 or not os.environ.get('SUDO_USER') or os.environ['SUDO_USER'] == 'root':
        sys.exit('Run it like this, from your normal user:  sudo python3 auto_demo.py')
    user = os.environ['SUDO_USER']

    banner('PROJECT 25: SDN INTRUSION DETECTION AND RESPONSE ')
    print('Hosts:  h1 = normal user 10.0.0.1 | h2 = ATTACKER 10.0.0.2 | h3 = victim server 10.0.0.3')
    print('Switch: s1 (Open vSwitch)  <--OpenFlow-->  Controller (ids_controller.py, runs as user "%s")' % user)
    print('Block time for this demo: %d seconds\n' % ARGS.block)

    sh('service openvswitch-switch start; mn -c')
    ctl = start_controller(user, ARGS.block)
    for _ in range(40):
        if 'instantiating app' in read_out():
            break
        time.sleep(0.5)
    else:
        sys.exit('Controller did not start. Look at logs/controller.out')

    from mininet.log import setLogLevel
    setLogLevel('warning')
    import topology
    net = None
    try:
        net = topology.build()
        for _ in range(40):
            if 'Switch 1 connected' in read_out():
                break
            time.sleep(0.5)
        else:
            sys.exit('Switch did not connect to the controller. Look at logs/controller.out')
        h1, h2, h3 = net.get('h1'), net.get('h2'), net.get('h3')

        banner('SETUP DONE')
        show('Controller says', '\n'.join(l for l in read_out().splitlines() if 'Switch' in l))
        show('Network links (net)', '\n'.join(
            '%s <-> %s' % (l.intf1, l.intf2) for l in net.links))
        show('Flow table: ONLY the table-miss rule ("send unknown packets to the controller")',
             sh("ovs-ofctl -O OpenFlow13 dump-flows s1 | grep 'priority=0'"))
        pause('S0: topology + controller connected')

        # ---------------- STEP 1 ----------------
        banner('STEP 1: NORMAL TRAFFIC (expect NO alert)')
        show('h1 sends 5 requests to the server h3', h1.cmd('python3 client.py --count 5 --interval 0.5'))
        show('Controller alerts so far', '\n'.join(all_alerts()) or 'none: no false positives')
        h1.cmd('rm -f /tmp/ids_h1.log; python3 client.py --interval 1 > /tmp/ids_h1.log 2>&1 &')
        say('h1 keeps running in the background so you can see it stays healthy during the attack.')
        pause('S1: normal traffic OK, no alert')

        # ---------------- STEP 2 + 3 ----------------
        banner('STEP 2: PORT SCAN from h2 (nmap SYN scan of ports 1-200)')
        h3.cmd('rm -f /tmp/ids_syn_h3.txt; tcpdump -l -n -i h3-eth0 '
               '"tcp[tcpflags] == tcp-syn and src host 10.0.0.2" > /tmp/ids_syn_h3.txt 2>&1 &')
        time.sleep(1)
        out = h2.cmd('bash attacks.sh scan')
        time.sleep(1)
        h3.cmd('pkill -f "tcpdump -l -n -i h3-eth0"')
        show('nmap result (last lines; "filtered" = packets were dropped mid-scan)',
             '\n'.join(out.strip().splitlines()[-8:]))
        fresh = new_alerts()
        show('CONTROLLER DECISION', '\n'.join(fresh) or 'NO ALERT (check thresholds in ids_controller.py)')
        show('SWITCH FLOW TABLE: the drop rule the controller pushed (priority=100, actions=drop)', drop_rules() or '(none)')
        n = sh(r"grep -c 'Flags \[S\]' /tmp/ids_syn_h3.txt").strip()
        show('VICTIM SIDE: SYNs from h2 that actually reached h3', '%s of ~200 probes (the rest were dropped after the block)' % n)
        pause('S2: ALERT + drop rule + how few SYNs reached the victim')

        banner('STEP 3: PROVE THE BLOCK (and that the normal user is not affected)')
        show('h2 tries to connect to the server (should FAIL)', h2.cmd('python3 client.py --count 3'))
        show('h2 pings the server (should be 100% packet loss)', h2.cmd('ping -c 3 -W 1 10.0.0.3'))
        show('h1 log, last lines (normal user still OK)', h1.cmd('tail -4 /tmp/ids_h1.log'))
        show('Drop rule counters: n_packets = packets the switch discarded', drop_rules() or '(none)')
        pause('S3: h2 fails, h1 still OK')

        banner('STEP 4: THE LOG OF THE DECISION (detection time)')
        show('logs/events.csv  (detect_latency_s = seconds from first attack packet to block)',
             sh('cat logs/events.csv'))
        pause('S4: events.csv with detection time')

        # ---------------- STEP 5 ----------------
        banner('STEP 5: AUTOMATIC RECOVERY (the block expires by itself)')
        wait_unblocked(ARGS.block)
        show('Drop rules in the switch now', drop_rules() or 'none: the switch removed the rule by itself')
        show('h2 connects again', h2.cmd('python3 client.py --count 3'))
        pause('S5: rule expired, h2 works again')

        # ---------------- STEP 6 ----------------
        banner('STEP 6: FAST SYN FLOOD (100 SYN/s to one port) -> rate rule')
        out = h2.cmd('bash attacks.sh syn-fast')
        show('hping3 summary', '\n'.join(out.strip().splitlines()[-4:]))
        show('CONTROLLER DECISION', '\n'.join(new_alerts()) or 'NO ALERT')
        show('SWITCH: drop rule', drop_rules() or '(none)')
        pause('S6: HIGH_CONN_RATE alert')
        wait_unblocked(ARGS.block)

        # ---------------- STEP 7 ----------------
        banner('STEP 7: SLOW SYN FLOOD (10 SYN/s, half-open) -> caught from FLOW STATISTICS')
        say('This is too slow for the rate rule. The controller polls the switch counters every 3 s '
            'and sees many connections that never completed.')
        h2.cmd('bash attacks.sh syn-slow > /tmp/ids_slow.log 2>&1 &')
        found = wait_alert('HALF_OPEN', 45)
        h2.cmd('pkill -f hping3')
        show('CONTROLLER DECISION', '\n'.join(new_alerts()) or 'NO ALERT within 45 s')
        show('SWITCH: drop rule', drop_rules() or '(none)')
        pause('S7: HALF_OPEN_SYN_FLOOD alert' if found else 'S7 (half-open rule did not fire)')

        # ---------------- STEP 8 ----------------
        banner('STEP 8: SUMMARY AND GRAPH')
        show('All decisions (logs/events.csv)', sh('cat logs/events.csv'))
        show('Flow statistics sample (logs/flow_stats.csv)', sh('head -6 logs/flow_stats.csv'))
        show('Graph', sh('sudo -u %s python3 plot_results.py 2>&1' % user))
        say('Graph saved as results.png and logs in the logs/ folder of the project.')
        pause('S8: summary and graph message')
    finally:
        print(C['dim'] + '\nCleaning up ...' + C['end'])
        if net is not None:
            try:
                net.get('h1').cmd('pkill -f client.py')
                net.stop()
            except Exception:
                pass
        sh('pkill -f osken-manager; mn -c')
        ctl.terminate()
    print(C['ok'] + '\nDONE. Open results.png and copy the logs/ folder for your report.' + C['end'])


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nInterrupted. Cleaning up ...')
