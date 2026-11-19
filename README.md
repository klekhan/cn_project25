# CN Project 25: Network Intrusion Detection and Response (SDN + TCP)

A controller (OS-Ken / Ryu) that watches TCP connection behaviour on an Open vSwitch
switch inside Mininet, detects **port scans, connection floods and half-open SYN floods**
with threshold rules, and **automatically blocks the attacker** by installing a drop flow
on the switch.

> Read **GUIDE.md** for the problem statement, concepts, how it works, the demo script for
> your teacher and viva questions. This README is only "install and run".

## Files

| File | What it does |
|---|---|
| `setup.sh` | One-time install of everything (Ubuntu 22.04 / 24.04) |
| `ids_controller.py` | The IDS: learning switch + Monitor + Detector + Responder |
| `topology.py` | Mininet network: h1 client, h2 attacker, h3 server, s1 switch |
| `server.py`, `client.py` | Normal TCP socket traffic (server on h3, client on h1) |
| `attacks.sh`, `rapid_connect.py` | Attack scripts (scan, SYN floods, rapid connections) |
| `plot_results.py` | Makes `results.png` (connection rate + block markers) from the logs |
| `logs/` | Created by the controller: `events.csv` (alerts), `syn_events.csv`, `flow_stats.csv` |

## Verification status (be honest in your report)

The controller was tested **without Mininet** by (a) a simulated switch with a fake clock
(normal traffic, port scan, fast flood, slow flood, half-open flow stats, whitelist, recovery
all behaved as designed) and (b) a fake OpenFlow 1.3 switch connected over TCP to the real
running controller (handshake, table-miss, forwarding flows, drop flow with correct match,
priority, 60 s timeout and no actions, stats polling). Mininet/nmap/hping3 themselves have not
been run in that test, so do the first real run early and tune thresholds if needed.

## Install (once)

```bash
cd ~/cn_project25        # the folder with these files
bash setup.sh            # asks for your sudo password, takes a few minutes
```

Important: the controller is installed in a virtualenv with **os-ken pinned to 3.1.1**
(os-ken 4.x removed the `osken-manager` command). Plain `pip3 install ryu` often breaks on
Ubuntu 22.04/24.04, so don't use it.

## Run (4 terminals, all inside the project folder)

**Terminal 1: controller (start this first)**
```bash
cd ~/cn_project25
~/ids-venv/bin/osken-manager ids_controller.py
```

**Terminal 2: network**
```bash
cd ~/cn_project25
sudo mn -c                       # clean old Mininet state
sudo -E python3 topology.py      # -E keeps your DISPLAY so xterm works
```
Terminal 1 should now print `Switch 1 connected, table-miss installed`.

Quick sanity check at the `mininet>` prompt:
```
mininet> h1 ping -c 2 h3
mininet> h1 python3 client.py --count 3        # 3 x OK
```

**Terminal 3: the switch flow table (the "proof")**
```bash
watch -n1 "sudo ovs-ofctl -O OpenFlow13 dump-flows s1"
```

**Terminal 4: packets arriving at the victim (h3's switch port is s1-eth3)**
```bash
sudo tcpdump -i s1-eth3 -n 'tcp[tcpflags] & tcp-syn != 0'
```
(or `sudo wireshark &` and capture on `s1-eth3`; capture on `lo` with filter `openflow_v4`
to see the controller talking to the switch)

### Running commands on h1 / h2

Option A (windows): at `mininet>` type `xterm h1 h2`, then type commands in those windows.
If xterm says "can't open display", run `xhost +local:root` in a normal terminal first.

Option B (no windows needed): use the Mininet prompt directly
```
mininet> h2 bash attacks.sh scan
mininet> h1 python3 client.py --count 5
```
For a continuously running client: `mininet> h1 python3 client.py > /tmp/h1.log 2>&1 &`
and watch it in another terminal with `tail -f /tmp/h1.log`.

## Demo commands

| Step | Command | Expected |
|---|---|---|
| Normal traffic | `h1 python3 client.py --count 10` | `OK` lines, no alert in Terminal 1 |
| Port scan | `h2 bash attacks.sh scan` | `ALERT PORT_SCAN from 10.0.0.2 ... BLOCKING`; flow table shows `priority=100,ip,nw_src=10.0.0.2 actions=drop` |
| Prove the block | `h2 python3 client.py --count 3` and `h2 ping -c 3 10.0.0.3` | FAIL / 100% loss |
| Legit user fine | `h1 python3 client.py --count 3` | still `OK` |
| Recovery | wait 60 s, then `h2 python3 client.py --count 3` | rule disappears, `OK` again |
| Fast SYN flood | `h2 bash attacks.sh syn-fast` | `ALERT HIGH_CONN_RATE` |
| Rapid real connections | `h2 bash attacks.sh rapid` | `ALERT HIGH_CONN_RATE` |
| Slow SYN flood | `h2 bash attacks.sh syn-slow` | `ALERT HALF_OPEN_SYN_FLOOD` within about 5 s |
| Graph | `python3 plot_results.py` (after exiting Mininet) | creates `results.png` |

Wait for the 60 s block to expire between attacks (the controller keeps its own record of the
block, so deleting the flow by hand does not unblock the host; restart the controller if you
are in a hurry).

## Detection rules (edit `CONFIG` at the top of `ids_controller.py`)

| Rule | Trigger | Data source |
|---|---|---|
| PORT_SCAN | >= 15 distinct dst ports from one IP within 5 s | packet-in |
| HIGH_CONN_RATE | >= 50 new connections from one IP within 2 s | packet-in |
| HALF_OPEN_SYN_FLOOD | >= 20 flows to one dst:port that carried <= 1 packet | flow stats, polled every 3 s |

Whitelist: h1 (10.0.0.1) and h3 (10.0.0.3) are never blocked. Block = drop flow,
priority 100, hard timeout 60 s.

## Troubleshooting

| Problem | Fix |
|---|---|
| `osken-manager: command not found` | Use the full path `~/ids-venv/bin/osken-manager`, or rerun `setup.sh` |
| Terminal 1 never says "Switch 1 connected" | Start the controller first; check `sudo ovs-vsctl show` and that port 6653 isn't taken (`sudo ss -ltnp | grep 6653`) |
| `mn` complains about existing state / stuck | `sudo mn -c`, then start again |
| `h1 ping h3` fails | Controller not connected yet (wait 3 s) or controller crashed: read Terminal 1 |
| xterm "can't open display" | `xhost +local:root`, then use `sudo -E python3 topology.py`; or use Option B |
| Scan/flood not detected | Look at `logs/syn_events.csv` (is it filling?). Lower `scan_ports` / `rate_conns` in CONFIG |
| Normal traffic blocked | Raise thresholds; check the whitelist set in CONFIG |
| `PermissionError` on `logs/` | `sudo chown -R $USER:$USER ~/cn_project25`, rerun the controller as your normal user (not sudo) |
| VM/laptop freezes during flood | Never use `hping3 --flood`; use the scripted rates only |
| Packets seem to bypass the controller | `sudo ovs-vsctl get bridge s1 protocols` must show `OpenFlow13` |

Use this only inside your own Mininet lab.
