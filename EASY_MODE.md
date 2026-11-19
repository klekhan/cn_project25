# EASY MODE: one terminal, one command

No 5 panes. No Ryu install (OS-Ken, already working on your laptop, is the maintained Ryu and runs the same code).
`auto_demo.py` starts the controller, builds the network, runs the normal traffic and all the attacks, and prints
what happened after every step. It **pauses after each step** so you can take a screenshot, then you press Enter.

## 1. Put the new files in the project folder (once)

Download these 3 files and drop them into **Linux > Ubuntu > home > klekh > cn_project25** in Windows Explorer:
- `auto_demo.py` (new)
- `ids_controller.py` (replace the old one: only one line changed, so the demo can use a shorter block time)
- `EASY_MODE.md` (this file)

## 2. Run it

Open **one** Ubuntu terminal, maximize it, and make the text a bit smaller (Ctrl + mouse wheel down):

```bash
cd ~/cn_project25
sudo -v
sudo python3 auto_demo.py
```
Type your password if asked. That's it. The whole demo takes about 4 minutes (plus however long you spend on screenshots).

- Block time is 30 s by default to keep it short. For the real 60 s: `sudo python3 auto_demo.py --block 60`
- To record a video without pauses: `sudo python3 auto_demo.py --auto`
- Stop any time with **Ctrl+C**. It cleans up by itself.

## 3. What you will see (and what to say)

Each step is a coloured banner. Yellow `>>` lines explain; grey `---` lines are the evidence.

| Step | What the script does | Evidence it prints | Say this |
|---|---|---|---|
| **Setup** | Starts the controller, builds h1/h2/h3 + switch | "Switch 1 connected", the links, the flow table with only the table-miss rule | "Switch connected to the controller. It only has one rule: send unknown packets to the controller." |
| **1 Normal traffic** | h1 sends 5 requests, then keeps running in the background | Controller alerts: none | "Normal traffic, no false positives." |
| **2 Port scan** | h2 runs nmap on ports 1-200 | **ALERT PORT_SCAN**, the **drop rule** in the switch, and how many SYNs actually reached the victim | "The controller detected the scan and pushed a drop rule. Only a few SYNs reached the victim before the block." |
| **3 Prove the block** | h2 tries to connect and ping | h2 FAIL / 100% loss, **h1 still OK**, drop rule packet counter | "Only the attacker is blocked. The normal user is fine." |
| **4 Log** | Prints `events.csv` | rule, source, **detect_latency_s** | "Every decision is logged, including detection time." |
| **5 Recovery** | Waits for the block to expire | Rule gone, h2 connects again | "The block is temporary so mistakes heal themselves." |
| **6 Fast SYN flood** | 100 SYN/s to port 5000 | **ALERT HIGH_CONN_RATE** + drop rule | "Too many new connections per second." |
| **7 Slow SYN flood** | 10 SYN/s, never completing | **ALERT HALF_OPEN_SYN_FLOOD** + drop rule | "Too slow for the rate rule, so it's caught from the switch's flow statistics." |
| **8 Summary** | Prints all events and makes the graph | events.csv, `results.png` created | "Everything is logged and graphed." |

## 4. Screenshots (9 + 1)

The script tells you when: it prints **[SCREENSHOT NOW] S#** and waits for Enter. Use **Win + PrtSc** (saves a file automatically in Pictures\Screenshots), or Win + Shift + S for an area. If a step's output is longer than your screen, scroll up and take two shots.

| # | Printed as | What's in it |
|---|---|---|
| S0 | topology + controller connected | "Switch 1 connected", links, table-miss rule |
| S1 | normal traffic OK, no alert | h1 OK lines + "none: no false positives" |
| S2 | ALERT + drop rule + SYNs reached victim | the controller's PORT_SCAN decision and the `priority=100 ... actions=drop` line |
| S3 | h2 fails, h1 still OK | FAIL lines, 100% loss, h1 OK |
| S4 | events.csv with detection time | the CSV row |
| S5 | rule expired, h2 works again | "none: the switch removed the rule", h2 OK |
| S6 | HIGH_CONN_RATE alert | alert + drop rule |
| S7 | HALF_OPEN_SYN_FLOOD alert | alert + drop rule |
| S8 | summary and graph message | all events |
| S9 | the graph | after the script ends: `explorer.exe results.png` in Ubuntu |

## 5. After the demo: save your evidence

```bash
cd ~/cn_project25
explorer.exe .
```
Copy the **logs** folder and **results.png** into your CN folder in Windows, along with your screenshots.
Also `logs/controller.out` is the controller's own console log (all ALERT lines), good to attach to the report.

## 6. If something fails

| Message / problem | Do this |
|---|---|
| `Run it like this, from your normal user` | Use exactly `sudo python3 auto_demo.py` (don't log in as root) |
| `Controller not found ... Run: bash setup.sh` | `cd ~/cn_project25 && bash setup.sh` |
| `Controller did not start` or `Switch did not connect` | `tail -30 logs/controller.out` and send me the output |
| `NO ALERT` in a step | Tell me which step, and send `tail -30 logs/controller.out` plus `cat logs/syn_events.csv \| tail` |
| Anything weird / leftover state | `sudo mn -c`, `pkill -f osken-manager`, run again |
| No such module `mininet` | You ran it with the venv active. Open a fresh terminal and run it again |

## 7. Backup: manual way with only 2 terminals

**Terminal A**
```bash
cd ~/cn_project25
~/ids-venv/bin/osken-manager ids_controller.py
```
**Terminal B**
```bash
cd ~/cn_project25
sudo service openvswitch-switch start
sudo mn -c
sudo python3 topology.py
```
At the `mininet>` prompt you can see everything without extra windows:
```
h1 python3 client.py --count 3
h2 bash attacks.sh scan
sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100
h2 python3 client.py --count 3
sh cat logs/events.csv
```
The ALERT lines show in Terminal A.
