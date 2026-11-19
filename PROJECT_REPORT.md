# Network Intrusion Detection and Response using SDN

**Computer Networks Project 25 (TCP) — Project Report**  
**November 2026**

| Name | SRN |
|---|---|
| Lekhan K | PES1UG25AM495 |
| Kushi Reddy | PES1UG25AM489 |
| Girish B | PES1UG25AM484 |

> This is a text-format version of the submitted Word report. The original report's terminal screenshots and graph are not embedded in this GitHub-rendered Markdown copy.

1. Aim The assignment for project 25 says: develop an intrusion-detection prototype that analyzes TCP socket traffic, identifies predefined abnormal behaviors and dynamically responds by modifying SDN forwarding rules. In this project we built a small software-defined network in Mininet. A controller program watches the TCP connections going through the switch. When it sees a port scan or a SYN flood it decides that the source is an attacker and installs a drop rule in the switch for that source. No person has to type anything. Normal users keep working while the attacker is blocked, and the block is removed by itself after a fixed time.

2. Background
2.1 TCP and the three attacks we used
A TCP connection starts with a three-step handshake. The client sends a SYN, the server
answers with SYN-ACK, and the client finishes with an ACK. If the port is closed the server
answers with RST instead. A connection where the SYN was sent but the last ACK never came
is called half-open.
- Port scan: the attacker sends SYN packets to many different ports to find which services
are open.
- Connection flood (fast SYN flood): the attacker opens connections at a very high rate to
overload the server.
- Half-open (slow) SYN flood: the attacker sends SYNs but never completes the
handshake. The server keeps waiting for each one. The rate can be low, so a simple rate
check can miss it.

2.2 SDN and OpenFlow In a normal switch the same device decides where a packet goes and also forwards it. In SDN these two jobs are separated. The switch (data plane) only forwards packets by following a table of flow rules. The controller (control plane) is a normal program that decides what the rules should be and sends them to the switch using OpenFlow. Because the controller is just a program, it can read what is happening in the network and change the rules at once. The OpenFlow messages and terms we used:

```text
Term                    What it means here
 Table-miss rule         Priority 0 rule. If no other rule matches, send the packet to the controller.
                         It is the only rule at the start.
 Packet-In               Switch to controller: "I have no rule for this packet, here it is". We see
                         every new connection this way.
 Packet-Out              Controller to switch: "send this packet out of port X".
 Flow-Mod                Controller to switch: add or delete a rule. Used for forwarding rules and
                         for the drop rule.
```

```text
Term                            What it means here
 Flow statistics                 The switch reports packet and byte counters for each rule. We ask for
                                 them every 3 seconds.
 Priority                        The matching rule with the highest priority wins. Block 100, forwarding
                                 10, table-miss 0.
 Idle / hard timeout             Idle: the rule is removed if it is not used for N seconds. Hard: removed N
                                 seconds after it was created.
 Drop rule                       A rule with no actions. The switch discards every packet that matches it.
```

3. Setup 3.1 Network Everything runs on one laptop (Ubuntu under WSL). Mininet creates three virtual hosts and one Open vSwitch switch. The switch connects to the controller at 127.0.0.1, port 6653, using OpenFlow 1.3. The controller is written for OS-Ken, which is the maintained fork of Ryu.

```text
Host                IP address                   Role
 h1                  10.0.0.1                     Normal user. Runs client.py, one request per second.
 h2                  10.0.0.2                     Attacker. Runs nmap and hping3.
 h3                  10.0.0.3                     Victim. Runs server.py, a TCP echo server on port 5000,
                                                  and a web server on port 80.
 s1                  -                            Open vSwitch, OpenFlow 1.3, connected to the
                                                  controller.
```

```text
3.2 Files
 File                              Purpose
 ids_controller.py                 The controller: monitor, detector and responder.
 topology.py                       Builds the Mininet network and starts the servers on h3.
 server.py / client.py             Our own TCP socket programs. Server echoes what the client sends.
                                   The client prints OK or FAIL for every request.
 rapid_connect.py                  Opens many real TCP connections quickly (connection flood with
                                   sockets).
 attacks.sh                        The controlled attacks: nmap scan, fast and slow hping3 SYN floods.
 auto_demo.py                      Runs the whole demo in one terminal and prints what happens after
                                   each step.
 plot_results.py                   Draws the graph from the log files.
```

4. How the controller works The controller has three parts, all in ids_controller.py.

Monitor. Every new TCP connection is a new flow, so the switch sends its first packet to the controller (Packet-In). The controller notes the source IP, destination IP and port of every SYN packet and writes it to syn_events.csv. It then installs a forwarding rule for that connection with priority 10 and an idle timeout of 5 seconds, and forwards the first packet itself with Packet-Out. A second thread asks the switch for flow statistics every 3 seconds and writes the totals per source to flow_stats.csv. Detector. Three threshold rules, all in one CONFIG block at the top of the file so they are easy to change.

```text
Rule                    Condition                                    Data used
 PORT_SCAN               One source sends SYNs to 15 or more          Packet-In
                         different ports within 5 seconds
 HIGH_CONN_RATE          One source opens 50 or more new              Packet-In
                         connections within 2 seconds
 HALF_OPEN_SYN_FL        One source has 20 or more flows to the       Flow statistics
 OOD                     same ip:port that carried at most 1
                         packet
```

The half-open rule works because a normal connection sends several packets (handshake, data, close), so its flow counter goes above 1. A half-open attempt stays at 1 or 0. Responder. When a rule fires, the controller sends a Flow-Mod that matches all IPv4 packets from the attacker address, has priority 100 and no actions, with a hard timeout (30 seconds in the demo, 60 by default). Priority 100 is higher than the forwarding rules, so the drop rule wins. After the timeout the switch removes the rule by itself and the controller logs BLOCK_EXPIRED. Every decision is written to events.csv with the time and the detection latency. Hosts h1 and h3 are on a whitelist and are never blocked.

5. Experiments and observations All screenshots come from one run of auto_demo.py on 18 November 2026. The block time was 30 seconds.

### 5.1 Start of the demo

_Figure 1: Network created, controller connected, only the table-miss rule in the switch_

The switch connected to the controller ("Switch 1 connected, table-miss installed"). The links are h1-s1, h2-s1 and h3-s1. The flow table has one rule only, priority 0 with action CONTROLLER, so every first packet goes to the controller. The line "Unable to contact the remote controller" appears for a moment while Mininet starts, before the controller connection is made. It disappears once the switch connects.

### 5.2 Step 1: normal traffic

_Figure 2: h1 sends 5 requests to the server_

All 5 requests worked with response times between 8.2 ms and 21.9 ms. The controller raised no alert, so there were no false positives for normal traffic of about one connection per second.

### 5.3 Step 2: port scan

_Figure 3: nmap scan of ports 1 to 200 from h2, and the controller decision_

h2 ran nmap -sS -Pn -p 1-200 -T4 against h3. The controller logged ALERT PORT_SCAN from 10.0.0.2 with 15 distinct ports in 5.0 seconds and started blocking for 30 seconds. The detection latency in events.csv is 0.018 seconds, counted from the first SYN of the scan. The scan was slowed down by the block. A normal nmap scan of 200 ports on a local network finishes in a few seconds, but here it took 30.54 seconds because the switch dropped the probes and nmap kept retrying. Only 20 of the roughly 200 probes reached the victim (counted with tcpdump on h3). The rest were dropped at the switch. One thing to note. The demo printed "(none)" for the drop rule in this step. The reason is that the scan itself lasted 30 seconds, so by the time the script looked at the flow table the 30 second block had already expired (the block was logged at 13:31:48 and expired at 13:32:18). The drop rule is shown properly in Figures 7 and 8.

### 5.4 Step 3: after the block

_Figure 4: h2 and h1 after the first block had expired_

This step was meant to show h2 failing. It did not fail, because it ran at 13:32:22, four seconds after the block expired. h2 got 3 OK replies and the ping had 0% packet loss. This matches the

expiry in the log. h1 kept getting OK replies the whole time (requests #41 to #44), so the normal user was not affected by the attack or by the block. The blocking itself is shown in Step 6.

### 5.5 Step 4: the decision log

_Figure 5: events.csv after the port scan_

The log shows the PORT_SCAN block at 13:31:48 and BLOCK_EXPIRED at 13:32:18. The difference is 30 seconds, which is the hard timeout we set.

### 5.6 Step 5: automatic recovery

_Figure 6: the rule is gone and h2 can connect again_

After the timeout no drop rule was left in the switch. The switch removed it without any command from the controller or from us. h2 connected three times with replies in 7 to 13 ms.

### 5.7 Step 6: fast SYN flood

_Figure 7: hping3 flood at about 100 SYN per second, alert and drop rule_

hping3 sent 1000 SYN packets at 100 per second to port 5000 of h3. The controller raised HIGH_CONN_RATE (50 new connections in 2.0 seconds) with a detection latency of 0.501 seconds. The drop rule in the switch is: priority=100,ip,nw_src=10.0.0.2 actions=drop hard_timeout=30, n_packets=950, n_bytes=51300

The counter n_packets=950 is the number of packets the switch discarded. Out of 1000 packets sent, only 49 got a reply, a packet loss of 96%. So about 50 packets got through before the block, which matches the threshold of 50. The block did its job.

### 5.8 Step 7: slow SYN flood

_Figure 8: slow half-open flood detected from flow statistics_

Here hping3 sent only 10 SYN per second and never completed the handshake. This is too slow for the rate rule (50 in 2 seconds), so it was not caught by Packet-In counting. The flow statistics poll saw 23 flows from 10.0.0.2 to 10.0.0.3:5000, each with one packet, and the controller raised HALF_OPEN_SYN_FLOOD. The drop rule was installed straight away (duration 0.249 s in the dump). The matching line in flow_stats.csv is: flows=23, packets=23, max_halfopen_to_one_target=23. There is no detection latency value for this rule in events.csv. The rule works from the 3 second statistics poll and not from the first attack packet, so the time depends on when the poll happens.

### 5.9 Step 8: summary

_Figure 9: all decisions, flow statistics sample and graph saved_

```text
6. Results
 Attack              Rule that fired     Trigger value        Latency            Block time
 nmap port scan,     PORT_SCAN           15 ports in 5.0 s    0.018 s            30 s
 ports 1-200
 hping3 about 100    HIGH_CONN_R         50 connections in    0.501 s            30 s
 SYN/s               ATE                 2.0 s
 hping3 about 10     HALF_OPEN_S         23 half-open         not recorded (3    30 s
 SYN/s               YN_FLOOD            flows                s poll)
```

```text
Measurement                                            Value
 Normal client response time                            8.2 to 23.4 ms
 False alerts on normal traffic                         0
 Probes of the scan that reached the victim             20 of about 200
 Fast flood packets dropped by the switch               950 of 1000 (96% loss)
 Packets that got through before the block (fast        about 50
 flood)
 Time from block to automatic unblock                   30 s (13:31:48 to 13:32:18)
 Flow statistics polling interval                       3s
 Normal client rate (graph)                             1 new connection per second
```

_Figure 10: new TCP connections per second for each source, with the block points_

In the graph h1 (blue) stays at 1 connection per second the whole time. h2 (orange) shows up in bursts: 30 per second during the scan, 50 per second during the fast flood and 10 per second during the slow flood. Red dashed lines are blocks and green dashed lines are the automatic unblocks. The five events in order were: PORT_SCAN block at 6.8 s, unblock at 37.1 s, HIGH_CONN_RATE block at 61.4 s, unblock at 95.3 s, HALF_OPEN_SYN_FLOOD block at 97.6 s.

```text
7. Assignment tasks and where they are done
 Task in the assignment                      What we did
 Generate controlled TCP security-test       server.py and client.py for normal traffic; nmap and hping3
 traffic                                     for scan and floods, only inside Mininet.
 Monitor connection rates                    Packet-In handler records every SYN and counts per source
                                             in a sliding window.
```

```text
Task in the assignment                   What we did
 Collect flow statistics                  OpenFlow flow-stats request every 3 seconds; totals saved in
                                          flow_stats.csv.
 Define intrusion-detection rules         Three threshold rules in CONFIG: port scan, high
                                          connection rate, half-open flood.
 Detect abnormal connection behavior      All three attacks were detected (Figures 3, 7, 8). No alert for
                                          normal traffic (Figure 2).
 Simulate controlled scanning             nmap SYN scan of ports 1 to 200 from h2 against h3 (Step
                                          2).
 Dynamically block suspicious             Controller pushes a priority-100 drop Flow-Mod for the
 sources                                  attacker IP with a hard timeout (Figure 7: 950 packets
                                          dropped).
```

8. Limitations
- The thresholds (15 ports, 50 connections, 20 half-open flows) were chosen by us for this
small network. A real network would need tuning. If they are too low, normal users get
blocked. If they are too high, attacks are missed.
- A very slow scan (for example one port every 10 seconds) stays under the 5 second
window and would not be detected.
- The block is by source IP. An attacker who spoofs or changes the IP is not stopped, and
spoofing someone else's IP could get that person blocked.
- The controller sees only the first packet of each connection, so the detection is about
connection behavior and not about packet contents.
- The half-open rule depends on the 3 second poll, so it reacts more slowly than the packet-
in rules.
- h1 and h3 are whitelisted. This is a lab choice so that the demo is stable.
- There is only one switch, and the demo runs in a simulation, not on real hardware.
- In our run the Step 2 and Step 3 screenshots did not show the drop rule or a failing h2
because the 30 second block had already expired. The blocking is proven by the numbers
in Step 2 (20 of 200 probes) and Step 6 (950 packets dropped).

9. Conclusion The prototype detected all three attack types in the lab and blocked the attacker automatically by changing the forwarding rules of the switch, without any manual command. The port scan was caught in 0.018 seconds and the fast flood in 0.501 seconds, and the slow flood was caught from flow statistics, which a simple rate check would have missed. Normal traffic from h1 was never affected and no false alerts came up. The blocks ended by themselves after 30 seconds. The main thing we learned is that SDN makes this kind of response easy, because the same program can watch the traffic and rewrite the switch rules.
