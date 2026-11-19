"""
CN Project 25 - Network Intrusion Detection and Response (SDN + TCP)
Ryu / OS-Ken controller app, OpenFlow 1.3.

Modules (all in this file so it is easy to run):
  1. MONITOR   - packet-in handler counts new TCP connections (SYN-only packets)
                 per source IP; a polling thread collects flow statistics.
  2. DETECTOR  - threshold rules (see CONFIG below).
  3. RESPONDER - installs a high-priority DROP flow for the attacker with a
                 hard timeout, logs every event to logs/events.csv.

Run:  ryu-manager ids_controller.py        (or: osken-manager ids_controller.py)
"""
import csv
import os
import time
from collections import defaultdict, deque

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                        DEAD_DISPATCHER, set_ev_cls)
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, ether_types
    from ryu.lib import hub
except ImportError:  # OS-Ken (maintained fork of Ryu)
    from os_ken.base import app_manager
    from os_ken.controller import ofp_event
    from os_ken.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                           DEAD_DISPATCHER, set_ev_cls)
    from os_ken.ofproto import ofproto_v1_3
    from os_ken.lib.packet import packet, ethernet, ipv4, tcp, ether_types
    from os_ken.lib import hub

# --------------------------------------------------------------------------
# CONFIG: all thresholds live here. Tune them and report the effect.
# --------------------------------------------------------------------------
CONFIG = {
    # Rule 1: PORT_SCAN - one source hits >= scan_ports distinct (dst, port)
    #         targets within `window` seconds.
    'window': 5.0,
    'scan_ports': 15,
    # Rule 2: HIGH_CONN_RATE - one source opens >= rate_conns new connections
    #         within `rate_window` seconds.
    'rate_window': 2.0,
    'rate_conns': 50,
    # Rule 3: HALF_OPEN (SYN flood, from flow stats) - one source has
    #         >= halfopen_flows live flows to the same dst:port that carried
    #         <= 1 packet (SYN seen, handshake never completed).
    'halfopen_flows': 20,
    # Flow statistics polling period (seconds)
    'poll_interval': 3,
    # Response
    'block_seconds': int(os.environ.get('IDS_BLOCK_SECONDS', 60)),   # hard timeout of the drop rule
    'flow_idle_timeout': 5,       # idle timeout of per-connection forward flows
    # Never block these (legit client h1 and server h3)
    'whitelist': {'10.0.0.1', '10.0.0.3'},
}

PRIO_FORWARD = 10    # per-connection TCP forwarding flows
PRIO_BLOCK = 100     # drop rules (must beat forwarding rules)
LOG_DIR = 'logs'


# Ryu calls its base class RyuApp, OS-Ken renamed it OSKenApp
AppBase = getattr(app_manager, 'RyuApp', None) or app_manager.OSKenApp


class IDSController(AppBase):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IDSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.history = defaultdict(deque)   # src_ip -> deque[(ts, dst, dport)]
        self.blocked = {}                   # src_ip -> expiry epoch

        os.makedirs(LOG_DIR, exist_ok=True)
        self._f_ev = open(os.path.join(LOG_DIR, 'events.csv'), 'w', newline='')
        self._w_ev = csv.writer(self._f_ev)
        self._w_ev.writerow(['epoch', 'time', 'src_ip', 'rule', 'detail',
                             'action', 'detect_latency_s'])
        self._f_syn = open(os.path.join(LOG_DIR, 'syn_events.csv'), 'w', newline='')
        self._w_syn = csv.writer(self._f_syn)
        self._w_syn.writerow(['epoch', 'src_ip', 'dst_ip', 'dst_port'])
        self._f_st = open(os.path.join(LOG_DIR, 'flow_stats.csv'), 'w', newline='')
        self._w_st = csv.writer(self._f_st)
        self._w_st.writerow(['epoch', 'src_ip', 'flows', 'packets', 'bytes',
                             'max_halfopen_to_one_target'])

        self.poller = hub.spawn(self._poll_loop)

    # ------------------------------------------------------------------
    # Switch connection handling
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # Table-miss: send everything unknown to the controller (full packet)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        self.logger.info('Switch %s connected, table-miss installed', dp.id)

    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle,
                                hard_timeout=hard)
        dp.send_msg(mod)

    # ------------------------------------------------------------------
    # MONITOR: packet-in
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # Simple L2 learning
        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)
        if ip is not None and t is not None:
            is_syn = bool(t.bits & tcp.TCP_SYN) and not (t.bits & tcp.TCP_ACK)
            if is_syn:
                self._on_syn(ip.src, ip.dst, t.dst_port)

            # Source got blocked (now or earlier): do not forward anything
            if self._is_blocked(ip.src):
                return

            # Per-connection forwarding flow. Matching on the TCP ports means
            # every NEW connection / new port produces a packet-in, which is
            # how we "see" connection attempts (OpenFlow 1.3 cannot match flags).
            if out_port != ofp.OFPP_FLOOD:
                match = parser.OFPMatch(
                    in_port=in_port, eth_src=eth.src, eth_dst=eth.dst,
                    eth_type=0x0800, ip_proto=6,
                    ipv4_src=ip.src, ipv4_dst=ip.dst,
                    tcp_src=t.src_port, tcp_dst=t.dst_port)
                self._add_flow(dp, PRIO_FORWARD, match, actions,
                               idle=CONFIG['flow_idle_timeout'])
        # NOTE: non-TCP traffic (ARP, ICMP) is only packet-out'd, never given
        # a flow, so it can never hide TCP packets from the controller.

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    # ------------------------------------------------------------------
    # DETECTOR (packet-in based rules)
    # ------------------------------------------------------------------
    def _on_syn(self, src, dst, dport):
        now = time.time()
        self._w_syn.writerow(['%.3f' % now, src, dst, dport])
        self._f_syn.flush()

        if src in CONFIG['whitelist'] or self._is_blocked(src):
            return

        h = self.history[src]
        h.append((now, dst, dport))
        while h and now - h[0][0] > CONFIG['window']:
            h.popleft()

        # Rule 1: port scan
        targets = {(d, p) for _, d, p in h}
        if len(targets) >= CONFIG['scan_ports']:
            self._block(src, 'PORT_SCAN',
                        '%d distinct ports in %.1fs' % (len(targets), CONFIG['window']),
                        attack_start=h[0][0])
            return

        # Rule 2: high connection rate
        recent = [ts for ts, _, _ in h if now - ts <= CONFIG['rate_window']]
        if len(recent) >= CONFIG['rate_conns']:
            self._block(src, 'HIGH_CONN_RATE',
                        '%d new connections in %.1fs' % (len(recent), CONFIG['rate_window']),
                        attack_start=recent[0])

    # ------------------------------------------------------------------
    # MONITOR: flow statistics polling + stats-based rule (half-open)
    # ------------------------------------------------------------------
    def _poll_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(CONFIG['poll_interval'])

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        now = time.time()
        per_src = {}
        for st in ev.msg.body:
            if st.priority != PRIO_FORWARD:
                continue
            f = dict(st.match.items())
            if 'ipv4_src' not in f:
                continue
            e = per_src.setdefault(f['ipv4_src'], {
                'flows': 0, 'packets': 0, 'bytes': 0,
                'half': defaultdict(int)})
            e['flows'] += 1
            e['packets'] += st.packet_count
            e['bytes'] += st.byte_count
            # Handshake never completed: the SYN went via packet-out, so a
            # flow that carried <= 1 further packet is a half-open attempt.
            if st.packet_count <= 1:
                e['half'][(f.get('ipv4_dst'), f.get('tcp_dst'))] += 1

        for src, e in per_src.items():
            worst = max(e['half'].values()) if e['half'] else 0
            self._w_st.writerow(['%.3f' % now, src, e['flows'], e['packets'],
                                 e['bytes'], worst])
            self._f_st.flush()
            if src in CONFIG['whitelist'] or self._is_blocked(src):
                continue
            # Rule 3: half-open / SYN flood
            for target, cnt in e['half'].items():
                if cnt >= CONFIG['halfopen_flows']:
                    self._block(src, 'HALF_OPEN_SYN_FLOOD',
                                '%d half-open flows to %s:%s' % (cnt, target[0], target[1]))
                    break

    # ------------------------------------------------------------------
    # RESPONDER
    # ------------------------------------------------------------------
    def _is_blocked(self, src):
        exp = self.blocked.get(src)
        if exp is None:
            return False
        if time.time() < exp:
            return True
        del self.blocked[src]
        self.history.pop(src, None)
        self._log_event(src, 'BLOCK_EXPIRED', 'hard timeout reached', 'UNBLOCK', '')
        return False

    def _block(self, src, rule, detail, attack_start=None):
        if self._is_blocked(src):
            return
        now = time.time()
        self.blocked[src] = now + CONFIG['block_seconds']
        latency = '%.3f' % (now - attack_start) if attack_start else ''
        for dp in list(self.datapaths.values()):
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src)
            # No instructions = DROP. Higher priority than forwarding flows.
            mod = parser.OFPFlowMod(datapath=dp, priority=PRIO_BLOCK,
                                    match=match, instructions=[],
                                    hard_timeout=CONFIG['block_seconds'])
            dp.send_msg(mod)
        self.logger.warning('ALERT %s from %s (%s) -> BLOCKING for %ds',
                            rule, src, detail, CONFIG['block_seconds'])
        self._log_event(src, rule, detail, 'BLOCK', latency)

    def _log_event(self, src, rule, detail, action, latency):
        now = time.time()
        self._w_ev.writerow(['%.3f' % now, time.strftime('%H:%M:%S'), src,
                             rule, detail, action, latency])
        self._f_ev.flush()
