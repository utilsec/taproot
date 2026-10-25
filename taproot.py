#!/usr/bin/env python3
"""
============================================================
TAPROOT - TAP Record Offline Observation Tool (v1.1.1)
============================================================

Passive capture analyst. Point it at a .pcap / .pcapng file - or, since v1.1,
at a network interface on a SPAN/mirror port or TAP - and it prints who was on
the wire: every IP address, every MAC address (with vendor), the
hostnames devices announced about themselves, and the TCP/UDP ports each host
was communicating on - separated into ports the host actually ANSWERED on and
ports that were merely addressed.

Why the separation matters: a capture is evidence, not a scan. A port that only
ever appears as a destination proves somebody tried, not that anything is
listening. TAPROOT labels the two differently so a finding that lands in an
assessment report can be defended:

  SERVING     the host answered - TCP SYN/ACK seen from it, or a two-way
              conversation on that port
  RESPONDING  UDP: the host sent traffic back from that port to a peer that
              had addressed it
  REFUSED     the host answered with RST, or sent an ICMP port unreachable -
              the host is up and that port is closed
  OBSERVED    addressed only, no reply in this capture - suspected, not proven

When the capture starts mid-conversation there is no handshake to prove which
end is the server, so the role is inferred from the port numbers and the
evidence string says "(role inferred)". Ephemeral source ports are ruled out
first, because FL-net (55000), DNP3 (20000) and EtherNet/IP I/O (2222) all sit
inside the range operating systems hand out to clients.

TAPROOT TRANSMITS NOTHING. In file mode it opens a file, never a socket. That
makes it the one assessment step that is always authorised on a production
control network: if you can get a SPAN/mirror or TAP capture off the segment,
the whole analysis happens somewhere else, on a laptop, with zero packets on
the plant wire.

Live mode (--live) opens a RECEIVE-ONLY capture handle on an interface and
builds the same inventory as packets arrive, printing each new host, answering
port, announced name and Modbus write the moment it is seen. With --map it also
serves taproot.html on 127.0.0.1 and draws the network map in the browser as
traffic is detected. TAPROOT still never sends a frame - but the operating
system WILL, on any NIC that has an IP address (DHCP, NetBIOS/LLMNR, IPv6
neighbour discovery, connectivity checks). On a control network, capture from a
dedicated USB NIC on a SPAN port or passive TAP with IPv4/IPv6 unbound from it.
A NIC on an ordinary switch port only sees broadcast, multicast and its own
traffic.

Live capture backends, best first - all standard library, no pip:
  Npcap (Windows) / libpcap (Linux, macOS) through ctypes - full frames, BPF
      filter, drop counters. Npcap comes with Wireshark.
  AF_PACKET (Linux) - full frames, no filter, VLAN tags stripped by the kernel.
  Windows raw socket - DEGRADED: IPv4 only, no MACs/ARP/LLDP/CDP/DCP, and the
      NIC must carry an IP address.

What it decodes
  Link     Ethernet II, 802.1Q / QinQ VLAN tags, 802.3 LLC/SNAP, Linux SLL /
           SLL2, raw IPv4/IPv6, BSD loopback
  L2/disc  ARP (incl. gratuitous & probes), LLDP, CDP, PROFINET DCP, STP
  L3/L4    IPv4, IPv6 (with extension-header walk), TCP (flags/handshake), UDP,
           ICMP / ICMPv6, plus ICMP unreachable mined for closed UDP ports
  Identity DHCP (MAC, requested/assigned IP, hostname, vendor class), NBNS,
           mDNS / LLMNR
  OT/ICS   Modbus TCP, S7comm, DNP3, EtherNet/IP & CIP, BACnet/IP, OPC UA,
           IEC 60870-5-104, PROFINET RT, Niagara Fox, FL-net, MELSEC, FINS and
           more named on sight; Modbus function codes counted, so READ vs WRITE
           traffic to a controller is called out explicitly
  Vendors  Longest-prefix MAC vendor lookup (/36 MA-S & IAB > /28 MA-M > /24
           MA-L) from a local OUI database - the same three-tier logic and the
           same database file as AtomICS (formerly OT RUNG)

Formats: pcap (both endiannesses, microsecond and nanosecond), pcapng
(multiple sections, per-interface link types and timestamp resolution), and
either of those gzip-compressed. Standard library only.

!! DISCLAIMER !!
For training/education or AUTHORIZED assessment ONLY, on captures you own or
are explicitly permitted to analyse, and on networks you are explicitly
authorised to monitor. Not for production environments where safety or
operational availability cannot be guaranteed. Capture files from a control network are
sensitive: they can contain process values, credentials and topology. Handle
and store them accordingly. This tool is read-only and sends no traffic, but
it is not a substitute for engineering judgement - do not treat inferred
findings as verified facts. Use is at your own risk.

This script was vibe coded by Mike Holcomb of UtilSec, LLC.
LinkedIn : https://www.linkedin.com/in/mikeholcomb
Website  : https://mikeholcomb.com
License  : MIT - see the LICENSE file. SPDX-License-Identifier: MIT

------------------------------------------------------------
CHANGELOG
------------------------------------------------------------
v1.0  First release. pcap + pcapng + gzip readers; Ethernet/VLAN/SLL/raw/
      loopback link layers; ARP, LLDP, CDP, PROFINET DCP, STP, DHCP, NBNS,
      mDNS/LLMNR decoders; IPv4/IPv6 with TCP flag-state tracking, UDP and
      ICMP; tiered port evidence (SERVING / RESPONDING / REFUSED / OBSERVED);
      three-tier OUI vendor lookup shared with OT RUNG; per-host and per-MAC
      inventories; IP/MAC conflict and multi-homing flags; OT protocol summary
      with Modbus read/write function-code breakdown; plaintext-protocol
      observations; conversation (flow) table; CSV/JSON export; interactive
      file prompt when run with no arguments.
v1.1  Live capture. --live [IFACE] listens on an interface (SPAN/mirror port
      or TAP) and fills the same inventory as packets arrive, printing each
      new host, answering port, announced name, layer-2 device, IP conflict
      and first Modbus write per client/controller/function as it happens;
      Ctrl+C, --duration or --max-packets ends it with the full normal report
      and the usual --csv/--json exports. Backends: Npcap/libpcap via ctypes,
      Linux AF_PACKET, Windows raw socket (degraded). New flags: --live,
      --list-ifaces, --duration, --filter, --snaplen, --write,
      --capture-backend, --map, --map-port, --map-buffer-mb, --allow-remote,
      --no-browser. --map serves taproot.html (rev 1.5+) on 127.0.0.1 with a
      per-run token and the page draws the map live. The no-argument prompt
      now also accepts L to listen live. File mode, existing flags and output
      formats unchanged; the JSON report gains a capture.live block in live
      mode only. Fix: an all-zero source MAC (Linux loopback frames) is no
      longer listed as a host's MAC - it was shown as 'XEROX CORPORATION'.
v1.1.1 Fix: the shared MAC vendor database is also found through
      $ATOMICS_OUI_FILE (OT RUNG is now AtomICS). Order: --oui-file,
      $TAPROOT_OUI_FILE, $ATOMICS_OUI_FILE, legacy $RUNG_OUI_FILE, then known
      filenames beside the script and in the current folder. References to
      OT RUNG now say AtomICS. Released under the MIT license (LICENSE
      file; SPDX tag above). No change to flags, output or exports.
============================================================
"""

import argparse
import collections
import csv
import gzip
import hmac
import http.server
import itertools
import json
import os
import secrets
import select
import socket
import struct
import sys
import threading
import time
import urllib.parse
import webbrowser
import zlib
from datetime import datetime

VERSION = "1.1.1"
TOOL_NAME = "TAPROOT"
TOOL_LONG = "TAP Record Offline Observation Tool"

DISCLAIMER_SHORT = (
    "Passive analysis - transmits nothing. For training or AUTHORIZED assessment\n"
    "only, on captures you may analyse and networks you may monitor. Not for\n"
    "production networks where safety or availability cannot be guaranteed."
)

# ============================================================
#  CONSTANTS
# ============================================================

# Link-layer header types (libpcap DLT / pcapng LinkType).
DLT_NULL      = 0      # BSD loopback: 4-byte host-order address family
DLT_EN10MB    = 1      # Ethernet
DLT_RAW       = 101    # raw IP, no link header
DLT_LINUX_SLL = 113    # Linux cooked v1
DLT_IPV4      = 228
DLT_IPV6      = 229
DLT_LINUX_SLL2 = 276   # Linux cooked v2

DLT_NAMES = {
    DLT_NULL: "BSD loopback (DLT_NULL)",
    DLT_EN10MB: "Ethernet (DLT_EN10MB)",
    DLT_RAW: "Raw IP (DLT_RAW)",
    DLT_LINUX_SLL: "Linux cooked v1 (DLT_LINUX_SLL)",
    DLT_IPV4: "Raw IPv4 (DLT_IPV4)",
    DLT_IPV6: "Raw IPv6 (DLT_IPV6)",
    DLT_LINUX_SLL2: "Linux cooked v2 (DLT_LINUX_SLL2)",
}
SUPPORTED_DLTS = set(DLT_NAMES)

# EtherTypes.
ETH_IPV4      = 0x0800
ETH_ARP       = 0x0806
ETH_RARP      = 0x8035
ETH_IPV6      = 0x86DD
ETH_LLDP      = 0x88CC
ETH_PROFINET  = 0x8892
ETH_ETHERCAT  = 0x88A4
ETH_VLAN_TAGS = (0x8100, 0x88A8, 0x9100)

ETH_TYPE_NAMES = {
    ETH_RARP: "RARP", ETH_ETHERCAT: "EtherCAT",
    0x8863: "PPPoE-Discovery", 0x8864: "PPPoE", 0x88F7: "PTP (1588)",
    0x22F0: "AVTP", 0x8906: "FCoE", 0x9000: "Ethernet Loopback/CTP",
    0x8100: "VLAN", 0x88E5: "MACsec", 0x88CD: "SERCOS III",
    0x8847: "MPLS", 0x0842: "Wake-on-LAN",
}

IP_PROTO_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP",
    51: "AH", 58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP",
}

# OT / ICS protocol ports. Matching either the source or destination names the
# conversation; the port list is deliberately the same one AtomICS (formerly
# OT RUNG) uses.
OT_PORTS = {
    102: "S7comm / ISO-TSAP (Siemens)",
    502: "Modbus TCP",
    789: "Red Lion Crimson",
    1089: "Foundation Fieldbus HSE",
    1090: "Foundation Fieldbus HSE",
    1091: "Foundation Fieldbus HSE",
    1911: "Niagara Fox (Tridium)",
    1962: "PCWorx (Phoenix Contact)",
    2222: "EtherNet/IP (implicit I/O)",
    2404: "IEC 60870-5-104",
    2455: "CoDeSys",
    4000: "OPC (Emerson ROC)",
    4840: "OPC UA",
    4911: "Niagara Fox SSL (Tridium)",
    5006: "MELSEC-Q (Mitsubishi)",
    5007: "MELSEC-Q (Mitsubishi)",
    9600: "OMRON FINS",
    18245: "GE SRTP",
    18246: "GE SRTP",
    20000: "DNP3",
    20547: "ProConOS",
    34962: "PROFINET RT",
    34963: "PROFINET RT",
    34964: "PROFINET RT",
    44818: "EtherNet/IP (explicit / CIP)",
    47808: "BACnet/IP",
    55000: "FL-net",
}

# Common IT service ports.
IT_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
    110: "POP3", 111: "RPCbind", 123: "NTP", 135: "MSRPC", 137: "NBNS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "ISAKMP", 514: "Syslog", 515: "LPD", 520: "RIP", 546: "DHCPv6",
    547: "DHCPv6", 548: "AFP", 587: "Submission", 623: "IPMI/RMCP",
    636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1434: "MSSQL-browser", 1521: "Oracle", 1723: "PPTP",
    1900: "SSDP/UPnP", 2049: "NFS", 3268: "LDAP-GC", 3306: "MySQL",
    3389: "RDP", 3702: "WS-Discovery", 4786: "Cisco Smart Install",
    5060: "SIP", 5353: "mDNS", 5355: "LLMNR", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "JetDirect",
    27017: "MongoDB",
}

# Protocols that carry credentials or control in the clear. Worth calling out
# in an OT report every time, because "we'll fix it later" has been the answer
# on plant networks for twenty years.
PLAINTEXT_PORTS = {
    21: "FTP - credentials in the clear",
    23: "Telnet - credentials in the clear",
    69: "TFTP - no authentication at all",
    80: "HTTP - credentials/session in the clear",
    161: "SNMP - community string in the clear (v1/v2c)",
    162: "SNMP-Trap - community string in the clear (v1/v2c)",
    512: "rexec - credentials in the clear",
    513: "rlogin - credentials in the clear",
    514: "Syslog/rsh - unauthenticated",
    5900: "VNC - weak/legacy authentication",
    8080: "HTTP-alt - credentials/session in the clear",
}

# Modbus function codes, split so read vs write traffic can be reported
# separately. Reference: MODBUS Application Protocol Specification V1.1b3.
MODBUS_FUNCS = {
    1: ("Read Coils", "read"),
    2: ("Read Discrete Inputs", "read"),
    3: ("Read Holding Registers", "read"),
    4: ("Read Input Registers", "read"),
    5: ("Write Single Coil", "write"),
    6: ("Write Single Register", "write"),
    7: ("Read Exception Status", "read"),
    8: ("Diagnostics", "diag"),
    11: ("Get Comm Event Counter", "read"),
    12: ("Get Comm Event Log", "read"),
    15: ("Write Multiple Coils", "write"),
    16: ("Write Multiple Registers", "write"),
    17: ("Report Server ID", "read"),
    20: ("Read File Record", "read"),
    21: ("Write File Record", "write"),
    22: ("Mask Write Register", "write"),
    23: ("Read/Write Multiple Registers", "write"),
    24: ("Read FIFO Queue", "read"),
    43: ("Encapsulated Interface / Device ID", "read"),
}

DHCP_MAGIC = b"\x63\x82\x53\x63"
DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}

# Caps, so one chatty host cannot balloon memory or bury the report.
MAX_LABELS_PER_HOST = 24     # distinct protocol labels kept per host
MAX_PEERS_PER_PORT  = 64     # distinct peers remembered per service port
MAX_IPS_PER_MAC     = 64
MAX_HOSTNAMES       = 8
MAX_CLIENT_PORTS    = 2000   # counted beyond this, not stored
MAX_HOSTS           = 50000  # inventory guard: a garbage or enormous capture
MAX_MACS            = 50000  #   must not exhaust memory - overflow is counted
MAX_FLOWS           = 150000 # tracked conversations; beyond this, grading
MAX_SERVICES_PER_HOST = 2048 #   degrades to per-packet instead of eating RAM
MAX_FLOW_LABELS     = 3      # protocol labels kept per conversation
SHOW_HOSTS_DEFAULT  = 250    # per-host detail blocks printed without --all-ports
SHOW_MACS_DEFAULT   = 150    # MAC table rows printed without --all-ports

# Client source ports are drawn from the ephemeral range (IANA 49152-65535,
# and the Windows default since Vista). A port in here is almost never the
# server side of a conversation, even when it collides with a registered OT
# service - which FL-net (55000), DNP3 (20000) and EtherNet/IP I/O (2222) do.
EPHEMERAL_MIN = 49152

# Port-evidence states, strongest first. Ranked so a later observation never
# downgrades a stronger one.
STATE_RANK = {"serving": 4, "responding": 3, "refused": 2, "observed": 1}

# Live capture (v1.1). Conservative: one capture handle, a short read timeout so
# Ctrl+C is honoured promptly, and a bounded frame buffer for the browser map.
LIVE_SNAPLEN_DEFAULT = 65535
LIVE_TIMEOUT_MS = 250            # read timeout - how often the loop wakes up
LIVE_KERNEL_BUFFER = 32 * 1024 * 1024   # absorbs bursts while Python parses
LIVE_EVENTS_PER_SEC = 25         # console event lines per second before summarising
MAP_PORT_DEFAULT = 8765
MAP_BUFFER_MB_DEFAULT = 128      # frames held for the browser map
MAP_CHUNK_BYTES = 4 * 1024 * 1024

# ============================================================
#  OUTPUT
# ============================================================

_COLOR = False


def _supports_color(stream):
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "").lower() in ("dumb", ""):
        if os.name != "nt":
            return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        # Windows 10+ consoles do ANSI once VT processing is enabled; ask the
        # OS to turn it on and fall back to plain text if it refuses.
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not k.GetConsoleMode(h, ctypes.byref(mode)):
                return False
            if not k.SetConsoleMode(h, mode.value | 0x0004):
                return False
        except Exception:
            return False
    return True


class C:
    """ANSI codes. Body text is BRIGHT white - grey is unreadable in a plant."""
    RESET = "\033[0m"
    BODY = "\033[97m"          # bright white
    HEAD = "\033[1;96m"        # bright cyan, bold
    GOOD = "\033[92m"
    WARN = "\033[93m"
    BAD = "\033[91m"
    DIM = "\033[37m"
    OT = "\033[95m"            # magenta: OT/ICS protocol


def _c(code, text):
    return f"{code}{text}{C.RESET}" if _COLOR else text


def echo(msg=""):
    print(_c(C.BODY, msg) if msg else "")


def head(msg):
    print()
    print(_c(C.HEAD, msg))
    print(_c(C.HEAD, "-" * min(len(msg), 78)))


def warn(msg):
    print(_c(C.WARN, msg))


def bad(msg):
    print(_c(C.BAD, msg))


def banner():
    line = "=" * 64
    print(_c(C.HEAD, line))
    print(_c(C.HEAD, f" {TOOL_NAME} v{VERSION} - {TOOL_LONG}"))
    print(_c(C.HEAD, " Passive pcap/pcapng + live capture: IPs, MACs, ports, OT protocols"))
    print(_c(C.HEAD, line))
    for ln in DISCLAIMER_SHORT.split("\n"):
        print(_c(C.WARN, " " + ln))
    print(_c(C.HEAD, line))


# ============================================================
#  OUI / MAC VENDOR DATABASE
# ============================================================
# Longest-prefix match across three tiers, identical to AtomICS: a /36 (MA-S,
# IAB) assignment beats a /28 (MA-M), which beats the /24 (MA-L). Roughly 45%
# of /24 ranges are subdivided among several vendors, so a /24-only lookup
# returns whichever sub-block loaded last - i.e. the wrong vendor, confidently.
# There is no built-in vendor list: names come only from a real database file.

OUI_DB = {}            # /24 (MA-L, CID): {"AA:BB:CC": vendor}
OUI_DB_M = {}          # /28 (MA-M):      {"AABBCCD": vendor}
OUI_DB_S = {}          # /36 (MA-S, IAB): {"AABBCC001": vendor}
OUI_SOURCE = None

OUI_FILENAMES = ("oui.csv", "mac-vendors-export.csv", "maclookup.csv",
                 "oui.txt", "manuf")
# $ATOMICS_OUI_FILE is AtomICS's own variable; $RUNG_OUI_FILE is its legacy
# name from before the OT RUNG -> AtomICS rename and is still honoured.
OUI_ENV_VARS = ("TAPROOT_OUI_FILE", "ATOMICS_OUI_FILE", "RUNG_OUI_FILE")

OUI_SOURCES = [
    ("https://maclookup.app/downloads/csv-database", "oui.csv", "maclookup.app (CSV)"),
    ("https://standards-oui.ieee.org/oui/oui.csv", "oui.csv", "IEEE registry (CSV)"),
    ("https://www.wireshark.org/download/automated/data/manuf", "manuf", "Wireshark manuf"),
    ("https://raw.githubusercontent.com/wireshark/wireshark/master/manuf", "manuf",
     "Wireshark manuf (GitHub mirror)"),
]


def _script_dir():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.getcwd()


def _norm_oui(token):
    """Normalise an OUI token to 'AA:BB:CC' (first 3 octets, upper). '' if bad."""
    token = token.strip().split("/")[0].strip()
    token = token.replace("-", ":").replace(".", ":")
    if ":" in token:
        parts = [p for p in token.split(":") if p != ""]
    else:
        parts = [token[i:i + 2] for i in range(0, len(token), 2)]
    if len(parts) < 3:
        return ""
    try:
        for p in parts[:3]:
            int(p, 16)
    except ValueError:
        return ""
    return ":".join(p.zfill(2) for p in parts[:3]).upper()


def _norm_oui_prefix(token):
    """Normalise a MAC prefix to uppercase hex nibbles, its LENGTH carrying the
    block size: MA-L/CID = 6, MA-M = 7, MA-S/IAB = 9. Handles maclookup's
    digit-count encoding ('1C:87:76:D' -> 7) and Wireshark's '/NN' bit mask
    ('00:1B:1B:00:00:00/28' -> '001B1B0')."""
    token = token.strip()
    bits = None
    if "/" in token:
        base, _sep, m = token.partition("/")
        m = m.strip()
        if m.isdigit():
            bits = int(m)
        token = base
    t = token.strip().replace("-", "").replace(":", "").replace(".", "").upper()
    if bits is not None:
        t = t[:max(6, bits // 4)]
    if len(t) < 6:
        return ""
    for ch in t:
        if ch not in "0123456789ABCDEF":
            return ""
    return t


def _oui_add(db24, dbm, dbs, prefix_token, vendor):
    raw = _norm_oui_prefix(prefix_token)
    if not raw or not vendor:
        return
    vendor = vendor.rstrip(", ").strip()      # maclookup leaves trailing commas
    if not vendor:
        return
    n = len(raw)
    if n >= 9:
        dbs[raw[:9]] = vendor
    elif n >= 7:
        dbm[raw[:7]] = vendor
    else:
        pfx = _norm_oui(prefix_token)
        if pfx:
            db24[pfx] = vendor


def _parse_oui_file(path):
    """Parse maclookup.app CSV, IEEE oui.csv, IEEE oui.txt or Wireshark manuf
    into (db24, dbm, dbs). Unparseable lines are skipped, never fatal."""
    db24, dbm, dbs = {}, {}, {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head_line = f.readline()
            f.seek(0)
            low = head_line.lower()
            if "mac prefix" in low:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) < 2:
                        continue
                    _oui_add(db24, dbm, dbs, row[0], row[1].strip().strip('"'))
            elif "registry" in low and "assignment" in low:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) < 3:
                        continue
                    _oui_add(db24, dbm, dbs, row[1], row[2].strip().strip('"'))
            else:
                for line in f:
                    s = line.rstrip("\n")
                    if not s or s.lstrip().startswith("#"):
                        continue
                    if "(base 16)" in s:
                        continue
                    if "(hex)" in s:
                        left, _sep, right = s.partition("(hex)")
                        _oui_add(db24, dbm, dbs, left, right.strip())
                        continue
                    toks = [t for t in s.split("\t") if t.strip() != ""]
                    if len(toks) < 2:
                        toks = s.split(None, 2)
                    if len(toks) >= 2:
                        vendor = toks[-1].strip()
                        if vendor and not vendor.startswith("#"):
                            _oui_add(db24, dbm, dbs, toks[0], vendor)
    except OSError:
        return {}, {}, {}
    return db24, dbm, dbs


def _find_oui_file(explicit=None):
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for var in OUI_ENV_VARS:
        env = os.environ.get(var)
        if env and os.path.isfile(env):
            return env
    for d in (_script_dir(), os.getcwd()):
        for n in OUI_FILENAMES:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    return None


def load_oui_database(explicit=None, verbose=True):
    global OUI_DB, OUI_DB_M, OUI_DB_S, OUI_SOURCE
    path = _find_oui_file(explicit)
    if not path:
        if verbose:
            echo("[i] OUI: no database loaded - every MAC will show '(unknown vendor)'.")
            echo(f"    Run 'python {os.path.basename(sys.argv[0] or 'taproot.py')} "
                 f"--update-oui', or drop the maclookup.app CSV")
            echo("    (https://maclookup.app/downloads/csv-database) beside the script "
                 "as oui.csv.")
            echo("    An existing AtomICS database is picked up automatically "
                 "($ATOMICS_OUI_FILE,")
            echo("    or the legacy $RUNG_OUI_FILE).")
        return
    db24, dbm, dbs = _parse_oui_file(path)
    if not (db24 or dbm or dbs):
        if verbose:
            warn(f"[!] OUI file {path} could not be parsed - no vendor resolution.")
        return
    OUI_DB, OUI_DB_M, OUI_DB_S = db24, dbm, dbs
    OUI_SOURCE = path
    if verbose:
        total = len(db24) + len(dbm) + len(dbs)
        extra = (f" (incl. {len(dbm)} MA-M + {len(dbs)} MA-S/IAB sub-blocks)"
                 if (dbm or dbs) else "")
        echo(f"[i] OUI: {total} vendor prefixes loaded from "
             f"{os.path.basename(path)}{extra}.")


def update_oui():
    """Download an OUI database beside the script, trying several sources."""
    import urllib.request
    dest_dir = _script_dir()
    echo("Fetching a full OUI (MAC vendor) database. Trying sources in order:")
    for url, fname, label in OUI_SOURCES:
        dest = os.path.join(dest_dir, fname)
        echo(f"  - {label}: {url}")
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": f"Mozilla/5.0 ({TOOL_NAME} OUI updater)"})
            with urllib.request.urlopen(req, timeout=90) as r:
                data = r.read()
        except Exception as e:
            echo(f"      [x] failed: {e}")
            continue
        try:
            with open(dest, "wb") as out:
                out.write(data)
        except OSError as e:
            echo(f"      [x] could not write {dest}: {e}")
            continue
        db24, dbm, dbs = _parse_oui_file(dest)
        n = len(db24) + len(dbm) + len(dbs)
        if n < 1000:
            echo(f"      [x] only {n} entries parsed - looks incomplete, "
                 f"trying the next source.")
            try:
                os.remove(dest)
            except OSError:
                pass
            continue
        echo(f"      [+] {n} OUI entries saved to {dest}")
        echo("      It loads automatically next time you run the tool.")
        return
    bad("[x] Every source failed (network blocked, or offline).")
    echo("    Download one of these in a browser and save it next to the script:")
    echo(f"      {_script_dir()}")
    echo("      https://maclookup.app/downloads/csv-database        -> save as oui.csv")
    echo("      https://standards-oui.ieee.org/oui/oui.csv          -> save as oui.csv")
    echo("      https://www.wireshark.org/download/automated/data/manuf -> save as manuf")


def _oui_vendor(mac):
    """Vendor for a MAC by longest-prefix match, '' when unmapped."""
    if not mac or len(mac) < 8:
        return ""
    raw = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(raw) >= 9 and raw[:9] in OUI_DB_S:
        return OUI_DB_S[raw[:9]]
    if len(raw) >= 7 and raw[:7] in OUI_DB_M:
        return OUI_DB_M[raw[:7]]
    name = OUI_DB.get(mac[:8].upper())
    if name:
        return name
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return ""
    if first & 0x02:
        return "(randomized / local MAC)"
    return ""


def _vendor_label(mac):
    v = _oui_vendor(mac)
    if v:
        if v.startswith("(") and v.endswith(")"):
            v = v[1:-1]
        return v
    return "unknown vendor"


def _mac_with_vendor(mac):
    if not mac:
        return "(unknown MAC)"
    return f"{mac} ({_vendor_label(mac)})"


# ============================================================
#  CAPTURE FILE READERS
# ============================================================
# pcap: 24-byte global header, then per-record ts_sec/ts_usec/incl_len/orig_len.
# pcapng: typed blocks; SHB sets byte order, IDB carries link type and
# timestamp resolution per interface, EPB/SPB/PB carry the packets.
#
# Both are streamed one packet at a time, so the FILE never lands in memory.
# What does grow is the inventory - hosts, MACs, conversations - which is why
# the MAX_* caps above exist: past them, correlation is dropped rather than
# memory grown, and the summary says so instead of the process dying on a
# field laptop halfway through a 5 GB SPAN capture.


class CaptureError(Exception):
    pass


def _open_maybe_gzip(path):
    try:
        with open(path, "rb") as probe:
            magic = probe.read(2)
    except OSError as e:
        raise CaptureError(f"cannot open {path}: {e}")
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rb"), True
    try:
        return open(path, "rb"), False
    except OSError as e:
        raise CaptureError(f"cannot open {path}: {e}")


def _read_exact(fh, n, cap=None):
    """Read exactly n bytes, or return what is there (short = truncated file).

    A corrupt or half-copied .pcap.gz raises out of the gzip layer instead of
    returning short, so that is caught here and treated as truncation - a USB
    stick pulled early must produce a message, not a traceback."""
    buf = b""
    try:
        while len(buf) < n:
            chunk = fh.read(n - len(buf))
            if not chunk:
                break
            buf += chunk
    except (OSError, EOFError, zlib.error) as e:
        if cap is not None:
            cap.read_error = str(e)
    return buf


class Capture:
    """Streaming reader for pcap / pcapng, gzip-compressed or not."""

    def __init__(self, path):
        self.path = path
        self.fh, self.gzipped = _open_maybe_gzip(path)
        self.format = None
        self.endian = "<"
        self.snaplen = 0
        self.linktypes = {}        # interface id -> linktype (current section)
        self.seen_linktypes = set()   # every link type seen in the whole file
        self.truncated = False
        self.bad_blocks = 0
        self.read_error = None
        self._tsresol = {}         # interface id -> divisor
        self._nanosecond = False
        head_bytes = _read_exact(self.fh, 4, self)
        if len(head_bytes) < 4:
            if self.read_error:
                raise CaptureError(
                    f"file could not be read - it looks damaged: {self.read_error}")
            raise CaptureError("file is too small to be a capture")
        self._first4 = head_bytes
        if head_bytes == b"\x0a\x0d\x0d\x0a":
            self.format = "pcapng"
        else:
            self.format = "pcap"
            self._init_pcap(head_bytes)

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass

    # ---------------- classic pcap ----------------

    def _init_pcap(self, magic_bytes):
        magic = struct.unpack("<I", magic_bytes)[0]
        if magic == 0xA1B2C3D4:
            self.endian, self._nanosecond = "<", False
        elif magic == 0xD4C3B2A1:
            self.endian, self._nanosecond = ">", False
        elif magic == 0xA1B23C4D:
            self.endian, self._nanosecond = "<", True
        elif magic == 0x4D3CB2A1:
            self.endian, self._nanosecond = ">", True
        else:
            raise CaptureError(
                f"not a pcap/pcapng file (magic 0x{magic:08x}). "
                "Wireshark can 'Save As' pcap/pcapng if this is another format.")
        rest = _read_exact(self.fh, 20, self)
        if len(rest) < 20:
            raise CaptureError("truncated pcap global header")
        vmaj, vmin, _tz, _sig, snaplen, network = struct.unpack(
            self.endian + "HHiIII", rest)
        self.version = f"{vmaj}.{vmin}"
        self.snaplen = snaplen
        self.linktypes = {0: network}
        self.seen_linktypes.add(network)

    def _packets_pcap(self):
        e = self.endian
        div = 1e9 if self._nanosecond else 1e6
        while True:
            hdr = _read_exact(self.fh, 16, self)
            if not hdr:
                return
            if len(hdr) < 16:
                self.truncated = True
                return
            ts_sec, ts_frac, incl, orig = struct.unpack(e + "IIII", hdr)
            if incl > 0x4000000:          # 64 MB sanity guard on a bad length
                self.bad_blocks += 1
                self.truncated = True
                return
            data = _read_exact(self.fh, incl, self)
            if len(data) < incl:
                self.truncated = True
                return
            yield (ts_sec + ts_frac / div, self.linktypes.get(0, DLT_EN10MB),
                   data, orig)

    # ---------------- pcapng ----------------

    def _packets_pcapng(self):
        # The first 4 bytes (block type) are already consumed.
        pending_type = struct.unpack("<I", self._first4)[0]
        first = True
        next_iface = 0
        while True:
            if first:
                btype = pending_type
                first = False
            else:
                raw = _read_exact(self.fh, 4, self)
                if not raw:
                    return
                if len(raw) < 4:
                    self.truncated = True
                    return
                btype = struct.unpack(self.endian + "I", raw)[0]
            lenraw = _read_exact(self.fh, 4, self)
            if len(lenraw) < 4:
                self.truncated = True
                return
            if btype == 0x0A0D0D0A:
                # Section Header Block: byte-order magic decides endianness for
                # this whole section, and a section resets the interface table.
                body_head = _read_exact(self.fh, 4, self)
                if len(body_head) < 4:
                    self.truncated = True
                    return
                bom = struct.unpack("<I", body_head)[0]
                if bom == 0x1A2B3C4D:
                    self.endian = "<"
                elif bom == 0x4D3C2B1A:
                    self.endian = ">"
                else:
                    raise CaptureError(
                        f"pcapng byte-order magic not recognised (0x{bom:08x})")
                total = struct.unpack(self.endian + "I", lenraw)[0]
                if total < 12:
                    raise CaptureError("pcapng section header block is malformed")
                skip = total - 12 - 4      # header(8) + trailer(4) + bom(4)
                if skip > 0 and len(_read_exact(self.fh, skip, self)) < skip:
                    self.truncated = True
                    return
                if len(_read_exact(self.fh, 4, self)) < 4:
                    self.truncated = True
                    return
                self.linktypes = {}
                self._tsresol = {}
                next_iface = 0
                continue

            total = struct.unpack(self.endian + "I", lenraw)[0]
            if total < 12 or total > 0x8000000:
                self.bad_blocks += 1
                self.truncated = True
                return
            body = _read_exact(self.fh, total - 12, self)
            if len(body) < total - 12:
                self.truncated = True
                return
            if len(_read_exact(self.fh, 4, self)) < 4:
                self.truncated = True
                return

            e = self.endian
            if btype == 0x00000001:                       # Interface Description
                if len(body) >= 8:
                    lt, _res, snap = struct.unpack(e + "HHI", body[:8])
                    self.linktypes[next_iface] = lt
                    self.seen_linktypes.add(lt)
                    self.snaplen = max(self.snaplen, snap)
                    self._tsresol[next_iface] = self._parse_tsresol(body[8:])
                    next_iface += 1
            elif btype == 0x00000006:                     # Enhanced Packet Block
                if len(body) >= 20:
                    iface, ts_hi, ts_lo, cap, orig = struct.unpack(e + "IIIII", body[:20])
                    data = body[20:20 + cap]
                    yield (self._ts(iface, ts_hi, ts_lo),
                           self.linktypes.get(iface, DLT_EN10MB), data, orig)
            elif btype == 0x00000003:                     # Simple Packet Block
                if len(body) >= 4:
                    orig = struct.unpack(e + "I", body[:4])[0]
                    data = body[4:]
                    yield (0.0, self.linktypes.get(0, DLT_EN10MB), data, orig)
            elif btype == 0x00000002:                     # obsolete Packet Block
                if len(body) >= 20:
                    iface, _drops, ts_hi, ts_lo, cap, orig = struct.unpack(
                        e + "HHIIII", body[:20])
                    data = body[20:20 + cap]
                    yield (self._ts(iface, ts_hi, ts_lo),
                           self.linktypes.get(iface, DLT_EN10MB), data, orig)
            # every other block type (NRB, ISB, decryption secrets, ...) is skipped

    def _parse_tsresol(self, opts):
        """if_tsresol (option code 9): one byte. High bit set means 2^-n,
        otherwise 10^-n. Default is microseconds."""
        e = self.endian
        i = 0
        div = 1e6
        try:
            while i + 4 <= len(opts):
                code, olen = struct.unpack(e + "HH", opts[i:i + 4])
                val = opts[i + 4:i + 4 + olen]
                i += 4 + olen + ((4 - olen % 4) % 4)
                if code == 0:
                    break
                if code == 9 and val:
                    r = val[0]
                    div = float(2 ** (r & 0x7F)) if r & 0x80 else float(10 ** r)
        except Exception:
            pass
        return div

    def _ts(self, iface, hi, lo):
        div = self._tsresol.get(iface, 1e6)
        return ((hi << 32) | lo) / div

    # ---------------- public ----------------

    def packets(self):
        if self.format == "pcap":
            return self._packets_pcap()
        return self._packets_pcapng()

    def describe(self):
        # Every link type in the file, not just the last pcapng section's: a
        # section whose packets were skipped must still be reported.
        lts = sorted(self.seen_linktypes or set(self.linktypes.values()))
        names = ", ".join(DLT_NAMES.get(l, f"link type {l} (unsupported)") for l in lts) \
            or "not yet known"
        fmt = self.format + (" + gzip" if self.gzipped else "")
        return fmt, names


# ============================================================
#  PACKET DISSECTION
# ============================================================


def _u16(b, off):
    return struct.unpack(">H", b[off:off + 2])[0]


def _u32(b, off):
    return struct.unpack(">I", b[off:off + 4])[0]


def _mac_str(raw):
    return ":".join(f"{b:02x}" for b in raw)


def _ipv4(b, off):
    return socket.inet_ntoa(b[off:off + 4])


def _ipv6(b, off):
    try:
        return socket.inet_ntop(socket.AF_INET6, b[off:off + 16])
    except (OSError, ValueError, AttributeError):
        # Windows Python before 3.4 / odd builds: format it by hand.
        parts = [f"{_u16(b, off + i):x}" for i in range(0, 16, 2)]
        return ":".join(parts)


def _printable(raw):
    try:
        s = raw.decode("utf-8", errors="ignore").replace("\x00", "").strip()
    except Exception:
        return ""
    if s and all(32 <= ord(c) < 127 for c in s):
        return s
    return ""


def port_name(port, proto="tcp"):
    """Best-known name for a port: OT first (that is the point of the tool)."""
    if port in OT_PORTS:
        return OT_PORTS[port]
    return IT_PORTS.get(port, "")


def is_ot_port(port):
    return port in OT_PORTS


# ---------------- L2 discovery decoders ----------------

def _decode_arp(payload):
    """RFC 826. The sender hardware/protocol pair is the prize."""
    if len(payload) < 28:
        return None
    try:
        op = _u16(payload, 6)
        sha = _mac_str(payload[8:14])
        spa = _ipv4(payload, 14)
        tpa = _ipv4(payload, 24)
        label = {1: "ARP-request", 2: "ARP-reply"}.get(op, f"ARP-op{op}")
        if spa == "0.0.0.0":
            return {"mac": sha, "ip": "", "proto": "ARP-probe",
                    "detail": f"probing for {tpa}"}
        if spa == tpa:
            label = "ARP-gratuitous"
        return {"mac": sha, "ip": spa, "proto": label, "detail": "",
                "arp_claim": (spa, sha)}
    except Exception:
        return None


def _decode_nbns(payload):
    """RFC 1002 first-level encoded NetBIOS name."""
    try:
        if len(payload) < 13:
            return ""
        if payload[12] != 0x20 or len(payload) < 45:
            return ""
        enc = payload[13:45]
        out = []
        for i in range(0, 32, 2):
            hi, lo = enc[i] - 0x41, enc[i + 1] - 0x41
            if hi < 0 or lo < 0 or hi > 15 or lo > 15:
                return ""
            out.append(chr((hi << 4) | lo))
        return "".join(out).strip()[:15].strip()
    except Exception:
        return ""


def _decode_dns_name(payload, off):
    try:
        parts = []
        guard = 0
        while off < len(payload) and guard < 16:
            ln = payload[off]
            if ln == 0:
                break
            if ln & 0xC0:
                break
            off += 1
            parts.append(payload[off:off + ln].decode("utf-8", errors="ignore"))
            off += ln
            guard += 1
        name = ".".join(p for p in parts if p)
        return name if all(32 <= ord(c) < 127 for c in name) else ""
    except Exception:
        return ""


def _decode_mdns(payload):
    if len(payload) < 13:
        return ""
    name = _decode_dns_name(payload, 12)
    for suffix in ("._tcp.local", "._udp.local", ".local"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    if name.startswith("_"):
        return ""
    return name


def _decode_lldp(payload):
    """IEEE 802.1AB TLVs: chassis ID (1), port ID (2), system name (5)."""
    out = {"system": "", "port": "", "chassis": "", "descr": ""}
    try:
        i = 0
        while i + 2 <= len(payload):
            hdr = _u16(payload, i)
            ttype, tlen = hdr >> 9, hdr & 0x01FF
            val = payload[i + 2:i + 2 + tlen]
            i += 2 + tlen
            if ttype == 0:
                break
            if ttype == 1 and len(val) > 1:
                out["chassis"] = _printable(val[1:]) or val[1:].hex()
            elif ttype == 2 and len(val) > 1:
                out["port"] = _printable(val[1:]) or val[1:].hex()
            elif ttype == 5:
                out["system"] = _printable(val)
            elif ttype == 6:
                out["descr"] = _printable(val)[:60]
    except Exception:
        pass
    return out


def _decode_cdp(payload):
    """Cisco Discovery Protocol: device ID (1), port ID (3), platform (6)."""
    out = {"device": "", "port": "", "platform": ""}
    try:
        i = 4
        while i + 4 <= len(payload):
            ttype = _u16(payload, i)
            tlen = _u16(payload, i + 2)
            if tlen < 4:
                break
            val = payload[i + 4:i + tlen]
            i += tlen
            if ttype == 0x0001:
                out["device"] = _printable(val)
            elif ttype == 0x0003:
                out["port"] = _printable(val)
            elif ttype == 0x0006:
                out["platform"] = _printable(val)[:50]
    except Exception:
        pass
    return out


def _decode_profinet_dcp(payload):
    """PROFINET DCP NameOfStation (option 0x02, suboption 0x02)."""
    try:
        if len(payload) < 12:
            return ""
        if _u16(payload, 0) not in (0xFEFE, 0xFEFF, 0xFEFD, 0xFEFC):
            return ""
        data_len = _u16(payload, 10)
        i, end = 12, min(len(payload), 12 + data_len)
        while i + 4 <= end:
            option, subopt = payload[i], payload[i + 1]
            blk_len = _u16(payload, i + 2)
            val = payload[i + 4:i + 4 + blk_len]
            i += 4 + blk_len + (blk_len % 2)
            if option == 0x02 and subopt == 0x02 and len(val) > 2:
                return _printable(val[2:])
    except Exception:
        pass
    return ""


def _decode_llc_snap(raw, off, src_mac):
    """802.3 LLC/SNAP - how CDP and STP arrive."""
    try:
        if off + 3 > len(raw):
            return None
        dsap, ssap = raw[off], raw[off + 1]
        if dsap == 0x42 and ssap == 0x42:
            return {"mac": src_mac, "ip": "", "proto": "STP", "detail": ""}
        if dsap == 0xAA and ssap == 0xAA and off + 8 <= len(raw):
            pid = _u16(raw, off + 6)
            body = raw[off + 8:]
            if pid == 0x2000:
                cdp = _decode_cdp(body)
                return {"mac": src_mac, "ip": "", "proto": "CDP",
                        "hostname": cdp["device"], "switch": cdp["device"],
                        "swport": cdp["port"], "detail": cdp["platform"]}
            if pid == 0x2004:
                return {"mac": src_mac, "ip": "", "proto": "DTP", "detail": ""}
            return {"mac": src_mac, "ip": "", "proto": f"SNAP 0x{pid:04x}",
                    "detail": ""}
        return {"mac": src_mac, "ip": "", "proto": "802.3 LLC", "detail": ""}
    except Exception:
        return None


def _decode_dhcp(body):
    """Enough DHCP to learn MAC, offered/requested IP, hostname, vendor class.
    RFC 2131 fixed header, RFC 2132 options."""
    try:
        if len(body) < 240 or body[236:240] != DHCP_MAGIC:
            return None
        out = {"msg_type": 0, "mac": "", "yiaddr": "", "req_ip": "",
               "hostname": "", "vendor_class": ""}
        hlen = body[2]
        if 0 < hlen <= 16:
            out["mac"] = _mac_str(body[28:28 + hlen])
        y = _ipv4(body, 16)
        if y != "0.0.0.0":
            out["yiaddr"] = y
        i = 240
        while i < len(body):
            code = body[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            if i + 2 > len(body):
                break
            olen = body[i + 1]
            val = body[i + 2:i + 2 + olen]
            i += 2 + olen
            if code == 53 and val:
                out["msg_type"] = val[0]
            elif code == 12:
                out["hostname"] = _printable(val)
            elif code == 60:
                out["vendor_class"] = _printable(val)[:48]
            elif code == 50 and len(val) == 4:
                out["req_ip"] = socket.inet_ntoa(val)
        return out
    except Exception:
        return None


def _modbus_funcs(payload):
    """Function codes in a Modbus/TCP stream. One TCP segment can carry several
    PDUs, so walk the MBAP lengths. Returns a list of (fc, is_exception)."""
    out = []
    try:
        i = 0
        guard = 0
        while i + 8 <= len(payload) and guard < 16:
            proto_id = _u16(payload, i + 2)
            length = _u16(payload, i + 4)
            if proto_id != 0 or not (2 <= length <= 260):
                break
            fc = payload[i + 7]
            out.append((fc & 0x7F, bool(fc & 0x80)))
            i += 6 + length
            guard += 1
    except Exception:
        pass
    return out


# ---------------- link-layer entry points ----------------

def _strip_link(raw, linktype):
    """Return (src_mac, dst_mac, ethertype_or_None, offset, vlan, l3proto).

    For cooked/raw link types there is no MAC, and for raw IP there is no
    EtherType either - the caller gets an explicit IP version instead."""
    if linktype == DLT_EN10MB:
        if len(raw) < 14:
            return None
        dst_mac = _mac_str(raw[0:6])
        src_mac = _mac_str(raw[6:12])
        etype = _u16(raw, 12)
        off, vlan, hops = 14, None, 0
        while etype in ETH_VLAN_TAGS and off + 4 <= len(raw) and hops < 3:
            vlan = _u16(raw, off) & 0x0FFF
            etype = _u16(raw, off + 2)
            off += 4
            hops += 1
        return src_mac, dst_mac, etype, off, vlan, None
    if linktype in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
        if linktype == DLT_LINUX_SLL:
            if len(raw) < 16:
                return None
            halen = _u16(raw, 4)
            addr = raw[6:6 + min(halen, 8)]
            etype = _u16(raw, 14)
            off = 16
        else:
            # SLL2: protocol(2) reserved(2) if_index(4) hatype(2) pkttype(1)
            # halen(1) addr(8) - the address length byte is at offset 11.
            if len(raw) < 20:
                return None
            etype = _u16(raw, 0)
            halen = raw[11]
            addr = raw[12:12 + min(halen, 8)]
            off = 20
        src_mac = _mac_str(addr[:6]) if len(addr) >= 6 else ""
        return src_mac, "", etype, off, None, None
    if linktype in (DLT_RAW, DLT_IPV4, DLT_IPV6):
        if not raw:
            return None
        if linktype == DLT_IPV4:
            ver = 4
        elif linktype == DLT_IPV6:
            ver = 6
        else:
            ver = raw[0] >> 4
        return "", "", None, 0, None, ver
    if linktype == DLT_NULL:
        if len(raw) < 4:
            return None
        af = struct.unpack("<I", raw[0:4])[0]
        if af > 0xFFFF:
            af = struct.unpack(">I", raw[0:4])[0]
        ver = 6 if af in (24, 28, 30) else 4
        return "", "", None, 4, None, ver
    return None


def _parse_l4(raw, off, proto, src_ip, dst_ip, info):
    """TCP / UDP / ICMP. Fills info with ports, flags and any identity found."""
    info["l4"] = IP_PROTO_NAMES.get(proto, f"IP-proto-{proto}")
    try:
        if proto == 6 and off + 14 <= len(raw):                  # TCP
            sport, dport = _u16(raw, off), _u16(raw, off + 2)
            doff = (raw[off + 12] >> 4) * 4
            flags = raw[off + 13]
            payload = raw[off + doff:] if doff >= 20 else b""
            info.update({
                "sport": sport, "dport": dport, "tcp_flags": flags,
                "syn": bool(flags & 0x02), "ack": bool(flags & 0x10),
                "rst": bool(flags & 0x04), "fin": bool(flags & 0x01),
                "paylen": len(payload),
            })
            name = port_name(dport) or port_name(sport)
            info["proto"] = name or _generic_label("TCP", sport, dport)
            if 502 in (sport, dport) and payload:
                info["modbus"] = _modbus_funcs(payload)
        elif proto == 17 and off + 8 <= len(raw):                # UDP
            sport, dport = _u16(raw, off), _u16(raw, off + 2)
            ulen = _u16(raw, off + 4)
            body = raw[off + 8:off + 8 + max(0, ulen - 8)] or raw[off + 8:]
            info.update({"sport": sport, "dport": dport, "paylen": len(body)})
            name = port_name(dport) or port_name(sport)
            info["proto"] = name or _generic_label("UDP", sport, dport)
            if {sport, dport} & {67, 68}:
                d = _decode_dhcp(body)
                if d:
                    info["proto"] = "DHCP-" + DHCP_MSG_TYPES.get(d["msg_type"], "?")
                    if d["mac"]:
                        info["dhcp_mac"] = d["mac"]
                    claim = d["yiaddr"] or d["req_ip"]
                    if claim:
                        info["dhcp_ip"] = claim
                    if d["hostname"]:
                        info["hostname"] = d["hostname"]
                    if d["vendor_class"]:
                        info["detail"] = f'vendor-class="{d["vendor_class"]}"'
            elif 137 in (sport, dport):
                info["hostname"] = _decode_nbns(body) or info.get("hostname", "")
            elif {sport, dport} & {5353, 5355}:
                info["hostname"] = _decode_mdns(body) or info.get("hostname", "")
        elif proto in (1, 58):                                   # ICMP / ICMPv6
            if off + 8 <= len(raw):
                itype, icode = raw[off], raw[off + 1]
                info["proto"] = f"ICMP type {itype}" if proto == 1 else \
                    f"ICMPv6 type {itype}"
                if proto == 1 and itype == 3:
                    info["proto"] = "ICMP unreachable"
                    # The quoted original datagram names the port that was
                    # closed ON THE SENDER of this ICMP message.
                    q = off + 8
                    if icode == 3 and q + 20 <= len(raw):
                        ihl = (raw[q] & 0x0F) * 4
                        if raw[q + 9] == 17 and q + ihl + 4 <= len(raw):
                            info["icmp_closed_port"] = _u16(raw, q + ihl + 2)
                elif proto == 1 and itype == 8:
                    info["proto"] = "ICMP echo request"
                elif proto == 1 and itype == 0:
                    info["proto"] = "ICMP echo reply"
    except Exception:
        pass
    return info


def _is_group_mac(mac):
    """Broadcast or multicast destination MAC (LSB of the first octet)."""
    if not mac:
        return False
    if mac == "ff:ff:ff:ff:ff:ff":
        return True
    try:
        return bool(int(mac[:2], 16) & 0x01)
    except ValueError:
        return False


def _is_group_ip(ip):
    """Broadcast, multicast or unspecified address - not a host."""
    if not ip:
        return False
    if ip in ("255.255.255.255", "0.0.0.0", "::", "::0"):
        return True
    if ":" in ip:
        return ip.lower().startswith("ff")
    try:
        first = int(ip.split(".")[0])
    except (ValueError, IndexError):
        return False
    return 224 <= first <= 239


def _generic_label(kind, sport, dport):
    """Label an unnamed port pair. A well-known port is worth recording; an
    ephemeral client port is not."""
    for port in (dport, sport):
        if port < 1024:
            return f"{kind}/{port}"
    return kind


def parse_packet(raw, linktype):
    """Dissect one captured frame. Returns a dict or None. Never raises: a
    malformed frame in the middle of a capture must not stop the analysis."""
    try:
        stripped = _strip_link(raw, linktype)
        if not stripped:
            return None
        src_mac, dst_mac, etype, off, vlan, ipver = stripped
        info = {"src_mac": src_mac, "dst_mac": dst_mac, "vlan": vlan,
                "src_ip": "", "dst_ip": "", "proto": "", "l4": "",
                "hostname": "", "detail": "", "switch": "", "swport": "",
                "sport": None, "dport": None}

        if etype is not None and ipver is None:
            if etype <= 1500:
                out = _decode_llc_snap(raw, off, src_mac)
                if out:
                    info["proto"] = out.get("proto", "802.3")
                    info["hostname"] = out.get("hostname", "")
                    info["switch"] = out.get("switch", "")
                    info["swport"] = out.get("swport", "")
                    info["detail"] = out.get("detail", "")
                return info
            if etype == ETH_ARP:
                a = _decode_arp(raw[off:])
                if not a:
                    return None
                info["proto"] = a["proto"]
                info["src_ip"] = a["ip"]
                info["detail"] = a["detail"]
                if a.get("arp_claim"):
                    info["arp_claim"] = a["arp_claim"]
                if a["mac"]:
                    info["src_mac"] = a["mac"]
                return info
            if etype == ETH_LLDP:
                l = _decode_lldp(raw[off:])
                info["proto"] = "LLDP"
                info["hostname"] = l["system"]
                info["switch"] = l["system"] or l["chassis"]
                info["swport"] = l["port"]
                info["detail"] = l["descr"]
                return info
            if etype == ETH_PROFINET:
                name = _decode_profinet_dcp(raw[off:])
                info["proto"] = "PROFINET-DCP"
                info["hostname"] = name
                return info
            if etype == ETH_IPV4:
                ipver = 4
            elif etype == ETH_IPV6:
                ipver = 6
            else:
                info["proto"] = ETH_TYPE_NAMES.get(etype, f"EtherType 0x{etype:04x}")
                return info

        if ipver == 4:
            if off + 20 > len(raw):
                return info if info["proto"] else None
            ihl = (raw[off] & 0x0F) * 4
            if ihl < 20:
                return None
            proto = raw[off + 9]
            frag_off = _u16(raw, off + 6) & 0x1FFF
            info["src_ip"] = _ipv4(raw, off + 12)
            info["dst_ip"] = _ipv4(raw, off + 16)
            if frag_off:
                info["proto"] = f"IPv4 fragment ({IP_PROTO_NAMES.get(proto, proto)})"
                info["l4"] = IP_PROTO_NAMES.get(proto, f"IP-proto-{proto}")
                return info
            return _parse_l4(raw, off + ihl, proto, info["src_ip"], info["dst_ip"], info)

        if ipver == 6:
            if off + 40 > len(raw):
                return info if info["proto"] else None
            nxt = raw[off + 6]
            info["src_ip"] = _ipv6(raw, off + 8)
            info["dst_ip"] = _ipv6(raw, off + 24)
            p = off + 40
            hops = 0
            # Walk extension headers to the real transport header. Two traps:
            # a non-first fragment has no transport header at all (reading one
            # invents ports out of payload bytes), and the Authentication
            # Header is sized (payload_len + 2) * 4 per RFC 4302, not by the
            # RFC 8200 Hdr-Ext-Len rule the other headers use.
            while nxt in (0, 43, 60, 51, 44) and p + 8 <= len(raw) and hops < 8:
                if nxt == 44:                              # fragment header
                    nxt_hdr = raw[p]
                    if _u16(raw, p + 2) >> 3:              # offset != 0
                        name = IP_PROTO_NAMES.get(nxt_hdr, f"IP-proto-{nxt_hdr}")
                        info["proto"] = f"IPv6 fragment ({name})"
                        info["l4"] = name
                        return info
                    nxt, p = nxt_hdr, p + 8
                elif nxt == 51:                            # RFC 4302 AH
                    nxt, p = raw[p], p + (raw[p + 1] + 2) * 4
                else:
                    nxt, p = raw[p], p + (raw[p + 1] + 1) * 8
                hops += 1
            return _parse_l4(raw, p, nxt, info["src_ip"], info["dst_ip"], info)

        if not info["proto"]:
            return None
        return info
    except Exception:
        return None


# ============================================================
#  INVENTORY
# ============================================================
# Three views, built in one pass:
#   hosts  keyed by IP   - the report most people want
#   macs   keyed by MAC  - catches the router, the hypervisor, the device whose
#                          IP changed mid-capture, and the MAC nobody expected
#   flows  keyed by the normalised 5-tuple - how port evidence is graded


def _new_host(ip):
    return {"ip": ip, "macs": {}, "hostnames": [], "protocols": {},
            "services": {}, "client_ports": set(), "client_port_overflow": 0,
            "pkts_out": 0, "pkts_in": 0, "bytes_out": 0, "bytes_in": 0,
            "first": None, "last": None, "vlans": set(), "peers": set(),
            "modbus": {}, "notes": set()}


def _new_mac(mac):
    return {"mac": mac, "ips": set(), "hostnames": [], "protocols": {},
            "pkts": 0, "bytes": 0, "first": None, "last": None,
            "switch": "", "swport": "", "descr": "", "vlans": set()}


class Inventory:
    def __init__(self):
        self.hosts = {}
        self.macs = {}
        self.flows = {}
        self.arp_claims = {}      # ip -> {mac: count}
        self.overflow_hosts = 0
        self.overflow_macs = 0
        self.overflow_flows = 0
        self.overflow_services = 0
        self.stats = {
            "packets": 0, "decoded": 0, "undecoded": 0, "bytes": 0,
            "first": None, "last": None, "linktypes": {}, "vlans": set(),
            "ipv6_packets": 0, "non_ip": 0, "truncated_payloads": 0,
            "group_packets": 0, "groups": set(),
        }
        self.ethertype_counts = {}

    # ---------- helpers ----------

    def _host(self, ip):
        h = self.hosts.get(ip)
        if h is None:
            if len(self.hosts) >= MAX_HOSTS:
                self.overflow_hosts += 1
                return _new_host(ip)          # scratch record, not retained
            h = self.hosts[ip] = _new_host(ip)
        return h

    def _mac(self, mac):
        m = self.macs.get(mac)
        if m is None:
            if len(self.macs) >= MAX_MACS:
                self.overflow_macs += 1
                return _new_mac(mac)
            m = self.macs[mac] = _new_mac(mac)
        return m

    @staticmethod
    def _bump(d, key, n=1, cap=None):
        if key in d:
            d[key] += n
        elif cap is None or len(d) < cap:
            d[key] = n

    @staticmethod
    def _add_name(lst, name):
        if name and name not in lst and len(lst) < MAX_HOSTNAMES:
            lst.append(name)

    @staticmethod
    def _touch(rec, ts):
        if ts:
            if rec["first"] is None or ts < rec["first"]:
                rec["first"] = ts
            if rec["last"] is None or ts > rec["last"]:
                rec["last"] = ts

    # ---------- service grading ----------

    def _service(self, ip, proto, port):
        h = self._host(ip)
        key = (proto, port)
        svc = h["services"].get(key)
        if svc is None:
            scratch = len(h["services"]) >= MAX_SERVICES_PER_HOST
            if scratch:
                self.overflow_services += 1
            svc = {
                "proto": proto, "port": port, "state": "observed",
                "evidence": "addressed only", "name": port_name(port),
                "peers": set(), "peer_overflow": 0, "pkts": 0, "bytes": 0,
                "first": None, "last": None,
            }
            if not scratch:
                h["services"][key] = svc
        return svc

    def _set_state(self, svc, state, evidence):
        """Evidence only ever strengthens. A host that answered once stays
        SERVING even if a later probe to the same port went unanswered."""
        if STATE_RANK[state] > STATE_RANK.get(svc["state"], 0):
            svc["state"] = state
            svc["evidence"] = evidence

    def _note_peer(self, svc, peer):
        if peer and peer not in svc["peers"]:
            if len(svc["peers"]) < MAX_PEERS_PER_PORT:
                svc["peers"].add(peer)
            else:
                svc["peer_overflow"] += 1

    def _client_port(self, ip, port):
        h = self._host(ip)
        if len(h["client_ports"]) < MAX_CLIENT_PORTS:
            h["client_ports"].add(port)
        else:
            h["client_port_overflow"] += 1

    @staticmethod
    def _guess_server_side(sip, sport, dip, dport):
        """With no handshake in the capture, decide which end is the server.
        Returns (server_ip, server_port, confident) - and confident is ALWAYS
        False here. Only a SYN or SYN/ACK proves a role; everything below is a
        convention, and the output says "role inferred" so nobody quotes a
        guess as a finding.

        Ephemeral source ports are ruled out first, because several OT ports
        (FL-net 55000, DNP3 20000, EtherNet/IP I/O 2222) sit inside the range
        Windows and Linux hand out to clients. Without that test, an ordinary
        web session from port 55000 gets reported as an FL-net server, with the
        client and server exactly backwards."""
        s_eph, d_eph = sport >= EPHEMERAL_MIN, dport >= EPHEMERAL_MIN
        if s_eph != d_eph:
            return (dip, dport, False) if s_eph else (sip, sport, False)
        s_known, d_known = is_ot_port(sport), is_ot_port(dport)
        if d_known != s_known:
            return (dip, dport, False) if d_known else (sip, sport, False)
        s_it, d_it = sport in IT_PORTS, dport in IT_PORTS
        if d_it != s_it:
            return (dip, dport, False) if d_it else (sip, sport, False)
        s_low, d_low = sport < 1024, dport < 1024
        if d_low != s_low:
            return (dip, dport, False) if d_low else (sip, sport, False)
        # Both ends look alike: the lower port is the conventional server side.
        return (dip, dport, False) if dport <= sport else (sip, sport, False)

    # ---------- main ingest ----------

    def add(self, ts, info, orig_len, cap_len, linktype):
        st = self.stats
        st["packets"] += 1
        st["bytes"] += orig_len or cap_len
        if orig_len and cap_len and orig_len > cap_len:
            st["truncated_payloads"] += 1
        self._bump(st["linktypes"], linktype)
        if ts:
            if st["first"] is None or ts < st["first"]:
                st["first"] = ts
            if st["last"] is None or ts > st["last"]:
                st["last"] = ts
        if not info:
            st["undecoded"] += 1
            return
        st["decoded"] += 1

        proto_label = info.get("proto") or info.get("l4") or "unknown"
        vlan = info.get("vlan")
        if vlan is not None:
            st["vlans"].add(vlan)

        src_mac = info.get("src_mac") or ""
        dhcp_mac = info.get("dhcp_mac") or ""
        src_ip = info.get("src_ip") or ""
        dst_ip = info.get("dst_ip") or ""
        hostname = info.get("hostname") or ""

        # --- MAC view ---
        for mac in {m for m in (src_mac, dhcp_mac) if m}:
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
            m = self._mac(mac)
            m["pkts"] += 1
            m["bytes"] += orig_len or cap_len
            self._touch(m, ts)
            self._bump(m["protocols"], proto_label, cap=MAX_LABELS_PER_HOST)
            self._add_name(m["hostnames"], hostname)
            if vlan is not None:
                m["vlans"].add(vlan)
            if info.get("switch") and not m["switch"]:
                m["switch"] = info["switch"]
            if info.get("swport") and not m["swport"]:
                m["swport"] = info["swport"]
            if info.get("detail") and not m["descr"]:
                m["descr"] = info["detail"][:60]
            claim_ip = src_ip or info.get("dhcp_ip") or ""
            if _is_group_ip(claim_ip):
                claim_ip = ""
            if claim_ip and len(m["ips"]) < MAX_IPS_PER_MAC:
                m["ips"].add(claim_ip)

        # --- ARP / DHCP address claims, for conflict detection ---
        if info.get("arp_claim"):
            ip, mac = info["arp_claim"]
            self._bump(self.arp_claims.setdefault(ip, {}), mac)

        # --- host view ---
        # A broadcast or multicast address is a destination, never a host: an
        # inventory that lists 224.0.0.251 as a device is worse than useless.
        dst_is_group = _is_group_ip(dst_ip) or _is_group_mac(info.get("dst_mac"))
        src_is_group = _is_group_ip(src_ip)
        if dst_is_group and dst_ip:
            st["group_packets"] += 1
            if len(st["groups"]) < 64:
                st["groups"].add(dst_ip)
        if not src_ip and not dst_ip:
            st["non_ip"] += 1
        if src_ip and not src_is_group:
            h = self._host(src_ip)
            h["pkts_out"] += 1
            h["bytes_out"] += orig_len or cap_len
            self._touch(h, ts)
            self._bump(h["protocols"], proto_label, cap=MAX_LABELS_PER_HOST)
            self._add_name(h["hostnames"], hostname)
            if src_mac and src_mac != "00:00:00:00:00:00":
                self._bump(h["macs"], src_mac)
            if vlan is not None:
                h["vlans"].add(vlan)
            if dst_ip and not dst_is_group and len(h["peers"]) < 256:
                h["peers"].add(dst_ip)
        if (info.get("dhcp_ip") and info["dhcp_ip"] != src_ip
                and not _is_group_ip(info["dhcp_ip"])):
            h = self._host(info["dhcp_ip"])
            self._touch(h, ts)
            self._add_name(h["hostnames"], hostname)
            if dhcp_mac or src_mac:
                self._bump(h["macs"], dhcp_mac or src_mac)
            h["notes"].add("address seen in DHCP only")
        if dst_ip and not dst_is_group:
            hd = self._host(dst_ip)
            hd["pkts_in"] += 1
            hd["bytes_in"] += orig_len or cap_len
            self._touch(hd, ts)

        # --- L4 port evidence ---
        sport, dport = info.get("sport"), info.get("dport")
        if (sport is None or dport is None or not src_ip or not dst_ip
                or dst_is_group or src_is_group):
            if info.get("icmp_closed_port") and src_ip and not src_is_group:
                svc = self._service(src_ip, "udp", info["icmp_closed_port"])
                self._set_state(svc, "refused", "ICMP port unreachable")
            return

        l4 = "tcp" if info.get("l4") == "TCP" else \
             "udp" if info.get("l4") == "UDP" else info.get("l4", "").lower()
        if l4 not in ("tcp", "udp"):
            return

        key = (l4,) + tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
        flow = self.flows.get(key)
        if flow is None:
            flow = {
                "proto": l4, "a": key[1], "b": key[2], "pkts_a": 0, "pkts_b": 0,
                "live_a": 0, "live_b": 0,
                "bytes": 0, "server": None, "confident": False,
                "syn_to": None, "synack_from": None, "rst_sides": set(),
                "first": None, "last": None, "labels": set(),
            }
            if len(self.flows) < MAX_FLOWS:
                self.flows[key] = flow
            else:
                # Past the cap, correlation across packets is dropped rather
                # than memory grown. Grading degrades to what one packet proves,
                # which is conservative: a state is never downgraded once set.
                self.overflow_flows += 1
        side = "pkts_a" if (src_ip, sport) == flow["a"] else "pkts_b"
        flow[side] += 1
        flow["bytes"] += orig_len or cap_len
        # A RST is an answer, but it is not conversation: counting it as one
        # would promote a closed port to SERVING on the "two-way" rule.
        if not (l4 == "tcp" and info.get("rst")):
            flow["live_" + side[-1]] += 1
        if flow["first"] is None or (ts and ts < flow["first"]):
            flow["first"] = ts
        if ts and (flow["last"] is None or ts > flow["last"]):
            flow["last"] = ts
        if len(flow["labels"]) < MAX_FLOW_LABELS:
            flow["labels"].add(proto_label)

        if l4 == "tcp":
            syn, ack, rst = info.get("syn"), info.get("ack"), info.get("rst")
            if syn and not ack:
                flow["syn_to"] = (dst_ip, dport)
                flow["server"] = (dst_ip, dport)
                flow["confident"] = True
            elif syn and ack:
                flow["synack_from"] = (src_ip, sport)
                flow["server"] = (src_ip, sport)
                flow["confident"] = True
            if rst:
                # Recorded whatever came before it. An ACK scan, or a capture
                # that started mid-scan, produces a RST with no SYN in the file
                # - and that RST is still proof the port is closed.
                flow["rst_sides"].add((src_ip, sport))

        if flow["server"] is None:
            sip, spt, conf = self._guess_server_side(src_ip, sport, dst_ip, dport)
            flow["server"] = (sip, spt)
            flow["confident"] = conf

        srv_ip, srv_port = flow["server"]
        cli = (dst_ip, dport) if (srv_ip, srv_port) == (src_ip, sport) else (src_ip, sport)
        svc = self._service(srv_ip, l4, srv_port)
        svc["pkts"] += 1
        svc["bytes"] += orig_len or cap_len
        if svc["first"] is None or (ts and ts < svc["first"]):
            svc["first"] = ts
        if ts and (svc["last"] is None or ts > svc["last"]):
            svc["last"] = ts
        self._note_peer(svc, cli[0])
        self._client_port(cli[0], cli[1])

        if l4 == "tcp":
            if flow["synack_from"] == (srv_ip, srv_port):
                self._set_state(svc, "serving", "TCP SYN/ACK from host")
            elif flow["live_a"] and flow["live_b"]:
                self._set_state(
                    svc, "serving",
                    "two-way traffic" + ("" if flow["confident"] else " (role inferred)"))
            elif (srv_ip, srv_port) in flow["rst_sides"]:
                self._set_state(svc, "refused", "RST from host")
            else:
                self._set_state(svc, "observed", "addressed only, no reply")
        else:
            if flow["live_a"] and flow["live_b"]:
                self._set_state(
                    svc, "responding",
                    "two-way UDP" + ("" if flow["confident"] else " (role inferred)"))
            else:
                self._set_state(svc, "observed", "one-way UDP, no reply")

        # Modbus function codes, attributed to the server (the controller).
        if info.get("modbus"):
            hsrv = self._host(srv_ip)
            to_server = (src_ip, sport) != (srv_ip, srv_port)
            for fc, is_exc in info["modbus"]:
                name, kind = MODBUS_FUNCS.get(fc, (f"FC {fc}", "other"))
                bucket = "exception" if is_exc else ("request" if to_server else "response")
                self._bump(hsrv["modbus"], (fc, name, kind, bucket))


# ============================================================
#  ANALYSIS / DISPLAY
# ============================================================


def _ts_str(ts):
    if not ts:
        return "-"
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, OverflowError, ValueError):
        return "-"


def _dur_str(a, b):
    if not a or not b or b < a:
        return "-"
    s = b - a
    if s < 60:
        return f"{s:.1f}s"
    if s < 3600:
        return f"{int(s // 60)}m {int(s % 60)}s"
    return f"{int(s // 3600)}h {int((s % 3600) // 60)}m"


def _bytes_str(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def _ip_sort_key(ip):
    try:
        return (0, tuple(int(p) for p in ip.split(".")))
    except (ValueError, AttributeError):
        return (1, ip)


def _endpoint(ip, port):
    """host:port, RFC 3986 style for IPv6 so the result stays parseable."""
    return f"[{ip}]:{port}" if ip and ":" in ip else f"{ip}:{port}"


def _trunc(s, n):
    s = s or ""
    if len(s) <= n:
        return s
    # ASCII only: a horizontal ellipsis is undefined in cp437/cp850 and breaks
    # redirected output on a legacy Windows code page.
    return s[: n - 3] + "..." if n > 3 else s[:n]


STATE_LABEL = {
    "serving": "SERVING",
    "responding": "RESPONDING",
    "refused": "REFUSED",
    "observed": "OBSERVED",
}
STATE_COLOR = {
    "serving": C.GOOD, "responding": C.GOOD, "refused": C.DIM, "observed": C.WARN,
}


def _svc_str(svc, color=True):
    port, proto = svc["port"], svc["proto"]
    name = svc["name"]
    txt = f"{proto}/{port}"
    if name:
        txt += f" {name}"
    tag = STATE_LABEL[svc["state"]]
    body = f"{txt} [{tag}]"
    if color and _COLOR and is_ot_port(port):
        return _c(C.OT, body)
    return body


def print_file_summary(cap, inv, path):
    st = inv.stats
    fmt, links = cap.describe()
    head("CAPTURE FILE")
    echo(f"  File          : {os.path.abspath(path)}")
    try:
        echo(f"  Size on disk  : {_bytes_str(os.path.getsize(path))}")
    except OSError:
        pass
    echo(f"  Format        : {fmt}")
    echo(f"  Link type(s)  : {links}")
    if cap.snaplen:
        echo(f"  Snap length   : {cap.snaplen} bytes")
    echo(f"  Packets       : {st['packets']} "
         f"({st['decoded']} dissected, {st['undecoded']} not understood)")
    echo(f"  Capture bytes : {_bytes_str(st['bytes'])}")
    echo(f"  First packet  : {_ts_str(st['first'])}")
    echo(f"  Last packet   : {_ts_str(st['last'])}")
    echo(f"  Duration      : {_dur_str(st['first'], st['last'])}")
    if st["vlans"]:
        echo(f"  VLAN IDs seen : {', '.join(str(v) for v in sorted(st['vlans']))}")
    if st["group_packets"]:
        groups = sorted(st["groups"], key=_ip_sort_key)
        echo(f"  Bcast/mcast   : {st['group_packets']} packet(s) to "
             f"{len(groups)} group address(es) - {', '.join(groups[:6])}"
             + (" ..." if len(groups) > 6 else ""))
        echo("                  (group addresses are destinations, not hosts, so "
             "they are not listed below)")
    if st["truncated_payloads"]:
        warn(f"  [!] {st['truncated_payloads']} packet(s) were sliced by the capture "
             f"snap length - payload-based findings may be incomplete.")
    if cap.truncated:
        warn("  [!] The file ends mid-record: it was truncated or the capture was "
             "still running. Everything read before that point is reported.")
    if cap.read_error:
        warn(f"  [!] The file is damaged and reading stopped early: {cap.read_error}")
        warn("      Everything decoded before that point is reported, but treat the "
             "inventory as partial.")
    unsupported = [lt for lt in (cap.seen_linktypes or set(cap.linktypes.values()))
                   if lt not in SUPPORTED_DLTS]
    if unsupported:
        warn(f"  [!] Unsupported link type(s) present: "
             f"{', '.join(str(u) for u in sorted(set(unsupported)))} - those packets "
             f"were skipped.")


def print_hosts(inv, args):
    hosts = sorted(inv.hosts.values(), key=lambda h: _ip_sort_key(h["ip"]))
    if args.host:
        hosts = [h for h in hosts if h["ip"] in args.host]
    head(f"HOSTS  ({len(hosts)} IP address{'es' if len(hosts) != 1 else ''})")
    if not hosts:
        echo("  No IP addresses in this capture.")
        return
    if len(hosts) > SHOW_HOSTS_DEFAULT and not args.all_ports:
        warn(f"  Showing the first {SHOW_HOSTS_DEFAULT} of {len(hosts)} - use "
             f"--all-ports for every host, or --csv for the full inventory.")
        hosts = hosts[:SHOW_HOSTS_DEFAULT]
    for h in hosts:
        macs = sorted(h["macs"].items(), key=lambda kv: -kv[1])
        primary = macs[0][0] if macs else ""
        label = h["ip"]
        echo("")
        line = f"  {_c(C.HEAD, label)}" if _COLOR else f"  {label}"
        extras = []
        if h["hostnames"]:
            extras.append(", ".join(h["hostnames"]))
        if h["vlans"]:
            extras.append("VLAN " + ",".join(str(v) for v in sorted(h["vlans"])))
        print(line + (f"   {_c(C.BODY, ' | '.join(extras))}" if extras else ""))
        if primary:
            echo(f"      MAC        : {_mac_with_vendor(primary)}")
            for mac, cnt in macs[1:]:
                echo(f"                   also {_mac_with_vendor(mac)} "
                     f"({cnt} frame{'s' if cnt != 1 else ''})")
        else:
            echo("      MAC        : not observed (routed traffic, or a "
                 "cooked/raw capture)")
        echo(f"      Traffic    : {h['pkts_out']} sent / {h['pkts_in']} received, "
             f"{_bytes_str(h['bytes_out'] + h['bytes_in'])}")
        echo(f"      Seen       : {_ts_str(h['first'])} -> {_ts_str(h['last'])}")

        svcs = sorted(h["services"].values(),
                      key=lambda s: (-STATE_RANK[s["state"]], s["proto"], s["port"]))
        strong = [s for s in svcs if s["state"] in ("serving", "responding")]
        weak = [s for s in svcs if s["state"] == "observed"]
        closed = [s for s in svcs if s["state"] == "refused"]
        if strong:
            echo("      Answering  :")
            for s in strong:
                echo(f"        - {_svc_str(s)}  {s['evidence']}, "
                     f"{len(s['peers'])} peer{'s' if len(s['peers']) != 1 else ''}, "
                     f"{s['pkts']} pkts")
        if closed:
            echo("      Closed     : " + ", ".join(
                f"{s['proto']}/{s['port']}" for s in closed[:16]))
        if weak:
            shown = weak if args.all_ports else weak[:8]
            echo("      Addressed  : " + ", ".join(
                f"{s['proto']}/{s['port']}" + (f" {s['name']}" if s["name"] else "")
                for s in shown)
                 + ("" if len(shown) == len(weak)
                    else f"  (+{len(weak) - len(shown)} more, --all-ports to list)"))
        if h["client_ports"] and (args.all_ports or args.verbose):
            n = len(h["client_ports"]) + h["client_port_overflow"]
            echo(f"      Client-side: {n} source port(s) used to reach others")
        protos = sorted(h["protocols"].items(), key=lambda kv: -kv[1])
        if protos:
            echo("      Protocols  : " + ", ".join(
                f"{p} ({c})" for p, c in protos[:10]))
        for note in sorted(h["notes"]):
            warn(f"      Note       : {note}")


def print_macs(inv, args):
    macs = sorted(inv.macs.values(), key=lambda m: -m["pkts"])
    head(f"MAC ADDRESSES  ({len(macs)})")
    if not macs:
        echo("  No MAC addresses in this capture (cooked or raw-IP link type).")
        return
    if len(macs) > SHOW_MACS_DEFAULT and not args.all_ports:
        warn(f"  Showing the {SHOW_MACS_DEFAULT} busiest of {len(macs)} - use "
             f"--all-ports for every MAC, or --json for the full list.")
        macs = macs[:SHOW_MACS_DEFAULT]
    echo(f"  {'MAC':<18} {'VENDOR':<30} {'PKTS':>7}  IP ADDRESS(ES)")
    echo(f"  {'-' * 18} {'-' * 30} {'-' * 7}  {'-' * 24}")
    for m in macs:
        ips = sorted(m["ips"], key=_ip_sort_key)
        ipstr = ", ".join(ips[:4]) + (f" (+{len(ips) - 4})" if len(ips) > 4 else "")
        echo(f"  {m['mac']:<18} {_trunc(_vendor_label(m['mac']), 30):<30} "
             f"{m['pkts']:>7}  {ipstr or '-'}")
        if m["switch"] or m["swport"]:
            echo(f"      -> announced itself as '{m['switch']}'"
                 + (f" port '{m['swport']}'" if m["swport"] else "")
                 + (f" ({m['descr']})" if m["descr"] else ""))
        elif m["hostnames"]:
            echo(f"      -> hostname: {', '.join(m['hostnames'])}")


def print_ports(inv, args):
    """Every service port in the capture, grouped by evidence strength."""
    rows = []
    for h in inv.hosts.values():
        if args.host and h["ip"] not in args.host:
            continue
        for s in h["services"].values():
            rows.append((h["ip"], s))
    head(f"PORTS / SERVICES  ({len(rows)} host-port pair"
         f"{'s' if len(rows) != 1 else ''})")
    if not rows:
        echo("  No TCP/UDP traffic in this capture.")
        return
    order = {"serving": 0, "responding": 1, "refused": 2, "observed": 3}
    rows.sort(key=lambda r: (order[r[1]["state"]], _ip_sort_key(r[0]),
                             r[1]["proto"], r[1]["port"]))
    echo(f"  {'STATE':<11} {'HOST':<16} {'PORT':<10} {'SERVICE':<30} EVIDENCE")
    echo(f"  {'-' * 11} {'-' * 16} {'-' * 10} {'-' * 30} {'-' * 26}")
    shown = 0
    for ip, s in rows:
        if s["state"] == "observed" and not args.all_ports and shown > 400:
            break
        tag = STATE_LABEL[s["state"]]
        tagc = _c(STATE_COLOR[s["state"]], f"{tag:<11}") if _COLOR else f"{tag:<11}"
        portc = f"{s['proto']}/{s['port']}"
        name = _trunc(s["name"], 30)
        if _COLOR and is_ot_port(s["port"]):
            name = _c(C.OT, f"{name:<30}")
        else:
            name = f"{name:<30}"
        print(f"  {tagc} {_trunc(ip, 16):<16} {portc:<10} {name} "
              f"{_c(C.BODY, s['evidence'])}")
        shown += 1
    echo("")
    echo("  SERVING/RESPONDING = the host answered. REFUSED = answered, port closed.")
    echo("  OBSERVED = addressed only; suspected, not proven by this capture.")


def print_ot(inv, args):
    """OT/ICS read of the same data: which hosts speak control protocols, which
    side is the master/client, and whether anything wrote to a controller."""
    answering, addressed = [], []
    for h in inv.hosts.values():
        for s in h["services"].values():
            if not is_ot_port(s["port"]):
                continue
            if s["state"] in ("serving", "responding"):
                answering.append((h["ip"], s))
            else:
                addressed.append((h["ip"], s))
    head("OT / ICS PROTOCOL FINDINGS")
    if not answering and not addressed:
        echo("  No traffic on a known OT/ICS protocol port in this capture.")
        echo("  That is not proof of absence: a proprietary or non-standard port,")
        echo("  serial-tunnelled traffic, or a capture point on the wrong segment")
        echo("  all look identical to this tool.")
        return

    if answering:
        echo("  Confirmed control-protocol servers. The peers listed under each one are")
        echo("  the clients polling it - expect HMI, SCADA, historian or engineering")
        echo("  workstation, and question anything else.")
        answering.sort(key=lambda r: (_ip_sort_key(r[0]), r[1]["port"]))
        for ip, s in answering:
            echo("")
            line = (f"  {ip}  {s['proto']}/{s['port']}  {s['name']}  "
                    f"[{STATE_LABEL[s['state']]}]")
            print(_c(C.OT, line) if _COLOR else line)
            echo(f"      Role       : server / outstation ({s['evidence']})")
            peers = sorted(s["peers"], key=_ip_sort_key)
            if peers:
                pl = ", ".join(peers[:8]) + (f" (+{len(peers) - 8} more)"
                                             if len(peers) > 8 else "")
                echo(f"      Clients    : {pl}")
                if len(peers) > 3:
                    warn(f"      [!] {len(peers)} different hosts polled this "
                         f"controller. On a well-segmented plant that list is "
                         f"short and known.")
            echo(f"      Volume     : {s['pkts']} packets, "
                 f"{_bytes_str(s['bytes'])}, "
                 f"{_ts_str(s['first'])} -> {_ts_str(s['last'])}")
            h = inv.hosts[ip]
            if s["port"] == 502 and h["modbus"]:
                _print_modbus(h)

    if addressed:
        echo("")
        echo("  Control-protocol ports addressed but never answered in this capture")
        echo("  (a probe, a scan, a dead device, or simply nothing listening):")
        byhost = {}
        for ip, s in addressed:
            byhost.setdefault(ip, []).append(s)
        for ip in sorted(byhost, key=_ip_sort_key):
            svcs = sorted(byhost[ip], key=lambda x: x["port"])
            ports = ", ".join(f"{x['proto']}/{x['port']}" for x in svcs[:14])
            more = f" (+{len(svcs) - 14} more)" if len(svcs) > 14 else ""
            probers = sorted({p for x in svcs for p in x["peers"]}, key=_ip_sort_key)
            echo(f"    {ip}: {ports}{more}")
            if probers:
                echo(f"      addressed by {', '.join(probers[:6])}"
                     + (" ..." if len(probers) > 6 else ""))

    plain = []
    for h in inv.hosts.values():
        for s in h["services"].values():
            if s["port"] in PLAINTEXT_PORTS and s["state"] in ("serving", "responding"):
                plain.append((h["ip"], s["port"], PLAINTEXT_PORTS[s["port"]]))
    if plain:
        echo("")
        warn("  Cleartext services answering (credentials/control exposed on the wire):")
        for ip, port, why in sorted(plain, key=lambda r: (_ip_sort_key(r[0]), r[1])):
            warn(f"    - {ip}:{port}  {why}")


def _print_modbus(h):
    """Modbus function-code breakdown for one controller. Read vs write is the
    line that matters: reads are telemetry, writes are process control."""
    reads = sum(c for (fc, n, k, b), c in h["modbus"].items()
                if k == "read" and b == "request")
    writes = sum(c for (fc, n, k, b), c in h["modbus"].items()
                 if k == "write" and b == "request")
    excs = sum(c for (fc, n, k, b), c in h["modbus"].items() if b == "exception")
    echo(f"      Modbus     : {reads} read request(s), {writes} write request(s), "
         f"{excs} exception response(s)")
    detail = sorted(((n, b, c) for (fc, n, k, b), c in h["modbus"].items()),
                    key=lambda t: -t[2])
    for name, bucket, cnt in detail[:8]:
        echo(f"                   - {name} [{bucket}] x{cnt}")
    if excs:
        echo("                   Exception responses mean the master asked for "
             "something the")
        echo("                   device would not do - wrong register map, wrong "
             "unit ID, or")
        echo("                   a poll the device rejects. Worth explaining.")
    if writes:
        warn("      [!] WRITE traffic to this controller was captured. Confirm it came")
        warn("          from an authorised master inside an authorised window - this is")
        warn("          process control, not telemetry.")


def print_anomalies(inv, args):
    findings = []
    for ip, claims in inv.arp_claims.items():
        if len(claims) > 1:
            who = ", ".join(f"{m} ({_vendor_label(m)}, {c} frames)"
                            for m, c in sorted(claims.items(), key=lambda kv: -kv[1]))
            findings.append(
                f"IP {ip} was claimed in ARP by {len(claims)} different MACs: {who}\n"
                f"      -> duplicate address, a device replaced without cleanup, "
                f"failover, or ARP spoofing. Worth chasing.")
    for m in inv.macs.values():
        if len(m["ips"]) >= 4:
            findings.append(
                f"MAC {m['mac']} ({_vendor_label(m['mac'])}) carried "
                f"{len(m['ips'])} IP addresses\n"
                f"      -> a router/firewall/hypervisor uplink, or the capture point "
                f"is upstream of a layer-3 hop.")
    noisy = [h for h in inv.hosts.values()
             if h["pkts_out"] == 0 and h["pkts_in"] > 0]
    if noisy:
        ips = ", ".join(sorted((h["ip"] for h in noisy), key=_ip_sort_key)[:12])
        findings.append(
            f"{len(noisy)} address(es) were addressed but never sent a single packet: "
            f"{ips}\n      -> offline, filtered, off this segment, or scan targets.")
    unanswered = {}
    for h in inv.hosts.values():
        for x in h["services"].values():
            if x["state"] != "observed":
                continue
            for peer in x["peers"]:
                unanswered[peer] = unanswered.get(peer, 0) + 1
    for ip, n in sorted(unanswered.items(), key=lambda t: -t[1])[:5]:
        if n < 20:
            break
        findings.append(
            f"{ip} addressed {n} unanswered host-ports\n"
            f"      -> looks like a scan or a sweep. Confirm it was an authorised "
            f"tool and not something unexpected on the segment.")
    if inv.stats["vlans"] and len(inv.stats["vlans"]) > 1:
        findings.append(
            f"{len(inv.stats['vlans'])} VLAN IDs appear in one capture "
            f"({', '.join(str(v) for v in sorted(inv.stats['vlans']))})\n"
            f"      -> the capture point is a trunk or mirror of several VLANs; keep "
            f"that in mind before saying two hosts are 'on the same network'.")
    head("OBSERVATIONS / ANOMALIES")
    if not findings:
        echo("  Nothing structurally odd found: no duplicate IP claims, no "
             "multi-homed MACs,")
        echo("  no obvious sweeps.")
        return
    for f in findings:
        warn(f"  [!] {f}")


def print_flows(inv, args):
    flows = sorted(inv.flows.values(), key=lambda f: -(f["pkts_a"] + f["pkts_b"]))
    n = args.top or 20
    head(f"CONVERSATIONS  (top {min(n, len(flows))} of {len(flows)})")
    if not flows:
        echo("  No TCP/UDP conversations in this capture.")
        return
    echo(f"  {'PROTO':<5} {'ENDPOINT A':<22} {'ENDPOINT B':<22} "
         f"{'PKTS':>7} {'BYTES':>10}  SERVICE")
    echo(f"  {'-' * 5} {'-' * 22} {'-' * 22} {'-' * 7} {'-' * 10}  {'-' * 20}")
    for f in flows[:n]:
        a = _endpoint(f["a"][0], f["a"][1])
        b = _endpoint(f["b"][0], f["b"][1])
        labels = ", ".join(sorted(f["labels"]))[:28]
        echo(f"  {f['proto']:<5} {_trunc(a, 22):<22} {_trunc(b, 22):<22} "
             f"{f['pkts_a'] + f['pkts_b']:>7} {_bytes_str(f['bytes']):>10}  {labels}")


def print_summary(inv):
    st = inv.stats
    serving = sum(1 for h in inv.hosts.values() for s in h["services"].values()
                  if s["state"] in ("serving", "responding"))
    observed = sum(1 for h in inv.hosts.values() for s in h["services"].values()
                   if s["state"] == "observed")
    ot_hosts = {h["ip"] for h in inv.hosts.values()
                for s in h["services"].values() if is_ot_port(s["port"])}
    head("SUMMARY")
    echo(f"  {len(inv.hosts)} IP address(es), {len(inv.macs)} MAC address(es), "
         f"{len(inv.flows)} conversation(s)")
    echo(f"  {serving} confirmed service port(s), {observed} addressed-only port(s)")
    echo(f"  {len(ot_hosts)} host(s) on OT/ICS protocol ports")
    if (inv.overflow_hosts or inv.overflow_macs or inv.overflow_flows
            or inv.overflow_services):
        warn("  [!] An inventory cap was hit, so some observations were not "
             "retained:")
        if inv.overflow_hosts:
            warn(f"        {inv.overflow_hosts} host observation(s) beyond "
                 f"{MAX_HOSTS} hosts")
        if inv.overflow_macs:
            warn(f"        {inv.overflow_macs} MAC observation(s) beyond "
                 f"{MAX_MACS} MACs")
        if inv.overflow_flows:
            warn(f"        {inv.overflow_flows} packet(s) beyond {MAX_FLOWS} "
                 f"tracked conversations - port evidence for those is "
                 f"conservative")
        if inv.overflow_services:
            warn(f"        {inv.overflow_services} port observation(s) beyond "
                 f"{MAX_SERVICES_PER_HOST} ports on one host")
        warn("      Split the capture (editcap -c) or filter it (tshark -Y) before")
        warn("      analysing - a capture this wide is usually a mirror of several")
        warn("      segments at once.")
    if OUI_SOURCE is None and inv.macs:
        unresolved = sum(1 for m in inv.macs if _oui_vendor(m) == "")
        if unresolved:
            echo(f"  {unresolved} MAC(s) show '(unknown vendor)' - no OUI database "
                 f"loaded. Run --update-oui once.")


# ============================================================
#  EXPORT
# ============================================================


def _default_name(kind, ext, path):
    base = os.path.splitext(os.path.basename(path))[0]
    if base.endswith(".pcap"):
        base = base[:-5]
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return os.path.join(os.getcwd(), f"taproot_{base}_{kind}_{stamp}.{ext}")


def export_csv(inv, path, capture_path):
    """Two CSVs: one row per host, one row per host-port."""
    hosts_path = path if path else _default_name("hosts", "csv", capture_path)
    ports_path = (os.path.splitext(hosts_path)[0] + "_ports.csv"
                  if path else _default_name("ports", "csv", capture_path))
    try:
        with open(hosts_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "mac", "vendor", "other_macs", "hostnames",
                        "vlans", "pkts_sent", "pkts_received", "bytes_total",
                        "first_seen", "last_seen", "serving_ports",
                        "observed_ports", "refused_ports", "protocols", "notes"])
            for h in sorted(inv.hosts.values(), key=lambda x: _ip_sort_key(x["ip"])):
                macs = sorted(h["macs"].items(), key=lambda kv: -kv[1])
                primary = macs[0][0] if macs else ""
                svcs = h["services"].values()
                w.writerow([
                    h["ip"], primary, _vendor_label(primary) if primary else "",
                    " ".join(m for m, _ in macs[1:]),
                    " ".join(h["hostnames"]),
                    " ".join(str(v) for v in sorted(h["vlans"])),
                    h["pkts_out"], h["pkts_in"], h["bytes_out"] + h["bytes_in"],
                    _ts_str(h["first"]), _ts_str(h["last"]),
                    " ".join(f"{s['proto']}/{s['port']}" for s in svcs
                             if s["state"] in ("serving", "responding")),
                    " ".join(f"{s['proto']}/{s['port']}" for s in svcs
                             if s["state"] == "observed"),
                    " ".join(f"{s['proto']}/{s['port']}" for s in svcs
                             if s["state"] == "refused"),
                    " ".join(sorted(h["protocols"])),
                    "; ".join(sorted(h["notes"])),
                ])
        with open(ports_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "transport", "port", "service", "is_ot_protocol",
                        "state", "evidence", "peers", "packets", "bytes",
                        "first_seen", "last_seen"])
            for h in sorted(inv.hosts.values(), key=lambda x: _ip_sort_key(x["ip"])):
                for s in sorted(h["services"].values(),
                                key=lambda x: (x["proto"], x["port"])):
                    w.writerow([
                        h["ip"], s["proto"], s["port"], s["name"],
                        "yes" if is_ot_port(s["port"]) else "no",
                        STATE_LABEL[s["state"]], s["evidence"],
                        " ".join(sorted(s["peers"], key=_ip_sort_key)),
                        s["pkts"], s["bytes"], _ts_str(s["first"]), _ts_str(s["last"]),
                    ])
    except OSError as e:
        bad(f"[x] CSV export failed: {e}")
        return
    echo(f"[+] Hosts CSV : {hosts_path}")
    echo(f"[+] Ports CSV : {ports_path}")


def export_json(inv, path, capture_path, cap):
    out_path = path if path else _default_name("report", "json", capture_path)
    fmt, links = cap.describe()
    doc = {
        "tool": TOOL_NAME, "version": VERSION,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "capture": {
            "path": getattr(cap, "display_path", None) or os.path.abspath(capture_path),
            "format": fmt,
            "link_types": links, "snaplen": cap.snaplen,
            "packets": inv.stats["packets"],
            "bytes": inv.stats["bytes"],
            "first_packet": _ts_str(inv.stats["first"]),
            "last_packet": _ts_str(inv.stats["last"]),
            "truncated": cap.truncated,
            "vlans": sorted(inv.stats["vlans"]),
        },
        "oui_database": OUI_SOURCE,
        "hosts": [], "macs": [], "conversations": [],
    }
    if getattr(cap, "live_info", None):
        doc["capture"]["live"] = cap.live_info
    for h in sorted(inv.hosts.values(), key=lambda x: _ip_sort_key(x["ip"])):
        macs = sorted(h["macs"].items(), key=lambda kv: -kv[1])
        doc["hosts"].append({
            "ip": h["ip"],
            "macs": [{"mac": m, "vendor": _vendor_label(m), "frames": c}
                     for m, c in macs],
            "hostnames": h["hostnames"],
            "vlans": sorted(h["vlans"]),
            "packets_sent": h["pkts_out"], "packets_received": h["pkts_in"],
            "bytes": h["bytes_out"] + h["bytes_in"],
            "first_seen": _ts_str(h["first"]), "last_seen": _ts_str(h["last"]),
            "client_ports_used": len(h["client_ports"]) + h["client_port_overflow"],
            "protocols": h["protocols"],
            "services": [{
                "transport": s["proto"], "port": s["port"], "service": s["name"],
                "ot_protocol": is_ot_port(s["port"]),
                "state": STATE_LABEL[s["state"]], "evidence": s["evidence"],
                "peers": sorted(s["peers"], key=_ip_sort_key),
                "packets": s["pkts"], "bytes": s["bytes"],
            } for s in sorted(h["services"].values(),
                              key=lambda x: (x["proto"], x["port"]))],
            "modbus": [{"function_code": fc, "function": n, "kind": k,
                        "direction": b, "count": c}
                       for (fc, n, k, b), c in sorted(h["modbus"].items(),
                                                      key=lambda kv: -kv[1])],
            "notes": sorted(h["notes"]),
        })
    for m in sorted(inv.macs.values(), key=lambda x: -x["pkts"]):
        doc["macs"].append({
            "mac": m["mac"], "vendor": _vendor_label(m["mac"]),
            "ips": sorted(m["ips"], key=_ip_sort_key),
            "hostnames": m["hostnames"], "packets": m["pkts"], "bytes": m["bytes"],
            "announced_name": m["switch"], "announced_port": m["swport"],
            "description": m["descr"],
            "first_seen": _ts_str(m["first"]), "last_seen": _ts_str(m["last"]),
            "vlans": sorted(m["vlans"]),
        })
    for f in sorted(inv.flows.values(), key=lambda x: -(x["pkts_a"] + x["pkts_b"])):
        doc["conversations"].append({
            "transport": f["proto"],
            "endpoint_a": _endpoint(f["a"][0], f["a"][1]),
            "endpoint_a_ip": f["a"][0], "endpoint_a_port": f["a"][1],
            "endpoint_b": _endpoint(f["b"][0], f["b"][1]),
            "endpoint_b_ip": f["b"][0], "endpoint_b_port": f["b"][1],
            "server": _endpoint(*f["server"]) if f["server"] else None,
            "server_role_confident": f["confident"],
            "packets": f["pkts_a"] + f["pkts_b"], "bytes": f["bytes"],
            "labels": sorted(f["labels"]),
        })
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
    except OSError as e:
        bad(f"[x] JSON export failed: {e}")
        return
    echo(f"[+] JSON      : {out_path}")


# ============================================================
#  LIVE CAPTURE - SOURCES
# ============================================================
# Three ways to get frames off an interface, best first. Every one of them is
# RECEIVE-ONLY: TAPROOT opens a capture handle and reads from it, and never
# writes a frame to the interface.
#
#   pcap     Npcap (Windows) or libpcap (Linux/macOS), called through ctypes -
#            no pip package. Full Ethernet frames, so MACs, ARP, LLDP, CDP and
#            PROFINET DCP all work; promiscuous mode, BPF filter, drop counters.
#            Npcap is installed with Wireshark on most engineering laptops.
#   afpacket Linux only, standard library raw socket. Full frames, but the
#            kernel strips 802.1Q tags (VLAN IDs will not show) and there is no
#            BPF filter.
#   rawsock  Windows last resort (SIO_RCVALL). IPv4 only, NO Ethernet header:
#            no MACs, no ARP/LLDP/CDP/DCP. The NIC must have an IP address,
#            which means the OS is a live host on that network. Labelled
#            DEGRADED everywhere it appears.

class LiveError(Exception):
    pass


class LiveIface:
    """One capturable interface, as whichever backend sees it."""

    def __init__(self, name, desc="", addrs=None, friendly="", loopback=False,
                 backend=""):
        self.name = name              # what the backend opens
        self.desc = desc or ""
        self.addrs = list(addrs or [])  # IPv4 addresses bound to it
        self.friendly = friendly or ""  # Windows "Ethernet 2" style name
        self.loopback = loopback
        self.backend = backend

    def label(self):
        """Short human name for banners and default filenames."""
        return self.friendly or self.name

    def line(self):
        bits = [self.friendly] if self.friendly else []
        if self.desc and self.desc != self.friendly:
            bits.append(self.desc)
        extra = "  ".join(bits)
        ips = ", ".join(self.addrs) if self.addrs else "no IPv4"
        return self.name, extra, ips


# ---------- pcap via ctypes ----------

PCAP_ERRBUF_SIZE = 256
PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF
PCAP_IF_LOOPBACK = 0x00000001
PCAP_ACTIVATE_ERRORS = {
    -1: "generic error",
    -3: "capture handle not activated",
    -4: "capture handle already activated",
    -5: "no such device",
    -6: "monitor mode not supported",
    -8: "permission denied",
    -9: "interface is not up",
    -11: "permission denied for promiscuous mode",
}
PCAP_ACTIVATE_WARNINGS = {
    1: "libpcap warning",
    2: "this interface does not support promiscuous mode - only traffic to "
       "and from this machine will be seen",
    3: "requested timestamp type not supported",
}

try:
    import ctypes
    import ctypes.util
except ImportError:                 # a stripped-down embedded Python
    ctypes = None

if ctypes is not None:
    class _Timeval(ctypes.Structure):
        # Windows: two 32-bit longs. Linux: two native longs. macOS: long
        # tv_sec + 32-bit tv_usec (the structure is then padded to 16 bytes).
        _fields_ = [("tv_sec", ctypes.c_long),
                    ("tv_usec", ctypes.c_int32 if sys.platform == "darwin"
                     else ctypes.c_long)]

    class _PcapPkthdr(ctypes.Structure):
        _fields_ = [("ts", _Timeval), ("caplen", ctypes.c_uint32),
                    ("len", ctypes.c_uint32)]

    class _PcapStat(ctypes.Structure):
        # ps_recv / ps_drop / ps_ifdrop; Npcap may append bs_capt. The pad
        # makes room for anything a library appends.
        _fields_ = [("ps_recv", ctypes.c_uint), ("ps_drop", ctypes.c_uint),
                    ("ps_ifdrop", ctypes.c_uint), ("_pad", ctypes.c_uint * 8)]

    class _SockAddr(ctypes.Structure):
        _fields_ = [("raw", ctypes.c_ubyte * 16)]

    class _PcapAddr(ctypes.Structure):
        pass

    _PcapAddr._fields_ = [("next", ctypes.POINTER(_PcapAddr)),
                          ("addr", ctypes.POINTER(_SockAddr)),
                          ("netmask", ctypes.POINTER(_SockAddr)),
                          ("broadaddr", ctypes.POINTER(_SockAddr)),
                          ("dstaddr", ctypes.POINTER(_SockAddr))]

    class _PcapIf(ctypes.Structure):
        pass

    _PcapIf._fields_ = [("next", ctypes.POINTER(_PcapIf)),
                        ("name", ctypes.c_char_p),
                        ("description", ctypes.c_char_p),
                        ("addresses", ctypes.POINTER(_PcapAddr)),
                        ("flags", ctypes.c_uint32)]

    class _BpfProgram(ctypes.Structure):
        _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]

_PCAP = {"lib": None, "err": "", "tried": False, "path": ""}


def _bind_pcap(lib):
    """Declare the libpcap calls TAPROOT uses. A missing required symbol
    raises AttributeError, which rejects the library."""
    P, I, S = ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p
    lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_PcapIf)), S]
    lib.pcap_findalldevs.restype = I
    lib.pcap_freealldevs.argtypes = [ctypes.POINTER(_PcapIf)]
    lib.pcap_freealldevs.restype = None
    lib.pcap_open_live.argtypes = [S, I, I, I, S]
    lib.pcap_open_live.restype = P
    lib.pcap_datalink.argtypes = [P]
    lib.pcap_datalink.restype = I
    lib.pcap_next_ex.argtypes = [P, ctypes.POINTER(ctypes.POINTER(_PcapPkthdr)),
                                 ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    lib.pcap_next_ex.restype = I
    lib.pcap_close.argtypes = [P]
    lib.pcap_close.restype = None
    lib.pcap_geterr.argtypes = [P]
    lib.pcap_geterr.restype = S
    lib.pcap_compile.argtypes = [P, ctypes.POINTER(_BpfProgram), S, I, ctypes.c_uint32]
    lib.pcap_compile.restype = I
    lib.pcap_setfilter.argtypes = [P, ctypes.POINTER(_BpfProgram)]
    lib.pcap_setfilter.restype = I
    lib.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
    lib.pcap_freecode.restype = None
    lib.pcap_stats.argtypes = [P, ctypes.POINTER(_PcapStat)]
    lib.pcap_stats.restype = I
    # Optional - newer API. Old WinPcap 4.x lacks some of these; the code falls
    # back to pcap_open_live when they are missing.
    for name, args, res in (
            ("pcap_create", [S, S], P),
            ("pcap_set_snaplen", [P, I], I),
            ("pcap_set_promisc", [P, I], I),
            ("pcap_set_timeout", [P, I], I),
            ("pcap_set_immediate_mode", [P, I], I),
            ("pcap_set_buffer_size", [P, I], I),
            ("pcap_activate", [P], I),
            ("pcap_setnonblock", [P, I, S], I),
            ("pcap_get_selectable_fd", [P], I),
            ("pcap_getevent", [P], P),
            ("pcap_lib_version", [], S)):
        fn = getattr(lib, name, None)
        if fn is not None:
            fn.argtypes, fn.restype = args, res


def _load_pcap():
    """Find Npcap / libpcap. Returns the library or None (reason in
    _PCAP['err']). Tried once per run."""
    if _PCAP["tried"]:
        return _PCAP["lib"]
    _PCAP["tried"] = True
    if ctypes is None:
        _PCAP["err"] = "this Python has no ctypes module"
        return None
    cands = []
    if os.name == "nt":
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        npdir = os.path.join(sysroot, "System32", "Npcap")
        if os.path.isdir(npdir):
            try:
                os.add_dll_directory(npdir)      # Python 3.8+: Packet.dll lives here too
            except (AttributeError, OSError):
                pass
            cands.append(os.path.join(npdir, "wpcap.dll"))
        cands.append("wpcap.dll")                # WinPcap-compatible installs
    else:
        found = ctypes.util.find_library("pcap")
        if found:
            cands.append(found)
        cands += ["libpcap.so.1", "libpcap.so.0.8", "libpcap.so",
                  "/usr/lib/libpcap.dylib", "libpcap.dylib"]
    errs = []
    for c in cands:
        try:
            lib = ctypes.CDLL(c)
            _bind_pcap(lib)
        except (OSError, AttributeError) as e:
            errs.append(f"{c}: {e}")
            continue
        _PCAP["lib"], _PCAP["path"] = lib, c
        return lib
    _PCAP["err"] = ("Npcap not found (install it from https://npcap.com, or install "
                    "Wireshark, which bundles it)" if os.name == "nt"
                    else "libpcap not found (apt install libpcap0.8 / dnf install libpcap)")
    return None


def _pcap_version():
    lib = _PCAP["lib"]
    fn = getattr(lib, "pcap_lib_version", None) if lib else None
    try:
        return fn().decode(errors="replace") if fn else ""
    except Exception:
        return ""


def _sockaddr_ipv4(ptr):
    if not ptr:
        return ""
    raw = bytes(ptr.contents.raw)
    if sys.platform == "darwin" or "bsd" in sys.platform:
        fam = raw[1]                              # sa_len, sa_family (one byte each)
    else:
        fam = struct.unpack("=H", raw[:2])[0]
    if fam != socket.AF_INET:
        return ""
    return socket.inet_ntoa(raw[4:8])


def _win_friendly_names():
    """{GUID: 'Ethernet 2'} from the registry, so the list shows the names
    people see in ncpa.cpl instead of \\Device\\NPF_{GUID}."""
    out = {}
    try:
        import winreg
    except ImportError:
        return out
    base = (r"SYSTEM\CurrentControlSet\Control\Network"
            r"\{4D36E972-E325-11CE-BFC1-08002BE10318}")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(k, guid + r"\Connection") as c:
                        out[guid.upper()] = winreg.QueryValueEx(c, "Name")[0]
                except OSError:
                    continue
    except OSError:
        pass
    return out


def _pcap_interfaces():
    lib = _load_pcap()
    if not lib:
        return None
    err = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    head_ptr = ctypes.POINTER(_PcapIf)()
    if lib.pcap_findalldevs(ctypes.byref(head_ptr), err) != 0:
        raise LiveError("could not list interfaces: "
                        + err.value.decode(errors="replace"))
    friendly = _win_friendly_names() if os.name == "nt" else {}
    out = []
    try:
        node = head_ptr
        while node:
            d = node.contents
            name = (d.name or b"").decode(errors="replace")
            desc = (d.description or b"").decode(errors="replace")
            addrs = []
            a = d.addresses
            while a:
                ip = _sockaddr_ipv4(a.contents.addr)
                if ip and ip not in addrs:
                    addrs.append(ip)
                a = a.contents.next
            fr = ""
            if "{" in name:
                fr = friendly.get(name[name.index("{"):].upper(), "")
            elif name.lower().endswith("npf_loopback"):
                fr = "Npcap Loopback"             # \Device\NPF_Loopback
            loop = bool(d.flags & PCAP_IF_LOOPBACK) or "loopback" in (name + desc).lower()
            if name.lower() in ("any", "bluetooth-monitor", "nflog", "nfqueue",
                                "dbus-system", "dbus-session") \
                    or name.lower().startswith(("usbmon", "bluetooth")):
                node = d.next
                continue                  # not a network a plant engineer means
            out.append(LiveIface(name, desc, addrs, fr, loop, "pcap"))
            node = d.next
    finally:
        if head_ptr:
            lib.pcap_freealldevs(head_ptr)
    return out


class PcapSource:
    def __init__(self, iface, snaplen, bpf):
        lib = _load_pcap()
        if not lib:
            raise LiveError(_PCAP["err"])
        self.lib, self.iface, self.snaplen = lib, iface, snaplen
        self.backend = ("Npcap" if os.name == "nt" else "libpcap") + \
            (f" ({_pcap_version()})" if _pcap_version() else "")
        self.degraded = False
        self.warnings = []
        self.notes = []
        err = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
        name_b = iface.name.encode()
        h = None
        if getattr(lib, "pcap_create", None) and getattr(lib, "pcap_activate", None):
            h = lib.pcap_create(name_b, err)
            if not h:
                raise LiveError(err.value.decode(errors="replace") or "pcap_create failed")
            lib.pcap_set_snaplen(h, snaplen)
            lib.pcap_set_promisc(h, 1)
            lib.pcap_set_timeout(h, LIVE_TIMEOUT_MS)
            if getattr(lib, "pcap_set_immediate_mode", None):
                lib.pcap_set_immediate_mode(h, 1)
            if getattr(lib, "pcap_set_buffer_size", None):
                lib.pcap_set_buffer_size(h, LIVE_KERNEL_BUFFER)
            rc = lib.pcap_activate(h)
            if rc < 0:
                detail = (lib.pcap_geterr(h) or b"").decode(errors="replace")
                lib.pcap_close(h)
                raise LiveError(_pcap_activate_message(rc, detail))
            if rc > 0:
                self.warnings.append(PCAP_ACTIVATE_WARNINGS.get(rc, f"libpcap warning {rc}"))
        else:
            h = lib.pcap_open_live(name_b, snaplen, 1, LIVE_TIMEOUT_MS, err)
            if not h:
                raise LiveError(_pcap_activate_message(
                    -1, err.value.decode(errors="replace")))
        self.h = h
        self.linktype = lib.pcap_datalink(h)
        if bpf:
            prog = _BpfProgram()
            if lib.pcap_compile(h, ctypes.byref(prog), bpf.encode(), 1,
                                PCAP_NETMASK_UNKNOWN) != 0:
                detail = (lib.pcap_geterr(h) or b"").decode(errors="replace")
                self.close()
                raise LiveError(f"capture filter rejected: {detail}")
            rc = lib.pcap_setfilter(h, ctypes.byref(prog))
            lib.pcap_freecode(ctypes.byref(prog))
            if rc != 0:
                detail = (lib.pcap_geterr(h) or b"").decode(errors="replace")
                self.close()
                raise LiveError(f"capture filter could not be applied: {detail}")
        self._hdr = ctypes.POINTER(_PcapPkthdr)()
        self._data = ctypes.POINTER(ctypes.c_ubyte)()
        # The read timeout is NOT a promise: on Linux a quiet interface can
        # block pcap_next_ex forever, which would also swallow Ctrl+C and
        # --duration. So the handle goes non-blocking and TAPROOT does its own
        # bounded wait: select() on the pcap fd (POSIX) or the Npcap read event
        # (Windows). Old libraries without these keep the blocking read, where
        # Windows at least honours the timeout.
        self._fd = -1
        self._event = None
        self._kernel32 = None
        setnb = getattr(lib, "pcap_setnonblock", None)
        if setnb and setnb(h, 1, err) == 0:
            if os.name == "nt":
                getev = getattr(lib, "pcap_getevent", None)
                ev = getev(h) if getev else None
                if ev:
                    try:
                        k32 = ctypes.windll.kernel32
                        k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
                        k32.WaitForSingleObject.restype = ctypes.c_uint32
                        self._event, self._kernel32 = ev, k32
                    except Exception:
                        self._event = None
            else:
                getfd = getattr(lib, "pcap_get_selectable_fd", None)
                self._fd = getfd(h) if getfd else -1
            self._nonblock = True
        else:
            self._nonblock = False

    def _wait(self):
        """Wait up to one read-timeout for the handle to have something."""
        t = LIVE_TIMEOUT_MS / 1000.0
        if self._fd >= 0:
            try:
                select.select([self._fd], [], [], t)
            except (OSError, ValueError):
                time.sleep(0.05)
        elif self._event:
            self._kernel32.WaitForSingleObject(self._event, LIVE_TIMEOUT_MS)
        else:
            time.sleep(0.05)

    def next(self):
        rc = self.lib.pcap_next_ex(self.h, ctypes.byref(self._hdr),
                                   ctypes.byref(self._data))
        if rc == 1:
            hdr = self._hdr.contents
            data = ctypes.string_at(self._data, hdr.caplen)
            return hdr.ts.tv_sec + hdr.ts.tv_usec / 1e6, data, hdr.len
        if rc == 0:
            if self._nonblock:
                self._wait()
            return None                            # nothing arrived this time
        if rc == -2:
            raise EOFError
        detail = (self.lib.pcap_geterr(self.h) or b"").decode(errors="replace")
        raise LiveError(f"capture stopped: {detail or 'interface error'} - was the "
                        f"adapter unplugged or disabled?")

    def stats(self):
        st = _PcapStat()
        try:
            if self.lib.pcap_stats(self.h, ctypes.byref(st)) != 0:
                return None
        except Exception:
            return None
        return st.ps_recv, st.ps_drop + st.ps_ifdrop

    def close(self):
        if getattr(self, "h", None):
            try:
                self.lib.pcap_close(self.h)
            except Exception:
                pass
            self.h = None


def _pcap_activate_message(rc, detail):
    base = PCAP_ACTIVATE_ERRORS.get(rc, f"error {rc}")
    msg = f"could not open the interface: {base}"
    if detail:
        msg += f" ({detail})"
    if rc in (-8, -11) or "permission" in detail.lower() or "access" in detail.lower():
        if os.name == "nt":
            msg += ("\n    Run the prompt as Administrator - or Npcap was installed with "
                    "'Restrict driver access to Administrators only'.")
        else:
            msg += ("\n    Run with sudo, or once: sudo setcap cap_net_raw,cap_net_admin=eip "
                    "$(readlink -f $(which python3))")
    return msg


# ---------- Linux AF_PACKET ----------

ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772
ARPHRD_NONE = 65534
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_STATISTICS = 6
PACKET_MR_PROMISC = 1
PACKET_OUTGOING = 4


def _linux_if_ipv4(name):
    try:
        import fcntl
    except ImportError:
        return ""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = fcntl.ioctl(s.fileno(), 0x8915,                    # SIOCGIFADDR
                        struct.pack("256s", name[:15].encode()))
        return socket.inet_ntoa(r[20:24])
    except OSError:
        return ""
    finally:
        s.close()


def _linux_if_type(name):
    try:
        with open(f"/sys/class/net/{name}/type") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return ARPHRD_ETHER


def _afpacket_interfaces():
    if not sys.platform.startswith("linux") or not hasattr(socket, "AF_PACKET"):
        return None
    out = []
    try:
        pairs = socket.if_nameindex()
    except OSError:
        return None
    for _idx, name in pairs:
        ip = _linux_if_ipv4(name)
        out.append(LiveIface(name, "", [ip] if ip else [], "",
                             _linux_if_type(name) == ARPHRD_LOOPBACK, "afpacket"))
    return out


class AfPacketSource:
    def __init__(self, iface, snaplen, bpf):
        self.iface, self.snaplen = iface, snaplen
        self.backend = "AF_PACKET (Linux raw socket, no libpcap)"
        self.degraded = False
        self.warnings = []
        self.notes = ["802.1Q tags are stripped by the kernel on this backend, so "
                      "VLAN IDs will not show - install libpcap for them."]
        if bpf:
            self.warnings.append("--filter needs libpcap; it is ignored on the "
                                 "AF_PACKET fallback (everything is captured)")
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        except PermissionError:
            raise LiveError("permission denied - run with sudo, or once: sudo setcap "
                            "cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))")
        except OSError as e:
            raise LiveError(f"could not open a raw socket: {e}")
        try:
            s.bind((iface.name, 0))
        except OSError as e:
            s.close()
            raise LiveError(f"could not bind to {iface.name}: {e}")
        try:
            idx = socket.if_nametoindex(iface.name)
            s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                         struct.pack("iHH8s", idx, PACKET_MR_PROMISC, 0, b""))
        except OSError as e:
            self.warnings.append(f"promiscuous mode could not be enabled ({e}) - only "
                                 f"traffic to and from this machine will be seen")
        s.settimeout(LIVE_TIMEOUT_MS / 1000.0)
        self.s = s
        hatype = _linux_if_type(iface.name)
        self.loopback = hatype == ARPHRD_LOOPBACK
        self.linktype = DLT_RAW if hatype == ARPHRD_NONE else DLT_EN10MB
        self._recv = 0
        self._drop = 0

    def next(self):
        try:
            data, addr = self.s.recvfrom(262144)
        except socket.timeout:
            return None
        except OSError as e:
            raise LiveError(f"capture stopped: {e}")
        # On loopback every packet is delivered twice (out and back in). libpcap
        # drops the outgoing copy; so does this, or every count doubles.
        if self.loopback and len(addr) > 2 and addr[2] == PACKET_OUTGOING:
            return None
        orig = len(data)
        if orig > self.snaplen:
            data = data[:self.snaplen]
        return time.time(), data, orig

    def stats(self):
        try:
            raw = self.s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            pk, dr = struct.unpack("II", raw)      # counters reset on every read
            self._recv += pk
            self._drop += dr
        except OSError:
            return None
        return self._recv, self._drop

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


# ---------- Windows raw socket (degraded) ----------

def _rawsock_interfaces():
    if os.name != "nt" or not hasattr(socket, "SIO_RCVALL"):
        return None
    ips = []
    try:
        for fam, _t, _p, _c, sa in socket.getaddrinfo(socket.gethostname(), None,
                                                      socket.AF_INET):
            if sa[0] not in ips and not sa[0].startswith("127."):
                ips.append(sa[0])
    except OSError:
        pass
    return [LiveIface(ip, "IPv4 address (raw socket)", [ip], "", False, "rawsock")
            for ip in ips]


class WinRawSource:
    def __init__(self, iface, snaplen, bpf):
        self.iface, self.snaplen = iface, snaplen
        self.backend = "Windows raw socket (SIO_RCVALL) - DEGRADED"
        self.degraded = True
        self.warnings = []
        self.notes = [
            "DEGRADED: Npcap is not installed, so capture falls back to a Windows raw "
            "socket. IPv4 only, no Ethernet header: no MAC addresses or vendors, and no "
            "ARP, LLDP, CDP or PROFINET DCP. Install Npcap (or Wireshark) for full frames.",
            "This backend needs an IP address on the NIC - so Windows is a live host on "
            "that network while you capture.",
        ]
        if bpf:
            self.warnings.append("--filter needs Npcap; it is ignored on the raw-socket "
                                 "fallback")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((iface.addrs[0], 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except PermissionError:
            raise LiveError("permission denied - run the prompt as Administrator")
        except OSError as e:
            if getattr(e, "winerror", None) == 10013:
                raise LiveError("permission denied - run the prompt as Administrator")
            raise LiveError(f"could not open a raw socket on {iface.addrs[0]}: {e}")
        s.settimeout(LIVE_TIMEOUT_MS / 1000.0)
        self.s = s
        self.linktype = DLT_RAW

    def next(self):
        try:
            data = self.s.recv(65535)
        except socket.timeout:
            return None
        except OSError as e:
            raise LiveError(f"capture stopped: {e}")
        orig = len(data)
        return time.time(), data[:self.snaplen], orig

    def stats(self):
        return None

    def close(self):
        try:
            self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        try:
            self.s.close()
        except Exception:
            pass


# ---------- choosing a backend and an interface ----------

BACKENDS = ("auto", "pcap", "afpacket", "rawsock")


def list_interfaces(backend="auto"):
    """Returns (ifaces, backend_used, reasons). reasons explains every backend
    that was skipped, for the message when nothing works."""
    reasons = []
    order = ["pcap", "afpacket", "rawsock"] if backend == "auto" else [backend]
    for b in order:
        try:
            if b == "pcap":
                got = _pcap_interfaces()
                if got is None:
                    reasons.append(f"pcap: {_PCAP['err']}")
                    continue
            elif b == "afpacket":
                got = _afpacket_interfaces()
                if got is None:
                    reasons.append("afpacket: Linux only")
                    continue
            else:
                got = _rawsock_interfaces()
                if got is None:
                    reasons.append("rawsock: Windows only")
                    continue
        except LiveError as e:
            reasons.append(f"{b}: {e}")
            continue
        if got:
            return got, b, reasons
        reasons.append(f"{b}: no interfaces visible (permissions?)")
    return [], None, reasons


def print_interfaces(ifaces, backend):
    head(f"CAPTURE INTERFACES ({backend})")
    for i, f in enumerate(ifaces, 1):
        name, extra, ips = f.line()
        tag = "  [loopback]" if f.loopback else ""
        echo(f"  {i:>2}. {name}{tag}")
        if extra:
            echo(f"      {extra}")
        echo(f"      IPv4: {ips}")
    echo("")
    echo("  Use the number, the name, an IP address, or part of the description:")
    echo("    python taproot.py --live 3")


def choose_interface(spec, ifaces):
    """spec: '' (ask), a list number, a name, a friendly name, an IPv4
    address, 'loopback', or a unique substring of any of those."""
    if not ifaces:
        raise LiveError("no capture interfaces are visible")
    if spec == "" or spec is None:
        if len(ifaces) == 1:
            return ifaces[0]
        if not sys.stdin.isatty():
            raise LiveError("more than one interface - name one: --live <number|name|ip>")
        print_interfaces(ifaces, ifaces[0].backend)
        try:
            spec = input("Interface to listen on (number, blank to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            spec = ""
        if not spec:
            raise LiveError("no interface chosen")
    s = spec.strip().strip('"').strip("'")
    if s.isdigit() and 1 <= int(s) <= len(ifaces):
        return ifaces[int(s) - 1]
    low = s.lower()
    if low in ("loopback", "lo"):
        for f in ifaces:
            if f.loopback:
                return f
    for key in (lambda f: f.name, lambda f: f.friendly):
        for f in ifaces:
            if key(f) and key(f).lower() == low:
                return f
    for f in ifaces:
        if s in f.addrs:
            return f
    hits = [f for f in ifaces
            if low in f.name.lower() or low in f.friendly.lower() or low in f.desc.lower()]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        raise LiveError(f"'{spec}' matches {len(hits)} interfaces - be more specific "
                        f"(run --list-ifaces)")
    raise LiveError(f"no interface matches '{spec}' (run --list-ifaces)")


def open_live_source(iface, snaplen, bpf):
    cls = {"pcap": PcapSource, "afpacket": AfPacketSource,
           "rawsock": WinRawSource}[iface.backend]
    return cls(iface, snaplen, bpf)


# ============================================================
#  LIVE CAPTURE - CONSOLE, EVENTS, RECORDING
# ============================================================

class LiveConsole:
    """Event lines above a one-line status. On a terminal the status line is
    redrawn in place; piped to a file it becomes a line every 30 seconds.
    Events are rate-limited so a sweep across a /16 cannot bury the screen -
    everything suppressed is still in the final report."""

    def __init__(self, quiet=False, verbose=False):
        self.quiet, self.verbose = quiet, verbose
        self.tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        self._status_len = 0
        self._bucket = float(LIVE_EVENTS_PER_SEC)
        self._last_fill = time.time()
        self.suppressed = 0
        self.counts = {}

    def _clear_status(self):
        if self.tty and self._status_len:
            sys.stdout.write("\r" + " " * self._status_len + "\r")
            self._status_len = 0

    def event(self, kind, text, color=None):
        self.counts[kind] = self.counts.get(kind, 0) + 1
        if self.quiet:
            return
        now = time.time()
        self._bucket = min(float(LIVE_EVENTS_PER_SEC),
                           self._bucket + (now - self._last_fill) * LIVE_EVENTS_PER_SEC)
        self._last_fill = now
        if self._bucket < 1:
            self.suppressed += 1
            return
        self._bucket -= 1
        self._clear_status()
        stamp = datetime.now().strftime("%H:%M:%S")
        print(_c(color or C.BODY, f"  {stamp}  {text}"))
        sys.stdout.flush()

    def note(self, text, color=None):
        if self.quiet:
            return
        self._clear_status()
        print(_c(color or C.WARN, text))
        sys.stdout.flush()

    def status(self, text):
        if self.quiet:
            return
        if self.suppressed:
            n, self.suppressed = self.suppressed, 0
            self.note(f"  ... {n} more event(s) not shown (burst) - all of them are in "
                      f"the report at the end", C.DIM)
        if self.tty:
            line = text[:max(20, _term_width() - 1)]
            pad = max(0, self._status_len - len(line))
            sys.stdout.write("\r" + _c(C.HEAD, line) + " " * pad)
            sys.stdout.flush()
            self._status_len = len(line)
        else:
            print(text)
            sys.stdout.flush()

    def end(self):
        self._clear_status()


def _term_width():
    try:
        return os.get_terminal_size().columns
    except (OSError, ValueError, AttributeError):
        return 100


class LiveInventory(Inventory):
    """The same Inventory the file reader fills, plus a note of what is NEW,
    so the console can say so the moment it happens. Nothing here changes
    how evidence is graded - it only watches."""

    def __init__(self, console):
        super().__init__()
        self._con = console
        self._heard = set()          # IPs that have transmitted
        self._named = set()          # (ip, name) pairs already announced
        self._l2 = set()             # MACs announced as layer-2-only devices
        self._svc_ip = {}            # id(service record) -> host IP
        self._writes = set()         # (client, server, fc) Modbus writes announced
        self._conflicts = set()
        self.refused_new = 0

    def _service(self, ip, proto, port):
        svc = super()._service(ip, proto, port)
        self._svc_ip[id(svc)] = ip
        return svc

    def _set_state(self, svc, state, evidence):
        old = svc["state"]
        super()._set_state(svc, state, evidence)
        new = svc["state"]
        if new == old:
            return
        ip = self._svc_ip.get(id(svc), "?")
        h = self.hosts.get(ip)
        if h is None or h["services"].get((svc["proto"], svc["port"])) is not svc:
            return                                   # scratch record past a cap
        ot = is_ot_port(svc["port"])
        if new in ("serving", "responding"):
            peer = next(iter(svc["peers"]), "")
            who = f"  <- {peer}" if peer else ""
            self._con.event("port",
                            f"{STATE_LABEL[new]:<10} {ip:<15} {svc['proto']}/{svc['port']:<5} "
                            f"{_trunc(svc['name'], 30)}{who}",
                            C.OT if ot else C.GOOD)
        elif new == "refused":
            self.refused_new += 1
            if self._con.verbose:
                self._con.event("refused",
                                f"{'REFUSED':<10} {ip:<15} {svc['proto']}/{svc['port']:<5} "
                                f"{svc['evidence']}", C.DIM)

    def add(self, ts, info, orig_len, cap_len, linktype):
        super().add(ts, info, orig_len, cap_len, linktype)
        if not info:
            return
        src_ip = info.get("src_ip") or ""
        dst_ip = info.get("dst_ip") or ""
        src_mac = info.get("src_mac") or ""
        con = self._con

        if (src_ip and src_ip not in self._heard and not _is_group_ip(src_ip)
                and src_ip in self.hosts and self.hosts[src_ip]["pkts_out"]):
            self._heard.add(src_ip)
            mac = src_mac if (src_mac and not _is_group_mac(src_mac)
                              and src_mac != "00:00:00:00:00:00") else ""
            macbit = f"  {mac}  {_vendor_label(mac)}" if mac else ""
            con.event("host", f"{'HOST':<10} {src_ip:<15}{macbit}  ({info.get('proto') or info.get('l4') or 'IP'})",
                      C.GOOD)

        name = info.get("hostname") or ""
        if name:
            for ip in (src_ip, info.get("dhcp_ip") or ""):
                if ip and ip in self.hosts and (ip, name) not in self._named \
                        and name in self.hosts[ip]["hostnames"]:
                    self._named.add((ip, name))
                    con.event("name", f"{'NAME':<10} {ip:<15} = {name}  "
                                      f"({info.get('proto') or 'announced'})")

        if (src_mac and not src_ip and src_mac not in self._l2
                and src_mac in self.macs and not self.macs[src_mac]["ips"]
                and not _is_group_mac(src_mac)):
            self._l2.add(src_mac)
            extra = ""
            if info.get("switch") or info.get("swport"):
                extra = f"  {info.get('switch', '')} {info.get('swport', '')}".rstrip()
            elif name:
                extra = f"  {name}"
            con.event("device", f"{'L2 DEVICE':<10} {src_mac}  {_vendor_label(src_mac)}  "
                                f"({info.get('proto') or 'layer 2'}){extra}")

        claim = info.get("arp_claim")
        if claim:
            ip = claim[0]
            claims = self.arp_claims.get(ip, {})
            if len(claims) > 1 and ip not in self._conflicts:
                self._conflicts.add(ip)
                con.event("conflict", f"{'CONFLICT':<10} {ip:<15} claimed in ARP by "
                                      f"{', '.join(sorted(claims))}", C.WARN)

        if info.get("modbus") and info.get("sport") is not None and src_ip and dst_ip:
            sport, dport = info["sport"], info["dport"]
            key = ("tcp",) + tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
            flow = self.flows.get(key)
            server = tuple(flow["server"]) if flow and flow["server"] else None
            if server and (src_ip, sport) != server:
                for fc, is_exc in info["modbus"]:
                    fname, kind = MODBUS_FUNCS.get(fc, (f"FC {fc}", "other"))
                    if kind == "write" and not is_exc and (src_ip, dst_ip, fc) not in self._writes:
                        self._writes.add((src_ip, dst_ip, fc))
                        con.event("write", f"{'WRITE':<10} {src_ip:<15} -> {dst_ip}:{dport}  "
                                           f"Modbus FC {fc} {fname}", C.BAD)


class PcapWriter:
    """--write: classic little-endian microsecond pcap, readable by Wireshark
    and by taproot.py itself. Flushed about once a second, so a crash or a
    pulled USB stick still leaves a usable file."""

    def __init__(self, path, linktype, snaplen):
        self.path = path
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        self.frames = 0
        self.bytes = 24
        self.failed = None

    def write(self, ts, data, orig):
        if self.failed:
            return
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec, usec = sec + 1, usec - 1000000
        try:
            self.fh.write(struct.pack("<IIII", sec, usec, len(data), orig))
            self.fh.write(data)
        except OSError as e:
            self.failed = str(e)
            return
        self.frames += 1
        self.bytes += 16 + len(data)

    def flush(self):
        if not self.failed:
            try:
                self.fh.flush()
            except OSError as e:
                self.failed = str(e)

    def close(self):
        try:
            self.fh.close()
        except Exception:
            pass


class LiveCaptureInfo:
    """Stands in for a Capture object in the JSON export."""

    def __init__(self, src, iface, bpf):
        self.format = "live"
        self.gzipped = False
        self.snaplen = src.snaplen
        self.linktypes = {0: src.linktype}
        self.seen_linktypes = {src.linktype}
        self.truncated = False
        self.bad_blocks = 0
        self.read_error = None
        self.iface = iface
        self.display_path = "live:" + iface.name
        self.live_info = {"interface": iface.name, "interface_name": iface.friendly,
                          "backend": src.backend, "degraded": src.degraded,
                          "filter": bpf or "", "started": "", "stopped": "",
                          "kernel_drops": None, "saved_pcap": None}

    def describe(self):
        return ("live capture",
                ", ".join(DLT_NAMES.get(l, f"link type {l} (unsupported)")
                          for l in sorted(self.seen_linktypes)))


def _safe_label(text):
    out = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in text)
    return out.strip("_")[:40] or "iface"


# ============================================================
#  LIVE MAP SERVER
# ============================================================
# --map serves taproot.html (from beside this script) on 127.0.0.1 and hands
# the page every captured frame as a small pcap chunk. The page parses them
# with its own decoder - the same code that is cross-checked packet-for-packet
# against this file - and redraws the map as hosts appear. Every request must
# carry the random token printed in the terminal, and requests naming any
# host other than localhost are refused (a DNS-rebinding guard), because the
# frames contain whatever the plant network carries.

class FrameRing:
    """Every captured frame, oldest dropped first once the byte budget is
    spent. The page reads forward from a sequence number, so a page opened
    late (or reloaded) replays everything still held."""

    def __init__(self, max_bytes, linktype, snaplen):
        self.lock = threading.Lock()
        self.frames = collections.deque()
        self.max_bytes = max_bytes
        self.bytes = 0
        self.first_seq = 1
        self.next_seq = 1
        self.linktype = linktype
        self.snaplen = snaplen
        self.evicted = 0

    def append(self, ts, data, orig):
        with self.lock:
            self.frames.append((self.next_seq, ts, data, orig))
            self.next_seq += 1
            self.bytes += len(data) + 16
            while self.bytes > self.max_bytes and len(self.frames) > 1:
                seq, _t, d, _o = self.frames.popleft()
                self.bytes -= len(d) + 16
                self.first_seq = seq + 1
                self.evicted += 1

    def chunk(self, after, max_bytes):
        """pcap bytes for frames with seq > after. Returns (first_held,
        last_included, pcap_bytes)."""
        with self.lock:
            start = max(0, after + 1 - self.first_seq)
            picked, size = [], 0
            for fr in itertools.islice(self.frames, start, None):
                picked.append(fr)
                size += 16 + len(fr[2])
                if size >= max_bytes:
                    break
            first_held = self.first_seq
        last = picked[-1][0] if picked else max(after, first_held - 1)
        parts = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0,
                             self.snaplen, self.linktype)]
        for _seq, ts, data, orig in picked:
            sec = int(ts)
            usec = min(999999, int(round((ts - sec) * 1e6)))
            parts.append(struct.pack("<IIII", sec, usec, len(data), orig))
            parts.append(data)
        return first_held, last, b"".join(parts)


class LiveState:
    """What the map server needs to know about the running capture."""

    def __init__(self, token, allow_remote, ring, iface, src, bpf):
        self.token = token
        self.allow_remote = allow_remote
        self.ring = ring
        self.iface = iface
        self.src = src
        self.bpf = bpf
        self.started = time.time()
        self.packets = 0
        self.drops = None
        self.running = True
        self.self_skipped = 0            # map-server frames kept out of the capture
        self.html_path = os.path.join(_script_dir(), "taproot.html")


class _MapHandler(http.server.BaseHTTPRequestHandler):
    server_version = "TAPROOT"
    sys_version = ""

    def log_message(self, fmt, *args):         # keep the console for events
        pass

    def _send(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except OSError:
                pass

    def _text(self, code, msg):
        self._send(code, msg.encode(), "text/plain; charset=utf-8")

    def do_GET(self):
        st = self.server.taproot
        url = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(url.query)
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if not st.allow_remote and host not in ("127.0.0.1", "localhost", "::1"):
            return self._text(403, "TAPROOT: refused (unexpected Host header)")
        token = (qs.get("t") or qs.get("live") or [""])[0]
        if not hmac.compare_digest(token.encode(), st.token.encode()):
            return self._text(403, "TAPROOT: this link needs the token printed in the "
                                   "terminal where taproot.py is running.")
        path = url.path
        try:
            if path in ("/", "/index.html", "/taproot.html"):
                try:
                    with open(st.html_path, "rb") as fh:
                        body = fh.read()
                except OSError:
                    return self._text(404, "taproot.html was not found beside taproot.py")
                return self._send(200, body, "text/html; charset=utf-8")
            if path == "/live/status":
                doc = {
                    "tool": TOOL_NAME, "version": VERSION,
                    "interface": st.iface.name, "interface_name": st.iface.friendly,
                    "interface_label": st.iface.label(),
                    "backend": st.src.backend, "degraded": st.src.degraded,
                    "linktype": st.src.linktype, "snaplen": st.src.snaplen,
                    "filter": st.bpf or "", "started": st.started, "now": time.time(),
                    "running": st.running, "packets": st.packets, "drops": st.drops,
                    "first_seq": st.ring.first_seq, "next_seq": st.ring.next_seq,
                    "evicted": st.ring.evicted,
                    "notes": list(st.src.notes) + list(st.src.warnings),
                    "oui": os.path.basename(OUI_SOURCE) if OUI_SOURCE else None,
                }
                return self._send(200, json.dumps(doc).encode(), "application/json")
            if path == "/live/frames":
                try:
                    after = int((qs.get("since") or ["0"])[0])
                except ValueError:
                    after = 0
                first, last, body = st.ring.chunk(max(0, after), MAP_CHUNK_BYTES)
                return self._send(200, body, "application/vnd.tcpdump.pcap", {
                    "X-Taproot-First": str(first), "X-Taproot-Last": str(last),
                    "X-Taproot-Next": str(st.ring.next_seq)})
            if path == "/live/oui":
                if not OUI_SOURCE:
                    return self._text(404, "no OUI database loaded")
                try:
                    with open(OUI_SOURCE, "rb") as fh:
                        body = fh.read()
                except OSError:
                    return self._text(404, "OUI database could not be read")
                return self._send(200, body, "text/plain; charset=utf-8",
                                  {"X-Taproot-Oui": os.path.basename(OUI_SOURCE)})
        except Exception as e:                   # never kill the capture over a page
            return self._text(500, f"TAPROOT map server error: {e}")
        return self._text(404, "not found")

    do_HEAD = do_GET


class _MapServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


def start_map_server(state, port, open_browser):
    """Returns (server, url) or raises LiveError."""
    if not os.path.isfile(state.html_path):
        raise LiveError(f"taproot.html not found beside taproot.py ({state.html_path}) - "
                        f"copy it into the same folder to get the map")
    bind = "0.0.0.0" if state.allow_remote else "127.0.0.1"
    srv, last_err = None, None
    for p in range(port, port + 10):
        try:
            srv = _MapServer((bind, p), _MapHandler)
            break
        except OSError as e:
            last_err = e
    if srv is None:
        raise LiveError(f"could not open a local port for the map ({port}-{port + 9}): "
                        f"{last_err}")
    srv.taproot = state
    th = threading.Thread(target=srv.serve_forever, name="taproot-map", daemon=True)
    th.start()
    real_port = srv.server_address[1]
    url = f"http://127.0.0.1:{real_port}/?live={state.token}"
    if open_browser:
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass
    return srv, url


# ============================================================
#  LIVE CAPTURE - DRIVER
# ============================================================

LIVE_NOTICE = """\
[!] LIVE CAPTURE - passive, but read this before plugging into a plant network:
    TAPROOT sends nothing. Your operating system still will, on any network
    card that has an IP address: DHCP, NetBIOS/LLMNR, IPv6 neighbour discovery,
    Windows connectivity checks. On a normal switch port that makes this laptop
    a live host on the control network. Use a dedicated USB NIC on a SPAN/mirror
    port or a passive TAP, with IPv4 and IPv6 unbound from it (Npcap still
    captures). Only monitor networks you are authorised to monitor."""


def _live_status_line(src_state, inv, t0):
    el = int(time.time() - t0)
    hh, mm, ss = el // 3600, (el % 3600) // 60, el % 60
    drops = src_state.drops
    dtxt = "n/a" if drops is None else f"{drops:,}"
    heard = len(inv._heard)
    svcs = sum(1 for h in inv.hosts.values() for s in h["services"].values()
               if s["state"] in ("serving", "responding"))
    return (f"[LIVE {hh:02d}:{mm:02d}:{ss:02d}] {src_state.packets:,} pkts  "
            f"{heard} hosts heard  {len(inv.macs)} MACs  {svcs} ports answering  "
            f"drops {dtxt}   Ctrl+C to stop")


def run_live(args):
    """Returns (inv, info, label) or (None, None, None) on a setup failure."""
    quiet = args.quiet
    try:
        ifaces, backend, reasons = list_interfaces(args.capture_backend)
    except LiveError as e:
        bad(f"[x] {e}")
        return None, None, None
    if not ifaces:
        bad("[x] No way to capture on this machine:")
        for r in reasons:
            bad(f"      {r}")
        return None, None, None
    try:
        iface = choose_interface(args.live, ifaces)
    except LiveError as e:
        bad(f"[x] {e}")
        return None, None, None

    if not quiet:
        warn(LIVE_NOTICE)
        if iface.addrs and not iface.loopback:
            warn(f"[!] {iface.label()} has IPv4 {', '.join(iface.addrs)} - the OS is a "
                 f"live host on this network while you capture.")
    try:
        src = open_live_source(iface, args.snaplen, args.filter)
    except LiveError as e:
        bad(f"[x] {e}")
        return None, None, None
    if src.linktype not in SUPPORTED_DLTS:
        bad(f"[x] {iface.label()} delivers link type {src.linktype}, which TAPROOT does "
            f"not decode. Pick an Ethernet interface.")
        src.close()
        return None, None, None

    label = "live_" + _safe_label(iface.label())
    info = LiveCaptureInfo(src, iface, args.filter)
    con = LiveConsole(quiet=quiet, verbose=args.verbose)
    inv = LiveInventory(con)

    writer = None
    if args.write is not None:
        wpath = args.write or _default_name("capture", "pcap", label)
        try:
            writer = PcapWriter(wpath, src.linktype, src.snaplen)
        except OSError as e:
            bad(f"[x] --write: cannot create {wpath}: {e}")
            src.close()
            return None, None, None
        info.live_info["saved_pcap"] = os.path.abspath(wpath)

    state = LiveState(secrets.token_urlsafe(16), args.allow_remote,
                      FrameRing(max(8, args.map_buffer_mb) * 1024 * 1024,
                                src.linktype, src.snaplen),
                      iface, src, args.filter)
    server = None
    if args.map:
        try:
            server, url = start_map_server(state, args.map_port, not args.no_browser)
        except LiveError as e:
            warn(f"[!] Map not started: {e}")
            warn("    Live capture continues in this terminal.")
        else:
            echo(f"[+] Live map : {url}")
            if not args.no_browser:
                echo("    (opening your browser - if nothing appears, paste the link)")
            if args.allow_remote:
                echo(f"    From another machine: http://<this-machine's-ip>:"
                     f"{server.server_address[1]}/?live={state.token}")
                bad("[!] --allow-remote: the map server is listening on every interface. "
                    "Anyone who can reach this port with the link above sees the network "
                    "inventory AND the raw frames. Close it when you are done.")

    if not quiet:
        head("LIVE CAPTURE")
        echo(f"  Interface     : {iface.label()}" + (f"  ({iface.name})" if iface.friendly else ""))
        if iface.desc and iface.desc != iface.friendly:
            echo(f"  Adapter       : {iface.desc}")
        echo(f"  Backend       : {src.backend}")
        echo(f"  Link type     : {DLT_NAMES.get(src.linktype, src.linktype)}")
        if args.filter:
            echo(f"  Filter        : {args.filter}")
        if args.duration:
            echo(f"  Duration      : {args.duration:g} s")
        if writer:
            echo(f"  Saving to     : {os.path.abspath(writer.path)}")
        for w in src.warnings:
            warn(f"  [!] {w}")
        for n in src.notes:
            warn(f"  [i] {n}")
        echo("")
        echo(_c(C.DIM, "  Events: HOST first heard / SERVING, RESPONDING ports / NAME "
                       "announced / L2 DEVICE / WRITE / CONFLICT"))
        echo("")

    own_ips = set(iface.addrs)
    map_port = server.server_address[1] if server else None
    self_ips = own_ips | {"127.0.0.1", "::1"}
    foreign_unicast = 0
    own_unicast = 0
    hinted = False
    t0 = time.time()
    info.live_info["started"] = datetime.now().isoformat(timespec="seconds")
    last_status = 0.0
    last_flush = t0
    status_every = 1.0 if con.tty else 30.0
    reason = "stopped"
    try:
        while True:
            r = src.next()
            now = time.time()
            if r is not None:
                ts, data, orig = r
                pinfo = parse_packet(data, src.linktype)
                # The map server's own traffic to the browser must not be
                # captured: on loopback (or on the NIC serving --allow-remote)
                # every chunk sent would be captured, sent again, and so on.
                if (map_port and pinfo and pinfo.get("l4") == "TCP"
                        and map_port in (pinfo.get("sport"), pinfo.get("dport"))
                        and (pinfo.get("src_ip") in self_ips
                             or pinfo.get("dst_ip") in self_ips)):
                    state.self_skipped += 1
                    continue
                state.packets += 1
                state.ring.append(ts, data, orig)
                if writer:
                    writer.write(ts, data, orig)
                inv.add(ts, pinfo, orig, len(data), src.linktype)
                if pinfo and not hinted and own_ips:
                    s_ip, d_ip = pinfo.get("src_ip"), pinfo.get("dst_ip")
                    if s_ip and d_ip and not _is_group_ip(d_ip):
                        if s_ip in own_ips or d_ip in own_ips:
                            own_unicast += 1
                        else:
                            foreign_unicast += 1
                if args.max_packets and state.packets >= args.max_packets:
                    reason = f"--max-packets {args.max_packets} reached"
                    break
            if now - last_status >= status_every:
                last_status = now
                st = src.stats()
                if st:
                    state.drops = st[1]
                con.status(_live_status_line(state, inv, t0))
            if writer and now - last_flush >= 1.0:
                writer.flush()
                last_flush = now
                if writer.failed:
                    con.note(f"[!] --write stopped: {writer.failed} (capture continues)",
                             C.BAD)
                    writer.close()
                    writer = None
            if (not hinted and own_ips and not iface.loopback and now - t0 > 20
                    and foreign_unicast == 0):
                hinted = True
                con.note("[i] 20 s in and every unicast packet is to or from this machine. "
                         "A normal switch port only\n    delivers broadcast, multicast and "
                         "your own traffic - use a SPAN/mirror port or a TAP to see\n    "
                         "the plant's conversations.", C.WARN)
            if args.duration and now - t0 >= args.duration:
                reason = f"--duration {args.duration:g} s reached"
                break
    except KeyboardInterrupt:
        reason = "stopped with Ctrl+C"
    except EOFError:
        reason = "the capture source closed"
    except LiveError as e:
        con.end()
        bad(f"[x] {e}")
        reason = "capture error"
    finally:
        st = None
        try:
            st = src.stats()
        except Exception:
            pass
        if st:
            state.drops = st[1]
        state.running = False
        src.close()
        if writer:
            writer.flush()
            writer.close()
            info.live_info["saved_frames"] = writer.frames
        if server:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        con.end()

    info.live_info["stopped"] = datetime.now().isoformat(timespec="seconds")
    info.live_info["kernel_drops"] = state.drops
    info.live_info["stop_reason"] = reason
    if state.self_skipped:
        info.live_info["map_frames_excluded"] = state.self_skipped
    info.live_info["events"] = dict(con.counts)
    info.iface = iface
    info.live_info["seconds"] = round(time.time() - t0, 1)
    if not quiet:
        echo("")
        echo(f"[i] Capture {reason} after {_dur_str(t0, time.time())} - "
             f"{state.packets:,} packets.")
    return inv, info, label


def print_live_summary(info, inv):
    st = inv.stats
    li = info.live_info
    iface = getattr(info, "iface", None)
    head("LIVE CAPTURE")
    name = iface.label() if iface else li["interface"]
    echo(f"  Interface     : {name}"
         + (f"  ({li['interface']})" if iface and iface.friendly else ""))
    echo(f"  Backend       : {li['backend']}")
    echo(f"  Link type(s)  : {info.describe()[1]}")
    echo(f"  Snap length   : {info.snaplen} bytes")
    if li.get("filter"):
        echo(f"  Filter        : {li['filter']}")
    echo(f"  Started       : {li['started']}")
    echo(f"  Stopped       : {li['stopped']}  ({li.get('stop_reason', '')})")
    echo(f"  Packets       : {st['packets']} "
         f"({st['decoded']} dissected, {st['undecoded']} not understood)")
    echo(f"  Capture bytes : {_bytes_str(st['bytes'])}")
    drops = li.get("kernel_drops")
    if drops is None:
        echo("  Dropped       : not reported by this backend")
    elif drops:
        warn(f"  [!] Dropped   : {drops} packet(s) were dropped before TAPROOT saw them - "
             f"the inventory is incomplete. Narrow it with --filter, or capture with "
             f"dumpcap and analyse the file.")
    else:
        echo("  Dropped       : 0")
    if li.get("saved_pcap"):
        echo(f"  Saved pcap    : {li['saved_pcap']} ({li.get('saved_frames', 0)} frames)")
    if li.get("map_frames_excluded"):
        echo(f"  Map traffic   : {li['map_frames_excluded']} frame(s) between this machine "
             f"and the --map browser were left out")
    if st["vlans"]:
        echo(f"  VLAN IDs seen : {', '.join(str(v) for v in sorted(st['vlans']))}")
    if st["group_packets"]:
        groups = sorted(st["groups"], key=_ip_sort_key)
        echo(f"  Bcast/mcast   : {st['group_packets']} packet(s) to "
             f"{len(groups)} group address(es) - {', '.join(groups[:6])}"
             + (" ..." if len(groups) > 6 else ""))
    if li.get("degraded"):
        warn("  [!] DEGRADED backend: no MAC addresses, vendors or layer-2 discovery "
             "in this report.")
    if st["truncated_payloads"]:
        warn(f"  [!] {st['truncated_payloads']} packet(s) were sliced by --snaplen - "
             f"payload-based findings may be incomplete.")


# ============================================================
#  MAIN
# ============================================================

EPILOG = f"""
examples - capture files
  python taproot.py plant_span.pcapng
  python taproot.py capture.pcap --csv                # hosts + ports CSV in cwd
  python taproot.py capture.pcap --json-file report.json
  python taproot.py big.pcap.gz --max-packets 500000  # sample a huge capture
  python taproot.py capture.pcap --host 10.10.5.21    # one host, in detail
  python taproot.py capture.pcap --ot                 # OT/ICS findings only
  python taproot.py --update-oui                      # fetch a MAC vendor database

examples - live capture (needs Administrator / root)
  python taproot.py --list-ifaces                     # what can be captured on
  python taproot.py --live                            # pick an interface from a list
  python taproot.py --live 3 --map                    # interface 3 + live browser map
  python taproot.py --live "Ethernet 2" --duration 600 --csv --json
  python taproot.py --live eth1 --filter "not port 22" --write span.pcap
  python taproot.py --live loopback --map             # practise against plc_sim on 127.0.0.1

port evidence
  SERVING     the host answered: TCP SYN/ACK from it, or two-way traffic
  RESPONDING  UDP: it sent traffic back from that port
  REFUSED     it answered with RST, or ICMP port unreachable - closed, host up
  OBSERVED    addressed only, never answered - suspected, not proven

live capture on a control network
  TAPROOT sends nothing, but your OS will on any NIC with an IP address (DHCP,
  NetBIOS/LLMNR, IPv6 neighbour discovery). Use a dedicated USB NIC on a SPAN /
  mirror port or passive TAP, with IPv4 and IPv6 unbound from it - Npcap still
  captures. On an ordinary switch port you only see broadcast, multicast and
  this machine's own traffic. The --map server listens on 127.0.0.1 only and
  every request needs the per-run token; --allow-remote opens it to the network.

DISCLAIMER
  {DISCLAIMER_SHORT.replace(chr(10), chr(10) + '  ')}
  Capture files and live traffic from a control network contain process data,
  credentials and topology. Treat them as sensitive evidence.
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="taproot.py",
        description=f"{TOOL_NAME} v{VERSION} - {TOOL_LONG}. Reads a pcap/pcapng "
                    f"capture, or listens live on an interface, and reports every "
                    f"IP, MAC and communicating port, with OT/ICS protocol context. "
                    f"Passive: transmits nothing.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("pcap", nargs="?", help="capture file (.pcap, .pcapng, or .gz)")
    p.add_argument("--host", action="append", metavar="IP",
                   help="limit host/port output to this IP (repeatable)")
    p.add_argument("--all-ports", action="store_true",
                   help="list every OBSERVED port and client-side port too")
    p.add_argument("--ot", action="store_true",
                   help="OT/ICS findings and summary only")
    p.add_argument("--no-macs", action="store_true", help="skip the MAC table")
    p.add_argument("--no-ports", action="store_true",
                   help="skip the flat port/service table")
    p.add_argument("--flows", action="store_true",
                   help="add the conversation (flow) table")
    p.add_argument("--top", type=int, default=20, metavar="N",
                   help="rows in the conversation table (default 20)")
    p.add_argument("--max-packets", type=int, default=0, metavar="N",
                   help="stop after N packets (0 = whole file / until stopped)")
    p.add_argument("--csv", action="store_true",
                   help="export hosts + ports CSV using default filenames")
    p.add_argument("--csv-file", metavar="FILE", dest="csv_file",
                   help="export the hosts CSV to FILE (ports CSV beside it)")
    p.add_argument("--json", action="store_true",
                   help="export the full report as JSON using a default filename")
    p.add_argument("--json-file", metavar="FILE", dest="json_file",
                   help="export the full JSON report to FILE")
    p.add_argument("--oui-file", metavar="PATH",
                   help="MAC vendor database to use (overrides autodetect)")
    p.add_argument("--update-oui", action="store_true",
                   help="download a MAC vendor database beside this script and exit")
    p.add_argument("--no-color", action="store_true", help="plain text output")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="more per-host detail (live: also print REFUSED ports)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress the banner and progress lines (live: and events)")
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {VERSION}")

    g = p.add_argument_group("live capture (v1.1 - receive-only, needs Administrator/root)")
    g.add_argument("--live", nargs="?", const="", default=None, metavar="IFACE",
                   help="listen on an interface instead of reading a file: a number "
                        "from --list-ifaces, a name, an IP, 'loopback', or part of "
                        "the description. No value = choose from a list")
    g.add_argument("--list-ifaces", action="store_true",
                   help="list the interfaces live capture can use, and exit")
    g.add_argument("--duration", type=float, default=0, metavar="SEC",
                   help="stop after SEC seconds (0 = until Ctrl+C)")
    g.add_argument("--filter", metavar="BPF",
                   help='capture filter, e.g. "not port 22" or "net 10.10.10.0/24" '
                        "(Npcap/libpcap only)")
    g.add_argument("--snaplen", type=int, default=LIVE_SNAPLEN_DEFAULT, metavar="N",
                   help=f"bytes kept per frame (default {LIVE_SNAPLEN_DEFAULT})")
    g.add_argument("--write", nargs="?", const="", default=None, metavar="FILE",
                   help="also save what is captured to a .pcap (default name in the "
                        "current folder). Off unless asked: captures hold process "
                        "values and topology")
    g.add_argument("--capture-backend", choices=BACKENDS, default="auto",
                   help="force a capture backend (default auto: pcap, then afpacket, "
                        "then rawsock)")
    g.add_argument("--map", action="store_true",
                   help="serve taproot.html on 127.0.0.1 and draw the map live in the "
                        "browser (taproot.html must sit beside this script)")
    g.add_argument("--map-port", type=int, default=MAP_PORT_DEFAULT, metavar="PORT",
                   help=f"local port for --map (default {MAP_PORT_DEFAULT}; the next "
                        f"nine are tried if it is busy)")
    g.add_argument("--map-buffer-mb", type=int, default=MAP_BUFFER_MB_DEFAULT,
                   metavar="MB",
                   help=f"frames held for the browser (default {MAP_BUFFER_MB_DEFAULT} MB; "
                        f"a page opened late replays what is still held)")
    g.add_argument("--allow-remote", action="store_true",
                   help="let other machines reach the --map server (token still "
                        "required). Exposes the inventory and raw frames")
    g.add_argument("--no-browser", action="store_true",
                   help="print the --map link instead of opening a browser")
    return p


LIVE_CHOICES = ("l", "live")


def prompt_for_file():
    """Run with no arguments (double-clicked on Windows, or a bare 'python
    taproot.py' on a jump box): ask for the file rather than printing usage.
    'L' switches to live capture."""
    echo("")
    echo("No capture file given.")
    try:
        raw = input("Path to the .pcap / .pcapng file, or L to listen live "
                    "(blank to quit): ").strip()
    except (EOFError, KeyboardInterrupt):
        return ""
    return raw.strip('"').strip("'")


def analyse(path, args):
    try:
        cap = Capture(path)
    except (CaptureError, OSError, EOFError, zlib.error) as e:
        bad(f"[x] {e}")
        return None, None
    inv = Inventory()
    limit = args.max_packets or 0
    progress_every = 200000
    try:
        for i, (ts, linktype, data, orig_len) in enumerate(cap.packets(), 1):
            if linktype not in SUPPORTED_DLTS:
                inv.stats["packets"] += 1
                inv.stats["undecoded"] += 1
                inv._bump(inv.stats["linktypes"], linktype)
                continue
            info = parse_packet(data, linktype)
            inv.add(ts, info, orig_len, len(data), linktype)
            if limit and i >= limit:
                if not args.quiet:
                    warn(f"[i] Stopped at --max-packets {limit}; the rest of the "
                         f"file was not read.")
                break
            if not args.quiet and i % progress_every == 0:
                print(_c(C.DIM, f"    ... {i} packets"), file=sys.stderr)
    except KeyboardInterrupt:
        warn("\n[i] Interrupted - reporting on what was read so far.")
    except (CaptureError, OSError, EOFError, zlib.error) as e:
        bad(f"[x] Capture file could not be read past this point: {e}")
        warn("[i] Reporting on everything read before the damage.")
    except MemoryError:
        bad("[x] Out of memory. Re-run with --max-packets, or split the capture "
            "(editcap -c).")
    finally:
        cap.close()
    return cap, inv


def print_report(inv, args):
    """Everything after the capture summary - identical for files and live."""
    if args.ot:
        print_ot(inv, args)
        print_summary(inv)
    else:
        print_hosts(inv, args)
        if not args.no_macs:
            print_macs(inv, args)
        if not args.no_ports:
            print_ports(inv, args)
        print_ot(inv, args)
        print_anomalies(inv, args)
        if args.flows:
            print_flows(inv, args)
        print_summary(inv)


def do_exports(inv, args, capture_path, cap):
    if args.csv or args.csv_file or args.json or args.json_file:
        head("EXPORT")
        if args.csv or args.csv_file:
            export_csv(inv, args.csv_file, capture_path)
        if args.json or args.json_file:
            export_json(inv, args.json_file, capture_path, cap)


def main_live(args):
    load_oui_database(args.oui_file, verbose=not args.quiet)
    inv, info, label = run_live(args)
    if inv is None:
        return 2
    if inv.stats["packets"] == 0:
        warn("[!] No packets were captured. Check the interface choice, that the "
             "SPAN/mirror session is running, and that the cable is in the monitor port.")
        return 0
    print_live_summary(info, inv)
    print_report(inv, args)
    do_exports(inv, args, label, info)
    echo("")
    return 0


def main(argv=None):
    global _COLOR
    args = build_parser().parse_args(argv)
    _COLOR = (not args.no_color) and _supports_color(sys.stdout)

    if args.update_oui:
        banner()
        update_oui()
        return 0

    if not args.quiet:
        banner()

    if args.list_ifaces:
        try:
            ifaces, backend, reasons = list_interfaces(args.capture_backend)
        except LiveError as e:
            bad(f"[x] {e}")
            return 2
        if not ifaces:
            bad("[x] No capture interfaces available:")
            for r in reasons:
                bad(f"      {r}")
            return 2
        print_interfaces(ifaces, backend)
        return 0

    if args.live is not None and args.pcap:
        bad("[x] Give a capture file OR --live, not both.")
        return 2
    if args.map and args.live is None:
        bad("[x] --map works with --live. For a capture file, open taproot.html and "
            "drop the file on it.")
        return 2
    if args.live is not None:
        return main_live(args)

    path = args.pcap or prompt_for_file()
    if not path:
        echo("Nothing to do.")
        return 1
    if not args.pcap and path.lower() in LIVE_CHOICES:
        args.live = ""
        return main_live(args)
    if not os.path.isfile(path):
        bad(f"[x] No such file: {path}")
        return 2

    load_oui_database(args.oui_file, verbose=not args.quiet)
    if not args.quiet:
        echo(f"[i] Reading {os.path.basename(path)} ...")

    cap, inv = analyse(path, args)
    if inv is None:
        return 2
    if inv.stats["packets"] == 0:
        warn("[!] The file parsed but contained no packets.")
        return 0

    print_file_summary(cap, inv, path)
    print_report(inv, args)
    do_exports(inv, args, path, cap)
    echo("")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
