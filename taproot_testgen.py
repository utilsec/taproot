#!/usr/bin/env python3
"""
TAPROOT test capture generator
==============================
Builds synthetic captures that exercise every decoder and every port-evidence
path in taproot.py, with no need for a live network or a real plant capture:

  test.pcap        little-endian pcap, microsecond timestamps, Ethernet
  test_be.pcap     the same frames as a big-endian pcap
  test_nano.pcap   the same frames with nanosecond timestamps
  test.pcapng      the same frames as pcapng (if_tsresol = 6)
  test.pcap.gz     gzip-compressed pcap

What is in them: ARP request/reply/gratuitous/probe plus a duplicate address
claim from a second MAC; a full Modbus/TCP session with reads, two writes and
an exception response; S7comm picked up mid-conversation (no handshake); SSH
refused with RST; Telnet addressed and never answered on one host and answering
on another; HTTP answering; a 25-port sweep from one host; DNP3 one-way UDP;
BACnet/IP two-way UDP; SNMP; syslog answered with an ICMP port unreachable;
DHCP with hostname and vendor class; mDNS and NBNS names; LLDP and CDP from a
switch; STP; PROFINET DCP station name; a VLAN-tagged EtherNet/IP session;
IPv6 OPC UA; an EtherCAT frame; and a 3-byte runt to prove nothing crashes.

Run it in the same folder as taproot.py, then:
    python taproot.py test.pcap
    python taproot.py test.pcapng --flows --csv

License: MIT - see the LICENSE file. SPDX-License-Identifier: MIT
"""
import gzip
import struct
import socket

FRAMES = []          # (ts, bytes)
T = 1757600000.0


def eth(dst, src, etype, payload, vlan=None):
    d = bytes.fromhex(dst.replace(":", ""))
    s = bytes.fromhex(src.replace(":", ""))
    if vlan is not None:
        return d + s + struct.pack(">HHH", 0x8100, vlan, etype) + payload
    return d + s + struct.pack(">H", etype) + payload


def ipv4(src, dst, proto, payload, ihl_extra=b""):
    tot = 20 + len(ihl_extra) + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, 0x1234, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + ihl_extra + payload


def tcp(sport, dport, flags, payload=b"", seq=1):
    off = (5 << 4)
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, off, flags,
                       8192, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp(op, sha, spa, tha, tpa):
    return struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + \
        bytes.fromhex(sha.replace(":", "")) + socket.inet_aton(spa) + \
        bytes.fromhex(tha.replace(":", "")) + socket.inet_aton(tpa)


def add(frame, dt=0.01):
    global T
    T += dt
    FRAMES.append((T, frame))


def mbap(tid, unit, pdu):
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


# --- ARP: HMI asks for the PLC, PLC replies, gratuitous, duplicate claim ---
HMI_MAC = "00:0c:29:4a:1b:02"          # VMware
PLC_MAC = "00:1d:9c:aa:bb:cc"          # Rockwell
SIE_MAC = "00:1b:1b:11:22:33"          # Siemens
SW_MAC = "00:00:0c:de:ad:01"           # Cisco
ROGUE_MAC = "b8:27:eb:00:11:22"        # Raspberry Pi
BAC_MAC = "00:80:f4:22:33:44"          # building controller
SYS_MAC = "00:50:56:aa:bb:01"          # syslog host (VMware)
HMI, PLC, SIE, SCADA, ENG = "10.10.5.10", "10.10.5.21", "10.10.5.30", "10.10.5.11", "10.10.5.99"

add(eth("ff:ff:ff:ff:ff:ff", HMI_MAC, 0x0806, arp(1, HMI_MAC, HMI, "00:00:00:00:00:00", PLC)))
add(eth(HMI_MAC, PLC_MAC, 0x0806, arp(2, PLC_MAC, PLC, HMI_MAC, HMI)))
add(eth("ff:ff:ff:ff:ff:ff", SIE_MAC, 0x0806, arp(1, SIE_MAC, SIE, "00:00:00:00:00:00", SIE)))
# duplicate IP claim: rogue also claims the PLC address
add(eth("ff:ff:ff:ff:ff:ff", ROGUE_MAC, 0x0806, arp(2, ROGUE_MAC, PLC, HMI_MAC, HMI)))
# ARP probe (0.0.0.0 sender)
add(eth("ff:ff:ff:ff:ff:ff", ROGUE_MAC, 0x0806, arp(1, ROGUE_MAC, "0.0.0.0", "00:00:00:00:00:00", "10.10.5.77")))

# --- Modbus/TCP: full handshake, read then write, and an exception ---
add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(HMI, PLC, 6, tcp(52344, 502, 0x02))))
add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(PLC, HMI, 6, tcp(502, 52344, 0x12))))
add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(HMI, PLC, 6, tcp(52344, 502, 0x10))))
for i in range(6):
    add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(HMI, PLC, 6,
        tcp(52344, 502, 0x18, mbap(i + 1, 1, bytes([3]) + struct.pack(">HH", 0, 10))))))
    add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(PLC, HMI, 6,
        tcp(502, 52344, 0x18, mbap(i + 1, 1, bytes([3, 20]) + b"\x00" * 20)))))
# write single register + write multiple
add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(HMI, PLC, 6,
    tcp(52344, 502, 0x18, mbap(20, 1, bytes([6]) + struct.pack(">HH", 40, 1))))))
add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(PLC, HMI, 6,
    tcp(502, 52344, 0x18, mbap(20, 1, bytes([6]) + struct.pack(">HH", 40, 1))))))
add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(HMI, PLC, 6,
    tcp(52344, 502, 0x18, mbap(21, 1, bytes([16]) + struct.pack(">HHB", 10, 2, 4) + b"\x00\x01\x00\x02")))))
# exception response
add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(PLC, HMI, 6,
    tcp(502, 52344, 0x18, mbap(22, 1, bytes([0x83, 0x02]))))))

# --- S7comm to the Siemens PLC, mid-capture (no handshake seen) ---
for i in range(4):
    add(eth(SIE_MAC, HMI_MAC, 0x0800, ipv4(HMI, SIE, 6, tcp(50100, 102, 0x18, b"\x03\x00\x00\x16" + b"\x11" * 18))))
    add(eth(HMI_MAC, SIE_MAC, 0x0800, ipv4(SIE, HMI, 6, tcp(102, 50100, 0x18, b"\x03\x00\x00\x1b" + b"\x22" * 23))))

# --- SSH refused (SYN then RST), Telnet addressed but silent ---
add(eth(PLC_MAC, ROGUE_MAC, 0x0800, ipv4(ENG, PLC, 6, tcp(41001, 22, 0x02))))
add(eth(ROGUE_MAC, PLC_MAC, 0x0800, ipv4(PLC, ENG, 6, tcp(22, 41001, 0x14))))
add(eth(PLC_MAC, ROGUE_MAC, 0x0800, ipv4(ENG, PLC, 6, tcp(41002, 23, 0x02))))
# Telnet actually answering on the Siemens box (plaintext finding)
add(eth(SIE_MAC, ROGUE_MAC, 0x0800, ipv4(ENG, SIE, 6, tcp(41003, 23, 0x02))))
add(eth(ROGUE_MAC, SIE_MAC, 0x0800, ipv4(SIE, ENG, 6, tcp(23, 41003, 0x12))))
# HTTP answering on the HMI
add(eth(HMI_MAC, ROGUE_MAC, 0x0800, ipv4(ENG, HMI, 6, tcp(41004, 80, 0x02))))
add(eth(ROGUE_MAC, HMI_MAC, 0x0800, ipv4(HMI, ENG, 6, tcp(80, 41004, 0x12))))

# --- a small sweep from the rogue: 25 unanswered SYNs ---
for p in (135, 139, 445, 1433, 3389, 5900, 8080, 8443, 9100, 161, 102, 502,
          20000, 44818, 47808, 4840, 1911, 2404, 34962, 789, 1962, 2455, 5006, 9600, 18245):
    add(eth(PLC_MAC, ROGUE_MAC, 0x0800, ipv4("10.10.5.200", "10.10.5.50", 6, tcp(40000 + (p % 20000), p, 0x02))), 0.002)

# --- UDP: DNP3 one-way, BACnet two-way, SNMP, syslog ---
add(eth(BAC_MAC, SIE_MAC, 0x0800, ipv4(SIE, "10.10.5.60", 17, udp(20000, 20000, b"\x05\x64" + b"\x00" * 14))))
add(eth(SIE_MAC, BAC_MAC, 0x0800, ipv4("10.10.5.60", SIE, 17, udp(47808, 47808, b"\x81\x0a\x00\x11" + b"\x00" * 13))))
add(eth(BAC_MAC, SIE_MAC, 0x0800, ipv4(SIE, "10.10.5.60", 17, udp(47808, 47808, b"\x81\x0a\x00\x11" + b"\x00" * 13))))
add(eth(BAC_MAC, HMI_MAC, 0x0800, ipv4(HMI, "10.10.5.60", 17, udp(44444, 161, b"\x30\x26\x02\x01\x00\x04\x06public"))))
add(eth(HMI_MAC, BAC_MAC, 0x0800, ipv4("10.10.5.60", HMI, 17, udp(161, 44444, b"\x30\x26\x02\x01\x00\x04\x06public"))))
add(eth(SYS_MAC, HMI_MAC, 0x0800, ipv4(HMI, "10.10.5.9", 17, udp(51000, 514, b"<134>plant log line"))))

# --- ICMP port unreachable: closed UDP port on 10.10.5.9 ---
quoted = ipv4(HMI, "10.10.5.9", 17, udp(51000, 514, b"12345678")[:8])
add(eth(HMI_MAC, SYS_MAC, 0x0800, ipv4("10.10.5.9", HMI, 1,
    struct.pack(">BBHI", 3, 3, 0, 0) + quoted)))
# echo request/reply
add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(HMI, PLC, 1, struct.pack(">BBHHH", 8, 0, 0, 1, 1) + b"ping")))
add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(PLC, HMI, 1, struct.pack(">BBHHH", 0, 0, 0, 1, 1) + b"ping")))

# --- DHCP request with hostname + vendor class ---
opts = (b"\x35\x01\x03" + b"\x0c\x0aENG-LAPTOP" + b"\x3c\x0fMSFT 5.0 Windows"
        + b"\x32\x04" + socket.inet_aton(ENG) + b"\xff")
bootp = (struct.pack(">BBBBIHH", 1, 1, 6, 0, 0x11223344, 0, 0x8000)
         + socket.inet_aton("0.0.0.0") * 4
         + bytes.fromhex(ROGUE_MAC.replace(":", "")) + b"\x00" * 10
         + b"\x00" * 64 + b"\x00" * 128 + b"\x63\x82\x53\x63" + opts)
add(eth("ff:ff:ff:ff:ff:ff", ROGUE_MAC, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17, udp(68, 67, bootp))))

# --- mDNS announcement, NBNS query ---
mdns = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + b"\x08HMI-NODE\x05local\x00" + struct.pack(">HH", 1, 1)
add(eth("01:00:5e:00:00:fb", HMI_MAC, 0x0800, ipv4(HMI, "224.0.0.251", 17, udp(5353, 5353, mdns))))


def nb_encode(name):
    name = name.ljust(15)[:15] + "\x00"
    out = bytearray()
    for ch in name:
        b = ord(ch)
        out.append(0x41 + (b >> 4))
        out.append(0x41 + (b & 0x0F))
    return bytes(out)


nbns = struct.pack(">HHHHHH", 1, 0x0110, 1, 0, 0, 0) + b"\x20" + nb_encode("ENGWS01") + b"\x00" + struct.pack(">HH", 0x20, 1)
add(eth("ff:ff:ff:ff:ff:ff", ROGUE_MAC, 0x0800, ipv4(ENG, "10.10.5.255", 17, udp(137, 137, nbns))))

# --- LLDP from the switch ---
def tlv(t, v):
    return struct.pack(">H", (t << 9) | len(v)) + v


lldp = (tlv(1, b"\x04" + bytes.fromhex(SW_MAC.replace(":", "")))
        + tlv(2, b"\x05Gi1/0/7")
        + tlv(3, struct.pack(">H", 120))
        + tlv(5, b"PLANT-SW-01")
        + tlv(6, b"Cisco IE-4000 switch")
        + tlv(0, b""))
add(eth("01:80:c2:00:00:0e", SW_MAC, 0x88cc, lldp))

# --- CDP over LLC/SNAP ---
def cdp_tlv(t, v):
    return struct.pack(">HH", t, len(v) + 4) + v


cdp = b"\x02\xb4\x00\x00" + cdp_tlv(1, b"PLANT-SW-01") + cdp_tlv(3, b"GigabitEthernet1/0/7") + cdp_tlv(6, b"cisco IE-4000-8GT8GP4G-E")
snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + cdp
frame = bytes.fromhex("01000ccccccc") + bytes.fromhex(SW_MAC.replace(":", "")) + struct.pack(">H", len(snap)) + snap
add(frame)

# --- STP ---
stp = b"\x42\x42\x03" + b"\x00" * 35
add(bytes.fromhex("0180c2000000") + bytes.fromhex(SW_MAC.replace(":", "")) + struct.pack(">H", len(stp)) + stp)

# --- PROFINET DCP identify response with station name ---
blk = b"\x02\x02" + struct.pack(">H", 2 + 12) + b"\x00\x00" + b"plc-siemens1"
dcp = struct.pack(">HIHHH", 0xFEFF, 0x01020304, 0, 0, len(blk)) + blk
add(eth("ff:ff:ff:ff:ff:ff", SIE_MAC, 0x8892, dcp))

# --- VLAN-tagged EtherNet/IP session ---
add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(HMI, PLC, 6, tcp(53100, 44818, 0x02)), vlan=200))
add(eth(HMI_MAC, PLC_MAC, 0x0800, ipv4(PLC, HMI, 6, tcp(44818, 53100, 0x12)), vlan=200))
add(eth(PLC_MAC, HMI_MAC, 0x0800, ipv4(HMI, PLC, 6, tcp(53100, 44818, 0x18, b"\x6f\x00" + b"\x00" * 22)), vlan=200))

# --- IPv6 TCP to OPC UA ---
def ipv6(src, dst, nxt, payload):
    return struct.pack(">IHBB", 0x60000000, len(payload), nxt, 64) + \
        socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload


add(eth(SIE_MAC, HMI_MAC, 0x86dd, ipv6("fe80::1", "fe80::2", 6, tcp(51234, 4840, 0x02))))
add(eth(HMI_MAC, SIE_MAC, 0x86dd, ipv6("fe80::2", "fe80::1", 6, tcp(4840, 51234, 0x12))))

# --- managed switch with an IP: answers SNMP, and announces itself by LLDP/CDP ---
SWIP = "10.10.5.1"
for i in range(3):
    add(eth(SW_MAC, HMI_MAC, 0x0800, ipv4(HMI, SWIP, 17, udp(45000 + i, 161,
        b"\x30\x26\x02\x01\x01\x04\x06public"))))
    add(eth(HMI_MAC, SW_MAC, 0x0800, ipv4(SWIP, HMI, 17, udp(161, 45000 + i,
        b"\x30\x26\x02\x01\x01\x04\x06public"))))

# --- printer on the plant VLAN: answers JetDirect ---
PRN_MAC, PRN = "00:80:77:11:22:33", "10.10.5.70"      # Brother
add(eth(PRN_MAC, ROGUE_MAC, 0x0800, ipv4(ENG, PRN, 6, tcp(41010, 9100, 0x02))))
add(eth(ROGUE_MAC, PRN_MAC, 0x0800, ipv4(PRN, ENG, 6, tcp(9100, 41010, 0x12))))
add(eth(PRN_MAC, ROGUE_MAC, 0x0800, ipv4(ENG, PRN, 6, tcp(41010, 9100, 0x18, b"@PJL INFO STATUS"))))

# --- power meter: serves a web page and NOTHING else. The case that decides
#     whether "web = HMI" is a sensible rule.
MTR_MAC, MTR = "00:80:f4:0a:0b:0c", "10.10.5.40"
for i in range(2):
    add(eth(MTR_MAC, HMI_MAC, 0x0800, ipv4(HMI, MTR, 6, tcp(53200 + i, 80, 0x02))))
    add(eth(HMI_MAC, MTR_MAC, 0x0800, ipv4(MTR, HMI, 6, tcp(80, 53200 + i, 0x12))))
    add(eth(MTR_MAC, HMI_MAC, 0x0800, ipv4(HMI, MTR, 6, tcp(53200 + i, 80, 0x18, b"GET / HTTP/1.1\r\n"))))
    add(eth(HMI_MAC, MTR_MAC, 0x0800, ipv4(MTR, HMI, 6, tcp(80, 53200 + i, 0x18, b"HTTP/1.1 200 OK\r\n"))))

# --- historian: SMB + SQL, the classic OT-DMZ server ---
HST_MAC, HST = "00:14:22:aa:bb:cc", "10.10.5.15"      # Dell
for port, cport in ((445, 49300), (1433, 49301)):
    add(eth(HST_MAC, HMI_MAC, 0x0800, ipv4(HMI, HST, 6, tcp(cport, port, 0x02))))
    add(eth(HMI_MAC, HST_MAC, 0x0800, ipv4(HST, HMI, 6, tcp(port, cport, 0x12))))
    add(eth(HST_MAC, HMI_MAC, 0x0800, ipv4(HMI, HST, 6, tcp(cport, port, 0x18, b"\x00" * 40))))
nbns_h = struct.pack(">HHHHHH", 2, 0x0110, 1, 0, 0, 0) + b"\x20" + nb_encode("HIST01") + b"\x00" + struct.pack(">HH", 0x20, 1)
add(eth("ff:ff:ff:ff:ff:ff", HST_MAC, 0x0800, ipv4(HST, "10.10.5.255", 17, udp(137, 137, nbns_h))))

# --- an unknown ethertype and a runt, to prove nothing crashes ---
add(eth(PLC_MAC, SIE_MAC, 0x88a4, b"\x10\x00" + b"\x00" * 20))     # EtherCAT
add(b"\x01\x02\x03")                                                # runt


# ============================================================
#  writers
# ============================================================

def write_pcap(path, endian="<", nano=False):
    magic = 0xA1B2C3D4 if not nano else 0xA1B23C4D
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1))
        for ts, data in FRAMES:
            sec = int(ts)
            frac = int(round((ts - sec) * (1e9 if nano else 1e6)))
            f.write(struct.pack(endian + "IIII", sec, frac, len(data), len(data)))
            f.write(data)


def write_pcapng(path):
    def block(btype, body):
        total = 12 + len(body) + ((4 - len(body) % 4) % 4)
        pad = b"\x00" * ((4 - len(body) % 4) % 4)
        return struct.pack("<II", btype, total) + body + pad + struct.pack("<I", total)

    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    idb = struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", 9, 1) + b"\x06\x00\x00\x00"
    out = [block(0x0A0D0D0A, shb), block(0x00000001, idb)]
    for ts, data in FRAMES:
        usec = int(round(ts * 1e6))
        body = struct.pack("<IIIII", 0, usec >> 32, usec & 0xFFFFFFFF, len(data), len(data)) + data
        pad = b"\x00" * ((4 - len(data) % 4) % 4)
        total = 12 + len(body) + len(pad)
        out.append(struct.pack("<II", 0x00000006, total) + body + pad + struct.pack("<I", total))
    with open(path, "wb") as f:
        f.write(b"".join(out))


write_pcap("test.pcap")
write_pcap("test_be.pcap", endian=">")
write_pcap("test_nano.pcap", nano=True)
write_pcapng("test.pcapng")
with open("test.pcap", "rb") as src, gzip.open("test.pcap.gz", "wb") as dst:
    dst.write(src.read())
print(f"wrote {len(FRAMES)} frames to test.pcap / test_be.pcap / test_nano.pcap / test.pcapng / test.pcap.gz")
