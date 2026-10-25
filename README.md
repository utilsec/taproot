# TAPROOT — TAP Record Offline Observation Tool

`taproot.py` v1.1.1 · `taproot.html` rev 1.7.1 · Python 3.8+ · standard library only · Windows / Linux / macOS · MIT license

TAPROOT reads a packet capture from a control network, or listens on a SPAN/mirror
port or TAP, and tells you who was on the wire: every IP address, every MAC address
with its vendor, the names devices announced about themselves, and the TCP/UDP ports
each host was actually serving. OT/ICS protocols are named on sight, and Modbus reads
and writes are counted separately, so a write to a controller stands out.

**It transmits nothing.** In file mode it opens a file, never a socket. That makes
capture analysis the one assessment step that is always safe on a production control
network: get a SPAN or TAP capture off the segment, and the whole analysis happens on
a laptop somewhere else, with zero packets on the plant wire.

| File | What it is |
|---|---|
| `taproot.py` | CLI edition. Capture files and live capture, terminal report, CSV/JSON export |
| `taproot.html` | Browser edition. Drop a capture on the page; it is parsed locally in JavaScript and nothing is uploaded. Network map, asset classification, exports. Also serves as the live map for `taproot.py --map` |
| `taproot_testgen.py` | Builds synthetic test captures that exercise every decoder and evidence path |

The two editions share the same decoding and evidence logic and are cross-checked
packet-for-packet on every test capture.

## Quick start

```
python taproot.py plant_span.pcapng                  # full report
python taproot.py capture.pcap --ot                  # OT/ICS findings only
python taproot.py capture.pcap --host 10.10.5.21     # one host, in detail
python taproot.py capture.pcap --flows --csv --json  # add conversations, export everything
python taproot.py big.pcap.gz --max-packets 500000   # sample a huge capture
python taproot.py --update-oui                       # fetch a MAC vendor database (once)
python taproot.py                                    # no arguments: asks for a file, or L to listen live
```

**Browser:** open `taproot.html` (double-clicking it is fine). It starts with a
synthetic sample capture already analysed. Drop your own `.pcap`, `.pcapng` or `.gz`
on it, or click **Select capture…**.

## Port evidence

A capture is evidence, not a scan. A port that only ever appears as a destination
proves that somebody tried to connect, not that anything is listening. TAPROOT grades
every host-port so a finding that lands in an assessment report can be defended:

| Tier | Meaning |
|---|---|
| `SERVING` | The host answered: TCP SYN/ACK from it, or two-way traffic on that port |
| `RESPONDING` | UDP: the host sent traffic back from that port to a peer that addressed it |
| `REFUSED` | The host answered with RST or ICMP port unreachable, so it is up and the port is closed |
| `OBSERVED` | Addressed only, never answered in this capture. Suspected, not proven |

When a capture starts mid-conversation there is no handshake to prove which end is the
server, so the role is inferred from the port numbers and the evidence reads
`(role inferred)`. Ephemeral source ports are ruled out first, because FL-net (55000),
DNP3 (20000) and EtherNet/IP I/O (2222) all sit inside the ranges operating systems
hand out to clients. `--all-ports` also lists every OBSERVED and client-side port.

## What it decodes

| Layer | Coverage |
|---|---|
| Capture formats | pcap (both byte orders, microsecond and nanosecond), pcapng (multiple sections, per-interface link types and timestamp resolution), either one gzip-compressed |
| Link | Ethernet II, 802.1Q / QinQ VLAN tags, 802.3 LLC/SNAP, Linux SLL / SLL2, raw IPv4/IPv6, BSD loopback |
| L2 / discovery | ARP (including gratuitous and probes), LLDP, CDP, PROFINET DCP, STP |
| L3 / L4 | IPv4, IPv6 (extension headers walked), TCP with handshake and flag tracking, UDP, ICMP / ICMPv6 (port unreachables mined for closed UDP ports) |
| Identity | DHCP (MAC, requested/assigned IP, hostname, vendor class), NBNS, mDNS / LLMNR |
| MAC vendors | Longest-prefix lookup: MA-S / IAB (/36), then MA-M (/28), then MA-L (/24) |

### OT/ICS protocols named on sight

The port list is the same one AtomICS (formerly OT RUNG) uses.

| Port | Protocol |
|---|---|
| 102 | S7comm / ISO-TSAP (Siemens) |
| 502 | Modbus TCP — function codes counted, reads and writes reported separately |
| 789 | Red Lion Crimson |
| 1089–1091 | Foundation Fieldbus HSE |
| 1911 / 4911 | Niagara Fox / Fox SSL (Tridium) |
| 1962 | PCWorx (Phoenix Contact) |
| 2222 / 44818 | EtherNet/IP implicit I/O / explicit messaging (CIP) |
| 2404 | IEC 60870-5-104 |
| 2455 | CODESYS |
| 4000 | Emerson ROC |
| 4840 | OPC UA |
| 5006–5007 | MELSEC-Q (Mitsubishi) |
| 9600 | OMRON FINS |
| 18245–18246 | GE SRTP |
| 20000 | DNP3 |
| 20547 | ProConOS |
| 34962–34964 | PROFINET RT |
| 47808 | BACnet/IP |
| 55000 | FL-net |

EtherCAT and SERCOS III are recognized by EtherType. Plaintext protocols that answered
are called out every time: FTP, Telnet, TFTP, HTTP, SNMP v1/v2c, rexec, rlogin,
rsh/syslog and VNC.

## The report

| Section | What you get |
|---|---|
| Capture summary | Format, link types, packets dissected vs not understood, VLAN IDs, broadcast/multicast groups, truncation warnings |
| Hosts | Per IP: MACs and vendors, announced names, traffic counts, ports by evidence tier |
| MAC addresses | Vendor, IPs carried, and layer-2-only devices (switch and port from LLDP/CDP, PROFINET station names) |
| Ports & services | Every host-port with its tier, service name and peers |
| OT/ICS findings | Hosts on OT protocol ports, the Modbus function-code breakdown with reads vs writes per client and controller, and plaintext protocols that answered |
| Observations / anomalies | An IP claimed in ARP by more than one MAC; a MAC carrying four or more IPs; addresses that were addressed but never transmitted; one source addressing 20 or more unanswered host-ports (a sweep); more than one VLAN in one capture |
| Conversations | With `--flows`: the top flows by packet count (`--top N`, default 20) |

## Live capture

```
python taproot.py --list-ifaces                           # what can be captured on
python taproot.py --live                                  # pick an interface from a list
python taproot.py --live 3 --map                          # interface 3 + live browser map
python taproot.py --live "Ethernet 2" --duration 600 --csv --json
python taproot.py --live eth1 --filter "not port 22" --write span.pcap
```

Live capture needs Administrator or root. `--live` accepts a number from
`--list-ifaces`, an interface name, a Windows connection name such as `"Ethernet 2"`,
an IP address, `loopback`, or a unique part of the adapter description.

As packets arrive, the terminal prints events above a status line (packets, hosts,
MACs, answering ports, kernel drops):

| Event | When |
|---|---|
| `HOST` | An address transmits for the first time |
| `SERVING` / `RESPONDING` | A port is proven to answer (`-v` also prints `REFUSED`) |
| `NAME` | A host announces a name (DHCP, NBNS, mDNS/LLMNR) |
| `L2 DEVICE` | A MAC with no IP appears (LLDP, CDP, PROFINET DCP, STP) |
| `CONFLICT` | An IP is claimed in ARP by a second MAC |
| `WRITE` | The first Modbus write for each client, controller and function code |

Events are rate-limited so a sweep cannot bury the screen; nothing is dropped from the
report. Ctrl+C, `--duration` or `--max-packets` ends the capture and prints the same
full report as file mode, with the usual CSV/JSON exports.

### Capture backends

All three are standard library (ctypes and sockets), with no pip install. Auto mode
takes the first one that works; `--capture-backend` forces one.

| Backend | Platform | Notes |
|---|---|---|
| Npcap / libpcap | Windows, Linux, macOS | Full Ethernet frames, promiscuous mode, BPF `--filter`, drop counters. Npcap is installed with Wireshark |
| AF_PACKET | Linux | Full frames, no BPF filter, and the kernel strips 802.1Q tags, so VLAN IDs won't show |
| Raw socket (`SIO_RCVALL`) | Windows | **DEGRADED:** IPv4 only, no MAC addresses, no ARP/LLDP/CDP/DCP, and the NIC must have an IP address |

`--write` also saves the capture to a classic pcap that Wireshark and TAPROOT can
read. It is off by default because capture files hold process values and topology. The
file is flushed about once a second, so a pulled USB stick still leaves a usable file.

### Live map

`--map` serves `taproot.html` (it must sit beside `taproot.py`) on
`127.0.0.1:8765`, trying the next nine ports if that one is busy, and opens your
browser. The page decodes frames with the same code a dropped file goes through,
rebuilds every couple of seconds (backing off on large networks), and makes new hosts
and links glow for ten seconds. It has Pause view and Redraw now buttons and packet,
rate and drop counters. When the capture ends the page says so; save the JSON report
or the map PNG before you close the tab.

The map server hands raw frames to the browser, so it is locked down:

* It listens on loopback only, and every request needs the random token printed in the
  terminal for that run.
* Requests naming any host other than localhost are refused (a DNS-rebinding guard).
* Its own traffic to the browser is kept out of the capture.
* `--allow-remote` listens on every interface (the token is still required) and prints
  a warning: anyone with the link sees the inventory and the raw frames.
* `--map-buffer-mb` (default 128) sets how many frames are held, so a page opened late
  or reloaded replays what is still held.

### Before you plug into a plant network

* **TAPROOT sends nothing, but your operating system will** on any NIC that has an IP
  address: DHCP, NetBIOS/LLMNR, IPv6 neighbour discovery, connectivity checks. On an
  ordinary access port that makes your laptop a live host on the control network. Use
  a dedicated USB NIC on a SPAN/mirror port or a passive TAP, with IPv4 and IPv6
  unbound from it. Npcap still captures.
* **An ordinary switch port only shows broadcast, multicast and your own traffic.** If
  20 seconds pass and every unicast packet is to or from your machine, TAPROOT says so.
* **Watch the drop counter on a busy SPAN.** Non-zero drops mean the inventory is
  incomplete. Narrow it with `--filter`, or capture with dumpcap and analyse the file.

## Browser edition (`taproot.html`)

One self-contained file with no install. Opened from disk or a USB stick on an
air-gapped jump box, it reads the capture with FileReader and parses it in the
browser. No capture data leaves the machine. The only outbound request is the Google
Fonts stylesheet; offline, the page falls back to system fonts.

* **Network map.** Hosts sit in four role bands: clients/masters (initiated, never
  answered), servers (answered on an IT port), controllers/outstations (answered on an
  OT protocol port) and silent/addressed-only. Links are arrows from the initiator to
  the host that was connected to, labelled with the service port and coloured by
  evidence tier. Each device tag shows the IP, the host's primary MAC and its vendor
  ("via <mac>" when that MAC belongs to a router or hypervisor). Switches: Port
  labels, MAC / vendor, OT links only, Hide addressed-only, Web = HMI.
  **Save map PNG** for the report.
* **Asset classification.** Each host is labelled controller/outstation, operator
  station (HMI/SCADA), operator or engineering workstation, engineering workstation,
  server, workstation/client, network device, printer, scanning host or unclassified,
  with a confidence and the evidence behind it. A general-purpose computer that polls
  a control protocol is an operator *or* engineering workstation: polling alone cannot
  tell HMI software from engineering software. **Web = HMI** is off by default because embedded web servers are
  everywhere in OT.
* **Panels:** OT/ICS findings annunciator, hosts (OT only / answering only), ports and
  services (filter by tier, OT only), MAC addresses, conversations.
* **IPv4 / IPv6 switches** declutter the map and tables. OT findings, capture totals
  and every export stay complete, because a view switch never hides evidence.
* **Day / Night / Auto** panel lighting, remembered per browser.
* **Exports:** hosts CSV, ports CSV, JSON report, Copy JSON.
* **MAC vendors:** Load MAC vendor CSV… accepts the same database files as the CLI.

## MAC vendor database

No database is included in this repo. TAPROOT looks for one in this order:

1. `--oui-file PATH`
2. `$TAPROOT_OUI_FILE`, then `$ATOMICS_OUI_FILE`, then the legacy `$RUNG_OUI_FILE`
3. `oui.csv`, `mac-vendors-export.csv`, `maclookup.csv`, `oui.txt` or `manuf` beside
   the script, then in the current folder

`python taproot.py --update-oui` downloads one beside the script, trying the
maclookup.app CSV, then the IEEE registry, then Wireshark's `manuf`. It uses the same
three-tier lookup and the same files as AtomICS, so one database serves both tools.
Without a database every MAC shows `(unknown vendor)` and everything else works.
The repo's `.gitignore` keeps vendor databases, capture files and TAPROOT exports out
of commits.

## Exports

Files are written to the current folder unless you give a path.

| Flag | Output |
|---|---|
| `--csv` | `taproot_<capture>_hosts_<timestamp>.csv` and `taproot_<capture>_ports_<timestamp>.csv` |
| `--csv-file FILE` | `FILE`, plus the ports CSV beside it as `<FILE>_ports.csv` |
| `--json` | `taproot_<capture>_report_<timestamp>.json`: the full report. Live runs add a `capture.live` block |
| `--json-file FILE` | The same JSON report, to `FILE` |
| `--write [FILE]` | Live only: `taproot_live_<interface>_capture_<timestamp>.pcap` by default |

## Options

```
capture file
  pcap                  .pcap, .pcapng, or either one .gz
  --host IP             limit host/port output to this IP (repeatable)
  --all-ports           also list every OBSERVED port and client-side port
  --ot                  OT/ICS findings and summary only
  --no-macs / --no-ports  skip the MAC table / the flat port table
  --flows               add the conversation table   --top N (20)
  --max-packets N       stop after N packets (0 = whole file / until stopped)

export
  --csv / --csv-file FILE      hosts + ports CSV
  --json / --json-file FILE    full JSON report

MAC vendors
  --oui-file PATH       vendor database to use (overrides autodetect)
  --update-oui          download a vendor database beside the script and exit

live capture (receive-only, needs Administrator/root)
  --live [IFACE]        listen on an interface; no value = choose from a list
  --list-ifaces         list capturable interfaces and exit
  --duration SEC        stop after SEC seconds (0 = until Ctrl+C)
  --filter BPF          capture filter, e.g. "not port 22" (Npcap/libpcap only)
  --snaplen N           bytes kept per frame (65535)
  --write [FILE]        also save the capture to a .pcap (off unless asked)
  --capture-backend auto|pcap|afpacket|rawsock
  --map                 live network map in the browser (taproot.html beside the script)
  --map-port PORT (8765)   --map-buffer-mb MB (128)   --no-browser
  --allow-remote        let other machines reach the map server (token still required)

output
  -v / -q / --no-color / --version
```

## Test procedure

1. Build the synthetic captures: `python taproot_testgen.py` writes `test.pcap`,
   `test_be.pcap`, `test_nano.pcap`, `test.pcapng` and `test.pcap.gz`. They contain a
   duplicate ARP claim, a Modbus/TCP session with two writes and an exception
   response, S7comm picked up mid-conversation, SSH refused with RST, Telnet answering
   on one host and unanswered on another, a 25-port sweep, DNP3, BACnet/IP, SNMP,
   syslog answered with ICMP unreachable, DHCP, mDNS/NBNS names, LLDP/CDP from a
   switch, STP, a PROFINET DCP station name, VLAN-tagged EtherNet/IP, IPv6 OPC UA,
   an EtherCAT frame, and a 3-byte runt.
2. `python taproot.py test.pcap`, then `python taproot.py test.pcapng --flows --csv`.
   Expect the duplicate ARP claim and the sweep under anomalies, the Modbus writes
   called out under OT/ICS findings, S7comm marked `(role inferred)`, SSH `REFUSED`,
   and Telnet `SERVING` on one host and `OBSERVED` on the other. All five files
   should give the same inventory: 14 hosts, 10 MACs and 45 conversations.
3. Drop `test.pcap` on `taproot.html`. Host, MAC and port counts should match the CLI.
4. Live, from an elevated prompt: start `python moth.py --bind 127.0.0.2 --no-sniff`,
   then `python taproot.py --live loopback --map`. Point AtomICS (or any Modbus
   client) at 127.0.0.2:502 and do one read and one write. Expect
   `SERVING 127.0.0.2 tcp/502` and a `WRITE` line in the terminal, and two nodes
   joined by an arrow on the map. Use 127.0.0.2 rather than 127.0.0.1, because traffic
   from 127.0.0.1 to itself cannot be drawn as a link. Ctrl+C prints the full report.
5. Repeat step 4 with `--write live.pcap --json-file live.json`, then run
   `python taproot.py live.pcap --json-file file.json`. The hosts, MACs and
   conversations in the two JSON files should be identical.

## Operational notes

* Capture files and live traffic from a control network contain process values,
  credentials and topology. Treat them as sensitive evidence when you store, copy or
  share them.
* Role inference and asset classification are evidence-backed guesses. Check them
  before they go in a report.
* Per-host caps keep one chatty host from ballooning memory; anything beyond a cap is
  counted in the summary. For very large captures, sample with `--max-packets`.

## License

MIT. See [LICENSE](LICENSE).

---

Vibe coded by Mike Holcomb of UtilSec, LLC ·
[LinkedIn](https://www.linkedin.com/in/mikeholcomb) · [mikeholcomb.com](https://mikeholcomb.com)

AUTHORIZED USE ONLY. For training/education or authorized assessment, on captures you
own or are permitted to analyze and networks you are authorized to monitor. Not for
production environments where safety or operational availability cannot be
guaranteed. Inferred findings are not verified facts. Use at your own risk.
