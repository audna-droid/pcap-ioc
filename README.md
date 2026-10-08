# pcap-ioc

A small, dependency-free tool that pulls indicators of compromise out of a
classic libpcap capture. Point it at a `.pcap` and it hands back the things
you'd otherwise open Wireshark to dig for:

- **domains** that were looked up (DNS query names)
- **HTTP hosts** and the request URIs behind them
- **raw-IP URLs** — an `http://<ip>/...` with no domain in sight
- a short **flow summary**: the top destinations, and the raw-IP destinations
  that were never resolved via DNS first (the beaconing smell)

It reads the *classic* libpcap format only — the 24-byte global header plus a
16-byte header per packet — **not** the newer pcapng; a `.pcapng` is detected
and rejected with a message telling you how to convert it. The capture is only
ever read as bytes. Nothing in it is parsed as anything executable, opened, or
fetched, so it's safe to run against traffic pulled off a dirty network.

## Why

When I'm working a sample, the network side is always the same first move:
open the capture, skim the DNS, pull the HTTP hosts, and note anything talking
straight to a bare IP. In Wireshark that's a few minutes of clicking and a
display filter I retype every time. I got tired of that, so this does the one
pass and prints a short list of things to pivot on — domains, IPs, URLs —
without a GUI and without me missing the raw-IP callback because it scrolled
off screen.

It's the on-the-wire half of how I work: [elf-triage][elf] does the first
static pass on a suspicious file, and when a teardown over in [re-notes][notes]
recovers a hard-coded C2, this is what I point at the capture to catch it.

## Usage

```bash
python3 pcap_ioc.py capture.pcap
python3 pcap_ioc.py capture.pcap --top 20       # longer top-destinations list
python3 pcap_ioc.py capture.pcap --json > report.json
```

Requires Python 3.8+. No third-party packages.

If you only have a pcapng, convert it first:

```bash
editcap -F libpcap capture.pcapng capture.pcap
```

## Example

Run against a tiny two-packet capture — one DNS query and one HTTP request to a
raw IP, all synthetic (RFC 5737 addresses and `example.com`):

```
================================================================
pcap-ioc report: capture.pcap
================================================================
Link type : ETHERNET (1)
Packets   : 2 captured, 2 IPv4 TCP/UDP, 0 skipped

[ Domains (DNS queries) ]  1
  - telemetry.example.com

[ HTTP hosts ]  1
  - 203.0.113.9

[ HTTP requests ]  1
  - http://203.0.113.9/x

[ Raw-IP URLs ]  1
  - http://203.0.113.9/x

[ Flow summary ]
  Top destination IPs:
    198.51.100.53      1 pkt
    203.0.113.9        1 pkt
  Top destination ports:
    53/udp             1 pkt
    80/tcp             1 pkt
  Raw-IP destinations with no preceding DNS (beaconing smell):  1
    ! 203.0.113.9
================================================================
```

The `203.0.113.9` HTTP request is flagged under *beaconing smell* because the
host connected to it without ever resolving it through DNS — the resolver at
`198.51.100.53` was asked about `telemetry.example.com`, not about that IP. A
hard-coded-IP callback is exactly the shape that stands out.

`--json` emits the same report as a document you can feed to the next tool:

```json
{
  "file": "capture.pcap",
  "link_type": { "code": 1, "name": "ETHERNET" },
  "packets": { "captured": 2, "ipv4_tcp_udp": 2, "skipped": 0, "truncated": 0 },
  "iocs": {
    "domains": ["telemetry.example.com"],
    "http_hosts": ["203.0.113.9"],
    "http_requests": ["http://203.0.113.9/x"],
    "raw_ip_urls": ["http://203.0.113.9/x"]
  },
  "flow": {
    "top_dst_ips": [ { "ip": "198.51.100.53", "packets": 1 }, ... ],
    "dst_ips_no_preceding_dns": ["203.0.113.9"]
  }
}
```

## How it works

- **The container** is parsed with `struct`: read the magic to get the byte
  order (and reject pcapng), then walk record header → packet → record header
  until the file ends. A capture cut off mid-packet is noted, not crashed on.
- **Layers** are walked just far enough: Ethernet II (including VLAN tags) /
  raw-IP / BSD-loopback / Linux-SLL down to IPv4, then IPv4 → TCP or UDP to get
  the ports and the payload bytes.
- **DNS** is parsed by hand — the header, then the question section for query
  names, then the answer section for A records. Names follow `0xC0` compression
  pointers (with a loop guard). The A records feed the "was this destination
  ever actually resolved?" check.
- **HTTP** is matched out of the payload bytes: the request line (origin-form
  `GET /x` paired with its `Host:` header, or absolute-form `GET http://...`)
  and any `http(s)://<ip>` anywhere in the payload.
- Each packet is attributed to the **server endpoint** of its conversation
  (the well-known / lower port), so a destination's replies — and your own
  host — don't show up as destinations.

## Notes / limitations

- **IPv4 + TCP/UDP + classic pcap only.** ARP, IPv6 and other link/transport
  types are counted in `skipped`, not decoded. pcapng isn't read at all.
- **No stream reassembly.** Each packet's payload is scanned on its own, so an
  HTTP request whose headers span two segments can be missed, and the `Host:`
  pairing assumes one request per packet. For the first packet of a flow —
  which is what you usually care about — that's fine.
- **No TLS inspection.** HTTPS is opaque here; you get the flow (the IP and
  `:443`) but no SNI. That's a deliberate non-goal, not a TODO.
- The beaconing list is a *smell*, not a verdict: a CDN reached via a CNAME,
  NTP, or anything resolved in an earlier capture will land in it too. Private
  and loopback ranges are kept on purpose — an internal pivot can be the thing
  you care about. Read the list; a clean capture is not a clean host.

[elf]: https://github.com/audna-droid/elf-triage
[notes]: https://github.com/audna-droid/re-notes

## License

MIT
