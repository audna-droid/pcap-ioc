#!/usr/bin/env python3
"""
pcap-ioc - pull indicators of compromise out of a classic libpcap capture.

Point it at a .pcap and it hands back the things you'd open Wireshark to find:
the domains that were looked up, the HTTP hosts and request URIs, any URL
pointing straight at a raw IP, and a short flow summary (top destinations and
the raw-IP destinations that were never resolved via DNS first - the beaconing
smell). It's the quick pivot list, not a protocol analyser.

This reads the *classic* libpcap format only (the 24-byte global header + one
16-byte record header per packet), NOT the newer pcapng - a .pcapng file is
detected and rejected with a clear message. The capture is only ever read as
bytes; nothing in it is executed or fetched, so it's safe to run against a
capture pulled off a dirty network.

Scope, on purpose (see the limitations in the README):
  - IPv4 only, over TCP and UDP. ARP / IPv6 / other L3 are counted and skipped.
  - No stream reassembly. Each packet's payload is scanned on its own, so an
    HTTP request that Host-headers in one segment and GETs in another can be
    missed. For triage of the first packet of a flow this is almost always fine.
  - No TLS inspection. HTTPS payloads are opaque here; you get the flow (dst IP
    and :443) but not an SNI - that's a deliberate non-goal.

Usage:
    python3 pcap_ioc.py capture.pcap
    python3 pcap_ioc.py capture.pcap --top 20
    python3 pcap_ioc.py capture.pcap --json > report.json
"""

import argparse
import json
import re
import struct
import sys
from collections import Counter, OrderedDict

# --- classic libpcap on-disk format ----------------------------------------
# The magic in the first 4 bytes tells us the byte order the file was written
# in (and, by the 3c/4d variants, whether timestamps are micro- or nanosecond -
# we don't use the fractional part, so we only care about the endianness).
GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": ">",   # big-endian, microsecond
    b"\xd4\xc3\xb2\xa1": "<",   # little-endian, microsecond
    b"\xa1\xb2\x3c\x4d": ">",   # big-endian, nanosecond
    b"\x4d\x3c\xb2\xa1": "<",   # little-endian, nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"   # Section Header Block - the pcapng tell

# LINKTYPE_* values we know how to strip down to an IPv4 packet. Anything else
# is reported by number and its packets are skipped rather than guessed at.
LINKTYPES = {
    0: "NULL", 1: "ETHERNET", 12: "RAW", 101: "RAW",
    108: "LOOP", 113: "LINUX_SLL",
}

# --- payload matchers -------------------------------------------------------
# Run against raw payload bytes, so we never choke on a non-UTF-8 byte mid-flow.
HTTP_REQ_RE = re.compile(
    rb"\b(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT) "
    rb"(\S+) HTTP/1\.[01]\r?\n")
HTTP_HOST_RE = re.compile(rb"[Hh]ost:[ \t]*([^\r\n]+)")
URL_RE = re.compile(rb"https?://[^\s\"'<>)\]\\}]+", re.IGNORECASE)

# A url/host whose authority is a bare dotted-quad (optionally :port).
RAW_IP_URL_RE = re.compile(
    r"^(https?)://(\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?(?:[/?#]|$)",
    re.IGNORECASE)
IPV4_TEXT_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI",
                b"PATC", b"TRAC", b"CONN")


class PcapError(Exception):
    """A file we can't make sense of as a classic libpcap capture."""


# --- pcap container ---------------------------------------------------------

def read_pcap(path):
    """Yield (linktype, [raw packet bytes, ...]) from a classic .pcap file."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < GLOBAL_HEADER_LEN:
        raise PcapError("file is too short to hold a pcap global header")

    magic = data[:4]
    if magic == PCAPNG_MAGIC:
        raise PcapError(
            "this looks like a pcapng file - only classic libpcap (.pcap) is "
            "supported; re-save it as pcap (editcap -F libpcap in.pcapng out.pcap)")
    if magic not in PCAP_MAGICS:
        raise PcapError("not a libpcap capture (unexpected magic 0x%s)"
                        % magic.hex())

    endian = PCAP_MAGICS[magic]
    _magic, _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(
        endian + "IHHiIII", data[:GLOBAL_HEADER_LEN])

    packets = []
    truncated = 0
    off = GLOBAL_HEADER_LEN
    while off + RECORD_HEADER_LEN <= len(data):
        _ts, _us, incl_len, _orig = struct.unpack(
            endian + "IIII", data[off:off + RECORD_HEADER_LEN])
        off += RECORD_HEADER_LEN
        if incl_len > len(data) - off:
            # A capture cut off mid-packet (common when a tool is killed). Keep
            # what's there, note it, and stop - the length fields past here are
            # not trustworthy.
            packets.append(data[off:])
            truncated += 1
            break
        packets.append(data[off:off + incl_len])
        off += incl_len
    return linktype, packets, truncated


# --- layer 2 / 3 / 4 --------------------------------------------------------

def ipv4_from_link(linktype, pkt):
    """Strip the data-link header and return the IPv4 packet bytes, or None."""
    if linktype == 1:  # Ethernet II
        if len(pkt) < 14:
            return None
        etype = int.from_bytes(pkt[12:14], "big")
        pos = 14
        # Walk any 802.1Q / 802.1ad VLAN tags (4 bytes each) to the real type.
        while etype in (0x8100, 0x88a8):
            if len(pkt) < pos + 4:
                return None
            etype = int.from_bytes(pkt[pos + 2:pos + 4], "big")
            pos += 4
        return pkt[pos:] if etype == 0x0800 else None
    if linktype in (12, 101):  # raw IP, no link header at all
        return pkt if pkt and (pkt[0] >> 4) == 4 else None
    if linktype in (0, 108):  # BSD loopback: 4-byte address family, then IP
        return pkt[4:] if len(pkt) >= 4 and pkt[0] in (2, 0) else None
    if linktype == 113:  # Linux "cooked" SLL: 16-byte header, type at [14:16]
        if len(pkt) < 16 or int.from_bytes(pkt[14:16], "big") != 0x0800:
            return None
        return pkt[16:]
    return None


def parse_ipv4(ip):
    """Return (proto, src, dst, l4_bytes) or None if it isn't a sane IPv4 pkt."""
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0f) * 4
    if ihl < 20 or len(ip) < ihl:
        return None
    total_len = int.from_bytes(ip[2:4], "big")
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    # Trust the IP total-length to bound the payload when it's sane; otherwise
    # fall back to whatever bytes we actually captured (snaplen can clip it).
    end = total_len if ihl <= total_len <= len(ip) else len(ip)
    return proto, src, dst, ip[ihl:end]


def parse_ports(proto, seg):
    """Return (sport, dport, payload) for TCP(6)/UDP(17), else None."""
    if proto == 6:  # TCP
        if len(seg) < 20:
            return None
        sport = int.from_bytes(seg[0:2], "big")
        dport = int.from_bytes(seg[2:4], "big")
        data_off = (seg[12] >> 4) * 4
        if data_off < 20 or data_off > len(seg):
            data_off = 20  # malformed offset; assume a header with no options
        return sport, dport, seg[data_off:]
    if proto == 17:  # UDP
        if len(seg) < 8:
            return None
        sport = int.from_bytes(seg[0:2], "big")
        dport = int.from_bytes(seg[2:4], "big")
        ulen = int.from_bytes(seg[4:6], "big")
        end = ulen if 8 <= ulen <= len(seg) else len(seg)
        return sport, dport, seg[8:end]
    return None


# --- DNS (just enough to read names) ----------------------------------------

def read_name(data, off):
    """Read a DNS name starting at off, following 0xC0 compression pointers.

    Returns (name, next_off) where next_off is the position in the record just
    after the name as it was written here (i.e. after the first pointer, not at
    the pointer's target). Bounded against the malformed / hostile case.
    """
    labels = []
    pos = off
    next_off = None
    hops = 0
    while 0 <= pos < len(data):
        length = data[pos]
        if (length & 0xc0) == 0xc0:          # pointer
            if pos + 1 >= len(data):
                break
            if next_off is None:
                next_off = pos + 2
            pos = ((length & 0x3f) << 8) | data[pos + 1]
            hops += 1
            if hops > 128:                   # pointer loop / abuse guard
                break
            continue
        if length == 0:                      # root label -> end of name
            if next_off is None:
                next_off = pos + 1
            break
        pos += 1
        if pos + length > len(data):
            break
        labels.append(data[pos:pos + length].decode("latin-1", "replace"))
        pos += length
    return ".".join(labels), (next_off if next_off is not None else pos)


def parse_dns(payload):
    """Return (query_names, a_record_ips) from a DNS message; best-effort.

    Query names come from the question section (that's the lookup that was
    asked). A-record IPs come from the answer section and feed the "was this
    destination ever actually resolved?" check downstream.
    """
    names, a_ips = [], []
    if len(payload) < 12:
        return names, a_ips
    qd = int.from_bytes(payload[4:6], "big")
    an = int.from_bytes(payload[6:8], "big")
    off = 12
    try:
        for _ in range(qd):
            name, off = read_name(payload, off)
            if name:
                names.append(name.lower())
            off += 4  # QTYPE + QCLASS
        for _ in range(an):
            _name, off = read_name(payload, off)
            if off + 10 > len(payload):
                break
            rtype = int.from_bytes(payload[off:off + 2], "big")
            rdlen = int.from_bytes(payload[off + 8:off + 10], "big")
            rdata = off + 10
            if rdata + rdlen > len(payload):
                break
            if rtype == 1 and rdlen == 4:  # A record
                a_ips.append(".".join(str(b) for b in payload[rdata:rdata + 4]))
            off = rdata + rdlen
    except (IndexError, ValueError):
        pass  # truncated / malformed message - keep whatever we got
    return names, a_ips


# --- HTTP (request line + Host, no reassembly) ------------------------------

def host_of(url):
    """The authority (host, no scheme/userinfo/port/path) of an http(s) URL."""
    rest = url.split("://", 1)[1] if "://" in url else url
    rest = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    if rest.startswith("["):              # IPv6 literal - out of scope, but
        return rest.split("]", 1)[0] + "]"  # don't mangle it
    return rest.split(":", 1)[0]


def scan_http(payload, hosts, requests, raw_ip_urls):
    """Pull HTTP hosts, reconstructed request URLs and raw-IP URLs from one
    payload. Request lines are paired with Host headers positionally, which is
    right for the usual one-request-per-packet case (we don't reassemble)."""
    if not payload[:4] in HTTP_METHODS:
        # Still worth a cheap raw-IP-URL sweep (e.g. an absolute URL echoed in
        # a response body), but skip the request parsing.
        _sweep_raw_ip_urls(payload, raw_ip_urls)
        return
    reqs = HTTP_REQ_RE.findall(payload)
    hdr_hosts = [h.decode("latin-1", "replace").strip()
                 for h in HTTP_HOST_RE.findall(payload)]
    for i, (method, target) in enumerate(reqs):
        method = method.decode("ascii")
        target = target.decode("latin-1", "replace")
        host = hdr_hosts[i] if i < len(hdr_hosts) else (
            hdr_hosts[0] if hdr_hosts else None)

        url = None
        low = target.lower()
        if low.startswith("http://") or low.startswith("https://"):
            url = target                       # absolute-form (proxy style)
        elif method == "CONNECT":
            hosts.add(host_of("//" + target))  # authority-form "host:port"
            requests.add("CONNECT " + target)
            continue
        elif target.startswith("/") and host:
            url = "http://" + host + target     # origin-form + Host header
        else:
            if host:
                hosts.add(host)
            requests.add(method + " " + target)
            continue

        requests.add(url)
        h = host_of(url)
        if h:
            hosts.add(h)
        m = RAW_IP_URL_RE.match(url)
        if m and valid_ipv4(m.group(2)):
            raw_ip_urls.add(url)
    _sweep_raw_ip_urls(payload, raw_ip_urls)


def _sweep_raw_ip_urls(payload, raw_ip_urls):
    for m in URL_RE.finditer(payload):
        url = m.group().decode("latin-1", "replace").rstrip(".,;:!?\"')]}>")
        rm = RAW_IP_URL_RE.match(url)
        if rm and valid_ipv4(rm.group(2)):
            raw_ip_urls.add(url)


# --- helpers ----------------------------------------------------------------

def valid_ipv4(ip):
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and int(p) <= 255 for p in parts)


def is_to_server(sport, dport):
    """Best-effort "this packet is heading client -> server".

    Without flow state we can't know for certain, but the server almost always
    owns the well-known / lower port while the client picks an ephemeral high
    one. This is only used to attribute each packet to the server endpoint of
    its conversation, so a both-ephemeral-port flow (rare in triage) is the only
    case it can get backwards.
    """
    well_d, well_s = dport < 1024, sport < 1024
    if well_d != well_s:
        return well_d          # the well-known side is the server
    return dport <= sport      # otherwise treat the lower port as the server


def is_multicast_or_broadcast(ip):
    """Drop addresses that are never a C2 'destination' in any useful sense."""
    if ip in ("0.0.0.0", "255.255.255.255"):
        return True
    try:
        first = int(ip.split(".")[0])
    except ValueError:
        return False
    return 224 <= first <= 239  # 224.0.0.0/4, incl. mDNS/SSDP/IGMP groups


# --- the pass ---------------------------------------------------------------

def analyse(path, top):
    linktype, packets, truncated = read_pcap(path)

    domains = set()
    resolved = set()          # IPs seen as DNS A answers
    dns_servers = set()       # dst IPs we sent :53 queries to
    http_hosts = set()
    http_requests = set()
    raw_ip_urls = set()

    dst_ip_counts = Counter()
    dst_port_counts = Counter()   # keyed by (port, proto)
    contacted = set()             # dst IPs over TCP/UDP

    parsed = 0
    for pkt in packets:
        ip = ipv4_from_link(linktype, pkt)
        if ip is None:
            continue
        hdr = parse_ipv4(ip)
        if hdr is None:
            continue
        proto, src, dst, seg = hdr
        ports = parse_ports(proto, seg)
        if ports is None:
            continue
        sport, dport, payload = ports
        proto_name = "tcp" if proto == 6 else "udp"
        parsed += 1

        # Protocol parsing runs on either direction: a query goes client->server
        # and its answer comes back the other way, likewise HTTP request vs body.
        if 53 in (sport, dport):
            names, a_ips = parse_dns(payload)
            domains.update(names)
            resolved.update(a_ips)
        if payload and (80 in (sport, dport) or payload[:4] in HTTP_METHODS):
            scan_http(payload, http_hosts, http_requests, raw_ip_urls)

        # Attribute the packet to the *server* endpoint, so server->client
        # replies (and our own host) don't inflate the destination stats.
        if is_to_server(sport, dport):
            srv_ip, srv_port = dst, dport
        else:
            srv_ip, srv_port = src, sport
        dst_ip_counts[srv_ip] += 1
        dst_port_counts[(srv_port, proto_name)] += 1
        contacted.add(srv_ip)
        if srv_port == 53:
            dns_servers.add(srv_ip)

    # Beaconing smell: an IP we sent traffic to that was never handed to us by
    # DNS and isn't itself the resolver. Private ranges are kept on purpose -
    # an internal pivot can be exactly the thing you care about.
    no_dns = sorted(
        ip for ip in (contacted - resolved - dns_servers)
        if not is_multicast_or_broadcast(ip)
    )

    return OrderedDict([
        ("file", path),
        ("link_type", OrderedDict([
            ("code", linktype),
            ("name", LINKTYPES.get(linktype, "UNKNOWN")),
        ])),
        ("packets", OrderedDict([
            ("captured", len(packets)),
            ("ipv4_tcp_udp", parsed),
            ("skipped", len(packets) - parsed),
            ("truncated", truncated),
        ])),
        ("iocs", OrderedDict([
            ("domains", sorted(domains)),
            ("http_hosts", sorted(http_hosts)),
            ("http_requests", sorted(http_requests)),
            ("raw_ip_urls", sorted(raw_ip_urls)),
        ])),
        ("flow", OrderedDict([
            ("top_dst_ips", [
                OrderedDict([("ip", ip), ("packets", n)])
                for ip, n in dst_ip_counts.most_common(top)]),
            ("top_dst_ports", [
                OrderedDict([("port", p), ("proto", pr), ("packets", n)])
                for (p, pr), n in dst_port_counts.most_common(top)]),
            ("dst_ips_no_preceding_dns", no_dns),
        ])),
    ])


# --- output -----------------------------------------------------------------

def print_report(r):
    bar = "=" * 64
    pk = r["packets"]
    print(bar)
    print("pcap-ioc report: %s" % r["file"])
    print(bar)
    print("Link type : %s (%d)" % (r["link_type"]["name"], r["link_type"]["code"]))
    tail = " (%d truncated)" % pk["truncated"] if pk["truncated"] else ""
    print("Packets   : %d captured, %d IPv4 TCP/UDP, %d skipped%s"
          % (pk["captured"], pk["ipv4_tcp_udp"], pk["skipped"], tail))

    sections = [
        ("Domains (DNS queries)", r["iocs"]["domains"]),
        ("HTTP hosts", r["iocs"]["http_hosts"]),
        ("HTTP requests", r["iocs"]["http_requests"]),
        ("Raw-IP URLs", r["iocs"]["raw_ip_urls"]),
    ]
    for title, items in sections:
        print("\n[ %s ]  %d" % (title, len(items)))
        for v in items:
            print("  - %s" % v)

    flow = r["flow"]
    print("\n[ Flow summary ]")
    print("  Top destination IPs:")
    for e in flow["top_dst_ips"]:
        print("    %-18s %d pkt" % (e["ip"], e["packets"]))
    print("  Top destination ports:")
    for e in flow["top_dst_ports"]:
        print("    %-18s %d pkt" % ("%d/%s" % (e["port"], e["proto"]), e["packets"]))
    print("  Raw-IP destinations with no preceding DNS (beaconing smell):  %d"
          % len(flow["dst_ips_no_preceding_dns"]))
    for ip in flow["dst_ips_no_preceding_dns"]:
        print("    ! %s" % ip)
    print(bar)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Pull IOCs out of a classic libpcap (.pcap) capture.")
    ap.add_argument("pcap", help="path to the .pcap file (classic libpcap, not pcapng)")
    ap.add_argument("--top", type=int, default=10, metavar="N",
                    help="how many top destinations to list in the flow summary (default 10)")
    ap.add_argument("--json", action="store_true",
                    help="emit a JSON report instead of text")
    args = ap.parse_args(argv)

    try:
        report = analyse(args.pcap, max(1, args.top))
    except FileNotFoundError:
        sys.exit("error: no such file: %s" % args.pcap)
    except PcapError as exc:
        sys.exit("error: %s" % exc)

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print_report(report)


if __name__ == "__main__":
    main()
