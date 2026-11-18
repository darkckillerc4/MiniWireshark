<!-- Written by .github/scripts/reference_docs.py from the field tables in miniwireshark.py. Edit the tables, then run the script; CI fails when this page is out of date. -->

# Packet filter fields

Every field the **Packets** tab's field filter understands, grouped by protocol: 19 protocols and 166 fields, plus 11 shortcut fields. The same names appear in the packet details tree, so you can also right-click a value there and choose **Copy as filter**. For the friendly search tokens (`site:`, `port:` …) see [Filtering](USER-GUIDE.md#filtering).

## How to write a filter

- Compare a field with a value: `==` `!=` `>=` `<=` `>` `<` `contains`. `contains` matches part of a text value. Put text in double quotes.
- Combine with `and` (`&&`), `or` (`||`) and `not` (`!`), and use parentheses.
- A protocol name alone keeps the packets that have it, for example `dns`, `tls` or `arp`. The names that work this way are `arp`, `dhcp`, `dns`, `eth`, `http`, `icmp`, `icmpv6`, `ip`, `ipv6`, `mdns`, `ntp`, `quic`, `tcp`, `tls`, `udp`, `vlan`, and the port-based names below.
- A filter that doesn't parse shows the reason and changes nothing. Filters only choose what is shown; they never change what is captured.

```
ip.src == 192.168.1.20 && tcp.port == 443
dns.qry.name contains "example"
tls and not ip.dst == 10.0.0.1
frame.len > 1000 or expert.severity >= warning
```

## Shortcut fields

These match either direction, or describe the packet as a whole.

| Field | Type | Meaning |
|---|---|---|
| `frame.number` | number | Packet number |
| `ip.addr` | IPv4 address | IPv4 address, either direction |
| `ipv6.addr` | IPv6 address | IPv6 address, either direction |
| `tcp.port` | number | TCP port, either direction |
| `udp.port` | number | UDP port, either direction |
| `eth.addr` | MAC address | MAC address, either direction |
| `expert.severity` | severity | Worst expert finding on the packet (chat, note, warning, error) |
| `frame.time_relative` | number | Seconds since the first packet |
| `tcp.stream` | number | Connection number |
| `expert.group` | text | Expert finding group (Sequence, Malformed, Protocol, Security, Checksum, Response code) |
| `expert.message` | text | Expert finding text |

## Protocols known by port

These names work alone as a filter. They match the usual ports, so a service on another port is not matched.

| Name | Ports |
|---|---|
| `dot` | 853 |
| `ftp` | 21 |
| `imap` | 143, 993 |
| `mqtt` | 1883, 8883 |
| `pop3` | 110, 995 |
| `rdp` | 3389 |
| `rtsp` | 554 |
| `sip` | 5060, 5061 |
| `smb` | 139, 445 |
| `smtp` | 25, 465, 587 |
| `ssdp` | 1900 |
| `ssh` | 22 |
| `telnet` | 23 |

## Fields by protocol

- [Frame](#frame)
- [Ethernet II](#ethernet-ii)
- [802.1Q VLAN tag](#8021q-vlan-tag)
- [Linux cooked capture](#linux-cooked-capture)
- [ARP](#arp)
- [Internet Protocol version 4](#internet-protocol-version-4)
- [Internet Protocol version 6](#internet-protocol-version-6)
- [Internet Control Message Protocol](#internet-control-message-protocol)
- [Internet Control Message Protocol v6](#internet-control-message-protocol-v6)
- [User Datagram Protocol](#user-datagram-protocol)
- [Transmission Control Protocol](#transmission-control-protocol)
- [Domain Name System](#domain-name-system)
- [Dynamic Host Configuration Protocol](#dynamic-host-configuration-protocol)
- [Transport Layer Security](#transport-layer-security)
- [QUIC](#quic)
- [Hypertext Transfer Protocol](#hypertext-transfer-protocol)
- [Network Time Protocol](#network-time-protocol)
- [Text protocol](#text-protocol)
- [Data](#data)

## Frame

This layer has no filter name of its own; filter on its fields.

| Field | Type | Meaning |
|---|---|---|
| `frame.len` | number, in bytes | Frame length: bytes on the wire |
| `frame.linktype` | number | Link type: how the frame was captured |

## Ethernet II

Filter on the protocol alone with `eth`.

| Field | Type | Meaning |
|---|---|---|
| `eth.dst` | MAC address | Destination: the card the frame is for |
| `eth.src` | MAC address | Source: the card that sent the frame |
| `eth.type` | number (hex) | Type: which protocol is inside |

## 802.1Q VLAN tag

Filter on the protocol alone with `vlan`.

| Field | Type | Meaning |
|---|---|---|
| `vlan.priority` | number | Priority: 0 (lowest) to 7 |
| `vlan.id` | number | VLAN ID: which virtual network |
| `vlan.etype` | number (hex) | Type: which protocol is inside the tag |

## Linux cooked capture

This layer has no filter name of its own; filter on its fields.

| Field | Type | Meaning |
|---|---|---|
| `sll.pkttype` | number | Packet type: to us, broadcast, sent by us… |
| `sll.src.eth` | MAC address | Source: the card that sent the frame |
| `sll.etype` | number (hex) | Protocol: which protocol is inside |

## ARP

Filter on the protocol alone with `arp`.

| Field | Type | Meaning |
|---|---|---|
| `arp.hw.type` | number | Hardware type |
| `arp.proto.type` | number (hex) | Protocol type |
| `arp.opcode` | number | Operation: request (who has?) or reply |
| `arp.src.hw_mac` | MAC address | Sender MAC address |
| `arp.src.proto_ipv4` | IPv4 address | Sender IP address |
| `arp.dst.hw_mac` | MAC address | Target MAC address |
| `arp.dst.proto_ipv4` | IPv4 address | Target IP address |

## Internet Protocol version 4

Filter on the protocol alone with `ip`.

| Field | Type | Meaning |
|---|---|---|
| `ip.version` | number | Version |
| `ip.hdr_len` | number, in bytes | Header length |
| `ip.dsfield` | number (hex) | Differentiated services (priority marking) |
| `ip.len` | number, in bytes | Total length |
| `ip.id` | number (hex) | Identification: groups fragments of one packet |
| `ip.flags.df` | true or false | Don't fragment |
| `ip.flags.mf` | true or false | More fragments follow |
| `ip.frag_offset` | number, in bytes | Fragment offset |
| `ip.ttl` | number, in hops | Time to live: routers it may still cross |
| `ip.proto` | number | Protocol: what is inside |
| `ip.checksum` | number (hex) | Header checksum |
| `ip.checksum.status` | text | Checksum check |
| `ip.src` | IPv4 address | Source address |
| `ip.dst` | IPv4 address | Destination address |
| `ip.options` | bytes | Options |

## Internet Protocol version 6

Filter on the protocol alone with `ipv6`.

| Field | Type | Meaning |
|---|---|---|
| `ipv6.version` | number | Version |
| `ipv6.tclass` | number (hex) | Traffic class (priority marking) |
| `ipv6.flow` | number (hex) | Flow label |
| `ipv6.plen` | number, in bytes | Payload length |
| `ipv6.nxt` | number | Next header: what follows |
| `ipv6.hlim` | number, in hops | Hop limit: routers it may still cross |
| `ipv6.src` | IPv6 address | Source address |
| `ipv6.dst` | IPv6 address | Destination address |
| `ipv6.ext` | text | Extension header |
| `ipv6.fragment.id` | number (hex) | Fragment identification |
| `ipv6.fragment.offset` | number, in bytes | Fragment offset |
| `ipv6.fragment.more` | true or false | More fragments follow |

## Internet Control Message Protocol

Filter on the protocol alone with `icmp`.

| Field | Type | Meaning |
|---|---|---|
| `icmp.type` | number | Type: what kind of message |
| `icmp.code` | number | Code: detail for the type |
| `icmp.checksum` | number (hex) | Checksum |
| `icmp.ident` | number | Identifier (ping) |
| `icmp.seq` | number | Sequence number (ping) |

## Internet Control Message Protocol v6

Filter on the protocol alone with `icmpv6`.

| Field | Type | Meaning |
|---|---|---|
| `icmpv6.type` | number | Type: what kind of message |
| `icmpv6.code` | number | Code: detail for the type |
| `icmpv6.checksum` | number (hex) | Checksum |
| `icmpv6.nd.ra.cur_hop_limit` | number | Suggested hop limit |
| `icmpv6.nd.ra.flag` | number (hex) | Router flags (managed, other…) |
| `icmpv6.nd.ra.router_lifetime` | number, in s | Router lifetime: how long to use this router |
| `icmpv6.nd.na.flag` | number (hex) | Flags (router, solicited, override) |
| `icmpv6.nd.target` | IPv6 address | Target address |
| `icmpv6.opt.type` | number | Option type |
| `icmpv6.opt.linkaddr` | MAC address | Link-layer address |
| `icmpv6.opt.prefix` | IPv6 address | Prefix announced to the network |
| `icmpv6.opt.prefix.length` | number, in bits | Prefix length |

## User Datagram Protocol

Filter on the protocol alone with `udp`.

| Field | Type | Meaning |
|---|---|---|
| `udp.srcport` | number | Source port |
| `udp.dstport` | number | Destination port |
| `udp.length` | number, in bytes | Length |
| `udp.checksum` | number (hex) | Checksum |
| `udp.checksum.status` | text | Checksum check |

## Transmission Control Protocol

Filter on the protocol alone with `tcp`.

| Field | Type | Meaning |
|---|---|---|
| `tcp.srcport` | number | Source port |
| `tcp.dstport` | number | Destination port |
| `tcp.seq_raw` | number | Sequence number |
| `tcp.ack_raw` | number | Acknowledgment number |
| `tcp.hdr_len` | number, in bytes | Header length |
| `tcp.flags` | number (hex) | Flags |
| `tcp.flags.syn` | true or false | SYN: open a connection |
| `tcp.flags.ack` | true or false | ACK: acknowledges data |
| `tcp.flags.push` | true or false | PSH: hand data to the program now |
| `tcp.flags.fin` | true or false | FIN: no more data from this side |
| `tcp.flags.reset` | true or false | RST: abort the connection |
| `tcp.flags.urg` | true or false | URG: urgent pointer is valid |
| `tcp.window_size_value` | number | Window: receive space advertised |
| `tcp.checksum` | number (hex) | Checksum |
| `tcp.checksum.status` | text | Checksum check |
| `tcp.urgent_pointer` | number | Urgent pointer |
| `tcp.len` | number, in bytes | Payload length |
| `tcp.options.mss_val` | number, in bytes | Maximum segment size: largest piece the sender accepts |
| `tcp.options.wscale.shift` | number | Window scale: multiplies the window by 2^shift |
| `tcp.options.sack_perm` | true or false | Selective acknowledgments allowed |
| `tcp.options.sack` | text | Selective acknowledgment blocks |
| `tcp.options.timestamp.tsval` | number | Timestamp value |
| `tcp.options.timestamp.tsecr` | number | Timestamp echo reply |

## Domain Name System

Filter on the protocol alone with `dns`.

| Field | Type | Meaning |
|---|---|---|
| `dns.id` | number (hex) | Transaction ID: pairs a question with its answer |
| `dns.flags.response` | true or false | Message: query or response |
| `dns.flags.opcode` | number | Opcode |
| `dns.flags.authoritative` | true or false | Authoritative answer |
| `dns.flags.truncated` | true or false | Truncated |
| `dns.flags.recdesired` | true or false | Recursion desired |
| `dns.flags.recavail` | true or false | Recursion available |
| `dns.flags.rcode` | number | Reply code: did the lookup work? |
| `dns.count.queries` | number | Questions |
| `dns.count.answers` | number | Answers |
| `dns.count.auth_rr` | number | Authority records |
| `dns.count.add_rr` | number | Additional records |
| `dns.qry.name` | text | Name looked up |
| `dns.qry.type` | number | Record type asked for |
| `dns.resp.name` | text | Name |
| `dns.resp.type` | number | Record type |
| `dns.resp.ttl` | number, in s | Time to live: how long it may be cached |
| `dns.a` | IPv4 address | Address (A) |
| `dns.aaaa` | IPv6 address | Address (AAAA) |
| `dns.cname` | text | Alias of (CNAME) |
| `dns.ptr.domain_name` | text | Points to (PTR) |
| `dns.txt` | text | Text (TXT) |
| `dns.srv.target` | text | Service host (SRV) |
| `dns.srv.port` | number | Service port (SRV) |

## Dynamic Host Configuration Protocol

Filter on the protocol alone with `dhcp`.

| Field | Type | Meaning |
|---|---|---|
| `dhcp.type` | number | Message: 1 request from a device, 2 reply |
| `dhcp.id` | number (hex) | Transaction ID |
| `dhcp.ip.client` | IPv4 address | Client's current address |
| `dhcp.ip.your` | IPv4 address | Address offered to the client |
| `dhcp.ip.server` | IPv4 address | Next server address |
| `dhcp.ip.relay` | IPv4 address | Relay agent address |
| `dhcp.hw.mac_addr` | MAC address | Client hardware address |
| `dhcp.cookie` | number (hex) | Magic cookie |
| `dhcp.option.dhcp` | number | DHCP message type |
| `dhcp.option.hostname` | text | Host name the device announced |
| `dhcp.option.requested_ip_address` | IPv4 address | Requested address |
| `dhcp.option.ip_address_lease_time` | number, in s | Lease time |
| `dhcp.option.router` | IPv4 address | Router |
| `dhcp.option.domain_name_server` | IPv4 address | DNS server |
| `dhcp.option.dhcp_server_id` | IPv4 address | DHCP server |
| `dhcp.option.vendor_class_id` | text | Vendor class |
| `dhcp.option.request_list` | text | Parameter request list (a device fingerprint) |
| `dhcp.option.client_id` | number (hex) | Client identifier |
| `dhcp.option.other` | number (hex) | Other option |

## Transport Layer Security

Filter on the protocol alone with `tls`.

| Field | Type | Meaning |
|---|---|---|
| `tls.record.content_type` | number | Content type |
| `tls.record.version` | number (hex) | Record version |
| `tls.record.length` | number, in bytes | Record length |
| `tls.handshake.type` | number | Handshake type |
| `tls.handshake.version` | number (hex) | Version offered |
| `tls.handshake.ciphersuites_count` | number | Cipher suites offered |
| `tls.handshake.extensions_server_name` | text | Server name (SNI): the site asked for |
| `tls.handshake.extensions_alpn_str` | text | Application protocols offered (ALPN) |
| `tls.handshake.extensions.supported_version` | number (hex) | Supported version |
| `tls.app_data` | text | Encrypted application data |

## QUIC

Filter on the protocol alone with `quic`.

| Field | Type | Meaning |
|---|---|---|
| `quic.header_form` | text | Header form |
| `quic.version` | number (hex) | Version |
| `quic.dcid` | number (hex) | Destination connection ID |
| `quic.scid` | number (hex) | Source connection ID |
| `quic.long.packet_type` | text | Packet type |
| `quic.payload` | text | Protected payload |

## Hypertext Transfer Protocol

Filter on the protocol alone with `http`.

| Field | Type | Meaning |
|---|---|---|
| `http.request.method` | text | Method |
| `http.request.uri` | text | Path asked for |
| `http.request.version` | text | Version |
| `http.response.code` | number | Status code |
| `http.response.phrase` | text | Status text |
| `http.host` | text | Host: the site asked for |
| `http.user_agent` | text | User agent: the program asking |
| `http.server` | text | Server software |
| `http.content_length` | number, in bytes | Content length |
| `http.header` | text | Header |

## Network Time Protocol

Filter on the protocol alone with `ntp`.

| Field | Type | Meaning |
|---|---|---|
| `ntp.flags.li` | number | Leap indicator |
| `ntp.flags.vn` | number | Version |
| `ntp.flags.mode` | number | Mode: 3 client, 4 server |
| `ntp.stratum` | number | Stratum: distance from a reference clock |
| `ntp.xmt` | text | Transmit time |

## Text protocol

This layer has no filter name of its own; filter on its fields.

| Field | Type | Meaning |
|---|---|---|
| `text.line` | text | Line |

## Data

This layer has no filter name of its own; filter on its fields.

| Field | Type | Meaning |
|---|---|---|
| `data.len` | number, in bytes | Bytes not decoded further |
