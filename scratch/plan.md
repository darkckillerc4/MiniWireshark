# MiniWireshark 4 — Expansion Plan
 · 
## 1. Executive mission and product thesis
MiniWireshark 4 should turn 3.0's plain-English packet watcher into an evidence-backed observatory for your own network. Every claim it shows should be one click from its proof, and every blind spot should be named.
This plan starts from the code that exists today: miniwireshark.py 3.0.0, 18,715 lines, which I wrote and tested in our last session. It does not start from the brief's wish list. The measurements in section 2 change the priorities. The capture path tops out at roughly 2,000 packets per second because scapy dissects every packet. Memory grows by about 9.3 KiB for every packet kept in view. These two facts outrank any new feature.
Product promise. Open MiniWireshark, and within a minute you can tell:
which devices are here and which are active right now;
what each device is doing, as far as the evidence supports it;
what changed since you last looked;
what this computer cannot see from where it sits, and what would let it see more.
Every statement carries one of five evidence levels:
Observed — seen directly in traffic.
Reported — told by an integration you set up.
Correlated — two observations linked together.
Inferred — a guess, shown with its confidence.
Unknown — no evidence either way.
Who it serves. A household or small-office owner who wants plain answers. A power user who wants to drill from a summary down to the packets. A helper who receives a redacted report and must trust it.
The ten biggest transformations, in dependency order:
Capture pipeline 10x. Read raw bytes and parse headers with struct (1.2 µs per packet measured, against 270 µs for scapy). Call scapy only for packets that need it. Move analysis off the GUI thread. Target: 15,000 packets per second sustained, with every dropped packet counted.
Evidence ledger. Store raw observations separately from the conclusions drawn from them. Every device name, domain link and alert keeps a pointer to the observations behind it. "Why do you think that?" works everywhere.
Coverage model. For each device and each question, say what this vantage point can actually see — for example, "only its broadcasts" — and how to see more.
Identity graph with time. Link devices, network adapters and addresses through bindings that each have a start and an end. Reusing an IP can then never merge two owners' histories. Merges and splits go through an undoable journal.
Network fingerprints. Keep separate histories and separate scanning consent for each network (home, office, café). The network is identified by its router MAC, its subnet, and the Wi-Fi network name (SSID) when available.
Durable history and "what changed". Store history in SQLite with fixed retention tiers. Show a since-yesterday digest, a two-session comparison, and a timeline that pages through millions of events.
Managed modern runtime. The bootstrap is written in syntax any Python 3.8+ can read. It provisions a private, pinned and hash-checked Python 3.14 environment. It never rewrites system Python and can always roll back.
Legitimate coverage expansion. Opt-in, read-only connectors to the logs of Pi-hole and AdGuard Home (DNS filters many households already run). Connections to this PC attributed to the programs that opened them. LLDP frames to learn which switch port this PC is plugged into. Reading the site name from QUIC's first packet, which is protected only by public keys and so is not decryption.
Guided investigations. "Why is my Internet slow?" and "What is using my bandwidth?" walk through the evidence and the competing explanations. They never jump to blame.
Trustworthy sharing. Reports whose redaction keeps pseudonyms consistent, a troubleshooting bundle, and an evidence level printed beside every claim.
What stays. The navy header, the plain-English subtitle, the always-truthful Active/Quiet banner, the 13 tabs and their names, Beginner and Advanced views, and the Light, Dark and High Contrast themes. The tool remains one distributable .py file.
## 2. Source review and factual baseline
The baseline is solid for correctness but hits a hard throughput ceiling: about 480 µs of Python work per packet on one GIL, which caps sustained capture near 2,000 packets per second. I read the whole file, indexed it, ran the tests, and profiled it. Everything below is either measured here or cited to a line number.
### 2.1 Identity of what was inspected
ItemValueHow verified
Fileminiwireshark.py, version string SCRIPT_VERSION = "3.0.0"read
Size18,715 lines, 822,244 bytes, SHA-256 starts 278e8b1ea3683153wc, sha256sum
Structure64 classes, 140 top-level functions, 716 methods, 23 numbered section bannersAST index
Largest classesMiniWireshark 3,458 lines (154 methods), NetworkModel 1,168, SettingsWindow 772, DeviceRegistry 614, PacketsTab 545AST index
Predecessorminiwireshark (4).py, 7,267 lines, the version you uploadedread last session
Runtime assumptionsPython 3.8+ syntax (no walrus or match found), Tk 8.6, scapy 2.4.5+, optional psutilgrep, compiles on 3.11, 3.12 and 3.13
Privileged operationselevation at launch (_relaunch_elevated L245), Npcap installer (_install_npcap L553), raw sockets, ARP/mDNS/SSDP probes (LanScanner L3199)read
Verification status:
Verified: 23 of 23 self-tests pass. The headless GUI test passes for live capture, demo, PCAP import, session load, all themes, the settings window, export, self-healing and shutdown. The real launch path, including dependency setup, was run.
Not verified: Windows, macOS, a real Wi-Fi adapter, Npcap, and a successful download of reference data. The proxy in my test environment refused the downloads.
### 2.2 Measured performance baseline
Measured in this container on Python 3.12.3 with scapy 2.8.0, using 2,000 synthetic frames: a mix of TLS, DNS and QUIC.
StageCost per packetThroughputNotes
Module import + scapy import1.0 s + 1.2 s—once per launch
scapy dissection (Ether(bytes))270 µs3,700 pkt/sruns inside AsyncSniffer's thread (build_sniffer L2996)
decode_packet (L2190 section)126 µs7,900 pkt/sdecode worker thread
NetworkModel.ingest (L6528)82 µs12,200 pkt/sruns on the Tk thread via _drain_decoded (L14780)
Experiment: struct header parse1.2 µs815,000 pkt/sEthernet + IPv4 + TCP header fields only
Memory per kept packet row9.3 KiB—5,000 rows ≈ 48 MB. The allowed maximum of 100,000 rows ≈ 0.96 GB.
Model memory17 MB—at 5,000 active flows and 550 remote hosts
The profiler names the cheapest large win. Inside ingest, ipaddress parsing dominates: the same IP strings are parsed again and again by is_private_ip (L1695), is_public_ip (L1720) and eligible_ip (L4280). That came to 102,000 IPv4Address constructions per 20,000 packets.
All three stages share one interpreter lock (the GIL). A home link running at 100 Mbit/s with 1,000-byte packets carries about 12,500 packets per second. 3.0 would analyse less than a fifth of that and count the rest as dropped.
### 2.3 Capability inventory
AreaWhere in the codeStatus
Elevation, paths, rotating logAppPaths, setup_logging, _relaunch_elevated L245Works. Elevates the whole app, not just the steps that need it.
Dependency bootstrapDEPENDENCY_MANIFEST, run_bootstrap L848, BootstrapStateWorks with attempt limits. Installs into whichever Python runs it, falling back to --break-system-packages (L476). No hash pinning.
Npcap_install_npcap L553, _authenticode_status L540Works with a signature check, but the check accepts any valid signer. Fallback version 1.79 (L523) is stale: Npcap 1.89 shipped 2026-09-12.
Reference dataDataManager, DATA_MANIFESTDownloads the OUI vendor list, Public Suffix List, trackers and ASN data, with SHA-256 checks, atomic replace and backoff. Offline fallback was verified.
Capturebuild_sniffer L2996, _sniff_cb L14617, queues of 20,000 (L2971)Single interface. scapy dissects every packet. Drop counters exist but are app-side only.
Decodingdecode_packet, parse_tls_hello, TlsReassembler, _decode_icmpv6, DNS over UDP and TCP, DHCP, mDNS, SSDP, NBNS, banner sniffingBroad and tested. QUIC site names are never read. No LLDP, CDP or VLAN handling.
Device identityDeviceRecord, DeviceRegistry L4232, classify_device L4131, auto_merge_pass L4719Confidence from evidence, lifecycle states, presence history, merge and split. Keyed by MAC. The IP-to-device map is not scoped by time.
Websites and remote hostsregister_website L7070, RemoteHostRecordSeparated from devices; this rule is enforced and tested.
ConnectionsFlowRecord, FlowTable, _observe_flow L6885Bounded, expires idle flows, counts retransmissions. Has no capture-source dimension.
MetricsTimeSeries, MetricsEngineRolling buckets at three resolutions, peak rates.
AnomaliesAlertEngine (23 kinds), DnsTracker, BaselineEngine, ScanTrackerExplainable alerts with debouncing, muting and per-device baselines.
PersistenceAppConfig with migrations, SessionCodec v2, KnownDevicesStore, HistoryStore L7922History is write-only in practice. Only baselines are read back (L13741). known_device_rows is used only by tests.
GUI13 tabs (DashboardTab … HelpTab), SettingsWindow (15 pages), DetailDialog, DiagnosticsWindow, CrashDialogThemed and tested headless. Treeviews are not virtualised.
ReportsReportBuilder (HTML with inline SVG), CSV, JSON, PCAP exportWorks. Has no redaction.
Updates_check_for_updates, apply_self_update L17671Opt-in. Validates only by compiling the code and matching strings; there is no signature.
Health probesHealthProber L3547Router, Internet (default 1.1.1.1:443) and DNS timing. Paused in Quiet Mode.
Demo and self-testDemoGenerator, run_self_tests23 tests. The GUI harness lives only in my scratch folder, not in the file.
### 2.4 Defects and fragilities found
Throughput ceiling (2.2). The biggest problem; addressed in milestone M2.
Analysis on the GUI thread. _drain_decoded gives ingest 30 ms slices, so a busy network competes with typing and scrolling.
Memory per kept packet. all_rows (L14798) keeps full scapy packet objects, roughly 9.3 KiB each.
Repeated IP parsing (2.2). Fixable with a memoised address classifier.
Linear lookups. key_for_iid (L10037) scans every row on each lookup. AlertEngine uses order.insert(0) (L5652). WebsitesTab.rebuild redraws the whole tree whenever a new domain appears.
No separate evidence store. Device evidence is a summary list. A split restores a snapshot taken at merge time, so traffic recorded after the merge stays with the kept device.
IP ownership has no time. ip_to_key holds only the current owner. Per-device ip_history exists but nothing uses it for attribution.
Time handling. Live mode uses wall-clock time and imports use packet time. Nothing compensates for clock jumps. PCAP times are shown in local time without saying so.
Bootstrap mutates the interpreter it runs in. It needs neither an isolated environment nor a lockfile, and has neither.
Supply chain. The Npcap check accepts any valid signer (L585). Self-update has no signature. Tracker and data downloads are integrity-checked only after download; there are no pinned publisher hashes.
Untrusted text is displayed raw. Hostnames, mDNS TXT records, SSDP SERVER strings and SNI pass into Tk and reports without stripping control or bidirectional characters, so names can be spoofed. HTML reports are escaped.
History has no read side. There is no history view, no "what changed", and no way to compare sessions.
One interface, one network. History mixes networks: a laptop's home and café devices share one baseline and one consent state.
Broad exception catches. 77 except Exception sites, mostly at thread and GUI boundaries. Each needs a review that keeps the necessary ones and narrows the rest.
Licence facts not shown. Npcap's free licence covers up to 5 systems and forbids redistribution. 3.0 downloads it for the user but never shows those terms.
### 2.5 Strengths to preserve
The rule that a device is created only from local evidence, with remote hosts and websites as separate entity types, enforced by tests.
Plain-English, hedged wording everywhere ("Likely", "Possibly", "I cannot determine this").
An always-truthful Active/Quiet banner, plus offline, saved-session and demo banners.
Settings generated from one declarative schema, with a test that every option has a default.
Bounded data structures throughout, self-healing capture with exponential backoff, and Demo Mode that runs through the real pipeline.
## 3. Existing UI inventory and preservation contract
The window you know stays; 4.0 adds a docked inspector, evidence badges and a coverage card, and changes no tab names. I describe the current screens from the source and from the 39 headless screenshots taken last session.
### 3.1 What exists today (3.0)
From top to bottom:
Header in navy #2b3a55: the title "MiniWireshark", the subtitle "Your network, explained in plain English", a global search box with a button, a View selector (Beginner/Advanced), Help / About, and Settings.
Mode banner, always visible: green "ACTIVE SCANNING" or blue "QUIET MODE — PASSIVE ONLY", with a switch button.
Data-source banner, shown only when the data is not live: OFFLINE CAPTURE, SAVED SESSION, or DEMO DATA, with a button to go back to live.
Friendly status banner: transient messages, coloured by kind.
Toolbar: network-card picker, refresh, capture (BPF) filter, Start watching (accent colour), Stop, Clear, Export ▾, Session ▾.
Tabs: Dashboard, Happening, Timeline, Devices, Websites, Connections*, Remote hosts*, Alerts, Map, Health, Security, Packets*, Help. * = Advanced view only.
Status bar: a plain sentence with counts and drop warnings.
Pop-up windows: DetailDialog (device, website, remote host, connection and alert reports), Settings (15-page sidebar with search and a Reset/Cancel/Apply/OK footer), Diagnostics, Crash, Search results, merge chooser, rename and note editors.
Themes: Light, Dark, Light high contrast and Dark high contrast. They work by mapping every hex colour across the widget tree and adding chart tokens. Text size has four steps.
### 3.2 Preservation contract
ElementDecisionWhat changes and why
Navy header, subtitle, View selectorKeepIdentity. Back/forward arrows and a command palette (Ctrl+K) join the search box.
Active/Quiet bannerKeep, non-negotiableGains a third line when integrations are reading data: "Reading: Pi-hole (read-only)".
Data-source bannersKeepAdds "SAMPLED 1:N" when overload sampling is active (section 8).
ToolbarPolishThe card picker shows its sources (several interfaces, files, connectors). The layout wraps below 1,100 px.
DashboardExtendTwo new cards, "What I can see" (coverage) and "Changed since you last looked". Every number links to its evidence.
Happening feedConsolidateBecomes a story stream grouped by device episode, for example "Living Room TV: 14 connections to video.example.net in 2 min". Feed speeds stay.
TimelineExtendBacked by the database and paged so it can hold millions of events. Adds a "Changes since…" mode and day navigation. Comparing two sessions also lives here, rather than in a new tab.
DevicesExtend + replace pop-upsModal DetailDialog becomes a docked Inspector on the right. The table stays. Justification: a modal hides the list and cannot follow a selection across tabs.
Websites, Connections, Remote hostsKeep + extendAn evidence column (O/R/C/I/?) and a "why linked" explanation. Same inspector.
AlertsExtendRenamed in place to "Alerts & Insights". Holds investigation results and a hypothesis board. Severity icons stay.
MapExtendLayers (segment, subnet, Internet), saved positions, edge styles by evidence, a coverage overlay, and an accessible list view.
HealthExtendUptime history, TCP round-trip times, a DNS latency histogram, and this PC's Wi-Fi link quality.
SecurityKeepStill the friendly report, now with a "what I can't see" section from the coverage model.
PacketsReplace the widget onlyThe table is virtualised and reads from a disk ring buffer, because 9.3 KiB per row in memory does not scale (2.2). Columns, filters, presets and bookmarks stay.
HelpExtendA three-step first-run tour and a "Why can't I see X?" helper.
New: Sources (Advanced)IntroduceLists capture interfaces, imports and connectors, with health, freshness and permissions. Justified by the integrations and multi-interface capture.
SettingsExtendNew pages: Sources & Integrations, Networks & Consent, Storage & Retention. The declarative schema stays.
All colours keep going through THEMES and PALETTES; new widgets add tokens, never raw hex. The evidence glyphs are shape plus letter (◉ Observed, ◈ Reported, ◎ Correlated, ◌ Inferred, ? Unknown), so they never depend on colour alone.
## 4. Telemetry truthfulness: the network visibility matrix
From an ordinary PC on a switched or Wi-Fi network, MiniWireshark sees its own traffic in full, other devices' broadcasts and multicasts, and almost none of other devices' unicast. Every feature in this plan is bounded by that fact. The table below is the contract the UI must follow.
### 4.1 What can be established, and from where
Key: Yes = established directly. Part = partial or only for some devices. No = not available. Inf = inferable with stated confidence.
Columns are vantage points:
1 — passive capture on this host's adapter (switched or Wi-Fi).
2 — traffic to and from this host.
3 — broadcast and multicast on the segment.
4 — router, DNS-server or flow logs.
5 — a switch mirror port (SPAN) or an access-point controller export.
6 — an agent installed on the device itself.
7 — an imported capture.
8 — inference.
Claim12345678
A device with MAC M is on this segmentPart—Yes (ARP, DHCP, mDNS, SSDP, ND)Yes (DHCP leases, ARP table)YesYesAs captured—
The device is active right nowPart (only if it broadcasts)—PartYes (fresh lease/ARP/flow)YesYesNo (historic)Inf from silence: never "offline" from silence alone
Its hostname or modelPart—Yes (DHCP, mDNS TXT, SSDP)YesPartYesAs capturedInf (vendor, patterns)
Its OS familyNo—Part (DHCP options, TTL)PartPartYesAs capturedInf, low confidence
Which domains device X looks upNo for other devicesYes for this PCNo (except mDNS/LLMNR)Yes (Pi-hole/AdGuard/router DNS)YesYesAs captured—
Which sites device X connects toNo for other devicesYes (SNI, QUIC Initial, HTTP Host)NoPart (flow logs give IPs, not names)YesYesAs capturedInf (DNS name to IP, ambiguous behind CDNs)
Device X's bandwidthNo for other devicesYes for this PCNoYes (NetFlow, SNMP counters)YesYesAs captured—
The page or URL path on HTTPSNoNoNoNoNoPart (browser agent — out of scope)NoNever claimed
Which program on this PC opened a connectionNoYes (OS socket table)———YesNo—
Which switch port or AP the device usesNoPart (LLDP/CDP gives this PC's port)Part (LLDP frames)Yes (bridge table via SNMP, controller)Yes—As capturedInf, low
Wi-Fi signal and channelNoYes (this PC's adapter via OS API)—Yes (AP export)YesYesNo—
Latency and lossNoYes (TCP handshake RTT, own probes)—PartYesYesYes (RTT from handshakes)Inf (retransmissions)
Country or provider of a remote host———————Inf from an offline database; may be wrong
Someone is "watching a film"NoNoNoNoNoNoNoNever claimed. At most "long, steady, large download (streaming-like pattern)".
### 4.2 Things that change the answer
ConditionEffect on what MiniWireshark can claimWhat the UI says
Switched Ethernet or Wi-Fi without SPANOther devices' unicast is invisibleCoverage card: "Seeing this PC + broadcasts"
Wi-Fi client isolation, guest network, VLANsEven broadcasts from other segments are invisibleDevice count is a lower bound: "at least N"
VPN on this PCDestinations collapse into one tunnel endpoint"Most traffic goes through a VPN tunnel to X"; the VPN server is never shown as a website
NAT on the routerIntegrations see inside addresses; captures outside see one addressEach address is tagged with its source
DoH / DoTLookups unreadable; names come only from SNI/QUIC"Lookups from this device are encrypted" plus the share of its traffic that is unnamed
TLS ECHSNI shows only the outer CDN nameShown as "via Cloudflare (real site hidden by ECH)", never as the CDN being the site
QUICThe site name is readable from the Initial packet unless ECH is usedLabelled "QUIC Initial (public keys)", not "decrypted"
CDNs and shared IPsOne IP serves thousands of domainsThe domain link from DNS timing says "one of N names"
IPv6 privacy addressesOne device uses many temporary addressesLinked through ND, the MAC and timing; never through reverse DNS
Randomised MACsOne device appears as several identities"Possibly the same device"; merging needs strong evidence
ProxiesEvery flow goes to the proxyCONNECT host is shown when it is plain; otherwise unknown
Packet loss at captureCounts are minimumsTotals shown as "≥" when drops occurred in that window
### 4.3 Truthfulness contract
Every displayed claim is one of these five levels. A test checks that every claim-producing function returns a level.
Observed (◉) cites at least one stored observation: its packet number or byte offset, capture source and time.
Reported (◈) cites an integration record: source, its timestamp and how stale it is. It is never upgraded to Observed.
Correlated (◎) names the two or more observations it links and the rule used (for example "DNS answer for X then a TCP SYN to its IP within 5 s from the same device").
Inferred (◌) carries a confidence word, a 0–1 score, the reasons, and at least one alternative explanation.
Unknown (?) is shown as unknown. Absence of packets produces "not observed from here", never "inactive", unless the coverage model says this vantage point would have seen the activity.
Hard rules that become test cases:
A reverse-DNS name alone never names or merges a device.
A DNS query is a lookup, not a visit. Visit wording requires a correlated connection.
Remote hosts are never devices.
A topology edge from gateway inference is drawn dashed and labelled "logical". A solid edge requires LLDP or switch-table evidence.
Address bindings are time-scoped. A later owner of an IP never inherits an earlier owner's history.
Reported and Observed data that disagree are both shown, with the gap explained (for example "router counts 4.1 GB, this PC observed 0.3 GB because it can only see its own traffic").
## 5. Original invention catalog
The catalog holds 150 ideas in 22 domains. The tribunal at the end kills 9 proposals (one from the catalog, eight that were floated and rejected) and redesigns 11. Of what survives, 29 are P0 and 68 are P1; section 16 ranks the leaders. Effort runs from S (about a day) through M (under a week) and L (one to three weeks) to XL (more). Load is the runtime cost. Priority runs from P0 (foundation or correctness) to P3 (long horizon).
### D1 Capture engine and provenance
#IdeaUser valueEvidence and limitsEffortLoadPri
1Raw-bytes capture loop: recv_raw or a libpcap handle with no per-packet scapy dissection10x more traffic analysed before anything is droppedMeasured at 270 µs for scapy vs 1.2 µs for struct. Same Npcap or libpcap underneath.MLowers itP0
2Selective deep parse: scapy only for DNS, DHCP, TLS ClientHello, mDNS, SSDP, ND and the packet-detail paneKeeps the rich decoding without paying for it on bulk trafficAbout 5–15% of packets on a typical home link need it (to be measured in M2)MLowers itP0
3Driver drop counters (pcap_stats ps_drop/ps_ifdrop) shown next to the app's own drop stagesHonest "≥" totals; tells the user where loss happensNot every backend reports them; shown as unknown when absentSLowP0
4Capture-source registry: every observation carries a source ID (interface, file, demo, connector)Foundation for multiple interfaces, connectors and deduplication—MLowP0
5Multi-interface capture (Wi-Fi + Ethernet + VPN) with flow deduplicationLaptops docked on Ethernet with Wi-Fi still up; seeing inside and outside a VPN tunnelThe same packet can appear on two interfaces; deduplicate by 5-tuple, sequence number and timeLMediumP2
6PCAPNG export with interface blocks and per-packet comments carrying bookmarks and notesHand-offs to Wireshark keep your annotationsscapy has written pcapng since 2.5SLowP1
7On-disk packet ring: rotating, size-capped pcapng segments plus a time index"Show me the packets" for any event, hours later, without RAM growthRaw packets are sensitive: off by default, capped, cleared with historyMDiskP1
8Windows pktmon fallback when Npcap is missing: capture to ETL, convert with pktmon etl2pcap, importSome visibility with nothing installedBatch snapshots, not live. Windows 10, 11 and Server 2016+.MLowP2
9802.1Q VLAN tag awarenessCorrect segments on trunked SPAN portsTags are usually stripped before reaching a PCSLowP2
10Timestamp sanity: monotonic session clock, clock-jump detection, a time zone label on imported filesTimelines that don't lie after sleep or when reading foreign files—SLowP1
### D2 Coverage and vantage
#IdeaUser valueEvidence and limitsEffortLoadPri
11Coverage model per device and questionEnds the "not seen = not happening" confusionDerived from the source registry and vantage testsMLowP0
12Vantage test: the ratio of unicast frames not addressed to this PC tells whether we are on a mirror port, a hub or a normal switchSays automatically whether others' traffic is visiblePassive. Needs a few minutes of traffic.SLowP1
13Coverage overlay on Map and Devices (full / partial / broadcast-only / reported-only)Visible limits—SLowP1
14Presence states that include "not observable"Correct wording for quiet phones behind client isolation—SLowP0
15Dashboard "What I can see" card with "how to see more" steps (SPAN, Pi-hole, router)Turns a limitation into a next step—SLowP1
16Blind-spot meter: the share of this PC's traffic whose destination is unnamed (DoH, ECH, VPN, bare IP)Quantifies privacy technology at workMeasured on this PC's own flows onlySLowP1
### D3 Identity resolution
#IdeaUser valueEvidence and limitsEffortLoadPri
17Identity graph: Device ↔ Interface (MAC) ↔ AddressBinding, each binding with a start and end timeCorrect histories across DHCP churnFoundationLLowP0
18Time-scoped IP ownership used for every attributionIP reuse never merges historiesLeases, ARP and ND timesMLowP0
19Rotation linker for randomised MACs: DHCP client-id (option 61), option-55 order, hostname, mDNS name, timingFewer duplicate phonesProposes "possibly the same"; auto-merges only under the existing strict rulesMLowP1
20Built-in DHCP fingerprint table (option-55 order to OS family)Better device classesSmall curated table; low confidence by designSLowP2
21Merge and split through an operations journal, with undo and redo and no evidence lossSafe correctionsReplaces the snapshot-based splitMLowP0
22Multi-adapter devices (laptop Wi-Fi + Ethernet) linked by hostname and timingOne laptop instead of twoProposal only; never automaticMLowP2
23Evidence age decay: a half-life per evidence typeConfidence that reflects staleness—SLowP1
24User groups (Family, IoT, Work) and ownersFiltering and reports by groupUser data onlySLowP1
### D4 Lifecycle and presence
#IdeaUser valueEvidence and limitsEffortLoadPri
25Adaptive presence thresholds from each device's learned beacon intervalFewer false "offline" for sleepy IoTUses baseline historyMLowP1
26Presence heatmap (hour × weekday)Spot odd hoursHistory; opt-in for other people's devicesSLowP2
27Responsiveness check (single ARP probe) before declaring offlineDistinguishes asleep from goneActive, so Active mode only, rate-limitedSLowP2
28"Last proof of life" with the evidence type and timeHonest freshness—SLowP0
29Always-on expectations: "camera should never be offline more than 1 h"Useful home monitoringThe user sets it; respects coverageSLowP1
### D5 Topology and map
#IdeaUser valueEvidence and limitsEffortLoadPri
30Layered map: L2 segment, L3 subnet, Internet, servicesReal structure instead of a decorative ring—MMediumP1
31Saved node positionsA map that doesn't jump around—SLowP1
32Edge styles by evidence (solid observed, dashed logical, dotted reported)Honest topology—SLowP0
33LLDP and CDP parsing: the switch name and port this PC is plugged intoReal physical facts on wired networksOnly when switches send them; usually not on Wi-FiSLowP1
34Router card from its UPnP description (opt-in fetch)Model and firmware hintsOne HTTP GET to the router; Active modeSLowP2
35Map time-slider from historySee yesterday's networkHistory storeMMediumP2
36Large-network level of detail: cluster by class or subnet, expand on clickUsable at 300+ devices—MLowers itP2
37Path view: opt-in traceroute to a selected remote hostWhere the delay isActive, rate-limited, ICMP or UDPMLowP2
### D6 Destinations, domains and services
#IdeaUser valueEvidence and limitsEffortLoadPri
38Lookup→connection correlation: "looked up and connected" vs "looked up only"Stops treating DNS as visitsSame device, answer IP, SYN within a windowMLowP0
39CNAME chains kept (www.x → x.cdn.net)Shows the CDN behind a namePresent in DNS answersSLowP1
40Shared-IP ambiguity marker ("one of N names")Honest website linksPartly existsSLowP0
41Service catalog: domains grouped into services (video service, OS updates) from a signed data packBeginner-friendly meaningMapping errors possible, so shown as "Likely"MLowP1
42Third-party grouping from co-occurrence after a primary lookup"This page pulled 30 helper domains"Inferred; heuristicMLowP2
43TLS 1.2 certificate subject and issuer (sent in clear in 1.2)Identifies servers without SNITLS 1.3 encrypts certificatesMLowP2
44QUIC Initial SNI: derive the public Initial keys from the connection ID and read the ClientHelloNames most HTTP/3 traffic, which 3.0 leaves anonymousRFC 9001 keys are public; ECH still hides. Needs cryptography.MMediumP1
45DoH/DoT endpoint list as a data packBetter encrypted-DNS detection—SLowP1
### D7 Behaviour understanding
#IdeaUser valueEvidence and limitsEffortLoadPri
46Periodicity detector (inter-arrival histogram per device and destination)Spots beacons, polling and IoT heartbeatsNeeds repeated observationsMMediumP1
47Evidence-linked activity narratives from templatesReadable summaries that cannot inventTemplate slots filled only from claimsMLowP1
48Flow-shape labels: bulk, interactive, streaming-like, call-like"Pattern looks like", never contentByte ratio, duration, packet-size histogramMLowP2
49Idle-to-active transition events"TV woke up at 02:14"—SLowP1
50Peer-to-peer detector (many peers, high UDP ports)Explains odd uploadInferredSLowP2
51Discovery-storm characterisation (who floods mDNS/SSDP)Diagnoses chatty gadgetsBroadcasts are visibleSLowP2
52Daily "newest busy destination"Novelty at a glance—SLowP2
### D8 Performance diagnostics
#IdeaUser valueEvidence and limitsEffortLoadPri
53TCP handshake RTT (SYN → SYN-ACK) per remote hostPassive latency without probesThis PC's flows, plus any visible onesMLowP1
54DNS latency histogram per resolverSpots slow DNSExists as a medianSLowP1
55Retransmission, duplicate-ACK and zero-window counts per flowExplains stallsApproximateMLowP1
56Goodput per flow with a capture-loss annotationHonest throughput—SLowP1
57Opt-in latency-under-load testBufferbloat checkActive; generates loadMHigh (brief)P3
58This PC's Wi-Fi link: RSSI, rate, channel (netsh wlan show interfaces, iw, CoreWLAN)The most common cause of "slow"Read-only OS queryMLowP1
59Router and Internet uptime percentage from the health historyProof for the ISPExists as pointsSLowP1
60MTU and fragmentation detectorRare VPN issuesICMP "too big" messagesSLowP3
### D9 Timeline and forensic navigation
#IdeaUser valueEvidence and limitsEffortLoadPri
61Database-backed paged timeline (millions of events)No GUI freeze, long historySQLite index on timeLLowP1
62Bookmarks and annotations on events and packetsInvestigation notesExported as pcapng commentsSLowP1
63Compare two sessions or days"What's different from last week?"Needs stable IDsMMediumP1
64"What changed since…" digest (new devices, names, services, DNS servers, gateway MAC, IPv6 prefix)The 10-second daily checkHistory + network fingerprintMLowP0
65State snapshot at time TReconstruct an incidentRollup tablesMMediumP2
66Replay from the packet ring at chosen speedRe-analyse with new rulesSame pipelineMMediumP2
67Episode clustering: events within N seconds grouped under a likely cause"Router rebooted → 9 devices reconnected"InferredMLowP2
### D10 Search, filters and workflows
#IdeaUser valueEvidence and limitsEffortLoadPri
68One query language compiled to SQL (history) and to in-memory predicates (live)Same filter everywhereExtends DisplayFilterLLowP1
69Zero-result diagnosis ("capture filter excludes UDP")No silent empty screens—SLowP1
70Plain-English filter explanationLearnabilityPartly existsSLowP2
71Cross-highlighting: select a device and it is highlighted in every tabFaster investigation—MLowP1
72Saved views (filter + columns + tab)Repeatable checksExtends presetsSLowP2
73Command palette (Ctrl+K): jump to any device, site, tab or settingSpeed for power users—MLowP1
### D11 Insight engine and explainable inference
#IdeaUser valueEvidence and limitsEffortLoadPri
74Formal Insight object: evidence links, trigger, confidence, time span, alternatives, false-positive notes, freshnessEvery alert can be auditedGeneralises AlertMLowP0
75Guided investigation "Why is my Internet slow?"Diagnosis for beginnersCombines health, Wi-Fi link, top talkers on this PC, DNS and resetsLLowP1
76Bandwidth-mystery walkthrough (Challenge 6)Avoids blaming the wrong device or siteCoverage-aware; may conclude "can't tell from here"MLowP1
77Feedback loop: "this was expected" adjusts that device's thresholdsFewer false positives over timeBounded so it cannot silence everythingMLowP1
78Alert calibration page (share marked expected per alert type)Tunes noisy detectorsLocal onlySLowP2
79Template Q&A over the evidence store ("What did the TV contact yesterday?")Natural questions, grounded answersNo LLM; parsed patterns compiled into queriesMLowP2
80Data-quality auditor: stale enrichment, clock skew, drop rate, stale connectors → lower confidenceCalibrated under bad data (Challenge 8)—MLowP1
### D12 Security and anomaly awareness
#IdeaUser valueEvidence and limitsEffortLoadPri
81Rogue IPv6 router advertisement (RA from a MAC that isn't the router)Catches a real, common misconfigurationRAs are multicast, so visibleSLowP0
82DNS answer consistency check: compare a canary lookup across resolversHijacked DNS hintActive, opt-in, 2 queriesSLowP2
83New listening service on this PC (OS socket table)Notice unexpected open portspsutil, local onlySLowP1
84Router port-forward audit: ask the router (UPnP IGD) which ports it opened to the InternetFinds exposed servicesActive, opt-in, read-only SOAP queryMLowP1
85This PC's ARP cache vs observed claims (a poisoning cross-check)A stronger ARP-spoof signalReads the OS ARP tableSLowP1
86Inventory of cleartext protocols per deviceA to-do list for securing gadgetsExists as alertsSLowP2
87Opt-in threat feeds (abuse.ch) as signed data packs, labelled "listed by X"Context, not a verdictLicence to be checked; false positivesMLowP2
88Unauthorised-network guard: active features refuse subnets you haven't consented toSafetyPer network fingerprintSLowP0
### D13 Infrastructure and endpoint integrations
#IdeaUser valueEvidence and limitsEffortLoadPri
89Pi-hole v6 API, read-only: per-client DNS logs for the whole LANOther devices' lookups become ReportedSession ID from POST /api/auth; app password supportedMLowP1
90AdGuard Home query log APISame, for AdGuard usersBasic auth; API varies by versionMLowP1
91OpenWrt rpcd/ubus: DHCP leases and Wi-Fi associated stationsReported presence for every clientNeeds an ACL-limited rpcd user (to verify)MLowP2
92SNMP v2c/v3 read-only: ARP table, bridge table, interface counters, LLDP neighboursReal topology and per-port bandwidthNeeds pysnmp (maintenance to verify)LLowP2
93NetFlow v5/v9 and IPFIX collectorPer-device bandwidth from routers that export flowsUDP listener; custom parser; dedupe against captureLMediumP2
94Syslog receiver for dnsmasq DHCP logsLeases from cheap routersFormat variesMLowP3
95UniFi and Omada controller APIsWi-Fi client inventoryVendor API churnLLowP3
96Home Assistant device import (names, rooms)Friendly namesToken; read-onlyMLowP3
97This PC's connection owners (process name per socket)"Which program is using my bandwidth" on this PCpsutil; some processes need adminMLowP1
### D14 GUI visual system
#IdeaUser valueEvidence and limitsEffortLoadPri
98Docked inspector pane shared by every tabContext kept while drilling downReplaces modal pop-upsLLowP1
99Evidence badges (◉ ◈ ◎ ◌ ?) on every claimCredibility at a glance—SLowP0
100Virtualised tables (only visible rows exist as widgets)Smooth with 1M rowsCustom on top of TreeviewMLowers itP1
101Traffic sparklines in device rowsPattern at a glanceCanvas cellSLowP2
102Back/forward history with breadcrumbsNever lost while investigating—SLowP1
103First-run 3-step tourFaster onboarding—SLowP2
104Saved layout: column widths, sort, last tab, pane sizesFeels like your tool—SLowP1
105Density toggle (comfortable / compact)Power users fit more—SLowP2
### D15 Autonomy and setup
#IdeaUser valueEvidence and limitsEffortLoadPri
106Three-layer bootstrap with a private, pinned Python 3.14 runtimeModern stack on any starting PythonSection 12L—P0
107Lockfile with SHA-256 hashes (pip --require-hashes)Reproducible, tamper-evident installsGenerated at release timeM—P0
108Setup doctor (dry run): what would be installed and whyTrust, troubleshooting—S—P1
109Guided Npcap install: show its licence, check the signer is "Nmap Software LLC", track the current versionSafer driver setupThe free edition's installer is interactiveS—P0
110Offline install kit: export runtime + wheels to a folderAir-gapped machines—M—P3
111Repair mode: rebuild the environment from the lockfileOne-click fix—S—P1
112Signed release manifest and update channels (stable/beta)Safe self-updateEd25519M—P2
### D16 Resilience and data integrity
#IdeaUser valueEvidence and limitsEffortLoadPri
113SQLite in WAL mode, journaled migrations, quick_check at start, auto-restore from the nightly backupData survives crashesStandard libraryMLowP0
114Safe mode after two failed starts (no capture, no connectors)Never locked out—S—P1
115Heartbeat watchdog per pipeline stageDetects a hung thread, not just a dead one—SLowP1
116Redacted diagnostics bundle (zip of logs, config, perf counters)Easy help requestsRedaction engineM—P1
117Disk guard: tightens retention when free space drops below a thresholdNo disk-full crashes—SLowP1
118Periodic crash-consistent autosave (not only on exit)No lost sessions—SLowP1
### D17 Scale and performance
#IdeaUser valueEvidence and limitsEffortLoadPri
119Memoised address classifier (an LRU of IP → class)Removes the measured top hotspotProfile in 2.2SLowers itP0
120Analysis worker thread publishing deltas to the GUIThe GUI never competes with packets—LLowers itP0
121Optional process-based parsing for more than 20k packets/sGets past the GILProcess pipe overhead; experimentalLMediumP3
122Database rollups (minute / hour / day)Fast long-range charts—MLowP1
123Overload sampling, labelled "sampled 1:N"Graceful degradationCounts scaled and labelled as estimatesMLowers itP2
124Performance HUD in Diagnostics (queue depths, µs per stage, drops per stage)Self-diagnosing—SLowP1
### D18 Data model and storage
#IdeaUser valueEvidence and limitsEffortLoadPri
125Observations separated from claims in storageThe truth contract becomes enforceableSection 9LLowP0
126Stable entity IDs (ULID-style, time-ordered)Comparison, links and exports—SLowP0
127Versioned export schema with provenance fieldsMachine-readable reports—M—P2
128Encryption at restProtects history on shared PCsNo stdlib cipher; needs cryptography and key handlingLLowP3
129Retention per data class (packets 1 d, flows 30 d, summaries 1 y)Predictable disk use—SLowP1
### D19 Reporting and reproducibility
#IdeaUser valueEvidence and limitsEffortLoadPri
130Redaction engine with consistent pseudonyms (Device-A, 10.x.x.7)Safe sharing—M—P1
131Printable inventory reportPaperwork, insurance, IT hand-off—S—P1
132Weekly digest reportLong-term awareness—S—P2
133Troubleshooting bundle for a helperRemote helpRedactedS—P1
134Evidence level printed beside every report claimHonest reports—S—P1
### D20 Extensibility and maintenance
#IdeaUser valueEvidence and limitsEffortLoadPri
135Internal registries with typed contracts: parsers, detectors, connectors, exportersAdd features without rewritesSection 8M—P0
136Signed JSON data packs (service catalog, DoH list, fingerprints, OUI overrides)Update knowledge without codeData only; never executedM—P1
137Connector base class with a conformance testSafe integrationsNo third-party code executionS—P2
138In-file headless GUI test runner (--gui-test)Catches GUI regressionsNeeds a display or XvfbM—P1
139Golden replay corpus generated by the self-testRegression proof for analysisSynthetic pcapsM—P0
### D21 Accessibility and localisation
#IdeaUser valueEvidence and limitsEffortLoadPri
140French localisation (string catalog exists via tr())Canadian householdsTranslation quality review neededM—P2
141Screen-reader-friendly list alternative to the canvas mapAccessibilityCanvas can't expose structureS—P1
142Keyboard-only audit and visible focus ringsAccessibility—S—P1
143High-DPI detection with tk scalingCrisp UI on 4K—S—P1
144Colour-independent status everywhere (shape + word)Colour-blind safetyMostly doneS—P0
### D22 Speculative
#IdeaUser valueEvidence and limitsEffortLoadPri
145"What would break if…" dependency view from observed service usagePlanning changesInferred; small scope onlyLLowP3
146Causal timeline (root-cause chains)Faster incident understandingBuilds on 67LLowP2
147Fingerprint confidence calibration from user-confirmed device classesAccuracy improves locallyLocal onlyMLowP3
148Privacy exposure score per device (cleartext, trackers, plain DNS)Actionable hygieneInformationalSLowP2
149Household routine learning—Rejected by the tribunal———
150Device biography across sessionsA device's life storyHistory + identity graphMLowP2
### 5.1 Feasibility tribunal verdicts
Killed (do not build):
#149 Household routine learning. It profiles the people who live with the user, often without their knowledge. The privacy reviewer vetoed it.
Credential exposure checks (trying default passwords on devices). That is an attack, whatever the intent.
TLS interception or MITM to see pages. Excluded by the product rules.
ARP poisoning to see other devices' traffic. It is an attack, and it breaks networks.
A cloud LLM that reads captured data. Uploading data is out of bounds, and an LLM adds no visibility. Template Q&A (#79) covers the need.
A live world map with "flying" connection lines. Pure decoration; country data is inferred and often wrong.
An animated packet-by-packet map. Costly and unreadable.
A full IDS with signature rule sets. It needs visibility and rule maintenance this tool can't promise.
"Websites visited" pop-up notifications. DNS is not a visit; it would generate noise and false certainty.
Redesigned to match what can actually be seen:
#8 pktmon became batch snapshots: it cannot stream live.
#44 QUIC labels the name as "read from the Initial packet (public keys)" and checks for ECH.
#48 flow-shape labels say "pattern looks like", never what was watched.
#76 is allowed to conclude "can't tell from this vantage point".
#84 and #34 are opt-in Active-mode actions with a fixed request.
#89–93 produce Reported, never Observed.
#93 deduplicates against capture.
#25 never drops below its configured minimum.
#121 stays experimental behind a measured need.
#128 waits until key handling is solved.
#27 sends one ARP probe at most per device per 10 minutes.
## 6. Feature clusters and transformative experiences
The catalog becomes six experiences a person actually goes through. Each needs the same three foundations: the fast pipeline, the evidence store and the identity graph.
### 6.1 The six experiencesExperience | What the user does | Ideas combined | Done looks like | 
A. The 60-second check | Opens the app and glances at the Dashboard | 11, 15, 16, 28, 64, 99 | Three cards answer: what's here, what changed, what I can't see. Each number opens its evidence. | 
B. Who is this? | Clicks an unfamiliar device | 17–24, 28, 41, 98, 150 | The inspector shows the identity story: names over time, address bindings, evidence with ages, class with reasons, "possibly the same as…", one-click merge or split. | 
C. Why is it slow? | Starts the guided investigation | 53–59, 75, 76, 97, 80 | A ranked hypothesis board, from Wi-Fi link to DNS to the router to ISP to a heavy local process, each with evidence for and against, plus a printable result. | 
D. What changed? | Opens Timeline → Changes since… | 61–67, 63, 64, 146 | A digest of new devices, renamed devices, new services, new DNS servers, a changed gateway MAC, a new IPv6 prefix, alerts. Each entry opens the moment it happened. | 
E. See more, honestly | Opens Sources and adds Pi-hole, LLDP or a mirror port | 4, 5, 11–13, 33, 89–93 | The coverage card's numbers go up; new claims carry the Reported badge; connector freshness is shown. | 
F. Share safely | Exports a report or a help bundle | 116, 130–134 | A redaction preview with consistent pseudonyms and evidence levels in the output. | 
### 6.2 Creativity challenges, with what each changed
Tenfold usefulness. Comprehension speed comes from "what changed" and episodes, not from more packets. So 64 and 67 move up.
Tenfold credibility. Five 3.0 views could look confident while wrong: "offline" from silence, website "visits" from DNS, single-name links behind CDNs, the topology ring, and bandwidth totals during drops. Each now gets an evidence badge, a coverage state or a "≥".
Tenfold scalability. At 10x events, the first things to break are scapy dissection, Tk-thread analysis, and per-packet scapy objects kept in memory. Hence M2 and the disk packet ring.
Tenfold autonomy. The preventable failures on a fresh PC are: no compatible Python, no Tk, pip blocked by an externally-managed environment, a stale Npcap URL, and needing admin rights to run at all. All five are designed out in section 12. On Windows, Npcap's default install even allows capture without admin rights.
Tenfold originality. "Proof chips": every number and name is clickable down to the packets. No consumer network tool I know of does this end to end.
Explain a mystery. The bandwidth walkthrough must allow "not visible from here". If the router reports 4 GB and this PC sees 0.3 GB, the answer is another device, and the tool says so.
Change over time. Snapshots mislead. The answer is per-network histories, decaying confidence, and a digest built from stable IDs.
Bad data. Every claim carries freshness. Connectors show their age, drops turn counts into "≥", and stale enrichment is flagged by the data-quality auditor (80).
Hidden cost. Five "small" features need big foundations: domain history per device, comparing sessions, merge undo, multi-interface counts and "what changed". The foundations are provenance, stable IDs, time-scoped bindings, source-aware flows and network fingerprints. They go first.
Ruthless simplification. Killed: the flying-lines globe, per-packet animations, an LLM chat, and website pop-ups. Moved to Advanced: the query language, multi-interface capture, SNMP and NetFlow.
### 6.3 New ideas that came from the challenges
None of these is in the first catalog.
Proof chips. Every number and name in the UI is clickable, opening the query that produced it.
Uncertainty footer. Each view's footer shows what share of its rows are Observed, Reported, Correlated or Inferred.
Loss-aware ranges. Byte counts become "≥ 12 MB (some packets were not captured)" whenever drops overlap the window.
"Why can't I see…?" helper. Name a device or site and get the coverage reasons, such as client isolation, a different VLAN or DoH.
Network fingerprints. The current network is identified from router MAC, subnet and SSID. History, baselines and consent are kept per network, and "You are on Café Wi-Fi (seen 3 times)" is shown.
Per-network consent for active features. Remembered per fingerprint. A new network starts in Quiet Mode until you approve it.
Episodes. Bursts of related events grouped under one headline with a likely cause.
Connector freshness decay. Reported claims fade to "stale" after a configurable age, and the banner shows the last good read.
Self-traffic ledger. Everything MiniWireshark itself sends (probes, lookups, downloads) is logged in one list, labelled in Connections, and can be exported.
Observed-vs-reported reconciliation view. The router's numbers beside the capture's numbers, with the gap explained.
Heard-not-seen devices. Devices known only from broadcasts are labelled as such, with a different glyph.
Map time-lapse. A day of presence played as a 20-second animation, built from history and not from live packets.
Outbound kill switch. One click stops everything the app sends: probes, lookups, update checks and connector polls.
Redaction preview. Shown side by side before any export.
Retention budget forecast. Settings shows the estimated disk use per week for the chosen retention.
Hypothesis board. Investigations list competing explanations, each with evidence for and against, ranked.
## 7. Three alternative futures
The chosen strategy is A, "Truthful core first". It fixes the measured bottlenecks and builds the evidence foundations in place. It then adds B's two cheapest coverage connectors and defers C's multi-process engine until a benchmark proves it is needed.
### 7.1 The options
A — Truthful core first (evolution). Keep 3.0's classes and GUI. Replace the capture and analysis pipeline under them, add the SQLite evidence store and the identity graph, the managed runtime, coverage and history. Integrations come late.
B — Telemetry-rich platform. Lead with connectors (Pi-hole, AdGuard, OpenWrt, SNMP, NetFlow) so other devices' activity becomes visible, and grow the UI around Reported data. Pipeline and storage upgrades happen as needed.
C — Observability suite. Re-architect as a multi-process engine: capture process, analysis process and storage service, a full query language, plug-in style registries, perhaps a local web UI later. All still shipped from one .py.
### 7.2 Comparison
Criterion | A: Truthful core | B: Telemetry platform | C: Suite | 
User value in the first 3 milestones | High: speed, stability, honest badges, "what changed" | High only for users who run Pi-hole or OpenWrt | Low: mostly invisible plumbing | 
Fixes the measured ceiling (2.2) | Yes, M2 | No | Yes, at more cost | 
Architectural change | Moderate: new pipeline + store; GUI reused | Low at first, then heavy on schema rework | Very high | 
Risk of stranding 3.0 features | Low (vertical slices, tests stay green) | Medium | High (big-bang) | 
Install complexity | +managed runtime | +credentials, +per-vendor quirks | +multiprocessing on 3 OSes, +IPC | 
Feature ceiling | High (B and C pieces can be added) | Bounded by vendor APIs | Highest | 
Single-file maintainability | Good with section registries | Good | Strained: process boot code duplicated, harder debugging | 
Migration cost for users | Session v2 → v3 migration, config v2 → v3 | Small | Large | 
Time to first demo | 2 milestones | 2 milestones | 5+ milestones | 
### 7.3 Decision and borrowings
A wins. It is the only option that fixes the proven bottleneck early, keeps every 3.0 feature working at each step, and builds the provenance that B and C both secretly need. Without provenance, B's Reported data would be mixed into Observed data, and C's queries would have nothing trustworthy to query.
Borrowed from B: the connector framework plus Pi-hole v6 and AdGuard Home, read-only (M10). These two need one HTTPS API each and expand coverage the most for households.
Borrowed from C: the query language compiled to SQL (M7). Also the process-parser experiment (#121), behind a benchmark gate: built only if the threaded pipeline misses 15,000 packets per second on a mid-range laptop.
Decision rule for conflicts: correctness and truthfulness beat capture stability, which beats autonomy, which beats feature count. This keeps 3.0's priority order and adds truthfulness at the top.
## 8. Selected architecture
MiniWireshark 4 becomes a one-way pipeline: capture threads hand over raw bytes, one analysis worker turns them into claims with provenance, and the Tk thread only draws what it is sent. The 3.0 classes NetworkModel, DeviceRegistry, AlertEngine and the tabs survive; what changes is who calls them and on which thread.
Data only moves down; the GUI never calls into the analysis worker except through a small command queue.
### 8.1 Components inside the single file
The file keeps its numbered banners, now treated as internal modules with a stated public surface. Each module lists its exports at the top of its section, and a self-test checks that no section reaches into another's private names (_name).
Module | Responsibility | Public surface | Thread | 
L1 bootstrap | Parse on Python 3.8+, find or provision the managed runtime, hand over | main_bootstrap() | launcher | 
L2 runtime | Lockfile, venv, Npcap, repair, rollback | RuntimeManager | launcher / repair worker | 
sources | Live interfaces, PCAP import, demo, pktmon snapshots | CaptureSource base: start(), stop(), stats() | one per source | 
ring | Bounded raw frame ring | RawRing.put(), .drain(n) | lock-free deque, any | 
parse | struct fast path + selective deep parse | fast_parse(frame) -> PacketMeta | analysis | 
model | 3.0 NetworkModel and friends, now fed PacketMeta | ingest(meta), tick(now) | analysis | 
claims | Wraps every conclusion with level, confidence and evidence refs | Claim, ClaimBuilder | analysis | 
store | SQLite WAL, migrations, retention, packet ring on disk | Store.write_batch(), read-only Query | writer + readers | 
connectors | Pi-hole, AdGuard, later OpenWrt/SNMP/NetFlow | Connector base: poll() -> [Record], health() | one poll thread each | 
enrich | DataManager, reverse DNS, ASN, GeoIP | async results onto the analysis inbox | own threads | 
insights | Alerts, investigations, episodes, data-quality audit | Detector registry | analysis | 
publish | Coalesced UI deltas | UiDelta queue | analysis → Tk | 
gui | Tabs, inspector, settings, dialogs | reads deltas, sends Commands | Tk only | 
supervisor | Heartbeats, self-heal, safe mode | Supervisor.check() | Tk timer | 
### 8.2 Thread ownership and rules
Only the Tk thread touches widgets. Background threads post callables or deltas (3.0 already does this with _async_results).
Only the analysis worker mutates the model. The GUI reads immutable snapshots: copies of rows built on the worker and attached to deltas. Commands from the GUI (merge, rename, acknowledge) go through a Command queue and are applied by the worker, which publishes the result.
Only the store writer writes SQLite. Readers open separate read-only connections. WAL mode lets them read while the writer writes.
Capture threads never parse. They append (timestamp, source_id, bytes) and return. Socket receive happens in C and releases the GIL, so capture is not starved by analysis.
Nothing blocks the Tk thread for more than 16 ms. Queries run on a reader thread and their results come back as deltas. The 3.0 time-boxed drain stays as a safety net during migration.
### 8.3 Backpressure and graceful degradation
When the worker falls behind, cheaper losses come first. Every step is counted and shown.
Coalesce UI deltas. Under load, publish every 1 s instead of every 0.25 s. Invisible tabs get nothing.
Skip deep parse of bulk payloads. TLS application data and QUIC short headers already skip it. Under pressure, repeated DNS answers to the same name within 1 s are skipped too.
Sample flow analytics 1:N for already-known flows. Byte counters stay exact, because they come from the fast path. The banner says "SAMPLED 1:N".
Drop at the ring. Only when the ring is full. Counted per source, and totals in that window become "≥".
Capture itself is never paused, matching 3.0's "capture stability before analysis" rule.
### 8.4 State machines
Capture source: idle → starting → running ⇄ degraded (drops > 1%) → healing (backoff 1, 2, 4 … 60 s) → running | failed, plus stopped. This keeps 3.0's 12-attempt limit and restarts on wake from sleep, adapter loss or gateway change.
Connector: unconfigured → testing → ok ⇄ stale (no fresh data within 3 poll intervals) → error (backoff) → disabled. Reported claims from it fade with freshness.
Device presence: active → idle → offline → expired, plus a new not observable state when coverage says we couldn't see it either way. The thresholds adapt per device (#25), never below the configured minimum.
Data mode (unchanged from 3.0): idle | live | offline | session | demo. Starting live capture always creates a fresh live model.
### 8.5 Failure handling
Failure | Detection | Response | 
Capture thread dies or hangs | Heartbeat older than 5 s, or exception | Self-heal path from 3.0 with backoff; Timeline entry | 
Analysis worker exception on one packet | try around the per-packet step | Count, log the first 20 with packet number, continue; never stop capture | 
Analysis worker dies | Heartbeat | Restart worker from the last published snapshot; banner warning | 
SQLite locked or corrupt | Error code, quick_check | Writer retries with backoff. If corrupt: rename aside, restore last nightly backup, keep running in memory, banner. | 
Disk nearly full | Free space below 1 GB or 5% | Tighten retention, stop the packet ring first, warn | 
Connector errors | HTTP or auth errors | Backoff, stale badge, never retries credentials in a loop | 
GUI exception | report_callback_exception (exists) | Crash dialog, autosave (exists) | 
Two crashes within 2 min of start | Crash marker counter | Next launch in safe mode: no capture, no connectors, offers repair | 
## 9. Canonical entities, evidence and identity model
Observations are facts with a source and a time and are never edited; everything a user sees is a claim derived from them, so corrections change claims, not facts. This split is what lets merges be undone, connectors be distrusted and reports carry evidence levels.
### 9.1 Entity types
Entity | Key fields | Identity rule | Lifetime | 
Network | id, router MAC, subnet(s), SSID, IPv6 prefix, first/last seen, consent state | Fingerprint = router MAC + primary subnet; SSID refines it. A new fingerprint means a new network. | Kept until the user deletes it | 
CaptureSource | id, kind (iface, file, demo, connector, pktmon), name, network_id, vantage class | One per interface per session, per file, per connector | Session | 
Observation | id, ts, source_id, kind (arp_reply, dhcp_ack, dns_query, tls_sni, flow_start, mdns_srv…), subject refs, small payload JSON, packet ref (ring segment + offset) | Append-only, never edited | Retention class "observations" (default 30 days) | 
Device | id (stable, time-ordered), network_id, alias, notes, groups, flags (mine, expected, never_merge) | Created only from local evidence (3.0 rule kept) | Until deleted or expired by retention | 
Interface | MAC, randomised flag, vendor, first/last seen | One per MAC. Belongs to one Device at a time. | Long | 
AddressBinding | ip, interface MAC, valid_from, valid_to (open), source (DHCP, ARP, ND), lease seconds | IP ↔ MAC over an interval. Overlapping bindings for one IP are a conflict, raised as an alert. | Long | 
NameClaim | subject, name, source (user, DHCP, mDNS, NBNS, SSDP, rDNS), first/last seen | Per source; the display name comes from a priority order | Long | 
ServiceAd | device, service type, port, TXT summary, first/last seen | Per device + service | Long | 
RemoteHost | ip, ASN, country, org, enrichment version | Never a Device | Medium | 
Domain | name, registrable domain, category, CNAME targets | — | Medium | 
Resolution | domain, ip, answered_to (device), resolver, ts, TTL | One per DNS answer seen | Medium | 
Flow | id, source_id, 5-tuple, device, remote, domain + association level, counters, state, timings, RTT | 5-tuple + source + start time | Flows 30 days; rollups longer | 
Claim | id, kind, subject, value, level (O/R/C/I/?), confidence, evidence observation IDs, rule ID, computed_at, expires_at | Recomputed when its evidence changes | Same as subject | 
Insight (generalises Alert) | id, kind, severity, claims, alternatives, false-positive notes, episode id, state (new, acknowledged, expected, muted) | Debounced per kind + subject (3.0 logic) | 90 days default | 
Correction | id, op (rename, merge, split, never_merge, reclassify, mark expected), payload, user, ts, undone_by | Journal, append-only | Forever, small | 
Annotation | target (packet, flow, event), text, ts | — | Forever | 
### 9.2 Evidence weights, decay and confidence
3.0's weights stay as the base (EVIDENCE_WEIGHTS): MAC seen locally 40, ARP reply 25, IPv6 ND 25, DHCP lease 25 and so on. Two changes:
Decay. Each evidence type gets a half-life: ARP 1 h, DHCP = lease length, mDNS 2 h, local traffic 15 min, reverse DNS 6 h. Confidence is computed from decayed weights, so a device last proven yesterday drops from High to Medium on its own.
Source class. Reported evidence (connectors) counts toward existence and presence, but is stored and shown as Reported. It cannot by itself raise a claim to Observed.
### 9.3 Display-name priority
The display name is chosen in this order:
User alias
DHCP hostname
mDNS instance name
NBNS name
SSDP friendly name
Model hint from TXT records
Vendor + class
Reverse DNS
Within one level, a human-looking name beats a generated one (3.0's looks_generated). The name never comes from a reverse-DNS answer alone when another source exists, and reverse DNS never causes a merge.
### 9.4 Merge and split
Automatic merge, unchanged from 3.0's strict rule, which needs all of: the same distinctive self-announced name, at least one randomised MAC, no overlapping activity, the older identity inactive, and neither identity pinned. New extra requirement: the same network fingerprint.
Proposed merge ("Possibly the same device") adds: DHCP client-id (option 61) equality as strong evidence, option-55 order equality as medium, and timing adjacency under 10 minutes as weak. Similar websites or traffic never count.
Merge as an operation. Correction(op=merge, keep, absorbed) re-points the absorbed device's Interfaces to the kept device. Observations are untouched, and claims are recomputed.
Split writes Correction(op=split), which moves the chosen interfaces back. Because observations were never moved, the split is exact. 3.0's snapshot split is retired.
Undo replays the journal without the undone operation. A test runs merge, split and undo in random order against a property-based oracle.
### 9.5 Domain-to-device association levels
Level | Rule | Shown as | 
Observed | TLS SNI, QUIC Initial SNI or HTTP Host in a flow from this device | ◉ "connected to example.com" | 
Correlated, strong | This device received a DNS answer for the name, then opened a flow to that IP within 10 s, and the IP maps to 1–3 names | ◎ "connected to example.com (from its lookup)" | 
Correlated, ambiguous | The same, but the IP serves more than 3 known names | ◎ "connected to one of 14 names, e.g. example.com" | 
Reported | A connector's DNS log shows this client looked the name up | ◈ "looked up (per Pi-hole)" | 
Lookup only | A DNS query with no matching flow within 60 s | "looked up, no connection seen" | 
Inferred | An IP-to-domain map from another device's lookup | ◌ "possibly example.com (another device's lookup)" | 
### 9.6 Worked cases
Phone rotates its private MAC. A new Interface appears, and so does a new Device by default. The rotation linker sees the same option-61 client-id and hostname with no overlap, proposes "Possibly the same as Alex-iPhone (Medium)", and auto-merges only if the strict rule holds. History stays split until then.
The IP 192.168.1.50 moves from the printer to a laptop. The printer's binding closes when the laptop's DHCP ACK arrives. Flows after that time attribute to the laptop; the printer's history is untouched.
A CDN IP appears in DNS answers for 40 names. A RemoteHost and many Resolutions are created, but never a Device. Flows to it show "one of 40 names".
The router answers ARP for off-subnet addresses (proxy ARP). The router's MAC appears with many IPs. Those bindings are marked proxy and are not attributed to the router Device (3.0's _routed_private_v4 generalised).
The VPN comes up on this PC. The tunnel endpoint becomes a RemoteHost flagged as a VPN endpoint, and domains carried inside the tunnel stay unknown. The coverage card says the reach went down.
### 9.7 Storage schema (SQLite, history.sqlite3 v2)
The main tables, with the indexes that matter:
networks
sources
observations(ts, kind, source_id, subject) — index on (subject, ts), (kind, ts)
devices
interfaces
bindings — index on (ip, valid_from), (mac, valid_from)
names, services, remotes, domains
resolutions — index on (ip, ts), (domain, ts)
flows — index on (device, start), (remote, start)
claims
insights
corrections
annotations
rollup_minute, rollup_hour, rollup_day — per device × metric
meta — schema version, migration log
Migrations are numbered SQL scripts embedded in the file and run inside a transaction. A migration log row is written before and after each one. A crash mid-migration rolls back automatically, and the old file is backed up first.
## 10. Network map and behaviour intelligence
The map draws only edges it can justify, styled by how they are known, and behaviour summaries are filled from claims rather than written freely. Both reuse 3.0's MapTab canvas and BaselineEngine; the changes are in what feeds them.
### 10.1 How topology is built
Element | Built from | Evidence level | Drawn as | 
L2 segment | Devices whose MACs are seen as Ethernet sources on this interface | Observed | A shaded region | 
Router | Default route + DHCP option 3 + router advertisement source + gateway MAC | Observed (route), Correlated (DHCP/RA agree) | Centre node, "R" | 
This PC's switch and port | LLDP or CDP frames received on the wired interface | Observed | A solid edge to a switch node labelled with the port | 
Other switches and APs | SNMP LLDP/bridge tables, controller APIs (later milestones) | Reported | Dotted edges | 
Device → router | Logical: the device uses this gateway (DHCP lease, ARP to gateway) | Correlated | Dashed edge labelled "logical" | 
Subnet boundary | DHCP mask, route table, RA prefixes | Observed | A labelled frame | 
Internet side | Remote hosts grouped by provider (ASN) when the offline DB is on | Inferred grouping | A column outside the LAN frame | 
Device → site → host | Flows with association levels (9.5) | As per the level | Thickness = log(bytes); dash = level | 
A solid line between a device and a switch is never drawn without LLDP, CDP, bridge-table or SPAN evidence.
### 10.2 Layout and performance
Stable positions. First layout is radial by subnet then device class. Positions are saved per device ID in the store, and a drag pins a node.
Incremental redraw. Canvas items are created once and moved with coords(). 3.0's delete("all") on every change ends. The redraw budget is 16 ms; heavier work is spread over several frames.
Level of detail. Above 120 nodes, devices collapse into class clusters ("14 smart-home gadgets") that expand on click. Labels show only at zoom ≥ 1 or for the selection.
Overlays (toggles). Coverage (full / partial / broadcast-only / reported), activity in the last 5 minutes, alert severity, and evidence level of edges.
Accessible twin. A "Map as list" view shows the same graph as a tree (router → segment → devices → top destinations), readable by screen readers and keyboard.
Time slider (later milestone). It draws the graph at a past time from bindings and rollups, never by replaying packets.
### 10.3 Behaviour features (per device, per minute)
They extend 3.0's DeviceBaseline and are computed on the analysis worker:
packets and bytes up and down
distinct remote hosts and distinct domains
new flows, DNS queries and failed lookups
TCP resets
top services by port
an active-minutes bitmap per hour
From these:
Periodicity. The inter-arrival histogram per (device, destination) is bucketed on a log scale. A sharp peak with 10 or more repeats becomes "contacts X about every 60 s" (Correlated: it cites the flow starts).
Flow shape. Duration, byte ratio and the packet-size mode give bulk download, bulk upload, interactive, streaming-like or call-like. These are always phrased "pattern looks like".
Novelty. First contact with a domain or ASN after the baseline has 30 or more active minutes. Shown in "what changed", not as an alert by default.
Transitions. Idle-to-active after 30 minutes or more of silence becomes a timeline event ("TV became active at 02:14").
### 10.4 Narratives that cannot overclaim
A narrative is a template whose slots accept only claims, and the claim's level is printed with it. Example template: {device} {verb_by_level} {count} connections to {destination} over {duration}. Here verb_by_level is "made" for Observed, "appears to have made" for Correlated, and "was reported to make" for Reported. A template with an empty required slot is not rendered. A test feeds an Inferred claim into an Observed-only slot and expects a refusal.
Example output: "◉ Living Room TV made 14 connections to video.example.net in 2 minutes. ◌ Pattern looks like streaming (steady 6 Mbit/s download). Evidence: 14 flows."
### 10.5 Device → flow → domain → remote host
Every link in that chain has its own claim and level, and the inspector shows the chain with those levels. When a link is ambiguous (a shared IP), the chain forks and shows "one of N". The bandwidth walkthrough (#76) works on this chain: it adds up bytes by the strongest level it trusts and states how much is unattributed.
## 11. GUI expansion blueprint
The window keeps its header, banners, toolbar and 13 tab names. The one structural addition is a docked inspector on the right that follows your selection across every tab. Beginner view still shows ten tabs.
### 11.1 Navigation model
Global selection. Selecting a device, website, remote host, connection or alert in any tab sets one global selection. The inspector shows it, and other tabs highlight it (#71).
History. Back and forward buttons in the header (Alt+←, Alt+→) step through selections and tabs.
Command palette. Ctrl+K searches devices, sites, hosts, settings and actions, using the grouped search from 3.0 (search_results). The existing search box opens it.
Inspector. A right pane, 360 px by default and resizable, toggled with F2. Its sections are Summary, Evidence, History, Related and Actions. Every value has a proof chip (▸) that opens the evidence list.
Layout memory. Pane sizes, column widths, sort order and the last tab are saved per user (#104).
### 11.2 Dashboard (Beginner)
Click a card to open its tab with the matching filter. 3.0's 12 small cards become 5 big ones plus a counter strip.
Hover a number for its definition and its window ("bytes this PC observed in the last 3 s").
Empty state: "Nothing yet — I start counting as soon as watching begins."
Loading state: per card skeleton text, never a spinner over the whole screen.
### 11.3 Devices with the inspector
Click a row to fill the inspector. Double-click or Enter opens the inspector full height. Right-click keeps 3.0's menu.
The last column is the device's weakest evidence level, so doubtful rows stand out.
In Beginner view, IPv6 and packet counts are hidden, as in 3.0.
### 11.4 Timeline → Changes since…
Rows are paged from SQLite in blocks of 200, so scrolling never loads everything. Compare… opens two date pickers, and the same list shows the difference between two sessions.
### 11.5 Guided investigation (Alerts & Insights)
### 11.6 Sources (Advanced)
A table of capture interfaces, imported files, connectors and the packet ring. It shows state, packets or records per second, drops, last good data, permissions used, and what each source adds to coverage. [Add source…] runs a short wizard per connector type with a read-only test before saving.
### 11.7 Packets (Advanced)
The same filter bar and presets, over a virtualised table: only the 40–60 visible rows exist as Treeview items, the scrollbar is driven by the index, and rows load from the in-memory ring or the disk segments. The detail tree and hex view load on selection. "Follow newest" and pause keep their meaning.
### 11.8 First 60 seconds
0–5 s. The loader explains each step in plain words (3.0 behaviour), then the main window opens.
5–15 s. The banner says "Watching Wi-Fi — picked because it carries your Internet route." The Dashboard fills with this PC's own traffic first.
15–60 s. Devices appear as they announce themselves. The coverage card explains why some may be missing.
On a never-seen network, a one-time prompt asks: "Is this your network? Allow Active Scanning here?" The default is Quiet Mode. A three-step tour offers itself once (#103).
### 11.9 Visual and accessibility rules
Every status uses glyph + word + colour.
Evidence glyphs: ◉ Observed, ◈ Reported, ◎ Correlated, ◌ Inferred, ? Unknown.
The focus ring uses the theme's focus token, 2 px.
Row height is 24 px × text scale.
Text scale also follows tk scaling on high-DPI screens.
Animations are limited to state changes under 150 ms and are disabled in Low CPU mode.
All new widgets use theme tokens; a test walks the widget tree in Dark mode and fails on any light-palette hex.
Untrusted text (hostnames, SSIDs, TXT records) is cleaned of control and bidirectional characters, cut to 80 characters, and shown with a “quoted” style in the inspector.
## 12. Autonomous installation and modern runtime
MiniWireshark 4 should start from any Python 3.8 or newer, then run itself on a private Python 3.14 it installed with your consent. It never touches system Python or PATH, and it keeps the previous runtime until the new one passes a self-test.
### 12.1 The one-file problem, solved
The starting interpreter compiles the whole file before running a line. Any newer syntax anywhere would therefore crash an old Python before the bootstrap even starts.
Decision: the entire file stays within Python 3.8 grammar. A self-test runs ast.parse(source, feature_version=(3, 8)) to enforce this, and with from __future__ import annotations (already present) modern type hints are still allowed. Newer standard-library features are used only behind version checks. The managed 3.14 runtime is for speed, security fixes and current wheels, not for syntax. 3.0 already meets the rule (no walrus or match found).
### 12.2 Three layers
L1, wide-entry bootstrap (top of the file, standard library only, Python 3.8+):
Read runtime/state.json and check the runtime is healthy: its interpreter exists and is the expected version, the lock hash matches, and the last self-test passed.
If healthy and we are not already running inside it, re-launch the same script with the managed interpreter, passing MW_STAGE=app. The MW_STAGE value and an attempt counter (3.0's BootstrapState) prevent loops.
If it is missing or broken, show the loader with a consent screen: what will be downloaded, the size, where it goes, and how to remove it. Choices: Install / Use this Python instead (degraded mode, 3.0 behaviour) / Cancel.
L2, managed environment: a pinned CPython 3.14.x and a venv in the data folder. Packages are installed from a hashed lockfile embedded in the file, with pip install --require-hashes --only-binary=:all:. Wheels are cached for offline repair.
L3, the application: the full GUI, capture and storage. It runs inside L2, or degraded inside whatever Python started it, with a banner explaining what is missing.
### 12.3 Where the runtime comes from
Platform | First choice | Why | Fallback | 
Windows 10/11 x64, ARM64 | python.org 3.14.x installer, per-user, into %LOCALAPPDATA%\MiniWireshark\runtime\cp314. PATH, launcher, file associations and shortcuts all off. Silent per-user flags (to verify). | Signed by the PSF, includes Tcl/Tk and the VC++ runtime | python-build-standalone install_only if vcruntime140.dll is present (those builds don't ship it), then the existing Python 3.10+ in a venv | 
macOS (Apple silicon, Intel) | python-build-standalone install_only 3.14.x | No admin needed; per-user tarball | Existing Python 3.10+ in a venv | 
Linux x86-64, aarch64 | python-build-standalone GNU build (needs glibc 2.17+) | Doesn't touch the distro Python (avoids PEP 668 errors) | Distro Python 3.10+ in a venv. The Tk package is named in the error if missing. | 
The traditional Windows installer is scheduled for deprecation around April 2027 in favour of the Python Install Manager (PEP 773). M6 keeps a switchable provider so the Install Manager path can replace it. Whether python-build-standalone includes Tk on every target must be checked before M6 (section 21).
Integrity checks:
Windows installers: verify an Authenticode signature whose signer is the Python Software Foundation.
Tarballs: verify the SHA-256 against the published checksum file, then against a hash pinned inside MiniWireshark's own lockfile, so a compromised mirror cannot swap both.
Downloads resume (HTTP Range) and land in a temporary folder. They are renamed into place only after verification.
### 12.4 Dependency and utility decisions
Item | Purpose | Required? | Install surface | Licence | Trust mechanism | If missing | 
CPython 3.14.x | Runtime | Preferred | Per-user folder | PSF | Signature / pinned SHA-256 | Run on the starting Python, degraded | 
scapy 2.8.x | Deep parse, sending ARP/mDNS probes, pcap I/O, Npcap/libpcap binding | Yes | venv | GPL-2.0 | Hashed lock | Read-only file viewer mode only | 
psutil | Interface link state, this PC's connection owners, CPU | Optional | venv | BSD-3 | Hashed lock | Those features hidden, with an explanation | 
cryptography | QUIC Initial SNI (AES-GCM), signed packs and updates (Ed25519) | Optional (M8, M13) | venv | Apache-2.0 / BSD | Hashed lock | QUIC names unknown; updates check-only | 
pysnmp (later) | SNMP connector | Optional | venv | BSD-2 (maintenance to verify) | Hashed lock | Connector unavailable | 
Npcap (Windows) | Capture driver | Yes on Windows | System driver, interactive installer (free edition has no silent mode) | Npcap free licence: up to 5 systems, no redistribution | Authenticode signer = Nmap Software LLC; version from npcap.com (1.89 as of 2026-09-12) | pktmon snapshot mode (#8), file analysis | 
OUI list (Wireshark manuf) | Vendors | Optional data | cache | To verify | SHA-256 + size checks | scapy's built-in table | 
Public Suffix List | Domain grouping | Optional data | cache | MPL-2.0 | SHA-256 | Built-in heuristic | 
iptoasn ip2asn | Offline ASN and country | Optional data | cache | PDDL (public domain) | SHA-256 | Online lookup (opt-in) or none | 
Disconnect tracker list | Categories | Optional data | cache | To verify | SHA-256 | Built-in CDN list only | 
The lockfile is generated at release time from PyPI's JSON API. It is pinned per platform and Python minor version, and it is embedded in the file as a constant. A self-test fails if the lockfile and the DEPENDENCY_MANIFEST disagree.
### 12.5 Install and launch scenarios
Situation | Behaviour | 
First run, online, consent given | Download runtime → verify → create venv → install from lock → run --self-test --quick → write state.json → re-launch in L2. Shows plain-English steps, with package names behind "details". | 
First run, consent refused | Degraded mode on the starting Python. The 3.0 bootstrap still installs scapy, but now asks before using --break-system-packages, and recommends a venv. | 
Ordinary launch | Health check under 200 ms, then a straight handoff. No network access and no installs. Startup never changes the system. | 
Offline launch | Same as ordinary. Reference-data refresh is postponed. | 
Interrupted download or install | The temp folder is discarded on the next launch; resume where possible; the attempt counter limits retries per day. | 
Hash mismatch | Stop, delete the file, show the expected and actual hash, offer a retry later. Never run it. | 
Partial venv | Repair mode reinstalls from the cached wheels and lock, no network if the cache is complete. | 
Upgrade (new lock or new 3.14.x) | Build the new env side by side → self-test → switch state.json atomically → keep the old env for 7 days. | 
Upgraded env fails at start | Two failed starts flip state.json back to the previous env (like 3.0's update rollback). | 
Corrupted cache or state | state.json is checksummed; if it is invalid, treat the runtime as missing and repair. | 
Npcap missing (Windows) | Explain, show the licence summary, download from npcap.com, verify the signer, run the interactive installer. A reboot-pending state is remembered (3.0 logic). Meanwhile offer file analysis or a pktmon snapshot. | 
### 12.6 Least privilege
Windows. Npcap installed with defaults lets non-admin users capture (only /admin_only restricts it). So 4.0 runs unelevated by default and elevates only for the Npcap install. 3.0 elevates the whole app at launch.
Linux. Capture needs root or CAP_NET_RAW. 4.0 keeps the elevated launch (pkexec or sudo), shows why, and offers file analysis without elevation. It does not grant capabilities to the shared interpreter binary: that would give every script on the machine raw-socket rights.
macOS. BPF devices need root, or a group-based permission like Wireshark's ChmodBPF. 4.0 keeps the elevated launch and documents the ChmodBPF alternative.
Every privileged step is listed in Diagnostics, with when it was used and why.
### 12.7 Updates
Code updates stay opt-in. The release manifest (version, SHA-256, size, minimum Python) is signed with an Ed25519 key whose public half is embedded in the file. The download is verified before 3.0's backup-and-replace flow runs, and the rollback marker stays.
Data packs and reference lists update on their own schedule, with signature or hash checks. They never contain code.
The runtime is updated only by a new app release that changes the lock. There are no automatic "latest" upgrades of packages.
## 13. Security, consent, privacy and supply chain
MiniWireshark holds sensitive data about everyone on a network, so 4.0 adds consent per network, a single ledger of everything the app sends, redaction for sharing, signed updates, and sanitising of every untrusted string. Nothing is uploaded, and there is still no telemetry or account.
### 13.1 Threats and safeguards
Threat | Example | Safeguard | Test | 
Probing a network you don't control | Laptop on a café or office network starts ARP sweeps | Per-network consent (fingerprint). New networks start in Quiet Mode. Active features check consent and refuse subnets outside the directly connected one. | Scenario 36 (section 15) | 
Malicious names spoof the UI | A device announces ‮exe.txt or a 10 KB hostname | Strip control and bidi characters, cap length, show raw bytes in the inspector "technical" view | Fuzz names through every view | 
Malformed packets crash the parser | Truncated TLS, a looping DNS pointer | Fast parser bounds-checks every offset; deep parse runs under a per-packet try; recursion caps | Fuzz corpus (M0) | 
Hostile import files | A 50 GB pcap or a crafted pcapng block | Size and record caps, streaming reader, cancellable, never pickle | Import fuzz cases | 
Poisoned enrichment data | A tampered tracker list labels a bank as "ads" | Signed packs or pinned hashes; a category always shows its source; data never executes | Tampered-pack test | 
Supply chain: packages | A typo-squatted or replaced wheel | Hashed lockfile, --only-binary, PyPI only | Lock hash test | 
Supply chain: runtime and drivers | Swapped installer | Authenticode signer pinning (PSF, Nmap Software LLC) + SHA-256 pins | Signer-mismatch test using a self-signed file | 
Supply chain: app update | Malicious "update" from a repo | Ed25519-signed manifest; key embedded; 3.0's rollback | Wrong-key test | 
Credential leakage | Pi-hole app password in logs or config | Stored with OS protection: Windows DPAPI via ctypes, macOS Keychain via the security CLI, Linux Secret Service if present, otherwise asked each session. Never logged; redacted from bundles. | Grep logs and bundles in tests | 
Shared-computer exposure | Another user opens the history | History lives in the per-user data folder with user-only file permissions where the OS supports them; a one-click "Clear all history" | Permission check test | 
Over-collection | Raw packets kept forever | Raw packet ring off by default, capped size and age, cleared with history; summaries by default | Retention test | 
Third-party lookups leak browsing | Online GeoIP sends every remote IP | Offline ASN DB is the default; the online lookup stays opt-in with its exact disclosure (3.0); nothing goes out in Quiet Mode | Self-traffic ledger test | 
### 13.2 What the app sends, and when
Everything below is recorded in the self-traffic ledger (new idea 9) and paused by the outbound kill switch (new idea 13).
Activity | Destination | Content | When | 
ARP, mDNS and SSDP discovery | Your own subnet | Standard discovery messages | Active Mode, consented network | 
Health checks | Router, 1.1.1.1:443 (configurable), your DNS server | A TCP connect, one DNS query | Active Mode | 
Reverse DNS | Your DNS server | PTR query for local addresses only | Always (3.0); becomes Active-only in 4.0 | 
Reference data | wireshark.org, publicsuffix.org, iptoasn.com, GitHub | Plain file download | Opt-in toggles (3.0) | 
Online GeoIP | ipwho.is and others | One remote IP per lookup | Opt-in (3.0) | 
Connectors | Your Pi-hole or AdGuard | Read-only API calls with your token | When configured | 
Runtime, Npcap, updates | python.org, GitHub, npcap.com | File download | Setup or with consent | 
### 13.3 Explicitly excluded
These are excluded whatever the stated purpose:
credential capture or display;
TLS interception or decryption;
ARP or DNS poisoning;
traffic injection beyond the standard discovery and health probes;
Wi-Fi deauthentication;
port scanning outside your own subnet, or any scanning without consent;
exploitation or default-password testing;
stealth modes or hiding the app;
persistence on other machines;
cloud upload of captured data;
profiling household members' routines (tribunal veto).
### 13.4 Redaction for sharing
A redaction profile chooses what to mask: IPs (prefix kept or not), MACs (the vendor part kept or not), hostnames, domains, user labels and notes. Pseudonyms are consistent within one export (Device-A, 10.x.x.7, site-3.example). The same engine serves reports, bundles, CSV and JSON. Exports show a side-by-side preview first (new idea 14). Raw PCAP export cannot be redacted and says so.
## 14. Performance architecture and benchmark program
The performance goal is 15,000 packets per second analysed without loss on a mid-range laptop, against about 2,100 today. The plan gets there by removing work, not by optimising tricks.
The dissection bar mostly disappears because the fast path reads headers with struct (1.2 µs measured) and calls scapy only for the minority of packets that need it. The analysis target relies on the memoised address classifier and on dropping per-packet dict copies.
### 14.1 Workload profiles
These rates are hypothetical test loads, to be replaced by measured captures from real homes in M0.
Profile | Packets/s | Devices | New flows/min | Retention | Purpose | 
Idle | < 50 | 5 | < 20 | 1 day | Startup, CPU at rest | 
Typical home | 500–3,000 bursts | 20–40 | 200 | 30 days | Everyday budget | 
Busy home | 5,000–15,000 | 60 | 1,000 | 30 days | The design point | 
Lab / mirror port | 20,000–60,000 | 200 | 5,000 | 7 days | Graceful degradation | 
Large broadcast domain | 1,000 (mostly broadcast) | 1,000 | 100 | 7 days | Map, devices table, identity graph | 
Long haul | Typical profile for 7 days | 40 | 200 | 30 days | Leaks, DB growth, retention | 
### 14.2 Budgets
Measure | Target | How measured | 
Analysed without loss | ≥ 15,000 pkt/s busy-home mix | --bench busy replay; drop counters at ring and worker | 
GUI input latency | p95 ≤ 100 ms at busy-home load | Tk after lag probe (3.0's _gui_lag) + scripted clicks under Xvfb | 
Delta cadence | 250 ms normal, 1 s under load | Publisher timestamps | 
Window shown after launch | ≤ 3 s with the runtime ready (imports measured at 2.2 s today) | Timestamps in the log | 
First device shown | ≤ 2 s after its first DHCP, ARP or mDNS packet | Replay with known timestamps | 
Filter on a 1M-row timeline | ≤ 300 ms first page | SQLite EXPLAIN + timing | 
Memory | ≤ 350 MB busy home, ≤ 600 MB lab | tracemalloc + RSS sampling | 
Disk | ≤ 2 GB per week, typical home, default retention (estimate) | Long-haul run | 
Store commit | p95 ≤ 50 ms per 1 s batch | Writer timing | 
Enrichment | ≤ 5% CPU at busy home | Per-thread CPU via psutil | 
### 14.3 Instrumentation (Diagnostics → Performance)
Per stage: EWMA microseconds, items per second, queue depth, high-water mark, drops.
Store: commit latency, rows per batch, WAL size.
Caches: hit rates for the address classifier, the name cache and enrichment.
Claims: the share that are stale.
Time-to-insight: seconds from an event packet to its UI row, sampled.
GUI: lag and the number of Treeview items alive.
Everything is exportable in the diagnostics bundle.
### 14.4 Benchmark suite
Benchmark | Data | Automated? | 
--bench parse | 100k synthetic frames per protocol mix (generator in-file) | Yes, CI on Linux | 
--bench ingest | Same, through the analysis worker | Yes | 
--bench busy / lab | Replay of generated pcaps at target rates through a loopback source | Yes, single machine | 
--bench store | 10M observations, 1M flows; query timings | Yes | 
--gui-test --load busy | Scripted tab switches, filtering and scrolling under replay; measures lag | Yes, under Xvfb | 
Long haul | 10 h and 7 d live runs | Manual, home lab | 
Real adapters | Wi-Fi + Npcap, a mirror port at 1 Gbit/s | Manual, needs hardware | 
Rule: profile before optimising. The process-based parser (#121) is built only if --bench lab misses 15,000 pkt/s after M2.
## 15. Reliability and testing strategy
Every milestone ships with tests that live inside the file and run without admin rights. The 23 self-tests from 3.0 grow into five suites that a single command runs, and 40 adversarial scenarios define what "works" means.
### 15.1 Test layers
Suite | Command | What it covers | Needs | 
Unit + property | --self-test | Parsers, identity rules, merge/split/undo (property-based: random op sequences vs a reference model), filters, metrics, migrations, theme tokens, the 3.8 grammar gate, lock consistency | Nothing | 
Replay (golden) | --self-test --replay | Generated pcaps → the full pipeline → expected entities, claims and levels (JSON golden files embedded or generated deterministically) | scapy | 
Fuzz | --self-test --fuzz N | Random and mutated frames into the fast parser and deep parse; hostile names into every view model; malformed pcapng | scapy | 
GUI | --gui-test | Headless walk of all tabs, themes, modes, dialogs, inspector, palette; dark-mode hex audit; lag under replay (moved from last session's scratch harness into the file) | Display or Xvfb | 
Upgrade and fault injection | --self-test --faults | Kill the writer mid-batch, corrupt the DB, interrupt a migration, a bad lock hash, wrong signer, a connector timeout, disk full (via a quota stub) | Temp folder | 
Benchmarks | --bench … | Section 14 | Varies | 
Manual lab | Checklist | Windows + Npcap, Wi-Fi, mirror port, sleep/wake, real routers | Hardware | 
### 15.2 Scenario matrix
In the Check column: A = automated in-file, X = automated under Xvfb, L = manual lab.
# | Scenario | Expected behaviour | Truth and messaging | Data integrity | Check | 
1 | Clean Windows, no Python packages, no Npcap | L1 runs on the user's Python, asks consent, installs runtime, guides Npcap | Each step in plain words; licence shown | State written only after self-test | L | 
2 | Only Python 3.8 present | L1 parses (3.8 grammar gate) and provisions 3.14 | "Setting up a newer Python just for MiniWireshark" | — | A (grammar), L | 
3 | No admin rights (Windows, Npcap present) | Runs unelevated; capture works | Diagnostics shows "not elevated, not needed" | — | L | 
4 | No admin, no Npcap | Offers the install (needs admin once) or file and pktmon modes | No fake device list | — | L | 
5 | Internet blocked on first run | Degraded mode on the existing Python; retry later | "Couldn't reach python.org" + the exact host | No partial runtime left | A (network stub) | 
6 | Download interrupted | Temp discarded, resumed next time | Progress shows resumed bytes | Never installs partial files | A | 
7 | Hash mismatch | Abort, delete, report | Shows expected vs actual | Nothing executed | A | 
8 | Incompatible wheel (no build for the platform) | Lock lookup fails before download; that optional feature is disabled | Names the feature, not the package | — | A | 
9 | Offline second launch | Instant handoff; data refresh postponed | Reference data shows its age | — | A | 
10 | No usable interface | Dashboard explains; file and demo offered | "No network card with an address found" | — | X | 
11 | Permission revoked while capturing | Source → healing → failed after backoff | Timeline entry; banner | Session kept | A (fake source) | 
12 | Multiple NICs, VPN, hotspot, virtual adapters | Scored choice explained; VPN flagged | "Picked because…" (3.0) | Flows tagged by source | A (scoring), L | 
13 | Laptop sleeps and wakes; DHCP renews | Watcher detects resume, heals, rebinds addresses | "Woke from sleep — restarted watching" | Bindings closed and opened correctly | A (clock stub), L | 
14 | IPv4 and IPv6 change on the same device | New bindings; same device via MAC/ND | IP-change timeline event | Old bindings closed | A | 
15 | Randomised MAC rotation | New identity + "possibly the same" | Medium confidence, reasons listed | No auto-merge unless the strict rule holds | A | 
16 | Duplicate hostname on two devices | No merge (activity overlaps) | Both shown; ambiguity note | — | A | 
17 | Duplicate IP (conflict) | Alert with both MACs | Observed, cites ARP | Overlapping bindings flagged | A | 
18 | Conflicting OUI vs mDNS model | Class from strongest evidence; reasons show the conflict | "Possibly" wording | — | A | 
19 | CDN IP in DNS answers | RemoteHost only, never a Device | "One of N names" | — | A (exists) | 
20 | DNS lookup without a connection | "Looked up, no connection seen" | Not called a visit | — | A | 
21 | DoH, DoT, ECH, QUIC, proxy, VPN | Each labelled as in 4.2 | The blind-spot meter rises | — | A (synthetic) | 
22 | VLAN-separated clients | Not shown; coverage says "other segments not visible" | Device count is "at least" | — | A | 
23 | Import of 5M packets | Streams, cancellable, the UI stays responsive | OFFLINE banner, progress | Lossless (3.0 lossless flag) | A (bench) | 
24 | Busy link causing drops | Degradation ladder (8.3), counts as "≥" | Drop banner per stage | Exact counters stay exact | A (bench) | 
25 | 10-hour live session | Flat memory, steady CPU | — | Retention applied | L | 
26 | 7-day run, 30-day retention | DB within budget; rollups used | Retention forecast correct ± 20% | quick_check clean | L | 
27 | Disk nearly full | Ring stops first, retention tightens, warning | Banner with numbers | No corrupted DB | A (quota stub) | 
28 | Corrupted SQLite | Detected at start; restored from backup; running in memory meanwhile | "History restored from 02:00 backup" | Bad file kept for diagnosis | A | 
29 | Router connector disconnects then resumes | stale → ok; gap shown | Reported claims fade, then refresh | No duplicate records | A (fake connector) | 
30 | False-positive alert corrected | "Expected" adjusts thresholds for that device and kind only | Calibration page counts it | Correction journalled | A | 
31 | Rapid filtering during capture | Filters debounced; worker unaffected | Zero-result diagnosis when relevant | — | X | 
32 | Device disappears, returns with new IP and MAC | New identity + rotation proposal; presence gap recorded | "Possibly the same as…" | — | A | 
33 | Replayed file conflicts with live data | Separate data modes; never mixed (3.0 rule) | OFFLINE banner | Separate models | A (exists) | 
34 | Export with redaction | Consistent pseudonyms; preview | Evidence levels kept | Original untouched | A | 
35 | Resize, DPI change, theme switch | Layout reflows; no hard-coded hex | — | — | X | 
36 | Active probe requested on an unconsented or non-local subnet | Refused with an explanation | "Not your network yet — allow here?" | Nothing sent (ledger proves it) | A | 
37 | Crash mid-migration | Transaction rolls back; old file backed up; retry next start | "Upgrading history… resumed" | No half-migrated schema | A | 
38 | Rollback after a GUI failure in a new runtime or app | Two failed starts → previous env and app restored | Explains what was rolled back | Previous state intact | A | 
39 | Stale enrichment vs fresh observation | Fresh observation wins; enrichment shows its age | Data-quality auditor flags it | — | A | 
40 | PCAP from another time zone | Times shown in local time with the file's offset noted; option to view in file time | Label on the banner | Original timestamps kept | A | 
### 15.3 Regression rules
A bug fix lands with a test that failed before the fix.
Golden replay outputs change only with an explanation in the release notes.
--self-test must stay under 60 s, and the GUI test under 3 minutes, so they are actually run.
## 16. Scoring and prioritisation
The top of the ranking is plumbing that users feel indirectly (speed, honesty, durability); visible features follow once those foundations can carry them. Scores are my judgement on a 1–5 scale per criterion, weighted as below. Three overrides beat the score: safety, correctness, and being a prerequisite.
### 16.1 Weights
Criterion | Weight | 
Value to real users and how often the problem occurs | 20 | 
Gain in truthful visibility | 15 | 
Feasibility from the actual vantage point | 10 | 
Effort and dependency risk (inverse) | 10 | 
Reliability and testability | 10 | 
Privacy and security impact (positive = safer) | 10 | 
Architectural leverage | 10 | 
Performance and memory | 5 | 
UX complexity (inverse) | 5 | 
Novelty | 5 | 
### 16.2 Ranked leaders
Rank | Idea (# from section 5) | Score /5 | Why here | Milestone | 
1 | Memoised address classifier (#119) | 4.6 | Measured top hotspot; tiny change | M1 | 
2 | Raw-bytes capture + selective deep parse (#1, #2) | 4.5 | Removes the 270 µs stage; override: prerequisite | M2 | 
3 | Analysis worker off the Tk thread (#120) | 4.4 | GUI smoothness at any load | M2 | 
4 | Observations separated from claims (#125) | 4.3 | Makes the truth contract enforceable; override: prerequisite | M3 | 
5 | Time-scoped identity graph (#17, #18) | 4.3 | Fixes defect 7; unlocks history | M4 | 
6 | Evidence badges (#99) | 4.2 | Credibility everywhere for little cost | M5 | 
7 | Coverage model + card (#11, #15) | 4.2 | Answers "what can't you see?" | M5 | 
8 | "What changed since…" (#64) | 4.2 | Highest everyday value | M7 | 
9 | Managed runtime + hashed lock (#106, #107) | 4.1 | Fresh-machine success; override: safety | M6 | 
10 | SQLite WAL + migrations + backups (#113) | 4.1 | Durability | M3 | 
11 | Lookup→connection correlation (#38) | 4.0 | Ends "DNS = visit" | M3 | 
12 | Golden replay corpus (#139) | 4.0 | Proof for every later change; override: prerequisite | M0 | 
13 | Network fingerprints + per-network consent (new 5, 6, #88) | 3.9 | Safety on foreign networks; override: safety | M4 | 
14 | Npcap signer pin + current version (#109) | 3.9 | Supply chain; override: safety | M1 | 
15 | Rogue IPv6 RA detection (#81) | 3.9 | Real, visible, cheap | M1 | 
16 | Docked inspector (#98) | 3.8 | Workflow speed | M5 | 
17 | QUIC Initial site names (#44) | 3.8 | Large visibility gain on this PC | M8 | 
18 | This PC's Wi-Fi link quality (#58) | 3.8 | Most common slowness cause | M8 | 
19 | Process names for this PC's connections (#97) | 3.7 | "Which program?" | M9 | 
20 | TCP handshake RTT (#53) | 3.7 | Passive latency | M8 | 
21 | "Why is it slow?" investigation (#75) | 3.7 | Flagship diagnosis | M11 | 
22 | Pi-hole v6 connector (#89) | 3.6 | Whole-LAN DNS for many homes | M10 | 
23 | LLDP/CDP switch-port facts (#33) | 3.6 | First real physical topology | M8 | 
24 | Paged DB timeline (#61) | 3.6 | Long history without freezes | M7 | 
25 | Virtualised tables + disk packet ring (#100, #7) | 3.5 | Fixes defect 3 | M2/M7 | 
26 | Redaction engine (#130) | 3.5 | Safe sharing | M12 | 
27 | Router port-forward audit (#84) | 3.4 | Finds exposed services | M9 | 
28 | Vantage test (#12) | 3.4 | Automatic coverage truth | M5 | 
29 | Merge/split journal with undo (#21) | 3.4 | Exact splits; override: correctness | M4 | 
30 | Periodicity detector (#46) | 3.3 | Explains IoT chatter | M11 | 
### 16.3 Not now (revisit with evidence)
Idea | Revisit when | 
Multi-interface capture (#5) | After source-aware flows (M3) and a user need | 
SNMP and NetFlow (#92, #93) | After the connector framework proves itself with Pi-hole and AdGuard | 
Process-based parser (#121) | Only if --bench lab misses its target | 
Encryption at rest (#128) | When key storage is designed per OS | 
UniFi, Omada, Home Assistant (#95, #96) | After user demand | 
Latency-under-load test (#57) | Active and heavy; after health v2 | 
"What would break" view (#145) | Research only | 
Do not build: the nine tribunal kills in section 5.1.
### 16.4 Foundations that unlock the most
The ranking hides one dependency chain that decides the order of everything:
golden replay (M0) → fast pipeline + worker (M2) → observations/claims store (M3) → identity graph + fingerprints (M4) → badges, coverage, inspector (M5).
Everything users notice later hangs off this chain. "What changed", investigations, connectors and reports all assume stable IDs, provenance and time-scoped bindings. The roadmap diagram in section 17 draws it.
## 17. Milestone roadmap
Fourteen milestones in five phases. The first complete vertical slice — one device's lookup → connection → domain claim, with evidence shown in the inspector — is working at the end of M5. Each milestone keeps every 3.0 feature working and every test green.
No milestone carries a date: none were given, and sizes are only estimated (section 5's effort letters).
### M0 — Baseline harness and gates
Goal: prove 3.0's behaviour before changing it.
User sees: nothing new. Developers get --replay, --fuzz, --gui-test, --bench.
Areas: section 20 (self-tests), the scratch GUI harness from last session moved into the file, DemoGenerator reused as the pcap generator.
New contracts: golden JSON of entities and claims per replay file; the 3.8 grammar gate; the theme hex audit.
Dependencies: none. Packages: none new.
Acceptance: all 23 existing tests plus at least 25 new ones pass on Linux. The GUI test passes under Xvfb. Benchmarks record the 2.2 baseline numbers.
Gate: the replay corpus is green and deterministic over 3 runs.
Risk: golden files become brittle → compare semantic fields only.
Demo: run one command, and see 3.0's measured baseline and a green report.
Done when: a contributor can change the parser and get a failing test for a behaviour change within 60 s.
### M1 — Correctness and safety fixes
Goal: fix the cheap defects from 2.4.
User sees: a faster app, safer names, current Npcap, and "rogue router advertisement" alerts.
Areas: is_private_ip/is_public_ip/eligible_ip (memo cache), key_for_iid (reverse map), AlertEngine.order (deque), _install_npcap (signer = Nmap Software LLC, version 1.89 fallback, licence text), a new sanitize_text() applied at every UI and report boundary, rogue RA detector, reverse DNS made Active-only, narrowed except clauses.
Schema: none. Rollback: a code-only change.
Acceptance: ingest 82 → ≤ 45 µs per packet in --bench ingest; a hostile-name fuzz shows no control characters in any widget; the signer-mismatch test refuses.
Gate: no golden replay diffs except the intended ones.
Demo: a device named with an RTL-override character displays safely.
Done when: all fixes are listed in release notes with tests.
### M2 — Capture pipeline v2
Goal: remove the throughput ceiling.
User sees: no drops on busy networks, a smooth GUI, per-stage drop counts.
Areas: replaces build_sniffer/AsyncSniffer with CaptureSource using recv_raw or a pcap handle; new RawRing, fast_parse, a selective deep-parse rule table, an analysis worker thread, a UiDelta publisher. _drain_decoded is kept as a fallback path behind a setting for one release.
New contracts: PacketMeta (slots), UiDelta, Command.
Dependencies: M0, M1.
Fallback: if raw receive is unavailable on a backend, use the 3.0 sniffer path automatically and tell the user.
Acceptance: ≥ 15,000 pkt/s busy-mix replay with zero analysis drops; GUI p95 lag ≤ 100 ms at that load; all golden replays identical.
Gate: --bench busy on Linux and on one Windows + Npcap laptop (lab).
Risks: Npcap raw-receive differences → per-backend adapter + lab test; the fast parser misses encapsulations → unknown frames are sent to deep parse.
Demo: replay of a 4K stream plus downloads with a live drop counter at 0.
Done when: the old path is off by default and no regressions are open.
### M3 — Evidence store v2
Goal: observations versus claims; durable history.
User sees: history survives restarts (opt-in, as in 3.0), and websites show "looked up only" versus "connected".
Areas: HistoryStore → Store (writer thread, WAL, migrations, nightly backup, retention classes); ClaimBuilder; lookup→connection correlation; disk packet ring (opt-in); SessionCodec v3 (exports from the store, imports v1 and v2).
Migration: v1 history tables are copied into v2; the original file is kept as .v1.bak until the user clears it.
Acceptance: fault-injection suite green; 10M observations under 1.5 GB; time-range queries ≤ 300 ms.
Gate: migration and rollback tests, plus scenario 37.
Risks: write amplification → batch per second, store summaries for bulk traffic, store packets only when the ring is on.
Demo: kill the app mid-capture, restart, and see history intact up to the last second's batch.
Done when: every displayed website row has an evidence level.
### M4 — Identity graph and network fingerprints
Goal: time-scoped bindings, a merge journal, per-network history and consent.
User sees: "You are on Home", Quiet Mode by default on new networks, exact split, undo.
Areas: DeviceRegistry → Device/Interface/AddressBinding stores; merge/split rewritten as journal operations; the rotation linker (option 61/55); Network detection in NetworkWatcher; consent checks in LanScanner and HealthProber.
Migration: existing known_devices.json labels are attached to Interfaces by MAC.
Acceptance: property-based merge, split and undo vs the oracle (10,000 random sequences); scenarios 13–17, 32 and 36.
Gate: no attribution to the wrong owner across an IP reuse in replay.
Demo: a printer's IP is reused by a laptop; histories stay separate.
Done when: ip_to_key is gone and every attribution queries bindings by time.
### M5 — Truth UI (vertical slice complete)
Goal: make evidence and coverage visible.
User sees: badges, the docked inspector with proof chips, the coverage card, the vantage test result, "heard not seen" devices, the uncertainty footer.
Areas: BaseTab subclasses get an evidence column; a new Inspector widget; Dashboard cards; a vantage test in the analysis worker.
Acceptance: every claim in every view has a level (a GUI test walks them); scenario 22; screen-reader list view of the inspector.
Gate: usability check with 3 non-technical people. Pass: each can answer "how do you know?" for a device within 30 s.
Demo: click any number → see the packets behind it.
Done when: no modal detail dialogs remain except for reports.
### M6 — Managed runtime bootstrap
Goal: the section 12 design.
User sees: a one-time consent and setup; everything else is automatic.
Areas: L1 at the top of the file; RuntimeManager; the lockfile constant; repair and rollback; the unelevated Windows launch.
Acceptance: scenarios 1–9 and 38 on Windows 11, macOS 14+ and Ubuntu 24.04 (lab); Python 3.8 → 3.14 handoff.
Gate: fresh-machine install on 3 OSes, with no system Python changed (verified by before/after listings).
Risks: antivirus quarantining the downloaded runtime → signed sources, a clear message, the offline kit later.
Demo: a fresh VM, double-click, approve once, capturing within 3 minutes.
Done when: degraded mode still works for a user who refuses.
### M6b — Runtime Manager & Welcome Center (added 2026-10-18 at your request)
Added 2026-10-18: a one-click Repair button for beginners. Settings gets a large "🛠 Repair MiniWireshark" button, and the Welcome Center gets a "Something wrong? Repair" link. One click checks and fixes the usual problems:
reinstalls broken or missing packages (in the private runtime, or in your Python with permission)
re-downloads any reference list whose fingerprint is bad
checks the history database and restores it if damaged
restores a corrupted settings file from its backup
re-detects network cards and restarts the capture engine
runs the quick self-test
It then reports in plain words what it found and what it fixed. The Runtime Manager stays as the advanced view.
Goal: turn the 3.0-style loader (a progress bar with a log) into a 4.0 component. It installs, repairs and welcomes, and it can be reopened at any time for maintenance.
What "update" means here: "the newest versions this release has verified", never "whatever is newest online". Every package and Python download is checked against a fingerprint built into the file. When python.org has something newer, the window says so and suggests updating MiniWireshark itself.
Smart installer:
System check card: OS and CPU, which Python is running (private or not), pip, Tk, each package (installed / pinned / verified), Npcap or libpcap, admin rights, free disk space, detected proxy.
Health chip (Healthy, Needs repair, Degraded) with a one-click fix.
Named stages: Check → Download → Verify → Unpack → Environment → Packages → Self-test → Switch.
Progress shows MB/s and time left; downloads resume; there is a safe Cancel.
Reuse: build the private environment from a compatible Python 3.14 already on the computer (that copy is not modified), or from a cached verified download, instead of downloading again.
Rollback to the previous environment.
Friendly errors: no internet, a proxy or antivirus intercepting HTTPS, a quarantined file, disk full, no permission, fingerprint mismatch, Tk missing. Each shows the cause, what to try, and "copy details".
Welcome Center: when setup finishes, the same window turns into a welcome screen with Start Monitoring, Try Demo Mode, Quick Start Guide and Diagnostics. It also shows "What's new in 4.0" and a reminder that new networks start in Quiet Mode.
### M7 — History v2
Goal: paged timeline, "what changed", compare, the query language.
Areas: TimelineTab virtualised and SQL-backed; a digest builder; DisplayFilter compiled to SQL; virtualised packets table reading the ring.
Acceptance: 1M events scroll at ≥ 30 fps on the dev box; the digest matches a replay's known changes exactly.
Gate: a 7-day long-haul run passes (scenario 26).
Demo: "since yesterday" shows the new guest laptop and the DNS change.
### M8 — Diagnostics depth
Goal: TCP RTT, retransmission and goodput, DNS histograms, Wi-Fi link (Windows netsh, Linux iw, macOS framework or CLI), LLDP/CDP, QUIC Initial site names.
Package: cryptography (optional; QUIC names disabled without it).
Acceptance: QUIC test vectors from RFC 9001 Appendix A decode to the right SNI; LLDP replay shows switch and port.
Demo: the Health tab shows Wi-Fi −78 dBm as the likely culprit.
### M9 — This-PC intelligence
Goal: process attribution of this PC's flows; new listening services; ARP-cache cross-check; opt-in UPnP port-forward audit.
Permissions: psutil may need admin for some processes; shown as "unknown process (needs admin)".
Acceptance: a known test process's connection is attributed; the UPnP audit sends exactly one request, visible in the self-traffic ledger.
### M10 — Connectors v1
Goal: the Connector framework, Pi-hole v6 (POST /api/auth session ID, app password) and AdGuard Home, read-only; the credentials vault; the Sources tab.
Acceptance: conformance tests against recorded API fixtures; scenario 29; credentials never appear in logs or bundles.
Demo: after adding Pi-hole, the coverage card shows "lookups for 23 devices (Reported)".
### M11 — Investigations and narratives
Goal: "Why is it slow?", the bandwidth mystery, episodes, periodicity, the hypothesis board, template narratives.
Acceptance: each investigation on scripted replays reaches the planted cause, or answers "can't tell from here" when the cause is invisible.
Gate: no narrative contains a claim above its evidence level (automated check).
### M12 — Map v3, accessibility, French, reports v2
Goal: layered map with saved positions, edge styles and overlays; list twin; keyboard audit; high-DPI; FR string catalog; the redaction engine and preview; printable inventory.
Acceptance: a 300-device synthetic map redraws in ≤ 16 ms per frame on interaction; a redaction leak test finds no originals in output.
### M13 — Signed updates and data packs
Goal: an Ed25519-signed release manifest, signed data packs (service catalog, DoH list, fingerprints), release checklist automation.
Acceptance: wrong-key, truncated-download and downgrade tests refuse; rollback after a forced bad start.
Gate: a signed 4.0 release built from a clean checkout reproduces the same file hash.
## 18. Risk register and adversarial critique
The red-team pass found 34 risks. The most dangerous are not technical: they are the plan quietly overstating what a PC can see, and a 25,000-line single file becoming unmaintainable. Severity (Sev) and likelihood (Lik) are rated H, M or L.
# | Risk or blind spot | Area | Sev | Lik | Mitigation | Evidence it's handled | 
1 | Users read the coverage card and still assume the device list is complete | Truthfulness | H | H | "At least N devices" wording; heard-not-seen glyph; "Why can't I see…?" helper | Usability test in M5 | 
2 | The lookup→connection window links the wrong device when two devices resolve the same name together | Correctness | M | M | Require the same device for DNS and flow; ambiguity marked when two candidates exist | Replay with concurrent lookups | 
3 | The fast parser silently mishandles VLAN, PPPoE or IPv6 extension headers | Correctness | H | M | Unknown encapsulation → deep parse; fuzz + replay corpus per encapsulation | Fuzz suite counts "unknown" frames | 
4 | The GIL still limits a single analysis thread below target | Performance | M | M | Profile first; then the #121 gate | --bench busy result | 
5 | recv_raw behaves differently on Npcap vs Linux vs BPF | Capture | H | M | Per-backend adapter + automatic fallback to the 3.0 path | Lab test matrix | 
6 | SQLite write volume wears SSDs or fills disks | Resources | M | M | Summaries by default, batch writes, retention budget forecast, disk guard | 7-day run disk numbers | 
7 | WAL file grows without checkpoints during long reads | Storage | M | L | Periodic wal_checkpoint(TRUNCATE) when readers are idle | Long-haul WAL size | 
8 | Migration bugs destroy history | Data integrity | H | L | Backup before migrate; transactional; tested downgrade refusal | Scenario 37 | 
9 | Managed runtime download blocked by corporate proxy or antivirus | Install | M | H | Degraded mode on the existing Python; system proxy honoured; clear message; offline kit later | Scenarios 5, 1 | 
10 | python-build-standalone lacks Tk on a target | Install | H | M | Verify before M6; fall back to python.org or the system Python | Open question 1 | 
11 | The Windows per-user installer flags behave unexpectedly (registry, Apps list) | Install | M | M | Lab-test in M6; document the uninstall path; prefer the Install Manager when ready | Lab notes | 
12 | The whole file must stay 3.8 grammar, which limits modern syntax | Maintainability | L | H | Accept it; the gate test makes it explicit; modern libraries are still allowed | Grammar test | 
13 | One file becomes too large to navigate (25k+ lines) | Maintainability | H | H | Module banners with exports, a test against cross-section private access, an index comment at the top, a hard 30k-line budget (above it, move data such as glossaries into data packs) | Size check in CI | 
14 | Unelevated Windows mode breaks ARP sending | Capture | M | M | Npcap allows sending without admin when installed with defaults; if sending fails, fall to Quiet-only with a message | Lab test | 
15 | Per-network consent annoys users who move often | UX | M | M | One prompt per network, remembered; a default of "ask" vs "always quiet" in Settings | Usability test | 
16 | Network fingerprint changes when the router is replaced | Correctness | M | M | Treat it as a new network but offer "This is still Home" (link fingerprints) | Scenario test | 
17 | Evidence badges add clutter and confuse beginners | UX | M | M | Beginner view shows only the weakest badge per row plus a legend tooltip | Usability test | 
18 | Inspector pane squeezes tables on 1366×768 screens | UX | M | H | Auto-collapse under 1,280 px wide; overlay mode | GUI test at that resolution | 
19 | QUIC Initial parsing labelled as "decryption" alarms users or looks unsafe | Trust | M | M | Precise wording and a Help entry on why it's public | Copy review | 
20 | QUIC v2 or new versions break the parser | Correctness | L | M | Version check; unknown version → "name not visible" | Test vectors | 
21 | Pi-hole and AdGuard API changes break connectors | Integrations | M | M | Recorded fixtures per version; stale state rather than crashes | Conformance tests | 
22 | Connector credentials stored insecurely on Linux without Secret Service | Security | M | M | Ask each session there; never plaintext | Test on a minimal Linux | 
23 | Reported data treated as truth when the router's clock is wrong | Truthfulness | M | M | Compare connector timestamps with local time; flag skew; data-quality auditor | Skewed fixture test | 
24 | Double counting when the same flow is seen by capture and NetFlow | Correctness | M | M | Source-aware flow keys; reconciliation view; Reported never added to Observed | Dedup test | 
25 | Investigation hypotheses read as authoritative diagnoses | Truthfulness | H | M | Ranked with confidence; "can't tell from here" is allowed; alternatives always shown | M11 gate | 
26 | Narrative templates combine claims into an overclaim | Truthfulness | M | M | Slot level checks; a test injects low-level claims | M11 gate | 
27 | Redaction misses names inside free text (notes, SSDP strings) | Privacy | H | M | Redact by known entities and by patterns (IP, MAC, hostname-like); a leak test | M12 leak test | 
28 | The self-traffic ledger is incomplete, so the kill switch leaks | Privacy | H | L | One outbound gateway function for all app-initiated network I/O; lint test forbids direct urlopen or socket elsewhere | Static check | 
29 | Hostile pcap files exhaust memory in deep parse | Security | M | M | Size caps per record; streaming; time budget per packet | Fuzz suite | 
30 | Thresholds tuned on synthetic data produce noisy alerts in real homes | Product | M | H | Calibrate locally from the calibration page; conservative defaults; new detectors start at INFO | Calibration page after a week | 
31 | Plan assumes the user wants French and accessibility work early | Product | L | M | Kept in M12; easy to move | Your answer to open question 6 | 
32 | Dates and effort are unknown, so the plan looks more certain than it is | Planning | M | H | No dates; effort letters only; gates decide progress | This document | 
33 | Tests prove the synthetic world but not real networks | QA | H | M | Lab checklist per milestone; a request for anonymised real captures from you | Lab notes | 
34 | Signing key loss or theft halts updates or enables fakes | Supply chain | H | L | Offline key, documented rotation, two-key manifest support | M13 key-rotation test | 
### 18.1 Strongest counterarguments to the plan itself
"Just keep scapy and buy a faster PC." The 270 µs is per packet on one GIL-bound thread. A faster CPU gains maybe 1.5x, not 7x. The measurement stands.
"SQLite in a GUI app is overkill." Without durable observations there is no "what changed", no exact split and no comparison. In-memory dicts already exceed 17 MB at modest load.
"A private Python is heavy." About 100 MB of disk in exchange for an end to "works on my Python" failures. Users can refuse and stay on degraded mode.
"One file is the wrong packaging for this size." True as engineering taste, but it is your hard requirement. The plan contains the cost with banners, exports, tests and a size budget.
## 19. Revised plan after self-critique
The red-team pass changed twelve decisions. The biggest: all app-initiated network traffic now goes through one gate function, and Beginner view shows only one evidence badge per row.
### 19.1 Decision log
# | Before critique | After critique | Triggered by | 
1 | Each feature makes its own network calls | One outbound() gateway logs every send to the self-traffic ledger and honours the kill switch; a static test forbids direct urlopen or socket.connect elsewhere | Risk 28 | 
2 | Evidence badges on every column | Beginner view shows the weakest level per row only, with a legend tooltip; Advanced shows per-cell badges | Risk 17 | 
3 | Inspector always docked | Auto-collapses below 1,280 px into an overlay | Risk 18 | 
4 | New router = new network | Offer "This is still Home" to link fingerprints | Risk 16 | 
5 | Lookup→connection matched by IP and time only | Must also match the same device, and is marked ambiguous when several devices resolved the name | Risk 2 | 
6 | Fast parser decides everything it can | Any encapsulation it doesn't fully understand goes to deep parse and is counted | Risk 3 | 
7 | Connector data merged into counters | Reported numbers live beside observed ones in a reconciliation view; never summed | Risk 24 | 
8 | Reverse DNS always on (3.0) | Only in Active Mode, because it sends queries | Privacy review, 13.2 | 
9 | python-build-standalone everywhere | python.org installer first on Windows, because those builds don't ship vcruntime140.dll; Tk availability to be verified before M6 | Risks 10, 11; the PBS docs | 
10 | Elevate the app at launch on all OSes (3.0) | Unelevated on Windows when Npcap allows it; elevation only for installs | Least-privilege review, 12.6 | 
11 | No limit on file size | A 30,000-line budget with data moved to packs beyond it; an export list per section | Risk 13 | 
12 | Investigations always pick a culprit | "Can't tell from this vantage point" is a valid ranked outcome | Risk 25, Challenge 6 | 
### 19.2 What did not change, and why
Strategy A. No risk argued for a big-bang rewrite, and the measurements still favour fixing the pipeline first.
SQLite as the store. Its standard-library availability outweighs the write-volume risk, which batching and retention contain.
Tkinter. The current UI's identity and theme engine are built on it. Its limits (no accessibility tree on Canvas, no native virtual list) are handled with the list twin and a virtualised Treeview, not with a toolkit change.
## 20. Implementation handoff contract
These rules bind whoever writes the code, me included: work one milestone at a time, keep 3.0 behaviour green, and ship nothing that a test didn't see.
### 20.1 Coding rules
One file. miniwireshark.py stays the only source file. Runtime data (cache, DB, logs, runtime, wheels) lives in the data folder.
Python 3.8 grammar everywhere. Gate test: ast.parse(src, feature_version=(3, 8)). Newer standard-library calls sit behind sys.version_info checks.
Section discipline. Each numbered banner starts with an Exports: comment. No code reaches another section's _private names (a test checks this). New code goes into the section that owns the concern.
Threads. Widgets only on the Tk thread; model mutations only on the analysis worker; SQLite writes only on the writer. Cross-thread communication through the defined queues (RawRing, Command, UiDelta, _async_results).
Truthfulness. Every function that produces something user-visible returns a Claim (or takes one). No string concatenation of findings outside narrative templates.
Outbound traffic goes through outbound() only.
Text from the network goes through sanitize_text() before any widget, log or report.
Exceptions. Narrow except clauses. Broad catches only at thread tops and GUI callbacks, and they must log with context.
Theme. New colours are tokens in THEMES/PALETTES, never hex literals in widgets. The dark-mode audit test enforces this.
Settings. Every new option is declared in SETTINGS_PAGES with plain-English help and a default (existing test).
Wording. Hedged words for inferences ("Likely", "Possibly", "Pattern looks like"). Never "hacked", "visited" (without a connection) or "offline" (without coverage).
No new dependency without a row in the section 12.4 matrix, a lockfile entry, and a fallback that keeps the app running.
### 20.2 Per-milestone workflow
Re-read this plan's milestone and its acceptance list.
Write or extend the tests first (golden replay, unit, scenario).
Implement in small steps; run --self-test after each step.
Run the full gate: the commands below.
Update the release notes with user-visible changes, migrations and known limits.
Deliver the single file plus a short report: what changed, what was verified, and what wasn't (and why).
### 20.3 Verification commands
### 20.4 Release and rollback checklist
All gates of the milestone pass on Linux; lab items for Windows and macOS ticked or listed as unverified.
Golden replay diffs are explained in the release notes.
Config and session migrations tested from 2.x and 3.0 files.
Lockfile regenerated and hashes verified; dependency matrix updated.
SCRIPT_VERSION, SESSION_SCHEMA_VERSION, CONFIG_SCHEMA_VERSION, store schema version bumped where needed.
Manifest signed (from M13); file SHA-256 published.
Rollback rehearsed: install the new file, force two failed starts, confirm the previous version returns.
Privacy check: the ledger and outbound list match section 13.2.
## 21. Open questions and research backlog
Ten questions remain. Each already has a provisional answer, so none of them blocks M0–M5.
### 21.1 Facts to verify before the milestone that needs them
# | Question | Needed by | Provisional choice | 
1 | Do python-build-standalone install_only builds include a working Tcl/Tk (tkinter) on Windows, macOS and Linux? The docs I read don't say. | M6 | Assume no on Linux; use python.org on Windows; test on macOS before relying on it | 
2 | Do the python.org 3.14 Windows installer's per-user silent options still behave as in older releases, and what is left in the registry and Apps list? Can PEP 773's Install Manager install into a private folder? | M6 | python.org installer per-user; switch provider when the Install Manager is proven | 
3 | The licences of Wireshark's manuf file and Disconnect's services.json for automatic download and local caching | M1 (shown in Privacy settings) | Keep both opt-in, show source and licence when known | 
4 | Can an OpenWrt 24.10 rpcd user with a read-only ACL log in over HTTP? Forum reports say non-root logins are refused. | After M10 | OpenWrt connector stays P2 | 
5 | Maintenance status of pysnmp | After M10 | SNMP stays "not now" | 
6 | Current ECH deployment (the source I read is from Nov 2023) | M8 copy | Treat ECH as common for Cloudflare-hosted sites; wording already handles it | 
7 | cryptography wheels for Windows ARM64 on Python 3.14 | M8 | QUIC names optional; disabled when the wheel is missing | 
### 21.2 Decisions that are yours
# | Question | Your answer (2026-10-18) | 
8 | Private ~100 MB Python, or stay on whatever Python runs it? | Private Python, so it stays reliable on many computers | 
9 | Which helpers do you run at home? | A standard ISP router. 4.0 must work fully for that beginner setup; Pi-hole and AdGuard Home stay as optional connectors for power users | 
10 | Languages and accessibility | English, French and Spanish, translated last. Accessibility = a new Accessibility page in Settings with colour-blind modes for the most common types (red-green: deuteranopia, protanopia; blue-yellow: tritanopia), plus the existing text size and high contrast | 
Two more useful inputs: a few anonymised real captures from your network (to calibrate thresholds, risk 30), and whether Windows is your only daily platform (it would let M6 lab work focus there).
## 22. Final self-audit
The plan meets all twelve product rules on paper. Three of them can only be proven in a lab with real Windows, Wi-Fi and Npcap hardware, and I have not done that.
### 22.1 Against the non-negotiables
# | Rule | How the plan meets it | Status | 
1 | Single source file | All modules stay in miniwireshark.py; caches, DB and runtime are runtime data; 30k-line budget | Met | 
2 | Autonomous install | Three-layer bootstrap, consent screens, repair, rollback | Designed; lab-unverified | 
3 | Modern runtime | Private CPython 3.14 with a hashed lock; 3.8-grammar entry point | Designed; Tk question open | 
4 | Keep the UI identity | Header, banners, 13 tab names, themes kept; inspector added | Met | 
5 | Expand, don't remove | Every 3.0 capability mapped to its 4.0 home (2.3, 3.2); the old capture path kept as a fallback for one release | Met | 
6 | Zero imaginary visibility | Five evidence levels, coverage model, the 4.1 matrix as test cases | Met by design; enforced by M5 tests | 
7 | Entity separation | Separate types for device, interface, binding, remote host, domain, flow, service | Met | 
8 | Real-world conditions | 40 scenarios incl. sleep, VPN, randomised MACs, IPv6, offline | Designed; lab-unverified | 
9 | Speed and efficiency | Measured baseline; bounded queues; 15k pkt/s target with gates | Target unproven until M2 | 
10 | Transparent and trustworthy | Badges, proof chips, freshness, uncertainty footer | Met by design | 
11 | Safe, authorised use | Per-network consent, outbound gateway, explicit exclusions | Met | 
12 | Designed for change | Section modules with exports, registries, connector base class, data packs | Met | 
### 22.2 Deliverables the brief asked for
150 ideas across 22 domains, plus 16 from the challenges.
Three strategies compared.
40 scenarios.
34 risks.
12 decisions changed by critique.
14 milestones with gates.
Three diagrams and one chart.
No section is unfinished.
### 22.3 What is verified and what is not
Verified in this session:
the source identity and structure;
the per-stage costs and memory per row;
the struct header-parse experiment;
the profiler hotspot;
the current Python release status (3.15.0 released 2026-10-09; 3.14.8 current);
Npcap 1.89 (2026-09-12) and its licence terms, and that silent install is OEM-only;
pktmon's etl2pcap availability on Windows 10, 11 and Server 2016+;
python-build-standalone's flavours and its missing VC++ runtime on Windows;
scapy 2.8.0 being the last release for Python 3.7 and 3.8;
iptoasn's PDDL licence;
Pi-hole v6's session-based authentication;
what ECH hides.
Not verified: anything on Windows or macOS, real Wi-Fi, the open questions in section 21, and every performance target (marked as targets).
### 22.4 Ambition check
If delivered, a 4.0 user gets:
7x more traffic analysed;
every claim provable down to its packets;
an honest map of what this PC can and can't see;
a daily "what changed";
a guided answer to "why is it slow";
whole-network DNS when Pi-hole or AdGuard is present.
It remains a defensive tool for the user's own network, with the same look and the same plain English. The plan aims high in the experience and conservatively in the claims, which is what the brief asked for.
### Sources
Python active releases (python.org)
Npcap home — version and licence
Npcap Users' Guide — installer options
pktmon etl2pcap (Microsoft Learn)
python-build-standalone — running the distributions
scapy changelog
iptoasn enrichment and licence (Netdata docs)
Pi-hole v6 API authentication (Pi-hole forum)
Security control changes due to TLS ECH (CIS)
What is PEP 773 (pydevtools)
