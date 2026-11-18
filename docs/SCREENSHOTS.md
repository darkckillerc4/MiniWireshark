# Screenshots

Every tab of MiniWireshark **5.3.4**, plus the screens new in 5.3.4, taken in **Demo Mode** at 1440×900. The data is simulated and every website is a reserved `example.com`, `.org` or `.net` name. Nothing was captured.

The pictures follow your GitHub theme: switch between light and dark to see both. All 34 files are in [`assets/screens/`](assets/screens/). To take your own, start `python miniwireshark.py --demo` and look around; `--gui-shots DIR` photographs every tab of a synthetic network for developers.

**New in 5.3.4:** [Story mode](#story-mode) · [Unusual activity](#unusual-activity) · [Guided questions](#guided-questions)

## Dashboard

Three questions answered at a glance: is anything wrong, who is using the Internet, and what is new. Every card opens its evidence.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-dash.png">
  <img src="assets/screens/light-dash.png" alt="Dashboard tab, demo data" width="100%">
</picture>

## Happening

A plain-English feed of what the network is doing right now.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-feed.png">
  <img src="assets/screens/light-feed.png" alt="Happening tab, demo data" width="100%">
</picture>

## Timeline

Devices joining and leaving, alerts and changes, in order, with filters.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-timeline.png">
  <img src="assets/screens/light-timeline.png" alt="Timeline tab, demo data" width="100%">
</picture>

## Devices

Everything on your network with its type, maker, confidence level and evidence.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-devices.png">
  <img src="assets/screens/light-devices.png" alt="Devices tab, demo data" width="100%">
</picture>

## Map

Your network as a picture: router, devices, and the Internet beyond.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-map.png">
  <img src="assets/screens/light-map.png" alt="Map tab, demo data" width="100%">
</picture>

## Health

Wi-Fi, router, DNS and Internet checks, with what each result means.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-health.png">
  <img src="assets/screens/light-health.png" alt="Health tab, demo data" width="100%">
</picture>

## Alerts

Security and health findings, each with why it was flagged and what to check.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-alerts.png">
  <img src="assets/screens/light-alerts.png" alt="Alerts tab, demo data" width="100%">
</picture>

## Websites

The sites your devices reach, grouped by name, with trackers marked.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-websites.png">
  <img src="assets/screens/light-websites.png" alt="Websites tab, demo data" width="100%">
</picture>

## Connections

Every flow: who, where, how much and for how long.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-connections.png">
  <img src="assets/screens/light-connections.png" alt="Connections tab, demo data" width="100%">
</picture>

## Internet hosts

Public addresses contacted, kept apart from your own devices.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-remote.png">
  <img src="assets/screens/light-remote.png" alt="Internet hosts tab, demo data" width="100%">
</picture>

## Packets

The packet workspace: list, dissection tree, hex view, streams and filters.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-packets.png">
  <img src="assets/screens/light-packets.png" alt="Packets tab, demo data" width="100%">
</picture>

## Security

Your router, DHCP, DNS and encryption checked, in plain sentences.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-security.png">
  <img src="assets/screens/light-security.png" alt="Security tab, demo data" width="100%">
</picture>

## Sources

Where every piece of information comes from, and how much to trust it.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-sources.png">
  <img src="assets/screens/light-sources.png" alt="Sources tab, demo data" width="100%">
</picture>

## Help

Built-in guides, a glossary and the Quick Start.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-help.png">
  <img src="assets/screens/light-help.png" alt="Help tab, demo data" width="100%">
</picture>

## New in 5.3.4

### Story mode

The Timeline told as a story: what changed, day by day, in plain sentences, with repeats grouped together.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-story.png">
  <img src="assets/screens/light-story.png" alt="Timeline in Story mode, demo data" width="100%">
</picture>

### Unusual activity

At the top of the Security tab. Each device is compared with what it usually does, and anything odd is shown with the worrying and the innocent reading side by side. Here, in the demo, nothing is unusual.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-unusual.png">
  <img src="assets/screens/light-unusual.png" alt="Security tab with the Unusual activity section, demo data" width="100%">
</picture>

### Guided questions

Seven questions, such as *Why is my Internet slow?*, *Is it my Wi-Fi or the Internet?* and *Why does my call stutter?* Each explanation is ranked Likely, Possible or Unlikely, with the evidence for and against it. When it can't tell from this computer, it says so.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/screens/dark-investigate.png">
  <img src="assets/screens/light-investigate.png" alt="Why is my Internet slow? investigation window, demo data" width="100%">
</picture>
