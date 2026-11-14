<!-- Written by .github/scripts/reference_docs.py from the alert tables in miniwireshark.py. Edit the tables, then run the script; CI fails when this page is out of date. -->

# Alerts reference

Every alert MiniWireshark can raise, in the words the app uses. An alert means *worth a look*, not *hacked*. **Danger** is kept for strong, specific evidence, never for "unusual" alone.

Each alert in the app also shows what was seen, the evidence behind it and a confidence. You can turn each kind off or change its threshold in **Settings → Alerts**, and snooze it from the alert itself. Alerts that compare against "normal" wait until the device has a baseline. See [Features](FEATURES.md#is-anything-wrong) for how that works.

There are 27 kinds:

| Alert | Severity |
|---|---|
| [Possible ARP spoofing](#possible-arp-spoofing) | Danger |
| [Address on a public blocklist contacted](#address-on-a-public-blocklist-contacted) | Warning |
| [DHCP anomaly](#dhcp-anomaly) | Warning |
| [DNS server changed](#dns-server-changed) | Warning |
| [Duplicate IP address](#duplicate-ip-address) | Warning |
| [Excessive broadcast traffic](#excessive-broadcast-traffic) | Warning |
| [Gateway identity changed](#gateway-identity-changed) | Warning |
| [Login sent without encryption](#login-sent-without-encryption) | Warning |
| [Many DNS failures](#many-dns-failures) | Warning |
| [New service used](#new-service-used) | Warning |
| [Possible scanning pattern](#possible-scanning-pattern) | Warning |
| [Rapid reconnect/disconnect](#rapid-reconnectdisconnect) | Warning |
| [Remote-access service seen](#remote-access-service-seen) | Warning |
| [Repeated connection resets](#repeated-connection-resets) | Warning |
| [Slow DNS](#slow-dns) | Warning |
| [Unexpected IPv6 router announcement](#unexpected-ipv6-router-announcement) | Warning |
| [Unknown / unconfirmed device](#unknown--unconfirmed-device) | Warning |
| [Unusual upload spike](#unusual-upload-spike) | Warning |
| [Unusually chatty device](#unusually-chatty-device) | Warning |
| [Unusually many destinations](#unusually-many-destinations) | Warning |
| [Unusually many new connections](#unusually-many-new-connections) | Warning |
| [New advertised service](#new-advertised-service) | Info |
| [New country contacted](#new-country-contacted) | Info |
| [New device](#new-device) | Info |
| [Several DNS servers in use](#several-dns-servers-in-use) | Info |
| [Unencrypted protocol in use](#unencrypted-protocol-in-use) | Info |
| [Unusual download spike](#unusual-download-spike) | Info |

## Possible ARP spoofing

**Severity:** Danger · **Usual confidence:** High

**Why it is flagged:** The same address was claimed by different hardware back and forth within a minute.

**What it usually means:** Sometimes a router restart or a device with two network cards; rarely, a machine trying to sit between devices and the router.

**What to check:**

1. Disconnect from this network on any device you're unsure about.
2. Open your router's admin page from a device you trust and check its connected devices.
3. Restart the router; if this returns immediately, look for a device that shouldn't be there.

## Address on a public blocklist contacted

**Severity:** Warning · **Usual confidence:** Medium

**Why it is flagged:** The address is on a public list of malicious servers you turned on in the Components Center.

**What it usually means:** Usually a shared server or an old list entry; sometimes a link to a site known for trouble.

**What to check:**

1. Look at which device contacted it and whether that was expected (an app, an update, a link someone opened).
2. A list entry is a reason to look, not proof: shared servers and old entries are common.

## DHCP anomaly

**Severity:** Warning · **Usual confidence:** High

**Why it is flagged:** More than one device answered DHCP requests.

**What it usually means:** Usually a second router or access point handing out addresses by mistake.

**What to check:**

1. Check whether a second router or access point was plugged in recently.
2. Unplug anything you don't recognize and see whether the second DHCP server disappears.

## DNS server changed

**Severity:** Warning

**What it usually means:** Usually a VPN, a new router setting or an app with its own DNS.

**What to check:**

1. Did you (or an app/VPN) just change DNS settings? Then this is expected.
2. Otherwise, check the DNS settings in your router and on the device.

## Duplicate IP address

**Severity:** Warning · **Usual confidence:** Medium

**Why it is flagged:** Two different hardware addresses claimed the same IP address.

**What it usually means:** Usually two devices set to the same fixed address, or a device that kept an old lease.

**What to check:**

1. Check for two devices set to the same fixed IP.
2. Renew the lease (reconnect the device) and see if it stops.

## Excessive broadcast traffic

**Severity:** Warning

**What it usually means:** Usually a misbehaving device or a network cable loop.

**What to check:**

1. A misbehaving device or a network loop can flood the network.
2. Unplug recently added network cables/switches and see if it stops.

## Gateway identity changed

**Severity:** Warning · **Usual confidence:** Medium

**Why it is flagged:** Your router's hardware (MAC) address changed during this session.

**What it usually means:** Usually a router restart, firmware update or a replaced router.

**What to check:**

1. Did you just restart, update or replace the router? If yes, this is expected.
2. If not, check the router's admin page and its connected devices before trusting this network.

## Login sent without encryption

**Severity:** Warning · **Usual confidence:** High

**Why it is flagged:** A sign-in was recognised in a reassembled, unencrypted connection (Full Power).

**What it usually means:** Usually an older router, camera, printer or storage box on your own network that only offers a plain sign-in page.

**What to check:**

1. If it is your own router, camera or storage box, look in its settings for a secure (HTTPS) way to sign in.
2. Use a password there that you don't use anywhere else, and change it if this login crossed the Internet.

## Many DNS failures

**Severity:** Warning

**What it usually means:** Usually a provider or router hiccup; sometimes an app asking for names that don't exist.

**What to check:**

1. Check whether websites load normally right now.
2. If not, restart the router; if it persists, try a different DNS server or contact your provider.

## New service used

**Severity:** Warning

**What it usually means:** Usually a firmware update or a new feature in the device's app.

**What to check:**

1. Did the device update itself, or did you add a feature in its app?
2. If not, restart it and check its app for an update; unplug it if it keeps happening.

## Possible scanning pattern

**Severity:** Warning

**What it usually means:** Usually a network scanner you ran yourself, or a device's own discovery feature.

**What to check:**

1. If you ran a network scanner yourself, this is expected.
2. Otherwise, find that device and check what software it is running.

## Rapid reconnect/disconnect

**Severity:** Warning · **Usual confidence:** Medium

**Why it is flagged:** The device went offline and came back many times in a short window.

**What it usually means:** Usually weak Wi-Fi or power saving on the device.

**What to check:**

1. Check the device's Wi-Fi signal and its distance from the router.
2. Look for power-saving or roaming settings on the device.

## Remote-access service seen

**Severity:** Warning

**What it usually means:** Usually remote-desktop or SSH you set up on purpose.

**What to check:**

1. Make sure remote access on that device is something you set up on purpose.
2. Use strong passwords and turn the service off if you don't need it.

## Repeated connection resets

**Severity:** Warning

**What it usually means:** Usually a service refusing connections, a firewall or an ad-blocker.

**What to check:**

1. A website or service may be refusing connections.
2. Firewalls and ad-blockers also cause resets; check if something isn't working.

## Slow DNS

**Severity:** Warning

**What it usually means:** Usually your provider's DNS being slow at the moment.

**What to check:**

1. Run the Health tab's checks to compare router and Internet response times.
2. Slow DNS is often your provider's — a different DNS server can help.

## Unexpected IPv6 router announcement

**Severity:** Warning · **Usual confidence:** Medium

**Why it is flagged:** A device other than your router announced itself as an IPv6 router.

**What it usually means:** Usually a second router, a mesh node or a shared connection (phone hotspot, VM host).

**What to check:**

1. Normal if you have a second router, a mesh system or a device sharing its connection (phone hotspot, VM host).
2. Otherwise find that device: a rogue router announcement can redirect IPv6 traffic through it.

## Unknown / unconfirmed device

**Severity:** Warning · **Usual confidence:** Medium

**Why it is flagged:** The device stayed hard to identify after sending a number of packets.

**What it usually means:** Usually a quiet gadget that hasn't said much yet; confidence grows as it talks.

**What to check:**

1. Give it time — confidence rises as more evidence arrives.
2. Compare its MAC address with the labels on your devices or your router's list.

## Unusual upload spike

**Severity:** Warning

**What it usually means:** Usually a photo backup, a video upload or a call.

**What to check:**

1. Is the device backing up photos, uploading video, or on a video call?
2. If not, check what it is running — large unexpected uploads are worth understanding.

## Unusually chatty device

**Severity:** Warning · **Usual confidence:** Medium

**Why it is flagged:** Traffic this minute is far above this device's own recent average.

**What it usually means:** Usually an update, a backup, streaming or a video call.

**What to check:**

1. Is the device downloading an update, streaming or on a video call?
2. If it should be idle, restart it or look at what it is running.

## Unusually many destinations

**Severity:** Warning

**What it usually means:** Usually updates, cloud sync or peer-to-peer apps.

**What to check:**

1. Is the device updating, syncing a cloud folder, or running a peer-to-peer app?
2. If it should be idle, look at what it is running.

## Unusually many new connections

**Severity:** Warning

**What it usually means:** Usually browsers, games or updates opening many connections at once.

**What to check:**

1. Browsers, games and updates open many connections; check what the device is doing.
2. Restart the device if it should be idle.

## New advertised service

**Severity:** Info

**What it usually means:** Usually something you just enabled: file sharing, casting, a printer.

**What to check:**

1. Did you just install or enable something on that device (e.g. file sharing, casting)?

## New country contacted

**Severity:** Info

**What it usually means:** Usually a content network or cloud service hosted abroad.

**What to check:**

1. Usually normal: content networks and cloud services live in many countries.
2. Only worth a look if the device should rarely use the Internet.

## New device

**Severity:** Info · **Usual confidence:** High

**Why it is flagged:** A device appeared that I haven't seen in this session.

**What it usually means:** Usually a phone, laptop or gadget of someone in the house, or a guest joining the Wi-Fi.

**What to check:**

1. Open your router's connected-devices list and look for this device.
2. If it isn't yours or a guest's, change your Wi-Fi password and re-check.

## Several DNS servers in use

**Severity:** Info

**What it usually means:** Usually browsers, VPNs or apps with their own DNS.

**What to check:**

1. Usually harmless: VPNs, browsers with secure DNS, and some apps use their own DNS servers.

## Unencrypted protocol in use

**Severity:** Info

**What it usually means:** Usually older devices or simple home gear that doesn't encrypt.

**What to check:**

1. Avoid entering passwords on services that are not encrypted.
2. Check whether the device/app offers a secure (TLS) option.

## Unusual download spike

**Severity:** Info

**What it usually means:** Usually an update, a game download or streaming.

**What to check:**

1. Usually an update, a game download or streaming.

## Something here is wrong

If an alert fired when it shouldn't have, or the advice didn't help, please [open an issue](https://github.com/darkckillerc4/MiniWireshark/issues/new/choose). Attach a debug bundle from **Diagnostics**: it masks addresses and secrets.
