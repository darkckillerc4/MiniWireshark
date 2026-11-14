# Changelog

All notable changes to MiniWireshark. Versions follow `MAJOR.MINOR.PATCH`; each release is one `.py` file attached to its [GitHub release](https://github.com/darkckillerc4/MiniWireshark/releases). Checksums are in [docs/VERSIONS.md](docs/VERSIONS.md).

## [5.3.4] — 2026-11-04

A medium release that makes MiniWireshark safer, easier to start and easier to understand. Every finding of the 5.2.3 security audit is fixed in the code (four of the fixes still need a check on real hardware: a Windows PC, a Mac and a real Wi-Fi roam), new screens explain your network to a beginner, and the largest bug campaign so far ran before, during and after the new features.

**Security and privacy**

- **Administrator rights only when needed.** On Linux and macOS, MiniWireshark no longer starts as administrator (root). It asks for your password when capture starts, not at all when the computer already allows capture, and carries on without capture if you say no. The demo and the help never ask.
- **Your files stay yours.** The data folder is closed to other people on the computer, and a folder that belongs to someone else is not used. There is no shared temporary folder any more. Another user can no longer swap the saved copy that speeds up starting, the update rollback copy or the private packages to run their own code.
- **The administrator copy runs nothing of yours.** On Linux and macOS, the copy that runs as root for capture starts Python isolated and runs programs only from the system's own folders. A Python file or program planted in your home folder, or in the folder you started MiniWireshark from, no longer runs as root.
- **The browser never opens as administrator.** When capture runs with administrator (root) rights on Linux or macOS, a local service, a report or a folder now opens as you, not as root.
- **Saving into a shared folder is safe.** A save no longer follows a link that someone else left under its temporary name, so it can't overwrite another file. A table row or chart data copied to the clipboard can't start a spreadsheet formula, the same as a CSV file.
- **The settings file follows the data folder's rule.** It is no longer read from or written to a folder next to the program that other people can write to, so they can't plant settings there; it goes in your data folder instead.
- **A new install asks first.** It no longer trusts the first network it sees or starts Active Scanning by itself.
- **History does what it says.** "Session only" history is really deleted when you close the window. "Delete ALL history" also removes the backups and the saved packet files.
- **"Delete ALL history" deletes everything it names.** It now also deletes the last autosave, the crash copies, your device names and notes, the remembered networks and the list of programs that wait for connections, and its question lists them.
- **History off keeps no session.** With history off (the default), closing the window no longer saves the whole session as an autosave. The trust page now says when health checks run (every 30 seconds, only on a network you marked as yours, to 1.1.1.1 unless you change it) and that reference lists are downloaded only when you ask.
- **Every redirect is listed and can be stopped.** When a download is sent on to another site, that site is listed in the self-traffic ledger and the kill switch stops it; https is never sent on to plain http. Country lookups use only https services, and *Retry* asks only about addresses seen while watching live.
- **Passwords stay out of everything.** Logins, form contents and the private parts of web addresses are hidden in packet details, saved conversations, CSV files and anything you copy, whatever the port. A new warning, *Login sent without encryption*, says who signed in and where, never the password.
- **A fake router is caught.** When a second device claims to be your router, a DANGER alert appears, even if the fake one answers much faster. An IPv6 announcement from another device that tries to take over your network is flagged.
- **The kill switch stops everything.** Package downloads now go through the same gate, so the kill switch stops them too. Device names are looked up only on your own network. Demo Mode downloads nothing. The download list waits for your answer instead of counting down.
- **Updates now come only from the official GitHub page, checked once a day; you can turn it off.** Fake download sites copy MiniWireshark, so the update check asks only [github.com/darkckillerc4/MiniWireshark](https://github.com/darkckillerc4/MiniWireshark/releases), follows no link off GitHub, and only ever shows that page. It sends one request to `api.github.com` and nothing about you. Another source still works if you type one, but it is called *unofficial* everywhere. Turn the check off in **Settings → Updates & Dependencies**; the kill switch, Safe Mode and working offline stop it too.
- **A new install is told about the update check too.** Its first automatic check (a few seconds after the first start) shows that MiniWireshark checks GitHub once a day and how to turn that off. Only upgrades were told before.
- **Connected helpers:** a Pi-hole or AdGuard Home certificate is checked before the password is sent.
- **Windows:** the Npcap installer is no longer refused by its own signature check. **macOS:** an apostrophe in a folder name can't break the administrator prompt, and Wi-Fi is found without Apple's removed `airport` tool.
- **Help → About** shows the version, the MIT licence and the Wireshark trademark notice.

**New features**

- **Ready?** The Welcome Center shows one list: Python, capture driver, capture permission, network card, data folder, history, signed updates and what leaves this computer. Each line says whether it is ready, with a fix button where one exists. `--boot-check` prints the same list, so the two never disagree.
- **Story mode.** The Timeline can tell what changed in plain sentences, day by day, newest first. Repeats are folded ("Phone left and came back 6 times"), and a line marks what is new since you last looked. A Dashboard card says how many changes are waiting. A traffic spike on this computer names the program: "At 14:02 chrome.exe on this computer sent 80.0 MB in one minute".
- **Better device names.** Apple model codes become product names ("MacBook Pro"), and DHCP clues suggest when two entries are probably the same device. When the evidence disagrees, the device card says "But:". On a test set of 65 devices, 64 get the right kind.
- **A baseline that knows day from night.** Each device has a day and a night profile, starts from what is normal for its kind, and is judged after 5 minutes instead of 15. What it learned more than 14 days ago is forgotten. The device card says what it has learned so far. A new alert, *New service used*, appears when a one-job device suddenly reaches a service it never used.
- **Unusual activity** at the top of the Security tab: one card for each unusual thing, with *Could be a problem* and *Could be normal* side by side, what was seen and one next step. A Dashboard card opens it.
- **Snooze an alert** for 1 hour, 1 day or until tomorrow, for one device or for all. A DANGER alert can be snoozed for a day at most, and the Alerts tab says how many alerts are held back.
- **Seven guided questions instead of two.** New: *Is my DNS working?*, *Is IPv6 working?*, *Why can't this device connect?*, *Is it my Wi-Fi or the Internet?* and *Why does my call stutter?* Each lists the likely causes with the evidence for and against, never a verdict, and says "Can't tell from here" when it can't. They are in `Ctrl+K`, the Alerts tab and **Health → More questions…**
- **Calls.** A Calls card under Health shows how many packets video and voice calls lose and how uneven they arrive, read from packet headers only, never the call itself. It says so when a call app can't be measured.
- **Network check-up.** **Export → Network check-up…** writes one page in plain English: what is ready, what changed, unusual activity, the seven questions and your devices. Names and addresses are hidden unless you turn that off. Print it, or save it as PDF from the browser.
- **Notifications while minimised** (off until you turn them on in **Settings → Alerts → Where alerts appear**). The window title counts new DANGER alerts, the taskbar button flashes on Windows, and an optional silent Windows notification appears at most once a minute. It names no device unless you ask, and never shows an address.
- **Local services.** **Websites → Local services** lists the programs on this computer that wait for connections: the port, the program, what it probably is ("Web app in development" for 3000 or 5173, printing for 631, PostgreSQL for 5432) and who can reach it: *Only this computer can reach it* or *Other devices on your network can reach it*. Each web port is asked once for its home page (plain HTTP, then HTTPS without checking the certificate; 1 second, 64 KB, no redirect followed, listed in the self-traffic ledger, never in Demo Mode), so the list shows whether it is a web page, its title and http or https; **Refresh** asks again. Databases, Redis, raw printing (9100) and file sharing are never asked. Double-click a web app, or press **Open in browser**, to open it at 127.0.0.1, or at this computer's own network address when it listens only there. That is listed in the self-traffic ledger and the kill switch stops it. Without the optional psutil component the list and program names come from Windows' netstat and tasklist, Linux's /proc or lsof. When the list can't be read without administrator rights, it says so.
- **Your own blocklist.** Load a text file of addresses, ranges or website names from the Security tab (**Your own blocklist…**). It stays on your computer and is never downloaded. Private addresses and entries that are too wide are refused, with the reason.
- **Command line.** `--help` and `--version` work. An unknown switch or a missing value ends with a one-line explanation. `--self-test NAME` runs one test. Starting without a screen no longer forces Safe Mode next time.
- **Clearer words.** A filter you type is said in words under the box. The Beginner view says what happened ("asked the network which device has 192.168.1.1") instead of naming ARP, QUIC or MAC, and calls a MAC a hardware address. Grey text meets the WCAG AA contrast level, so it is easier to read. On Windows the title bar turns dark with the dark theme. Everything new is in French and Spanish.

**Speed and memory**

- **Faster start on Windows.** The window now starts from the saved compiled copy, as on Linux and macOS. On a Windows PC the first start went from about 14 to under 5 seconds, and the window's memory from about 440 to about 220 MB.
- Packets are analysed about a fifth faster (69 instead of 87 microseconds each on the home test network).
- When a live capture can't keep up, deep analysis pauses and packets are only counted, with a plain line saying so. It comes back after 5 calm seconds.
- Memory stays flatter over long runs. In an 80-minute stress replay it grows 5.3 MB an hour after the first hour (it was 7.5), and no freeze is longer than half a second. Past 500 departed devices, the oldest unnamed ones leave memory.
- **Memory levels off within a day.** Every list that could grow with time was checked:
  - Lists that had no limit now have one. They are web hosts, VPN servers, encrypted-DNS users, DNS servers, half-finished web and chat requests, and mail reconnects.
  - What the DNS tracker knew about a device now leaves with the device.
  - The list of websites keeps at most 10,000 (it was 20,000).
  - The memos that speed up address handling keep at most 16,384 entries each (they were 65,536).
  - The list of the names each address answered for now takes about half the memory.
  - A device keeps the 16 IPv4 addresses it used most recently. Before, it kept any 16, so it could drop the address it was using.
  - When the list of finished connections is made shorter in Settings, the connections it drops now really leave memory.
  - Old history now also removes its records of saved packet files. Before, these records stayed after the files were deleted.

  This was measured in a 30-hour fast replay of the analysis, with 20 devices that meet 40 new websites a minute. From hour 6 to hour 30, memory grew by 6 MB, and not at all after hour 24. Before these changes it grew by 33 MB and was still growing at hour 30.
- **The window keeps fewer rows.** The Remote hosts table keeps at most 5,000 rows. The Alerts tab drops the rows of alerts that the alert list has already let go. The Timeline and the live feed let go of what they kept for rows they had already removed. The Connections table drops rows for connections that have already been forgotten.
- **Background timers no longer pile up.** The network check and the restart counter now keep one timer each. In the 500-round test, the window's timers grew from 13 to 27; now they stay at 13 to 15.
- **Two new tests: "memory stays flat in fast time".** One runs the analysis, the other runs the whole window through hours of made-up traffic, with the size limits made 80 times smaller so that they fill up:
  - **The analysis test** runs 160 minutes. After minute 100, its memory grew by 14 to 64 KB (the limit is 256 KB). The changes come from lists that fill up and empty again.
  - **The window test** runs 200 minutes, switching tabs and refreshing as it goes. After minute 120, its memory grew by 164 KB (the limit is 2 MB). The window's widgets, timers, bindings and table rows stayed where they were.
- On Windows the capture driver gets a bigger buffer, so short bursts lose fewer packets.
- *Compare sessions* over 90 days of history takes about 60 ms instead of 4.9 seconds.

**Fixes**

- The Timeline's Time column makes room for Story mode ranges such as "22:52–23:07", which were cut off at larger text sizes.
- The Security page no longer repeats its "What is this?" heading: each refresh left one more copy on the Unusual activity line (in every language the page had been shown in).
- Switching to French or Spanish and back leaves every English label as it was. Some came back as another word with the same translation ("Find" as "Search", "Kind:" as "Type:", "Took" as "Duration"). Open device and alert cards change language too.
- Nothing is kept from one right-click menu, refresh or language change to the next: each popup menu, each pointer movement over Settings, each settings change and each restyle of the state line or an empty table's button kept a little more memory until the window closed.
- Damaged or hostile capture, session and settings files end with a message, never a crash or runaway memory. A session file that would unpack past 256 MB is refused.
- Two copies in one folder: a busy database is no longer taken for a damaged one, session numbers never clash, and each crash journal belongs to one copy.
- Windows 11 24H2 hiding Wi-Fi details while Location is off, and German Windows output, are read correctly. MiniWireshark never turns Location on.
- Blocklists with ranges inside ranges, and IPv6 ranges, now match. *Why is my Internet slow?* no longer blames the network for packets the capture itself missed.
- A sleep, a clock change or daylight-saving time no longer restarts the capture, silences alerts or empties the history. A "#" or accents in the data folder name are fine.
- The two packet decoders now agree on unusual packets (296 disagreements fixed). A million damaged packets in a row raise no error.
- Every tab, dialog and settings page fits from 1024×768 to 1920×1080 in all three languages, both themes and four text sizes (the layout check found 51 kinds of problem; now none).
- Errors that used to vanish are logged or shown. The Dashboard and Health always agree. A device has one name everywhere.
- History on a network folder opens. A program on this computer keeps its name when an old connection ends.
- **Ubuntu 22.04:** the window no longer crashes while it opens. Ubuntu 22.04's font library crashes Tk when it draws a colour emoji; MiniWireshark now leaves colour fonts out there, so emoji show in plain form.
- **Repair's quick self-test** takes about 20 seconds instead of up to 6 minutes. It used to run nearly the whole self-test (344 tests at the time). It now runs 62: the core checks, plus the tests for each part Repair looks at (program components, data folder, history database, capture, settings file, update checks). It no longer checks the program's own code, layouts or translations, because Repair can't change those. `--self-test` still runs everything.
- A Windows console with an old code page no longer stops MiniWireshark with a text error; a character it can't show is printed as "?".
- On a small screen, an Inspector switched on in Settings now makes room for the tabs when the window opens narrow, not only when you make the window narrower.
- A text-size change is quicker: the tables, the rows of buttons and the scrolling pages on tabs you can't see are fitted when you open their tab.
- When your computer's address changes (another Wi-Fi network, a VPN switched on), a connection from the old address is no longer named after a different program that happens to use the same port number now. It is left without a program name.
- The search results window opens under the search box instead of over the tabs, takes the keyboard, and closes with Escape or a click elsewhere; the search box gets its text back selected, so typing replaces it.
- Search counts what it lists (it said "0 result(s)" over a list of results), includes the Settings, Health and Help matches the list under the box shows, and ignores hyphens and spaces, so "wifi" finds "Wi-Fi signal (this computer)".
- Settings takes the keyboard when it opens, so Escape closes it. The footer says "No changes yet" until you save something, and closing with unsaved changes asks "Save your changes before closing?", where Yes saves them. Changing Beginner or Advanced in the header no longer shows up in Settings as an unsaved change. A ticked checkbox shows a tick instead of a cross, which looked like "no".
- Ctrl+K knows the tabs by their names ("happening" finds the Happening tab), names every settings entry "Settings › …" with Settings itself first, says when nothing matches, and closes on a click elsewhere. Drop-down lists, number boxes and Dashboard cards show a clear ring when they have the keyboard.
- A rare crash ("Tcl_AsyncDelete: async handler deleted by the wrong thread") can no longer happen when the last piece of a closed window is let go by a background task.
- After an update that didn't start is rolled back, the start carries on: the loading screen and the Welcome Center say what happened. A message box used to stop the start until you clicked OK.
- Opening a packet from the packet history during a busy capture no longer freezes the window for up to 3 seconds.
- **Ubuntu 22.04:** if MiniWireshark can't leave colour fonts out, the log now says so (it said nothing, and the window could crash). It also finds the font library's version from its file name when it can't ask the library.
- A connection is named after its program even when the system writes this computer's address in another IPv6 form, such as `::ffff:c0a8:114`.
- The kill switch is the same everywhere: ticking it in the self-traffic ledger ticks it in an open Settings window too (without "unsaved changes"), turning it off from the banner clears the ledger's box, and the banner, Settings, Help and Ready? all say the same sentence about what it stops. An empty ledger says "Nothing sent or blocked yet."
- The Dashboard and the Security page no longer say "Nothing unusual right now" while the Alerts tab has open warnings; they say how many warnings need a look.
- The Timeline's counter counts the events it lists (it could say "0 events this session" over a list of events), and an event no longer appears twice.
- The Story is written again as soon as the data it tells has changed, so its count matches the Dashboard instead of lagging up to a minute behind.
- The Health verdict says "Partly checked" and names what was not checked yet, instead of "Healthy" over rows that all say Unknown. "Why is it slow?" now agrees with the Health rows about the router and the Internet.
- A weak Wi-Fi signal is called the "likely culprit" only when slowness was actually measured; otherwise it is "worth a look". *Is it my Wi-Fi or the Internet?* says it timed how fast connections open, not download speed.
- Health says why instead of showing a bare "—" (network card, IPv6 prefix, why this card), and the greyed "Run checks now" button says why when you point at it.
- The Dashboard's time window (now called "Time window") sets the period of the "Who is using the Internet?" answer too, and a chart longer than the data says how much data there is.
- The Packets tab's "in memory" count stays current while the display is paused, so it matches Statistics and the I/O graph.
- The Devices tab explains its three ways of saying how sure it is: "Device evidence" (is it a real device, with the score each level needs), the "Evidence" marks, and "Likely" or "Possibly" before a kind.
- *Start watching* on a computer that can't capture no longer clears the demo or the opened file first: it keeps what is on screen and says why it can't watch, with a Repair button. After the demo ends, the status line no longer says Demo Mode.
- *Clear and start fresh* (Ctrl+L) and *New session* now ask before they wipe the session ("Ask before clearing data" is on by default), say whether watching carries on, and whether Undo is possible. Saying No to New session no longer stops watching.
- Alerts now use a device's current name: a renamed device, or one whose name is learned later, is renamed in the Alerts tab too, and this computer is called "This computer" instead of its address or maker. A rule stored with *Expected* names the device and service instead of a raw key such as "02:00:5e:10:00:10|SSH". A device without a name no longer reads "192.168.50.40 got address 192.168.50.40 from DHCP".
- Devices without a name of their own can be told apart in alerts and the Timeline: "Device using a private Wi-Fi address (192.168.1.77)" instead of the same words for each, translated inside French and Spanish sentences.
- Packets tab: the packet details keep room for a few lines in a short window instead of shrinking to their heading; a filter that hides the packet shown in the details empties them; *Pause display* and a filter that matches nothing say so next to the count; the Expert view says why it is empty in Full Power; the Protocol hierarchy headings sit over their own numbers again (they were one column off).
- Printing and saving: the preview of the Network sheet no longer shows its title twice and lists each device on its own lines instead of one run-together paragraph; the preview has a *Print…* button that opens the page in your web browser to print or save as PDF; the sheet and the inventory say when they are demo data; Save and Open dialogs start in your Documents folder instead of the folder MiniWireshark was started from.
- French and Spanish: after a language change, the rows already in the Timeline and the Alerts tab are shown in the new language; the packet list's Info column, the Start watching question, the Help's Start here and Evidence marks pages, a maker's device in a sentence ("Appareil D-Link …") and "This computer" under *Contacted by* are translated.
- Help → Troubleshooting now says how to watch on Linux and macOS (your password when watching starts, or sudo; on Linux the one-time `setcap` capture right) and names the real menu path to Diagnostics, in all three languages. Diagnostics has a *Capture rights* line that says what is missing and what to do.
- The I/O graph draws packets per second, traffic in bits per second and DNS latency as three charts, each with its unit on the axis. Packets per second no longer lie flat at 0 under the traffic line, and the DNS axis no longer shows "0" twice.
- A .pcap file with a packet larger than 1 MB is read to the end. Reading used to stop at that packet with "The file ended early", and every packet after it was lost.
- Capture files: a .pcap that records the Ethernet checksum is decoded as Ethernet again; a .pcapng packet for a network card the file doesn't describe is left out with a note instead of being read as Ethernet; a packet longer than its block, or a block whose two lengths disagree, is reported as damage.
- In French and Spanish, the message at the end of an import keeps "(stopped early)", says "1 paquet" / "1 paquete" instead of "1 paquets" / "1 paquetes", and the "Stopped reading the file" message is translated.
- A packet with many IPv6 extension headers, or with three or more VLAN tags, no longer slows the analysis: 180 extension headers took up to 0.2 seconds a packet, now well under a millisecond.
- A UDP message whose length field claims more than the packet holds shows its real size ("Quick message (2 bytes)", not 65527 bytes). IPv6 carried inside IPv6 is called "IPv6-in-IPv6", not "IPv6-in-IPv4", and the packet details say "truncated" or "this isn't IPv4" instead of "malformed (packed IP wrong length for inet_ntoa)".
- A packet that breaks the decoder is now written in the log, the first of each kind with its details, so it can be reported. It used to be counted silently.
- In Demo Mode, **Websites → Local services** shows made-up services instead of the programs really running on this computer, and opens nothing in the browser. It used to list this computer's own programs under the "Everything shown is simulated" banner.

- `--self-test` passes on a fresh install, before the capture library (scapy) and the optional parts are installed. Three tests assumed they were already there and failed, although the program was fine.

- A settings value MiniWireshark can't use (a theme that doesn't exist, a list where a word belongs, an empty number, a number out of range) is set back to its default with a warning. It used to stop every start, even in Safe Mode, or make a background task fail over and over.
- A settings file saved by Windows Notepad (with a byte-order mark) is read normally. It used to be taken for damaged, and all settings went back to the defaults.
- Two copies of MiniWireshark that share a settings file keep each other's changes. The last one to save used to undo the other's without a word.

- `--boot-check` works on a Python without the window toolkit (tkinter), the most common Linux problem: it says that is what's missing, how to install it, and whether the data folder is fine. It used to print only "needs tkinter". When the window can't open, its Ready? list no longer says "✓ Python and window toolkit" under "Window FAILED".
- With `--no-elevate`, the Ready? list no longer says MiniWireshark will ask for your password when you start watching. `--help` shows that `--bench-gui` takes scenario names; the install guide lists `-h` and `-V`, Homebrew's `python-tk`, and the right box to tick in the Windows Python installer.
- A device that sends a lot to the Internet at night (say 30 MB at 3 am) now raises *Large upload at night* under Unusual activity, once: the next night the same amount is known. A backup to iCloud, Dropbox or OneDrive is said as a backup and doesn't count as unusual.
- A password sent without encryption, in a web form, HTTP Basic or a web address, or with FTP, POP3 or IMAP, now raises *Login sent without encryption* in the normal mode too, not only in Full Power. The password itself is still never read into anything or kept.
- A device that contacts the same server on a timer (30 times or more, nearly evenly spaced) now raises *Regular check-ins to one server*. The clock, a server several of your devices share and uneven contacts raise nothing. The device card counts every contact (it stopped at 24).
- Many long, random-looking names looked up under one domain (a way to hide data in name lookups, "DNS tunnelling") now raise *Data hidden in name lookups*.
- A second DHCP server that hands out a different router is now DANGER and says what it hands out, including when it names itself as the router and the DNS server. MiniWireshark keeps the real router as your gateway, even when the other server answers more often.
- iCloud backups, Netflix, YouTube and other known backup and streaming services no longer show up as unusual uploads, downloads or a busy device; the Timeline still tells the spike.
- During ARP spoofing, the attacker's claim on another device's address no longer adds a "Duplicate IP address … often harmless" warning, and the Story says "Danger" for a DANGER alert (and "Aviso" in Spanish, like the Severity column). A port scan says the most ports it tried in a minute instead of the first count seen, and the resets the scan gets back no longer raise *Repeated connection resets* about the scanner.
- The Story no longer says the router "changed its address 24 times" when it simply answers for two addresses, back and forth.
- French and Spanish: an alert's whole text is translated, not only its title: what was seen, what it usually means, the innocent explanations and why it was flagged.
- A new device's alert no longer says "low-confidence" under a High confidence: it says how sure MiniWireshark is of what the device is.
- French and Spanish: a device without a name ("Device using a private Wi-Fi address") is translated inside a translated sentence too, not left in English in the middle of it.
- Timeline Story mode: each day's heading reads "Today · 2 changes" in the *What happened* column, and the *Type* column says what a line is about (Devices, Websites, Alerts …) instead of "×5"; the sentence already says how many times.
- The Dashboard's ALERTS card names its counts ("Danger 0 · Warning 1 · Info 5") instead of three bare numbers behind symbols.
- The Map legend says what the letter on a device means: how sure MiniWireshark is that it is a real device (H high, M medium, L low, ? unconfirmed).
- French: a fact another system told MiniWireshark is called "Signalé" everywhere (it was "rapporté" in places), and a correlated one "Corrélé" (it was "Recoupé" in the evidence key).
- Pressing Stop while MiniWireshark was restarting a capture that had stopped by itself no longer starts the capture again a few seconds later.
- The help for the Beginner view now names all the tabs it hides: Connections, Internet hosts, Packets and Sources.
- The help for the downloaded vendor and site lists says what really happens: nothing is downloaded unless you ask (Updates is Manual by default); with Weekly, a missing list is fetched at start and each list again once it is more than 30 days old. The Components Center says the same.
- `--help` shows the scenarios `--bench-gui` takes (S1 S2 S3 S4, or all).
- A download cut off part way (for the private Python or a package) now says "No Internet connection" and resumes next time, instead of failing with a raw error. A message that merely contains "407" (a size, a folder) is no longer taken for a proxy problem.
- The private Python's disk space is one number everywhere: it needs about 300 MB free while it installs (the message said 250 MB, the description 120 MB).
- A failed save of your labels, trusted networks or taught device types leaves no temporary file behind, and a damaged copy of one is set aside once, not again on every start.
- History no longer stops in silence when one batch can't be written: the error is shown and the next batches are saved.
- *Why can't this device connect?* only says "the router answered" when it answered one of the device's recent questions, not one from long before.
- *Why does my call stutter?* no longer says the call's packets "arrived complete" when the capture itself missed packets or some were lost.
- *Is IPv6 working?* counts IPv6 traffic that uses no TCP handshake (QUIC), so a network used over IPv6 is no longer called one that "doesn't offer IPv6".
- "Contacts X about every 60 s (N times)" counts every contact seen.
- A switch port that moves to another VLAN is reported as a VLAN change, not as "Moved to" the same port.
- A French or Spanish text of the Calls card that doesn't fit its numbers falls back to English instead of breaking the card.
- Renaming a workspace to the name of another one asks before replacing it.
- An update whose download isn't a working program now says so (the update failed without a word). If the update was installed but its automatic restore couldn't be set up, the message says that instead of "nothing was changed". A restore of the previous version is copied in one step, so an interruption can't leave a broken program.
- Stopping MiniWireshark with Ctrl+C while it starts ends with exit code 130 instead of 0.
- The network check's DNS lookup gives up at its time limit even when other answers keep arriving.
- The network-card pick reads a card's state when the capture library gives it as a number, and checks "your router is on the same network" against the card's real network instead of assuming a /24.

**Known limits**

- **Opening a capture file still raises a "new device" alert for every device in it, the router included,** so "joined your network" is said of devices that were simply in the file. The wording and grouping of these alerts for a file is planned for a later release.
- **French and Spanish: a few alert sentences built from changing parts may still show English words**, for example a website or provider name inside a translated sentence, or a rare alert's details. The titles and the fixed text of every alert are translated.
- **Spanish Packets Info column:** the audit saw "Secure web browsing (FIN,ACK)" untranslated; on 5.3.4 it is translated ("Navegación web segura (FIN,ACK)") and we could not reproduce the English text, so the case it came from may remain.
- **Extra large text on a small screen (1024×690) is still cramped,** and Extra large doesn't enlarge everything: tab names, the main button, cards and monospace text stay at their normal size.
- **Timeline:** the "N events this session" count above the list can be lower than the number of rows shown, and the Story counts websites by site name (example.com) while the Dashboard counts every name looked up, so their numbers of new websites can differ.
- **Some labels can still be cut off** in French with a small window or an unusual font: the Alerts *Concerne* cell and *Confiance* heading, a Map line that crosses a printer's label, a few buttons that drew empty on one test machine, and the DEMO DATA banner shown twice.
- **One false alarm from the audit is not explained yet:** a phone raised a warning the tester saw as normal use; without the capture we could not tell which rule fired.

- **Changing the text size on Windows is slow.** It takes about 0.4 seconds on the test machine, and the window doesn't answer for about a tenth of a second while it happens (the goal is 0.1 seconds; on Linux it is well under that). The reason: on Windows every part of the window is its own small system window, and when the shared fonts change, all of them (about 700) are measured and drawn again. Making this fast needs a change to how the window shares its fonts, planned for a later release.
- **Not re-tested on a real PC for this release: long-run memory, thread and handle growth on Windows, and the network-card pick with a VPN connected.** The last real 8-hour run was on an older build. On that build memory grew by about 8–9 MB an hour, Python threads went from 13 to 19, system threads from 15 to 24 and handles from 318 to 507. Changes made since then are meant to stop this growth: each background job runs only one at a time, a helper program that hangs is ended together with anything it started, and finished helper programs are closed properly. These changes are checked by automated tests on Linux only, not on a Windows PC, so this is untested, not fixed. The evidence that does exist is the GUI test step "round 8: 500 rounds of the periodic jobs in fast time" (`gt_r8_long_run_fast_time`). It runs the network check, capture start, stop and restart, the programs table, the Wi-Fi check, the update check and the screen refresh 500 times, with helpers that hang, fail or are slow. It then checks that threads, open files and helper processes are back to where they started. It uses a fake capture in place of Npcap, and it does not show how memory behaves over hours. The soak script (`.github/scripts/soak.py`) replays saved packets and never opens Npcap, so it does not cover live capture either. Its "blocks" figure counts memory blocks handed out by Python's small-object allocator (pymalloc), not objects.

- **Memory over long runs was not re-checked with the audits' own replays.** Our own 30-hour replay of the analysis is flat after hour 24 (see *Speed and memory*). The audits' 24-hour replay and the harsh replay at 30 times normal speed were not run again. The harsh replay grew from 575 to 2,175 MB in 11 minutes.
- **When analysis falls behind, packets waiting for it can use up to about 110 MB.** That is at most 150,000 packets or 96 MB of packet data, plus about 0.1 KB of bookkeeping for each packet. This limit is intended and unchanged. In the harsh replay, packets waited at this limit because analysis could not keep up.
- **A device's IPv6 addresses:** a device keeps 12. When it has more, the first ones in alphabetical order are dropped, not the oldest ones, so the address in use can be dropped.
- **Not re-tested on a real PC for 5.3.4:** memory, threads and handles over an 8-hour capture on Windows, and the network-card pick with a real VPN switched on. These were checked only in replays and with simulated network cards.
- **macOS and Linux** fixes were checked in the automated tests (CI) only, not on a real Mac or Linux desktop. The window test does not run on macOS or on Python 3.8.
- **Two messages at start still wait for a click:** "Administrator required" on Windows when the administrator prompt is refused, and "Startup error" when the window can't open. Both end the program, so nothing else waits behind them. The operating system's own password or administrator prompt also waits for your answer.
- **The text-size speed check on Windows is loose.** The GUI test now judges the middle of its six runs, not the quickest, but on Windows it allows 600 ms, about 1.45 times the slowest test machine's usual 414 ms, so a smaller slowdown there passes. A second check compares with an older, slower version on the same machine and fails above 0.80 of it (measured 0.65 to 0.73).
- **The network-card pick on Windows** now prefers the card that Windows' own routing uses (it changes the order of the cards, it doesn't only log). It knows the common VPN cards by name, but may not know every VPN product's name.
- **Started as administrator (root) on Linux, the window uses about 270 MB more memory.** For safety, a root start never uses the saved compiled copy of the program (another user could have planted it), so it compiles the 4 MB file itself, and Python keeps the compiler's memory: compiling alone takes the process from 9 to 292 MB, loading the compiled copy from 9 to 24 MB. This is why the window benchmark run as root measures 413–433 MB with data loaded against its 265 MB limit, which holds for a normal start. Run the release gate as a normal user. A root start that keeps less memory needs a compiled copy only root can write, planned for a later release.
- **Reading a large capture can still freeze the window for about half a second.** In the 1,000-device benchmark (S2) one screen update after the import took 366–447 ms; the cause is not found yet. In the medium benchmark (S1) the longest freeze was 141–146 ms in our runs, under the 260 ms limit; the audit's 367 ms (run as root on a busy 4-core machine) was not reproduced. The *Network check-up* also holds the window for 133–285 ms on a very large session.
- **Capture files that are read but not decoded:** Wi-Fi (802.11 and radiotap), OpenBSD loopback and big-endian BSD loopback captures are read but their packets are not decoded, and `.gz` captures must be unpacked first. The packet details view doesn't take apart Linux cooked v2 or BSD loopback frames, though the packet list does. A .pcapng "simple packet" cut by the capture length can keep up to 3 bytes of padding.
- **Some unusual packets are still slower to analyse:** traffic on port 53 that isn't DNS takes about 77 microseconds a packet instead of 3, and its row can read like a DNS answer. Tunnels (IP inside IP) are still handed to the slower decoder: up to about 3 ms for a full-size packet.
- **Local services: http or https.** The address uses what the check found; a port not asked yet (or one whose check failed) is shown as https only for 443 and 8443. A server that answers plain HTTP on an HTTPS port with neither a TLS message nor a closed connection is shown as http. A service bound only to an IPv6 link-local address (fe80::) isn't asked or opened. The release gate's screenshots don't include the Local services view.
- **An upgrade from 5.3.3 or older turns the daily update check on, even if it was off.** 5.3.3 stored "off" for everyone, so a real choice can't be told from that. A one-time notice says how to turn it off again (Settings → Updates & Dependencies).
- **On Windows, the saved compiled copy is trusted by its folder only.** It is used only from under your own LOCALAPPDATA folder and must carry this install's signature (HMAC), but the key file's owner and permissions are not checked there as they are on Linux and macOS.
- **A rollback can bring back an older genuine version.** When an update fails to start three times, the version it replaced comes back, even if the update fixed a security problem in it. Download the newer version again from the releases page.

**Not in this release**

- Device fingerprints from DHCP request lists ship without built-in rows until real captures of your own devices are available.

Tested on Python 3.8, 3.12 and 3.13 (more than 350 self-tests) and with 67 GUI steps on Ubuntu 22.04 and 24.04 and on Windows. A test that can't run on a machine (for example one that needs Windows) is reported as skipped, not passed.

## [5.2.3] — 2026-10-24

A reliability release: capture starts without freezing, devices are identified correctly on PCs with VPN and virtual adapters, and copies of different versions can share a folder safely.

- **Capture:** starting and recovering capture runs on a helper thread, so the window never freezes. Cards that refuse promiscuous mode open without it.
- **Network identity:** the LAN comes from the capture card only. VPN, ZeroTier, WSL, Hyper-V and VMware subnets are no longer taken for it. CGNAT addresses are not "local". Pi-hole answers no longer rename devices. The router never moves to a routed address. "This computer" follows an address change.
- **Archive safety:** copies of different versions in one folder no longer damage each other's update rollback, settings, crash journal, history database or Safe Mode count. The Welcome Center says when versions share a data folder.
- **Memory:** bounded while minimised. The previous data is freed after loading a session. Exports and history writes run in the background.
- **Closing and workers:** closing waits only for saves and exports. Analysis workers start together, with a time limit.
- **Windows:**
  - non-English `netsh`/`arp` output is read correctly
  - the Npcap installer alone asks for administrator rights
  - a Store-Python runtime that broke after a Store update is detected
  - saves retry a briefly locked file
  - a 1 ms timer is used only while busy
  - no console windows flash
- **Security:** the macOS keychain secret is no longer passed on the command line.
- **Fixes:** 6 GHz Wi-Fi channels, keychain newline handling, NTP delay, PID reuse in the program list, and a stale exception reference in the certificate dialog. pyflakes is clean.
- **Groundwork** for a future standalone `.exe`: the program can start itself, its workers and its tests without a `.py` file. No exe is shipped.
- Tested on Python 3.8, 3.12 and 3.13: 138 self-tests and 50 GUI steps.

## [5.1.2] — 2026-10-24

The window stays responsive while packets are analysed.

- Analysis gives the window its turn (fair gate, chunked work, a frozen garbage collector during bursts). Slow work moved to background jobs.
- Table kit with sticky sorting. Grouped tab strip, state line and answer cards.
- Find and explain, understanding features and expert features. Accessibility and platform polish.
- **150 MB less memory:** the process no longer keeps the compiler's leftovers. On Linux and macOS it runs from a cached compiled copy.
- **Warm start:** the loading screen does the first-time work, so the window appears finished.
- Release gate (`--release-gate`) with fixed performance budgets (`BENCH_LIMITS`). Opening a session no longer stalls, and the S2 stress-profile freeze is fixed.
- French and Spanish now cover the remaining surfaces.
- Tested on Python 3.8, 3.12 and 3.13 (Tk 9.0): 131 self-tests and 48 GUI steps. The minimum Python version is now checked statically.

## [5.0.2] — 2026-10-21

Layout and loading bug campaign. A crawler opened every tab, view, dialog and settings page in three languages, two themes, four text sizes and screen sizes from 1024×768 to 1920×1080.

- Wrapping tab strip and toolbars, dialogs that fit their content, a dashboard that reflows, charts that measure their labels.
- Compact density on short screens. Tables and tooltips fixed.
- Loading and behaviour fixes found by the same run.

## [5.0.1] — 2026-10-20

- Expert list actions: show these packets, Export CSV and a right-click menu.
- "Copy as filter" and "Filter on this conversation". Follow stream: save as text (always redacted), previous/next, direction.
- `Ctrl+G` go to packet. New time-column formats.
- **Fixes:**
  - The hex view of a redacted stream now stays redacted.
  - CSV formula injection blocked.
  - `pythonw` worker handling fixed.
  - French text fixes.

## [5.0.0] — 2026-10-20

- Starts on the Python that launched it. Packages go into a private per-ABI folder, never the system Python. A managed Python is used only when chosen or needed.
- Boot receipts, crash-loop Safe Mode, `--safe`, `--boot-check`.
- Capture pipeline: coverage buckets, capture epochs, watchdog, and capture faults classified with a fix for each.
- Own packet builder, protocol registry (166 fields), dissectors with byte ranges, IP defragmentation and TCP reassembly.
- **Full Power:** a deep pass in worker processes, with protocol exchanges (DNS, DHCP, TLS, HTTP, RTSP, SSH, SMB, MQTT, NTP, SIP).
- **Email Traffic:** SMTP, IMAP and POP3 analysis with secrets dropped inside the parser.
- Packet workspace: streams, exchanges, statistics, expert findings, Follow stream and a field filter language.
- Command palette (`Ctrl+K`), workspaces, flight recorder, crash-safe session journal, first-run calibration, Storage panel, privacy posture report.

## [4.0.0] — 2026-10-19

- Capture pipeline v2: fast wire decoder (115k frames/s), raw-socket capture, ring buffer, analysis worker, and a stdlib pcap/pcapng reader.
- Evidence levels and observations. A SQLite history store with WAL, migrations and recovery.
- Identity over time: IP binding history, merge and split, undoable corrections, network profiles with Quiet Mode.
- Truth UI: a docked Inspector, vantage meter, coverage report and blind spots.
- Private Python runtime and Runtime Manager, Welcome Center, one-click Repair.
- HTTP/3 (QUIC) site names, LLDP/CDP, TCP health metrics, this computer's Wi-Fi link.
- Outbound gate and self-traffic ledger, programs per connection, ARP cross-check, UPnP audit.
- Pi-hole and AdGuard Home connectors with a credential vault.
- "Why is my Internet slow?" investigations. Colour-blind modes. Map v3. Redaction and shareable reports.
- Ed25519-signed updates and data packs. English, French and Spanish.

## [3.0.0]

- "Your network, explained in plain English": a single-file observability, troubleshooting and defensive-monitoring workstation, with devices, websites, remote hosts, flows, metrics, a security engine, persistence, settings, export and a demo.

## [2.0.0] and [1.x]

- The original "super noob-friendly" single-file packet sniffer. It handles elevation, dependency and driver installs, network-card choice, LAN discovery (ARP, mDNS, SSDP), self-healing capture and a paced plain-English feed.

[5.3.4]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.3.4
[5.2.3]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.2.3
[5.1.2]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.1.2
[5.0.2]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.2
[5.0.1]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.1
[5.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v5.0.0
[4.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v4.0.0
[3.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v3.0.0
[2.0.0]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v2.0.0
[1.x]: https://github.com/darkckillerc4/MiniWireshark/releases/tag/v1.0.0
