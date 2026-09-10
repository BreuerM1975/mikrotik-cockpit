# MikroTik Cockpit — What makes it different

> This file exists because the first question everyone asks is: *"Why not just use WinBox?"*

## 1. Explanations, not raw data

WinBox shows you fields. Cockpit tells you what they mean.

| WinBox | Cockpit |
|---|---|
| A checkbox labeled "enabled" | "Enable this port — traffic will be forwarded to the device behind it" |
| A text field for "ARP" with three modes | "How the router finds devices on this network — leave at 'enabled' unless you know what you're doing" |
| A screen full of counters | A status dashboard: internet up/down, uptime, WAN address, number of connected devices, and one security score |

Every setting in Cockpit carries a plain-language explanation of what it does and when you'd change it — written for the 80 % of users who don't hold a networking certification.

## 2. Device links your router can't see

WinBox shows you RouterOS objects only. Cockpit looks *past* the router:

- A Shelly smart plug appears in the DHCP lease list? Cockpit turns it into a clickable link to the Shelly's web interface.
- An ESPHome sensor got an IP from DHCP? Cockpit shows its web dashboard.
- Any device whose MAC prefix matches a known manufacturer (OUI lookup) gets a direct-link suggestion.

RouterOS has no idea these devices exist beyond their IP addresses. WinBox has no feature for this. Cockpit opens them in a new browser tab — one click from the router dashboard to the device itself.

## 3. Safety warnings where WinBox stays silent

Cockpit is honest about what it can and cannot protect you from:

- **No Safe Mode?** Told upfront, with a note that router-wide changes are applied immediately — unlike WinBox which claims Safe Mode but disconnects you when you try to use it via SSH (verified against RouterOS 7.23.1).
- **Changing the router's IP?** A confirmation dialog warns you that the connection may drop.
- **Changing the Wi-Fi password?** Applied live, but with a 5-minute undo window — one click puts the old password back if your devices stop connecting.
- **SSH is your only connection?** Disabling it in the IP Services panel triggers an extra warning: *"This will cut Cockpit's own connection. Make sure you have another way in (WinBox, console)."* *(Pro)*
- **Firewall rules marked `defconf`?** Deleting a RouterOS system rule shows a stronger warning than deleting a user-created one. *(Pro)*
- **Rebooting the router?** Confirmation required, with a note that it takes ~30 seconds to come back. *(Pro)*

WinBox warns about none of these things.

## 4. Local. No account. No cloud.

Cockpit runs entirely on your machine:

- **No signup.** No account creation. No email verification.
- **No cloud.** No central server. No data leaves your network.
- **No telemetry.** No tracking. No "anonymous usage statistics."
- **Connect like WinBox:** IP address, username, password — and you're in.

The backend binds to `127.0.0.1` only. Nobody on your LAN can reach it. The session lives in memory: close the browser, and it's gone. Shut down the backend, same thing — exactly like closing WinBox ends your session.

## 5. Speed for daily tasks

The 80 % of things you do most often — in fewer clicks:

| Task | WinBox | Cockpit |
|---|---|---|
| Change Wi-Fi password | 5–8 clicks through menus | 2 clicks: open Wi-Fi card, type new password, save |
| See what's connected | Open DHCP Leases screen | Shown on the main dashboard immediately |
| Add a port forward | IP → Firewall → NAT → Add → 6+ fields | One form: name, port, internal IP |
| Check whether the internet is up | System → Interfaces, then read counters | Stated in plain words on the dashboard |

## What Cockpit is *not*

- **Not a WinBox replacement.** WinBox gives you every single RouterOS knob. Cockpit gives you the ones you need daily. For VLANs, routing tables, BGP, MPLS, and the deep stuff — you still need WinBox.
- **Not a config generator.** It connects *live* to a running router, reads its state, and makes changes in real time. Nothing gets uploaded. Nothing gets exported.
- **Not a cloud dashboard.** No multi-router fleet management. One router, one browser tab.
- **Not finished.** This is an open-source prototype (218 tests, security audited, live hardware verified against RouterOS 7.23.1). It works, but it's not a polished commercial product.

## The philosophy in one sentence

> *WinBox gives you every lever. Cockpit gives you the ones you actually pull — and tells you what each one does before you pull it.*

## Safety record

- **218 passing backend tests** — every API endpoint, against a mocked router
- **Security audit completed** — 18 finding groups, P0 and P1 closed, all documented
- **Live hardware verification** — every endpoint tested against a MikroTik hAP ac Lite running RouterOS 7.23.1
- **Six RouterOS bugs found and fixed during development** — `parse_terse()` lookahead, `$`-masking, `print as-value` SSH quirk, DHCP comment timing, `:put` wrapper requirement, unquoted values in `print terse`

---

*MikroTik is a registered trademark of MikroTikls SIA. This project is not affiliated with or endorsed by MikroTik.*