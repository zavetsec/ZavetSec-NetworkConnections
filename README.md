<div align="center">

# `>_` ZavetSec-NetworkConnections

**Live network connection snapshot with process context, GeoIP enrichment, and threat indicators**

[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell&logoColor=white)](https://github.com/zavetsec)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d4?logo=windows&logoColor=white)](https://github.com/zavetsec)
[![No Dependencies](https://img.shields.io/badge/Dependencies-none%20required-00d4ff)](https://github.com/zavetsec)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](https://github.com/zavetsec)

TCP · UDP · GeoIP · LOLBin detection · DNS cache · ARP · Listening ports · Interactive HTML report

[When to Use](#-when-to-use) · [Quick Start](#-quick-start) · [Parameters](#-parameters) · [Report](#-html-report) · [Detection Logic](#-detection-logic) · [Limitations](#-limitations) · [Roadmap](#-roadmap)

</div>

---

## TL;DR

One command. Full network picture. Analyst-ready HTML report.

```powershell
.\ZavetSec-NetworkConnections.ps1
```

- Every TCP/UDP connection mapped to its owning process — name, path, parent, command line
- GeoIP enrichment via ip-api.com — country, city, ISP, VPS/hosting flag
- Risk scoring: LOLBins, temp-path binaries, suspicious ports, Tor, unsigned HTTPS — all flagged automatically
- DNS cache snapshot with entropy scoring for DGA and DNS tunnel detection
- ARP cache, network adapters, routing context
- Zero installation — single `.ps1`, PowerShell 5.1, any Windows endpoint
- Timeline-ready CSV output for SIEM and DFIR tooling

> **No agent. No install. No persistence. Just signal.**
> Works when EDR visibility is limited, unavailable, or untrusted.

---

## Audience

DFIR analysts · Incident responders · SOC engineers · Threat hunters · Pentesters (post-exploitation recon)

---

## Why this tool

Knowing that `svchost.exe` has an outbound connection to `185.x.x.x:443` means almost nothing without context. Knowing that `rundll32.exe` — launched by `winword.exe`, running from `%APPDATA%\Roaming\`, unsigned — is connected to a Hetzner VPS in Germany on port 443 is a completely different signal.

`ZavetSec-NetworkConnections.ps1` was built specifically for that gap: collects connections the same way any tool can, then answers the question *"is this normal?"* by enriching each row with the process that owns it, where the binary lives, who signed it, who spawned it, where the remote IP resolves geographically, and whether any of those facts should concern you.

What sets it apart from `netstat` and its wrappers:

- **Full process context per connection** — path, command line, parent process. Not just the name.
- **Publisher verification** — Authenticode signature check per binary (cached — no redundant I/O)
- **GeoIP enrichment** — batch lookup via ip-api.com free API, 100 IPs per request, no key required
- **Risk scoring built-in** — LOLBin list, suspicious path patterns, bad ports, Tor, RDP exposure, unsigned binary doing HTTPS — evaluated at collection time, not in the report
- **DNS entropy scoring** — Shannon entropy per hostname label to surface DGA candidates and DNS tunnels without signatures
- **No external binaries** — pure PowerShell 5.1, no `sqlite3.exe`, no `7z.exe`, no NuGet. Drop the `.ps1` and run.

**Where it fits in an IR workflow:**
Run it at the start of an investigation, before rebooting or isolating. It answers "what is this machine talking to right now, and why?" in under two minutes. The structured output feeds directly into a SIEM, timeline, or IOC pipeline. The HTML report works on an air-gapped analyst workstation.

---

## When to Use

**Active compromise investigation**
You have a live host that may be calling back to C2 infrastructure. You need to know: which process, what IP, what country, what ISP, is it a VPS, is this binary legitimate? Run the script before isolation cuts the connection.

**Lateral movement detection**
Unexpected Kerberos or SMB connections, RDP from unusual sources, WinRM to internal hosts — the connection table maps every active session to a process and owner chain. Pivot from the network to the process in one view.

**Threat hunting**
Hunt for LOLBin network activity, processes running from temp paths making external connections, high-entropy DNS names, connections to hosting providers on non-standard ports — all flagged automatically without writing custom detection logic.

**Post-exploitation recon (authorized assessments)**
Understand the full network exposure of a compromised host: what's listening, what's established, what internal targets are reachable, what DNS cache reveals about prior browsing or C2 check-ins.

**Baseline verification**
Run periodically on a host to capture the normal connection profile. Compare snapshots over time to detect drift.

**When not to use**
This is a point-in-time snapshot, not continuous monitoring. Connections that exist for less than a second (DNS queries, short-lived HTTP) may not appear. For continuous behavioral analysis, combine with EDR telemetry or Sysmon network events.

---

## Features

- **Full TCP/UDP enumeration** — all connections via `Get-NetTCPConnection` + `Get-NetUDPEndpoint`, enriched with WMI `Win32_Process` batch query
- **Process context** — name, full path, command line, parent process (name + PID), publisher (Authenticode or VersionInfo)
- **Triple source fallback** — WMI → `Get-Process` → `tasklist` for maximum coverage across permission levels
- **GeoIP enrichment** — batch lookup (up to 100 IPs per request), country, city, ISP, org, AS number, VPS/hosting flag; skippable with `-SkipGeoIP`
- **Risk scoring** — three levels (ALERT / SUSPICIOUS / CLEAN) evaluated per connection at collection time
- **LOLBin detection** — 30+ known Living-off-the-Land binaries flagged when making network connections
- **Suspicious path detection** — binaries running from `%TEMP%`, `%APPDATA%\Roaming\`, `Public\`, `Desktop\`, `Downloads\`, and Recycle Bin flagged automatically
- **DNS cache snapshot** — full `Get-DnsClientCache` output with Shannon entropy scoring per hostname; skippable with `-SkipDns`
- **DGA / DNS tunnel heuristics** — high-entropy labels, base64-ish label patterns, oversized labels flagged
- **Listening port audit** — all TCP listeners and UDP endpoints with owning process
- **ARP cache** — LAN reconnaissance indicator; shows all resolved MAC addresses
- **Network adapters** — IP/MAC/status per interface
- **Interactive HTML report** — self-contained, offline, no CDN; dark theme; filterable/sortable table; in-browser CSV export
- **Optional CSV export** — `-ExportCsv` writes `NetworkConnections_*.csv` and `*_dns.csv` alongside the HTML

---

## ⚡ Quick Start

```powershell
# View built-in help
Get-Help .\ZavetSec-NetworkConnections.ps1 -Full

# Standard run (Administrator recommended)
.\ZavetSec-NetworkConnections.ps1

# Open report immediately after generation
.\ZavetSec-NetworkConnections.ps1 -OpenReport

# Skip GeoIP lookup (faster, offline-safe)
.\ZavetSec-NetworkConnections.ps1 -SkipGeoIP -OpenReport

# Skip DNS cache collection
.\ZavetSec-NetworkConnections.ps1 -SkipDns

# Export CSV alongside HTML
.\ZavetSec-NetworkConnections.ps1 -ExportCsv

# Save report to a specific path
.\ZavetSec-NetworkConnections.ps1 -OutputPath C:\IR\host42_network.html -OpenReport

# Full offline run — no GeoIP, no DNS, export CSV, custom output path
.\ZavetSec-NetworkConnections.ps1 -SkipGeoIP -SkipDns -ExportCsv -OutputPath C:\IR\host42_network.html
```

> Without arguments the report is saved next to the script as `NC_<HOSTNAME>_<TIMESTAMP>.html`

---

## 📋 Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-OutputPath` | String | auto | Full path for the HTML report. Saved next to the script as `NC_<HOST>_<TS>.html` if omitted |
| `-OpenReport` | Switch | — | Open the report in the default browser after generation |
| `-SkipGeoIP` | Switch | — | Skip GeoIP lookup entirely. Useful for air-gapped systems or when speed matters |
| `-SkipDns` | Switch | — | Skip DNS cache collection |
| `-ExportCsv` | Switch | — | Write CSV exports alongside the HTML: connections + DNS entries |
| `-GeoIpBatchSize` | Int | `100` | IPs per batch request to ip-api.com. Max 100 (API limit) |

---

## 📊 HTML Report

Single self-contained `.html` file — no server, no CDN, no internet required. Opens on an air-gapped analyst workstation.

```
┌──────────┬──────────┬────────────┬──────────┬─────────────┬───────────────┐
│  Total   │  ALERT   │ SUSPICIOUS │  CLEAN   │ Established │  To Public IPs│
│   214    │    3     │     12     │   199    │     87      │      41       │
└──────────┴──────────┴────────────┴──────────┴─────────────┴───────────────┘
```

### Tabs

**Connections** — main table. Shows all TCP/UDP entries sorted by risk (ALERT first), with filter bar and search.

**DNS Cache** — all resolved hostnames with entropy score. High-entropy entries sorted to the top.

**Network Info** — adapter table (IP/MAC/status) and ARP cache.

### Connections table

| # | Risk | Proto / State | Local | Remote | Geo | Process / Path / Parent |
|---|------|---------------|-------|--------|-----|------------------------|
| 1 | ⚠ ALERT | TCP · Established | 10.0.0.5:49312 | 185.220.x.x:`443` | 🇩🇪 Germany · Frankfurt · Hetzner `VPS` | **rundll32.exe** [4921]<br>...\System32\rundll32.exe<br>via winword.exe |
| 2 | ? SUSP | TCP · Established | 10.0.0.5:52100 | 1.2.3.4:`8443` | 🇺🇸 United States · Ashburn · Amazon AWS `VPS` | **powershell.exe** [7744]<br>...\AppData\Local\Temp\ps.exe<br>via cmd.exe |
| 3 | ✓ | TCP · Established | 10.0.0.5:50881 | 140.82.x.x:`443` | 🇺🇸 United States · Seattle · GitHub | **chrome.exe** [2048]<br>...\Google\Chrome\chrome.exe |

**Filters:** Risk (ALERT / SUSP / CLEAN) · Protocol (TCP / UDP) · State (Established / Listen) · free text search · ↓ Export CSV of visible rows · click any column header to sort

**Tooltip on hover** — hovering a process cell shows the full binary path, complete command line, and parent process.

### DNS Cache table

| # | Risk | Hostname | Resolved IP | Entropy | Type | TTL |
|---|------|----------|-------------|---------|------|-----|
| 1 | ⚠ ALERT | `xk2a9f3mq.top` | 91.x.x.x | **4.71** | A | 60s |
| 2 | ? SUSP | `d3f8a1bc2e.ru` | 185.x.x.x | 3.92 | A | 300s |
| 3 | ✓ | `github.com` | 140.x.x.x | 2.14 | A | 3600s |

Entropy score reflects Shannon entropy of the hostname label (excluding TLD). Values above 3.8 indicate potential DGA or DNS tunneling activity.

---

## 🔍 Detection Logic

### Risk levels

| Level | Meaning |
|-------|---------|
| **ALERT** | High-confidence indicator — investigate immediately |
| **SUSPICIOUS** | Anomalous but not definitively malicious — review |
| **CLEAN** | No indicators triggered |

### ALERT triggers

| Indicator | Technique |
|-----------|-----------|
| LOLBin making outbound connection (`certutil`, `mshta`, `rundll32`, `bitsadmin`, `cmstp`, `msiexec`, `regsvr32`, `wmic`, and 22 others) | T1218, T1105 |
| Process binary running from `%TEMP%`, `%APPDATA%\Roaming\`, `Public\`, `Desktop\`, `Downloads\`, Recycle Bin | T1036, T1059 |
| Remote port in known C2 / tool list (1337, 4444, 4445, 5555, 6666–6669, 7777, 8888, 9001, 9002, 31337, etc.) | T1571 |
| Tor SOCKS port (9050, 9051, 9150) | T1090.003 |
| RDP (3389) established to a public IP | T1021.001 |
| SUSPICIOUS connection + VPS/hosting IP (GeoIP hosting flag) → upgraded to ALERT | T1583.003 |
| DNS hostname entropy > 4.2 | T1071.004 |
| DNS label length > 50 characters | T1071.004 |

### SUSPICIOUS triggers

| Indicator | Description |
|-----------|-------------|
| Binary not in `System32` / `SysWOW64` / `Program Files` and no publisher | Unsigned binary from non-standard path |
| Port 443 connection from an unsigned binary | HTTPS from untrusted binary |
| DNS hostname entropy 3.8–4.2 | Possible DGA activity |
| DNS label matching base64 charset, length > 30 | Possible DNS tunnel |

---

## 📁 Output

**Default:**
```
ZavetSec-NetworkConnections.ps1
NC_HOSTNAME_20260324_093100.html
```

**With `-ExportCsv`:**
```
ZavetSec-NetworkConnections.ps1
NC_HOSTNAME_20260324_093100.html
NC_HOSTNAME_20260324_093100.csv
NC_HOSTNAME_20260324_093100_dns.csv
```

**CSV columns (connections):** `Risk, Proto, State, LocalAddr, LocalPort, RemoteAddr, RemotePort, PortLabel, PID, ProcName, ProcPath, CmdLine, Parent, GeoCountry, GeoCity, GeoISP, GeoCC, GeoHosting`

**CSV columns (DNS):** `Risk, Name, RData, Type, TTL, Entropy`

---

## 🖥️ Remote Execution

The script resolves `$ScriptDir` correctly in PsExec / WinRM / SYSTEM contexts. `-OpenReport` is safe to include — it auto-suppresses when no interactive desktop is detected.

**PsExec:**
```powershell
psexec \\TARGET -s powershell.exe -ExecutionPolicy Bypass `
    -File "C:\Windows\Temp\ZavetSec-NetworkConnections.ps1" `
    -SkipGeoIP -OutputPath "\\share\IR\TARGET_network.html"
```

**WinRM:**
```powershell
Invoke-Command -ComputerName TARGET -FilePath .\ZavetSec-NetworkConnections.ps1
```

**Full remote workflow:**
```cmd
rem 1. Deploy
xcopy "C:\tools\ZavetSec-NetworkConnections" "\\TARGET\C$\Windows\Temp\ZavetSec-NetworkConnections\" /E /I /Y

rem 2. Run
psexec \\TARGET -s powershell.exe -ExecutionPolicy Bypass -File "C:\Windows\Temp\ZavetSec-NetworkConnections\ZavetSec-NetworkConnections.ps1" -SkipGeoIP -OutputPath "\\share\IR\TARGET_network.html"

rem 3. Cleanup
psexec \\TARGET cmd /c "rmdir /S /Q C:\Windows\Temp\ZavetSec-NetworkConnections"
```

> Use `-SkipGeoIP` for remote execution when the target has no internet access or when you prefer not to make outbound API calls from a compromised host.

---

## 🌐 GeoIP Notes

GeoIP lookup uses the [ip-api.com](https://ip-api.com) free batch API — no registration, no key required. Fields returned: country, city, ISP, org, AS, hosting flag.

**Rate limit:** ip-api.com free tier allows 45 requests/minute. The script batches up to 100 IPs per request with a 200ms inter-request pause. A host with 500 unique public IPs will complete GeoIP enrichment in under 15 seconds.

**Privacy:** Only public (non-RFC1918) remote IPs are sent to ip-api.com. Private, loopback, and link-local addresses are resolved locally as "LAN / Loopback" without any external call.

**Air-gapped systems:** use `-SkipGeoIP`. All other functionality works fully offline.

---

## 🧪 Tested On

| OS | Build | Notes |
|----|-------|-------|
| Windows 11 Pro | 22631 (23H2) | Domain-joined and standalone |
| Windows 11 Pro | 22000 (21H2) | |
| Windows 10 Pro | 19045 (22H2) | |
| Windows 10 LTSC | 17763 (2019) | |
| Windows Server 2022 | 20348 | |
| Windows Server 2019 | 17763 | |
| Windows Server 2016 | 14393 | |

---

## ⚠️ Limitations

- **Point-in-time snapshot** — captures connections at the moment of execution. Short-lived connections (sub-second DNS, quick HTTP) may not appear
- **GeoIP requires internet** — use `-SkipGeoIP` on air-gapped or isolated hosts
- **Process resolution requires elevation** — running without Administrator returns connections with partial or missing process context for system-owned sockets
- **WMI dependency** — process path and command line resolution requires WMI (`Win32_Process`). If WMI is broken, the script falls back to `Get-Process` and `tasklist` — process names are available but paths and command lines may be missing
- **IPv6 partial** — connections and addresses are collected for IPv6, but GeoIP lookup is limited to IPv4 public addresses
- **No historical data** — shows only active connections; does not reconstruct past network activity (use event logs or EDR telemetry for that)
- **No packet capture** — payload analysis, protocol identification beyond port number, and data volume are outside scope

---

## ❓ FAQ

**Running without Administrator — what do I lose?**
Process path, command line, and parent process context for connections owned by SYSTEM or other users. The connection itself (IP, port, state) is still collected. Risk scoring degrades because publisher verification requires the binary path.

**The GeoIP lookup is slow — why?**
ip-api.com free tier limits to 45 requests/minute. With 100 IPs per batch and a 200ms pause, you get ~300 IPs enriched per minute. A typical workstation has 20–60 unique public remote IPs, which resolves in under 5 seconds. Large servers with many connections may take 15–30 seconds.

**My EDR is blocking the WMI query — will the script fail?**
No. The script has a three-stage fallback: WMI → `Get-Process` → `tasklist`. If WMI is blocked, process names are still available via the other sources; you lose path and command line only.

**Can I run this as part of ZavetSec Triage?**
`Invoke-ZavetSecTriage.ps1` includes network state collection as module #3. That module uses a subset of the same logic. Run `ZavetSec-NetworkConnections.ps1` standalone when you need the full interactive HTML report with GeoIP, DNS entropy, and the filter/sort UI — Triage module #3 outputs raw CSVs.

**How is this different from `netstat -b`?**
`netstat -b` resolves process names but not paths, command lines, or parents. It has no GeoIP, no risk scoring, no DNS context, no ARP, no adapters, and no filterable report. Also `netstat -b` is significantly slower on systems with many connections.

**Does the script write anything to disk on the target besides the report?**
No. All collection is in-memory. The only file written is the HTML report (and optional CSV) at the path you specify. No temp files, no registry writes, no persistent artifacts.

---

## 🗺️ Roadmap

- [ ] **Threat intel integration** — check remote IPs against AbuseIPDB / VirusTotal / offline blocklist at collection time
- [ ] **Process tree view** — visual parent → child chain in the report for each connection
- [ ] **Connection history delta** — compare two snapshots, highlight new/dropped connections
- [ ] **IPv6 GeoIP** — extend enrichment to IPv6 public addresses
- [ ] **SOCKS / proxy detection** — heuristics for connections that are likely proxied or tunneled
- [ ] **Firewall rule correlation** — flag established connections that bypass expected firewall policy
- [ ] **Export to STIX/JSON** — structured IOC export for TIP ingestion

---

## 🤝 Contributing

Most useful contributions:

- **New LOLBin entries** — process names that should be flagged when making network connections
- **Port list updates** — suspicious ports not in the current list, or false positives to remove
- **Windows version coverage** — test results on Server 2012 R2, Windows 7, older builds
- **Bug reports** — unexpected behavior on specific domain configurations, EDR environments, or network setups

Requirements for PRs: PowerShell 5.1 compatible, ASCII-safe (no non-ASCII characters outside `@"..."@` here-strings), tested on at least one real Windows host, zero-dependency guarantee preserved.

[Open an issue](https://github.com/zavetsec/ZavetSec-NetworkConnections/issues)

---

## 📋 Changelog

### v1.0 — Initial release
- Full TCP/UDP enumeration via `Get-NetTCPConnection` + `Get-NetUDPEndpoint`
- Process context via WMI `Win32_Process` batch query with three-stage fallback (WMI → `Get-Process` → `tasklist`)
- Publisher verification via Authenticode + VersionInfo with path-level caching
- GeoIP batch enrichment via ip-api.com free API — country, city, ISP, org, AS, VPS/hosting flag
- Risk scoring: ALERT / SUSPICIOUS / CLEAN with 8 ALERT triggers and 4 SUSPICIOUS triggers
- LOLBin detection — 30+ known Living-off-the-Land binaries
- Suspicious path detection — 9 path patterns covering common malware staging locations
- DNS cache snapshot with Shannon entropy scoring per hostname label
- DGA / DNS tunnel heuristics — entropy threshold, label length, base64-charset detection
- Listening port audit and UDP endpoint enumeration
- ARP cache and network adapter collection
- Interactive dark-theme HTML report — self-contained, offline-capable
- Report features: risk filter · proto filter · state filter · free text search · column sort · in-browser CSV export
- Top Processes bar chart and Top Countries bar chart in report sidebar
- Tooltip on process cell: full path + complete command line + parent process
- GeoIP block: country flag, city, ISP with VPS badge; LAN/Loopback label for private IPs
- Port label display: port number + protocol name badge (HTTPS, SSH, RDP, etc.)
- `-ExportCsv` — connections CSV + DNS CSV with UTF-8 BOM (Excel-compatible)
- `-SkipGeoIP` / `-SkipDns` — selective collection for air-gapped or time-constrained runs
- ZavetSec-style ASCII banner on launch with host, user, output path, timestamp

---

## `>_` disclaimer

> Intended for authorized forensic analysis and incident response on systems you have explicit permission to access. The author assumes no responsibility for use outside these boundaries.

---

<div align="center">

**ZavetSec** — security tooling for those who read logs at 2am

[github.com/zavetsec](https://github.com/zavetsec) · MIT License

</div>
