# ============================================================
#  ZavetSec-NetworkConnections.ps1
#  Network connection snapshot with process context:
#    - All TCP/UDP connections with owning process
#    - Process binary path, publisher, parent process
#    - GeoIP lookup (ip-api.com, free, no key required)
#    - DNS cache snapshot
#    - Listening ports audit
#    - Suspicious indicators: unsigned bins, temp paths,
#      known bad port patterns, non-browser HTTPS on 443,
#      LOLBin connections, high-entropy DNS names
#    - ARP cache (LAN reconnaissance indicator)
#    - Network adapters + routing table
#  Requires: Run as Administrator (for process details)
# ============================================================

#Requires -Version 5.1

param(
    [string]$OutputPath       = "",
    [switch]$OpenReport,
    [switch]$SkipGeoIP,
    [switch]$SkipDns,
    [switch]$ExportCsv,
    [int]$GeoIpBatchSize      = 100
)

$ErrorActionPreference = "SilentlyContinue"
Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Net.Http

# --- Script directory ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# --- Output path ---
if ([string]::IsNullOrEmpty($OutputPath)) {
    $TimeStamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $HostTag    = $env:COMPUTERNAME
    $OutputPath = Join-Path $ScriptDir "NC_${HostTag}_${TimeStamp}.html"
}

Write-Host ""
Write-Host "     ____                  _    ____            " -ForegroundColor DarkCyan
Write-Host "    |_  /__ ___ _____ ___ | |_ / __/__ ___     " -ForegroundColor Cyan
Write-Host "     / // _' \ V / -_)  _||  _\__ \/ -_) _|   " -ForegroundColor Cyan
Write-Host "    /___\__,_|\_/\___\__| |_| |___/\___\__|    " -ForegroundColor DarkCyan
Write-Host ""
Write-Host "    +-----------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host "    |  N E T W O R K   C O N N E C T I O N S   v 1 . 0        |" -ForegroundColor White
Write-Host "    |  TCP/UDP  //  GeoIP  //  Process Context  //  PS 5.1     |" -ForegroundColor Gray
Write-Host "    +-----------------------------------------------------------+" -ForegroundColor DarkGray
Write-Host ""
Write-Host "    [>] Host     : $env:COMPUTERNAME"  -ForegroundColor Green
Write-Host "    [>] User     : $env:USERNAME"       -ForegroundColor Green
Write-Host "    [>] Output   : $OutputPath"         -ForegroundColor Green
Write-Host "    [>] Started  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
Write-Host ""
Write-Host "    [!] Run as Administrator for full process context" -ForegroundColor Yellow
Write-Host ""

# ============================================================
#  HELPERS
# ============================================================

# LOLBins known to make suspicious network connections
$lolbins = @(
    'certutil','bitsadmin','mshta','wscript','cscript','regsvr32',
    'rundll32','msiexec','powershell','wmic','odbcconf','pcalua',
    'cmstp','expand','extrac32','ieexec','mavinject','msdeploy',
    'msdt','presentationhost','replace','rpcping','syncappvpublishingserver',
    'tttracer','vbc','xwizard','appsyncpublishingserver','appvlp',
    'dnscmd','esentutl','forfiles','hh','infdefaultinstall','makecab'
)

# Suspicious remote ports
$suspPorts = @(1337,4444,4445,5555,6666,6667,6668,6669,7777,8888,
               9001,9002,9050,9051,9150,31337,12345,54321,1234,65535)

# Known safe remote ports (with context)
$commonPorts = @{
    80   = "HTTP"
    443  = "HTTPS"
    53   = "DNS"
    123  = "NTP"
    25   = "SMTP"
    465  = "SMTPS"
    587  = "SMTP/TLS"
    993  = "IMAPS"
    995  = "POP3S"
    22   = "SSH"
    3389 = "RDP"
    5985 = "WinRM HTTP"
    5986 = "WinRM HTTPS"
    389  = "LDAP"
    636  = "LDAPS"
    88   = "Kerberos"
    445  = "SMB"
    135  = "RPC"
    139  = "NetBIOS"
}

# Private / reserved IP ranges
function Test-PrivateIp {
    param([string]$IP)
    if ([string]::IsNullOrEmpty($IP)) { return $true }
    if ($IP -eq "0.0.0.0" -or $IP -eq "::" -or $IP -eq "127.0.0.1" -or $IP -eq "::1") { return $true }
    try {
        $bytes = ([System.Net.IPAddress]::Parse($IP)).GetAddressBytes()
        if ($bytes.Length -eq 4) {
            if ($bytes[0] -eq 10) { return $true }
            if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $true }
            if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
            if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $true }
        }
    } catch {}
    return $false
}

function Get-FilePublisher {
    param([string]$FilePath)
    if ([string]::IsNullOrEmpty($FilePath) -or -not (Test-Path $FilePath -PathType Leaf)) { return "" }
    try {
        $sig = Get-AuthenticodeSignature $FilePath -ErrorAction SilentlyContinue
        if ($sig -and $sig.SignerCertificate) {
            return $sig.SignerCertificate.Subject -replace '.*CN=([^,]+).*','$1'
        }
    } catch {}
    try {
        $vi = (Get-Item $FilePath).VersionInfo
        if ($vi.CompanyName) { return $vi.CompanyName }
    } catch {}
    return ""
}

# DNS entropy (high = DGA / tunnel indicator)
function Get-StringEntropy {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return 0.0 }
    $freq = @{}
    foreach ($c in $s.ToCharArray()) {
        $k = [string]$c
        if ($freq.ContainsKey($k)) { $freq[$k]++ } else { $freq[$k] = 1 }
    }
    $entropy = 0.0
    $len = $s.Length
    foreach ($count in $freq.Values) {
        $p = $count / $len
        $entropy -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($entropy, 2)
}

function Get-RiskLevel {
    param(
        [string]$ProcName,
        [string]$ProcPath,
        [string]$Publisher,
        [string]$RemoteIP,
        [int]$RemotePort,
        [string]$State,
        [string]$LocalPort
    )

    $procLower = $ProcName.ToLower() -replace '\.exe$',''
    $pathLower = $ProcPath.ToLower()

    # ALERT: LOLBin making outbound connection
    if ($lolbins -contains $procLower) { return "ALERT" }

    # ALERT: process running from temp/suspicious location
    $suspPaths = @('\temp\','\tmp\','\appdata\roaming\','\appdata\local\temp\',
                   '\public\','\recycle','\downloads\','\desktop\','\users\public\')
    foreach ($sp in $suspPaths) {
        if ($pathLower.Contains($sp)) { return "ALERT" }
    }

    # ALERT: known bad remote ports
    if ($suspPorts -contains $RemotePort) { return "ALERT" }

    # ALERT: Tor ports
    if ($RemotePort -eq 9050 -or $RemotePort -eq 9051 -or $RemotePort -eq 9150) { return "ALERT" }

    # ALERT: RDP exposed to non-RFC1918
    if ($RemotePort -eq 3389 -and -not (Test-PrivateIp $RemoteIP)) { return "ALERT" }

    # SUSPICIOUS: no publisher and not in system32/program files
    $safePaths = @("$env:SystemRoot\system32","$env:SystemRoot\syswow64","$env:ProgramFiles")
    $inSafe = $false
    foreach ($sp in $safePaths) {
        if ($pathLower.StartsWith($sp.ToLower())) { $inSafe = $true; break }
    }
    if (-not $inSafe -and [string]::IsNullOrEmpty($Publisher) -and $ProcPath -ne "") {
        return "SUSPICIOUS"
    }

    # SUSPICIOUS: unsigned binary making HTTPS connections
    if ($RemotePort -eq 443 -and [string]::IsNullOrEmpty($Publisher) -and $ProcPath -ne "") {
        return "SUSPICIOUS"
    }

    return "CLEAN"
}

# ============================================================
#  GEOIP BATCH LOOKUP
# ============================================================
function Get-GeoIpBatch {
    param([string[]]$IPs)
    $result = @{}
    if ($SkipGeoIP -or $IPs.Count -eq 0) { return $result }

    # Filter to public IPs only
    $publicIPs = $IPs | Where-Object { -not (Test-PrivateIp $_) } | Select-Object -Unique

    if ($publicIPs.Count -eq 0) { return $result }

    Write-Host "  [*] GeoIP lookup for $($publicIPs.Count) unique public IPs ..." -ForegroundColor Cyan

    # ip-api.com batch endpoint: max 100 per request, free, no key
    $batches = @()
    for ($i = 0; $i -lt $publicIPs.Count; $i += 100) {
        $batches += ,@($publicIPs[$i..([Math]::Min($i+99, $publicIPs.Count-1))])
    }

    foreach ($batch in $batches) {
        try {
            $body = ($batch | ForEach-Object {
                "{`"query`":`"$_`",`"fields`":`"query,country,countryCode,city,isp,org,as,hosting`"}"
            }) -join ","
            $body = "[$body]"

            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("Content-Type","application/json")
            $wc.Headers.Add("User-Agent","Mozilla/5.0")
            $response = $wc.UploadString("http://ip-api.com/batch?fields=query,country,countryCode,city,isp,org,as,hosting", $body)

            $parsed = $response | ConvertFrom-Json
            foreach ($entry in $parsed) {
                if ($entry.query) {
                    $result[$entry.query] = [PSCustomObject]@{
                        Country     = if ($entry.country)     { $entry.country }     else { "" }
                        CountryCode = if ($entry.countryCode) { $entry.countryCode } else { "" }
                        City        = if ($entry.city)        { $entry.city }        else { "" }
                        ISP         = if ($entry.isp)         { $entry.isp }         else { "" }
                        Org         = if ($entry.org)         { $entry.org }         else { "" }
                        AS          = if ($entry.as)          { $entry.as }          else { "" }
                        Hosting     = if ($entry.hosting)     { $true }              else { $false }
                    }
                }
            }
            Start-Sleep -Milliseconds 200
        } catch {
            Write-Host "  [!] GeoIP batch failed: $_" -ForegroundColor Yellow
        }
    }

    Write-Host "  [+] GeoIP: $($result.Count) IPs resolved" -ForegroundColor Green
    return $result
}

# ============================================================
#  1. TCP/UDP CONNECTIONS WITH PROCESS INFO
# ============================================================
Write-Host "  [*] Collecting TCP/UDP connections ..." -ForegroundColor Cyan

# --- Build PID -> info map: WMI batch query (one call for ALL processes) ---
Write-Host "  [*] Building process map via WMI ..." -ForegroundColor DarkGray

$pidName  = @{}   # pid -> exe name (e.g. svchost.exe)
$pidPath  = @{}   # pid -> full path (e.g. C:\Windows\System32\svchost.exe)
$pidCmd   = @{}   # pid -> command line
$pidPPID  = @{}   # pid -> parent pid
$pubCache = @{}   # path -> publisher (avoid re-signing same binary)

# Source 1: WMI Win32_Process - most reliable, works from SYSTEM
try {
    $wmiProcs = Get-WmiObject Win32_Process -ErrorAction Stop
    foreach ($wp in $wmiProcs) {
        $p = [int]$wp.ProcessId
        if ($wp.Name)            { $pidName[$p]  = $wp.Name }
        if ($wp.ExecutablePath)  { $pidPath[$p]  = $wp.ExecutablePath }
        if ($wp.CommandLine)     { $pidCmd[$p]   = $wp.CommandLine }
        if ($wp.ParentProcessId) { $pidPPID[$p]  = [int]$wp.ParentProcessId }
    }
    Write-Host "  [+] WMI: $($pidName.Count) processes" -ForegroundColor Green
} catch {
    Write-Host "  [!] WMI failed: $_ - trying fallbacks" -ForegroundColor Yellow
}

# Source 2: Get-Process - fills gaps for Name if WMI missed anything
try {
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $p = [int]$_.Id
        if (-not $pidName.ContainsKey($p) -or [string]::IsNullOrEmpty($pidName[$p])) {
            $pidName[$p] = "$($_.ProcessName).exe"
        }
        if (-not $pidPath.ContainsKey($p) -or [string]::IsNullOrEmpty($pidPath[$p])) {
            try { $pidPath[$p] = $_.MainModule.FileName } catch {}
        }
    }
} catch {}

# Source 3: tasklist - last resort if both above returned nothing
if ($pidName.Count -eq 0) {
    Write-Host "  [!] Falling back to tasklist" -ForegroundColor Yellow
    try {
        $tlLines = & tasklist /fo csv /nh 2>$null
        foreach ($line in $tlLines) {
            if ($line -match '^"([^"]+)","(\d+)"') {
                $p = [int]$Matches[2]
                if (-not $pidName.ContainsKey($p)) {
                    $pidName[$p] = $Matches[1]
                }
            }
        }
    } catch {}
}

Write-Host "  [+] Process map total: $($pidName.Count) entries" -ForegroundColor Green

# --- Get TCP connections ---
$tcpConns = @()
try { $tcpConns = Get-NetTCPConnection -ErrorAction SilentlyContinue } catch {}

# --- Get UDP endpoints ---
$udpConns = @()
try { $udpConns = Get-NetUDPEndpoint -ErrorAction SilentlyContinue } catch {}

$connections = @()

foreach ($conn in $tcpConns) {
    $pid_  = [int]$conn.OwningProcess

    # Resolve name - guaranteed to have something
    $procName = if ($pidName.ContainsKey($pid_) -and $pidName[$pid_]) { $pidName[$pid_] } else { "PID:$pid_" }
    $procPath = if ($pidPath.ContainsKey($pid_)) { $pidPath[$pid_] } else { "" }
    $cmdLine  = if ($pidCmd.ContainsKey($pid_))  { $pidCmd[$pid_]  } else { "" }

    # Parent name
    $parent = ""
    if ($pidPPID.ContainsKey($pid_)) {
        $ppid   = $pidPPID[$pid_]
        $pname  = if ($pidName.ContainsKey($ppid) -and $pidName[$ppid]) { $pidName[$ppid] } else { "PID:$ppid" }
        $parent = "$pname (PID $ppid)"
    }

    # Publisher (cached)
    $pub = ""
    if ($procPath) {
        if ($pubCache.ContainsKey($procPath)) {
            $pub = $pubCache[$procPath]
        } else {
            $pub = Get-FilePublisher $procPath
            $pubCache[$procPath] = $pub
        }
    }

    $remoteIP   = $conn.RemoteAddress
    $remotePort = [int]$conn.RemotePort
    $localPort  = [int]$conn.LocalPort
    $state      = $conn.State

    $risk = Get-RiskLevel -ProcName $procName -ProcPath $procPath -Publisher $pub `
        -RemoteIP $remoteIP -RemotePort $remotePort -State $state -LocalPort $localPort

    $portLabel = if ($commonPorts.ContainsKey($remotePort)) { $commonPorts[$remotePort] } else { "" }

    $connections += [PSCustomObject]@{
        Proto      = "TCP"
        State      = $state
        LocalAddr  = $conn.LocalAddress
        LocalPort  = $localPort
        RemoteAddr = $remoteIP
        RemotePort = $remotePort
        PortLabel  = $portLabel
        PID        = $pid_
        ProcName   = $procName
        ProcPath   = $procPath
        CmdLine    = $cmdLine
        Parent     = $parent
        Publisher  = $pub
        Risk       = $risk
        GeoCountry = ""
        GeoCity    = ""
        GeoISP     = ""
        GeoCC      = ""
        GeoHosting = $false
    }
}

foreach ($conn in $udpConns) {
    $pid_  = [int]$conn.OwningProcess

    $procName = if ($pidName.ContainsKey($pid_) -and $pidName[$pid_]) { $pidName[$pid_] } else { "PID:$pid_" }
    $procPath = if ($pidPath.ContainsKey($pid_)) { $pidPath[$pid_] } else { "" }
    $cmdLine  = if ($pidCmd.ContainsKey($pid_))  { $pidCmd[$pid_]  } else { "" }

    $parent = ""
    if ($pidPPID.ContainsKey($pid_)) {
        $ppid   = $pidPPID[$pid_]
        $pname  = if ($pidName.ContainsKey($ppid) -and $pidName[$ppid]) { $pidName[$ppid] } else { "PID:$ppid" }
        $parent = "$pname (PID $ppid)"
    }

    $pub = ""
    if ($procPath) {
        if ($pubCache.ContainsKey($procPath)) {
            $pub = $pubCache[$procPath]
        } else {
            $pub = Get-FilePublisher $procPath
            $pubCache[$procPath] = $pub
        }
    }

    $localPort = [int]$conn.LocalPort
    $risk = Get-RiskLevel -ProcName $procName -ProcPath $procPath -Publisher $pub `
        -RemoteIP "" -RemotePort 0 -State "Bound" -LocalPort $localPort

    $connections += [PSCustomObject]@{
        Proto      = "UDP"
        State      = "Bound"
        LocalAddr  = $conn.LocalAddress
        LocalPort  = $localPort
        RemoteAddr = "*"
        RemotePort = 0
        PortLabel  = ""
        PID        = $pid_
        ProcName   = $procName
        ProcPath   = $procPath
        CmdLine    = $cmdLine
        Parent     = $parent
        Publisher  = $pub
        Risk       = $risk
        GeoCountry = ""
        GeoCity    = ""
        GeoISP     = ""
        GeoCC      = ""
        GeoHosting = $false
    }
}

Write-Host "  [+] Connections: TCP $($tcpConns.Count) + UDP $($udpConns.Count) = $($connections.Count) total" -ForegroundColor Green

# ============================================================
#  2. GEOIP ENRICHMENT
# ============================================================
$remoteIPs = $connections | Where-Object { $_.RemoteAddr -and $_.RemoteAddr -ne "*" } |
    Select-Object -ExpandProperty RemoteAddr -Unique

$geoData = Get-GeoIpBatch -IPs $remoteIPs

# Enrich connections with geo data
foreach ($c in $connections) {
    if ($c.RemoteAddr -and $geoData.ContainsKey($c.RemoteAddr)) {
        $geo = $geoData[$c.RemoteAddr]
        $c.GeoCountry = $geo.Country
        $c.GeoCity    = $geo.City
        $c.GeoISP     = $geo.ISP
        $c.GeoCC      = $geo.CountryCode
        $c.GeoHosting = $geo.Hosting

        # Upgrade risk if VPS/hosting provider + suspicious process
        if ($geo.Hosting -and $c.Risk -eq "SUSPICIOUS") { $c.Risk = "ALERT" }
    }
}

# ============================================================
#  3. DNS CACHE
# ============================================================
$dnsEntries = @()
if (-not $SkipDns) {
    Write-Host "  [*] DNS cache snapshot ..." -ForegroundColor Cyan
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($entry in $dnsCache) {
            $name     = $entry.Entry
            $rdata    = $entry.Data
            $ttl      = $entry.TimeToLive
            $recType  = $entry.Type
            $entropy  = Get-StringEntropy ($name -replace '\.[^.]+$','')  # entropy of hostname only

            # Risk heuristics for DNS
            $dnsRisk = "CLEAN"
            # High entropy hostname (DGA / DNS tunnel indicator)
            if ($entropy -gt 3.8 -and $name.Length -gt 10) { $dnsRisk = "SUSPICIOUS" }
            if ($entropy -gt 4.2) { $dnsRisk = "ALERT" }
            # Very long labels
            $labels = $name -split '\.'
            foreach ($lbl in $labels) { if ($lbl.Length -gt 50) { $dnsRisk = "ALERT" } }
            # TXT-like base64-ish label in DNS (tunnel indicator)
            foreach ($lbl in $labels) {
                if ($lbl.Length -gt 30 -and $lbl -match '^[A-Za-z0-9+/=]+$') { $dnsRisk = "SUSPICIOUS" }
            }

            $dnsEntries += [PSCustomObject]@{
                Name    = $name
                RData   = $rdata
                Type    = $recType
                TTL     = $ttl
                Entropy = $entropy
                Risk    = $dnsRisk
            }
        }
    } catch {}
    Write-Host "  [+] DNS cache: $($dnsEntries.Count) entries" -ForegroundColor Green
}

# ============================================================
#  4. LISTENING PORTS DETAIL
# ============================================================
Write-Host "  [*] Listening ports ..." -ForegroundColor Cyan
$listening = $connections | Where-Object { $_.State -eq "Listen" -or $_.State -eq "Bound" } |
    Sort-Object LocalPort

# ============================================================
#  5. ARP CACHE
# ============================================================
Write-Host "  [*] ARP cache ..." -ForegroundColor Cyan
$arpEntries = @()
try {
    $arpRaw = arp -a 2>$null
    foreach ($line in $arpRaw) {
        if ($line -match '^\s*([\d.]+)\s+([\w-]+)\s+(\w+)') {
            $ip   = $matches[1]
            $mac  = $matches[2]
            $type = $matches[3]
            if ($ip -ne "Interface" -and $ip -notmatch "^---") {
                $arpEntries += [PSCustomObject]@{ IP=$ip; MAC=$mac; Type=$type }
            }
        }
    }
} catch {}
Write-Host "  [+] ARP entries: $($arpEntries.Count)" -ForegroundColor Green

# ============================================================
#  6. NETWORK ADAPTERS
# ============================================================
Write-Host "  [*] Network adapters ..." -ForegroundColor Cyan
$adapters = @()
try {
    $nics = Get-NetIPAddress -ErrorAction SilentlyContinue
    $ifaceMap = @{}
    Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
        $ifaceMap[$_.InterfaceIndex] = [PSCustomObject]@{
            Name        = $_.Name
            Description = $_.InterfaceDescription
            Status      = $_.Status
            Speed       = $_.LinkSpeed
            MAC         = $_.MacAddress
        }
    }
    foreach ($nic in $nics) {
        $iface = $ifaceMap[$nic.InterfaceIndex]
        $adapters += [PSCustomObject]@{
            InterfaceAlias = $nic.InterfaceAlias
            Description    = if ($iface) { $iface.Description } else { "" }
            IPAddress      = $nic.IPAddress
            PrefixLength   = $nic.PrefixLength
            AddressFamily  = $nic.AddressFamily
            Status         = if ($iface) { $iface.Status } else { "" }
            MAC            = if ($iface) { $iface.MAC } else { "" }
        }
    }
} catch {}
Write-Host "  [+] Adapters: $($adapters.Count) addresses" -ForegroundColor Green

# ============================================================
#  SUMMARY
# ============================================================
$alertConns  = ($connections | Where-Object { $_.Risk -eq "ALERT" }).Count
$suspConns   = ($connections | Where-Object { $_.Risk -eq "SUSPICIOUS" }).Count
$cleanConns  = ($connections | Where-Object { $_.Risk -eq "CLEAN" }).Count
$established = ($connections | Where-Object { $_.State -eq "Established" }).Count
$publicConns = ($connections | Where-Object { -not (Test-PrivateIp $_.RemoteAddr) -and $_.RemoteAddr -ne "*" }).Count

Write-Host ""
Write-Host "  [=] Total connections : $($connections.Count)"  -ForegroundColor White
Write-Host "  [=] Established       : $established"           -ForegroundColor White
Write-Host "  [=] To public IPs     : $publicConns"           -ForegroundColor White
Write-Host "  [!] ALERT             : $alertConns"            -ForegroundColor Red
Write-Host "  [?] SUSPICIOUS        : $suspConns"             -ForegroundColor Yellow
Write-Host "  [+] CLEAN             : $cleanConns"            -ForegroundColor Green
Write-Host ""
Write-Host "  [*] Building HTML report..." -ForegroundColor Cyan

# ============================================================
#  HTML GENERATION
# ============================================================

# --- Connection rows ---
$sortedConns = @(
    $connections | Where-Object { $_.Risk -eq "ALERT" }      | Sort-Object State
    $connections | Where-Object { $_.Risk -eq "SUSPICIOUS" } | Sort-Object State
    $connections | Where-Object { $_.Risk -eq "CLEAN" }      | Sort-Object State
)

$rowsHtml = ""
$idx = 1
foreach ($c in $sortedConns) {
    $safeProc    = [System.Web.HttpUtility]::HtmlEncode($c.ProcName)
    $safePath    = [System.Web.HttpUtility]::HtmlEncode($c.ProcPath)
    $safeRemote  = [System.Web.HttpUtility]::HtmlEncode($c.RemoteAddr)
    $safeLocal   = [System.Web.HttpUtility]::HtmlEncode($c.LocalAddr)
    $safeParent  = [System.Web.HttpUtility]::HtmlEncode($c.Parent)
    $safeCmd     = [System.Web.HttpUtility]::HtmlEncode($c.CmdLine)
    $safeCC      = if ($c.GeoCC) { $c.GeoCC.ToLower() } else { "" }
    $safeCountry = [System.Web.HttpUtility]::HtmlEncode($c.GeoCountry)
    $safeCity    = [System.Web.HttpUtility]::HtmlEncode($c.GeoCity)
    $safeISP     = [System.Web.HttpUtility]::HtmlEncode($c.GeoISP)

    $portStr = if ($c.RemotePort -gt 0) { "$($c.RemotePort)" } else { "*" }
    $portLabelHtml = if ($c.PortLabel) { " <span class=`"plabel`">$($c.PortLabel)</span>" } else { "" }

    $riskClass = switch ($c.Risk) {
        "ALERT"      { "risk-alert" }
        "SUSPICIOUS" { "risk-susp" }
        default      { "risk-clean" }
    }
    $riskBadge = switch ($c.Risk) {
        "ALERT"      { "<span class=`"rb risk-alert-b`">&#9888; ALERT</span>" }
        "SUSPICIOUS" { "<span class=`"rb risk-susp-b`">&#63; SUSP</span>" }
        default      { "<span class=`"rb risk-clean-b`">&#10003;</span>" }
    }

    $stateClass = switch ($c.State) {
        "Established" { "st-est" }
        "Listen"      { "st-lst" }
        "TimeWait"    { "st-tw"  }
        default       { "st-oth" }
    }

    $geoHtml = ""
    if ($c.GeoCountry) {
        $hostingBadge = if ($c.GeoHosting) { " <span class=`"hb`">VPS</span>" } else { "" }
        $geoHtml = "<div class=`"geo-block`"><div class=`"geo-country`"><span class=`"flag`">$safeCC</span>$safeCountry$hostingBadge</div>"
        if ($c.GeoCity) { $geoHtml += "<div class=`"geo-detail`">$safeCity</div>" }
        if ($c.GeoISP)  { $geoHtml += "<div class=`"geo-isp`">$safeISP</div>" }
        $geoHtml += "</div>"
    } elseif ($c.RemoteAddr -and $c.RemoteAddr -ne "*") {
        if (Test-PrivateIp $c.RemoteAddr) { $geoHtml = "<span class=`"geo-priv`">LAN / Loopback</span>" }
        else { $geoHtml = "<span class=`"geo-unk`">&#8212;</span>" }
    }

    # Tooltip: full path + cmdline + parent (shown on hover)
    $tipLines = @()
    if ($c.ProcPath)  { $tipLines += "Path: $($c.ProcPath)" }
    if ($c.CmdLine)   { $tipLines += "CMD:  $($c.CmdLine)" }
    if ($c.Parent)    { $tipLines += "Parent: $($c.Parent)" }
    $procTip = [System.Web.HttpUtility]::HtmlEncode($tipLines -join "`n")

    # Path display: shorten to last two path segments for readability
    $pathDisplay = ""
    if ($c.ProcPath) {
        $parts = $c.ProcPath -split '\\'
        if ($parts.Count -ge 3) {
            $pathDisplay = "..\" + ($parts[-3..-1] -join "\")
        } else {
            $pathDisplay = $c.ProcPath
        }
    }
    $safePathDisplay = [System.Web.HttpUtility]::HtmlEncode($pathDisplay)

    # Parent: show just the exe name without PID for brevity in cell
    $parentExe = ""
    if ($c.Parent) {
        $parentExe = ($c.Parent -split ' ')[0]
    }
    $safeParentExe = [System.Web.HttpUtility]::HtmlEncode($parentExe)

    $rowsHtml += "<tr class=`"$riskClass`" data-proto=`"$($c.Proto)`" data-state=`"$($c.State)`" data-risk=`"$($c.Risk)`" data-proc=`"$safeProc`">`n"
    $rowsHtml += "<td class=`"idx`">$idx</td>`n"
    $rowsHtml += "<td>$riskBadge</td>`n"
    $rowsHtml += "<td><span class=`"proto-$($c.Proto.ToLower())`">$($c.Proto)</span><span class=`"st-sep`">&#183;</span><span class=`"$stateClass`">$($c.State)</span></td>`n"
    $rowsHtml += "<td class=`"addr`">$safeLocal<span class=`"port`">:$($c.LocalPort)</span></td>`n"
    $rowsHtml += "<td class=`"addr`">$safeRemote<span class=`"port`">:$portStr</span>$portLabelHtml</td>`n"
    $rowsHtml += "<td class=`"geo`">$geoHtml</td>`n"
    $parentHtml = if ($safeParentExe) { "<div class=`"par`">via $safeParentExe</div>" } else { "" }
    $rowsHtml += "<td class=`"proc`" title=`"$procTip`"><div class=`"proc-top`"><span class=`"pn`">$safeProc</span><span class=`"pid`">$($c.PID)</span></div><div class=`"pp`">$safePathDisplay</div>$parentHtml</td>`n"
    $rowsHtml += "</tr>`n"
    $idx++
}

# --- DNS rows ---
$dnsRowsHtml = ""
$dnsIdx = 1
$sortedDns = @(
    $dnsEntries | Where-Object { $_.Risk -eq "ALERT" }
    $dnsEntries | Where-Object { $_.Risk -eq "SUSPICIOUS" }
    $dnsEntries | Where-Object { $_.Risk -eq "CLEAN" } | Sort-Object Name
)
foreach ($d in $sortedDns) {
    $safeName  = [System.Web.HttpUtility]::HtmlEncode($d.Name)
    $safeRdata = [System.Web.HttpUtility]::HtmlEncode($d.RData)
    $riskClass = switch ($d.Risk) {
        "ALERT"      { "risk-alert" }
        "SUSPICIOUS" { "risk-susp" }
        default      { "risk-clean" }
    }
    $riskBadge = switch ($d.Risk) {
        "ALERT"      { "<span class=`"rb risk-alert-b`">&#9888; ALERT</span>" }
        "SUSPICIOUS" { "<span class=`"rb risk-susp-b`">&#63; SUSP</span>" }
        default      { "<span class=`"rb risk-clean-b`">&#10003;</span>" }
    }
    $entropyColor = if ($d.Entropy -gt 4.0) { "var(--ac3)" } elseif ($d.Entropy -gt 3.5) { "var(--yw)" } else { "var(--mt)" }
    $dnsRowsHtml += "<tr class=`"$riskClass`">`n"
    $dnsRowsHtml += "<td class=`"idx`">$dnsIdx</td>`n"
    $dnsRowsHtml += "<td>$riskBadge</td>`n"
    $dnsRowsHtml += "<td class=`"dn`">$safeName</td>`n"
    $dnsRowsHtml += "<td class=`"addr`">$safeRdata</td>`n"
    $dnsRowsHtml += "<td style=`"color:$entropyColor;font-size:11px;font-weight:600`">$($d.Entropy)</td>`n"
    $dnsRowsHtml += "<td><span class=`"plabel`">$($d.Type)</span></td>`n"
    $dnsRowsHtml += "<td style=`"color:var(--mt);font-size:11px`">$($d.TTL)s</td>`n"
    $dnsRowsHtml += "</tr>`n"
    $dnsIdx++
}

# --- ARP rows ---
$arpRowsHtml = ""
foreach ($a in $arpEntries) {
    $safeIP  = [System.Web.HttpUtility]::HtmlEncode($a.IP)
    $safeMAC = [System.Web.HttpUtility]::HtmlEncode($a.MAC)
    $arpRowsHtml += "<tr><td class=`"addr`">$safeIP</td><td style=`"color:var(--ac2);font-size:11px`">$safeMAC</td><td style=`"color:var(--mt);font-size:10px`">$($a.Type)</td></tr>`n"
}

# --- Adapter rows ---
$adapterRowsHtml = ""
foreach ($a in $adapters) {
    $safeIface = [System.Web.HttpUtility]::HtmlEncode($a.InterfaceAlias)
    $safeDesc  = [System.Web.HttpUtility]::HtmlEncode($a.Description)
    $safeIP    = [System.Web.HttpUtility]::HtmlEncode($a.IPAddress)
    $safeMAC   = [System.Web.HttpUtility]::HtmlEncode($a.MAC)
    $safeStatus= [System.Web.HttpUtility]::HtmlEncode($a.Status)
    $statusCol = if ($a.Status -eq "Up") { "var(--gr)" } else { "var(--mt)" }
    $adapterRowsHtml += "<tr>`n"
    $adapterRowsHtml += "<td style=`"color:var(--ac);font-size:11px`">$safeIface</td>`n"
    $adapterRowsHtml += "<td style=`"color:var(--mt);font-size:10px`">$safeDesc</td>`n"
    $adapterRowsHtml += "<td class=`"addr`">$safeIP / $($a.PrefixLength)</td>`n"
    $adapterRowsHtml += "<td style=`"color:var(--ac2);font-size:11px`">$safeMAC</td>`n"
    $adapterRowsHtml += "<td style=`"color:$statusCol;font-size:10px`">$safeStatus</td>`n"
    $adapterRowsHtml += "</tr>`n"
}

# --- Stats panels ---
# Top processes by connection count
$procStats = $connections | Group-Object ProcName | Sort-Object Count -Descending | Select-Object -First 12
$procStatsHtml = ""
$maxPS = ($procStats | Measure-Object Count -Maximum).Maximum
if (-not $maxPS -or $maxPS -eq 0) { $maxPS = 1 }
foreach ($ps in $procStats) {
    $pct    = [int](($ps.Count / $maxPS) * 100)
    $alerts = ($ps.Group | Where-Object { $_.Risk -eq "ALERT" }).Count
    $barCol = if ($alerts -gt 0) { "var(--ac3)" } else { "var(--ac2)" }
    $sn     = [System.Web.HttpUtility]::HtmlEncode($ps.Name)
    $procStatsHtml += "<div class=`"sr`"><span class=`"sn`">$sn</span><div class=`"sbw`"><div class=`"sb`" style=`"width:$pct%;background:$barCol`"></div></div><span class=`"sc`">$($ps.Count)</span></div>`n"
}

# Top remote countries
$countryStats = $connections | Where-Object { $_.GeoCountry } |
    Group-Object GeoCountry | Sort-Object Count -Descending | Select-Object -First 10
$countryStatsHtml = ""
$maxCS = ($countryStats | Measure-Object Count -Maximum).Maximum
if (-not $maxCS -or $maxCS -eq 0) { $maxCS = 1 }
foreach ($cs in $countryStats) {
    $pct = [int](($cs.Count / $maxCS) * 100)
    $cn  = [System.Web.HttpUtility]::HtmlEncode($cs.Name)
    $countryStatsHtml += "<div class=`"sr`"><span class=`"sn`">$cn</span><div class=`"sbw`"><div class=`"sb`" style=`"width:$pct%;background:var(--pu)`"></div></div><span class=`"sc`">$($cs.Count)</span></div>`n"
}

$reportTime   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$hostName     = $env:COMPUTERNAME
$runAs        = $env:USERNAME
$totalConns   = $connections.Count
$dnsAlertCnt  = ($dnsEntries | Where-Object { $_.Risk -ne "CLEAN" }).Count

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>ZavetSec NetworkConnections :: $hostName</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#07090e;--bg2:#0d1117;--bg3:#131920;--bg4:#182028;--bd:#1e2d3d;--bd2:#253545;--ac:#00d4ff;--ac2:#2a9fff;--ac3:#ff3060;--gr:#00ff88;--yw:#ffd700;--tx:#d4e4f4;--mt:#6a8aaa;--mt2:#2a3d52;--pu:#b57bff;--or:#ff9a30}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.5;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,0,0,.08) 3px,rgba(0,0,0,.08) 4px);pointer-events:none;z-index:9998}
body::after{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,180,255,.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,180,255,.02) 1px,transparent 1px);background-size:36px 36px;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:1800px;margin:0 auto;padding:0 24px 60px}
/* HEADER */
.hdr{padding:36px 0 28px;border-bottom:1px solid var(--bd);margin-bottom:32px;position:relative}
.hdr::after{content:'';position:absolute;bottom:-1px;left:0;width:200px;height:2px;background:linear-gradient(90deg,var(--gr),transparent)}
.hdr-row{display:flex;justify-content:space-between;flex-wrap:wrap;gap:16px;align-items:flex-start}
.logo-line{display:flex;align-items:center;gap:10px}
.lb{color:var(--gr);font-family:'Rajdhani',sans-serif;font-size:30px;font-weight:700}
.lt{font-family:'Rajdhani',sans-serif;font-size:28px;font-weight:700;letter-spacing:5px;text-transform:uppercase;background:linear-gradient(130deg,#fff 0%,var(--gr) 50%,var(--ac) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.ls{font-size:10px;color:var(--mt);letter-spacing:3px;text-transform:uppercase;margin-top:6px}
.hdr-meta{display:flex;flex-direction:column;gap:5px;align-items:flex-end}
.mi{font-size:11px;color:var(--mt);letter-spacing:1px}.mi span{color:var(--ac)}
/* TABS */
.tabs{display:flex;gap:4px;margin-bottom:0;border-bottom:1px solid var(--bd)}
.tab{padding:10px 20px;font-family:'Rajdhani',sans-serif;font-size:12px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:var(--mt);cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;margin-bottom:-1px}
.tab:hover{color:var(--tx)}
.tab.active{color:var(--gr);border-bottom-color:var(--gr)}
.tabpanel{display:none;padding-top:24px}.tabpanel.active{display:block}
/* CARDS */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:28px}
.card{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:16px 18px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.card.c-total::before{background:linear-gradient(90deg,var(--ac2),var(--ac))}
.card.c-alert::before{background:linear-gradient(90deg,var(--ac3),var(--or))}
.card.c-susp::before{background:linear-gradient(90deg,#a07800,var(--yw))}
.card.c-clean::before{background:linear-gradient(90deg,#006030,var(--gr))}
.card.c-pub::before{background:linear-gradient(90deg,#5500aa,var(--pu))}
.cl{font-size:9px;color:var(--mt);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px}
.cv{font-family:'Rajdhani',sans-serif;font-size:38px;font-weight:700;line-height:1}
.cv.a{color:var(--ac)}.cv.r{color:var(--ac3)}.cv.y{color:var(--yw)}.cv.g{color:var(--gr)}.cv.p{color:var(--pu)}
/* PANELS */
.panels{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:28px}
@media(max-width:900px){.panels{grid-template-columns:1fr}}
.panel{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;overflow:hidden}
.ph{padding:12px 18px;border-bottom:1px solid var(--bd);background:var(--bg3)}
.pt{font-family:'Rajdhani',sans-serif;font-size:12px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:var(--gr)}
.pb{padding:18px}
.sr{display:flex;align-items:center;gap:10px;margin-bottom:9px}
.sn{width:140px;font-size:11px;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0}
.sbw{flex:1;height:5px;background:var(--bg4);border-radius:3px;overflow:hidden}
.sb{height:100%;border-radius:3px}
.sc{font-size:11px;color:var(--mt);width:36px;text-align:right;flex-shrink:0}
/* TOOLBAR */
.tb{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;padding:12px 18px;margin-bottom:14px;display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.tbl{font-size:9px;color:var(--mt);letter-spacing:2px;text-transform:uppercase;white-space:nowrap}
.sw{position:relative;flex:1;min-width:160px}
.si{width:100%;background:var(--bg3);border:1px solid var(--bd2);border-radius:3px;padding:7px 12px;color:var(--tx);font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;transition:border-color .2s}
.si:focus{border-color:var(--gr)}
.si::placeholder{color:var(--mt)}
.fg{display:flex;gap:6px;flex-wrap:wrap}
.fba{background:var(--bg3);border:1px solid var(--bd2);border-radius:3px;padding:4px 10px;color:var(--mt);font-family:'JetBrains Mono',monospace;font-size:10px;cursor:pointer;transition:all .15s;white-space:nowrap}
.fba:hover,.fba.active{border-color:var(--gr);color:var(--gr);background:rgba(0,255,136,.04)}
.fba.fa-alert:hover,.fba.fa-alert.active{border-color:var(--ac3);color:var(--ac3);background:rgba(255,48,96,.05)}
.fba.fa-clean:hover,.fba.fa-clean.active{border-color:var(--gr);color:var(--gr)}
.btn-csv{background:rgba(0,255,136,.08);border:1px solid rgba(0,255,136,.25);border-radius:3px;padding:4px 12px;color:var(--gr);font-family:'JetBrains Mono',monospace;font-size:10px;cursor:pointer;transition:all .15s;white-space:nowrap;margin-left:auto}
.btn-csv:hover{background:rgba(0,255,136,.15);border-color:var(--gr)}
.ctr{font-size:11px;color:var(--mt);margin-left:auto}.ctr span{color:var(--gr)}
/* TABLE */
.tw{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;overflow:hidden}
.ti{overflow-x:auto}
table{width:100%;border-collapse:collapse}
thead{background:var(--bg3);position:sticky;top:0;z-index:10}
th{padding:10px 12px;text-align:left;font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--gr);border-bottom:1px solid var(--bd);font-weight:600;cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:#fff}
th::after{content:' \21C5';opacity:.25;font-size:8px}
th.sa::after{content:' \2191';opacity:1}th.sd::after{content:' \2193';opacity:1}
tbody tr{border-bottom:1px solid var(--bd);transition:background .1s}
tbody tr:hover{background:rgba(0,212,255,.025)}
tbody tr.hidden{display:none}
tbody tr.risk-alert{border-left:3px solid rgba(255,48,96,.6)}
tbody tr.risk-susp{border-left:3px solid rgba(255,215,0,.5)}
tbody tr.risk-clean{border-left:3px solid rgba(0,255,136,.18)}
td{padding:9px 12px;vertical-align:middle}
.idx{color:var(--mt);font-size:10px;width:36px;vertical-align:middle}
.rb{display:inline-block;padding:2px 7px;border-radius:3px;font-size:9px;font-weight:700;letter-spacing:.5px;white-space:nowrap}
.risk-alert-b{background:rgba(255,48,96,.18);color:var(--ac3);border:1px solid rgba(255,48,96,.35)}
.risk-susp-b{background:rgba(255,215,0,.12);color:var(--yw);border:1px solid rgba(255,215,0,.3)}
.risk-clean-b{background:rgba(0,255,136,.08);color:var(--gr);border:1px solid rgba(0,255,136,.2)}
.proto-tcp{display:inline-block;padding:1px 5px;border-radius:2px;font-size:9px;font-weight:700;color:var(--ac);background:rgba(0,212,255,.1);border:1px solid rgba(0,212,255,.2)}
.proto-udp{display:inline-block;padding:1px 5px;border-radius:2px;font-size:9px;font-weight:700;color:var(--pu);background:rgba(153,102,255,.1);border:1px solid rgba(153,102,255,.2)}
.st-est{font-size:10px;color:var(--gr)}
.st-lst{font-size:10px;color:var(--yw)}
.st-tw{font-size:10px;color:var(--mt)}
.st-oth{font-size:10px;color:var(--mt)}
.addr{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--ac2);white-space:nowrap}
.port{color:var(--yw);margin-left:1px}
.geo{font-size:11px;line-height:1.6;min-width:130px}
.flag{display:inline-block;font-size:9px;background:rgba(255,255,255,.1);padding:1px 5px;border-radius:2px;color:#ccc;letter-spacing:1px;font-weight:600}
.geo-priv{font-size:10px;color:var(--mt)}
.geo-unk{color:var(--bd2);font-size:13px}
.hb{display:inline-block;padding:1px 4px;border-radius:2px;font-size:8px;font-weight:700;background:rgba(255,136,0,.2);color:var(--or);border:1px solid rgba(255,136,0,.3);margin-left:3px}
.proc{min-width:220px;max-width:320px}
.proc-top{display:flex;align-items:baseline;gap:6px;margin-bottom:2px}
.pn{color:var(--tx);font-weight:700;font-size:12px;letter-spacing:.3px}
.pid{color:var(--mt);font-size:9px;font-weight:400;background:var(--bg4);padding:1px 5px;border-radius:2px;border:1px solid var(--bd2);white-space:nowrap}
.pp{font-size:10px;color:var(--mt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:300px;margin-bottom:1px}
.par{font-size:10px;color:var(--pu);margin-top:1px}
.plabel{display:inline-block;margin-left:5px;padding:1px 5px;border-radius:2px;font-size:9px;font-weight:600;color:var(--ac2);background:rgba(42,159,255,.1);border:1px solid rgba(42,159,255,.2);vertical-align:middle;letter-spacing:.3px}
.st-sep{margin:0 4px;color:var(--bd2);font-size:11px}
.geo-block{display:flex;flex-direction:column;gap:1px;padding:4px 6px;background:rgba(255,255,255,.02);border-radius:3px;border:1px solid var(--bd)}
.geo-country{display:flex;align-items:center;gap:4px;font-size:11px;color:var(--tx);font-weight:600}
.geo-detail{font-size:10px;color:var(--mt)}
.geo-isp{font-size:10px;color:var(--ac2);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pub{font-size:10px;color:var(--mt);max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:middle}
.dn{font-size:11px;color:var(--ac2);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* secondary tables */
.stw{background:var(--bg2);border:1px solid var(--bd);border-radius:4px;overflow:hidden;margin-bottom:24px}
.sth{padding:10px 16px;background:var(--bg3);border-bottom:1px solid var(--bd);font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--ac)}
/* FOOTER */
.ftr{margin-top:36px;padding-top:18px;border-top:1px solid var(--bd);display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px}
.ft{font-size:10px;color:var(--mt)}.fa{color:var(--gr)}
.nr{text-align:center;padding:36px;color:var(--mt);font-size:12px;display:none}
.nr.v{display:block}
</style>
</head>
<body>
<div class="wrap">
<header class="hdr">
  <div class="hdr-row">
    <div>
      <div class="logo-line"><span class="lb">[</span><span class="lt">ZavetSec Network Connections</span><span class="lb">]</span></div>
      <div class="ls">Live Connection Snapshot &nbsp;//&nbsp; Process Context &nbsp;//&nbsp; GeoIP Enrichment</div>
    </div>
    <div class="hdr-meta">
      <div class="mi">HOST <span>$hostName</span></div>
      <div class="mi">RUN AS <span>$runAs</span></div>
      <div class="mi">TIME <span>$reportTime</span></div>
    </div>
  </div>
</header>

<!-- TABS -->
<div class="tabs">
  <div class="tab active" onclick="showTab('connections',this)">Connections ($totalConns)</div>
  <div class="tab" onclick="showTab('dns',this)">DNS Cache ($($dnsEntries.Count))</div>
  <div class="tab" onclick="showTab('network',this)">Network Info</div>
</div>

<!-- TAB: CONNECTIONS -->
<div class="tabpanel active" id="tab-connections">
<div class="cards">
  <div class="card c-total"><div class="cl">Total</div><div class="cv a">$totalConns</div></div>
  <div class="card c-alert"><div class="cl">ALERT</div><div class="cv r">$alertConns</div></div>
  <div class="card c-susp"><div class="cl">SUSPICIOUS</div><div class="cv y">$suspConns</div></div>
  <div class="card c-clean"><div class="cl">CLEAN</div><div class="cv g">$cleanConns</div></div>
  <div class="card c-pub"><div class="cl">Established</div><div class="cv p">$established</div></div>
  <div class="card c-total"><div class="cl">To Public IPs</div><div class="cv a">$publicConns</div></div>
</div>
<div class="panels">
  <div class="panel"><div class="ph"><span class="pt">Top Processes</span></div><div class="pb">$procStatsHtml</div></div>
  <div class="panel"><div class="ph"><span class="pt">Top Countries</span></div><div class="pb">$countryStatsHtml</div></div>
</div>
<div class="tb">
  <span class="tbl">Risk</span>
  <div class="fg">
    <button class="fba active"   data-r="all"       onclick="srf('all',this)">All</button>
    <button class="fba fa-alert" data-r="ALERT"     onclick="srf('ALERT',this)">&#9888; ALERT ($alertConns)</button>
    <button class="fba"          data-r="SUSPICIOUS" onclick="srf('SUSPICIOUS',this)">? SUSP ($suspConns)</button>
    <button class="fba fa-clean" data-r="CLEAN"     onclick="srf('CLEAN',this)">&#10003; CLEAN ($cleanConns)</button>
  </div>
  <span class="tbl" style="margin-left:6px">Proto</span>
  <div class="fg">
    <button class="fba active" data-p="all" onclick="spf('all',this)">All</button>
    <button class="fba" data-p="TCP" onclick="spf('TCP',this)">TCP</button>
    <button class="fba" data-p="UDP" onclick="spf('UDP',this)">UDP</button>
  </div>
  <span class="tbl" style="margin-left:6px">State</span>
  <div class="fg">
    <button class="fba active" data-s="all" onclick="ssf('all',this)">All</button>
    <button class="fba" data-s="Established" onclick="ssf('Established',this)">Established</button>
    <button class="fba" data-s="Listen" onclick="ssf('Listen',this)">Listen</button>
  </div>
  <div class="sw"><input class="si" id="ci" placeholder="Search process, IP, port, country..." oninput="cft()"/></div>
  <div class="ctr">Showing <span id="csc">$totalConns</span> / $totalConns</div>
  <button class="btn-csv" onclick="exportCsv()">&#8595; Export CSV</button>
</div>
<div class="tw"><div class="ti">
<table id="ctable">
<thead><tr>
  <th onclick="cst(0)">#</th>
  <th onclick="cst(1)">Risk</th>
  <th onclick="cst(2)">Proto / State</th>
  <th onclick="cst(3)">Local</th>
  <th onclick="cst(4)">Remote</th>
  <th onclick="cst(5)">Geo</th>
  <th onclick="cst(6)">Process / Path / Parent</th>
</tr></thead>
<tbody id="ctb">
$rowsHtml
</tbody>
</table>
</div>
<div class="nr" id="cnr">No matching connections.</div>
</div>
</div><!-- /tab-connections -->

<!-- TAB: DNS -->
<div class="tabpanel" id="tab-dns">
<div class="cards">
  <div class="card c-total"><div class="cl">DNS Entries</div><div class="cv a">$($dnsEntries.Count)</div></div>
  <div class="card c-alert"><div class="cl">Anomalous</div><div class="cv r">$dnsAlertCnt</div></div>
</div>
<div class="tb">
  <div class="sw"><input class="si" id="di" placeholder="Search hostname, IP..." oninput="dft()"/></div>
  <div class="ctr">Showing <span id="dsc">$($dnsEntries.Count)</span> / $($dnsEntries.Count)</div>
</div>
<div class="tw"><div class="ti">
<table id="dtable">
<thead><tr>
  <th>#</th><th>Risk</th><th>Hostname</th><th>Resolved IP</th>
  <th title="Shannon entropy of hostname label -- high value may indicate DGA or DNS tunnel">Entropy</th>
  <th>Type</th><th>TTL</th>
</tr></thead>
<tbody id="dtb">
$dnsRowsHtml
</tbody>
</table>
</div>
<div class="nr" id="dnr">No matching DNS entries.</div>
</div>
</div><!-- /tab-dns -->

<!-- TAB: NETWORK INFO -->
<div class="tabpanel" id="tab-network">
<div class="stw">
  <div class="sth">Network Adapters</div>
  <div class="ti">
  <table><thead><tr>
    <th>Interface</th><th>Description</th><th>IP / Prefix</th><th>MAC</th><th>Status</th>
  </tr></thead>
  <tbody>$adapterRowsHtml</tbody></table>
  </div>
</div>
<div class="stw">
  <div class="sth">ARP Cache ($($arpEntries.Count) entries)</div>
  <div class="ti">
  <table><thead><tr><th>IP Address</th><th>MAC Address</th><th>Type</th></tr></thead>
  <tbody>$arpRowsHtml</tbody></table>
  </div>
</div>
</div><!-- /tab-network -->

<div class="ftr">
  <div class="ft">Generated by <span class="fa">ZavetSec-NetworkConnections.ps1</span></div>
  <div class="ft">$hostName :: $runAs :: <span class="fa">$reportTime</span></div>
  <div class="ft"><a href="https://gitlab.com/zavetsec" target="_blank" style="color:var(--mt);text-decoration:none;transition:color .15s" onmouseover="this.style.color='var(--gr)'" onmouseout="this.style.color='var(--mt)'">gitlab.com/zavetsec</a></div>
</div>
</div><!-- /wrap -->

<script>
// --- Tabs ---
function showTab(id,el){
  document.querySelectorAll('.tabpanel').forEach(function(p){p.classList.remove('active');});
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});
  document.getElementById('tab-'+id).classList.add('active');
  el.classList.add('active');
}

// --- Connections filter ---
var cr='all',cp='all',cs='all',cq='';
function srf(n,el){cr=n;document.querySelectorAll('.fg .fba[data-r]').forEach(function(b){b.classList.remove('active');});el.classList.add('active');cft();}
function spf(n,el){cp=n;document.querySelectorAll('.fg .fba[data-p]').forEach(function(b){b.classList.remove('active');});el.classList.add('active');cft();}
function ssf(n,el){cs=n;document.querySelectorAll('.fg .fba[data-s]').forEach(function(b){b.classList.remove('active');});el.classList.add('active');cft();}
function cft(){
  cq=document.getElementById('ci').value.toLowerCase();
  var r=document.querySelectorAll('#ctb tr'),s=0;
  r.forEach(function(x){
    var mr=cr==='all'||x.dataset.risk===cr;
    var mp=cp==='all'||x.dataset.proto===cp;
    var ms=cs==='all'||x.dataset.state===cs;
    var cells=Array.from(x.cells).map(function(c){return c.textContent.toLowerCase();}).join(' ');
    var mq=!cq||cells.indexOf(cq)>=0;
    var v=mr&&mp&&ms&&mq;x.classList.toggle('hidden',!v);if(v)s++;
  });
  document.getElementById('csc').textContent=s;
  document.getElementById('cnr').classList.toggle('v',s===0);
}
var csc_=-1,csa=true;
function cst(c){
  var tb=document.getElementById('ctb'),r=Array.from(tb.querySelectorAll('tr')),hs=document.querySelectorAll('#ctable th');
  if(csc_===c){csa=!csa;}else{csc_=c;csa=true;}
  hs.forEach(function(h,i){h.classList.remove('sa','sd');if(i===c)h.classList.add(csa?'sa':'sd');});
  r.sort(function(a,b){
    var av=a.cells[c]?a.cells[c].textContent.trim():'',bv=b.cells[c]?b.cells[c].textContent.trim():'';
    var n=parseFloat(av)-parseFloat(bv);if(!isNaN(n))return csa?n:-n;
    return csa?av.localeCompare(bv):bv.localeCompare(av);
  });
  r.forEach(function(x){tb.appendChild(x);});
}

// --- CSV Export from browser ---
function exportCsv(){
  var rows=document.querySelectorAll('#ctb tr:not(.hidden)');
  // BOM for Excel UTF-8 recognition
  var bom='\uFEFF';
  var lines=['Risk,Proto,State,Local Addr,Local Port,Remote Addr,Remote Port,Geo Country,Geo City,Geo ISP,Process,Path,Parent'];
  rows.forEach(function(r){
    var c=r.cells;
    if(!c||c.length<7)return;

    // Use data attributes for clean values (no HTML entities / Unicode symbols)
    var risk  = r.dataset.risk  || '';
    var proto = r.dataset.proto || '';
    var state = r.dataset.state || '';
    var proc  = r.dataset.proc  || '';

    // Local: addr:port from cell text
    var localTxt = c[3] ? c[3].textContent.trim() : '';
    var lastColon = localTxt.lastIndexOf(':');
    var localAddr = lastColon > 0 ? localTxt.substring(0, lastColon) : localTxt;
    var localPort = lastColon > 0 ? localTxt.substring(lastColon+1) : '';

    // Remote: addr:port
    var remoteTxt = c[4] ? c[4].textContent.trim() : '';
    var rColon = remoteTxt.lastIndexOf(':');
    var remoteAddr = rColon > 0 ? remoteTxt.substring(0, rColon) : remoteTxt;
    var remotePort = rColon > 0 ? remoteTxt.substring(rColon+1) : '';

    // Geo: extract lines from cell
    var geoLines = c[5] ? c[5].innerText.trim().split('\n') : [];
    var geoCountry = (geoLines[0]||'').replace(/^[A-Z]{2}\s/,'').trim();
    var geoCity    = geoLines[1] || '';
    var geoISP     = geoLines[2] || '';

    // Path: full path from title attribute of proc cell (tooltip contains full path)
    var procCell = c[6];
    var titleRaw = procCell ? (procCell.getAttribute('title') || '') : '';
    // title format: "Path: C:\...\exe\nCMD: ...\nParent: ..."
    var path = '';
    var parent = '';
    var titleLines = titleRaw.split('\n');
    titleLines.forEach(function(line){
      if(line.indexOf('Path: ') === 0)   path   = line.substring(6).trim();
      if(line.indexOf('Parent: ') === 0) parent = line.substring(8).trim();
    });
    // Fallback: use .pp span if title had no path
    if(!path){ var ppSpan=procCell?procCell.querySelector('.pp'):null; path=ppSpan?ppSpan.textContent.trim():''; }

    function esc(v){return '"'+(v||'').replace(/"/g,'""')+'"';}
    lines.push([esc(risk),esc(proto),esc(state),esc(localAddr),esc(localPort),
                esc(remoteAddr),esc(remotePort),esc(geoCountry),esc(geoCity),
                esc(geoISP),esc(proc),esc(path),esc(parent)].join(','));
  });
  var blob=new Blob([bom+lines.join('\r\n')],{type:'text/csv;charset=utf-8;'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='ZavetSec-NetworkConnections_export.csv';
  a.click();
  URL.revokeObjectURL(a.href);
}
function dft(){
  var q=document.getElementById('di').value.toLowerCase();
  var r=document.querySelectorAll('#dtb tr'),s=0;
  r.forEach(function(x){
    var cells=Array.from(x.cells).map(function(c){return c.textContent.toLowerCase();}).join(' ');
    var v=!q||cells.indexOf(q)>=0;
    x.classList.toggle('hidden',!v);if(v)s++;
  });
  document.getElementById('dsc').textContent=s;
  document.getElementById('dnr').classList.toggle('v',s===0);
}
</script>
</body>
</html>
"@

$html | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host "  [+] Report saved: $OutputPath" -ForegroundColor Green

# --- CSV Export ---
if ($ExportCsv) {
    $csvPath = $OutputPath -replace '\.html$','.csv'

    # Build CSV content with UTF-8 BOM so Excel opens without garbled characters
    $csvRows = $connections | Select-Object `
        Risk, Proto, State,
        LocalAddr, LocalPort,
        RemoteAddr, RemotePort, PortLabel,
        PID, ProcName, ProcPath, CmdLine, Parent,
        GeoCountry, GeoCity, GeoISP, GeoCC,
        @{N='GeoHosting'; E={ if ($_.GeoHosting) { 'Yes' } else { 'No' } }}

    # Export-Csv in PS 5.1 does not support -Encoding UTF8BOM, so write BOM manually
    $tempCsv = [System.IO.Path]::GetTempFileName()
    $csvRows | Export-Csv -Path $tempCsv -NoTypeInformation -Encoding UTF8
    $csvContent = [System.IO.File]::ReadAllText($tempCsv, [System.Text.Encoding]::UTF8)
    Remove-Item $tempCsv -Force -ErrorAction SilentlyContinue

    $utf8Bom = New-Object System.Text.UTF8Encoding $true   # $true = emit BOM
    [System.IO.File]::WriteAllText($csvPath, $csvContent, $utf8Bom)

    Write-Host "  [+] CSV saved  : $csvPath" -ForegroundColor Green

    # DNS CSV (separate file)
    if ($dnsEntries.Count -gt 0) {
        $dnsCsvPath = $OutputPath -replace '\.html$','_dns.csv'
        $tempDns = [System.IO.Path]::GetTempFileName()
        $dnsEntries | Select-Object Risk, Name, RData, Type, TTL, Entropy |
            Export-Csv -Path $tempDns -NoTypeInformation -Encoding UTF8
        $dnsCsvContent = [System.IO.File]::ReadAllText($tempDns, [System.Text.Encoding]::UTF8)
        Remove-Item $tempDns -Force -ErrorAction SilentlyContinue
        [System.IO.File]::WriteAllText($dnsCsvPath, $dnsCsvContent, $utf8Bom)
        Write-Host "  [+] DNS CSV    : $dnsCsvPath" -ForegroundColor Green
    }
}

Write-Host ""

if ($OpenReport) {
    Start-Process $OutputPath
}
