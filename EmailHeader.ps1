# 🔐 Set your VirusTotal API key
$VT_APIKey = ""

function Parse-Headers {
    param ([string]$Headers)

    # Unfold multiline headers (combine continuation lines)
    $unfolded = ($Headers -split "`n") -join "`n"
    $unfolded = $unfolded -replace "`n\s+", " "

    Write-Host "`n📬 [+] Basic Header Fields" -ForegroundColor Cyan

    foreach ($key in "From", "To", "Subject", "Reply-To", "Return-Path", "Message-ID") {
        $pattern = "(?im)^${key}:\s*(.+)"
        if ($unfolded -match $pattern) {
            $value = $matches[1].Trim()
            $decoded = Decode-MIMEHeader -EncodedString $value
            Write-Host ("   ✉ {0,-13}: {1}" -f $key, $decoded) -ForegroundColor White
        } else {
            Write-Host ("   ✉ {0,-13}: Not found" -f $key) -ForegroundColor DarkGray
        }
    }

    Write-Host "`n🔒 [+] Authentication Results" -ForegroundColor Cyan
    if ($unfolded -match "(?im)^Authentication-Results:\s*(.+)") {
        Write-Host ("   ✅ Authentication-Results: {0}" -f $matches[1]) -ForegroundColor White
    } else {
        Write-Host "   ❌ Authentication-Results: Not found" -ForegroundColor DarkGray
    }

    Write-Host "`n🛡 [+] SPF / DKIM / DMARC" -ForegroundColor Cyan
    if ($unfolded -match "(?im)^Received-SPF:\s*(.+)") {
        Write-Host ("   ☀️  SPF Result           : {0}" -f $matches[1]) -ForegroundColor White
    } else {
        Write-Host "   ☀️  SPF Result           : Not found" -ForegroundColor DarkGray
    }

    Write-Host ("   ✍️  DKIM Signature       : {0}" -f ($unfolded -match "(?im)^DKIM-Signature:" ? "Found" : "Not found")) -ForegroundColor White

    Write-Host "`n🏢 [+] Microsoft / Exchange Headers" -ForegroundColor Cyan
    ($unfolded -split "`n") | Where-Object { $_ -match "^(X-MS|X-Forefront).*:" } | ForEach-Object {
        Write-Host ("   🏷  {0}" -f $_.Trim()) -ForegroundColor Gray
    }

    Write-Host "`n🔐 [+] Tenant ID" -ForegroundColor Cyan
    if ($unfolded -match "(?im)^X-MS-Exchange-Tenant-Id:\s*(.+)") {
        Write-Host "   🆔 Tenant ID: $($matches[1])" -ForegroundColor White
    } else {
        Write-Host "   🆔 Tenant ID: Not found" -ForegroundColor DarkGray
    }

    Write-Host "`n📡 [+] Mail Route (Received Headers)" -ForegroundColor Cyan
    $receivedLines = ($unfolded -split "`n") | Where-Object { $_ -like "Received:*" }
    [array]::Reverse($receivedLines)
    foreach ($line in $receivedLines) {
        Write-Host "   🔁 $line" -ForegroundColor DarkGray
    }

    return $receivedLines
}

function Decode-MIMEHeader {
    param ([string]$EncodedString)

    # Try decoding UTF-8 base64 or quoted-printable encoded strings
    if ($EncodedString -match "=\?UTF-8\?B\?(.+?)\?=") {
        $base64 = $matches[1]
        $bytes = [System.Convert]::FromBase64String($base64)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } elseif ($EncodedString -match "=\?UTF-8\?Q\?(.+?)\?=") {
        $qp = $matches[1] -replace "_", " " -replace "=([0-9A-F]{2})", { [char][byte]("0x$($args[0].Groups[1].Value)") }
        return $qp
    } else {
        return $EncodedString
    }
}

function Extract-IPs {
    param ([string[]]$ReceivedHeaders)

    $ipRegex = "\b(?:\d{1,3}\.){3}\d{1,3}\b"
    $ipSet = @{}
    foreach ($line in $ReceivedHeaders) {
        $matches = [regex]::Matches($line, $ipRegex)
        foreach ($match in $matches) {
            $ipSet[$match.Value] = $true
        }
    }
    return $ipSet.Keys
}

function Check-VirusTotal {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ip
    )

    $url = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
    $headers = @{ "x-apikey" = $VT_APIKey }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
        $data = $response.data
        $attributes = $data.attributes
        $stats = $attributes.last_analysis_stats
        $analysisDate = [DateTimeOffset]::FromUnixTimeSeconds($attributes.last_analysis_date).ToString("yyyy-MM-dd HH:mm:ss")
        $isMalicious = $stats.malicious -gt 0
        $ipColor = if ($isMalicious) { "Red" } else { "Green" }

        # 📌 IP Overview
        Write-Host "`n🧠 IP Overview: $ip" -ForegroundColor Yellow
        Write-Host "   🌍 Country        : $($attributes.country)" -ForegroundColor White
        Write-Host "   🏢 Owner          : $($attributes.as_owner)" -ForegroundColor White
        Write-Host "   ⭐ Reputation     : $($attributes.reputation)" -ForegroundColor Yellow
        Write-Host "   🕒 Last Analysis  : $analysisDate" -ForegroundColor White

        # 🛡️ Threat Stats
        Write-Host "`n🛡️ Threat Stats:" -ForegroundColor Cyan
        Write-Host ("   ✔ Harmless       : {0}" -f $stats.harmless) -ForegroundColor Green
        Write-Host ("   ⚠ Suspicious     : {0}" -f $stats.suspicious) -ForegroundColor Yellow
        Write-Host ("   ❌ Malicious      : {0}" -f $stats.malicious) -ForegroundColor $ipColor
        Write-Host ("   ❓ Undetected     : {0}" -f $stats.undetected) -ForegroundColor Gray

 # Passive DNS
if ($attributes.total_resolutions -gt 0 -and $attributes.resolutions) {
    Write-Host "`n📡 Passive DNS Replication (Top 5):" -ForegroundColor Cyan
    $topRes = $attributes.resolutions | Select-Object -First 5

    foreach ($res in $topRes) {
        # Try to get hostname directly
        $hostname = $null
        if ($res.PSObject.Properties.Name -contains 'hostname' -and $res.hostname -ne '') {
            $hostname = $res.hostname
        } else {
            # Fallback: parse hostname from 'id' field
            $id = $res.id
            # Remove leading IP (e.g. 4.248.26.197)
            $domain = $id -replace '^\d{1,3}(?:\.\d{1,3}){3}', ''
            # Remove leading digits/dashes
            $domain = $domain -replace '^[\d-]*', ''
            $hostname = $domain
        }

        # Convert date from Unix timestamp if available
        $dateStr = "Unknown Date"
        if ($res.PSObject.Properties.Name -contains 'date' -and $res.date -match '^\d+$') {
            $dateStr = [DateTimeOffset]::FromUnixTimeSeconds([int]$res.date).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        }

        Write-Host ("   🔗 Hostname: {0}  📅 {1}" -f $hostname, $dateStr) -ForegroundColor White
    }
}


        # Communicating Files
        if ($attributes.communicating_files.Count -gt 0) {
            Write-Host "`n📁 Communicating Files (Top 5):" -ForegroundColor Cyan
            $topFiles = $attributes.communicating_files | Select-Object -First 5
            foreach ($file in $topFiles) {
                Write-Host ("   🧬 SHA256 : {0}" -f $file.id) -ForegroundColor Magenta
                Write-Host ("     📂 Type : {0}" -f $file.type_description) -ForegroundColor DarkCyan
            }
        }

        Write-Host "`n✅ Scan Complete for $ip" -ForegroundColor Green
        Write-Host "---------------------------------------------------"

    } catch {
        Write-Host "❌ Error querying VirusTotal: $_" -ForegroundColor Red
    }
}

function Analyze-Headers {
    Write-Host "`n💼 SOC Email Header Analyzer" -ForegroundColor Magenta
    Write-Host "📩 Paste full email headers (press Enter on an empty line to finish):" -ForegroundColor Gray

    $lines = @()
    while ($true) {
        $line = Read-Host
        if ([string]::IsNullOrWhiteSpace($line)) { break }
        $lines += $line
    }

    $rawHeaders = $lines -join "`n"
    $receivedLines = Parse-Headers -Headers $rawHeaders
    $ips = Extract-IPs -ReceivedHeaders $receivedLines

    Write-Host "`n🔎 [+] VirusTotal IP Scan Results" -ForegroundColor Cyan
    foreach ($ip in $ips) {
        Write-Host "`n🚨 Checking IP: $ip" -ForegroundColor Yellow
        Check-VirusTotal -ip $ip
    }
}
# 🚀 Start Analysis
Analyze-Headers
