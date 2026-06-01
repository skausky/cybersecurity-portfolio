<#
.SYNOPSIS
    Audits a Windows host against a selection of CIS-aligned security controls
    and reports PASS / FAIL for each. Read-only by default.

.DESCRIPTION
    Learning artifact for a blue-team portfolio. Checks common hardening
    controls and prints a colour-coded report. Does NOT make changes.

.NOTES
    Author : Sean Spakausky
    Run as : Administrator (PowerShell)
    Test in a lab / snapshot before relying on results in production.

.EXAMPLE
    .\Invoke-WindowsAudit.ps1
#>

[CmdletBinding()]
param()

$results = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [string]$Control,
        [bool]$Pass,
        [string]$Detail
    )
    $results.Add([pscustomobject]@{
        Control = $Control
        Status  = if ($Pass) { 'PASS' } else { 'FAIL' }
        Detail  = $Detail
    })
}

Write-Host "`n=== Windows Security Audit ($(Get-Date -Format s)) ===`n" -ForegroundColor Cyan

# 1. SMBv1 should be disabled (CIS / WannaCry mitigation)
try {
    $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    Add-Check 'SMBv1 disabled' (-not $smb1) "EnableSMB1Protocol = $smb1"
} catch { Add-Check 'SMBv1 disabled' $false "Could not query: $($_.Exception.Message)" }

# 2. Windows Firewall enabled on all profiles
try {
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $allOn = ($profiles | Where-Object { -not $_.Enabled } | Measure-Object).Count -eq 0
    Add-Check 'Firewall enabled (all profiles)' $allOn (($profiles | ForEach-Object { "$($_.Name)=$($_.Enabled)" }) -join ', ')
} catch { Add-Check 'Firewall enabled (all profiles)' $false "Could not query: $($_.Exception.Message)" }

# 3. RDP Network Level Authentication required
try {
    $nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop).UserAuthentication
    Add-Check 'RDP requires NLA' ($nla -eq 1) "UserAuthentication = $nla"
} catch { Add-Check 'RDP requires NLA' $false "Could not query (RDP may be disabled)" }

# 4. Guest account disabled
try {
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
    Add-Check 'Guest account disabled' (-not $guest.Enabled) "Enabled = $($guest.Enabled)"
} catch { Add-Check 'Guest account disabled' $true 'Guest account not present' }

# 5. PowerShell Script Block Logging enabled
try {
    $sbl = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction Stop).EnableScriptBlockLogging
    Add-Check 'PS Script Block Logging' ($sbl -eq 1) "EnableScriptBlockLogging = $sbl"
} catch { Add-Check 'PS Script Block Logging' $false 'Not configured' }

# --- Report ---
foreach ($r in $results) {
    $colour = if ($r.Status -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host ('[{0}] {1,-34} {2}' -f $r.Status, $r.Control, $r.Detail) -ForegroundColor $colour
}

$pass = ($results | Where-Object Status -eq 'PASS').Count
Write-Host ("`nScore: {0}/{1} controls passing.`n" -f $pass, $results.Count) -ForegroundColor Cyan
