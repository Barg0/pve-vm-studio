<#
pvs-cis.ps1 - applies and checks a CIS Benchmark inside a Windows guest (PVE VM Studio).

  pvs-cis.ps1 fix   -Benchmark w11sa -Level 1|2 [-Phase gold|vm] [-Exceptions FILE] [-Only ID,ID]
  pvs-cis.ps1 check -Benchmark w11sa -Level 1|2 [-Exceptions FILE] [-Only ID,ID] [-Json FILE]
  pvs-cis.ps1 list  -Benchmark w11sa

The rules are <bench>\rules.tsv beside this script (cisv winmap: id, level, kind, mech, target,
op, value, title - no CIS text). One recommendation may have several rows (several registry
values); all of them must hold. Mechanisms:
  reg    a registry value; HKU means every user: the Default user's hive and every profile
  acct   a secedit [System Access] key (account policy, lockout, guest, anonymous SID lookup)
  right  a user right (secedit [Privilege Rights]), principals as SIDs or names
  audit  an advanced audit subcategory (auditpol)
Phases of fix: gold (the bake's audit mode, before sysprep - all but the renames survive
generalize, measured 2026-10-18), vm (each deployed VM in SetupComplete: everything again plus
the renames of the built-in Administrator and Guest, which generalize resets - OOBE changes
values on the way - but not Winlogon AutoAdminLogon: OOBE signs its defaultuser0 in once after
SetupComplete and only then disables it; a 0 there leaves that account enabled and in
Administrators) and final (the studio, once OOBE is done: all of it, AutoAdminLogon included).
Measured on the deployed CIS VMs 2026-10-18.
Exceptions: one "ID<TAB>reason[<TAB>fix]" per line, as for Linux: a plain fail becomes
"exception"; its fix is skipped unless the third column says fix.
The JSON report has the Linux engine's shape, so the studio reads both the same way.
#>
param(
    [Parameter(Position = 0, Mandatory = $true)][ValidateSet('fix', 'check', 'list', 'emit')][string]$Command,
    [Parameter(Mandatory = $true)][string]$Benchmark,
    [ValidateSet(1, 2)][int]$Level = 1,
    [ValidateSet('gold', 'vm', 'final')][string]$Phase = 'gold',
    [string]$Exceptions = '',
    [string]$Only = '',
    [string]$Json = '',
    [string]$AdminName = 'pvsadmin',
    [string]$GuestName = 'pvsguest',
    # the bake reads its console: CIS-* lines go out as PVS-CIS-* markers
    [switch]$Markers
)
$ErrorActionPreference = 'Stop'
$Pre = if ($Markers) { 'PVS-' } else { '' }
Set-StrictMode -Version 2.0
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path

# The studio's log layout (GuestProvision.ps1 Write-Log): time, a five-wide tag, the message.
function Write-Log([string]$Tag, [string]$Msg) {
    $shown = if ($Tag -eq 'ok') { 'o.k.' } else { $Tag }
    Write-Host (' {0} [ {1,-5} ] {2}' -f (Get-Date -Format 'HH:mm:ss'), $shown, $Msg)
}

$BenchConf = @{
    w11sa    = @{ name = 'CIS Microsoft Windows 11 Stand-alone Benchmark'; version = '5.0.0' }
    ws2025sa = @{ name = 'CIS Microsoft Windows Server 2025 Stand-alone Benchmark'; version = '2.0.0' }
    ws2022sa = @{ name = 'CIS Microsoft Windows Server 2022 Stand-alone Benchmark'; version = '2.0.0' }
}
if (-not $BenchConf.ContainsKey($Benchmark)) { throw "unknown benchmark $Benchmark" }

# ---- the rules ----
$Rules = @()
foreach ($line in Get-Content (Join-Path $Here "$Benchmark\rules.tsv")) {
    if ($line -match '^\s*(#|$)') { continue }
    $f = $line -split "`t"
    $Rules += [pscustomobject]@{ id = $f[0]; level = $f[1]; kind = $f[2]; mech = $f[3]; target = $f[4]; op = $f[5]; value = $f[6]; title = $f[7] }
}
# The site's own values (the studio's CIS settings, kept with the gold): "Key<TAB>value" in
# site beside this script, UTF-8. They replace the rules' defaults for the logon message
# (2.3.7.4, 2.3.7.5) and the names the built-in accounts get (2.3.1.3, 2.3.1.4).
$SiteFile = Join-Path $Here 'site'
if (Test-Path $SiteFile) {
    $Site = @{}
    foreach ($line in Get-Content -Encoding UTF8 $SiteFile) {
        $f = $line -split "`t", 2
        if ($f.Count -eq 2 -and $f[1].Trim()) { $Site[$f[0]] = $f[1].Trim() }
    }
    if ($Site.ContainsKey('AdminName') -and -not $PSBoundParameters.ContainsKey('AdminName')) { $AdminName = $Site['AdminName'] }
    if ($Site.ContainsKey('GuestName') -and -not $PSBoundParameters.ContainsKey('GuestName')) { $GuestName = $Site['GuestName'] }
    foreach ($r in $Rules) {
        foreach ($k in 'LegalNoticeText', 'LegalNoticeCaption') {
            if ($r.mech -eq 'reg' -and $r.target -like "*:$k" -and $Site.ContainsKey($k)) { $r.value = 'REG_SZ:' + $Site[$k] }
        }
    }
}
$OnlySet = @{}
if ($Only) { foreach ($i in $Only -split ',') { $OnlySet[$i.Trim()] = 1 } }
function Selected($r) {
    $inLevel = ($r.level -eq 'L1') -or ($r.level -eq 'L2' -and $Level -ge 2)
    $inLevel -and ((-not $Only) -or $OnlySet.ContainsKey($r.id))
}
$Ids = @()
$ById = @{}
foreach ($r in $Rules) {
    if (-not (Selected $r)) { continue }
    if (-not $ById.ContainsKey($r.id)) { $ById[$r.id] = @(); $Ids += $r.id }
    $ById[$r.id] += $r
}
$Exc = @{}; $ExcFix = @{}
foreach ($ef in @((Join-Path $Here "$Benchmark\exceptions.default"), $Exceptions)) {
    if ($ef -and (Test-Path $ef)) {
        foreach ($line in Get-Content $ef) {
            if ($line -match '^\s*(#|$)') { continue }
            $f = $line -split "`t"
            $Exc[$f[0]] = if ($f.Count -gt 1 -and $f[1]) { $f[1] } else { 'no reason given' }
            if ($f.Count -gt 2 -and $f[2] -eq 'fix') { $ExcFix[$f[0]] = 1 }
        }
    }
}

# ---- principals ----
# A service's SID is the SHA-1 of its upper-case name (UTF-16LE) as five little-endian words:
# NT SERVICE\x under S-1-5-80, RESTRICTED SERVICES\x under S-1-5-99. Computed, because the
# name translates only while that service (or its restricted SID) is registered - in audit
# mode RESTRICTED SERVICES\PrintSpoolerService does not, and would silently drop out.
function Service-Sid([string]$auth, [string]$name) {
    $sha = [System.Security.Cryptography.SHA1]::Create()
    $h = $sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes($name.ToUpperInvariant()))
    "S-1-5-$auth-" + ((0..4 | ForEach-Object { [BitConverter]::ToUInt32($h, $_ * 4) }) -join '-')
}
function Resolve-Sid([string]$p) {
    if ($p.StartsWith('*')) { return $p.Substring(1) }
    if ($p -match '^NT SERVICE\\(.+)$') { return Service-Sid 80 $Matches[1] }
    if ($p -match '^RESTRICTED SERVICES\\(.+)$') { return Service-Sid 99 $Matches[1] }
    try { return (New-Object System.Security.Principal.NTAccount($p)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { return $null }
}
function Sid-Name([string]$sid) {
    try { return (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $sid }
}

# ---- secedit ----
function Get-Secedit {
    $tmp = Join-Path $env:TEMP ("pvs-cis-" + [guid]::NewGuid().ToString('N') + '.inf')
    & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
    $o = @{}
    if (Test-Path $tmp) {
        foreach ($l in Get-Content $tmp) {
            if ($l -match '^\s*([A-Za-z]+)\s*=\s*(.*)$') { $o[$Matches[1]] = $Matches[2].Trim().Trim('"') }
        }
        Remove-Item $tmp -Force
    }
    $o
}

# ---- registry ----
function Split-Target([string]$t) {
    $i = $t.LastIndexOf(':')
    @{ path = $t.Substring(0, $i); name = $t.Substring($i + 1) }
}
function Hive-Roots([string]$path) {
    # HKLM\x -> HKLM:\x; HKU\x -> every user: the Default hive (mounted as HKU\pvs-cis-default) and each loaded profile
    if ($path.StartsWith('HKLM\')) { return @('HKLM:\' + $path.Substring(5)) }
    $rest = $path.Substring(4)
    $roots = @()
    if (Test-Path 'Registry::HKEY_USERS\pvs-cis-default') { $roots += "Registry::HKEY_USERS\pvs-cis-default\$rest" }
    foreach ($k in Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue) {
        if ($k.PSChildName -match '^S-1-5-21-[\d-]+$') { $roots += "Registry::HKEY_USERS\$($k.PSChildName)\$rest" }
    }
    $roots
}
# reg.exe through cmd: its stderr would otherwise become a PowerShell error record and stop the
# script (a check without its report, seen in the mutation test 2026-10-18).
function Mount-Default {
    if (-not (Test-Path 'Registry::HKEY_USERS\pvs-cis-default')) {
        & cmd.exe /c "reg load HKU\pvs-cis-default `"$env:SystemDrive\Users\Default\NTUSER.DAT`" >nul 2>&1"
        if ($LASTEXITCODE -ne 0) { Write-Log 'warn' "the Default user hive did not load (reg rc $LASTEXITCODE): its values are not checked" }
    }
}
function Dismount-Default {
    # PowerShell's registry provider lets go of the hive's keys only after a collection: a few
    # tries; a hive that stays loaded goes with the next boot and harms nothing until then.
    for ($i = 0; $i -lt 5 -and (Test-Path 'Registry::HKEY_USERS\pvs-cis-default'); $i++) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        & cmd.exe /c "reg unload HKU\pvs-cis-default >nul 2>&1"
        if ($LASTEXITCODE -eq 0) { return }
        Start-Sleep -Seconds 1
    }
    if (Test-Path 'Registry::HKEY_USERS\pvs-cis-default') { Write-Log 'warn' 'the Default user hive stays loaded until the next boot (in use)' }
}
function Parse-Value([string]$v) {
    $i = $v.IndexOf(':')
    @{ type = $v.Substring(0, $i); data = $v.Substring($i + 1) }
}
function Reg-Ok($cur, [string]$op, $want) {
    switch ($op) {
        'eq' { if ($want.type -eq 'REG_MULTI_SZ') { return (@($cur) -join '|') -eq $want.data } else { return "$cur" -eq $want.data } }
        'eq_or_absent' { return ($null -eq $cur) -or ("$cur" -eq $want.data) }
        'ne' { return ($null -ne $cur) -and ("$cur" -ne $want.data) }
        # "is configured": any value but none; the fix writes the rule's (the studio's) value
        'nonempty' { return ($null -ne $cur) -and ("$cur".Trim() -ne '') }
        'ge' { return ($null -ne $cur) -and ([int64]$cur -ge [int64]$want.data) }
        'le' { return ($null -ne $cur) -and ([int64]$cur -le [int64]$want.data) }
        'range' { $lo, $hi = $want.data -split '\.\.'; return ($null -ne $cur) -and ([int64]$cur -ge [int64]$lo) -and ([int64]$cur -le [int64]$hi) }
        'in' { return ($null -ne $cur) -and (($want.data -split '\|') -contains "$cur") }
    }
    $false
}
# The value fix writes: the strictest the rule allows within the studio's choice (the upper end of a
# range is the benchmark's own number: 900 s, 365 days, 15 minutes).
function Reg-Target([string]$op, $want) {
    switch ($op) {
        'range' { return ($want.data -split '\.\.')[1] }
        'in' { return ($want.data -split '\|')[0] }
        'ne' { return '0' }
        default { return $want.data }
    }
}
function Check-Reg($r) {
    $t = Split-Target $r.target; $want = Parse-Value $r.value
    $bad = @(); $ev = @()
    $roots = @(Hive-Roots $t.path)
    if ($roots.Count -eq 0) { return @{ ok = $false; ev = "$($t.path): no user hive to check" } }
    foreach ($root in $roots) {
        $cur = $null
        try { $cur = (Get-ItemProperty -Path $root -Name $t.name -ErrorAction Stop).($t.name) } catch { $cur = $null }
        $shown = if ($null -eq $cur) { 'absent' } else { (@($cur) -join '|') }
        $ev += "$($root -replace '^Registry::HKEY_USERS\\', 'HKU\' -replace '^HKLM:\\', 'HKLM\'):$($t.name) = $shown"
        if (-not (Reg-Ok $cur $r.op $want)) { $bad += $root }
    }
    # The benchmark audits the policy value; the evidence also says what actually runs.
    if ($t.path -eq 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -and $t.name -eq 'EnableVirtualizationBasedSecurity') {
        try {
            $d = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
            $run = @{ 1 = 'Credential Guard'; 2 = 'HVCI' }
            $ev += "running now: VBS " + @('off', 'configured, not running', 'running')[[int]$d.VirtualizationBasedSecurityStatus] +
                   "; services: " + $(if (@($d.SecurityServicesRunning | Where-Object { $_ }).Count) { (@($d.SecurityServicesRunning | Where-Object { $run[[int]$_] } | ForEach-Object { $run[[int]$_] }) -join ', ') } else { 'none' })
        } catch { $ev += 'running now: unknown (no Win32_DeviceGuard)' }
    }
    @{ ok = ($bad.Count -eq 0); ev = ($ev -join "`n") }
}
# ---- local Group Policy (Registry.pol, PReg format) ----
# Policy values go into the local GPO as well: they then show as policy (gpresult), every later
# user gets the user part at logon, and Windows writes a few values only through the Group
# Policy engine (W11 26200: Windows Feeds EnableFeeds, Dsh AllowNewsAndInterests - a direct
# write is refused even for SYSTEM).
$Gpo = @{ Machine = [ordered]@{}; User = [ordered]@{} }
$PolType = @{ REG_SZ = 1; REG_EXPAND_SZ = 2; REG_DWORD = 4; REG_MULTI_SZ = 7; REG_QWORD = 11 }
function Read-Pol([string]$file) {
    $o = [ordered]@{}
    if (-not (Test-Path $file)) { return $o }
    $b = [IO.File]::ReadAllBytes($file)
    if ($b.Length -lt 8) { return $o }
    $u = [Text.Encoding]::Unicode
    $i = 8
    while ($i -lt $b.Length) {
        # [key;value;type;size;data]
        $i += 2
        $j = $i; while ($b[$j] -ne 0 -or $b[$j + 1] -ne 0) { $j += 2 }; $key = $u.GetString($b, $i, $j - $i); $i = $j + 4
        $j = $i; while ($b[$j] -ne 0 -or $b[$j + 1] -ne 0) { $j += 2 }; $name = $u.GetString($b, $i, $j - $i); $i = $j + 4
        $type = [BitConverter]::ToUInt32($b, $i); $i += 6
        $size = [BitConverter]::ToUInt32($b, $i); $i += 6
        $data = New-Object byte[] $size; [Array]::Copy($b, $i, $data, 0, $size); $i += $size + 2
        $o["$key`0$name".ToLower()] = @{ key = $key; name = $name; type = $type; data = $data }
    }
    $o
}
function Write-Pol([string]$file, $entries) {
    $ms = New-Object IO.MemoryStream; $bw = New-Object IO.BinaryWriter($ms); $u = [Text.Encoding]::Unicode
    $bw.Write([byte[]](0x50, 0x52, 0x65, 0x67)); $bw.Write([uint32]1)
    foreach ($e in $entries.Values) {
        $bw.Write($u.GetBytes('[')); $bw.Write($u.GetBytes($e.key + [char]0)); $bw.Write($u.GetBytes(';'))
        $bw.Write($u.GetBytes($e.name + [char]0)); $bw.Write($u.GetBytes(';'))
        $bw.Write([uint32]$e.type); $bw.Write($u.GetBytes(';')); $bw.Write([uint32]$e.data.Length); $bw.Write($u.GetBytes(';'))
        $bw.Write([byte[]]$e.data); $bw.Write($u.GetBytes(']'))
    }
    $bw.Flush(); New-Item -ItemType Directory -Force (Split-Path $file) | Out-Null
    [IO.File]::WriteAllBytes($file, $ms.ToArray())
}
function Pol-Data([string]$type, [string]$data) {
    $u = [Text.Encoding]::Unicode
    switch ($type) {
        'REG_DWORD' { return [BitConverter]::GetBytes([uint32]$data) }
        'REG_QWORD' { return [BitConverter]::GetBytes([uint64]$data) }
        'REG_MULTI_SZ' { return $u.GetBytes((@(if ($data) { $data -split '\|' }) -join [char]0) + [char]0 + [char]0) }
        default { return $u.GetBytes($data + [char]0) }
    }
}
function Add-Gpo([string]$path, [string]$name, [string]$type, [string]$data) {
    if ($path.StartsWith('HKLM\')) { $scope = 'Machine'; $key = $path.Substring(5) } else { $scope = 'User'; $key = $path.Substring(4) }
    $Gpo[$scope]["$key`0$name".ToLower()] = @{ key = $key; name = $name; type = $PolType[$type]; data = (Pol-Data $type $data) }
}
function Save-Gpo {
    $root = "$env:windir\System32\GroupPolicy"
    $ext = @{ Machine = 'gPCMachineExtensionNames'; User = 'gPCUserExtensionNames' }
    $reg = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
    $changed = $false
    foreach ($scope in 'Machine', 'User') {
        if ($Gpo[$scope].Count -eq 0) { continue }
        $file = "$root\$scope\Registry.pol"
        $all = Read-Pol $file
        foreach ($k in $Gpo[$scope].Keys) { $all[$k] = $Gpo[$scope][$k] }
        # Unchanged (a VM from the gold): no new version, no gpupdate - in SetupComplete the
        # policy client is not up yet and gpupdate /force waited out its 600 s there.
        $new = "$file.pvs-new"
        Write-Pol $new $all
        if ((Test-Path $file) -and (Get-FileHash $new).Hash -eq (Get-FileHash $file).Hash) { Remove-Item $new -Force; continue }
        Move-Item $new $file -Force
        $changed = $true
    }
    if (-not $changed) { return }
    # gpt.ini: the registry extension for both halves, the version raised (machine low word, user high word)
    $ini = "$root\gpt.ini"; $ver = 0; $lines = @()
    if (Test-Path $ini) { $lines = @(Get-Content $ini) }
    foreach ($l in $lines) { if ($l -match '^\s*Version\s*=\s*(\d+)') { $ver = [int64]$Matches[1] } }
    $ver = $ver + 1 + 65536
    $out = @('[General]')
    foreach ($scope in 'Machine', 'User') {
        $cur = ($lines | Where-Object { $_ -match "^\s*$($ext[$scope])\s*=" } | Select-Object -First 1)
        $val = if ($cur) { ($cur -split '=', 2)[1].Trim() } else { '' }
        if ($val -notlike "*35378EAC-683F-11D2-A89A-00C04FBBCFA2*") { $val = $val + $reg }
        $out += "$($ext[$scope])=$val"
    }
    $out += "Version=$ver"
    $out | Set-Content -Encoding ASCII $ini
    & gpupdate.exe /force | Out-Null
}

function Fix-Reg($r) {
    $t = Split-Target $r.target; $want = Parse-Value $r.value
    # "Disabled" policies whose value is empty or absent: nothing to write where it is absent or
    # empty already - a value that is there with anything else is set to empty.
    if ($r.op -eq 'eq_or_absent' -and $want.data -eq '') {
        $set = @(Hive-Roots $t.path | Where-Object {
            $cur = $null
            try { $cur = (Get-ItemProperty -Path $_ -Name $t.name -ErrorAction Stop).($t.name) } catch { $cur = $null }
            $null -ne $cur -and "$cur" -ne '' })
        if ($set.Count -eq 0) { return }
    }
    $data = Reg-Target $r.op $want
    $kind = @{ REG_DWORD = 'DWord'; REG_QWORD = 'QWord'; REG_SZ = 'String'; REG_EXPAND_SZ = 'ExpandString'; REG_MULTI_SZ = 'MultiString' }[$want.type]
    $policy = $t.path -match '\\Policies\\' -or $t.path.StartsWith('HKU\')
    if ($policy) { Add-Gpo $t.path $t.name $want.type $data }
    foreach ($root in @(Hive-Roots $t.path)) {
        $v = if ($want.type -eq 'REG_MULTI_SZ') { [string[]]@(if ($data) { $data -split '\|' }) } elseif ($want.type -match 'DWORD|QWORD') { [int64]$data } else { $data }
        try {
            if (-not (Test-Path $root)) { New-Item -Path $root -Force | Out-Null }
            New-ItemProperty -Path $root -Name $t.name -PropertyType $kind -Value $v -Force | Out-Null
        }
        catch [System.UnauthorizedAccessException] {
            # only the Group Policy engine may write this one: the GPO above carries it
            if (-not $policy) { throw }
        }
    }
    Fix-Effect $t
}
# What the Device Guard policy needs to take effect on a stand-alone VM, measured on PVE
# 2026-10-18 (nested virtualization + vTPM): with the policy values alone the hypervisor
# never launched, and once it did, HVCI stayed off until its scenario key was there.
function Fix-Effect($t) {
    $dg = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
    if ($t.path -ne $dg) { return }
    switch ($t.name) {
        'EnableVirtualizationBasedSecurity' {
            & bcdedit.exe /set '{current}' hypervisorlaunchtype auto | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "bcdedit hypervisorlaunchtype rc $LASTEXITCODE" }
        }
        'HypervisorEnforcedCodeIntegrity' {
            # the policy's 1 is "Enabled with UEFI lock": the scenario enabled and locked
            $s = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
            if (-not (Test-Path $s)) { New-Item -Path $s -Force | Out-Null }
            New-ItemProperty -Path $s -Name Enabled -PropertyType DWord -Value 1 -Force | Out-Null
            New-ItemProperty -Path $s -Name Locked -PropertyType DWord -Value 1 -Force | Out-Null
        }
    }
}

# ---- secedit-backed rules ----
function Acct-Ok($cur, [string]$op, [string]$v) {
    if ($null -eq $cur -or $cur -eq '') { return $false }
    switch ($op) {
        'eq' { return "$cur" -eq $v }
        'ne' { return "$cur" -ne $v }
        'ge' { return [int64]$cur -ge [int64]$v }
        'le' { return [int64]$cur -le [int64]$v }
        'range' { $lo, $hi = $v -split '\.\.'; return ([int64]$cur -ge [int64]$lo) -and ([int64]$cur -le [int64]$hi) }
    }
    $false
}
# The rule's principals as SIDs. One that does not resolve stays as "?name": the check then
# fails with it in the evidence, and the fix refuses to write a list short of the benchmark's.
function Right-Sids([string]$v) { @(if ($v) { foreach ($p in $v -split ',') { $s = Resolve-Sid $p.Trim(); if ($s) { $s } else { '?' + $p.Trim() } } }) }
function Right-Ok($cur, [string]$op, [string]$v) {
    $have = @(@(if ($cur) { foreach ($p in $cur -split ',') { Resolve-Sid $p.Trim() } }) | Where-Object { $_ } | Sort-Object -Unique)
    $want = @(Right-Sids $v | Sort-Object -Unique)
    switch ($op) {
        'none' { return $have.Count -eq 0 }
        'eq' { return (@($have) -join ',') -eq (@($want) -join ',') }
        'has' { foreach ($w in $want) { if ($have -notcontains $w) { return $false } }; return $true }
    }
    $false
}

# ---- audit ----
function Get-Audit {
    $o = @{}
    foreach ($row in (& auditpol.exe /get /category:* /r | ConvertFrom-Csv)) {
        $o[$row.'Subcategory GUID'.Trim('{}').ToUpper()] = $row.'Inclusion Setting'
    }
    $o
}
function Audit-Has([string]$setting) {
    @{ s = ($setting -match 'Success'); f = ($setting -match 'Failure') }
}
function Audit-Ok([string]$cur, [string]$op, [string]$v) {
    $c = Audit-Has $cur; $w = Audit-Has $v
    if ($op -eq 'eq') { return ($c.s -eq $w.s) -and ($c.f -eq $w.f) }
    (-not $w.s -or $c.s) -and (-not $w.f -or $c.f)
}

# ---- check ----
function Check-Rec([string]$id, $sec, $aud) {
    $rows = $ById[$id]; $ok = $true; $ev = @()
    foreach ($r in $rows) {
        switch ($r.mech) {
            'reg' { $c = Check-Reg $r; $ok = $ok -and $c.ok; $ev += $c.ev }
            'acct' {
                $cur = $sec[$r.target]
                if ($r.target -in 'NewAdministratorName', 'NewGuestName') {
                    $sid = if ($r.target -eq 'NewAdministratorName') { '-500' } else { '-501' }
                    $u = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith($sid) } | Select-Object -First 1
                    $cur = if ($u) { $u.Name } else { $cur }
                }
                $o = Acct-Ok $cur $r.op $r.value; $ok = $ok -and $o
                $ev += "$($r.target) = $(if ($null -eq $cur) { 'not set' } else { $cur })"
            }
            'right' {
                $cur = $sec[$r.target]; $o = Right-Ok $cur $r.op $r.value; $ok = $ok -and $o
                $names = @(if ($cur) { foreach ($p in $cur -split ',') { Sid-Name ($p.Trim().TrimStart('*')) } })
                $ev += "$($r.target) = $(if ($names.Count) { $names -join ', ' } else { 'No One' })"
            }
            'audit' {
                $cur = $aud[$r.target.ToUpper()]; $o = Audit-Ok $cur $r.op $r.value; $ok = $ok -and $o
                $ev += "{$($r.target)} = $cur"
            }
            default { $ok = $false; $ev += "no check for $($r.mech)" }
        }
    }
    $kind = $rows[0].kind
    $status = if ($ok) { 'pass' } elseif ($kind -eq 'manual') { 'review' } else { 'fail' }
    # The gold's own check: generalize resets the built-in accounts' names, so each VM renames them.
    if ($status -eq 'fail' -and $Phase -eq 'gold' -and ($rows | Where-Object { $_.target -in 'NewAdministratorName', 'NewGuestName' })) {
        $Exc[$id] = 'renamed on each VM at its first boot (sysprep /generalize resets the built-in accounts'' names)'
    }
    if ($status -eq 'fail' -and $Exc.ContainsKey($id)) { $status = 'exception' }
    @{ status = $status; ev = ($ev -join "`n") }
}

function Do-Check {
    Mount-Default
    $sec = Get-Secedit; $aud = Get-Audit
    $res = @(); $counts = [ordered]@{ pass = 0; fail = 0; na = 0; review = 0; exception = 0; error = 0 }
    foreach ($id in $Ids) {
        try { $c = Check-Rec $id $sec $aud } catch { $c = @{ status = 'error'; ev = $_.Exception.Message } }
        $counts[$c.status]++
        $r0 = $ById[$id][0]
        $o = [ordered]@{ id = $id; key = $r0.mech + ':' + $r0.target; level = [int]($r0.level -replace '\D', ''); kind = $r0.kind; title = $r0.title; status = $c.status; evidence = $c.ev }
        if ($Exc.ContainsKey($id)) { $o.reason = $Exc[$id] }
        $res += [pscustomobject]$o
        switch ($c.status) {
            'pass' { }
            'fail' { Write-Log 'error' "$id fail: $($r0.title)" }
            'error' { Write-Log 'error' "$id error: $($r0.title) - $($c.ev)" }
            'exception' { Write-Log 'warn' "$id exception: $($r0.title) - $($Exc[$id])" }
            default { Write-Log 'info' "$id $($c.status): $($r0.title)" }
        }
    }
    Dismount-Default
    $b = $BenchConf[$Benchmark]
    if ($Json) {
        $doc = [ordered]@{ benchmark = $b.name; version = $b.version; distro = $Benchmark; level = $Level; profile = "level${Level}"
            checked = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); host = $env:COMPUTERNAME; counts = $counts; results = $res }
        $doc | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $Json
    }
    $tag = if ($counts.fail + $counts.error -eq 0) { 'ok' } else { 'error' }
    Write-Log $tag ("check level {0}: {1} pass, {2} fail, {3} n/a, {4} review, {5} exception, {6} error" -f $Level, $counts.pass, $counts.fail, $counts.na, $counts.review, $counts.exception, $counts.error)
    Write-Output ($Pre + "CIS-CHECK-DONE level {0}: {1} pass, {2} fail, {3} n/a, {4} review, {5} exception, {6} error" -f $Level, $counts.pass, $counts.fail, $counts.na, $counts.review, $counts.exception, $counts.error)
}

# ---- fix ----
function Do-Fix {
    $applied = 0; $failed = 0
    $sysAccess = [ordered]@{}; $privs = [ordered]@{}
    $sec = Get-Secedit
    Mount-Default
    foreach ($id in $Ids) {
        if ($Exc.ContainsKey($id) -and -not $ExcFix.ContainsKey($id)) { Write-Log 'info' "$id exception, left alone: $($Exc[$id])"; continue }
        foreach ($r in $ById[$id]) {
            try {
                switch ($r.mech) {
                    'reg' {
                        if ($Phase -eq 'vm' -and $r.target -eq 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:AutoAdminLogon') {
                            Write-Log 'info' "$id left for the final phase: OOBE still has to sign defaultuser0 in once"
                            continue
                        }
                        Fix-Reg $r; $applied++
                    }
                    'acct' {
                        if ($r.target -in 'NewAdministratorName', 'NewGuestName') {
                            # generalize resets these: renamed on each VM
                            if ($Phase -ne 'gold') {
                                $sid = if ($r.target -eq 'NewAdministratorName') { '-500' } else { '-501' }
                                $new = if ($r.target -eq 'NewAdministratorName') { $AdminName } else { $GuestName }
                                $u = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith($sid) } | Select-Object -First 1
                                if ($u -and $u.Name -ne $new) { Rename-LocalUser -SID $u.SID -NewName $new }
                                $applied++
                            }
                        }
                        else {
                            $sysAccess[$r.target] = switch ($r.op) { 'range' { ($r.value -split '\.\.')[1] } default { $r.value } }
                        }
                    }
                    'right' {
                        $want = Right-Sids $r.value
                        $bad = @($want | Where-Object { $_.StartsWith('?') })
                        if ($bad.Count) { throw "cannot resolve $($bad -join ', ')" }
                        if ($r.op -eq 'has') {
                            $have = @(if ($sec[$r.target]) { foreach ($p in $sec[$r.target] -split ',') { Resolve-Sid $p.Trim() } })
                            $want = @($have + $want) | Where-Object { $_ } | Sort-Object -Unique
                        }
                        $privs[$r.target] = (@($want | ForEach-Object { "*$_" }) -join ',')
                    }
                    'audit' {
                        $w = Audit-Has $r.value
                        $args2 = @("/subcategory:{$($r.target)}")
                        if ($r.op -eq 'eq') { $args2 += "/success:$(if ($w.s) { 'enable' } else { 'disable' })", "/failure:$(if ($w.f) { 'enable' } else { 'disable' })" }
                        else { if ($w.s) { $args2 += '/success:enable' }; if ($w.f) { $args2 += '/failure:enable' } }
                        & auditpol.exe /set @args2 | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw "auditpol rc $LASTEXITCODE" }
                        $applied++
                    }
                }
            }
            catch { $failed++; Write-Log 'error' "$id fix failed ($($r.mech) $($r.target)): $($_.Exception.Message)"; if ($Markers) { Write-Output "PVS-CIS-FIX-FAILED $id $($r.mech)" } }
        }
    }
    Dismount-Default
    try { Save-Gpo } catch { $failed++; Write-Log 'error' "local GPO: $($_.Exception.Message)" }
    if ($sysAccess.Count -or $privs.Count) {
        $inf = Join-Path $env:TEMP 'pvs-cis-secedit.inf'; $db = Join-Path $env:TEMP 'pvs-cis-secedit.sdb'
        $t = @('[Unicode]', 'Unicode=yes', '[System Access]')
        foreach ($k in $sysAccess.Keys) { $t += "$k = $($sysAccess[$k])" }
        $t += '[Privilege Rights]'
        foreach ($k in $privs.Keys) { $t += "$k = $($privs[$k])" }
        $t += '[Version]', 'signature="$CHICAGO$"', 'Revision=1'
        $t | Set-Content -Encoding Unicode $inf
        & secedit.exe /configure /db $db /cfg $inf /areas SECURITYPOLICY USER_RIGHTS /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { $failed++; Write-Log 'error' "secedit /configure rc $LASTEXITCODE" } else { $applied += $sysAccess.Count + $privs.Count }
        Remove-Item $inf, $db -Force -ErrorAction SilentlyContinue
    }
    $tag = if ($failed -eq 0) { 'ok' } else { 'error' }
    Write-Log $tag "fix level $Level ($Phase): $applied applied, $failed failed"
    Write-Output "${Pre}CIS-FIX-DONE level ${Level} ${Phase}: $applied applied, $failed failed"
}

switch ($Command) {
    'fix' { Do-Fix }
    'check' { Do-Check }
    'list' { foreach ($id in $Ids) { $r = $ById[$id][0]; "{0}`t{1}`t{2}`t{3}" -f $id, $r.level, $r.kind, $r.title } }
    # The report for the bake, which reads only the console: gzip, base64, PVS-CIS-R lines.
    'emit' {
        $raw = [IO.File]::ReadAllBytes($Json)
        $ms = New-Object IO.MemoryStream
        $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
        $gz.Write($raw, 0, $raw.Length); $gz.Close()
        $b64 = [Convert]::ToBase64String($ms.ToArray())
        for ($i = 0; $i -lt $b64.Length; $i += 900) { 'PVS-CIS-R ' + $b64.Substring($i, [Math]::Min(900, $b64.Length - $i)) }
        "PVS-CIS-REPORT $($raw.Length) bytes"
    }
}
