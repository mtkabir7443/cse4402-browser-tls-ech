#Requires -Version 7.2
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^S-1-5-21-\d+-\d+-\d+-\d+$')][string]$TargetUserSid,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$')][string]$Batch,
    [ValidateRange(30,600)][int]$LeaseSeconds = 600
)
$ErrorActionPreference = 'Stop'
$labRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$labRuntime = Join-Path $labRoot '.runtime'
$labStatePath = Join-Path $labRuntime ("edge-policy-lease-$Batch.json")
$labReleasePath = Join-Path $labRuntime ("edge-policy-lease-$Batch.release")
$labLockPath = Join-Path $labRuntime 'edge-policy-lease.lock'
$labEvidencePath = Join-Path $labRoot ("evidence/edge-policy-lease-$Batch.json")
$labRegistryPath = "$TargetUserSid\Software\Policies\Microsoft\Edge"
$labNames = @('DnsOverHttpsMode', 'DnsOverHttpsTemplates')
$labValues = @('secure', 'https://127.0.0.1:8443/dns-query')

# This helper neither elevates itself nor launches a browser. The caller must
# deliberately start it elevated and supply the original user's SID, not HKCU.
function Assert-NoEdge {
    if (Get-Process -Name msedge -ErrorAction SilentlyContinue) {
        throw 'An Edge process already exists. Close personal Edge first; the lease will not change policy.'
    }
}
function Assert-Unredirected([string]$Path) {
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            if ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a redirected ownership/evidence path: $cursor"
            }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}
function Save-LeaseState {
    $json = $labState | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($labStatePath, $json + [Environment]::NewLine)
    [IO.File]::WriteAllText($labEvidencePath, $json + [Environment]::NewLine)
}
Assert-NoEdge
foreach ($file in @($labStatePath,$labReleasePath,$labLockPath,$labEvidencePath)) {
    Assert-Unredirected $file
    if (Test-Path -LiteralPath $file) { throw "Preserve existing lease evidence; choose a fresh batch or inspect the existing lock: $file" }
}
foreach ($directory in @($labRuntime,(Join-Path $labRoot 'evidence'))) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "Required project directory is absent: $directory" }
}

$labUsers = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users,[Microsoft.Win32.RegistryView]::Registry64)
$labMachine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)
$labParent = $null; $labEdge = $null; $labLock = $null; $labCreatedKey = $false; $labBackupSaved = $false
$labBefore = @(); $labRestoreErrors = @(); $labFailure = $null
try {
    $profileKey = $labMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$TargetUserSid",$false)
    if (-not $profileKey) { throw 'Target SID does not identify a registered Windows profile.' }
    try { $profilePath = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$profileKey.GetValue('ProfileImagePath'))) }
    finally { $profileKey.Dispose() }
    if (-not $labRoot.StartsWith($profilePath.TrimEnd('\') + '\',[StringComparison]::OrdinalIgnoreCase)) {
        throw 'The explicit target SID does not own the profile containing this project.'
    }
    $hiveCheck = $labUsers.OpenSubKey($TargetUserSid,$false)
    if (-not $hiveCheck) { throw 'The explicit target user hive is not loaded; no hive will be loaded by this helper.' }
    $hiveCheck.Dispose()
    $machinePolicy = $labMachine.OpenSubKey('SOFTWARE\Policies\Microsoft\Edge',$false)
    try {
        foreach ($name in $labNames) {
            if ($machinePolicy -and $machinePolicy.GetValueNames().Contains($name)) { throw "Machine policy already specifies $name; it will not be changed or overridden." }
        }
    } finally { if ($machinePolicy) { $machinePolicy.Dispose() } }
    $original = $labUsers.OpenSubKey($labRegistryPath,$false)
    $labKeyExisted = $null -ne $original
    try {
        foreach ($name in $labNames) {
            $present = $original -and $original.GetValueNames().Contains($name)
            $labBefore += [ordered]@{
                name=$name; exists=[bool]$present
                value=$(if($present){$original.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}else{$null})
                kind=$(if($present){[string]$original.GetValueKind($name)}else{$null})
            }
        }
    } finally { if ($original) { $original.Dispose() } }
    $labState = [ordered]@{
        batch_id=$Batch; owner_pid=$PID; target_user_sid=$TargetUserSid; registry_path="HKEY_USERS\$labRegistryPath"
        started_utc=[DateTime]::UtcNow.ToString('o'); maximum_seconds=$LeaseSeconds; release_file=$labReleasePath
        state_file=$labStatePath; key_existed=$labKeyExisted; before=$labBefore
        applied=@{ DnsOverHttpsMode=$labValues[0]; DnsOverHttpsTemplates=$labValues[1] }
        status='prepared'; restored=$false; restore_errors=@()
        scope='Two temporary values in the explicit original user hive; no HKLM, ACL, browser, or certificate changes'
    }
    if (-not $PSCmdlet.ShouldProcess("HKEY_USERS\$labRegistryPath", "Lease only DnsOverHttpsMode and DnsOverHttpsTemplates for at most $LeaseSeconds seconds; restore both afterward")) {
        $labState | ConvertTo-Json -Depth 10
        return
    }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This protected policy key requires an explicitly elevated invocation; the helper does not elevate itself.'
    }
    Assert-NoEdge
    $labLock = [IO.File]::Open($labLockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    $lockBytes = [Text.Encoding]::UTF8.GetBytes(($labState | ConvertTo-Json -Depth 10))
    $labLock.Write($lockBytes,0,$lockBytes.Length); $labLock.Flush($true)
    Save-LeaseState
    $labBackupSaved = $true
    $labParent = $labUsers.OpenSubKey("$TargetUserSid\Software\Policies\Microsoft",$true)
    if (-not $labParent) { throw 'The existing Microsoft policy parent is missing; no parent keys will be created.' }
    $labEdge = $labParent.OpenSubKey('Edge',$true)
    if (-not $labEdge) { $labEdge = $labParent.CreateSubKey('Edge',$true); $labCreatedKey=$true }
    for ($i=0; $i -lt $labNames.Count; $i++) { $labEdge.SetValue($labNames[$i],$labValues[$i],[Microsoft.Win32.RegistryValueKind]::String) }
    $labEdge.Flush()
    $labState.status='active'; $labState.expires_utc=[DateTime]::UtcNow.AddSeconds($LeaseSeconds).ToString('o')
    Save-LeaseState
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $LeaseSeconds -and -not (Test-Path -LiteralPath $labReleasePath)) { Start-Sleep -Milliseconds 250 }
    $labState.release_reason = $(if(Test-Path -LiteralPath $labReleasePath){'release_file'}else{'lease_timeout'})
} catch {
    $labFailure = $_
    if ($labBackupSaved) { $labState.error=$_.Exception.Message }
} finally {
    if ($labBackupSaved) {
        if ($labEdge) {
            foreach ($old in $labBefore) {
                try {
                    if ($old.exists) { $labEdge.SetValue($old.name,$old.value,[Microsoft.Win32.RegistryValueKind]::$($old.kind)) }
                    else { $labEdge.DeleteValue($old.name,$false) }
                } catch { $labRestoreErrors += "$($old.name): $($_.Exception.Message)" }
            }
            try { $labEdge.Flush() } catch { $labRestoreErrors += $_.Exception.Message }
            $labEdge.Dispose(); $labEdge=$null
        }
        if ($labCreatedKey -and $labParent) {
            try {
                $remaining=$labParent.OpenSubKey('Edge',$false)
                $empty=$remaining -and $remaining.ValueCount -eq 0 -and $remaining.SubKeyCount -eq 0
                if ($remaining) { $remaining.Dispose() }
                if ($empty) { $labParent.DeleteSubKey('Edge',$false) }
            } catch { $labRestoreErrors += $_.Exception.Message }
        }
        $check=$null
        try {
            $check=$labUsers.OpenSubKey($labRegistryPath,$false)
            foreach ($old in $labBefore) {
                $present=$check -and $check.GetValueNames().Contains($old.name)
                if ([bool]$present -ne $old.exists) { throw "Restoration presence mismatch: $($old.name)" }
                if ($old.exists) {
                    $actual=$check.GetValue($old.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    if ([string]$check.GetValueKind($old.name) -ne $old.kind -or (ConvertTo-Json -InputObject $actual -Compress) -cne (ConvertTo-Json -InputObject $old.value -Compress)) { throw "Restoration value/kind mismatch: $($old.name)" }
                }
            }
            if (-not $labKeyExisted -and $check -and $check.ValueCount -eq 0 -and $check.SubKeyCount -eq 0) { throw 'An empty Edge key created by the lease remains.' }
        } catch { $labRestoreErrors += $_.Exception.Message }
        finally { if ($check) { $check.Dispose() } }
        $labState.restored=($labRestoreErrors.Count -eq 0)
        $labState.status=$(if($labState.restored){'restored'}else{'restore_failed'})
        $labState.restore_errors=$labRestoreErrors; $labState.finished_utc=[DateTime]::UtcNow.ToString('o')
        try { Save-LeaseState } catch { $labRestoreErrors += "Saving final evidence: $($_.Exception.Message)" }
    }
    if ($labEdge) { $labEdge.Dispose() }; if ($labParent) { $labParent.Dispose() }
    $labUsers.Dispose(); $labMachine.Dispose()
    if ($labLock) { $labLock.Dispose(); Remove-Item -LiteralPath $labLockPath -ErrorAction Stop }
}
if ($labRestoreErrors.Count) { throw ('Lease restoration requires inspection: ' + ($labRestoreErrors -join '; ')) }
if ($labFailure) { throw $labFailure }
if ($labBackupSaved) { $labState | ConvertTo-Json -Depth 10 }
