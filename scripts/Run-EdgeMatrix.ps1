#Requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$Batch,
    [string]$Cases,
    [ValidateRange(1,3)][int]$Repeats = 3,
    [switch]$UseAdministratorLease
)
$ErrorActionPreference = 'Stop'
$labRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (Get-Process -Name msedge -ErrorAction SilentlyContinue) {
    throw 'Close personal Edge windows first. This isolated experiment refuses to change policy while Edge is already running.'
}
$labPolicy = 'HKCU:\Software\Policies\Microsoft\Edge'
$labNames = @('DnsOverHttpsMode', 'DnsOverHttpsTemplates')
$labValues = @('secure', 'https://127.0.0.1:8443/dns-query')
$labExisting = Test-Path -LiteralPath $labPolicy
$labBefore = @()
foreach ($labName in $labNames) {
    $machine = Get-ItemProperty -LiteralPath 'HKLM:\Software\Policies\Microsoft\Edge' -Name $labName -ErrorAction SilentlyContinue
    if ($null -ne $machine) { throw "Machine policy already sets $labName; no override will be attempted." }
    $labKey = if ($labExisting) { Get-Item -LiteralPath $labPolicy } else { $null }
    $labPresent = $labKey -and $labKey.GetValueNames().Contains($labName)
    $labBefore += [ordered]@{ name=$labName; exists=[bool]$labPresent; value=$(if($labPresent){$labKey.GetValue($labName)}else{$null}); kind=$(if($labPresent){[string]$labKey.GetValueKind($labName)}else{$null}) }
}
if ($UseAdministratorLease) {
    $labIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $labPrincipal = [Security.Principal.WindowsPrincipal]::new($labIdentity)
    if ($labPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this wrapper from a normal, unelevated PowerShell. Only the two-value policy helper may be elevated; the browser runner must remain unelevated.'
    }
    $labUserSid = $labIdentity.User.Value
    $labLeaseId = 'edge-' + $Batch.Substring(0,[Math]::Min(20,$Batch.Length)) + '-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $labLeaseHelper = Join-Path $PSScriptRoot 'Edge-PolicyLease.ps1'
    $labLeaseStatePath = Join-Path $labRoot (".runtime/edge-policy-lease-$labLeaseId.json")
    $labLeaseRelease = Join-Path $labRoot (".runtime/edge-policy-lease-$labLeaseId.release")
    $labLeaseLock = Join-Path $labRoot '.runtime/edge-policy-lease.lock'
    $labLeaseProcess = $null; $labLeaseError = $null; $labLeaseCleanupError = $null; $labLeaseState = $null; $labExit = 1
    if (-not (Test-Path -LiteralPath $labLeaseHelper -PathType Leaf)) { throw 'The bounded Edge policy lease helper is missing.' }
    if (Test-Path -LiteralPath $labLeaseLock) { throw 'An existing policy lease lock must be inspected/released before starting another lease.' }
    function Read-LabEdgeLease {
        if (-not (Test-Path -LiteralPath $labLeaseStatePath)) { return $null }
        try { $state = Get-Content -Raw -LiteralPath $labLeaseStatePath | ConvertFrom-Json }
        catch { return $null } # The helper may be replacing its short status file.
        if ($state.batch_id -ne $labLeaseId -or $state.target_user_sid -ne $labUserSid -or $state.owner_pid -ne $labLeaseProcess.Id) {
            throw 'Policy lease status does not match the helper process and original user.'
        }
        return $state
    }
    function Test-LabEdgeHelperExited {
        try { $labLeaseProcess.Refresh(); return $labLeaseProcess.HasExited }
        catch { return $false } # An unreadable elevated handle is not proof of exit.
    }
    function Test-LabEdgeOriginalPolicy {
        $key = Get-Item -LiteralPath $labPolicy -ErrorAction SilentlyContinue
        foreach ($old in $labBefore) {
            $present = $key -and $key.GetValueNames().Contains($old.name)
            if ([bool]$present -ne $old.exists) { return $false }
            if ($old.exists -and ([string]$key.GetValueKind($old.name) -ne $old.kind -or (ConvertTo-Json -InputObject $key.GetValue($old.name) -Compress) -cne (ConvertTo-Json -InputObject $old.value -Compress))) { return $false }
        }
        if (-not $labExisting -and $key -and $key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) { return $false }
        return $true
    }
    try {
        # Start-Process joins ArgumentList on Windows; quote the only path argument.
        # UAC approval is left entirely to the user. No prompt is clicked/accepted here.
        $labHelperArgs = @('-NoProfile','-NonInteractive','-File',('"' + $labLeaseHelper + '"'),'-TargetUserSid',$labUserSid,'-Batch',$labLeaseId,'-LeaseSeconds','600')
        $labLeaseProcess = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList $labHelperArgs -Verb RunAs -WindowStyle Hidden -PassThru
        $labReadyTimer = [Diagnostics.Stopwatch]::StartNew()
        while ($labReadyTimer.Elapsed.TotalSeconds -lt 60) {
            $labLeaseState = Read-LabEdgeLease
            if ($labLeaseState -and $labLeaseState.status -eq 'active') { break }
            if (($labLeaseState -and $labLeaseState.status -in @('restored','restore_failed')) -or (Test-LabEdgeHelperExited)) { throw ('Policy helper did not become active. ' + $labLeaseState.error) }
            Start-Sleep -Milliseconds 250
        }
        if (-not $labLeaseState -or $labLeaseState.status -ne 'active') { throw 'Policy helper did not become active within 60 seconds; requesting release.' }
        Write-Host "Edge policy lease active: $labLeaseId. Only the helper is elevated."
        if (-not $labLeaseState.expires_utc) { throw 'Active policy lease did not provide its expiry; refusing an unbounded browser run.' }
        # ConvertFrom-Json can return DateTime; a plain string cast loses ISO UTC.
        $labLeaseDeadline = ([DateTimeOffset]$labLeaseState.expires_utc).UtcDateTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)
        $labArgs = @((Join-Path $PSScriptRoot 'run-matrix.cjs'),'--browser','edge-current','--batch',$Batch,'--repeats',[string]$Repeats,'--stop-before-utc',$labLeaseDeadline)
        if ($Cases) { $labArgs += @('--case',$Cases) }
        & node @labArgs
        $labExit = $LASTEXITCODE
    } catch { $labLeaseError = $_ }
    finally {
        if ($labLeaseProcess) {
            try {
                # Never kill the elevated helper: its finally block owns restoration.
                if (-not (Test-Path -LiteralPath $labLeaseRelease)) { New-Item -ItemType File -Path $labLeaseRelease -Value 'Release requested by the unelevated Edge wrapper.' | Out-Null }
                $labRestoreTimer = [Diagnostics.Stopwatch]::StartNew()
                $labRestored = $false
                while ($labRestoreTimer.Elapsed.TotalSeconds -lt 60) {
                    $labLeaseState = Read-LabEdgeLease
                    if ($labLeaseState -and $labLeaseState.status -eq 'restore_failed') { throw ('Policy helper reports restoration failure: ' + ($labLeaseState.restore_errors -join '; ')) }
                    if ($labLeaseState -and $labLeaseState.status -eq 'restored' -and $labLeaseState.restored -eq $true -and -not (Test-Path -LiteralPath $labLeaseLock)) {
                        $labRestored = Test-LabEdgeOriginalPolicy
                        if (-not $labRestored) { throw 'Helper restoration status disagrees with the original user policy values/types.' }
                        break
                    }
                    if (-not $labLeaseState -and (Test-LabEdgeHelperExited) -and (Test-LabEdgeOriginalPolicy)) { $labRestored=$true; break }
                    Start-Sleep -Milliseconds 250
                }
                if (-not $labRestored) { throw "Restoration was not verified within 60 seconds. The helper was not killed; its 10-minute lease still applies. Inspect $labLeaseStatePath and $labLeaseLock before further tests." }
            } catch { $labLeaseCleanupError = $_ }
        }
    }
    if ($labLeaseCleanupError) { throw ("Edge lease cleanup needs inspection: $($labLeaseCleanupError.Exception.Message) Original failure: $($labLeaseError.Exception.Message)") }
    if ($labLeaseError) { throw $labLeaseError }
    if ($labLeaseState.release_reason -eq 'lease_timeout') { throw 'The Edge policy lease expired during this invocation. Policy was restored; review this batch before using its results.' }
    if ($labExit -ne 0) { throw "Browser runner exited with code $labExit; the administrator lease restored the original user policy." }
    Write-Host "Edge policy restored and verified: $labLeaseStatePath"
    $labMatrix = Get-Content -Raw -LiteralPath (Join-Path $labRoot ("evidence/matrix/$Batch/matrix.json")) | ConvertFrom-Json
    if ($labMatrix.batch_id -ne $Batch) { throw 'Runner report does not match the requested batch.' }
    if ($labMatrix.status -eq 'paused') {
        Write-Host "Edge matrix paused safely before $($labMatrix.pause.next_cell). Completed measurements were preserved. Resume this same batch with a fresh approved lease."
    } elseif ($labMatrix.status -ne 'completed') {
        throw "Runner returned without a completed or safely paused report: $($labMatrix.status)"
    }
    return
}
$labState = [ordered]@{ batch_id=$Batch; started_utc=[DateTime]::UtcNow.ToString('o'); path=$labPolicy; key_existed=$labExisting; before=$labBefore; applied=$labValues; restored=$false; scope='Temporary CurrentUser Edge DoH policy; no existing Edge process; no machine-policy changes' }
$labEvidence = Join-Path $labRoot ('evidence/edge-policy-' + $Batch + '.json')
if (Test-Path -LiteralPath $labEvidence) { throw 'This batch already has policy evidence. Choose a fresh batch ID.' }
$labExit = 1
try {
    if (-not $labExisting) { New-Item -Path $labPolicy -Force | Out-Null }
    $labState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $labEvidence -Encoding utf8
    for ($i=0; $i -lt $labNames.Count; $i++) {
        New-ItemProperty -LiteralPath $labPolicy -Name $labNames[$i] -Value $labValues[$i] -PropertyType String -Force | Out-Null
    }
    $labArgs = @((Join-Path $PSScriptRoot 'run-matrix.cjs'), '--browser', 'edge-current', '--batch', $Batch, '--repeats', [string]$Repeats)
    if ($Cases) { $labArgs += @('--case', $Cases) }
    & node @labArgs
    $labExit = $LASTEXITCODE
} finally {
    foreach ($labOld in $labBefore) {
        if ($labOld.exists) { New-ItemProperty -LiteralPath $labPolicy -Name $labOld.name -Value $labOld.value -PropertyType $labOld.kind -Force | Out-Null }
        elseif (Test-Path -LiteralPath $labPolicy) { Remove-ItemProperty -LiteralPath $labPolicy -Name $labOld.name -ErrorAction SilentlyContinue }
    }
    if (-not $labExisting -and (Test-Path -LiteralPath $labPolicy)) {
        $labKey = Get-Item -LiteralPath $labPolicy
        if ($labKey.ValueCount -eq 0 -and $labKey.SubKeyCount -eq 0) { Remove-Item -LiteralPath $labPolicy }
    }
    $labState.restored = $true
    foreach ($labOld in $labBefore) {
        $labKey = Get-Item -LiteralPath $labPolicy -ErrorAction SilentlyContinue
        $labNowPresent = $labKey -and $labKey.GetValueNames().Contains($labOld.name)
        if ([bool]$labNowPresent -ne $labOld.exists -or ($labOld.exists -and $labKey.GetValue($labOld.name) -ne $labOld.value)) { $labState.restored=$false }
    }
    $labState.finished_utc = [DateTime]::UtcNow.ToString('o')
    $labState | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $labEvidence -Encoding utf8
    if (-not $labState.restored) { throw 'Edge test policy restoration verification failed; inspect the saved before state.' }
}
if ($labExit -ne 0) { throw "Browser runner exited with code $labExit; temporary Edge DNS policy was restored." }
