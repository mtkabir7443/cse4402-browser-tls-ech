#Requires -Version 7.2
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$statePath = Join-Path $root '.runtime/suite-fixtures-process.json'
$readyPath = Join-Path $root '.runtime/suite-fixtures-ready.json'
if (-not (Test-Path -LiteralPath $statePath)) { Write-Output 'No suite-fixture process is recorded.'; return }
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$proc = Get-Process -Id ([int]$state.pid) -ErrorAction SilentlyContinue
if ($proc) {
    if ($proc.Path -ne $state.executable -or $proc.StartTime.ToUniversalTime().Ticks -ne [long]$state.start_time_ticks) {
        throw 'Recorded PID no longer identifies the owned suite process; refusing to stop it.'
    }
    $details = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + [int]$state.pid)
    if (-not $details.CommandLine.Contains([string]$state.instance) -or -not $details.CommandLine.Contains([string]$state.script)) {
        throw 'Suite process command line differs from the recorded instance; refusing to stop it.'
    }
    $proc.Kill($true)
    if (-not $proc.WaitForExit(5000)) { throw 'Owned suite process did not exit within five seconds.' }
    $proc.Dispose()
}
if (Test-Path -LiteralPath $readyPath) {
    $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
    if ($ready.instance -eq $state.instance) { Remove-Item -LiteralPath $readyPath }
}
Remove-Item -LiteralPath $statePath
Write-Output 'Owned suite fixtures stopped; certificates and evidence were preserved.'
