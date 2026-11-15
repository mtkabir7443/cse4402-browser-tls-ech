#Requires -Version 7.2
[CmdletBinding()]
param([string]$NodePath = (Get-Command node -ErrorAction Stop).Source)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptPath = Join-Path $PSScriptRoot 'suite-fixtures.cjs'
$statePath = Join-Path $root '.runtime/suite-fixtures-process.json'
$readyPath = Join-Path $root '.runtime/suite-fixtures-ready.json'
$NodePath = [IO.Path]::GetFullPath($NodePath)
foreach ($required in @($NodePath, $scriptPath, (Join-Path $root '.runtime/server.pem'), (Join-Path $root '.runtime/server-key.pem'))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required fixture input is missing: $required" }
}
if (Test-Path -LiteralPath $statePath) {
    $old = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $existing = Get-Process -Id ([int]$old.pid) -ErrorAction SilentlyContinue
    if ($existing) { throw 'A recorded suite-fixture process still exists. Run Stop-SuiteFixtures.ps1 before starting another.' }
}
foreach ($port in @(9451, 9452, 9453)) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $port)
    $listener.ExclusiveAddressUse = $true
    try { $listener.Start() }
    catch { throw "Fixture port 127.0.0.1:$port is occupied; no existing process will be stopped." }
    finally { $listener.Stop() }
}
$instance = [guid]::NewGuid().ToString('N')
$stdoutPath = Join-Path $root '.runtime/suite-fixtures-stdout.log'
$stderrPath = Join-Path $root '.runtime/suite-fixtures-stderr.log'
$proc = $null
try {
    $arguments = @(('"' + $scriptPath + '"'), '--root', ('"' + $root + '"'), '--instance', $instance)
    $proc = Start-Process -FilePath $NodePath -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    $state = [ordered]@{ pid = $proc.Id; start_time_ticks = $proc.StartTime.ToUniversalTime().Ticks; executable = $NodePath; script = $scriptPath; instance = $instance; project_root = $root }
    [IO.File]::WriteAllText($statePath, ($state | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $proc.Refresh()
        if ($proc.HasExited) { throw "Suite fixtures exited with code $($proc.ExitCode). Inspect $stderrPath" }
        if (Test-Path -LiteralPath $readyPath) {
            try { $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json } catch { $ready = $null }
            if ($ready -and $ready.instance -eq $instance -and [int]$ready.pid -eq $proc.Id -and $ready.fixtures.Count -eq 3) {
                $ready | ConvertTo-Json -Depth 6
                return
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Suite fixtures did not publish readiness within ten seconds.'
} catch {
    if ($proc -and -not $proc.HasExited) { $proc.Kill($true); $null = $proc.WaitForExit(5000) }
    throw
} finally {
    if ($proc) { $proc.Dispose() }
}
