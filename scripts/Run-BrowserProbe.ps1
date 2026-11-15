#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('chrome', 'firefox')]
    [string]$Browser,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,39}$')]
    [string]$Case = 'valid',

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$')]
    [string]$RunId,

    [string]$URL,

    [string]$ExecutablePath,

    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 60
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$utf8 = [System.Text.UTF8Encoding]::new($false)
if (-not $RunId) {
    $RunId = '{0}-{1}-{2}-{3}' -f ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmssfff')), $Browser, $Case, ([guid]::NewGuid().ToString('N').Substring(0, 6))
}
if (-not $URL) {
    $URL = 'https://{0}.tlslab.test:9443/probe?run={1}' -f $Case, [Uri]::EscapeDataString($RunId)
}
$target = [Uri]$URL
if (-not $target.IsAbsoluteUri -or $target.Scheme -ne 'https' -or
    -not ($target.Host.EndsWith('.tlslab.test', [StringComparison]::OrdinalIgnoreCase) -or
          $target.Host -in @('127.0.0.1', 'localhost', '[::1]'))) {
    throw 'The browser probe only navigates to an HTTPS endpoint in the controlled tlslab.test/loopback lab.'
}

$dohUri = 'https://127.0.0.1:8443/dns-query'
$profile = Join-Path $projectRoot ('.runtime/profiles/' + $RunId)
$evidence = Join-Path $projectRoot 'evidence'
if (Test-Path -LiteralPath $profile) {
    throw "Fresh-profile requirement: the run directory already exists: $profile"
}
New-Item -ItemType Directory -Path $profile -Force | Out-Null
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$metadataPath = Join-Path $evidence ($RunId + '-runner.json')
$stdoutPath = Join-Path $evidence ($RunId + '-stdout.txt')
$stderrPath = Join-Path $evidence ($RunId + '-stderr.txt')
$domPath = Join-Path $evidence ($RunId + '-dom.html')
$netlogPath = Join-Path $evidence ($RunId + '-netlog.json')
$screenshotPath = Join-Path $evidence ($RunId + '.png')
foreach ($outputPath in @($metadataPath, $stdoutPath, $stderrPath, $domPath, $netlogPath, $screenshotPath)) {
    if (Test-Path -LiteralPath $outputPath) { throw "Run ID already has evidence: $outputPath" }
}

$meta = [ordered]@{
    run_id = $RunId
    browser = $Browser
    case = $Case
    url = $URL
    started_utc = [DateTime]::UtcNow.ToString('o')
    finished_utc = $null
    status = 'preparing'
    feature_result = 'Not inferred from runner exit status; inspect the server handshake records and browser evidence.'
    timeout_seconds = $TimeoutSeconds
    timed_out = $false
    executable = $null
    executable_version = $null
    os_version = [Environment]::OSVersion.VersionString
    powershell_version = $PSVersionTable.PSVersion.ToString()
    profile = $profile
    settings = $null
    arguments = @()
    root_process_id = $null
    owned_process_ids = @()
    cleanup_errors = @()
    exit_code = $null
    error = $null
    certificate_verification_bypassed = $false
    trust = $null
    evidence = [ordered]@{ stdout = $stdoutPath; stderr = $stderrPath }
}
$process = $null
$processStarted = $false
$stdoutTask = $null
$stderrTask = $null
$owned = @{}
$runFailure = $null

function Register-OwnedDescendants {
    param([int]$RootProcessId, [hashtable]$Known)
    # Discover only descendants of the process created by this script. Capture
    # creation time as well as PID, so cleanup cannot target a reused PID.
    $snapshot = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, CreationDate -ErrorAction Stop)
    foreach ($row in $snapshot) {
        if ([int]$row.ProcessId -eq $RootProcessId -and $row.CreationDate -and -not $Known.ContainsKey($RootProcessId)) {
            $Known[$RootProcessId] = $row.CreationDate.ToUniversalTime().Ticks
        }
    }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($row in $snapshot) {
            $childId = [int]$row.ProcessId
            if ($row.CreationDate -and $Known.ContainsKey([int]$row.ParentProcessId) -and -not $Known.ContainsKey($childId)) {
                $Known[$childId] = $row.CreationDate.ToUniversalTime().Ticks
                $changed = $true
            }
        }
    }
}

try {
    $arguments = [System.Collections.Generic.List[string]]::new()
    if ($Browser -eq 'chrome') {
        $candidates = @(
            (Join-Path $env:ProgramFiles 'Google/Chrome/Application/chrome.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Google/Chrome/Application/chrome.exe'),
            (Join-Path $env:LOCALAPPDATA 'Google/Chrome/Application/chrome.exe')
        )
        $executable = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if ($ExecutablePath) {
            $candidatePath=[IO.Path]::GetFullPath($ExecutablePath)
            $toolsPrefix=[IO.Path]::GetFullPath((Join-Path $projectRoot '.tools'))+[IO.Path]::DirectorySeparatorChar
            if(-not $candidatePath.StartsWith($toolsPrefix,[StringComparison]::OrdinalIgnoreCase) -or -not(Test-Path -LiteralPath $candidatePath -PathType Leaf)){throw 'Override executable must be an existing project-local browser.'}
            $executable=$candidatePath
        }
        if (-not $executable) { throw 'No installed Chrome executable was found in the standard application paths.' }
        $settings = [ordered]@{
            dns_over_https = [ordered]@{ mode = 'secure'; templates = $dohUri }
            async_dns = [ordered]@{ enabled = $true; additional_dns_query_types_enabled = $true }
            ssl = [ordered]@{ ech_enabled = $true }
        }
        [IO.File]::WriteAllText((Join-Path $profile 'Local State'), ($settings | ConvertTo-Json -Depth 8), $utf8)
        $meta.settings = $settings
        $meta.evidence.dom = $domPath
        $meta.evidence.netlog = $netlogPath
        foreach ($argument in @(
            '--headless=new', '--no-first-run', '--no-default-browser-check',
            '--disable-quic', '--disable-background-networking', '--disable-component-update',
            '--disable-sync', '--disable-default-apps',
            ('--user-data-dir=' + $profile), ('--log-net-log=' + $netlogPath),
            '--net-log-capture-mode=IncludeSensitive', '--dump-dom', $URL
        )) { $arguments.Add($argument) }
    } else {
        $executable = Join-Path $projectRoot '.tools/firefox-160/core/firefox.exe'
        if (-not (Test-Path -LiteralPath $executable)) { throw "Firefox fixture executable not found: $executable" }
        $meta.trust = & (Join-Path $PSScriptRoot 'Configure-FirefoxTrust.ps1')
        $settings = [ordered]@{
            'network.trr.mode' = 3
            'network.trr.uri' = $dohUri
            'network.trr.custom_uri' = $dohUri
            'network.trr.confirmationNS' = 'skip'
            'network.trr.wait-for-portal' = $false
            'network.trr.allow-rfc1918' = $true
            'network.trr.excluded-domains' = ''
            'network.trr.temp_blocklist' = $false
            'network.dns.echconfig.enabled' = $true
            'network.http.http3.enable' = $false
            'security.enterprise_roots.enabled' = $false
            'browser.shell.checkDefaultBrowser' = $false
            'browser.startup.homepage_override.mstone' = 'ignore'
            'browser.aboutwelcome.enabled' = $false
            'browser.startup.page' = 0
            'app.update.auto' = $false
            'datareporting.policy.dataSubmissionEnabled' = $false
            'toolkit.telemetry.enabled' = $false
            'network.captive-portal-service.enabled' = $false
            'network.connectivity-service.enabled' = $false
        }
        $prefLines = foreach ($entry in $settings.GetEnumerator()) {
            'user_pref({0}, {1});' -f (ConvertTo-Json -InputObject $entry.Key -Compress), (ConvertTo-Json -InputObject $entry.Value -Compress)
        }
        [IO.File]::WriteAllLines((Join-Path $profile 'user.js'), [string[]]$prefLines, $utf8)
        $meta.settings = $settings
        $meta.evidence.screenshot = $screenshotPath
        foreach ($argument in @('-no-remote', '-profile', $profile, '--headless', '--screenshot', $screenshotPath, $URL)) {
            $arguments.Add($argument)
        }
    }

    $meta.executable = $executable
    $meta.executable_version = (Get-Item -LiteralPath $executable).VersionInfo.ProductVersion
    $meta.arguments = $arguments.ToArray()
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $executable
    $start.WorkingDirectory = $projectRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $arguments) { $start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'Browser process did not start.' }
    $processStarted = $true
    $meta.root_process_id = $process.Id
    $meta.status = 'running'
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $lastCapture = -1000
    while (-not $process.HasExited -and $watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if ($watch.ElapsedMilliseconds - $lastCapture -ge 500) {
            Register-OwnedDescendants -RootProcessId $process.Id -Known $owned
            $lastCapture = $watch.ElapsedMilliseconds
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $process.HasExited) {
        $meta.timed_out = $true
        $meta.status = 'timeout'
    } else {
        $meta.exit_code = $process.ExitCode
        $meta.status = if ($process.ExitCode -eq 0) { 'completed' } else { 'browser_exit_error' }
    }
} catch {
    $runFailure = $_
    $meta.status = 'runner_error'
    $meta.error = $_.Exception.Message
} finally {
    if ($processStarted) {
        if (-not $process.HasExited) {
            try { $process.Kill($true); $null = $process.WaitForExit(5000) }
            catch { $meta.cleanup_errors += $_.Exception.Message }
        }
        # A browser may leave a helper after its root exits. Only kill a helper
        # previously observed in this run's process tree with the same birth time.
        foreach ($entry in @($owned.GetEnumerator() | Sort-Object Value -Descending)) {
            try {
                $row = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $entry.Key) -Property ProcessId, CreationDate -ErrorAction Stop
                if ($row -and $row.CreationDate -and $row.CreationDate.ToUniversalTime().Ticks -eq $entry.Value) {
                    $helper = [Diagnostics.Process]::GetProcessById([int]$entry.Key)
                    if (-not $helper.HasExited) { $helper.Kill($true); $null = $helper.WaitForExit(3000) }
                    $helper.Dispose()
                }
            } catch { $meta.cleanup_errors += $_.Exception.Message }
        }
        foreach ($streamName in @('stdout', 'stderr')) {
            $task = if ($streamName -eq 'stdout') { $stdoutTask } else { $stderrTask }
            if ($task) {
                try {
                    if ($task.Wait(5000)) {
                        $streamText = $task.Result
                        $streamPath = if ($streamName -eq 'stdout') { $stdoutPath } else { $stderrPath }
                        [IO.File]::WriteAllText($streamPath, $streamText, $utf8)
                        if ($streamName -eq 'stdout' -and $Browser -eq 'chrome') { [IO.File]::WriteAllText($domPath, $streamText, $utf8) }
                    } else { $meta.cleanup_errors += "$streamName capture did not close after browser cleanup." }
                } catch { $meta.cleanup_errors += $_.Exception.Message }
            }
        }
        if ($process.HasExited -and $null -eq $meta.exit_code) { $meta.exit_code = $process.ExitCode }
    }
    if ($process) { $process.Dispose() }
    $meta.owned_process_ids = @($owned.Keys | Sort-Object)
    $meta.finished_utc = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText($metadataPath, ($meta | ConvertTo-Json -Depth 12), $utf8)
}

$meta | ConvertTo-Json -Depth 12
if ($runFailure) { throw $runFailure }
