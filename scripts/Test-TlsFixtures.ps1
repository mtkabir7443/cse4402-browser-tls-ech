#Requires -Version 7.2
<#
.SYNOPSIS
Independently verifies the local Go and OpenSSL TLS fixtures with OpenSSL clients.
.DESCRIPTION
Requires the Go fixture server to be running already. Starts only three owned
OpenSSL servers on 127.0.0.1:9451-9453, runs positive and cross-suite negative
controls, writes raw logs and summary.json, and stops its servers in finally.
No browser outcome is inferred from these fixture probes.
#>
[CmdletBinding()]
param(
    [string]$ProjectRoot = (Join-Path $PSScriptRoot '..'),
    [string]$OpenSslPath = 'C:\msys64\mingw64\bin\openssl.exe',
    [ValidateRange(2, 60)][int]$ProbeTimeoutSeconds = 15,
    [ValidateRange(1, 30)][int]$StartupTimeoutSeconds = 5,
    [string]$EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProjectRoot = [IO.Path]::GetFullPath($ProjectRoot)
$certificate = Join-Path $ProjectRoot '.runtime/server.pem'
$privateKey = Join-Path $ProjectRoot '.runtime/server-key.pem'
$caFile = Join-Path $ProjectRoot '.runtime/ca.pem'
$serverName = 'tls13.tlslab.test'

foreach ($requiredPath in @($OpenSslPath, $certificate, $privateKey, $caFile)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required fixture input is missing: $requiredPath"
    }
}
if (-not $EvidenceDirectory) {
    $runStamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
    $EvidenceDirectory = Join-Path $ProjectRoot "evidence/fixture-probes/$runStamp"
}
$EvidenceDirectory = [IO.Path]::GetFullPath($EvidenceDirectory)
if (Test-Path -LiteralPath $EvidenceDirectory) {
    throw "Refusing to overwrite an existing evidence directory: $EvidenceDirectory"
}
$null = New-Item -ItemType Directory -Path $EvidenceDirectory
$utf8 = [Text.UTF8Encoding]::new($false)
$servers = [Collections.Generic.List[object]]::new()
$results = [Collections.Generic.List[object]]::new()
$startedAt = [DateTime]::UtcNow
$fatalError = $null

$serverFixtures = @(
    @{ Id = 'tls13-aes128'; Port = 9451; Cipher = 'TLS_AES_128_GCM_SHA256' },
    @{ Id = 'tls13-aes256'; Port = 9452; Cipher = 'TLS_AES_256_GCM_SHA384' },
    @{ Id = 'tls13-chacha'; Port = 9453; Cipher = 'TLS_CHACHA20_POLY1305_SHA256' }
)

# TLS 1.0/1.1 need CBC, not TLS-1.2-only GCM, and fixture-local SECLEVEL=0.
$testCases = @(
    @{ Id = 'go-tls10'; Port = 9440; Version = 'TLSv1'; VersionFlag = '-tls1'; CipherOption = '-cipher'; Cipher = 'ECDHE-RSA-AES128-SHA:@SECLEVEL=0'; ExpectedCipher = 'ECDHE-RSA-AES128-SHA'; ExpectSuccess = $true },
    @{ Id = 'go-tls11'; Port = 9441; Version = 'TLSv1.1'; VersionFlag = '-tls1_1'; CipherOption = '-cipher'; Cipher = 'ECDHE-RSA-AES128-SHA:@SECLEVEL=0'; ExpectedCipher = 'ECDHE-RSA-AES128-SHA'; ExpectSuccess = $true },
    @{ Id = 'go-tls12'; Port = 9442; Version = 'TLSv1.2'; VersionFlag = '-tls1_2'; CipherOption = '-cipher'; Cipher = 'ECDHE-RSA-AES128-GCM-SHA256'; ExpectedCipher = 'ECDHE-RSA-AES128-GCM-SHA256'; ExpectSuccess = $true },
    @{ Id = 'go-tls13'; Port = 9443; Version = 'TLSv1.3'; VersionFlag = '-tls1_3'; CipherOption = '-ciphersuites'; Cipher = 'TLS_AES_128_GCM_SHA256'; ExpectedCipher = 'TLS_AES_128_GCM_SHA256'; ExpectSuccess = $true },
    @{ Id = 'go-tls12-aes128'; Port = 9445; Version = 'TLSv1.2'; VersionFlag = '-tls1_2'; CipherOption = '-cipher'; Cipher = 'ECDHE-RSA-AES128-GCM-SHA256'; ExpectedCipher = 'ECDHE-RSA-AES128-GCM-SHA256'; ExpectSuccess = $true },
    @{ Id = 'go-tls12-chacha'; Port = 9446; Version = 'TLSv1.2'; VersionFlag = '-tls1_2'; CipherOption = '-cipher'; Cipher = 'ECDHE-RSA-CHACHA20-POLY1305'; ExpectedCipher = 'ECDHE-RSA-CHACHA20-POLY1305'; ExpectSuccess = $true },
    @{ Id = 'openssl-tls13-aes128'; Port = 9451; Version = 'TLSv1.3'; VersionFlag = '-tls1_3'; CipherOption = '-ciphersuites'; Cipher = 'TLS_AES_128_GCM_SHA256'; ExpectedCipher = 'TLS_AES_128_GCM_SHA256'; ExpectSuccess = $true },
    @{ Id = 'openssl-tls13-aes256'; Port = 9452; Version = 'TLSv1.3'; VersionFlag = '-tls1_3'; CipherOption = '-ciphersuites'; Cipher = 'TLS_AES_256_GCM_SHA384'; ExpectedCipher = 'TLS_AES_256_GCM_SHA384'; ExpectSuccess = $true },
    @{ Id = 'openssl-tls13-chacha'; Port = 9453; Version = 'TLSv1.3'; VersionFlag = '-tls1_3'; CipherOption = '-ciphersuites'; Cipher = 'TLS_CHACHA20_POLY1305_SHA256'; ExpectedCipher = 'TLS_CHACHA20_POLY1305_SHA256'; ExpectSuccess = $true },
    @{ Id = 'negative-aes128-rejects-aes256'; Port = 9451; Version = 'TLSv1.3'; VersionFlag = '-tls1_3'; CipherOption = '-ciphersuites'; Cipher = 'TLS_AES_256_GCM_SHA384'; ExpectedCipher = ''; ExpectSuccess = $false },
    @{ Id = 'negative-aes256-rejects-chacha'; Port = 9452; Version = 'TLSv1.3'; VersionFlag = '-tls1_3'; CipherOption = '-ciphersuites'; Cipher = 'TLS_CHACHA20_POLY1305_SHA256'; ExpectedCipher = ''; ExpectSuccess = $false },
    @{ Id = 'negative-chacha-rejects-aes128'; Port = 9453; Version = 'TLSv1.3'; VersionFlag = '-tls1_3'; CipherOption = '-ciphersuites'; Cipher = 'TLS_AES_128_GCM_SHA256'; ExpectedCipher = ''; ExpectSuccess = $false },
    @{ Id = 'negative-tls12-aes128-rejects-chacha'; Port = 9445; Version = 'TLSv1.2'; VersionFlag = '-tls1_2'; CipherOption = '-cipher'; Cipher = 'ECDHE-RSA-CHACHA20-POLY1305'; ExpectedCipher = ''; ExpectSuccess = $false },
    @{ Id = 'negative-tls12-chacha-rejects-aes128'; Port = 9446; Version = 'TLSv1.2'; VersionFlag = '-tls1_2'; CipherOption = '-cipher'; Cipher = 'ECDHE-RSA-AES128-GCM-SHA256'; ExpectedCipher = ''; ExpectSuccess = $false }
)

function New-OpenSslProcess {
    param([string[]]$OpenSslArguments)
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $OpenSslPath
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.WorkingDirectory = $ProjectRoot
    foreach ($argument in $OpenSslArguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    $null = $process.Start()
    return [pscustomobject]@{
        Process = $process
        StdoutTask = $process.StandardOutput.ReadToEndAsync()
        StderrTask = $process.StandardError.ReadToEndAsync()
        Arguments = $OpenSslArguments
    }
}

function Stop-OwnedProcess {
    param($State)
    # Never search by executable name: only stop the Process object we started.
    if (-not $State.Process.HasExited) {
        $State.Process.Kill($true)
        if (-not $State.Process.WaitForExit(5000)) {
            throw "Owned process PID $($State.Process.Id) did not terminate."
        }
    }
}

function Get-CompletedText {
    param($Task)
    if (-not $Task.Wait(5000)) { throw 'Redirected stream did not complete within five seconds.' }
    return $Task.GetAwaiter().GetResult()
}

function Test-LoopbackPortAvailable {
    param([int]$Port)
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    $listener.ExclusiveAddressUse = $true
    try { $listener.Start() }
    catch { throw "Fixture port 127.0.0.1:$Port is already occupied or unavailable: $($_.Exception.Message)" }
    finally { $listener.Stop() }
}

function Wait-OwnedServer {
    param($State, [int]$Port)
    $deadline = [DateTime]::UtcNow.AddSeconds($StartupTimeoutSeconds)
    do {
        if ($State.Process.HasExited) {
            throw "OpenSSL fixture on port $Port exited before readiness (code $($State.Process.ExitCode))."
        }
        $tcp = [Net.Sockets.TcpClient]::new()
        try {
            $task = $tcp.ConnectAsync([Net.IPAddress]::Loopback, $Port)
            if ($task.Wait(150) -and $tcp.Connected) { return }
        }
        catch { }
        finally { $tcp.Dispose() }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "OpenSSL fixture on port $Port did not become ready within $StartupTimeoutSeconds seconds."
}

function Invoke-FixtureProbe {
    param([hashtable]$Case)
    $clientArguments = @(
        's_client', '-connect', "127.0.0.1:$($Case.Port)",
        '-servername', $serverName, '-verify_hostname', $serverName,
        '-CAfile', $caFile, '-verify_return_error', '-brief', '-ign_eof',
        $Case.VersionFlag, $Case.CipherOption, $Case.Cipher
    )
    $state = $null
    $probeStarted = [DateTime]::UtcNow
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $stdout = ''
    $stderr = ''
    $exitCode = $null
    $timedOut = $false
    $executionError = $null
    try {
        $state = New-OpenSslProcess -OpenSslArguments $clientArguments
        # HTTP/1.0 + Connection: close makes normal servers terminate the session.
        $request = "GET / HTTP/1.0`r`nHost: $serverName`r`nConnection: close`r`n`r`n"
        $state.Process.StandardInput.Write($request)
        $state.Process.StandardInput.Close()
        if (-not $state.Process.WaitForExit($ProbeTimeoutSeconds * 1000)) {
            $timedOut = $true
            Stop-OwnedProcess -State $state
        }
        $exitCode = $state.Process.ExitCode
    }
    catch { $executionError = $_.Exception.Message }
    finally {
        if ($null -ne $state) {
            try {
                Stop-OwnedProcess -State $state
                if ($null -eq $exitCode) { $exitCode = $state.Process.ExitCode }
                $stdout = Get-CompletedText -Task $state.StdoutTask
                $stderr = Get-CompletedText -Task $state.StderrTask
            }
            catch { $executionError = @($executionError, $_.Exception.Message) -join '; ' }
            finally { $state.Process.Dispose() }
        }
        $timer.Stop()
    }

    $stdoutPath = Join-Path $EvidenceDirectory "$($Case.Id).stdout.log"
    $stderrPath = Join-Path $EvidenceDirectory "$($Case.Id).stderr.log"
    [IO.File]::WriteAllText($stdoutPath, $stdout, $utf8)
    [IO.File]::WriteAllText($stderrPath, $stderr, $utf8)
    $combined = "$stdout`n$stderr"
    $protocolMatch = [regex]::Match($combined, '(?im)^\s*Protocol version:\s*(\S+)')
    $cipherMatch = [regex]::Match($combined, '(?im)^\s*Ciphersuite:\s*(\S+)')
    $protocol = if ($protocolMatch.Success) { $protocolMatch.Groups[1].Value } else { $null }
    $cipher = if ($cipherMatch.Success) { $cipherMatch.Groups[1].Value } else { $null }
    $verified = [regex]::IsMatch($combined, '(?im)^\s*Verification:\s*OK\s*$')
    # A refused connection, local cipher error, or timeout is not a negative-control pass.
    $peerRejected = [regex]::IsMatch($combined, '(?i)alert (handshake failure|protocol version|insufficient security)')
    if ($Case.ExpectSuccess) {
        $passed = (-not $timedOut) -and (-not $executionError) -and ($exitCode -eq 0) -and
            $verified -and ($protocol -eq $Case.Version) -and ($cipher -eq $Case.ExpectedCipher)
    }
    else {
        $passed = (-not $timedOut) -and (-not $executionError) -and ($null -ne $exitCode) -and
            ($exitCode -ne 0) -and $peerRejected -and (-not $protocol) -and (-not $cipher)
    }
    return [pscustomobject]@{
        id = $Case.Id
        started_at_utc = $probeStarted.ToString('o')
        endpoint = "127.0.0.1:$($Case.Port)"
        server_name = $serverName
        expected_success = $Case.ExpectSuccess
        expected_protocol = $Case.Version
        expected_cipher = $Case.ExpectedCipher
        offered_cipher_argument = $Case.Cipher
        command_arguments = $clientArguments
        exit_code = $exitCode
        timed_out = $timedOut
        duration_ms = $timer.ElapsedMilliseconds
        protocol = $protocol
        cipher = $cipher
        certificate_verified = $verified
        peer_rejected_handshake = $peerRejected
        execution_error = $executionError
        passed = [bool]$passed
        stdout_log = $stdoutPath
        stderr_log = $stderrPath
    }
}

try {
    foreach ($fixture in $serverFixtures) {
        Test-LoopbackPortAvailable -Port $fixture.Port
        $serverArguments = @(
            's_server', '-accept', "127.0.0.1:$($fixture.Port)",
            '-cert', $certificate, '-key', $privateKey,
            '-tls1_3', '-ciphersuites', $fixture.Cipher,
            '-no_ticket', '-no_cache', '-www', '-brief'
        )
        $state = New-OpenSslProcess -OpenSslArguments $serverArguments
        $server = [pscustomobject]@{ Id = $fixture.Id; Port = $fixture.Port; State = $state; Pid = $state.Process.Id; Stopped = $false; CleanupError = $null }
        $servers.Add($server)
        Wait-OwnedServer -State $state -Port $fixture.Port
    }
    foreach ($case in $testCases) {
        $result = Invoke-FixtureProbe -Case $case
        $results.Add($result)
        Write-Host ("{0}: {1}" -f $result.id, $(if ($result.passed) { 'PASS' } else { 'FAIL' }))
    }
}
catch { $fatalError = $_.Exception.Message }
finally {
    foreach ($server in $servers) {
        try {
            Stop-OwnedProcess -State $server.State
            $server.Stopped = $server.State.Process.HasExited
            [IO.File]::WriteAllText((Join-Path $EvidenceDirectory "$($server.Id).server.stdout.log"), (Get-CompletedText -Task $server.State.StdoutTask), $utf8)
            [IO.File]::WriteAllText((Join-Path $EvidenceDirectory "$($server.Id).server.stderr.log"), (Get-CompletedText -Task $server.State.StderrTask), $utf8)
        }
        catch { $server.CleanupError = $_.Exception.Message }
        finally { $server.State.Process.Dispose() }
    }
}

$failed = @($results | Where-Object { -not $_.passed })
$cleanupFailed = @($servers | Where-Object { (-not $_.Stopped) -or $_.CleanupError })
$allPassed = (-not $fatalError) -and ($results.Count -eq $testCases.Count) -and
    ($failed.Count -eq 0) -and ($cleanupFailed.Count -eq 0)
$summary = [ordered]@{
    purpose = 'Independent TLS fixture verification; not browser measurements'
    started_at_utc = $startedAt.ToString('o')
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    openssl_path = $OpenSslPath
    openssl_sha256 = (Get-FileHash -LiteralPath $OpenSslPath -Algorithm SHA256).Hash
    certificate_sha256 = (Get-FileHash -LiteralPath $certificate -Algorithm SHA256).Hash
    ca_sha256 = (Get-FileHash -LiteralPath $caFile -Algorithm SHA256).Hash
    server_name = $serverName
    expected_probe_count = $testCases.Count
    completed_probe_count = $results.Count
    passed_probe_count = @($results | Where-Object passed).Count
    failed_probe_count = $failed.Count
    all_passed = [bool]$allPassed
    fatal_error = $fatalError
    owned_servers = @($servers | ForEach-Object { [ordered]@{ id = $_.Id; port = $_.Port; pid = $_.Pid; stopped = $_.Stopped; cleanup_error = $_.CleanupError; arguments = $_.State.Arguments } })
    probes = $results.ToArray()
}
$summaryPath = Join-Path $EvidenceDirectory 'summary.json'
[IO.File]::WriteAllText($summaryPath, ($summary | ConvertTo-Json -Depth 12), $utf8)
Write-Host "Fixture verification evidence: $summaryPath"
if (-not $allPassed) {
    throw "TLS fixture verification failed or was incomplete. Inspect $summaryPath"
}
Write-Output ([pscustomobject]@{ Passed = $true; Probes = $results.Count; SummaryPath = $summaryPath })
