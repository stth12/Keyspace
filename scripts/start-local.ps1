$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$artifactDirectory = Join-Path $projectRoot 'artifacts'
New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null
$nodeBinary = (Get-Command node.exe).Source
$services = @(
    @{ Name='api'; Port=4000; Directory=$projectRoot; Arguments=@('node_modules/tsx/dist/cli.mjs','apps/api/src/main.ts') },
    @{ Name='web'; Port=3000; Directory=(Join-Path $projectRoot 'apps/web'); Arguments=@('../../node_modules/next/dist/bin/next','dev','--hostname','127.0.0.1','--port','3000') },
    @{ Name='worker'; Port=0; Directory=$projectRoot; Arguments=@('node_modules/tsx/dist/cli.mjs','apps/worker/src/main.ts') }
)
foreach ($service in $services) {
    $existingListener = $null
    if ($service.Port -gt 0) { $existingListener = Get-NetTCPConnection -State Listen -LocalPort $service.Port -ErrorAction SilentlyContinue }
    $pidFile = Join-Path $artifactDirectory "$($service.Name).pid"
    if ($service.Port -eq 0 -and (Test-Path -LiteralPath $pidFile)) {
        $recordedPid = [int](Get-Content -LiteralPath $pidFile)
        $recordedProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $recordedPid" -ErrorAction SilentlyContinue
        if ($recordedProcess -and $recordedProcess.CommandLine.Contains('apps/worker/src/main.ts')) { Write-Output 'worker: already running'; continue }
    }
    if ($existingListener) { Write-Output "$($service.Name): port already occupied; existing process left untouched"; continue }
    $process = Start-Process -FilePath $nodeBinary -ArgumentList $service.Arguments -WorkingDirectory $service.Directory -WindowStyle Hidden -RedirectStandardOutput (Join-Path $artifactDirectory "$($service.Name).log") -RedirectStandardError (Join-Path $artifactDirectory "$($service.Name)-error.log") -PassThru
    Set-Content -LiteralPath (Join-Path $artifactDirectory "$($service.Name).pid") -Value $process.Id
    Write-Output "$($service.Name) started (PID $($process.Id))"
}
