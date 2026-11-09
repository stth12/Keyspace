$ErrorActionPreference = 'Stop'
$restoreDatabase = 'lk_restore_' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
if ($restoreDatabase -notmatch '^lk_restore_[0-9]+$') { throw 'Invalid restore database name' }
$dumpPath = '/tmp/' + $restoreDatabase + '.dump'
$checkQuery = "SELECT 'users',count(*) FROM users UNION ALL SELECT 'licenses',count(*) FROM licenses UNION ALL SELECT 'audit_logs',count(*) FROM audit_logs UNION ALL SELECT 'constraints',count(*) FROM pg_constraint WHERE connamespace='public'::regnamespace ORDER BY 1"
function Invoke-DatabaseTool {
    param([string[]]$ToolArguments)
    $result = & docker compose exec -T postgres @ToolArguments
    if ($LASTEXITCODE -ne 0) { throw 'Database verification command failed' }
    return $result
}
$created = $false
try {
    Invoke-DatabaseTool @('pg_dump','-U','postgres','-d','licensing','--format=custom','--file',$dumpPath)
    $expected = Invoke-DatabaseTool @('psql','-U','postgres','-d','licensing','-At','-c',$checkQuery)
    Invoke-DatabaseTool @('createdb','-U','postgres',$restoreDatabase)
    $created = $true
    Invoke-DatabaseTool @('pg_restore','-U','postgres','-d',$restoreDatabase,'--no-owner','--no-acl','--exit-on-error',$dumpPath)
    $actual = Invoke-DatabaseTool @('psql','-U','postgres','-d',$restoreDatabase,'-At','-c',$checkQuery)
    if (($expected -join "`n") -ne ($actual -join "`n")) { throw 'Restored row or constraint counts differ; run with writers stopped' }
    Write-Output 'Restore verified in isolated database: user, license, audit counts and constraints match.'
} finally {
    if ($created) { Invoke-DatabaseTool @('dropdb','-U','postgres',$restoreDatabase) }
    Invoke-DatabaseTool @('rm','-f',$dumpPath)
}
