# Run every Windows-oracle probe on real Windows, one transcript per probe.
#
#   pwsh tests/oracle/run-windows.ps1 -OutputDir <dir>
#
# Each probe starts in a fresh directory, as run-winrun.sh starts it in
# C:\oracle-run under Win-Runner. Standard output is captured as raw bytes,
# then line endings are normalized to LF.
param([Parameter(Mandatory = $true)][string]$OutputDir)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$OutputDir = (Resolve-Path $OutputDir).Path
Get-ChildItem (Join-Path $root 'tests\artifacts\exe') -Filter 'oracle_*.exe' | ForEach-Object {
    $name = $_.BaseName -replace '^oracle_', ''
    # Not under %TEMP%: on GitHub runners that is an 8.3 short path
    # (C:\Users\RUNNER~1\...), whose long form final-path queries would
    # report instead. Short names get probe cases of their own.
    $run = Join-Path $root ("oracle-run-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $run | Out-Null
    Push-Location $run
    try {
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = $_.FullName
        $start.WorkingDirectory = $run
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::Start($start)
        $stdout = New-Object System.IO.MemoryStream
        $errorTask = $process.StandardError.ReadToEndAsync()
        $process.StandardOutput.BaseStream.CopyTo($stdout)
        $process.WaitForExit()
        $text = [System.Text.Encoding]::UTF8.GetString($stdout.ToArray()) -replace "`r`n", "`n"
        [System.IO.File]::WriteAllText((Join-Path $OutputDir "$name.txt"), $text)
        [System.IO.File]::WriteAllText((Join-Path $OutputDir "$name.stderr"), $errorTask.Result)
        Write-Host "ran ${name}: exit $($process.ExitCode)"
    } finally {
        Pop-Location
        Remove-Item -Recurse -Force $run -ErrorAction SilentlyContinue
    }
}
