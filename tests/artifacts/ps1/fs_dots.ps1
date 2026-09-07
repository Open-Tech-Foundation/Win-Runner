# WinCLI `.` / `..` / `/` normalization test.
# Run: wincli fs_dots.ps1
# Expected stdout:
#   dots-ok
#   dots-ok
#   True
#   PS1-DOTS-DONE
New-Item -Path "C:\d1\d2" -ItemType Directory -Force
Set-Content -Path "C:\d1\d2\x.txt" -Value "dots-ok"
Get-Content -Path "C:\d1\.\d2\..\d2\x.txt"
Get-Content -Path "C:/d1/d2/x.txt"
Test-Path "C:\d1\d2\..\d2\."
Write-Host "PS1-DOTS-DONE"
