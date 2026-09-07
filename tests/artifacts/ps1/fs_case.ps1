# WinCLI case-insensitivity test.
# Run: wincli fs_case.ps1
# Expected stdout:
#   ci-ok
#   CaSe.TxT
#   True
#   PS1-CASE-DONE
New-Item -Path "C:\Mixed" -ItemType Directory
Set-Content -Path "C:\MIXED\CaSe.TxT" -Value "ci-ok"
Get-Content -Path "c:\mixed\case.txt"
Get-ChildItem -Path "C:\MIXED"
Test-Path "c:\MIXED\CASE.TXT"
Write-Host "PS1-CASE-DONE"
