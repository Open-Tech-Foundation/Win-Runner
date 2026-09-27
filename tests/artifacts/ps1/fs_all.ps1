# Win-Runner FS smoke test: exercises every supported cmdlet.
# Run: winrun fs_all.ps1
# Expected stdout:
#   two
#   three
#   a.txt
#   b.txt
#   True
#   PS1-ALL-DONE
New-Item -Path "C:\art" -ItemType Directory
New-Item -Path "C:\art\a.txt" -ItemType File -Value "one"
Set-Content -Path "C:\art\b.txt" -Value "two"
Add-Content -Path "C:\art\b.txt" -Value "three"
Get-Content -Path "C:\art\b.txt"
Get-ChildItem -Path "C:\art"
Copy-Item -Path "C:\art\b.txt" -Destination "C:\art\c.txt"
Move-Item -Path "C:\art\c.txt" -Destination "C:\art\d.txt"
Test-Path "C:\art\d.txt"
Remove-Item -Path "C:\art\a.txt"
Remove-Item -Path "C:\art\b.txt"
Remove-Item -Path "C:\art\d.txt"
Write-Host "PS1-ALL-DONE"
