# WinCLI error-path test: must exit nonzero with a clear stderr,
# and must NOT print the marker.
# Run: wincli fs_error.ps1
Remove-Item -Path "C:\nope\missing.txt"
Write-Host "SHOULD-NOT-PRINT"
