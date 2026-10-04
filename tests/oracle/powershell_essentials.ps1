# Identical script runs in real PowerShell on Windows and the guest shell.
$ErrorActionPreference = 'Stop'
New-Item work -ItemType Directory | Out-Null
Push-Location work
try {
    Set-Content test.js hello
    Rename-Item test.js test.mjs
    Write-Output 'rename.old'
    Test-Path test.js
    Write-Output 'rename.new'
    Test-Path test.mjs -PathType Leaf
    Get-Content test.mjs
    Rename-Item -Path test.mjs -NewName 'with space.mjs'
    Get-Content -LiteralPath 'with space.mjs'
    try {
        Set-Content taken.mjs keep
        Rename-Item 'with space.mjs' taken.mjs -Force -ErrorAction Stop
        Write-Output 'collision: wrong'
    } catch {
        Write-Output 'collision: rejected'
    }
    Get-Content taken.mjs
    Rename-Item 'with space.mjs' preview.mjs -WhatIf | Out-Null
    Test-Path 'with space.mjs'
    Test-Path preview.mjs
    New-Item folder -ItemType Directory | Out-Null
    Set-Content folder\nested.txt nested
    Rename-Item folder renamed
    Get-Content renamed\nested.txt
    Write-Output 'listing'
    Get-ChildItem *.mjs | ForEach-Object { Split-Path $_ -Leaf }
    Split-Path 'renamed\nested.txt' -Leaf
    Split-Path 'renamed\nested.txt' -Extension
    Get-Content taken.mjs | Select-String KEEP -Quiet
    'pipeline' | Out-File output.txt -Encoding utf8
    'append' | Out-File output.txt -Append -Encoding utf8
    Get-Content output.txt -TotalCount 1
    Get-Content output.txt -Tail 1
    Clear-Content output.txt
    Test-Path output.txt
    Get-Content output.txt
    Write-Output 'END'
} finally {
    Pop-Location
}
