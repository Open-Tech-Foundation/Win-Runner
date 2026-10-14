# Identical script runs in real PowerShell on Windows and the guest shell.
# Covers expressions (operators, arrays, hashtables, casts, static members,
# string methods), the utility cmdlets' output formats, the registry
# provider under Get-ChildItem, and where.exe.
$ErrorActionPreference = 'Stop'

1+1
7/2
1/3
7 % 3
'1' + 1
1 + '1'
'x' * 3
-3 + 1
1kb
0x10
$a = 1,2,3
$a.Count
$a[-1]
1..4 -join ','
(1,5,9) -gt 3
@(1,2) + 3
$h = @{a=1; b='two'}
$h.b
$h['A']
'a;b' -split ';'
'Hello' -replace 'l','L'
'abc' -like 'A*'
'abc' -clike 'A*'
'Hello' -match 'h.l'
3 -in 1,2,3
'{0}-{1:N1}' -f 'x', 1234.5
'{0,5}|{1,-4}|' -f 'ab', 'c'
'{0:D4} {1:X} {2:F3}' -f 7, 255, 2.5
[math]::Max(3, 9)
[math]::Round(2.5)
[int]2.5
[int]3.5
[int]'42' + 1
'  hi '.Trim().ToUpper()
'hello'.Substring(1, 3)
'a-b-c'.Split('-').Count
-not $false
$null -eq $null
$s = 'a'
$s += 'b'
$s
$n = 1
$n += 2
$n
[bool]'0'
"sub: $(1+2)"
5 -band 3
[string]::Join('-', @('a','b'))

# Each formatted block is captured alone with Out-String: how one script's
# consecutive outputs share a table is the host's whole-stream formatting,
# not the cmdlets'. Hashtable key order is hash order, so JSON input uses
# [ordered] and pscustomobject.
"group: [$('a','b','a' | Group-Object | Out-String)]"
"group.noelement: [$('a','b','a' | Group-Object -NoElement | Out-String)]"
[ordered]@{Name='n'; Size=3} | ConvertTo-Json
[ordered]@{Name='n'; Size=3} | ConvertTo-Json -Compress
$o = '{"Ab":1,"c":{"d":"x"},"l":[1,2]}' | ConvertFrom-Json
$o.ab
$o.c.d
$o.l.Count
$o | ConvertTo-Json -Compress
"table: [$([pscustomobject]@{Name='n'; Size=3} | Format-Table | Out-String)]"
"list: [$([pscustomobject]@{Name='n'; Size=3} | Format-List | Out-String)]"
"string: [$('x','y' | Out-String)]"

$key = 'HKCU:\Software\WinRunOracleExpr'
if (Test-Path $key) { Remove-Item $key -Recurse }
New-Item "$key\Child" -Force | Out-Null
New-ItemProperty -Path $key -Name V -Value 'x' | Out-Null
New-ItemProperty -Path "$key\Child" -Name W -Value 'y' | Out-Null
"reg.children: $((Get-ChildItem $key).PSChildName)"
"reg.names: $((Get-ChildItem $key).Name)"
"reg.value: $(Get-ItemPropertyValue $key -Name V)"
try { Get-Content $key } catch { "reg.content: $($_.Exception.Message)" }
Remove-Item $key -Recurse

where.exe cmd
where.exe winrun-no-such-program 2>$null
"where.missing: $LASTEXITCODE"
(Get-Command cmd,where).Count
