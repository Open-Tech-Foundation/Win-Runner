# Identical script runs in real PowerShell on Windows and the guest shell.
# Covers what installer scripts rely on: param blocks, return, and the
# registry provider with Microsoft.Win32.RegistryKey methods.
param(
    [String]$Version = "latest",
    [Switch]$Quiet = $false
)
$ErrorActionPreference = 'Stop'
Write-Output "param.defaults: $Version $Quiet"

function Show-Args {
    param([String]$Name = "def", [Switch]$Loud, [bool]$Flag = $False)
    Write-Output "param.bound: $Name-$Loud-$Flag"
}
Show-Args
Show-Args -Name x -Loud
Show-Args -Fl $True y
Show-Args -Loud:$false -N z

function Get-First($x) {
    if ($x -eq 1) { return 'return.early: one' }
    foreach ($i in @(5, 6)) { return "loop-$i" }
    Write-Output 'unreachable'
}
Get-First 1
$first = Get-First 2
Write-Output "return.value: $first"

Write-Output "reg.arch: $((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment').PROCESSOR_ARCHITECTURE)"
$key = 'HKCU:\Software\WinRunOracle'
if (Test-Path $key) { Remove-Item $key -Recurse }
$created = New-Item -Path $key -Force
Write-Output "reg.created: $($created.Name)"
New-ItemProperty -Path $key -Name Plain -Value 'C:\plain' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name Expand -Value '%SystemRoot%\x' -PropertyType ExpandString | Out-Null
New-ItemProperty -Path $key -Name Number -Value 7 -PropertyType DWord | Out-Null
Write-Output "reg.plain: $((Get-ItemProperty $key).Plain)"
Write-Output "reg.expanded: $((Get-ItemProperty $key).Expand)"
Write-Output "reg.number: $((Get-ItemProperty $key).Number)"
Set-ItemProperty -Path $key -Name Plain -Value 'C:\changed'
Write-Output "reg.changed: $((Get-ItemProperty $key).Plain)"
$root = Get-Item -Path 'HKCU:'
Write-Output "reg.root: $($root.Name)"
$sub = $root.OpenSubKey('Software\WinRunOracle', $true)
Write-Output "reg.open: $($sub.Name)"
Write-Output "reg.raw: $($sub.GetValue('Expand', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames))"
Write-Output "reg.kind: $($sub.GetValueKind('Expand')) $($sub.GetValueKind('Number'))"
$sub.SetValue('Path', 'a;b', [Microsoft.Win32.RegistryValueKind]::ExpandString)
Write-Output "reg.set: $($sub.GetValueKind('Path')) $($sub.GetValue('Path'))"
$sub.DeleteValue('Path')
Write-Output "reg.deleted: $($sub.GetValue('Path', 'gone'))"
$missing = $root.OpenSubKey('Software\WinRunOracle\Nope')
if ($null -eq $missing) { Write-Output 'reg.missing: null' }
$sub.Close()
Remove-ItemProperty -Path $key -Name Number
Write-Output "reg.removed: [$((Get-ItemProperty $key).Number)]"
Remove-Item $key -Recurse
Write-Output "reg.cleaned: $(Test-Path $key)"
$v = [System.Environment]::OSVersion.Version
Write-Output "os: $($v.Major -ge 10) $([Environment]::OSVersion.Platform)"
$isArm = 'AMD64' -eq 'ARM64'
Write-Output "expr.bool: $isArm $(-not ($isArm -or 'x' -like 'X*')) $(!$isArm)"
Write-Output "expr.numeric: $(9 -lt 10) $(0x10 -eq 16) $('Bun' -notlike '*-canary.*')"
Write-Output "nested: $(if ('a' -eq "a") { "yes" } else { 'no' })"
Write-Output `
    'continued: ok'
$null = mkdir -Force made\deep
$made = mkdir -Force made\deep
Write-Output "mkdir: $(Split-Path $made -Leaf) $(Test-Path made\deep)"
Remove-Item missing.txt -ErrorAction SilentlyContinue
Write-Output 'erroraction: continued'
$global:Pref = 'g'
Write-Output "scope: $Pref $global:Pref"
$noSse2 = !( `
    Add-Type -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool IsProcessorFeaturePresent(int ProcessorFeature);' `
        -Name 'OracleKernel32' -Namespace 'WinRunOracle' -PassThru `
)::IsProcessorFeaturePresent(10)
Write-Output "addtype.sse2: $noSse2 $([WinRunOracle.OracleKernel32]::IsProcessorFeaturePresent(10))"
Write-Output "addtype.as: $(-not ('WinRunOracle.Missing' -as [Type])) $([bool]('WinRunOracle.OracleKernel32' -as [Type]))"
$here = @"
quote "one" and `$literal
second $noSse2
"@
Write-Output "here: $here"
$verbatim = @'
keep $this `n
'@
Write-Output "verbatim: $verbatim"
Write-Output "escapes: `"q`" [`$x] it`'s"
Write-Output ("char: " + [char]65)
$p = [IntPtr] 0xff
Write-Output "cast: $p $([int]'42')"
& cmd.exe /c exit 7
Write-Output "program.exit: $LASTEXITCODE"
$captured = "$(cmd.exe /c echo hi 2>&1)"
Write-Output "program.output: [$captured] $LASTEXITCODE"
& "$env:SystemRoot\System32\cmd.exe" /c "exit 0"
Write-Output "program.path: $LASTEXITCODE $(Test-Path "$env:SystemRoot\System32\curl.exe")"
Write-Warning 'not in output'
Write-Output 'END'
