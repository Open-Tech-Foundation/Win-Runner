# Identical script runs in real PowerShell on Windows and the guest shell.
# Covers cmd.exe's file built-ins (dir, ren, move, path) and the System32
# text tools (find.exe, sort.exe, more.com). Files are written by cmd's own
# echo so their bytes match on both sides; dates, free space, and the run
# directory's path never reach the output.
# A fresh directory: the guest run directory also holds this script.
New-Item work -ItemType Directory | Out-Null
Set-Location work
cmd /c 'mkdir sub & echo pear> fruit.txt & echo Apple>> fruit.txt & echo banana>> fruit.txt & echo x> sub\note.log'

"dir.bare:"
cmd /c 'dir /b'
"dir.dirs:"
cmd /c 'dir /b /a:d'
"dir.files_reverse:"
cmd /c 'dir /b /a:-d /o:-n'
"dir.sub:"
cmd /c 'dir /b sub'
"dir.summary:"
cmd /c 'dir | find "File(s)"'
cmd /c 'dir | find /c "<DIR>"'
"dir.recursive_summary:"
cmd /c 'dir /s | find "File(s)"'
cmd /c 'dir /b nothing.xyz'
"dir.missing: $LASTEXITCODE"

"ren:"
cmd /c 'ren fruit.txt fruits.txt & dir /b *.txt'
cmd /c 'copy fruits.txt notes.txt >nul & ren notes.txt new_* & dir /b new*'
cmd /c 'ren *.txt *.bak & dir /b *.bak'
cmd /c 'ren nothing.txt other.txt'
"ren.missing: $LASTEXITCODE"

"move:"
cmd /c 'move sub moved'
cmd /c 'move fruits.bak moved'
cmd /c 'dir /b moved'

"path:"
cmd /c 'set PATH=C:\one;C:\two& path'
cmd /c 'path ; & path'

"find:"
cmd /c 'find "an" moved\fruits.bak'
cmd /c 'find /c /i "a" moved\fruits.bak'
cmd /c 'find /n /v "pear" moved\fruits.bak'
cmd /c 'type moved\fruits.bak | find "Apple"'
cmd /c 'find "zz" moved\fruits.bak'
"find.none: $LASTEXITCODE"
cmd /c 'find "an" missing.txt'
"find.missing: $LASTEXITCODE"

"sort:"
cmd /c 'type moved\fruits.bak | sort'
cmd /c 'sort /r moved\fruits.bak'
cmd /c 'sort /+2 moved\fruits.bak'

"more:"
cmd /c 'type moved\fruits.bak | more'
"more.file:"
cmd /c 'more moved\fruits.bak'
