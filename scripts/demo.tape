# Win-Runner demo: Linux shell in, Windows tooling out.
#
# Render from the repository root (target/release/winrun must be built):
#
#   cargo build --release
#   vhs scripts/demo.tape
#
# Setup runs hidden: the download cache is wiped and pre-warmed with
# python only (so python installs instantly from cache while nodejs
# stays cold), then scripts/demo-throttle-server.py starts as a loopback
# package mirror. Its nodejs archive is streamed at a fixed rate, and a
# hidden `wpkg refresh` points the guest registry at it, so the recorded
# download bar always has the same bounded duration. Hidden commands are
# never part of the recording.
#
# Requires the nodejs archive in the host wpkg cache
# ($XDG_CACHE_HOME/winrun/wpkg), and a snapshot with dotnet, micro and
# uv installed but no nodejs/python archives in its guest cache
# (C:\ProgramData\wpkg\cache).

Output assets/demo.gif
Output assets/demo.mp4

Set Shell bash
Set Width 1280
Set Height 720
Set FontSize 26
Set Theme "tokyonight-storm"
Set Padding 10
Set Margin 12
Set MarginFill "#24283b"
Set BorderRadius 12
Set WindowBar "Colorful"
Set TypingSpeed 40ms
Set PlaybackSpeed 1.5

Hide
Type "export PATH=$PWD/target/release:$PATH WINRUN_CACHE_DIR=/tmp/winrun-demo-cache WINRUN_WPKG_REGISTRY=http://127.0.0.1:8734/registry.zip" Enter
Type "rm -rf /tmp/winrun-demo-cache" Enter
Type "mkdir -p /tmp/winrun-demo-cache/wpkg && cp $XDG_CACHE_HOME/winrun/wpkg/46a4da5529a92d18ff894911f6e6033a8253198d705b8161bf28c9123c87d46b /tmp/winrun-demo-cache/wpkg/" Enter
Type "test -f /tmp/winrun-demo-cache/wpkg/46a4da5529a92d18ff894911f6e6033a8253198d705b8161bf28c9123c87d46b || (echo 'wpkg install python'; echo exit) | ./target/release/winrun --snapshot=scripts/demo-fs/demo.winfs runner >/dev/null 2>&1" Enter
Type "pkill -f 'demo-throttle-serve[r]' || true" Enter
Type "python3 scripts/demo-throttle-server.py >/tmp/winrun-demo-server.log 2>&1 &" Enter
Sleep 1500ms
Type "cd scripts/demo-fs" Enter
Type "clear" Enter
Sleep 400ms
Show

Type "winrun --snapshot=demo.winfs --mount=Z:. shell"
Enter
Sleep 900ms

Hide
Type "wpkg refresh"
Enter
Sleep 1500ms
Type "cls"
Enter
Sleep 300ms
Show

Type "uname -a"
Enter
Sleep 900ms

Type "cls"
Enter
Sleep 450ms

Type "wpkg install nodejs"
Enter
Sleep 10000ms

Type "node"
Enter
Sleep 2200ms

Type "process.platform"
Enter
Sleep 800ms

Type ".exit"
Enter
Sleep 900ms

Type "cls"
Enter
Sleep 450ms

Type "wpkg install python"
Enter
Sleep 1600ms

Type "python -c 'import platform; print(platform.platform())'"
Enter
Sleep 2300ms

Type "uv run python Z:/hello.py"
Enter
Sleep 4400ms

Type "dotnet --list-runtimes"
Enter
Sleep 1500ms

Type "cls"
Enter
Sleep 450ms

Type "micro C:\Users\runner\hello.ps1"
Enter
Sleep 1200ms

Type "param([string]$name = 'world')"
Enter
Sleep 400ms

Type "Write-Host ('hello, ' + $name + ' from Windows PowerShell')"
Enter
Sleep 500ms

Ctrl+S
Sleep 550ms

Ctrl+Q
Sleep 1000ms

Type "cls"
Enter
Sleep 450ms

Type ".\hello.ps1 -name demo"
Enter
Sleep 1500ms

Sleep 1500ms

Hide
Type "exit"
Enter
Sleep 700ms
Type "pkill -f 'demo-throttle-serve[r]' || true" Enter
Sleep 300ms
