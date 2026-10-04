#!/usr/bin/env bash
# Build the fixture for tests/dotnet_native.rs: Microsoft's official win-x64
# .NET runtime plus a framework-dependent hello app published for win-x64.
#
#   scripts/fetch-dotnet-fixture.sh [DIR]   (default: target/dotnet-fixture)
#   WINRUN_DOTNET_FIXTURE=DIR cargo test --test dotnet_native -- --ignored
#
# DIR/dotnet is the runtime (installed to C:\Program Files\dotnet by the
# test) and DIR/hello the app. A Linux .NET SDK is installed into DIR/sdk
# only to publish the app.
set -euo pipefail
channel=10.0
dir=$(realpath -m "${1:-target/dotnet-fixture}")
mkdir -p "$dir"
cd "$dir"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_ROOT="$dir/sdk"

if [ ! -x sdk/dotnet ]; then
  curl -sSfL https://dot.net/v1/dotnet-install.sh -o dotnet-install.sh
  bash dotnet-install.sh --channel "$channel" --install-dir "$dir/sdk" --no-path >/dev/null
fi
version=$(ls sdk/shared/Microsoft.NETCore.App/ | sort -V | tail -1)

if [ ! -f hello/hello.dll ]; then
  rm -rf hello-src hello
  sdk/dotnet new console -n hello -o hello-src --framework "net$channel" >/dev/null
  cat > hello-src/Program.cs <<'EOF'
System.Console.WriteLine("Hello from .NET " + System.Environment.Version);
System.Console.WriteLine("args: " + string.Join(",", args));
return args.Length;
EOF
  sdk/dotnet publish hello-src -p:AssemblyName=hello -c Release -r win-x64 --self-contained false -o hello >/dev/null
fi

if [ ! -d dotnet ]; then
  curl -sSfL -o runtime.zip \
    "https://builds.dotnet.microsoft.com/dotnet/Runtime/$version/dotnet-runtime-$version-win-x64.zip"
  mkdir dotnet
  (cd dotnet && unzip -q ../runtime.zip)
  rm runtime.zip
fi
echo "WINRUN_DOTNET_FIXTURE=$dir  (runtime $version)"
