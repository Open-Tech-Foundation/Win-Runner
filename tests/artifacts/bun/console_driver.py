"""Exercise Windows Bun console detection across the native worker boundary."""
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

with tempfile.TemporaryDirectory(prefix="winrun-bun-console-") as directory:
    source = os.path.join(directory, "console.js")
    with open(source, "w", encoding="utf-8") as stream:
        stream.write("""const cp = require('child_process');
if (!process.stdin.isTTY || !process.stdout.isTTY || !process.stderr.isTTY) throw Error('console identity lost across worker');
const output = cp.execFileSync(process.execPath, ['-e', 'process.stdout.write(process.stdout.isTTY ? "console" : "pipe")'], {encoding:'utf8'});
if (output !== 'pipe') throw Error('redirected child misclassified: '+output);
console.log('native console identity verified');
""")
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
    child = subprocess.Popen([sys.argv[1], 'shell'], stdin=slave, stdout=slave,
                             stderr=slave, start_new_session=True)
    os.close(slave)
    output = bytearray()
    try:
        deadline = time.monotonic() + 45
        prompt = b'PS C:\\Users\\runner> '
        def read_until(needle, start):
            while time.monotonic() < deadline:
                if needle in output[start:]:
                    return
                if select.select([master], [], [], .1)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
                if child.poll() is not None:
                    break
            raise AssertionError(output.decode(errors='replace'))
        read_until(prompt, 0)
        commands = ['New-Item C:\\probe -ItemType Directory',
                    f'@seed "{os.path.abspath(sys.argv[2])}" C:\\probe\\bun.exe',
                    f'@seed "{source}" C:\\probe\\console.js',
                    '$env:BUN_BE_BUN = "1"']
        for command in commands:
            start = len(output)
            os.write(master, (command + '\r').encode())
            read_until(prompt, start)
        start = len(output)
        os.write(master, b'C:\\probe\\bun.exe C:\\probe\\console.js\r')
        read_until(b'native console identity verified', start)
        read_until(prompt, start)
        os.write(master, b'exit\r')
        assert b'unsupported native import called' not in output, output.decode(errors='replace')
        assert child.wait(timeout=5) == 0, output.decode(errors='replace')
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        os.close(master)
print('native console identity verified')
