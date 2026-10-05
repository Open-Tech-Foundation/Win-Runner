"""Check unchanged Windows OpenCode startup, keyboard input and shutdown in a PTY."""
import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time

master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 120, 0, 0))
child = subprocess.Popen([sys.argv[1], 'shell'], stdin=slave, stdout=slave,
                         stderr=slave, start_new_session=True)
os.close(slave)
output = bytearray()
prompt = b'PS C:\\Users\\runner> '
deadline = time.monotonic() + 75

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
    raise AssertionError(output.decode(errors='replace')[-12000:])

try:
    read_until(prompt, 0)
    for command in ['New-Item C:\\probe -ItemType Directory',
                    f'@seed "{os.path.abspath(sys.argv[2])}" C:\\probe\\opencode.exe']:
        start = len(output)
        os.write(master, (command + '\r').encode())
        read_until(prompt, start)
    start = len(output)
    mode = ' --standalone' if sys.argv[3] == 'standalone' else ''
    os.write(master, ('C:\\probe\\opencode.exe' + mode + ' .\r').encode())
    read_until(b'Ask anything', start)
    assert b'\x1b[?2026h' in output[start:], 'No rendered frame'
    start = len(output)
    os.write(master, b'winrun-keyboard-check')
    read_until(b'winrun-keyboard-check', start)
    start = len(output)
    # First Ctrl+C clears the composer; the second requests exit.
    os.write(master, b'\x03')
    time.sleep(.3)
    os.write(master, b'\x03')
    read_until(prompt, start)
    assert b'unsupported native import called' not in output, output.decode(errors='replace')[-12000:]
    assert b'Win-Runner native error' not in output, output.decode(errors='replace')[-12000:]
    os.write(master, b'exit\r')
    assert child.wait(timeout=5) == 0
finally:
    # This shell and its workers have their own process group.
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if child.poll() is None:
        child.wait(timeout=5)
    os.close(master)
print('OpenCode first frame, keyboard input and shutdown verified (' + sys.argv[3] + ')')
