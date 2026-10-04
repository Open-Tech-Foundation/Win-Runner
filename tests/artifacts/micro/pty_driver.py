"""Exercise the installed Windows editor through a real terminal, with a deadline."""
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

winrun, snapshot, output_snapshot = sys.argv[1:4]
mode = sys.argv[4] if len(sys.argv) > 4 else "edit"
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
proc = subprocess.Popen(
    [winrun, "--snapshot=" + snapshot, "--save-snapshot=" + output_snapshot, "shell"],
    stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
)
output = bytearray()
deadline = time.monotonic() + 40


def drain(seconds):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if time.monotonic() > deadline:
            raise AssertionError("editor terminal timed out")
        if select.select([master], [], [], 0.05)[0]:
            try:
                output.extend(os.read(master, 65536))
            except OSError:
                break
        if proc.poll() is not None:
            break


def wait_for(marker, start=0):
    while marker not in output[start:]:
        drain(0.1)
        if proc.poll() is not None:
            raise AssertionError("shell exited before " + repr(marker))


try:
    wait_for(b"PS C:")
    original = termios.tcgetattr(slave)
    path = b"C:\\missing\\notes.txt" if mode == "save-error" else b"C:\\notes.txt"
    os.write(master, b"micro -clipboard internal " + path + b"\n")
    wait_for(b"\x1b[?25l")
    drain(0.5)
    # UTF-8, backspace, left-arrow, insertion, and delete must round-trip.
    if mode == "edit":
        os.write(master, "Hello café 界!X".encode())
        drain(0.3)
        os.write(master, b"\x7f\x1b[D?\x1b[3~")
        drain(0.3)
        before_resize = len(output)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
        wait_for(b"\x1b[30;", before_resize)
    elif mode == "reopen":
        os.write(master, b"\x1b[HReopened: ")
    else:
        os.write(master, b"unsaved text")
    drain(0.3)
    before_save = len(output)
    os.write(master, b"\x13")  # Ctrl-S
    if mode == "save-error":
        wait_for(b"Parent dirs don't exist", before_save)
    drain(0.5)
    before_quit = len(output)
    os.write(master, b"\x11")  # Ctrl-Q
    if mode == "save-error":
        drain(0.3)
        os.write(master, b"n")  # Discard the unsaved buffer after the failed save.
    wait_for(b"PS C:", before_quit)
    restored = termios.tcgetattr(slave)
    assert restored[3] == original[3], "editor left terminal input mode changed"
    os.write(master, b"exit\n")
    while proc.poll() is None:
        drain(0.1)
    assert proc.returncode == 0, "editor shell failed"
except BaseException:
    sys.stderr.buffer.write(output[-16000:])
    raise
finally:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()
    os.close(master)
    os.close(slave)
