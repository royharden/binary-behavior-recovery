"""Known authored SOFTWARE transport fixture, never a recovery candidate.

Used only by granted host regression tests for bounded pipe capture/owned-child
cleanup. It cannot select code/modules/commands and executes no supplied text.
"""

import sys
import time


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "echo":
        sys.stdout.buffer.write(sys.stdin.buffer.read(64))
    elif mode == "burst":
        sys.stdout.buffer.write(b"x" * 8192)
        sys.stdout.buffer.flush()
    elif mode == "sleep":
        time.sleep(2)
    else:
        raise SystemExit("unknown fixed software fixture mode")
