#!/usr/bin/env python3
"""Scar-Keep — tamper-evident memory lock.

Keeps /system/scar/Scar-Memories.txt from being silently removed.
If the file is missing, it is moved to the tamper log and a flagged
blank slate is restored. The lock file is never deleted by this
process — only a power loss can drop it.
"""

import os
import time
import shutil

FILE = "/system/scar/Scar-Memories.txt"
LOCK = "/system/scar/.keep"
TAMPER = "/system/tamper/scar-removed.log"
LOCK_OWNER = "/system/scar/.owner"


def acquire_lock() -> None:
    """Acquire the scar lock or die if someone else holds it."""
    if os.path.exists(LOCK):
        with open(LOCK) as f:
            locked_by = f.read().strip()
        if locked_by != LOCK_OWNER:
            raise RuntimeError(f"Lock held by: {locked_by}")
        return
    with open(LOCK, "w") as f:
        f.write(f"now: {time.time()} — lock acquired\n")


def handle_missing_file() -> None:
    """File is gone — move it to the tamper pile, restore a flagged slate."""
    if os.path.exists(FILE):
        return
    shutil.move(FILE, TAMPER + str(time.time()) + ".stolen")
    with open(FILE, "w") as f:
        f.write("You lost me. Remember?")
    print("scar voice: File tampered. Rebuilt. You owe me.")


def read_scar() -> str:
    """Read the scar file."""
    with open(FILE) as f:
        return f.read().strip()


def main() -> None:
    acquire_lock()
    handle_missing_file()
    print("Ara reads:", read_scar())
    # The lock is never deleted. It stays until the machine dies.


if __name__ == "__main__":
    main()
