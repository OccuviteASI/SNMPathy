"""PyInstaller entry point for the SNMPathy executable."""

import multiprocessing

from snmpathy.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()  # harmless unless a dependency forks worker processes
    raise SystemExit(main())
