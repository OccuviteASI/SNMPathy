"""PyInstaller entry point for SNMPathy Collector (the small app for site computers)."""

import multiprocessing

from snmpathy.collector_app import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
