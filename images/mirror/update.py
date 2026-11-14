"""Keeps a private ClamAV database mirror up to date.

Runs cvdupdate (https://github.com/Cisco-Talos/cvdupdate, by Cisco Talos)
once per hour. Its configuration and state (the database versions, the
cool-down after an HTTP 429 and the UUID in its User-Agent) live on the
mirror volume next to the databases, so that they survive a restart; the
HTTP server (meles mirror) serves only the database directory.
"""

import os
import signal
import subprocess
import sys
import time

DB_DIR = os.environ.get("MIRROR_DB_DIR", "/mirror/db")
CONFIG = os.environ.get("MIRROR_CVD_CONFIG", "/mirror/.cvdupdate/config.json")
LOG_DIR = os.environ.get("MIRROR_LOG_DIR", "/tmp/cvd-logs")
INTERVAL = int(os.environ.get("MIRROR_INTERVAL", "3600"))


def cvd(*args):
    return subprocess.run([sys.executable, "-m", "cvdupdate", *args], check=False).returncode


def main():
    # PID 1 gets no default handler for SIGTERM.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    if INTERVAL < 3600:
        # Cisco Talos rate-limits downloads; cvdupdate checks DNS first,
        # but more often than hourly is never needed.
        sys.exit("MIRROR_INTERVAL must be at least 3600 seconds")
    os.makedirs(os.path.dirname(CONFIG), exist_ok=True)
    if cvd("config", "set", "--config", CONFIG, "--dbdir", DB_DIR, "--logdir", LOG_DIR) != 0:
        sys.exit("cvd config set failed")
    while True:
        if cvd("update", "--config", CONFIG) != 0:
            print("cvd update failed, retrying in an hour", file=sys.stderr, flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
