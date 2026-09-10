#!/usr/bin/env python3
"""Entrypoint: start the reap worker and (optionally) the Flask WebUI.

  python run.py            # worker + WebUI (per config)
  python run.py --no-web   # worker only (headless daemon)
"""

import sys

from protectarr import config as cfg_mod
from protectarr.core import ProtectarrService
from protectarr.web import create_app


def main():
    no_web = "--no-web" in sys.argv
    cfg = cfg_mod.load()

    service = ProtectarrService()
    service.start()

    if no_web or not cfg["web"].get("enabled", True):
        print("[Protectarr] worker running (no WebUI). Ctrl-C to stop.", flush=True)
        try:
            service._thread.join()
        except KeyboardInterrupt:
            service.stop()
        return

    app = create_app(service)
    web = cfg["web"]
    print(f"[Protectarr] WebUI on http://{web['host']}:{web['port']}", flush=True)
    app.run(host=web["host"], port=int(web["port"]), threaded=True)


if __name__ == "__main__":
    main()
