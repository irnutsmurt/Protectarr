#!/usr/bin/env python3
"""Entrypoint: start the reap worker and (optionally) the Flask WebUI.

  python run.py            # worker + WebUI (per config)
  python run.py --no-web   # worker only (headless daemon)
"""

import sys

from protectarr import config as cfg_mod
from protectarr import logs
from protectarr.core import ProtectarrService
from protectarr.web import create_app


def main():
    no_web = "--no-web" in sys.argv
    cfg = cfg_mod.load()
    # Before anything else, so startup problems land in the log too.
    logs.configure(cfg)
    log = logs.get()
    import time as _t
    log.info("Protectarr starting: config=%s dry_run=%s log_level=%s timezone=%s",
             cfg_mod.CONFIG_PATH, cfg.get("dry_run"),
             cfg.get("logging", {}).get("level", "info"),
             _t.strftime("%Z %z"))

    service = ProtectarrService()
    service.start()

    if no_web or not cfg["web"].get("enabled", True):
        log.info("Worker running (no WebUI). Ctrl-C to stop.")
        try:
            service._thread.join()
        except KeyboardInterrupt:
            log.info("Interrupted, stopping.")
            service.stop()
        return

    app = create_app(service)
    web = cfg["web"]
    log.info("WebUI on http://%s:%s", web["host"], web["port"])
    app.run(host=web["host"], port=int(web["port"]), threaded=True)


if __name__ == "__main__":
    main()
