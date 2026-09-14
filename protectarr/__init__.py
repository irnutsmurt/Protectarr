"""Protectarr: remove torrents containing executables before they finish."""
# The single source of truth for the version. Every surface that shows one -
# the sidebar, the System page, /ping, /api/v1, /api/v1/system/status - reads
# it from here, and tests/test_version.py fails if any of them stops doing so.
#
# Bump this and tag the commit for every release that changes shipped
# behaviour. `latest` is a convenience, not an identifier: v0.1.0 shipped for
# months across substantial changes, so a bug report naming it said nothing
# about which build the reporter was actually running.
__version__ = "0.3.1"
