"""Entry point for python -m pyzephyrconnect - runs the probe CLI."""

import sys

from .probe import run

sys.exit(run())
