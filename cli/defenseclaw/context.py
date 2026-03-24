"""Shared Click context types used by command modules."""

from __future__ import annotations

import click


class AppContext:
    """Shared application context passed through Click."""

    def __init__(self) -> None:
        self.cfg = None
        self.store = None
        self.logger = None


pass_ctx = click.make_pass_decorator(AppContext, ensure=True)
