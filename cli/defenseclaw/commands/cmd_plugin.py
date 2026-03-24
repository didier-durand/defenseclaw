"""defenseclaw plugin — Manage plugins (install, list, remove).

Stub implementation — plugin system is not yet fully implemented.
"""

from __future__ import annotations

import os
import shutil

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def plugin() -> None:
    """Manage DefenseClaw plugins — install, list, remove."""


@plugin.command()
@click.argument("name_or_path")
@pass_ctx
def install(app: AppContext, name_or_path: str) -> None:
    """Install a plugin from a path or registry."""
    plugin_dir = app.cfg.plugin_dir
    os.makedirs(plugin_dir, exist_ok=True)

    if os.path.isdir(name_or_path):
        name = os.path.basename(name_or_path.rstrip("/"))
        dest = os.path.join(plugin_dir, name)
        if os.path.exists(dest):
            click.echo(f"Plugin already installed: {name}")
            click.echo(f"  Remove first with: defenseclaw plugin remove {name}")
            return
        shutil.copytree(name_or_path, dest)
        click.echo(f"Installed plugin: {name}")
        if app.logger:
            app.logger.log_action("plugin-install", name, f"source={name_or_path}")
    else:
        click.echo(f"Plugin registry not yet implemented.")
        click.echo(f"  Install from a local path: defenseclaw plugin install /path/to/plugin")


@plugin.command("list")
@pass_ctx
def list_plugins(app: AppContext) -> None:
    """List installed plugins."""
    plugin_dir = app.cfg.plugin_dir
    if not os.path.isdir(plugin_dir):
        click.echo("No plugins installed.")
        return

    entries = [e for e in os.listdir(plugin_dir) if os.path.isdir(os.path.join(plugin_dir, e))]
    if not entries:
        click.echo("No plugins installed.")
        return

    click.echo("Installed plugins:")
    for name in sorted(entries):
        click.echo(f"  {name}")


@plugin.command()
@click.argument("name")
@pass_ctx
def remove(app: AppContext, name: str) -> None:
    """Remove an installed plugin."""
    plugin_dir = app.cfg.plugin_dir
    path = os.path.join(plugin_dir, name)

    if not os.path.isdir(path):
        click.echo(f"Plugin not found: {name}")
        return

    shutil.rmtree(path)
    click.echo(f"Removed plugin: {name}")
    if app.logger:
        app.logger.log_action("plugin-remove", name, "")
