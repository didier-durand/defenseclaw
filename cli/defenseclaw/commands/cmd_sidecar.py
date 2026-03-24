"""defenseclaw sidecar — Run DefenseClaw as a sidecar process.

The sidecar daemon runs in Go. This command provides status checking
and guidance for starting the Go daemon.

Mirrors internal/cli/sidecar.go (status subcommand only).
"""

from __future__ import annotations

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group(invoke_without_command=True)
@click.pass_context
def sidecar(ctx: click.Context) -> None:
    """Run DefenseClaw as a sidecar process.

    The sidecar is a long-running Go daemon that connects to the OpenClaw
    gateway via WebSocket and enforces policy in real time.

    Use 'defenseclaw sidecar status' to check if it's running.
    """
    if ctx.invoked_subcommand is None:
        app: AppContext = ctx.find_object(AppContext)
        cfg = app.cfg

        click.echo("╔══════════════════════════════════════════════╗")
        click.echo("║       DefenseClaw Gateway Sidecar            ║")
        click.echo("╚══════════════════════════════════════════════╝")
        click.echo()
        click.echo("  The sidecar daemon runs as a Go binary.")
        click.echo("  Start it with: defenseclaw-go sidecar")
        click.echo()

        if cfg:
            click.echo(f"  Gateway:      {cfg.gateway.host}:{cfg.gateway.port}")
            click.echo(f"  Auto-approve: {cfg.gateway.auto_approve_safe}")
            token = cfg.gateway.token
            if not token:
                click.echo("  Auth:         none (will use device identity only)")
            elif len(token) > 8:
                click.echo(f"  Auth:         {token[:4]}...{token[-4:]}")
            else:
                click.echo("  Auth:         ***")
            click.echo(f"  API port:     {cfg.gateway.api_port}")
            click.echo(f"  Watcher:      {cfg.gateway.watcher.enabled}")
        click.echo()
        click.echo("  Use 'defenseclaw sidecar status' to check health.")


@sidecar.command()
@pass_ctx
def status(app: AppContext) -> None:
    """Show health of the running sidecar's subsystems."""
    from defenseclaw.gateway import OrchestratorClient

    port = app.cfg.gateway.api_port if app.cfg else 18790
    client = OrchestratorClient(port=port)

    if not client.is_running():
        click.echo("Sidecar Status: NOT RUNNING")
        click.echo(f"  Could not reach http://127.0.0.1:{port}/health")
        click.echo("  Start the sidecar with: defenseclaw-go sidecar")
        return

    try:
        snap = client.health()
    except Exception as exc:
        click.echo(f"Sidecar Status: ERROR — {exc}")
        return

    started_at = snap.get("started_at", "unknown")
    uptime_ms = snap.get("uptime_ms", 0)

    click.echo("DefenseClaw Sidecar Health")
    click.echo("══════════════════════════")
    click.echo(f"  Started:  {started_at}")
    click.echo(f"  Uptime:   {_format_duration(uptime_ms)}")
    click.echo()

    for name in ("gateway", "watcher", "api"):
        sub = snap.get(name, {})
        state = sub.get("state", "unknown").upper()
        since = sub.get("since", "")
        click.echo(f"  {name + ':':<12s} {state}", nl=False)
        if since:
            click.echo(f" (since {since})", nl=False)
        click.echo()
        last_err = sub.get("last_error", "")
        if last_err:
            click.echo(f"               last error: {last_err}")
        details = sub.get("details", {})
        for k, v in details.items():
            click.echo(f"               {k}: {v}")
        click.echo()


def _format_duration(ms: int) -> str:
    secs = ms // 1000
    hours = secs // 3600
    mins = (secs % 3600) // 60
    s = secs % 60
    if hours > 0:
        return f"{hours}h {mins}m {s}s"
    if mins > 0:
        return f"{mins}m {s}s"
    return f"{s}s"
