"""defenseclaw alerts — View and manage security alerts.

Mirrors internal/cli/alerts.go.
"""

from __future__ import annotations

import click

from defenseclaw.context import AppContext, pass_ctx


@click.command()
@click.option("-n", "--limit", default=25, help="Number of alerts to show")
@pass_ctx
def alerts(app: AppContext, limit: int) -> None:
    """View security alerts.

    Displays recent security alerts (events with CRITICAL, HIGH,
    MEDIUM, or LOW severity).
    """
    if not app.store:
        click.echo("No audit store available. Run 'defenseclaw init' first.")
        return

    alert_list = app.store.list_alerts(limit)

    if not alert_list:
        click.echo("No alerts. All clear.")
        return

    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title=f"Security Alerts (last {limit})")
    table.add_column("Severity", style="bold")
    table.add_column("Timestamp")
    table.add_column("Action")
    table.add_column("Target")
    table.add_column("Details")

    for e in alert_list:
        sev_style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
        }.get(e.severity, "")

        details = e.details
        if len(details) > 55:
            details = details[:52] + "..."

        table.add_row(
            f"[{sev_style}]{e.severity}[/{sev_style}]" if sev_style else e.severity,
            e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            e.action,
            e.target,
            details,
        )

    console.print(table)
