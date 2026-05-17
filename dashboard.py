#!/usr/bin/env python3
"""
SSH Honeypot — Live TUI Dashboard
Reads from honeypot.db and refreshes every 2 seconds.
"""

import sqlite3
import time
import sys
import os
from datetime import datetime, timedelta
from collections import Counter

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.align import Align

DB_PATH = "honeypot.db"
REFRESH = 2   # seconds


def get_db():
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH)


def fetch_all(con):
    rows = con.execute(
        "SELECT ts, ip, port, username, password FROM attempts ORDER BY id DESC"
    ).fetchall()
    return rows


def stat_block(label: str, value: str, color: str = "cyan") -> Panel:
    content = Align.center(
        Text(value, style=f"bold {color}", justify="center"),
        vertical="middle",
    )
    return Panel(content, title=f"[dim]{label}[/dim]", border_style=color, height=5)


def build_dashboard(rows) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="stats",  size=7),
        Layout(name="body"),
        Layout(name="footer", size=1),
    )
    layout["body"].split_row(
        Layout(name="recent", ratio=3),
        Layout(name="top",    ratio=2),
    )

    # ── Header ────────────────────────────────────────────────────────────────
    ts = datetime.utcnow().strftime("%Y-%m-%d  %H:%M:%S UTC")
    layout["header"].update(
        Panel(
            Align.center(Text(f"🍯  SSH HONEYPOT MONITOR   [{ts}]", style="bold yellow")),
            border_style="yellow",
        )
    )

    # ── Stats ─────────────────────────────────────────────────────────────────
    total = len(rows)

    last_hour_cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat(timespec="seconds")
    last_hour = sum(1 for r in rows if r[0] >= last_hour_cutoff)

    unique_ips = len({r[1] for r in rows})

    top_user = Counter(r[3] for r in rows).most_common(1)
    top_user_str = top_user[0][0] if top_user else "—"

    top_pass = Counter(r[4] for r in rows).most_common(1)
    top_pass_str = top_pass[0][0] if top_pass else "—"

    layout["stats"].update(
        Columns(
            [
                stat_block("Total Attempts",  str(total),        "cyan"),
                stat_block("Last Hour",        str(last_hour),    "magenta"),
                stat_block("Unique IPs",       str(unique_ips),   "green"),
                stat_block("Top Username",     top_user_str,      "red"),
                stat_block("Top Password",     top_pass_str,      "bright_red"),
            ],
            equal=True,
            expand=True,
        )
    )

    # ── Recent Attempts ───────────────────────────────────────────────────────
    recent_table = Table(
        box=box.SIMPLE_HEAD,
        show_edge=False,
        header_style="bold cyan",
        border_style="dim",
        expand=True,
    )
    recent_table.add_column("Time (UTC)",  style="dim",          no_wrap=True)
    recent_table.add_column("IP Address",  style="cyan",         no_wrap=True)
    recent_table.add_column("Username",    style="yellow",       no_wrap=True)
    recent_table.add_column("Password",    style="bright_red",   no_wrap=True)

    for row in rows[:30]:
        ts_short = row[0][11:19]   # just HH:MM:SS
        recent_table.add_row(ts_short, row[1], row[3], row[4])

    layout["recent"].update(
        Panel(
            recent_table,
            title="[bold]Recent Attempts[/bold]",
            border_style="cyan",
        )
    )

    # ── Top IPs ───────────────────────────────────────────────────────────────
    ip_counts = Counter(r[1] for r in rows).most_common(15)
    top_table = Table(
        box=box.SIMPLE_HEAD,
        show_edge=False,
        header_style="bold green",
        border_style="dim",
        expand=True,
    )
    top_table.add_column("IP Address", style="green")
    top_table.add_column("Attempts",   style="bold white", justify="right")

    max_count = ip_counts[0][1] if ip_counts else 1
    for ip, count in ip_counts:
        bar_len = int((count / max_count) * 12)
        bar = "█" * bar_len
        top_table.add_row(ip, f"{bar} {count}")

    layout["top"].update(
        Panel(
            top_table,
            title="[bold]Top Attackers[/bold]",
            border_style="green",
        )
    )

    # ── Footer ────────────────────────────────────────────────────────────────
    layout["footer"].update(
        Align.center(Text("Ctrl+C to quit  •  refreshes every 2s", style="dim"))
    )

    return layout


def main():
    console = Console()

    with Live(console=console, refresh_per_second=1, screen=True) as live:
        while True:
            con = get_db()
            if con is None:
                live.update(
                    Panel(
                        Align.center(
                            Text(
                                f"Waiting for {DB_PATH} …\nStart honeypot.py first.",
                                style="yellow",
                                justify="center",
                            ),
                            vertical="middle",
                        ),
                        title="SSH Honeypot Monitor",
                        border_style="yellow",
                    )
                )
            else:
                try:
                    rows = fetch_all(con)
                    live.update(build_dashboard(rows))
                finally:
                    con.close()

            time.sleep(REFRESH)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
