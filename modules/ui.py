from rich.console import Console
from rich.table import Table
from rich.live import Live
import time
import random
import datetime


def generate_log_table():
    table = Table(title="Praetorian Dashboard")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Level", style="magenta")
    table.add_column("Message", style="green")

    # Dummy events for demonstration.
    # Replace with actual log data or events from your detection modules.
    levels = ["INFO", "WARNING", "ERROR"]
    messages = [
        "System initialized.",
        "SYN packet detected from 192.168.1.105.",
        "Suspicious OS fingerprinting attempt from 10.0.0.5.",
        "Firewall rule updated.",
        "Potential scan detected from 172.16.0.3."
    ]

    # Create 5 random entries
    for _ in range(5):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level = random.choice(levels)
        message = random.choice(messages)
        table.add_row(timestamp, level, message)
    return table


def main():
    console = Console()
    with Live(generate_log_table(), refresh_per_second=1, console=console) as live:
        while True:
            # In a real implementation, update events from your logging module or an event queue.
            live.update(generate_log_table())
            time.sleep(1)


if __name__ == "__main__":
    main()
