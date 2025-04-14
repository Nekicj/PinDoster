#!/usr/bin/env python3

import asyncio
import sys
import logging
from typing import List, Optional

import click
from rich.console import Console

from src.packet_capture.capture_engine import CaptureEngine
from src.cli.interface import CLI

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)
console = Console()


@click.group()
@click.version_option()
def cli():
    pass


@cli.command()
@click.option('--interface', '-i', help='Network interface to capture packets from.')
@click.option('--filter', '-f', help='Filter expression for packet capture.')
@click.option('--count', '-c', type=int, default=0, help='Number of packets to capture (0 for unlimited).')
async def capture(interface: Optional[str], filter: Optional[str], count: int):
    console.print("[bold green]Starting packet capture...[/]")
    
    capture_engine = CaptureEngine(interface=interface)
    
    if filter:
        capture_engine.set_filter(filter)
    
    try:
        await capture_engine.start_capture(packet_count=count)
    except KeyboardInterrupt:
        console.print("[bold yellow]Capture stopped by user.[/]")
    except Exception as e:
        console.print(f"[bold red]Error during capture: {e}[/]")
    finally:
        await capture_engine.stop_capture()


@cli.command()
def interactive():
    console.print("[bold green]Starting interactive mode...[/]")
    
    cli_interface = CLI()
    
    try:
        cli_interface.start()
    except KeyboardInterrupt:
        console.print("[bold yellow]Interactive mode exited by user.[/]")
    except Exception as e:
        console.print(f"[bold red]Error in interactive mode: {e}[/]")


def main():
    try:
        cli()
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()

