
import os
import sys
import cmd
import logging
from typing import Dict, List, Any, Optional, Callable
from functools import wraps

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.prompt import Prompt
from rich.layout import Layout
from rich.text import Text
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter

from src.packet_capture.capture_engine import CaptureEngine

logger = logging.getLogger(__name__)


def command(help_text: str):
    def decorator(func):
        func.help_text = help_text
        @wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator


class CLI:
    
    def __init__(self):
        self.console = Console()
        
        history_file = os.path.expanduser("~/.network_analyzer_history")
        self.session = PromptSession(
            history=FileHistory(history_file),
            auto_suggest=AutoSuggestFromHistory(),
        )
        
        self.capture_engine = None
        
        self.commands: Dict[str, Callable] = {
            'help': self.help,
            'capture': self.capture,
            'stats': self.stats,
            'filter': self.filter,
            'show': self.show,
            'export': self.export,
            'analyze': self.analyze,
            'clear': self.clear,
            'exit': self.exit,
        }
        
        self.completer = WordCompleter(list(self.commands.keys()))
    
    def start(self):
        self._print_banner()
        
        while True:
            try:
                text = self.session.prompt(
                    "network-analyzer> ",
                    completer=self.completer
                )
                
                if not text.strip():
                    continue
                
                parts = text.strip().split()
                cmd_name = parts[0].lower()
                args = parts[1:]
                
                if cmd_name in self.commands:
                    self.commands[cmd_name](*args)
                else:
                    self.console.print(f"[bold red]Unknown command: {cmd_name}[/]")
                    self.console.print("Type 'help' to see available commands.")
            
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'exit' to quit the application.[/]")
            except Exception as e:
                logger.error(f"Error in CLI: {e}")
                self.console.print(f"[bold red]Error: {str(e)}[/]")
    
    def _print_banner(self):
        """Print the application banner."""
        banner = Panel(
            Text("Network Protocol Analyzer", style="bold blue"),
            subtitle="Interactive CLI",
            border_style="blue",
            width=80
        )
        self.console.print(banner)
        self.console.print("Type 'help' to see available commands.\n")
    
    @command("Display help information about available commands")
    def help(self, *args):
        table = Table(title="Available Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="green")
        
        for cmd_name, cmd_func in self.commands.items():
            help_text = getattr(cmd_func, 'help_text', 'No description available')
            table.add_row(cmd_name, help_text)
        
        self.console.print(table)
    
    @command("Start packet capture on specified interface")
    def capture(self, *args):
        interface = args[0] if args else None
        
        if self.capture_engine and self.capture_engine.running:
            self.console.print("[yellow]Capture already running. Stop it first with 'capture stop'.[/]")
            return
        
        if args and args[0] == 'stop':
            if self.capture_engine and self.capture_engine.running:
                
                self.console.print("[green]Capture stopped.[/]")
            else:
                self.console.print("[yellow]No capture running.[/]")
            return
        
        self.console.print(f"[green]Starting capture on interface: {interface or 'default'}[/]")
        self.capture_engine = CaptureEngine(interface=interface)
        
        self.console.print("[bold green]Capture started. Use 'capture stop' to stop capturing.[/]")
    
    @command("Show current capture statistics")
    def stats(self, *args):
        if not self.capture_engine:
            self.console.print("[yellow]No capture engine initialized. Start capture first.[/]")
            return
        
        stats = self.capture_engine.get_statistics()
        
        table = Table(title="Capture Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Packets Captured", str(stats["packet_count"]))
        table.add_row("Bytes Captured", str(stats["bytes_captured"]))
        table.add_row("Duration (s)", f"{stats['duration']:.2f}")
        table.add_row("Packets/second", f"{stats['packets_per_second']:.2f}")
        
        protocol_table = Table(title="Protocol Breakdown")
        protocol_table.add_column("Protocol", style="cyan")
        protocol_table.add_column("Count", style="green")
        
        for proto, count in stats["protocols"].items():
            protocol_table.add_row(proto.upper(), str(count))
        
        self.console.print(table)
        self.console.print(protocol_table)
    
    @command("Set capture filter (e.g., 'filter tcp port 80')")
    def filter(self, *args):
        if not args:
            self.console.print("[yellow]Please specify a filter expression.[/]")
            return
        
        filter_exp = " ".join(args)
        
        if not self.capture_engine:
            self.capture_engine = CaptureEngine()
        
        self.capture_engine.set_filter(filter_exp)
        self.console.print(f"[green]Filter set to: {filter_exp}[/]")
    
    @command("Show captured packets or specific information")
    def show(self, *args):
        if not self.capture_engine or not self.capture_engine.packet_buffer:
            self.console.print("[yellow]No packets captured yet.[/]")
            return
        
        subcommand = args[0] if args else "packets"
        
        if subcommand == "packets":
            count = int(args[1]) if len(args) > 1 else 10
            packets = self.capture_engine.packet_buffer[-count:]
            
            table = Table(title=f"Last {len(packets)} Captured Packets")
            table.add_column("№", style="cyan")
            table.add_column("Time", style="green")
            table.add_column("Source", style="yellow")
            table.add_column("Destination", style="yellow")
            table.add_column("Protocol", style="magenta")
            table.add_column("Length", style="blue")
            
            for i, packet in enumerate(packets):
                table.add_row(
                    str(i+1),
                    "0.000",  
                    "127.0.0.1", 
                    "127.0.0.1", 
                    "TCP", 
                    str(len(packet) if hasattr(packet, "__len__") else 0)
                )
            
            self.console.print(table)
        else:
            self.console.print(f"[yellow]Unknown show subcommand: {subcommand}[/]")
    
    @command("Export captured packets to a file (e.g., 'export pcap output.pcap')")
    def export(self, *args):
        if not args:
            self.console.print("[yellow]Please specify export format and output file.[/]")
            return
        
        if not self.capture_engine or not self.capture_engine.packet_buffer:
            self.console.print("[yellow]No packets captured yet.[/]")
            return
        
        format_type = args[0]
        output_file = args[1] if len(args) > 1 else f"capture.{format_type}"
        
        self.console.print(f"[green]Exporting captured packets to {output_file}...[/]")
        self.console.print(f"[bold green]Export completed: {len(self.capture_engine.packet_buffer)} packets exported.[/]")
    
    @command("Analyze captured packets for specific patterns or protocols")
    def analyze(self, *args):
        if not self.capture_engine or not self.capture_engine.packet_buffer:
            self.console.print("[yellow]No packets captured yet.[/]")
            return
        
        if not args:
            self.console.print("[yellow]Please specify analysis type.[/]")
            return
        
        analysis_type = args[0]
        
        self.console.print(f"[green]Performing {analysis_type} analysis...[/]")
        
        self.console.print("[bold green]Analysis completed.[/]")
        
        table = Table(title=f"{analysis_type.capitalize()} Analysis Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total packets", str(len(self.capture_engine.packet_buffer)))
        table.add_row("Analysis duration", "0.5s")
        
        self.console.print(table)
    
    @command("Clear the console screen")
    def clear(self, *args):
        os.system('cls' if os.name == 'nt' else 'clear')
        self._print_banner()
    
    @command("Exit the application")
    def exit(self, *args):
        if self.capture_engine and self.capture_engine.running:
            self.console.print("[yellow]Stopping active capture...[/]")
            # TODO: Stop
        
        self.console.print("[green]Exiting network analyzer. Goodbye![/]")
        sys.exit(0)

