import getpass
import socket
import logging

from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True, highlight=False)


logger = logging.getLogger("burpai")


def init_logger(debug: bool = False):
    """Initialize logger with rich handler."""
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False
    handler = RichHandler(
        console=console,
        show_time=False,
        show_path=debug,
        show_level=True,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=debug,
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)


def display_sessid(session_id: str, length: int = 8) -> str:
    """Abbreviate and colorize session ID."""
    abbrev = session_id[:length]

    hash_val = hash(session_id)
    r = 100 + (abs(hash_val) % 156)
    g = 100 + (abs(hash_val >> 8) % 156)
    b = 100 + (abs(hash_val >> 16) % 156)

    return f"[bold rgb({r},{g},{b})]{abbrev}[/bold rgb({r},{g},{b})]"


def ask(prompt: str, is_secret=False, validator=None):
    """Ask user for input until validator returns True."""
    console.print(f"[magenta]INPUT   [/magenta] {prompt}", end=" ")
    while True:
        value = getpass.getpass("") if is_secret else input()

        if validator and not validator(value):
            console.print(f"[magenta]INPUT   [/magenta] {prompt}", end=" ")
            continue

        return value


def ask_yn(prompt: str) -> bool:
    """Ask user a yes/no question."""

    def validate_yn(response):
        if response.lower() in ("y", "n"):
            return True
        logger.error("Please enter 'y' or 'n'")
        return False

    response = ask(prompt, validator=validate_yn)
    return response.lower() == "y"


def is_port_available(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            return True
    except OSError:
        logger.error("Socket [cyan]%s:%s[/cyan] is already in use", host, port)
        return False
