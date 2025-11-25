"""
Terminal color utilities for ZKP output.

Uses ANSI escape codes for cross-platform color support.
"""

import sys

# Check if terminal supports colors
COLORS_ENABLED = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


class Colors:
    """ANSI color codes."""
    # Reset
    RESET = '\033[0m'

    # Regular colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bold/Bright colors
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'

    # Bold colors
    BOLD_RED = '\033[1;31m'
    BOLD_GREEN = '\033[1;32m'
    BOLD_YELLOW = '\033[1;33m'
    BOLD_BLUE = '\033[1;34m'
    BOLD_MAGENTA = '\033[1;35m'
    BOLD_CYAN = '\033[1;36m'
    BOLD_WHITE = '\033[1;37m'

    # Background colors
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'


def colorize(text: str, color: str) -> str:
    """Apply color to text if colors are enabled."""
    if not COLORS_ENABLED:
        return text
    return f"{color}{text}{Colors.RESET}"


# Convenience functions
def success(text: str) -> str:
    """Green text for success messages."""
    return colorize(text, Colors.BOLD_GREEN)


def error(text: str) -> str:
    """Red text for errors."""
    return colorize(text, Colors.BOLD_RED)


def warning(text: str) -> str:
    """Yellow text for warnings."""
    return colorize(text, Colors.BOLD_YELLOW)


def info(text: str) -> str:
    """Cyan text for info."""
    return colorize(text, Colors.BOLD_CYAN)


def highlight(text: str) -> str:
    """Magenta text for highlights."""
    return colorize(text, Colors.BOLD_MAGENTA)


def bold(text: str) -> str:
    """Bold white text."""
    return colorize(text, Colors.BOLD_WHITE)


def dim(text: str) -> str:
    """Dimmed text."""
    return colorize(text, Colors.DIM)


def header(text: str, width: int = 70) -> str:
    """Create a colored header."""
    line = "=" * width
    return f"{Colors.BOLD_CYAN}{line}\n{text.center(width)}\n{line}{Colors.RESET}"


def box(title: str, content: list, width: int = 70) -> str:
    """Create a colored box with title and content."""
    lines = [
        colorize("=" * width, Colors.CYAN),
        colorize(title.center(width), Colors.BOLD_WHITE),
        colorize("=" * width, Colors.CYAN),
    ]
    for line in content:
        lines.append(line)
    lines.append(colorize("=" * width, Colors.CYAN))
    return "\n".join(lines)


# Status indicators
PASS = f"{Colors.BOLD_GREEN}✓ PASS{Colors.RESET}"
FAIL = f"{Colors.BOLD_RED}✗ FAIL{Colors.RESET}"
OK = f"{Colors.BOLD_GREEN}OK{Colors.RESET}"
VALID = f"{Colors.BOLD_GREEN}VALID{Colors.RESET}"
INVALID = f"{Colors.BOLD_RED}INVALID{Colors.RESET}"
