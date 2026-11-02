"""
Usage:
    from core.logger import log

    log.info("Application started")
    log.success("Task completed")
    log.warning("Low memory")
    log.error("Connection failed")
    log.critical("System crash")
    log.debug("Variable x = 42")

    # With context
    log.info("User logged in", user="admin", ip="192.168.1.1")

    # Change level
    log.set_level("DEBUG")

    # Log to file
    log.add_file("app.log")
"""

from __future__ import annotations

import os
import sys
import logging
import datetime
from pathlib import Path
from typing import Any

from colorama import init as colorama_init, Fore, Back, Style

# Initialize colorama for cross-platform color support
colorama_init(autoreset=False)

R = Style.RESET_ALL  # shortcut


# ──────────────────────────────────────────────────────────────────────
# Custom log levels
# ──────────────────────────────────────────────────────────────────────
TRACE_LEVEL = 5
SUCCESS_LEVEL = 25
logging.addLevelName(TRACE_LEVEL, "TRACE")
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

LEVEL_MAP = {
    "TRACE":    TRACE_LEVEL,
    "DEBUG":    logging.DEBUG,
    "INFO":     logging.INFO,
    "SUCCESS":  SUCCESS_LEVEL,
    "WARNING":  logging.WARNING,
    "ERROR":    logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


# ──────────────────────────────────────────────────────────────────────
# Level Styles: (icon, label_color, msg_color)
#   All emoji are single codepoints (no variation selectors)
#   so they render at consistent 2-column width for alignment.
# ──────────────────────────────────────────────────────────────────────
LEVEL_STYLES = {
    "TRACE":    (Fore.LIGHTBLACK_EX,                           Style.DIM + Fore.WHITE),
    "DEBUG":    (Fore.LIGHTCYAN_EX,                            Fore.CYAN),
    "INFO":     (Fore.LIGHTBLUE_EX,                            Fore.WHITE),
    "SUCCESS":  (Fore.LIGHTGREEN_EX,                           Fore.GREEN),
    "WARNING":  (Fore.LIGHTYELLOW_EX,                          Fore.YELLOW),
    "ERROR":    (Fore.LIGHTRED_EX,                             Fore.RED),
    "CRITICAL": (Back.RED + Style.BRIGHT + Fore.WHITE,         Style.BRIGHT + Fore.RED),
}

SEP = f"{Fore.LIGHTBLACK_EX}\u2502{R}"

# ──────────────────────────────────────────────────────────────────────
# Colored Console Formatter
# ──────────────────────────────────────────────────────────────────────


class LiveDisplayHandler(logging.Handler):
    """Routes log records through a LiveDisplay's erase/print/redraw flow."""

    def __init__(self, display: Any, formatter: logging.Formatter) -> None:
        super().__init__()
        self.display = display
        self.setFormatter(formatter)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            # Also buffer plain text for log file
            now = datetime.datetime.fromtimestamp(record.created).strftime("%H:%M:%S")

            with self.display._lock:
                self.display._log_buffer_plain.append(f"[{now}] {record.getMessage()}")
                self.display._log_count += 1
                if self.display._running:
                    self.display._erase_bar()
                    sys.stdout.write(f"{msg}\n")
                    sys.stdout.flush()
                    self.display._last_refresh_time = 0.0  # force redraw after log
                    self.display._draw_bar()
                else:
                    sys.stdout.write(f"{msg}\n")
                    sys.stdout.flush()
        except Exception:
            self.handleError(record)


class ColoredFormatter(logging.Formatter):
    """Pretty formatter with colorama colors, emoji icons, and structured context."""

    def format(self, record: logging.LogRecord) -> str:
        # ── Timestamp ─────────────────────────────────────────────
        dt = datetime.datetime.fromtimestamp(record.created)
        time_main = dt.strftime("%H:%M:%S")
        timestamp = f"{Style.DIM}{Fore.WHITE}{time_main}{R}"
        hachi_tag = f"{Fore.LIGHTCYAN_EX}{Style.BRIGHT}RoBipass{R}"

        # ── Level ─────────────────────────────────────────────────
        level_name = record.levelname
        label_clr, msg_clr = LEVEL_STYLES.get(
            level_name, ("\u2022", Fore.WHITE, Fore.WHITE)
        )
        level_label = f"{label_clr}{Style.BRIGHT}{level_name:<8}{R}"

        # ── Message ───────────────────────────────────────────────
        message = f"{msg_clr}{record.getMessage()}{R}"

        # ── Context kwargs ────────────────────────────────────────
        ctx_str = ""
        extra = getattr(record, "_extra_ctx", None)
        if extra:
            pairs = []
            for k, v in extra.items():
                pairs.append(
                    f"{Fore.LIGHTBLACK_EX}{k}{R}"
                    f"{Style.DIM}={R}"
                    f"{Fore.LIGHTMAGENTA_EX}{v}{R}"
                )
            ctx_str = (
                f"  {Fore.LIGHTBLACK_EX}({R}"
                f"{', '.join(pairs)}"
                f"{Fore.LIGHTBLACK_EX}){R}"
            )

        # ── Assemble ────────────────────────────────────────────────
        line = f" {timestamp} {SEP} {level_label} {SEP} {message}{ctx_str}"

        # ── Exception traceback ───────────────────────────────────
        if record.exc_info and record.exc_info != (None, None, None):
            try:
                exc_text = self.formatException(record.exc_info)
                tb_lines = exc_text.split("\n")
                colored_tb = "\n".join(
                    f"      {Style.DIM}{Fore.RED}{ln}{R}" for ln in tb_lines
                )
                line += f"\n{colored_tb}"
            except Exception:
                pass

        return line


# ──────────────────────────────────────────────────────────────────────
# Plain File Formatter (no colors)
# ──────────────────────────────────────────────────────────────────────
class PlainFormatter(logging.Formatter):
    """Clean formatter for file output — no color codes."""

    def format(self, record: logging.LogRecord) -> str:
        dt = datetime.datetime.fromtimestamp(record.created)
        ts = dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{int(record.msecs):03d}"
        level = record.levelname

        tags = {
            "TRACE": "[TRACE]", "DEBUG": "[DEBUG]", "INFO": "[INFO ]",
            "SUCCESS": "[ OK  ]", "WARNING": "[WARN ]",
            "ERROR": "[ERROR]", "CRITICAL": "[CRIT ]",
        }
        tag = tags.get(level, "[     ]")
        msg = record.getMessage()

        ctx_str = ""
        extra = getattr(record, "_extra_ctx", None)
        if extra:
            pairs = [f"{k}={v}" for k, v in extra.items()]
            ctx_str = f"  ({', '.join(pairs)})"

        line = f"{ts} {tag} {msg}{ctx_str}"

        if record.exc_info and record.exc_info != (None, None, None):
            try:
                line += f"\n{self.formatException(record.exc_info)}"
            except Exception:
                pass

        return line


# ──────────────────────────────────────────────────────────────────────
# Logger Class
# ──────────────────────────────────────────────────────────────────────
class Logger:
    """
    Beautiful multi-level logger powered by colorama.

    Levels (lowest → highest):
        TRACE → DEBUG → INFO → SUCCESS → WARNING → ERROR → CRITICAL
    """

    def __init__(self, name: str = "hachi-tools", level: str = "DEBUG") -> None:
        self._logger = logging.getLogger(name)
        self._logger.setLevel(LEVEL_MAP.get(level.upper(), logging.DEBUG))
        self._logger.propagate = False

        # Console handler
        self._console = logging.StreamHandler(sys.stdout)
        self._console.setLevel(TRACE_LEVEL)
        self._console.setFormatter(ColoredFormatter())
        self._logger.addHandler(self._console)

        self._file_handler: logging.FileHandler | None = None
        self._live_handler: LiveDisplayHandler | None = None

    # ── Public API ────────────────────────────────────────────────────

    def set_level(self, level: str) -> None:
        """Set minimum log level."""
        numeric = LEVEL_MAP.get(level.upper())
        if numeric is None:
            raise ValueError(
                f"Unknown level: {level}. Use one of {list(LEVEL_MAP.keys())}"
            )
        self._logger.setLevel(numeric)

    def add_file(self, filepath: str, level: str = "DEBUG") -> None:
        """Add a file handler for persistent logging."""
        if self._file_handler:
            self._logger.removeHandler(self._file_handler)
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(path), encoding="utf-8")
        fh.setLevel(LEVEL_MAP.get(level.upper(), logging.DEBUG))
        fh.setFormatter(PlainFormatter())
        self._logger.addHandler(fh)
        self._file_handler = fh

    def remove_file(self) -> None:
        """Remove file handler."""
        if self._file_handler:
            self._logger.removeHandler(self._file_handler)
            self._file_handler.close()
            self._file_handler = None

    def attach_display(self, display: Any) -> None:
        """Attach a LiveDisplay — routes logs through its erase/print/redraw."""
        self.detach_display()
        self._live_handler = LiveDisplayHandler(display, ColoredFormatter())
        self._live_handler.setLevel(TRACE_LEVEL)
        self._logger.addHandler(self._live_handler)
        self._logger.removeHandler(self._console)

    def detach_display(self) -> None:
        """Detach LiveDisplay, restore normal console logging."""
        if self._live_handler:
            self._logger.removeHandler(self._live_handler)
            self._live_handler = None
        if self._console not in self._logger.handlers:
            self._logger.addHandler(self._console)

    # ── Logging Methods ───────────────────────────────────────────────

    def trace(self, msg: str, **ctx: Any) -> None:
        self._log(TRACE_LEVEL, msg, ctx)

    def debug(self, msg: str, **ctx: Any) -> None:
        self._log(logging.DEBUG, msg, ctx)

    def info(self, msg: str, **ctx: Any) -> None:
        self._log(logging.INFO, msg, ctx)

    def success(self, msg: str, **ctx: Any) -> None:
        self._log(SUCCESS_LEVEL, msg, ctx)

    def warning(self, msg: str, **ctx: Any) -> None:
        self._log(logging.WARNING, msg, ctx)

    def warn(self, msg: str, **ctx: Any) -> None:
        self.warning(msg, **ctx)

    def error(self, msg: str, exc: Exception | None = None, **ctx: Any) -> None:
        self._log(logging.ERROR, msg, ctx, exc_info=exc)

    def critical(self, msg: str, exc: Exception | None = None, **ctx: Any) -> None:
        self._log(logging.CRITICAL, msg, ctx, exc_info=exc)

    def exception(self, msg: str, **ctx: Any) -> None:
        """Log current exception at ERROR level (use inside except block)."""
        self._log(logging.ERROR, msg, ctx, exc_info=sys.exc_info())

    # ── Dividers & Helpers ────────────────────────────────────────────
    def newline(self, number: int = 1) -> None:
        print("\n" * number)

    def divider(self, title: str = "", char: str = "\u2500", width: int = 0) -> None:
        """Print a visual divider line, centered. width=0 means full terminal width."""
        try:
            import shutil
            tw = shutil.get_terminal_size().columns
        except Exception:
            tw = 80

        if width <= 0:
            width = tw

        if title:
            padding = max(0, width - len(title) - 4)
            left = padding // 2
            right = padding - left
            content = (
                f"{Fore.LIGHTBLACK_EX}{char * left} "
                f"{Style.BRIGHT}{Fore.BLUE}{title} "
                f"{R}{Fore.LIGHTBLACK_EX}{char * right}{R}"
            )
        else:
            content = f"{Fore.LIGHTBLACK_EX}{char * width}{R}"

        # Center the divider in the terminal
        if width < tw:
            margin = (tw - width) // 2
            content = " " * margin + content

        print(content)

    def banner(self, subtitle: str = "") -> None:
        # Clear the console before showing the banner
        os.system("cls" if os.name == "nt" else "clear")

        BANNER = r"""
  _____       ____  _
 |  __ \     |  _ \(_)
 | |__) |___ | |_) |_ _ __   __ _ ___ ___
 |  _  // _ \|  _ <| | '_ \ / _` / __/ __|
 | | \ \ (_) | |_) | | |_) | (_| \__ \__ \
 |_|  \_\___/|____/|_| .__/ \__,_|___/___/
                     | |
                     |_|
        """

        lines = [ln.rstrip() for ln in BANNER.split("\n")]
        max_w = max(len(ln) for ln in lines)

        try:
            import shutil
            tw = shutil.get_terminal_size().columns
        except Exception:
            tw = 80

        print()                       # blank line
        for ln in lines:
            pad = max(0, (tw - max_w) // 2)
            print(f"{' ' * pad}{Style.BRIGHT}{Fore.CYAN}{ln}{R}")

        print()

        if subtitle:
            pad = max(0, (tw - len(subtitle)) // 2)
            print(f"{' ' * pad}{Style.DIM}{Fore.LIGHTWHITE_EX}{subtitle}{R}")

        print()

    # ── Internal ──────────────────────────────────────────────────────

    def _log(
        self,
        level: int,
        msg: str,
        ctx: dict[str, Any],
        exc_info: Any = None,
    ) -> None:
        frame = sys._getframe(2)
        record = self._logger.makeRecord(
            name=self._logger.name,
            level=level,
            fn=frame.f_code.co_filename,
            lno=frame.f_lineno,
            msg=msg,
            args=(),
            exc_info=(
                (type(exc_info), exc_info, exc_info.__traceback__)
                if isinstance(exc_info, BaseException)
                else exc_info
                if isinstance(exc_info, tuple)
                else None
            ),
        )
        record._extra_ctx = ctx  # type: ignore[attr-defined]
        self._logger.handle(record)


# ──────────────────────────────────────────────────────────────────────
# Default singleton instance
# ──────────────────────────────────────────────────────────────────────
log = Logger()
