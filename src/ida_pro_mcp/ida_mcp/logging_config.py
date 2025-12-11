"""Logging configuration for IDA MCP server.

By default logs go to a rotating file in a sensible writable location and
warnings/errors are also mirrored to IDA's output window (via ida_kernwin.msg).

You can override the file location with:
- IDA_MCP_LOG_PATH=/path/to/file.log
- IDA_MCP_LOG_DIR=/path/to/dir  (file will be ida_mcp.log inside)
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler


def _get_log_path() -> str:
    """Determine the path for the log file."""
    import tempfile

    # Explicit override (file or dir)
    env_path = os.environ.get("IDA_MCP_LOG_PATH")
    if env_path:
        return env_path
    env_dir = os.environ.get("IDA_MCP_LOG_DIR")
    if env_dir:
        log_name = "ida_mcp.log"
        try:
            import idaapi  # type: ignore

            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            if idb_path:
                stem = os.path.splitext(os.path.basename(idb_path))[0]
                log_name = f"{stem}.log"
        except Exception:
            pass
        return os.path.join(env_dir, log_name)

    # Prefer IDB directory when running inside IDA and writable
    try:
        import idaapi  # type: ignore

        idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        if idb_path:
            idb_dir = os.path.dirname(idb_path)
            if os.path.isdir(idb_dir) and os.access(idb_dir, os.W_OK):
                stem = os.path.splitext(os.path.basename(idb_path))[0]
                return os.path.join(idb_dir, f"{stem}.log")
    except Exception:
        pass

    # Fallback to temp directory
    return os.path.join(tempfile.gettempdir(), "ida_mcp.log")


class IDAOutputHandler(logging.Handler):
    """Handler that outputs to IDA's output window."""

    def emit(self, record):
        try:
            import ida_kernwin
            msg = self.format(record)
            # Only show warnings and errors in IDA's output window
            if record.levelno >= logging.WARNING:
                ida_kernwin.msg(f"[MCP] {msg}\n")
        except ImportError:
            pass  # Not running inside IDA
        except Exception:
            pass  # Don't crash on logging errors


def setup_logging(level: int = logging.DEBUG) -> logging.Logger:
    """Set up logging for the IDA MCP server.

    Returns the configured logger.
    """
    logger = logging.getLogger("ida_mcp")

    # Avoid adding handlers multiple times
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # File handler with rotation (5MB max, keep 3 backups)
    log_path = _get_log_path()
    try:
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
        logger.info(f"Logging to: {log_path}")
    except Exception as e:
        # If file logging fails, at least log to stderr
        print(f"[MCP] Warning: Could not set up file logging: {e}", file=sys.stderr)

    # IDA output handler (warnings and above)
    ida_handler = IDAOutputHandler()
    ida_handler.setLevel(logging.WARNING)
    ida_format = logging.Formatter("%(levelname)s: %(message)s")
    ida_handler.setFormatter(ida_format)
    logger.addHandler(ida_handler)

    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a logger instance.

    Args:
        name: Optional child logger name (e.g., "rpc", "sync")
    """
    root_logger = logging.getLogger("ida_mcp")
    if not root_logger.handlers:
        setup_logging()

    if name:
        return logging.getLogger(f"ida_mcp.{name}")
    return root_logger
