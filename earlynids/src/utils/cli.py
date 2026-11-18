"""Consistent CLI behaviour: exit codes, actionable errors, overwrite protection."""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Callable, Iterable, Optional

EXIT_OK = 0
EXIT_UNEXPECTED = 1
EXIT_INVALID_INPUT = 2       # missing file, bad schema, bad config value
EXIT_NO_ELIGIBLE_PACKETS = 3
EXIT_GATE_FAILED = 4         # dataset quality gate / validation failed
EXIT_OUTPUT_EXISTS = 5
EXIT_CONSERVATION = 6        # packet conservation violated

log = logging.getLogger("earlynids.cli")


class InputError(ValueError):
    """Invalid user input that the user can fix (message must say how)."""


class OutputExistsError(FileExistsError):
    pass


def require_file(path: Path, what: str) -> Path:
    p = Path(path)
    if not p.exists():
        raise InputError(f"{what} not found: {p}. Check the path (PowerShell: Test-Path '{p}').")
    if not p.is_file():
        raise InputError(f"{what} is not a file: {p}")
    return p


def guard_outputs(paths: Iterable[Path], overwrite: bool) -> None:
    existing = [str(p) for p in paths if Path(p).exists()]
    if existing and not overwrite:
        raise OutputExistsError(
            f"refusing to overwrite existing output(s): {existing}. Use a new path or pass --overwrite.")
    for p in paths:
        Path(p).parent.mkdir(parents=True, exist_ok=True)


def run_cli(main: Callable[[Optional[list]], int], argv: Optional[list] = None) -> int:
    from src.labeling.cicids2017 import LabelSchemaError
    try:
        return int(main(argv) or 0)
    except OutputExistsError as exc:
        log.error("%s", exc)
        return EXIT_OUTPUT_EXISTS
    except (InputError, LabelSchemaError, FileNotFoundError) as exc:
        log.error("invalid input: %s", exc)
        return EXIT_INVALID_INPUT
    except ValueError as exc:
        log.error("invalid configuration or data: %s", exc)
        return EXIT_INVALID_INPUT
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_UNEXPECTED
    except Exception:  # noqa: BLE001 - logged with traceback, never swallowed
        log.exception("unexpected error (please report with the traceback above)")
        return EXIT_UNEXPECTED
