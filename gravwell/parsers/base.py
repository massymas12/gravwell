from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from gravwell.models.dataclasses import ParseResult


class BaseParser(ABC):
    name: str = "base"

    @classmethod
    @abstractmethod
    def can_parse(cls, filepath: Path) -> bool:
        """Return True if this parser can handle the given file."""

    @classmethod
    @abstractmethod
    def parse(cls, filepath: Path) -> ParseResult:
        """Parse the file and return a ParseResult."""

    @classmethod
    def _read_head(cls, filepath: Path, bytes_: int = 512) -> str:
        try:
            with open(filepath, "rb") as f:
                return f.read(bytes_).decode("utf-8", errors="ignore")
        except OSError:
            return ""
