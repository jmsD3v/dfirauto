"""Base class for all DFIR collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from dfirauto.types.artifacts import CollectorResult


class BaseCollector(ABC):
    """Abstract DFIR evidence collector."""

    name: str = "base"
    description: str = ""
    platforms: list[str] = ["linux", "windows", "darwin"]   # supported OS

    @abstractmethod
    async def collect(self) -> CollectorResult:
        """Run collection. Must return CollectorResult with artifacts."""

    def is_supported(self) -> bool:
        import sys
        platform = sys.platform
        if platform.startswith("win"):
            return "windows" in self.platforms
        if platform.startswith("darwin"):
            return "darwin" in self.platforms
        return "linux" in self.platforms
