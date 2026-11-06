"""Configuration management for Algorithm-Optimized Reconnaissance Framework.

Loads settings from environment variables and sets sensible defaults for
safe timeouts, rate limits, file paths, and tool discovery.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _load_env_file() -> None:
    """Load key-value pairs from .env file into os.environ if present."""
    env_file = Path(__file__).resolve().parent / ".env"
    if env_file.is_file():
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k and k not in os.environ:
                        os.environ[k] = v
        except Exception:
            pass


_load_env_file()


@dataclass(frozen=True)
class AppConfig:
    """Central configuration class."""

    # Project Directories
    BASE_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent)
    REPORTS_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "reports")
    FIXTURES_DIR: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "fixtures")
    SIGNATURES_FILE: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent / "banner" / "signatures.json"
    )
    BENCHMARKS_DIR: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent / "benchmarks" / "results"
    )

    # Network and Safety Limits
    NETWORK_TIMEOUT: float = float(os.getenv("RECON_TIMEOUT_SECONDS", "5.0"))
    MAX_RETRIES: int = int(os.getenv("RECON_MAX_RETRIES", "2"))
    RATE_LIMIT_DELAY: float = float(os.getenv("RECON_RATE_LIMIT_DELAY", "0.5"))
    MAX_BANNER_BYTES: int = int(os.getenv("RECON_MAX_BANNER_BYTES", "2048"))
    DEFAULT_PROBE_BUDGET: int = int(os.getenv("RECON_DEFAULT_BUDGET", "100"))

    # Passive API Credentials (Optional)
    SHODAN_API_KEY: Optional[str] = os.getenv("SHODAN_API_KEY") or None
    CENSYS_API_ID: Optional[str] = os.getenv("CENSYS_API_ID") or None
    CENSYS_API_SECRET: Optional[str] = (
        os.getenv("CENSYS_API_SECRET") or os.getenv("CENSYS_API_KEY") or None
    )
    CENSYS_API_KEY: Optional[str] = (
        os.getenv("CENSYS_API_KEY") or os.getenv("CENSYS_API_SECRET") or os.getenv("CENSYS_API_ID") or None
    )
    CENSYS_ORGANIZATION_ID: Optional[str] = (
        os.getenv("CENSYS_ORGANIZATION_ID") or os.getenv("CENSYS_ORG_ID") or None
    )

    # Safety: active scan allowed protocols / ports
    DEFAULT_ACTIVE_PORTS: tuple[int, ...] = (21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443)

    def ensure_directories(self) -> None:
        """Create necessary directories if they do not exist."""
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.BENCHMARKS_DIR.mkdir(parents=True, exist_ok=True)
        self.FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def is_tool_available(tool_name: str) -> bool:
        """Check if an external CLI tool is available on system PATH."""
        return shutil.which(tool_name) is not None

    def get_tool_status(self) -> dict[str, bool]:
        """Check availability of external utilities."""
        tools = ["nmap", "whois", "dig", "theHarvester", "whatweb"]
        return {tool: self.is_tool_available(tool) for tool in tools}


# Singleton config instance
config = AppConfig()
config.ensure_directories()
