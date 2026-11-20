"""Single source of truth for the NetVision semantic version."""

from __future__ import annotations

# Semantic Versioning policy:
# - PATCH (0.10.0 -> 0.10.1): compatible bug fixes and focused patches.
# - MINOR (0.10.0 -> 0.11.0): compatible user-facing features.
# - MAJOR (0.x.y -> 1.0.0): incompatible public API or architecture changes.
__version__ = "0.10.3"

# Optional UI-only prerelease label, for example "beta" or "rc.1". Keep the
# package version above PEP 440-compatible so setuptools can build the project.
PRERELEASE: str | None = None


def display_version() -> str:
    """Return the user-facing version label, preserving prerelease suffixes."""
    suffix = f"-{PRERELEASE.strip()}" if PRERELEASE and PRERELEASE.strip() else ""
    return f"v{__version__}{suffix}"


def window_title() -> str:
    """Return the language-independent title used by the main window."""
    return f"NetVision V {display_version()[1:]}"
