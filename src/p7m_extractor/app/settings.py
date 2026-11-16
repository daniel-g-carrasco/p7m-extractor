"""The preferences: an INI file in the per-user configuration directory."""

from __future__ import annotations

import configparser
import io
from pathlib import Path

from p7m_extractor.data import atomic

from . import services


def config_dir() -> Path:
    """Per-user configuration directory (app/services.py): %LOCALAPPDATA%\\
    p7m-extractor on Windows, $XDG_CONFIG_HOME/p7m-extractor elsewhere
    (Flatpak points it inside the sandbox)."""
    return services.app_paths().config


class Settings:
    """Tiny persistent key/value store (settings.ini). No file means defaults."""

    DEFAULTS = {
        "language": "auto",            # auto (desktop language) | it | en
        "color_scheme": "auto",        # auto (follow the system) | light | dark
        # Windows: the system title bar (and so Snap) rather than GTK's
        "system_title_bar": "true",
        "ask_default_app": "true",     # Windows: offer to become the .p7m handler
        "check_updates": "true",       # Windows: look for a new release, every 4 hours at most
        "verify_signatures": "true",   # check who signed and whether the signature holds (uses the network)
        # when the last check made on its own was (updates.check_stamp); a
        # date alone, as the once-a-day check wrote it, is that day's midnight
        "last_update_check": "",
    }

    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else services.app_paths().config_file
        self._cp = configparser.ConfigParser()
        self._cp["general"] = dict(self.DEFAULTS)
        try:
            self._cp.read(self.path, encoding="utf-8")
        except (OSError, configparser.Error):
            pass

    def get(self, key: str) -> str:
        return self._cp["general"].get(key, self.DEFAULTS.get(key, ""))

    def get_bool(self, key: str) -> bool:
        return self.get(key).strip().lower() in ("1", "true", "yes", "on")

    def set(self, key: str, value) -> None:
        if isinstance(value, bool):
            value = "true" if value else "false"
        self._cp["general"][key] = str(value)
        self.save()

    def save(self) -> None:
        """Written whole or not at all (data/atomic.py: a temporary file
        renamed over the old one, the rename tried again for a moment when
        Windows refuses it, an antivirus or the indexer holding the file
        just written)."""
        text = io.StringIO()
        self._cp.write(text)
        try:
            atomic.write_bytes(self.path, text.getvalue().encode("utf-8"))
        except OSError:
            pass  # preferences are a convenience, never fatal
