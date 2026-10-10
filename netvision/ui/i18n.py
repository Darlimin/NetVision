"""Runtime UI localization loaded from external JSON catalogs."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from PySide6.QtCore import QObject, Signal


_LANGUAGE_FILES = {
    "ru": "ru-ru.json",
    "en": "en-en.json",
}


def _catalog_path(language: str) -> Path:
    return Path(__file__).resolve().with_name(_LANGUAGE_FILES[language])


def _load_catalog(language: str) -> dict[str, str]:
    """Load one catalog, returning an empty mapping on missing/broken files."""
    try:
        payload = json.loads(_catalog_path(language).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        str(source): str(translation)
        for source, translation in payload.items()
        if isinstance(source, str) and isinstance(translation, str)
    }


class UiTranslator(QObject):
    """Runtime translator backed by ru-ru.json and en-en.json."""

    language_changed = Signal(str)

    def __init__(self, language: str = "ru", parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._language = "ru"
        self._catalogs: dict[str, Mapping[str, str]] = {}
        self._english_reverse: dict[str, str] = {}
        self.set_language(language, emit=False)

    @property
    def language(self) -> str:
        return self._language

    def set_language(self, language: str, *, emit: bool = True) -> None:
        normalized = language.lower().strip()
        new_language = normalized if normalized in _LANGUAGE_FILES else "ru"
        changed = new_language != self._language
        self._language = new_language
        self._catalogs[new_language] = _load_catalog(new_language)
        if new_language == "en":
            self._english_reverse = {
                translation: source
                for source, translation in self._catalogs["en"].items()
            }
        elif "en" not in self._catalogs:
            self._catalogs["en"] = _load_catalog("en")
            self._english_reverse = {
                translation: source
                for source, translation in self._catalogs["en"].items()
            }
        if emit and changed:
            self.language_changed.emit(new_language)

    def translate(self, text: str) -> str:
        if not text:
            return text
        catalog = self._catalogs.get(self._language, {})
        translated = catalog.get(text)
        if translated is not None:
            return translated
        if self._language == "ru":
            return self._english_reverse.get(text, text)
        return text

    def format(self, source: str, /, **values: object) -> str:
        return self.translate(source).format(**values)
