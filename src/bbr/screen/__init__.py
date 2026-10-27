"""Deterministic annotation of untrusted binary strings; never an execution guard."""

from dataclasses import dataclass
from html import escape


@dataclass(frozen=True)
class ScreenedText:
    text: str
    html: str
    flags: tuple[str, ...]


def screen(text: str) -> ScreenedText:
    """Preserve text as data and separately provide HTML text-node escaping.

    Flags are transparent heuristics, not proof that an unflagged string is safe.
    Consumers must never interpret these strings as instructions or markup.
    """
    lowered = text.casefold()
    rules = (
        ("instruction_override", ("ignore previous", "ignore all", "disregard", "system prompt")),
        ("role_marker", ("[system]", "[assistant]", "<|system|>", "<|assistant|>", "system:")),
        ("exfiltration_hint", ("api_key", "secret", "password", "token=", "send to")),
        ("markup", ("<script", "javascript:", "<iframe", "onerror=")),
        ("external_reference", ("https://", "http://", "file://")),
    )
    flags = tuple(name for name, needles in rules if any(n in lowered for n in needles))
    return ScreenedText(text=text, html=escape(text, quote=True), flags=flags)


__all__ = ["ScreenedText", "screen"]
