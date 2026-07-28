"""Shared passphrase strength policy.

Sections 0.1 and 0.2 both ask for a "sufficiently strong" passphrase, so both
the Master Passphrase and user passphrases go through the same check. Length is
the dominant factor for offline guessing resistance, but a long single-class
string ("aaaaaaaaaaaaaa") is still trivially guessable, hence the character-class
and repetition rules.

The check deliberately stays local and deterministic: no external breach lists,
no network calls, and the passphrase is never logged or persisted anywhere.
"""

import re
from dataclasses import dataclass


MIN_LENGTH = 12
MIN_CHARACTER_CLASSES = 3
MAX_REPEATED_RUN = 4

_CLASS_PATTERNS = (
    re.compile(r"[a-z]"),
    re.compile(r"[A-Z]"),
    re.compile(r"[0-9]"),
    re.compile(r"[^A-Za-z0-9]"),
)

# Lowercased substrings that make a passphrase guessable regardless of length.
_FORBIDDEN_SUBSTRINGS = (
    "password",
    "passphrase",
    "minivault",
    "qwerty",
    "123456",
    "abcdef",
    "letmein",
    "admin",
)


@dataclass(frozen=True)
class PassphraseIssue:
    code: str
    message: str


def evaluate(passphrase: object) -> PassphraseIssue | None:
    """Return the first policy violation, or None when the passphrase passes."""
    if not isinstance(passphrase, str):
        return PassphraseIssue("NOT_A_STRING", "Passphrase must be a string")
    if len(passphrase) < MIN_LENGTH:
        return PassphraseIssue(
            "TOO_SHORT", f"Passphrase must contain at least {MIN_LENGTH} characters"
        )
    if passphrase.strip() != passphrase or not passphrase.strip():
        return PassphraseIssue(
            "SURROUNDING_WHITESPACE",
            "Passphrase must not be blank or padded with whitespace",
        )

    classes = sum(1 for pattern in _CLASS_PATTERNS if pattern.search(passphrase))
    if classes < MIN_CHARACTER_CLASSES:
        return PassphraseIssue(
            "TOO_FEW_CHARACTER_CLASSES",
            "Passphrase must mix at least three of: lowercase, uppercase, digits, symbols",
        )

    if _has_long_run(passphrase):
        return PassphraseIssue(
            "REPEATED_CHARACTERS",
            f"Passphrase must not repeat the same character {MAX_REPEATED_RUN} times in a row",
        )

    lowered = passphrase.lower()
    if any(bad in lowered for bad in _FORBIDDEN_SUBSTRINGS):
        return PassphraseIssue(
            "COMMON_PATTERN", "Passphrase must not contain a common guessable word"
        )

    return None


def is_strong(passphrase: object) -> bool:
    return evaluate(passphrase) is None


def _has_long_run(passphrase: str) -> bool:
    run = 1
    for previous, current in zip(passphrase, passphrase[1:]):
        run = run + 1 if current == previous else 1
        if run >= MAX_REPEATED_RUN:
            return True
    return False
