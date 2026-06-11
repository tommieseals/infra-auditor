"""Helpers for deciding whether report glyphs survive the output encoding."""

import sys


def stdout_can_encode(text: str) -> bool:
    """Return True if the current ``sys.stdout`` encoding can encode *text*.

    Streams without a declared encoding (or with an unknown one) are treated
    as unable, so callers degrade to ASCII output rather than crash.
    """
    encoding = getattr(sys.stdout, "encoding", None)
    if not encoding:
        return False
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True
