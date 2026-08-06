"""Comment-preserving .env reader/writer.

Both projects' .env files are extensively commented (setup notes, links,
warnings) -- a naive parse-into-dict-and-rewrite approach would flatten all
of that on first save. This keeps every line (comments, blank lines,
inline "# ..." trailers) byte-identical except for the specific VALUE of a
key that was actually changed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_KV_RE = re.compile(
    r"""^(?P<prefix>\s*)
        (?P<key>[A-Za-z_][A-Za-z0-9_]*)
        =
        (?P<value>.*)$""",
    re.VERBOSE,
)


@dataclass
class EnvLine:
    raw: str  # original full line, no trailing newline
    key: str | None = None  # set if this line is a KEY=VALUE assignment
    value: str = ""
    inline_comment: str = ""  # e.g. " # also used for dashboard login"


@dataclass
class EnvFile:
    path: Path
    lines: list[EnvLine] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "EnvFile":
        ef = cls(path=path)
        if not path.exists():
            return ef
        text = path.read_text()
        for raw in text.splitlines():
            ef.lines.append(_parse_line(raw))
        return ef

    @classmethod
    def from_text(cls, text: str, path: Path) -> "EnvFile":
        """Same parsing as load(), but from an in-memory string instead of
        reading `path` from disk -- used for remote-fetched .env content
        (see core/env_upload.py's download_env_text()), where there's no
        local file to read. `path` is kept only for display (e.g. the
        editor's "no keys found" message) and is NOT where .save() would
        write -- callers editing remote content should call
        apply_to_env_file() + render() and upload the result themselves,
        not .save()."""
        ef = cls(path=path)
        for raw in text.splitlines():
            ef.lines.append(_parse_line(raw))
        return ef

    def get(self, key: str, default: str = "") -> str:
        for line in self.lines:
            if line.key == key:
                return line.value
        return default

    def keys(self) -> list[str]:
        return [l.key for l in self.lines if l.key is not None]

    def set(self, key: str, value: str) -> None:
        """Update an existing key's value, or append a new KEY=VALUE line
        if it doesn't exist yet (rare -- only for keys entirely missing
        from a hand-edited .env)."""
        for line in self.lines:
            if line.key == key:
                line.value = value
                return
        self.lines.append(EnvLine(raw="", key=key, value=value))

    def as_dict(self) -> dict[str, str]:
        return {l.key: l.value for l in self.lines if l.key is not None}

    def render(self) -> str:
        out = []
        for line in self.lines:
            if line.key is None:
                out.append(line.raw)
            else:
                prefix_match = _KV_RE.match(line.raw) if line.raw else None
                prefix = prefix_match.group("prefix") if prefix_match else ""
                out.append(f"{prefix}{line.key}={line.value}{line.inline_comment}")
        return "\n".join(out) + "\n"

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(self.render())


def _parse_line(raw: str) -> EnvLine:
    stripped = raw.strip()
    if not stripped or stripped.startswith("#"):
        return EnvLine(raw=raw)

    m = _KV_RE.match(raw)
    if not m:
        return EnvLine(raw=raw)

    key = m.group("key")
    rest = m.group("value")

    # Split a trailing "# comment" off the value, but only outside quotes --
    # a value can legitimately contain '#' inside quotes (not currently used
    # by either .env, but safer to handle).
    value, inline_comment = _split_inline_comment(rest)
    return EnvLine(raw=raw, key=key, value=value, inline_comment=inline_comment)


def _split_inline_comment(rest: str) -> tuple[str, str]:
    in_single = False
    in_double = False
    for i, ch in enumerate(rest):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            # Keep the value trimmed, but preserve exact comment text
            # (including its leading space) so re-rendering is byte-stable.
            value = rest[:i].rstrip()
            trailing_ws = rest[len(value):i]
            return value, trailing_ws + rest[i:]
    return rest.rstrip(), ""


def seed_from_example(target: Path, example: Path) -> EnvFile:
    """Used by the setup wizard: if target doesn't exist yet, start from
    the .env.example template (same comments, placeholder values); if it
    already exists, load it as-is so the wizard edits real values, not a
    fresh template that would wipe an existing deployment's configuration."""
    if target.exists():
        return EnvFile.load(target)
    if example.exists():
        ef = EnvFile.load(example)
        ef.path = target
        return ef
    return EnvFile(path=target)
