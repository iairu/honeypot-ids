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
    # Keys merged in from .env.example by seed_from_example()/
    # merge_example_keys() that are NOT yet in the file on disk / on the
    # remote host -- the editor highlights these until the user saves.
    added_keys: list[str] = field(default_factory=list)

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

    def merge_missing_from(self, example: "EnvFile") -> list[str]:
        """Add every key `example` has that this file lacks, so the editor
        always shows the full set of keys the compose files can consume --
        not just whatever happened to be in .env when it was first created
        from the template. Without this, a key added to .env.example later
        (e.g. STRIPE_TEST_PUBLISHABLE_KEY) was invisible in the dashboard
        for every existing deployment, and could only be set by hand.

        Each missing key is inserted with the template's placeholder value
        AND the contiguous "# ..." comment block directly above it in the
        template (that's where the setup notes live), positioned right
        after the nearest preceding template key this file does have, so
        the new entry lands in the same section it occupies in the
        template rather than being dumped at the end. Nothing already in
        this file is touched. Returns the added keys, in insertion order,
        so the UI can point them out; nothing is written to disk here.
        """
        existing = set(self.keys())
        was_empty = not existing and not any(l.raw.strip() for l in self.lines)
        if was_empty:
            self.lines = []  # whitespace-only content: rebuild cleanly from the template
        added: list[str] = []
        anchor_key: str | None = None  # last template key that exists here
        for idx, ex_line in enumerate(example.lines):
            if ex_line.key is None:
                continue
            if ex_line.key in existing:
                anchor_key = ex_line.key
                continue

            block = _comment_block_above(example.lines, idx)
            n_above = len(block)
            block.append(EnvLine(raw=ex_line.raw, key=ex_line.key,
                                 value=ex_line.value,
                                 inline_comment=ex_line.inline_comment))
            block.extend(_comment_block_below(example.lines, idx))

            insert_at = self._insert_position_after(anchor_key)
            if insert_at is None:
                insert_at = len(self.lines)
            # Mirror the template's own section separation: if it puts a
            # blank line above this block, so do we (unless we're already
            # after one). A merge into an empty file rebuilds the
            # template byte-for-byte this way.
            first = idx - n_above  # index of the block's first line in the template
            template_has_gap = first > 0 and not example.lines[first - 1].raw.strip()
            if (template_has_gap and insert_at > 0
                    and self.lines[insert_at - 1].raw.strip()):
                block.insert(0, EnvLine(raw=""))
            self.lines[insert_at:insert_at] = block

            existing.add(ex_line.key)
            anchor_key = ex_line.key
            added.append(ex_line.key)

        # Starting from nothing at all (e.g. a remote host with no .env
        # yet): also carry over the template's trailing notes, which sit
        # below the last key and so belong to no key's block.
        if was_empty and added:
            last_key_idx = max(i for i, l in enumerate(example.lines) if l.key is not None)
            start = last_key_idx + 1 + len(_comment_block_below(example.lines, last_key_idx))
            self.lines.extend(EnvLine(raw=l.raw) for l in example.lines[start:])
        return added

    def _insert_position_after(self, key: str | None) -> int | None:
        """Index just past `key`'s line -- or past the inline comment lines
        that immediately trail it, so an inserted block never splits a
        key from a note written directly under it. None if `key` is None
        or absent (caller appends at the end)."""
        if key is None:
            return None
        for i, line in enumerate(self.lines):
            if line.key == key:
                j = i + 1
                while j < len(self.lines) and self.lines[j].raw.strip().startswith("#"):
                    j += 1
                return j
        return None

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


def _comment_block_above(lines: list[EnvLine], idx: int) -> list[EnvLine]:
    """The contiguous run of "# ..." lines directly above lines[idx]
    (copied), stopping at a blank line or a KEY=VALUE line. This is the
    template's documentation for that key."""
    block: list[EnvLine] = []
    j = idx - 1
    while j >= 0 and lines[j].key is None and lines[j].raw.strip().startswith("#"):
        block.append(EnvLine(raw=lines[j].raw))
        j -= 1
    block.reverse()
    return block


def _comment_block_below(lines: list[EnvLine], idx: int) -> list[EnvLine]:
    """Comment lines directly under lines[idx] that belong to IT (typically
    commented-out alternative values, e.g. "#LICENSE=trial") -- only when
    that run ends at a blank line or EOF. A run that leads straight into
    the next KEY=VALUE line is that next key's header instead (see
    _comment_block_above), so it is not claimed here."""
    block: list[EnvLine] = []
    j = idx + 1
    while j < len(lines) and lines[j].key is None and lines[j].raw.strip().startswith("#"):
        block.append(EnvLine(raw=lines[j].raw))
        j += 1
    if j < len(lines) and lines[j].key is not None:
        return []
    return block


def merge_example_keys(ef: EnvFile, example: Path) -> list[str]:
    """Bring `ef` up to date with the template's key set (see
    EnvFile.merge_missing_from). No-op, returning [], when the template
    doesn't exist. Used for local AND remote-fetched .env content -- the
    template is part of this repo, so it describes what a remote
    deployment of the same code needs just as much as a local one."""
    if not example.exists():
        return []
    return ef.merge_missing_from(EnvFile.load(example))


def seed_from_example(target: Path, example: Path) -> EnvFile:
    """Used by the setup wizard and the Settings .env tabs: if target
    doesn't exist yet, start from the .env.example template (same
    comments, placeholder values); if it already exists, load it and only
    ADD any keys the template has gained since (merge_example_keys) --
    never a fresh template that would wipe an existing deployment's
    configuration. Keys the merge added are recorded on ef.added_keys so
    the UI can flag them; they only reach disk on an explicit save."""
    if target.exists():
        ef = EnvFile.load(target)
        ef.added_keys = merge_example_keys(ef, example)
        return ef
    if example.exists():
        ef = EnvFile.load(example)
        ef.path = target
        return ef
    return EnvFile(path=target)
