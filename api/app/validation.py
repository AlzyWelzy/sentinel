"""Rules for names customers type, shared by every route that accepts them.

Tags and service names must match what ingest and the agent accept
(ingest/hostmeta.go, agent/collector/services.go), or a rule would be saved
that can never see data.
"""

import re

from pydantic import StringConstraints

# For names and titles people type: surrounding spaces are dropped before
# the length is checked, so "   " is refused rather than saved as blank.
Trimmed = StringConstraints(strip_whitespace=True)

TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")
MAX_TAGS = 20

# Service manager names (systemd units, rc.d scripts, Windows service names).
# Never starts with "-", so it can't be read as an option by service tools.
SERVICE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9@._:$ -]{0,99}$")

# Process names as ps, top or Task Manager show them: anything printable
# except path separators.
PROCESS_RE = re.compile(r"^[^\x00-\x1f\x7f/\\]{1,100}$")


def normalize_tag(value: str) -> str:
    tag = value.strip().lower()
    if not TAG_RE.match(tag):
        raise ValueError(
            "tags are 1-40 characters: lowercase letters, digits, '.', '_' or '-', "
            "starting with a letter or digit"
        )
    return tag


def normalize_tags(values: list[str]) -> list[str]:
    tags = sorted({normalize_tag(v) for v in values})
    if len(tags) > MAX_TAGS:
        raise ValueError(f"at most {MAX_TAGS} tags")
    return tags


def validate_target(kind: str, value: str) -> str:
    target = value.strip()
    if kind == "service_down" and not SERVICE_RE.match(target):
        raise ValueError(
            "service names use letters, digits and @ . _ : $ - (e.g. nginx, php8.2-fpm, W3SVC)"
        )
    if kind == "process_down" and not PROCESS_RE.match(target):
        raise ValueError("process names are 1-100 printable characters without / or \\")
    return target
