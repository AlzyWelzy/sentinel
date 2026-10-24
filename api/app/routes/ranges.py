"""Named time ranges for summary endpoints: (seconds, chart step)."""

from typing import Literal

Range = Literal["1h", "24h", "7d", "30d", "90d"]

RANGES: dict[str, tuple[int, int]] = {
    "1h": (3600, 60),
    "24h": (86400, 300),
    "7d": (7 * 86400, 1800),
    "30d": (30 * 86400, 7200),
    "90d": (90 * 86400, 21600),
}
