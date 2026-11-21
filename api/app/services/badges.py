# ruff: noqa: E501 -- SVG markup reads best on one line per element
"""SVG badges for README files and websites, in the familiar two-part
shape: a grey label and a coloured value. Text is measured with a width
table for Verdana 11px (what badge renderers use), so nothing is cut off
without a font on the server."""

import hashlib
import html

# Approximate advance widths at 11px Verdana, in pixels.
_NARROW = set("fijlrtI.,:;!|'() ")
_WIDE = set("mwMW%@")

COLOURS = {
    "green": "#16a34a",
    "lime": "#65a30d",
    "yellow": "#ca8a04",
    "orange": "#ea580c",
    "red": "#dc2626",
    "blue": "#2563eb",
    "grey": "#64748b",
}

STYLES = ("flat", "flat-square", "for-the-badge")


def _width(text: str, upper: bool = False) -> int:
    w = 0.0
    for ch in text:
        if ch in _NARROW:
            w += 3.6
        elif ch in _WIDE:
            w += 10.0
        elif ch.isupper() or ch.isdigit():
            w += 7.6
        else:
            w += 6.5
    if upper:
        # Bold, with 1px letter spacing.
        w = w * 1.12 + len(text)
    return int(w) + 1


def uptime_colour(pct: float | None) -> str:
    if pct is None:
        return COLOURS["grey"]
    if pct >= 99.9:
        return COLOURS["green"]
    if pct >= 99:
        return COLOURS["lime"]
    if pct >= 95:
        return COLOURS["yellow"]
    return COLOURS["red"]


def render(label: str, value: str, colour: str, style: str = "flat") -> str:
    """A badge. label and value are text from the owner or computed; both
    are escaped. colour is a #rrggbb from COLOURS or uptime_colour."""
    upper = style == "for-the-badge"
    if upper:
        label, value = label.upper(), value.upper()
    label, value = label[:60], value[:60]
    pad = 12 if upper else 6
    height = 28 if upper else 20
    lw = _width(label, upper) + 2 * pad if label else 0
    vw = _width(value, upper) + 2 * pad
    total = lw + vw
    radius = 0 if style != "flat" else 3
    e = html.escape
    # Ids unique per badge: several pasted inline into one page must not
    # use each other's clip and gradient.
    uid = hashlib.sha256(f"{label}|{value}|{colour}|{style}".encode()).hexdigest()[:8]
    y = 18 if upper else 14
    gloss = (
        f'<linearGradient id="s{uid}" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/></linearGradient>'
        if style == "flat"
        else ""
    )
    title = f"{label}: {value}" if label else value
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="{height}" role="img"'
        f' aria-label="{e(title)}"><title>{e(title)}</title>{gloss}'
        f'<clipPath id="r{uid}"><rect width="{total}" height="{height}" rx="{radius}" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r{uid})"><rect width="{lw}" height="{height}" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="{height}" fill="{e(colour)}"/>'
        + (f'<rect width="{total}" height="{height}" fill="url(#s{uid})"/>' if gloss else "")
        + "</g>"
        f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif"'
        f' font-size="11"{' font-weight="bold" letter-spacing="1"' if upper else ""}>'
        + (f'<text x="{lw / 2}" y="{y}">{e(label)}</text>' if label else "")
        + f'<text x="{lw + vw / 2}" y="{y}">{e(value)}</text></g></svg>'
    )
