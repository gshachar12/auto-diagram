"""
Best-effort actor icon lookup.

Maps an actor's `role` string to an icon image URL + a D2 built-in shape
by keyword match. Icons are served from img.icons8.com's "color" style at
96px (https://img.icons8.com/color/96/<name>.png) -- the filenames below
(evil, laptop, router, server, ...) are the same ones already confirmed
working in the reference diagram this was matched against, so they're a
safer bet than a guessed CDN path. Swap any entry below for your own
hosted/verified icon any time; nothing else in the Visualizer needs to
change.

The `shape` half of each entry (person/cloud/cylinder/hexagon/rectangle)
is a D2 built-in -- not fetched over the network -- so even if an icon URL
ever breaks, actors still end up visually distinguished by silhouette, not
just by color.
"""
from __future__ import annotations

from typing import Optional

_ICONS8_BASE = "https://img.icons8.com/color/96/"

# (keywords matched against role.lower() + description_ref.lower(), icons8 filename, D2 shape)
# First matching row wins -- keep more specific keywords above generic ones.
_ROLE_ICON_RULES: list[tuple[tuple[str, ...], str, str]] = [
    (("attacker", "adversary", "threat actor", "intruder", "malicious", "hacker"),
     "evil.png", "person"),
    (("c2", "command and control", "command & control", "beacon"),
     "cloud.png", "cloud"),
    (("victim", "target", "compromised"),
     "laptop.png", "person"),
    (("database", "db"),
     "database.png", "cylinder"),
    (("firewall", "gateway", "router", "network device", "switch"),
     "router.png", "hexagon"),
    (("server", "host", "endpoint", "workstation", "machine"),
     "server.png", "rectangle"),
    (("client", "user"),
     "user.png", "person"),
]

_DEFAULT_ICON_FILE = "user.png"
_DEFAULT_SHAPE = "person"


def icon_and_shape_for_role(role: Optional[str], description_ref: Optional[str] = None) -> tuple[str, str]:
    """Returns (icon_url, d2_shape) for an actor, matched best-effort against its role/description."""
    haystack = f"{role or ''} {description_ref or ''}".lower()
    for keywords, icon_file, shape in _ROLE_ICON_RULES:
        if any(k in haystack for k in keywords):
            return _ICONS8_BASE + icon_file, shape
    return _ICONS8_BASE + _DEFAULT_ICON_FILE, _DEFAULT_SHAPE

