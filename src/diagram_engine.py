#!/usr/bin/env python3
"""
Generates an educational sequence-diagram SVG illustrating the *concept*
of an ARP-spoofing MITM scenario (actors, phases, message flow).
This script only draws shapes/text - it performs no network actions
and contains no attack code.
"""

WIDTH, HEIGHT = 1002, 780

ACTORS = [
    {"x": 130, "name": "Victim",         "sub": "192.168.1.104", "box": "#eaf3de", "stroke": "#639922", "name_c": "#2a4a0a", "sub_c": "#3b6d11", "icon": "https://img.icons8.com/color/96/laptop.png"},
    {"x": 390, "name": "Attacker (Kali)","sub": "192.168.1.105", "box": "#fcebeb", "stroke": "#a32d2d", "name_c": "#501313", "sub_c": "#a32d2d", "icon": "https://img.icons8.com/color/96/evil.png"},
    {"x": 660, "name": "Gateway",        "sub": "192.168.1.1",   "box": "#e6f1fb", "stroke": "#185fa5", "name_c": "#042c53", "sub_c": "#185fa5", "icon": "https://img.icons8.com/color/96/router.png"},
    {"x": 900, "name": "Public Server",  "sub": "reddit.com / gql", "box": "#fff8ee", "stroke": "#854f0b", "name_c": "#412402", "sub_c": "#854f0b", "icon": "https://img.icons8.com/color/96/server.png"},
]

PHASES = [
    {"y0": 110, "y1": 240, "color": "#639922", "bg": "#eaf3de", "title": "Phase 1", "sub": ["Legitimate", "Baseline"]},
    {"y0": 248, "y1": 430, "color": "#a32d2d", "bg": "#fff5f5", "title": "Phase 2", "sub": ["ARP Spoofing", "Execution"]},
    {"y0": 438, "y1": 700, "color": "#185fa5", "bg": "#f0f6fc", "title": "Phase 3", "sub": ["Traffic", "Interception", "& Sniffing"]},
]

# (badge_x, badge_y, badge_num, x1,y1,x2,y2, color, label_main, label_sub, dashed)
MESSAGES = [
    (390, 128, "1.1", 398, 130, 652, 147, "#639922", "DHCP Request → assigned 192.168.1.105", None, False),
    (660, 163, "1.2", 652, 163, 398, 175, "#639922", "ARP: who has 192.168.1.105?", None, False),
    (130, 200, "1.3", 138, 198, 382, 188, "#639922", "ARP: who has 192.168.1.1? (broadcast)", None, False),

    (390, 272, "2.1", 382, 274, 138, 292, "#a32d2d", "FORGED ARP Reply → Victim", '"192.168.1.1 is at 08:00:27:2d:f8:5a"', False),
    (390, 325, "2.2", 398, 327, 652, 344, "#a32d2d", "FORGED ARP Reply → Gateway", '"192.168.1.104 is at 08:00:27:2d:f8:5a"', False),

    (130, 462, "3.1", 138, 460, 382, 470, "#185fa5", "DNS Query (UDP/53) — addressed to gateway", None, False),
    (400, 476, None,  400, 476, 652, 488, "#185fa5", None, "Forwarded to real gateway (transparent)", True),

    (130, 530, "3.2", 138, 528, 382, 540, "#185fa5", "HTTP/HTTPS → reddit.com / gql.reddit.com", None, False),
    (398, 545, None,  398, 545, 652, 556, "#185fa5", None, "→ gateway → internet", True),
    (660, 556, None,  660, 556, 888, 568, "#854f0b", None, "→ server", True),

    (900, 608, "3.3", 892, 606, 398, 618, "#185fa5", "TLS Client Hello (clear-text header) + DigiCert cert", None, False),
    (382, 622, None,  382, 622, 138, 610, "#185fa5", None, "TLS response relayed to victim", True),
]


def svg_header():
    return f'''<svg width="100%" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" xmlns="http://www.w3.org/2000/svg">
<title>ARP Spoofing MITM</title>
<desc>Three-phase sequence diagram of an ARP spoofing MITM attack showing directionality between actors.</desc>
<defs>
  <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>
  <marker id="arrow-dash" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>
  <style>
    svg {{ font-family: 'Segoe UI', Helvetica, Arial, sans-serif; }}
    .actor-name {{ font-size:10px; font-weight:700; text-anchor:middle; }}
    .actor-ip   {{ font-size:8px;  text-anchor:middle; }}
    .lifeline   {{ stroke-width:1; stroke-dasharray:4 4; }}
    .phase-label{{ fill:#fff; text-anchor:middle; }}
    .phase-title{{ font-size:12px; font-weight:700; }}
    .phase-sub  {{ font-size:9px; }}
    .phase-bg   {{ opacity:0.4; }}
    .badge-label{{ fill:#fff; font-size:9px; font-weight:700; text-anchor:middle; }}
    .lbl        {{ text-anchor:middle; }}
    .lbl-main   {{ font-size:11px; font-weight:600; }}
    .lbl-sub    {{ font-size:10px; }}
    .annot-box  {{ fill:#fff; rx:3; }}
    .annot-title{{ font-size:9px; font-weight:700; fill:#333; }}
    .annot-mono {{ font-size:9px; font-family:monospace; fill:#501313; }}
    .poison-bar {{ fill:#fff0f0; stroke:#a32d2d; stroke-width:0.8; rx:3; }}
    .poison-label{{ font-size:9px; }}
    .footer-box {{ fill:#faeeda; stroke:#854f0b; stroke-width:1; rx:4; }}
    .footer-text{{ font-size:12px; font-weight:700; fill:#412402; text-anchor:middle; }}
  </style>
</defs>
<text x="500" y="26" text-anchor="middle" font-size="18" font-weight="700" fill="#1a1a1a">ARP Spoofing MITM</text>
'''


def actor_boxes():
    out = []
    for a in ACTORS:
        out.append(f'''<g transform="translate({a["x"]},42)">
  <rect x="-55" y="0" width="110" height="52" rx="6" fill="{a["box"]}" stroke="{a["stroke"]}" stroke-width="1.5"/>
  <image href="{a["icon"]}" x="-18" y="2" width="36" height="36"/>
  <text x="0" y="42" class="actor-name" fill="{a["name_c"]}">{a["name"]}</text>
  <text x="0" y="49" class="actor-ip" fill="{a["sub_c"]}">{a["sub"]}</text>
</g>''')
    return "\n".join(out)


def lifelines():
    colors = ["#639922", "#f09595", "#85b7eb", "#fac775"]
    out = []
    for a, c in zip(ACTORS, colors):
        out.append(f'<line x1="{a["x"]}" y1="97" x2="{a["x"]}" y2="730" class="lifeline" stroke="{c}"/>')
    return "\n".join(out)


def phase_sidebars():
    out = []
    for p in PHASES:
        out.append(f'<rect x="8" y="{p["y0"]}" width="112" height="{p["y1"]-p["y0"]}" rx="6" fill="{p["color"]}"/>')
        ty = p["y0"] + 45
        out.append(f'<text x="64" y="{ty}" class="phase-label phase-title">{p["title"]}</text>')
        for i, line in enumerate(p["sub"]):
            out.append(f'<text x="64" y="{ty+15+12*i}" class="phase-label phase-sub">{line}</text>')
        out.append(f'<rect x="122" y="{p["y0"]}" width="870" height="{p["y1"]-p["y0"]}" class="phase-bg" fill="{p["bg"]}"/>')
        out.append(f'<line x1="8" y1="{p["y1"]}" x2="992" y2="{p["y1"]}" stroke="{p["color"]}" stroke-width="0.5" stroke-dasharray="4 2"/>')
    return "\n".join(out)


def messages():
    out = []
    for bx, by, num, x1, y1, x2, y2, color, main, sub, dashed in MESSAGES:
        marker = "arrow-dash" if dashed else "arrow"
        dash_attr = ' stroke-dasharray="4 3"' if dashed else ""
        if num is not None:
            out.append(f'<circle cx="{bx}" cy="{by}" r="8" fill="{color}"/>')
            out.append(f'<text x="{bx}" y="{by+4}" class="badge-label">{num}</text>')
        out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="1.5" fill="none"{dash_attr} marker-end="url(#{marker})"/>')
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 5
        if main:
            out.append(f'<text x="{mx}" y="{my}" class="lbl lbl-main" fill="{color}">{main}</text>')
        if sub:
            yoff = my + 13 if main else my
            out.append(f'<text x="{mx}" y="{yoff}" class="lbl lbl-sub" fill="{color}">{sub}</text>')
    return "\n".join(out)


def annotations():
    return '''
<rect x="700" y="112" width="282" height="54" rx="4" class="annot-box" stroke="#639922" stroke-width="1"/>
<polygon points="700,132 692,137 700,142" fill="#639922"/>
<text x="714" y="128" class="annot-title">Victim cache (legitimate):</text>
<text x="714" y="141" class="annot-mono" style="fill:#333">192.168.1.1 → MAC-A (real gateway)</text>
<text x="714" y="154" class="annot-mono" style="fill:#639922">✓ Normal ARP state</text>

<circle cx="390" cy="375" r="8" fill="#a32d2d"/>
<text x="390" y="379" class="badge-label">2.3</text>
<path d="M398,375 C430,368 430,388 398,382" stroke="#a32d2d" stroke-width="2" fill="none" marker-end="url(#arrow)"/>
<text x="456" y="370" class="lbl-main" fill="#791f1f">ip_forward=1 (pre-configured) — transparent relay</text>
<text x="456" y="382" class="lbl-sub" fill="#555">All packets relayed to true destination → victim stays online</text>
<text x="456" y="394" class="lbl-sub" fill="#854f0b">Gratuitous ARP replayed every ~30 s to keep caches poisoned</text>

<rect x="122" y="410" width="868" height="14" rx="3" class="poison-bar"/>
<text x="132" y="420" class="poison-label" font-weight="700" fill="#333">Poisoned: </text>
<text x="186" y="420" class="poison-label" fill="#333">Victim: 192.168.1.1→08:00:27:2d:f8:5a  |  Gateway: 192.168.1.104→08:00:27:2d:f8:5a</text>
<text x="860" y="420" class="poison-label" font-weight="700" fill="#333">✔ MITM active</text>

<rect x="400" y="432" width="268" height="22" rx="3" class="annot-box" stroke="#185fa5" stroke-width="0.8"/>
<text x="410" y="440" class="annot-title">Plain-text intercept:</text>
<text x="410" y="451" class="annot-mono">QNAME: reddit.com | debian.pool.ntp.org</text>

<rect x="400" y="502" width="268" height="22" rx="3" class="annot-box" stroke="#185fa5" stroke-width="0.8"/>
<text x="410" y="510" class="annot-title">All packets captured &amp; saved</text>
<text x="410" y="521" class="annot-mono">SNI: reddit.com | gql.reddit.com (high volume)</text>

<rect x="350" y="632" width="480" height="46" rx="4" class="annot-box" stroke="#185fa5" stroke-width="1"/>
<text x="360" y="645" class="annot-title">Attacker reads from TLS Client Hello (unencrypted fields):</text>
<text x="360" y="657" class="annot-mono">SNI → reddit.com, gql.reddit.com  |  ALPN → h2 (HTTP/2)  |  DigiCert cert intercepted (public)</text>
<text x="360" y="669" class="annot-mono">Payload: [ENCRYPTED — cannot decrypt without private key]</text>
'''


def footer():
    return '''
<rect x="8" y="710" width="984" height="30" rx="4" class="footer-box"/>
<text x="500" y="730" class="footer-text">MITM goal achieved — all traffic transparently proxied through Attacker. DNS &amp; TLS SNI exposed; payload remains encrypted.</text>
'''


def build_svg():
    parts = [
        svg_header(),
        actor_boxes(),
        lifelines(),
        phase_sidebars(),
        messages(),
        annotations(),
        footer(),
        "</svg>",
    ]
    return "\n".join(parts)


if __name__ == "__main__":
    svg = build_svg()
    out_path = "arp_spoofing_mitm.svg"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"Wrote {out_path}")