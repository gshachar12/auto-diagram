
from src.rendering_engine import AttackDiagram



if __name__ == "__main__":
    # 1. Initialize the general diagram container
    diagram = AttackDiagram(
        width=3000, height=1000,
        title="ARP Spoofing MITM",
        desc="Compact sequence diagram showing the three core phases of an ARP spoofing MITM attack."
    )

    # 2. Populate Actors
    diagram.add_actor(Actor(150, "Victim", "192.168.1.104", "#eaf3de", "#639922", "laptop", lifeline_color="#639922"))
    diagram.add_actor(Actor(416, "Kali-Attacker", "192.168.1.1", "#fcebeb", "#a32d2d", "evil", lifeline_color="#f09595"))
    diagram.add_actor(Actor(682, "Gateway Router", "IP: 192.168.1.1", "#e6f1fb", "#185fa5", "router", lifeline_color="#85b7eb"))
    diagram.add_actor(Actor(900, "Public Server", "reddit.com · CDN", "#faeeda", "#854f0b", "server", lifeline_color="#fac775"))
    diagram.add_actor(Actor(950, "Giraffe", "reddit.com · CDN", "#0004ff", "#d38b33", "giraffe", lifeline_color="#fac775"))

    # 3. Build Phase 1
    p1 = Phase(1, 120, 230, "Phase 1", ["Legitimate Baseline", "Initial Connection"], "#639922", "#f6fbf0")
    p1.add(
        p1.step(
            150, 25,
            badge_at=(0, 0, 1),
            arrows=[p1.arrow(x1=10, y1=0, x2=522, y2=0)],
            labels=[Label(200, -6, "ARP Request: Who has 192.168.1.1?", cls="pkt-text", fill="#27500a")],
            noteboxes=[p1.note(
                182, 0, 178, 52, stroke_width=1.2,
                lines=[
                    Label(271, 18, "Connection to Router", anchor="middle", font_family="'Segoe UI',sans-serif", font_size=13, font_weight=600, fill="#27500a"),
                    Label(271, 33, "Broadcasts for IP address", anchor="middle", font_family="'Segoe UI',sans-serif", font_size=12, fill="#3d3d3a"),
                    Label(271, 46, "CHADDR = 08:00:27:b8:b7:58", anchor="middle", font_family="'Segoe UI',sans-serif", font_size=11, fill="#639922"),
                ],
            )],
        ),
        p1.step(
            682, 65,
            arrows=[p1.arrow(x1=-10, y1=0, x2=-522, y2=0, dashed="3 1")],
            labels=[Label(-260, -6, "ARP Reply: 192.168.1.1 is [MAC A]", anchor="middle", cls="pkt-text", fill="#27500a")],
        ),
        p1.note(
            710, 20, 170, 60, shape="fold", corner="top-right",
            lines=[
                Label(10, 18, "Victim Cache:", cls="info-title"),
                Label(10, 35, "from: [Router IP] -> [MAC A]", cls="info-body"),
                Label(10, 48, "(Legitimate State Entry)", cls="info-body", fill="#639922"),
            ],
        ),
    )
    diagram.add_phase(p1)

    # 4. Build Phase 2
    p2 = Phase(2, 250, 380, "Phase 2", ["(ARP Poisoning)", "(The Core)"], "#a32d2d", "#fff5f5")
    p2.add(
        p2.step(
            416, 35,
            badge_at=(-255, -10, 2),
            arrows=[p2.arrow(path="M 0,0 L -10,0 L -10,20 L -256,20", width=2)],
            labels=[Label(-130, 12, "FORGED ARP Reply: 192.168.1.1 is [MAC B] (Attacker MAC)", anchor="middle", cls="pkt-text", fill="#501313")],
        ),
        p2.step(
            416, 75,
            badge_at=(0, -1, 3),
            arrows=[
                p2.arrow(x1=10, y1=0, x2=256, y2=0, width=2),
                p2.arrow(path="M5,10 A8,8 0 1,1 -5,10", width=1.2),
            ],
            labels=[
                Label(15, -16, "The Attack", cls="info-title", fill="#a32d2d"),
                Label(130, -6, "FORGED ARP Reply: [Victim IP] is [MAC B]", anchor="middle", cls="pkt-text", fill="#501313"),
                Label(15, 15, "Refresh every ~30s", cls="node-sub", font_weight="bold", fill="#a32d2d"),
            ],
        ),
        p2.note(
            710, 25, 275, 80, shape="fold", stroke_width=1.5,
            lines=[
                Label(10, 18, "POISONED CACHES:", cls="info-title", fill="#501313"),
                Label(10, 38, "Victim: [Router IP] -> [MAC B] (Attacker)", cls="info-body", font_weight="bold"),
                Label(10, 54, "Gateway: [Victim IP] -> [MAC B] (Attacker)", cls="info-body", font_weight="bold"),
                Label(10, 70, "✔ MITM Path Execution Established", cls="info-body", fill="#a32d2d"),
            ],
        ),
    )
    diagram.add_phase(p2)

    # 5. Build Phase 3
    p3 = Phase(3, 400, 540, "Phase 3", ["(Interception)"], "#185fa5", "#f0f6fc")
    p3.add(
        p3.step(
            150, 30,
            badge_at=(-12, 0, 4),
            arrows=[p3.arrow(x1=0, y1=0, x2=256, y2=0)],
            labels=[Label(110, -6, "DNS Query (addressed to Gateway)", anchor="middle", cls="pkt-text", fill="#042c53")],
        ),
        p3.step(
            416, 30,
            badge_at=(12, -15, 5),
            arrows=[p3.arrow(x1=0, y1=0, x2=256, y2=0, dashed="3 3")],
            labels=[Label(26, -11, "Forwarded Query", cls="info-title", fill="#185fa5")],
        ),
        p3.note(
            425, 45, 510, 35, shape="fold", corner="top-left",
            lines=[
                Label(15, 15, "Intercepted Traffic Callout (Kali Sees):", cls="info-title"),
                Label(15, 27, "QNAME: debian.pool.ntp.org | reddit.com | SNI: reddit.com | Payload: (ENCRYPTED)", cls="info-body", font_family="monospace", fill="#a32d2d"),
            ],
        ),
        p3.step(
            416, 105,
            badge_at=(-12, -15, 6),
            arrows=[
                p3.arrow(x1=0, y1=0, x2=-256, y2=0, dashed="3 3"),
                p3.arrow(x1=266, y1=0, x2=474, y2=0),
            ],
            labels=[
                Label(2, -11, "Intercepted Reply, Forwarded", cls="info-title", fill="#185fa5"),
                Label(240, -6, "Web Traffic (HTTP/HTTPS) Intercepted & Forwarded", anchor="middle", cls="pkt-text", fill="#042c53"),
                Label(240, 12, "Metadata Leak: Attacker sees SNI & ALPN", anchor="middle", cls="node-sub", font_weight="bold", fill="#555555"),
            ],
        ),
    )
    diagram.add_phase(p3)

    # 6. Build Footer
    diagram.set_footer(NoteBox(
        tx=10, ty=555, width=980, height=32, shape="rect", rx=4,
        stroke="#854f0b", stroke_width=1, fill="#faeeda",
        lines=[Label(490, 20, "MITM Goal Achieved: All traffic transparently proxy'd through Attacker.",
                     anchor="middle", font_family="'Segoe UI',sans-serif", font_size=12, font_weight="bold", fill="#412402")],
    ))

    # 7. Generate and output the SVG
    svg = diagram.build_svg()
    out_path = "arp_spoofing_mitm.svg"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"Wrote {out_path}")
    
    # open svg file in default browser
    import webbrowser   
    webbrowser.open(out_path)