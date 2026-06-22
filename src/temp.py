import os
import webbrowser
import urllib.parse

# 1. Draw.io XML Data
drawio_xml = """<mxGraphModel>
  <root>
    <mxCell id="0" />
    <mxCell id="1" parent="0" />

    <mxCell id="attacker" value="Attacker Client" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffccb3;strokeColor=none;fontStyle=1;fontSize=16;fontColor=#333333;" vertex="1" parent="1">
      <mxGeometry x="50" y="20" width="200" height="50" as="geometry" />
    </mxCell>
    <mxCell id="resolver" value="Recursive Resolver" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffccb3;strokeColor=none;fontStyle=1;fontSize=16;fontColor=#333333;" vertex="1" parent="1">
      <mxGeometry x="350" y="20" width="200" height="50" as="geometry" />
    </mxCell>
    <mxCell id="servers" value="Servers" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#ffccb3;strokeColor=none;fontStyle=1;fontSize=16;fontColor=#333333;" vertex="1" parent="1">
      <mxGeometry x="650" y="20" width="200" height="50" as="geometry" />
    </mxCell>

    <mxCell id="v_line1" value="" style="endArrow=none;html=1;rounded=0;dashed=1;dashPattern=6 6;strokeWidth=2;strokeColor=#888888;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="300" y="460" as="sourcePoint" />
        <mxPoint x="300" y="20" as="targetPoint" />
      </mxGeometry>
    </mxCell>
    <mxCell id="v_line2" value="" style="endArrow=none;html=1;rounded=0;dashed=1;dashPattern=6 6;strokeWidth=2;strokeColor=#888888;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="600" y="460" as="sourcePoint" />
        <mxPoint x="600" y="20" as="targetPoint" />
      </mxGeometry>
    </mxCell>

    <mxCell id="p1_text" value="Phase 1: Query" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontStyle=1;fontSize=14;fontColor=#666666;" vertex="1" parent="1">
      <mxGeometry x="60" y="130" width="120" height="30" as="geometry" />
    </mxCell>
    <mxCell id="block_lrr" value="Inferred LRR" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#4d94ff;strokeWidth=1.5;fontSize=13;fontColor=#333333;" vertex="1" parent="1">
      <mxGeometry x="375" y="110" width="150" height="50" as="geometry" />
    </mxCell>
    <mxCell id="arrow1" value="① DNS Request" style="endArrow=classic;html=1;rounded=0;strokeColor=#4d94ff;strokeWidth=2;labelBackgroundColor=#ffffff;fontColor=#4d94ff;fontStyle=1;fontSize=12;" edge="1" parent="1" source="attacker" target="block_lrr">
      <mxGeometry relative="1" as="geometry">
        <mxPoint x="150" y="135" as="sourcePoint" />
        <mxPoint x="375" y="135" as="targetPoint" />
        <Array as="points">
          <mxPoint x="250" y="135" />
        </Array>
      </mxGeometry>
    </mxCell>
    <mxCell id="h_line1" value="" style="endArrow=none;html=1;rounded=0;dashed=1;dashPattern=4 4;strokeWidth=1.5;strokeColor=purple;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="20" y="190" as="sourcePoint" />
        <mxPoint x="880" y="190" as="targetPoint" />
      </mxGeometry>
    </mxCell>

    <mxCell id="p2_text" value="Phase 2: Attack" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontStyle=1;fontSize=14;fontColor=#666666;" vertex="1" parent="1">
      <mxGeometry x="60" y="260" width="120" height="30" as="geometry" />
    </mxCell>
    <mxCell id="block_evidence" value="Evidence: Pkt #3" style="rounded=1;whiteSpace=wrap;html=1;fillColor=#e6f2ff;strokeColor=#4d94ff;strokeWidth=1.5;fontSize=13;fontColor=#333333;" vertex="1" parent="1">
      <mxGeometry x="675" y="240" width="150" height="50" as="geometry" />
    </mxCell>
    <mxCell id="arrow2" value="② Referral Query" style="endArrow=classic;html=1;rounded=0;strokeColor=#4d94ff;strokeWidth=2;labelBackgroundColor=#ffffff;fontColor=#4d94ff;fontStyle=1;fontSize=12;" edge="1" parent="1" source="resolver" target="block_evidence">
      <mxGeometry relative="1" as="geometry">
        <mxPoint x="450" y="265" as="sourcePoint" />
        <mxPoint x="675" y="265" as="targetPoint" />
        <Array as="points">
          <mxPoint x="560" y="265" />
        </Array>
      </mxGeometry>
    </mxCell>
    <mxCell id="h_line2" value="" style="endArrow=none;html=1;rounded=0;dashed=1;dashPattern=4 4;strokeWidth=1.5;strokeColor=purple;" edge="1" parent="1">
      <mxGeometry width="50" height="50" relative="1" as="geometry">
        <mxPoint x="20" y="320" as="sourcePoint" />
        <mxPoint x="880" y="320" as="targetPoint" />
      </mxGeometry>
    </mxCell>

    <mxCell id="p3_text" value="Phase 3: Response" style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;rounded=0;fontStyle=1;fontSize=14;fontColor=#666666;" vertex="1" parent="1">
      <mxGeometry x="60" y="390" width="140" height="30" as="geometry" />
    </mxCell>
    <mxCell id="arrow3" value="③ Authoritative Ans" style="endArrow=classic;html=1;rounded=0;strokeColor=#ff4d4d;strokeWidth=2;labelBackgroundColor=#ffffff;fontColor=#ff4d4d;fontStyle=1;fontSize=12;" edge="1" parent="1" source="servers" target="resolver">
      <mxGeometry relative="1" as="geometry">
        <mxPoint x="750" y="395" as="sourcePoint" />
        <mxPoint x="450" y="395" as="targetPoint" />
        <Array as="points">
          <mxPoint x="600" y="395" />
        </Array>
      </mxGeometry>
    </mxCell>
  </root>
</mxGraphModel>"""

# Clean and escape XML for the viewer JSON config
cleaned_xml = "".join([line.strip() for line in drawio_xml.splitlines()])
escaped_xml = cleaned_xml.replace('"', '&quot;')

# 2. Build a valid Draw.io Exportable SVG representation
# This format allows browsers to natively render the elements while keeping Draw.io metadata intact
svg_data = f"""<svg viewBox="0 0 900 600" xmlns="http://www.w3.org/2000/svg">
  <!-- Title -->
  <g>
    <text x="450" y="24" font-size="20" text-anchor="middle" font-weight="bold" fill="#111">NRDelegationAttack Sequence (Observed Packets Aggregated)</text>
    <text x="450" y="44" font-size="12" text-anchor="middle" fill="#333">Focus: k-limited chunks, delegation-triggered restarts, repeated CC(n) cache/ADB scans</text>
  </g>

  <!-- Column centers -->
  <!-- Client:100, Resolver:260, Malicious Auth:420, Delegation:580, NR NS:740 -->

  <!-- Participant headers -->
  <g>
    <rect x="20" y="60" width="160" height="60" fill="#e8f0fe" stroke="#5f6368"/>
    <image href="/assets/client.png" x="28" y="68" width="32" height="32"/>
    <text x="100" y="86" font-size="18" text-anchor="middle" font-weight="bold" fill="#111">Client</text>
    <text x="100" y="104" font-size="11" text-anchor="middle" fill="#333">127.0.0.1 (stub)</text>
  </g>

  <g>
    <rect x="180" y="60" width="160" height="60" fill="#e8f5e9" stroke="#2e7d32"/>
    <image href="/assets/dns.png" x="188" y="68" width="32" height="32"/>
    <text x="260" y="86" font-size="18" text-anchor="middle" font-weight="bold" fill="#111">Recursive Resolver</text>
    <text x="260" y="104" font-size="11" text-anchor="middle" fill="#333">127.0.0.1</text>
  </g>

  <g>
    <rect x="340" y="60" width="160" height="60" fill="#ffebee" stroke="#c62828"/>
    <image href="/assets/dns_auth.png" x="348" y="68" width="32" height="32"/>
    <text x="420" y="86" font-size="18" text-anchor="middle" font-weight="bold" fill="#111">Malicious Authoritative</text>
    <text x="420" y="104" font-size="11" text-anchor="middle" fill="#333">127.0.0.89 (LRR)</text>
  </g>

  <g>
    <rect x="500" y="60" width="160" height="60" fill="#fff8e1" stroke="#f57f17"/>
    <image href="/assets/dns_auth.png" x="508" y="68" width="32" height="32"/>
    <text x="580" y="86" font-size="18" text-anchor="middle" font-weight="bold" fill="#111">Delegation Server</text>
    <text x="580" y="104" font-size="11" text-anchor="middle" fill="#333">127.0.0.2</text>
  </g>

  <g>
    <rect x="660" y="60" width="160" height="60" fill="#f3e5f5" stroke="#6a1b9a"/>
    <image href="/assets/server.png" x="668" y="68" width="32" height="32"/>
    <text x="740" y="86" font-size="18" text-anchor="middle" font-weight="bold" fill="#111">NR NS Endpoints</text>
    <text x="740" y="104" font-size="11" text-anchor="middle" fill="#333">ns28..ns51.* (no reply)</text>
  </g>

  <!-- Lifelines -->
  <line x1="100" y1="120" x2="100" y2="560" stroke="#9e9e9e"/>
  <line x1="260" y1="120" x2="260" y2="560" stroke="#9e9e9e"/>
  <line x1="420" y1="120" x2="420" y2="560" stroke="#9e9e9e"/>
  <line x1="580" y1="120" x2="580" y2="560" stroke="#9e9e9e"/>
  <line x1="740" y1="120" x2="740" y2="560" stroke="#9e9e9e"/>

  <!-- Phase bands -->
  <g>
    <rect x="20" y="120" width="860" height="60" fill="#fafafa" stroke="#e0e0e0"/>
    <text x="30" y="136" font-size="12" fill="#616161">Phase 1: Trigger & LRR delivery</text>
  </g>
  <g>
    <rect x="20" y="190" width="860" height="70" fill="#fafafa" stroke="#e0e0e0"/>
    <text x="30" y="206" font-size="12" fill="#616161">Phase 2: k-chunked NS-name resolutions + CC(n) scan</text>
  </g>
  <g>
    <rect x="20" y="270" width="860" height="70" fill="#fafafa" stroke="#e0e0e0"/>
    <text x="30" y="286" font-size="12" fill="#616161">Phase 3: Delegations trigger restart events</text>
  </g>
  <g>
    <rect x="20" y="350" width="860" height="70" fill="#fafafa" stroke="#e0e0e0"/>
    <text x="30" y="366" font-size="12" fill="#616161">Phase 4: Expanding loop (k, k², k³ …)</text>
  </g>
  <g>
    <rect x="20" y="430" width="860" height="70" fill="#fafafa" stroke="#e0e0e0"/>
    <text x="30" y="446" font-size="12" fill="#616161">Phase 5: Waiting on NR targets; safety counters</text>
  </g>

  <!-- Step cards -->
  <!-- Step 1 -->
  <g>
    <a href="javascript:window.top.location.href='/?focus_step=1'">
      <rect x="215" y="128" width="90" height="40" fill="#e3f2fd" stroke="#64b5f6"/>
      <title>Step 1️⃣ • Pkt #2
Client → Resolver: attack0.home.lan</title>
    </a>
    <text x="260" y="144" font-size="12" text-anchor="middle" fill="#0d47a1">
      <tspan x="260" dy="0">1️⃣ Client → VRR</tspan>
      <tspan x="260" dy="14">Query attack0.home.lan</tspan>
    </text>
  </g>

  <!-- Client to Resolver packet line -->
  <a href="javascript:window.top.location.href='/?focus_step=1'">
    <line x1="100" y1="148" x2="260" y2="148" stroke="#1976d2">
      <title>Evidence: Pkt #2 (DNS_QUERY attack0.home.lan)</title>
    </line>
  </a>

  <!-- Step 2: Resolver -> Malicious Auth (LRR) -->
  <g>
    <a href="javascript:window.top.location.href='/?focus_step=2'">
      <rect x="375" y="128" width="90" height="40" fill="#ffebee" stroke="#ef9a9a"/>
      <title>Step 2️⃣ • Pkts #3, #27
Resolver → Malicious Authoritative
LRR (n NS, no glue) inferred</title>
    </a>
    <text x="420" y="144" font-size="12" text-anchor="middle" fill="#b71c1c">
      <tspan x="420" dy="0">2️⃣ VRR ↔ LRR</tspan>
      <tspan x="420" dy="14">n NS w/o glue</tspan>
    </text>
  </g>
  <a href="javascript:window.top.location.href='/?focus_step=2'">
    <line x1="260" y1="160" x2="420" y2="160" stroke="#d32f2f">
      <title>Resolver → Malicious Auth: Pkts #3, #27 (LRR implied)</title>
      <animate attributeName="stroke-width" values="2;5;2" dur="2s" repeatCount="indefinite"/>
    </line>
  </a>

  <!-- Step 3: CC(n) cache/ADB scan -->
  <g>
    <a href="javascript:window.top.location.href='/?focus_step=3'">
      <rect x="215" y="198" width="180" height="46" fill="#e8f5e9" stroke="#81c784"/>
      <title>Step 3️⃣ • Inferred from subsequent ns* lookups
VRR scans cache/ADB for n NS names: cost CC(n)</title>
    </a>
    <text x="305" y="214" font-size="12" text-anchor="middle" fill="#1b5e20">
      <tspan x="305" dy="0">3️⃣ VRR cache/ADB scan</tspan>
      <tspan x="305" dy="14">Compute cost CC(n)</tspan>
    </text>
  </g>

  <!-- Step 4: First k-chunk to Delegation Server -->
  <g>
    <a href="javascript:window.top.location.href='/?focus_step=4'">
      <rect x="520" y="198" width="120" height="46" fill="#fff8e1" stroke="#ffd54f"/>
      <title>Step 4️⃣ • Pkts #5–#24; Delegation responses #8–#10
VRR resolves first k names (ns28..ns32) via 127.0.0.2</title>
    </a>
    <text x="580" y="214" font-size="12" text-anchor="middle" fill="#e65100">
      <tspan x="580" dy="0">4️⃣ First k chunk</tspan>
      <tspan x="580" dy="14">ns28..ns32</tspan>
    </text>
  </g>
  <!-- Aggregated query lines to Delegation server -->
  <a href="javascript:window.top.location.href='/?focus_step=4'">
    <line x1="260" y1="206" x2="580" y2="206" stroke="#f57f17">
      <title>VRR → Delegation: Pkts #5, #6, #7, #11, #13, #15, #17, #19, #21, #23, #24</title>
    </line>
  </a>
  <!-- Delegation responses causing restart -->
  <a href="javascript:window.top.location.href='/?focus_step=5'">
    <line x1="580" y1="228" x2="260" y2="228" stroke="#8d6e63">
      <title>Delegation responses (restart triggers): Pkts #8, #9, #10</title>
      <animate attributeName="stroke-opacity" values="0.3;1;0.3" dur="1.5s" repeatCount="indefinite"/>
    </line>
  </a>

  <!-- Step 5: Next chunk after restart -->
  <g>
    <a href="javascript:window.top.location.href='/?focus_step=5'">
      <rect x="215" y="278" width="180" height="46" fill="#e8f5e9" stroke="#81c784"/>
      <title>Step 5️⃣ • Pkts #81–#98
Restart clears referral-limit; VRR processes ns33..ns37 and rescans CC(n)</title>
    </a>
    <text x="305" y="294" font-size="12" text-anchor="middle" fill="#1b5e20">
      <tspan x="305" dy="0">5️⃣ Restart → next k</tspan>
      <tspan x="305" dy="14">ns33..ns37 + CC(n)</tspan>
    </text>
  </g>
  <a href="javascript:window.top.location.href='/?focus_step=5'">
    <line x1="260" y1="300" x2="580" y2="300" stroke="#f57f17">
      <title>VRR → Delegation: Pkts #81–#98 (ns33..ns37)</title>
    </line>
  </a>

  <!-- Step 6: Further expansion -->
  <g>
    <a href="javascript:window.top.location.href='/?focus_step=6'">
      <rect x="215" y="358" width="180" height="46" fill="#e8f5e9" stroke="#81c784"/>
      <title>Step 6️⃣ • Pkts #101–#119
Further expansion: ns38..ns42; accumulated (k + k²)·CC(n)</title>
    </a>
    <text x="305" y="374" font-size="12" text-anchor="middle" fill="#1b5e20">
      <tspan x="305" dy="0">6️⃣ k² wave</tspan>
      <tspan x="305" dy="14">ns38..ns42</tspan>
    </text>
  </g>
  <a href="javascript:window.top.location.href='/?focus_step=6'">
    <line x1="260" y1="380" x2="580" y2="380" stroke="#f57f17">
      <title>VRR → Delegation: Pkts #101–#119 (ns38..ns42)</title>
    </line>
  </a>

  <!-- Step 7: Another restart wave, incl. root '.' -->
  <g>
    <a href="javascript:window.top.location.href='/?focus_step=7'">
      <rect x="215" y="438" width="200" height="46" fill="#e8f5e9" stroke="#81c784"/>
      <title>Step 7️⃣ • Pkts #121–#141
Restart continues: ns43..ns47; root query '.' indicates re-walk</title>
    </a>
    <text x="315" y="454" font-size="12" text-anchor="middle" fill="#1b5e20">
      <tspan x="315" dy="0">7️⃣ k³ wave + '.' probe</tspan>
      <tspan x="315" dy="14">ns43..ns47 + root '.'</tspan>
    </text>
  </g>
  <a href="javascript:window.top.location.href='/?focus_step=7'">
    <line x1="260" y1="460" x2="580" y2="460" stroke="#f57f17">
      <title>VRR → Delegation: Pkts #121–#141 (ns43..ns47, '.')</title>
    </line>
  </a>

  <!-- Step 8: Next observed batch -->
  <g>
    <a href="javascript:window.top.location.href='/?focus_step=8'">
      <rect x="520" y="438" width="130" height="46" fill="#fff8e1" stroke="#ffd54f"/>
      <title>Step 8️⃣ • Pkts #143–#153
Subsequent batch ns48..ns51; NR targets still silent</title>
    </a>
    <text x="585" y="454" font-size="12" text-anchor="middle" fill="#e65100">
      <tspan x="585" dy="0">8️⃣ Next batch</tspan>
      <tspan x="585" dy="14">ns48..ns51</tspan>
    </text>
  </g>
  <a href="javascript:window.top.location.href='/?focus_step=8'">
    <line x1="260" y1="488" x2="580" y2="488" stroke="#f57f17">
      <title>VRR → Delegation: Pkts #143–#153 (ns48..ns51)</title>
    </line>
  </a>

  <!-- Implied attempts to NR endpoints (no responses captured) -->
  <a href="javascript:window.top.location.href='/?focus_step=9'">
    <line x1="260" y1="512" x2="740" y2="512" stroke="#6a1b9a" stroke-opacity="0.35">
      <title>Implied VRR → NR NS endpoints (no replies observed). Attack persists until safety counters.</title>
    </line>
  </a>

  <!-- Legend note -->
  <g>
    <image href="/assets/packet.png" x="24" y="520" width="16" height="16"/>
    <text x="46" y="533" font-size="11" fill="#424242">
      <tspan x="46" dy="0">Lines denote aggregated packet flows; hover for packet IDs.</tspan>
    </text>
  </g>
</svg>"""

# 3. HTML Layout wrapping both implementations
html_wrapper = f"""<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>DNS Sequence Diagram Showcase</title>
    <script type="text/javascript" src="https://viewer.diagrams.net/js/viewer-static.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 30px; background-color: #f9f9f9; }}
        .container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        h2 {{ color: #333; }}
        h3 {{ color: #555; margin-top: 0; }}
        hr {{ border: 0; border-top: 1px solid #eee; margin: 20px 0; }}
    </style>
</head>
<body>

    <h2>תצוגת דיאגרמת DNS המשופרת</h2>
    <p>להלן שתי שיטות תואמות להצגת הדיאגרמה שלך ישירות בדפדפן ובכלי Draw.io.</p>
    
    <hr>

    <div class="container">
        <h3>1. גרסת SVG נקייה (רינדור דפדפן טבעי)</h3>
        <p>גרסה זו רצה ישירות בכל דפדפן ללא צורך בסקריפטים חיצוניים:</p>
        <div style="overflow-x: auto;">
            {svg_data}
        </div>
    </div>

    <div class="container">
        <h3>2. רכיב Draw.io אינטראקטיבי (מתוקן)</h3>
        <p>רכיב ה-Viewer הרשמי שטוען את ה-XML ומאפשר ניווט/עריכה (דורש חיבור אינטרנט לסקריפט):</p>
        <div class="mxgraph" style="max-width:100%; border:1px solid #ddd; padding: 10px; border-radius: 4px;" 
             data-mxgraph="{{"highlight":"#0000ff","nav":true,"resize":true,"toolbar":"zoom edit download","edit":"https://app.diagrams.net/","xml":"{escaped_xml}"}}">
        </div>
    </div>

</body>
</html>"""

# 4. Save and launch
filename = "dns_diagram_showcase.html"
filepath = os.path.abspath(filename)

with open(filename, "w", encoding="utf-8") as file:
    file.write(html_wrapper)

print(f"הקובץ נוצר בהצלחה בנתיב: {filepath}")
print("פותח את הדף בדפדפן...")

webbrowser.open(f"file://{filepath}")