import streamlit as st
import json
import zlib
import base64
import re
import urllib.parse
import xml.etree.ElementTree as ET


SVG_NS = "http://www.w3.org/2000/svg"


def _sanitize_svg(svg_content: str) -> str:
    if not svg_content:
        return ""
    text = svg_content.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    return text


def _drawio_svg_url(svg_content: str) -> str:
    """Encode SVG as a draw.io URL (opens as flat image — quick preview)."""
    if not svg_content:
        return ""
    svg = _sanitize_svg(svg_content)
    data = svg.encode("utf-8")
    compressed = zlib.compress(data, level=9, wbits=-15)
    encoded = base64.b64encode(compressed).decode("ascii")
    return "https://app.diagrams.net/#R" + urllib.parse.quote(encoded, safe="")


# ── Helpers for native mxCell conversion ────────────────────────────────────

def _a(el, name, default=""):
    return el.attrib.get(name, el.attrib.get(f"{{{SVG_NS}}}{name}", default))

def _color(val):
    return val if val and val != "none" else "none"

def _sw(el):
    try: return float(_a(el, "stroke-width", "1"))
    except: return 1.0

def _opacity(el):
    try: return float(_a(el, "opacity", "1"))
    except: return 1.0

def _fs(el):
    try: return float(re.sub(r"[^\d.]", "", _a(el, "font-size", "12")))
    except: return 12.0

def _align(el):
    return {"start": "left", "middle": "center", "end": "right"}.get(
        _a(el, "text-anchor", "start"), "left")

def esc(s):
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _rect_cell(el, cid):
    x,y = float(_a(el,"x","0")), float(_a(el,"y","0"))
    w,h = float(_a(el,"width","10")), float(_a(el,"height","10"))
    rx   = _a(el,"rx","0")
    fill = _color(_a(el,"fill","#ffffff"))
    strk = _color(_a(el,"stroke","none"))
    sd   = _a(el,"stroke-dasharray","")
    op   = _opacity(el)
    arc  = min(50, int(float(rx)/min(w,h)*100)) if rx and rx != "0" else 0
    style = (
        f"{'rounded=1' if arc else 'rounded=0'};"
        + (f"arcSize={arc};" if arc else "")
        + f"fillColor={fill};strokeColor={strk};strokeWidth={_sw(el)};"
        + ("dashed=1;dashPattern=8 3;" if sd else "")
        + (f"opacity={int(op*100)};" if op < 1 else "")
    )
    return (f'<mxCell id="{cid}" value="" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')

def _circle_cell(el, cid):
    cx,cy,r = float(_a(el,"cx","0")), float(_a(el,"cy","0")), float(_a(el,"r","5"))
    fill = _color(_a(el,"fill","#ffffff"))
    strk = _color(_a(el,"stroke","none"))
    style = f"ellipse;fillColor={fill};strokeColor={strk};strokeWidth={_sw(el)};"
    return (f'<mxCell id="{cid}" value="" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{cx-r}" y="{cy-r}" width="{r*2}" height="{r*2}" as="geometry"/></mxCell>')

def _text_cell(el, cid):
    x,y   = float(_a(el,"x","0")), float(_a(el,"y","0"))
    fill  = _color(_a(el,"fill","#000000"))
    fs    = _fs(el)
    fw    = _a(el,"font-weight","400")
    align = _align(el)
    italic= _a(el,"font-style","") == "italic"
    bold  = fw in ("700","800","900","bold")
    db    = _a(el,"dominant-baseline","auto")
    text  = esc(el.text or "")
    h     = fs * 1.4
    ty    = y - h/2 if db == "central" else y - fs
    w     = 400
    tx    = x - w/2 if align == "center" else (x - w if align == "right" else x)
    fs_int= int(bold)*1 + int(italic)*2
    style = (f"text;html=1;align={align};verticalAlign=middle;"
             f"fillColor=none;strokeColor=none;fontColor={fill};"
             f"fontSize={fs};fontStyle={fs_int};")
    return (f'<mxCell id="{cid}" value="{text}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{tx}" y="{ty}" width="{w}" height="{h}" as="geometry"/></mxCell>')

def _line_cell(el, cid):
    x1,y1 = float(_a(el,"x1","0")), float(_a(el,"y1","0"))
    x2,y2 = float(_a(el,"x2","0")), float(_a(el,"y2","0"))
    strk  = _color(_a(el,"stroke","#000000"))
    sd    = _a(el,"stroke-dasharray","")
    m_end = _a(el,"marker-end","")
    style = (
        f"{'endArrow=block;endFill=1' if m_end else 'endArrow=none'};"
        f"strokeColor={strk};strokeWidth={_sw(el)};"
        + ("dashed=1;dashPattern=6 3;" if sd else "")
    )
    return (f'<mxCell id="{cid}" value="" style="{style}" edge="1" parent="1">'
            f'<mxGeometry relative="1" as="geometry">'
            f'<mxPoint x="{x1}" y="{y1}" as="sourcePoint"/>'
            f'<mxPoint x="{x2}" y="{y2}" as="targetPoint"/>'
            f'</mxGeometry></mxCell>')

def _path_cell(el, cid):
    d     = _a(el,"d","")
    strk  = _color(_a(el,"stroke","#000000"))
    sd    = _a(el,"stroke-dasharray","")
    m_end = _a(el,"marker-end","")
    fill  = _color(_a(el,"fill","none"))
    nums  = [float(n) for n in re.findall(r"[-\d.]+", d)]
    xs    = nums[0::2]; ys = nums[1::2]
    if not xs: return ""
    style = (f"curved=1;fillColor={fill};strokeColor={strk};strokeWidth={_sw(el)};"
             + ("dashed=1;dashPattern=6 3;" if sd else "")
             + ("endArrow=block;endFill=1;" if m_end else "endArrow=none;"))
    sx,sy = xs[0], ys[0]
    tx2,ty2 = (xs[-2] if len(xs) > 1 else xs[0]), (ys[-2] if len(ys) > 1 else ys[0])
    return (f'<mxCell id="{cid}" value="" style="{style}" edge="1" parent="1">'
            f'<mxGeometry relative="1" as="geometry">'
            f'<mxPoint x="{sx}" y="{sy}" as="sourcePoint"/>'
            f'<mxPoint x="{tx2}" y="{ty2}" as="targetPoint"/>'
            f'</mxGeometry></mxCell>')

def _image_cell(el, cid):
    x,y = float(_a(el,"x","0")), float(_a(el,"y","0"))
    w,h = float(_a(el,"width","20")), float(_a(el,"height","20"))
    href = _a(el,"href","") or _a(el,"{http://www.w3.org/1999/xlink}href","")
    op   = _opacity(el)
    style = (f"shape=image;verticalLabelPosition=bottom;verticalAlign=top;"
             f"align=center;strokeColor=none;fillColor=none;"
             f"image={esc(href)};opacity={int(op*100)};")
    return (f'<mxCell id="{cid}" value="" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')


_HANDLERS = {
    f"{{{SVG_NS}}}rect":   _rect_cell,
    f"{{{SVG_NS}}}circle": _circle_cell,
    f"{{{SVG_NS}}}text":   _text_cell,
    f"{{{SVG_NS}}}line":   _line_cell,
    f"{{{SVG_NS}}}path":   _path_cell,
    f"{{{SVG_NS}}}image":  _image_cell,
    "rect":   _rect_cell,
    "circle": _circle_cell,
    "text":   _text_cell,
    "line":   _line_cell,
    "path":   _path_cell,
    "image":  _image_cell,
}


def _svg_to_drawio_native(svg_content: str) -> str:
    """
    Convert SVG to draw.io native format.
    Every shape becomes a separate, editable mxCell.
    """
    svg = _sanitize_svg(svg_content)
    root = ET.fromstring(svg)

    cells = ['<mxCell id="0" />', '<mxCell id="1" parent="0" />']
    cid = 2
    for el in root.iter():
        handler = _HANDLERS.get(el.tag)
        if handler:
            cell = handler(el, cid)
            if cell:
                cells.append(cell)
                cid += 1

    inner = "\n    ".join(cells)
    return (
        '<mxGraphModel dx="1422" dy="762" grid="1" gridSize="10" guides="1" '
        'tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
        'pageWidth="1169" pageHeight="827" math="0" shadow="0">\n'
        f'  <root>\n    {inner}\n  </root>\n</mxGraphModel>'
    )


def _svg_to_drawio_image(svg_content: str) -> str:
    """Legacy: embed SVG as a flat image cell (not editable)."""
    svg = _sanitize_svg(svg_content)
    svg_b64 = base64.b64encode(svg.encode("utf-8")).decode("ascii")
    return (
        '<mxGraphModel dx="1422" dy="762" grid="1" gridSize="10" guides="1" '
        'tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
        'pageWidth="1169" pageHeight="827" math="0" shadow="0">\n'
        '  <root>\n    <mxCell id="0" />\n    <mxCell id="1" parent="0" />\n'
        '    <mxCell id="2" value="" style="shape=image;verticalLabelPosition=bottom;'
        'labelBackgroundColor=default;verticalAlign=top;align=center;strokeColor=none;'
        f'fillColor=none;image=data:image/svg+xml,base64,{svg_b64};" vertex="1" parent="1">\n'
        '      <mxGeometry x="0" y="0" width="800" height="600" as="geometry" />\n'
        '    </mxCell>\n  </root>\n</mxGraphModel>'
    )


def export_diagram(svg_code: str):
    drawio_tab, download_tab = st.tabs(["draw.io", "download"])
    has_code = bool(svg_code and svg_code.strip())

    with drawio_tab:
        st.subheader("Draw.io")
        if not has_code:
            st.warning("No diagram found.")
        else:
            st.link_button(
                "🔗 Open in Draw.io (browser, flat preview)",
                _drawio_svg_url(svg_code),
                use_container_width=True,
                type="secondary",
            )
            st.divider()

            mode = st.radio(
                "Export mode",
                ["Native (editable shapes)", "Flat image (legacy)"],
                horizontal=True,
                help=(
                    "**Native** — every shape is a separate mxCell you can move/edit.\n\n"
                    "**Flat image** — SVG embedded as a single image cell."
                ),
            )
            native = mode.startswith("Native")
            drawio_content = (
                _svg_to_drawio_native(svg_code) if native
                else _svg_to_drawio_image(svg_code)
            )
            st.download_button(
                "⬇️ Download .drawio file",
                data=drawio_content,
                file_name="diagram.drawio",
                mime="application/xml",
                use_container_width=True,
                type="primary",
            )

    with download_tab:
        svg_tab, png_tab, jpg_tab = st.tabs(["SVG", "PNG", "JPG"])
        with svg_tab:
            if not has_code:
                st.info("No SVG available.")
            else:
                st.download_button(
                    "Download SVG",
                    svg_code,
                    file_name="diagram.svg",
                    mime="image/svg+xml",
                    use_container_width=True,
                )
        with png_tab:
            st.info("Not implemented")
        with jpg_tab:
            st.info("Not implemented")
