import math
import os
import logging
import palettes
import kiwisolver as kiwi
from xml.sax.saxutils import escape as xml_escape

try:
    from PIL import ImageFont
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

"""
Rendering Engine for the Auto-Diagram Application
"""

logger = logging.getLogger("rendering_engine")
if not logger.handlers:
    # Library code shouldn't call basicConfig unconditionally (that can
    # clobber a host application's logging setup) - only install a default
    # handler if nothing else already configured logging.
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class Position:
    """
    A simple 2D point/vector. Used everywhere a coordinate pair used to be
    passed around as two loose numbers (x/y anchor points, cx/cy circle
    centers, x1/y1/x2/y2 line endpoints, bbox_x/bbox_y bounding-box
    origins, ...).

    Supports the handful of operations this module actually needs:
    Position + Position, Position +/- a scalar (nudges both axes), scalar
    multiplication/division, iteration/unpacking (x, y = pos), and copy().
    """
    __slots__ = ("x", "y")

    def __init__(self, x=0, y=0):
        self.x = x
        self.y = y

    def __add__(self, other):
        if isinstance(other, Position):
            return Position(self.x + other.x, self.y + other.y)
        return Position(self.x + other, self.y + other)

    __radd__ = __add__

    def __sub__(self, other):
        if isinstance(other, Position):
            return Position(self.x - other.x, self.y - other.y)
        return Position(self.x - other, self.y - other)

    def __rsub__(self, other):
        return Position(other - self.x, other - self.y)

    def __mul__(self, scalar):
        return Position(self.x * scalar, self.y * scalar)

    __rmul__ = __mul__

    def __truediv__(self, scalar):
        return Position(self.x / scalar, self.y / scalar)

    def __neg__(self):
        return Position(-self.x, -self.y)

    def __eq__(self, other):
        if isinstance(other, Position):
            return self.x == other.x and self.y == other.y
        return NotImplemented

    def __iter__(self):
        yield self.x
        yield self.y

    def __repr__(self):
        return f"Position({self.x!r}, {self.y!r})"

    def as_tuple(self):
        return (self.x, self.y)

    def copy(self):
        return Position(self.x, self.y)

    def length(self):
        return math.sqrt(self.x ** 2 + self.y ** 2)
    
    def distance_to(self, other):
        if not isinstance(other, Position):
            raise ValueError("distance_to expects a Position instance.")
        dx = self.x - other.x
        dy = self.y - other.y
        return math.sqrt(dx ** 2 + dy ** 2)
    
    def normalize(self):
        len_self = self.length()
        if len_self == 0:
            return Position(0, 0)
        return Position(self.x / len_self, self.y / len_self)

# Common install paths for a proportional sans-serif font, tried in order.
# Real glyph metrics from a font file are far more accurate than a fixed
# "characters * font_size" guess - especially for this app's actual
# content (IPs, hex bytes, hostnames), where character width varies a lot.
# The exact rendering font (Segoe UI/Helvetica/Arial, per
# DEFAULT_STYLESHEET) usually isn't installed as a loadable file on the
# machine generating the SVG, so DejaVu Sans is used as a
# proportionally-similar stand-in. If none of these paths exist (or
# Pillow isn't installed), measure_text() falls back to the previous
# characters * (font_size * 0.62) estimate, so behavior degrades
# gracefully rather than breaking.
_FONT_PATHS = {
    "regular": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
    ],
    "bold": [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        "/Library/Fonts/Arial Bold.ttf",
        "C:\\Windows\\Fonts\\arialbd.ttf",
    ],
}
_font_cache = {}


def _get_font(size, bold=False):
    key = (bold, size)
    if key in _font_cache:
        return _font_cache[key]
    font = None
    if _HAS_PIL:
        for path in _FONT_PATHS["bold" if bold else "regular"]:
            if os.path.exists(path):
                try:
                    font = ImageFont.truetype(path, size)
                except Exception:
                    logger.warning("measure_text: failed to load font %s", path)
                    font = None
                break
    _font_cache[key] = font
    return font


def measure_text(text, font_size=11, bold=False):
    """
    Returns (width, height) in px that `text` will actually occupy at
    `font_size`. Uses real glyph metrics from a font file when one can be
    found; otherwise falls back to the old heuristic estimate, so this is
    always safe to call even on a machine with no usable font file.
    """
    if not text:
        return 0, font_size * 1.2
    font = _get_font(font_size, bold=bold)
    if font is not None:
        try:
            left, top, right, bottom = font.getbbox(text)
            return (right - left), font_size * 1.2
        except Exception:
            logger.warning("measure_text: font.getbbox failed for %r; using heuristic.", text)
    return len(text) * (font_size * 0.62), font_size * 1.2


class Collision_Grid:
    def __init__(self, cell_size=10, width=1000, height=1000):
        self.cell_size = cell_size
        self.width = width
        self.height = height
        self.occupied_cells = set()

    def _get_cells(self, pos, width, height):
        start_cx = int(pos.x // self.cell_size)
        start_cy = int(pos.y // self.cell_size)
        end_cx = int((pos.x + width) // self.cell_size)
        end_cy = int((pos.y + height) // self.cell_size)
        return start_cx, start_cy, end_cx, end_cy

    def is_area_free(self, pos, width, height):
        scx, scy, ecx, ecy = self._get_cells(pos, width, height)
        for cx in range(scx, ecx + 1):
            for cy in range(scy, ecy + 1):
                if (cx, cy) in self.occupied_cells:
                    return False
        return True

    def occupy_area(self, pos, width, height):
        scx, scy, ecx, ecy = self._get_cells(pos, width, height)
        for cx in range(scx, ecx + 1):
            for cy in range(scy, ecy + 1):
                self.occupied_cells.add((cx, cy))

    def find_and_occupy_space(self, start_pos, width, height, direction="vertical"):
        """
        Greedily Step space for an object, as close as possible to the
        requested start_pos.

        Each object first tries to take its own requested spot. If that's
        occupied, it greedily searches outward in expanding rings (in
        cell_size steps) and takes the *nearest* free spot it finds -
        checked via is_area_free, so it can never land on top of an
        object that's already been placed. `direction` only biases which
        side of the ring is probed first (kept for backwards
        compatibility with existing "vertical"/"horizontal" callers); it
        no longer restricts the search to a single axis.

        Returns a new Position (start_pos itself is never mutated).
        """
        if self.is_area_free(start_pos, width, height):
            self.occupy_area(start_pos, width, height)
            logger.debug("Placed at requested spot: (%s, %s) %sx%s", start_pos.x, start_pos.y, width, height)
            return start_pos.copy()

        step = self.cell_size
        max_radius = int(max(self.width, self.height) // step) + 1

        for radius in range(1, max_radius + 1):
            offset = radius * step
            candidates = []
            if direction == "vertical":
                # Prefer straight down/up first, then the rest of the ring.
                candidates.append(Position(start_pos.x, start_pos.y + offset))
                candidates.append(Position(start_pos.x, start_pos.y - offset))
                for d in range(-radius, radius + 1):
                    if d == 0:
                        continue
                    dx = d * step
                    candidates.append(Position(start_pos.x + dx, start_pos.y + offset))
                    candidates.append(Position(start_pos.x + dx, start_pos.y - offset))
            else:
                # Prefer straight right/left first, then the rest of the ring.
                candidates.append(Position(start_pos.x + offset, start_pos.y))
                candidates.append(Position(start_pos.x - offset, start_pos.y))
                for d in range(-radius, radius + 1):
                    if d == 0:
                        continue
                    dy = d * step
                    candidates.append(Position(start_pos.x + offset, start_pos.y + dy))
                    candidates.append(Position(start_pos.x - offset, start_pos.y + dy))

            for cand in candidates:
                if cand.x < 0 or cand.y < 0:
                    continue
                if self.is_area_free(cand, width, height):
                    self.occupy_area(cand, width, height)
                    logger.debug("Placed via ring search: (%s, %s) %sx%s", cand.x, cand.y, width, height)
                    return cand

        # Fallback (should only trigger once the whole grid is packed):
        # keep pushing along the original axis so we still terminate with
        # a valid, non-overlapping placement rather than raising.
        curr = start_pos.copy()
        while not self.is_area_free(curr, width, height):
            if direction == "vertical":
                curr.y += step
            else:
                curr.x += step
        logger.debug("Placed via fallback push: (%s, %s) %sx%s", curr.x, curr.y, width, height)
        self.occupy_area(curr, width, height)
        return curr

    def get_bounding_box(self):
        """Returns (Position, width, height) of all occupied cells, or None."""
        if not self.occupied_cells:
            return None

        min_cx = min(cx for cx, cy in self.occupied_cells)
        max_cx = max(cx for cx, cy in self.occupied_cells)
        min_cy = min(cy for cx, cy in self.occupied_cells)
        max_cy = max(cy for cx, cy in self.occupied_cells)

        pos = Position(min_cx * self.cell_size, min_cy * self.cell_size)
        width = (max_cx - min_cx + 1) * self.cell_size
        height = (max_cy - min_cy + 1) * self.cell_size

        return pos, width, height

    def get_rotated_bounds(self, pos, width, height, angle_degrees):
        """
        Get the bounding box of a rectangle after rotation by a given angle.
        Returns (Position, new_width, new_height).
        """
        angle_rad = math.radians(angle_degrees)
        cos_a = abs(math.cos(angle_rad))
        sin_a = abs(math.sin(angle_rad))

        new_width = (width * cos_a) + (height * sin_a)
        new_height = (width * sin_a) + (height * cos_a)

        center = Position(pos.x + width / 2, pos.y + height / 2)
        new_pos = Position(center.x - new_width / 2, center.y - new_height / 2)

        return new_pos, new_width, new_height

    def visualize_grid(self, fill_occupied="#e216fd", stroke_color="#ff003c", opacity_occupied=0.3, opacity_empty=0.15):
        """
        Returns an SVG <g> block that draws the entire grid across the canvas bounds.
        - Occupied cells: Drawn as filled rectangles.
        - Empty cells: Drawn as unfilled wireframe rectangles (just borders).
        """
        parts = ['<g class="collision-grid-debug">']

        max_cx = int(self.width // self.cell_size)
        max_cy = int(self.height // self.cell_size)
        for cx in range(max_cx + 1):
            for cy in range(max_cy + 1):
                cell_pos = Position(cx * self.cell_size, cy * self.cell_size)

                if (cx, cy) in self.occupied_cells:
                    parts.append(
                        f'  <rect x="{cell_pos.x}" y="{cell_pos.y}" width="{self.cell_size}" height="{self.cell_size}" '
                        f'fill="{fill_occupied}" stroke="{stroke_color}" stroke-width="1" opacity="{opacity_occupied}"/>'
                    )
                else:

                    parts.append(
                        f'  <rect x="{cell_pos.x}" y="{cell_pos.y}" width="{self.cell_size}" height="{self.cell_size}" '
                        f'fill="none" stroke="{stroke_color}" stroke-width="0.3" opacity="{opacity_empty}"/>'
                    )

        parts.append('</g>')
        return "\n".join(parts)



# Fallback grid used by any SVGObject that isn't explicitly given one. Real
# diagrams should create their own Collision_Grid and thread it through their
# objects (see diagram_creator) so that unrelated diagrams/tests don't share
# occupied space.
DEFAULT_GRID = Collision_Grid()


class SVGObject:

    def __init__(self, pos=None, width=0, height=0, angle=0, grid=None, register=False, is_dynamic = False):
        self.pos = pos if pos is not None else Position(0, 0)
        self.width = width
        self.height = height
        self.angle = angle
        self.is_dynamic = is_dynamic
        self.grid = grid if grid is not None else DEFAULT_GRID
        self.bounds = (self.pos, width, height)
        self.contents = []
        # Set (by Step.add_notebox/add_icon) for objects anchored to a
        # step's from_pos; resolve_layout uses these to spring an object
        # back toward its "ideal" position after a collision nudge. None
        # for objects with no such anchor (Actors, Phases, free Labels...).
        self.step = None
        self.pos_relative = None
        if register:
            self.register_with_grid()

    def get_bounds(self):
        """(Position, width, height) this object should occupy on the grid."""
        if self.angle:
            return self.grid.get_rotated_bounds(self.pos, self.width, self.height, self.angle)
        return (self.pos, self.width, self.height)

    def register_with_grid(self):
        """Steps this object's bounding box (rotated if angled) on its grid."""
        pos, w, h = self.get_bounds()
        if w <= 0 or h <= 0:
            return None
        self.pos = self.grid.find_and_occupy_space(pos, w, h)
        self.bounds = (self.pos, w, h)
        return self.bounds
    def intersects(box1, box2):
        pos1, w1, h1 = box1.bounds
        pos2, w2, h2 = box2.bounds
        return not (pos1.x + w1 < pos2.x or pos1.x > pos2.x + w2 or
                    pos1.y + h1 < pos2.y or pos1.y > pos2.y + h2)
    def update_position(self, position: Position =None, new_x: float = None, new_y: float=None):
            """
            Update the position of the object and its bounding box.
            """
            if position is not None:
                self.pos = position
            elif new_x is not None and new_y is not None:
                self.pos = Position(new_x, new_y)
            self.bounds = (self.pos, self.width, self.height)  

class Label(SVGObject):
    """A single positioned <text> element."""

    def __init__(self, pos, text, cls=None, anchor=None, fill=None,
                 font_family=None, font_size=None, font_weight=None,
                 stroke_width=None, angle=0, grid=None, register=False):
        self.text = text
        self.anchor = anchor
        self.cls = cls
        self.fill = fill

        self.font_family = font_family
        self.font_size = font_size
        self.font_weight = font_weight
        self.stroke_width = stroke_width

        # `pos` as passed in is treated as the SVG anchor point (baseline,
        # x/y per text-anchor semantics). Convert it to the top-left of the
        # bounding box so self.pos matches every other SVGObject.
        bbox_pos, bbox_w, bbox_h = self._estimate_bounds(pos)

        super().__init__(pos=bbox_pos, width=bbox_w, height=bbox_h,
                          angle=angle, grid=grid, register=register, is_dynamic=True)

    def _estimate_bounds(self, anchor_pos, default_size=11):
        """anchor_pos is an SVG-style anchor point (baseline y, x per
        text-anchor). Returns (top_left_pos, width, height)."""
        font_size = int(self.font_size) if self.font_size else default_size

        estimated_width, estimated_height = measure_text(
            self.text, font_size=font_size, bold=(self.font_weight == "bold")
        )
        bx = anchor_pos.x
        by = anchor_pos.y - estimated_height
        if self.anchor == "middle":
            bx = anchor_pos.x - (estimated_width / 2)
        elif self.anchor == "end":
            bx = anchor_pos.x - estimated_width
        return Position(bx, by), estimated_width, estimated_height

    def _anchor_from_bounds(self):
        """Inverse of _estimate_bounds: recover the SVG anchor point
        (baseline x/y) from the current top-left self.pos."""
        ax = self.pos.x
        ay = self.pos.y + self.height

        if self.anchor == "middle":
            ax = self.pos.x + (self.width / 2)
        elif self.anchor == "end":
            ax = self.pos.x + self.width

        return ax, ay

    def estimate_label_bounds(self, default_size=11):
        """Kept for backwards compatibility; returns the current text bbox
        (top-left, width, height) treating self.pos as an anchor point."""
        return self._estimate_bounds(self.pos, default_size=default_size)

    def get_bounds(self):
        # self.pos is already the top-left of the bbox, so no re-derivation
        # from an "anchor" is needed here anymore.
        if self.angle:
            return self.grid.get_rotated_bounds(self.pos, self.width, self.height, self.angle)
        return (self.pos, self.width, self.height)

    def to_svg(self):
        ax, ay = self._anchor_from_bounds()
        attrs = [f'x="{ax}"', f'y="{ay}"']
        if self.anchor:
            attrs.append(f'text-anchor="{self.anchor}"')
        if self.cls:
            attrs.append(f'class="{self.cls}"')
        if self.font_family:
            attrs.append(f'font-family="{self.font_family}"')
        if self.font_size:
            attrs.append(f'font-size="{self.font_size}"')
        if self.font_weight:
            attrs.append(f'font-weight="{self.font_weight}"')
        if self.stroke_width is not None:
            attrs.append(f'stroke-width="{self.stroke_width}"')
        if self.fill:
            attrs.append(f'fill="{self.fill}"')
        svg_content = f'<text {" ".join(attrs)}>{xml_escape(str(self.text))}</text>'
        return svg_content
    
    
class Badge(SVGObject):
    def __init__(self, center, number, color, radius=9, angle=0, grid=None, register=False):
        self.center = center
        self.number = number
        self.color = color
        self.radius = radius
        self.is_dynamic = False  # Badges are static by default
        self.label = Label(
            text=str(number),
            cls = "sans-serif",
            pos=Position(center.x, center.y + 3),
            font_size=10,
            font_weight="bold",
            anchor="middle",
            grid=grid,
            register=False
        )
        super().__init__(pos=Position(center.x - radius, center.y - radius),
                         width=radius * 2, height=radius * 2,
                         angle=angle, grid=grid, register=register)

    def to_svg(self):
        circle = f'<circle cx="{self.center.x}" cy="{self.center.y}" r="{self.radius}" fill="{self.color}"/>'
        return f"{circle}\n{self.label.to_svg()}"


class Arrow(SVGObject):
    RIGHT = 1
    LEFT = -1

    def __init__(self, start=None, end=None, color="#000",
                 width=1.5, dashed=None, path=None, angle=0, grid=None, register=False):
        self.start = start
        self.end = end
        self.color = color
        self.line_width = width
        self.dashed = dashed
        self.path = path
        self.is_dynamic = True  # Arrows are dynamic by default
        # Curved/free-form paths (used for loop arrows) don't have a simple
        # endpoint-derived bbox, so they're left unregistered here; LoopArrow
        # computes and registers its own box instead.
        if path is None and start is not None and end is not None:
            min_thickness = 10
            raw_h = abs(end.y - start.y)
            bh = max(raw_h, min_thickness)
            bx = min(start.x, end.x)
            # Center any extra padding on the actual line instead of only
            # padding downward, so near-horizontal arrows (raw_h ~ 0) get a
            # hitbox that straddles the drawn line rather than sitting
            # entirely below it.
            by = min(start.y, end.y) - (bh - raw_h) / 2
            bw = abs(end.x - start.x)
            box_pos = Position(bx, by)
        else:
            box_pos = Position(0, 0)
            bw = bh = 0
        logger.debug("Arrow: bx=%s, by=%s, bw=%s, bh=%s, angle=%s", box_pos.x, box_pos.y, bw, bh, angle)
        super().__init__(pos=box_pos, width=bw, height=bh, angle=angle, grid=grid, register=register)
        if register and self.start is not None and self.end is not None:
            # Preserve the original shift math exactly: after collision-avoidance
            # may have moved the registered box, `end` shifts by the box's x
            # delta (subtracted) and y delta (added) relative to the *original*
            # start point, and `start` snaps onto the box's final position.
            self.end = Position(self.end.x - (self.pos.x - self.start.x),
                                 self.end.y + (self.pos.y - self.start.y))
            self.start = self.pos.copy()

    def to_svg(self):
        dash_attr = f' stroke-dasharray="{self.dashed}"' if self.dashed else ""
        if self.path:
            return (f'<path d="{self.path}" fill="none" stroke="{self.color}" '
                    f'stroke-width="{self.line_width}"{dash_attr} marker-end="url(#arrow)"/>')
        return (f'<line x1="{self.start.x}" y1="{self.start.y}" x2="{self.end.x}" y2="{self.end.y}" '
                f'stroke="{self.color}" stroke-width="{self.line_width}"{dash_attr} '
                f'marker-end="url(#arrow)"/>')


class LoopArrow(Arrow):
    def __init__(self, start, width=40, height=30, color="#000", stroke_width=2.5,
                 angle=0, grid=None, register=False):
        self.start = start
        self.loop_width = width
        self.loop_height = height
        self.color = color
        self.stroke_width = stroke_width
        self.line_width = stroke_width
        self.path = None
        self.dashed = None
        self.end = None

        box_pos = Position(start.x, start.y - height / 2)
        SVGObject.__init__(self, pos=box_pos, width=width, height=height,
                            angle=angle, grid=grid, register=register)
        self.is_dynamic = True

    def to_svg(self):
        half_h = self.loop_height / 2
        path = (f"M {self.start.x},{self.start.y - half_h} "
                f"C {self.start.x + self.loop_width},{self.start.y - half_h} "
                f"{self.start.x + self.loop_width},{self.start.y + half_h} "
                f"{self.start.x},{self.start.y + half_h}")
        return (f'<path d="{path}" fill="none" stroke="{self.color}" '
                f'stroke-width="{self.stroke_width}" marker-end="url(#arrow)"/>')


class NoteBox(SVGObject):
    def __init__(self, pos, width=100, height=100, lines=[], shape="rect", rx=5,
                 fold=10, corner="top-right", fill="#ffffff", stroke="#000",
                 stroke_width=1, angle=0, grid=None, register=False):
        max_line_width = max((measure_text(l, font_size=10)[0] for l in lines), default=0)
        width = max(width, max_line_width + 20)
        height = max(height, 14 + (14 * len(lines)))
        self.lines = [
            Label(Position(6, 14 + (14 * i)), line, cls="info-body")
            for i, line in enumerate(lines)
        ]

        self.shape = shape
        self.rx = rx
        self.fold = fold
        self.corner = corner
        self.fill = fill
        self.stroke = stroke
        self.stroke_width = stroke_width

        super().__init__(pos=pos, width=width, height=height, is_dynamic=True,
                          angle=angle, grid=grid, register=register)
        self.contents.extend(self.lines)

    def _fold_path(self):
        w, h, f = self.width, self.height, self.fold
        if self.corner == "top-left":
            return f"M0,{f} L{f},0 L{w},0 L{w},{h} L0,{h} Z"
        return f"M0,0 L{w - f},0 L{w},{f} L{w},{h} L0,{h} Z"

    def to_svg(self):
        if self.shape == "fold":
            shape_svg = (f'<path d="{self._fold_path()}" fill="{self.fill}" '
                         f'stroke="{self.stroke}" stroke-width="{self.stroke_width}"/>')
        else:
            shape_svg = (f'<rect x="0" y="0" width="{self.width}" height="{self.height}" '
                         f'rx="{self.rx}" fill="{self.fill}" stroke="{self.stroke}" '
                         f'stroke-width="{self.stroke_width}"/>')
        lines_svg = "\n      ".join(line.to_svg() for line in self.lines)
        return (f'<g transform="translate({self.pos.x}, {self.pos.y})">\n      '
                f'{shape_svg}\n      {lines_svg}\n    </g>')


class Icon(SVGObject):
    def __init__(self, name, pos=None, width=30, height=30, angle=0, grid=None, register=False):
        self.name = name
        super().__init__(pos=pos if pos is not None else Position(0, 0),
                          width=width, height=height,
                          angle=angle, grid=grid, register=register, is_dynamic=True)

    @property
    def url(self):
        return f"https://img.icons8.com/color/96/{self.name}.png"

    def set_position(self, pos):
        # Note: moving an icon after creation does not release its old grid
        # cells or re-Step new ones (Collision_Grid has no "release" API).
        self.pos = pos

    def to_svg(self):
        return f'<image href="{self.url}" x="{self.pos.x}" y="{self.pos.y}" width="{self.width}" height="{self.height}" opacity="0.5"/>'


class Lifeline(SVGObject):
    def __init__(self, start_x, end_x, color, start_y=105, end_y=550, angle=0, register=False):
        self.start = Position(start_x, start_y)
        self.end = Position(end_x, end_y)
        self.color = color
        box_pos = Position(min(self.start.x, self.end.x), min(self.start.y, self.end.y))
        bw, bh = abs(self.end.x - self.start.x), abs(self.end.y - self.start.y)
        super().__init__(pos=box_pos, width=bw, height=bh,
                          angle=angle, register=register)

    def to_svg(self):
        return (f'<line x1="{self.start.x}" y1="{self.start.y}" x2="{self.end.x}" y2="{self.end.y}" '
                f'stroke="{self.color}" stroke-width="1" stroke-dasharray="4 4"/>')


class SVGBox(SVGObject):
    def __init__(self, pos, width, height, title_text, desc, fill_color, stroke_color, canvas_width, canvas_height, rx=6,
                 angle=0, grid=None, register=False, stroke_width=1.5, text_color="#000"):
        self.title_text = title_text
        self.desc = desc
        self.fill_color = fill_color
        self.stroke_color = stroke_color
        self.rx = rx
        self.contents = []
        self.canvas_width = canvas_width
        self.canvas_height = canvas_height
        self.stroke_width = stroke_width
        self.text_color = text_color
        self.title_lines = self._wrap_text(title_text, max_chars=22) if title_text else []
        self.desc_lines = self._wrap_text(desc, max_chars=22) if desc else []
        # Titles render via the "node-title" class (12px, bold) and
        # descriptions via "info-title" (11px, regular) - see
        # DEFAULT_STYLESHEET. Measuring everything as 12px/regular
        # under-measured bold title text (bold glyphs are wider than
        # regular at the same size), which could let a title line overflow
        # a box sized from that estimate.
        title_widths = [measure_text(line, font_size=12, bold=True)[0] for line in self.title_lines]
        desc_widths = [measure_text(line, font_size=11, bold=False)[0] for line in self.desc_lines]
        max_line_width = max(title_widths + desc_widths, default=0)

        # +14 rather than +10: measurement uses a DejaVu Sans stand-in
        # (see measure_text), while the SVG itself requests 'Segoe UI',
        # Helvetica, Arial - whichever of those is actually installed on
        # the viewer's machine will have slightly different metrics than
        # DejaVu Sans at the same size, so a small extra margin is kept as
        # a buffer against that mismatch rather than fitting to the exact
        # pixel.
        estimated_width = max_line_width + 14
        width = max(width, estimated_width)

        estimated_height = 40 + ((len(self.title_lines) + len(self.desc_lines)) * 14)
        height = max(height, estimated_height)

        # Final width/height are only known now, so the grid is Steped here
        # (end of __init__) rather than at the top.
        super().__init__(pos=pos, width=width, height=height,
                          angle=angle, grid=grid, register=register, is_dynamic=False)

    @staticmethod
    def _wrap_text(text, max_chars=25):
        if not text:
            return []
        words = text.split(' ')
        lines = []
        current_line = []
        current_length = 0

        for word in words:
            if current_length + len(word) + len(current_line) > max_chars:
                lines.append(' '.join(current_line))
                current_line = [word]
                current_length = len(word)
            else:
                current_line.append(word)
                current_length += len(word)
        if current_line:
            lines.append(' '.join(current_line))
        return lines

    @staticmethod
    def estimate_text_box_size(title_text, desc, title_max_chars=22, desc_max_chars=22,
                                min_width=0, min_height=0):
        """
        Mirrors the auto-fit sizing SVGBox.__init__ applies to itself (lines
        ~394-403), but callable up front - before any SVGBox/Actor/Phase
        instance exists - so callers can find the max size needed across a
        whole group (e.g. all actors) and pass a single uniform width/height
        into every instance instead of letting each one size itself
        independently.
        """
        title_lines = SVGBox._wrap_text(title_text, title_max_chars) if title_text else []
        desc_lines = SVGBox._wrap_text(desc, desc_max_chars) if desc else []
        # See the matching comment in SVGBox.__init__: title renders bold
        # (12px) via "node-title", desc renders regular (11px) via
        # "info-title" - measure each at its real weight/size so this
        # uniform box size actually fits what gets rendered.
        title_widths = [measure_text(line, font_size=12, bold=True)[0] for line in title_lines]
        desc_widths = [measure_text(line, font_size=11, bold=False)[0] for line in desc_lines]
        max_line_width = max(title_widths + desc_widths, default=0)

        estimated_width = max(min_width, max_line_width + 14)
        estimated_height = max(min_height, 40 + ((len(title_lines) + len(desc_lines)) * 14))
        return estimated_width, estimated_height

    def render_text_lines(self, x, start_y, lines, text_class="info-title", line_height=14, stroke_width=1.5):
        """
        Builds a Label object for each line of text and adds every one of
        them to self.contents, so box text is a real SVGObject (like every
        other drawable) instead of a hand-built <text> tag string.

        Labels are created with register=False: the box has already
        Steped its own footprint on the grid via its own registration,
        so its internal text lines shouldn't Step additional space.

        Returns (labels, next_y) - the list of Label objects just created,
        and the y-coordinate the next group of lines should start at (so
        e.g. desc lines can pick up where title lines left off).
        """
        labels = []
        current_y = start_y
        if type(lines) is str:
            lines = [lines]
        for line in lines:
            label = Label(
                pos=Position(x, current_y),
                text=line,
                anchor="middle",
                cls=text_class,
                stroke_width=stroke_width,
                grid=self.grid,
                register=False,
            )
            labels.append(label)
            self.contents.append(label)
            current_y += line_height

        return labels, current_y

    def to_svg(self):
        transform = f'translate({self.pos.x}, {self.pos.y})'
        if self.angle:
            transform += f' rotate({self.angle}, {self.width / 2}, {self.height / 2})'
        parts = [f'<g transform="{transform}">']
        parts.append(f'  <rect x="0" y="0" width="{self.width}" height="{self.height}" rx="{self.rx}" fill="{self.fill_color}" stroke="{self.stroke_color}" stroke-width="1.5"/>')
        parts.extend(c.to_svg() for c in self.contents)
        parts.append('</g>')
        return "\n".join(parts)


class Actor(SVGBox):
    def __init__(self, pos, name, desc, box_color, stroke_color, icon_name,
                 lifeline_color=None, width=100, height=60, is_malicious=False, canvas_width=1000, canvas_height=1000,
                 angle=0, grid=None, register=False, stroke_width=1.5, text_color="#000"):
        super().__init__(pos=pos, width=width, height=height,
                         title_text=name, desc=desc,
                         fill_color=box_color, stroke_color=stroke_color, canvas_width=canvas_width, canvas_height=canvas_height,
                         angle=angle, grid=grid, register=register, stroke_width=stroke_width, text_color=text_color)
        self.name = name
        # The icon is drawn at a fixed offset inside the actor's own <g>, so
        # its position isn't a meaningful diagram coordinate - don't register it.
        self.icon = Icon(icon_name, register=False)
        self.lifeline_color = lifeline_color or stroke_color
        self.is_malicious = is_malicious

        # Built once here (rather than inside to_svg()) since render_text_lines
        # now creates real Label objects and appends them to self.contents -
        # doing that on every to_svg() call would duplicate them.
        half_width = self.width / 2
        self.name_labels, next_y = self.render_text_lines(
            x=half_width, start_y=43, lines=self.title_lines, text_class="node-title")
        self.desc_labels, _ = self.render_text_lines(
            x=half_width, start_y=next_y, lines=self.desc_lines, text_class="info-title")

    def lifeline(self):
        center_x = self.pos.x + self.width / 2
        return Lifeline(start_x=center_x, end_x=center_x, start_y=self.pos.y + self.height, end_y=self.canvas_height - 50,
                         color=self.lifeline_color)

    def to_svg(self):
            half_width = self.width / 2
            icon_offset_x = half_width - (self.icon.width / 2)
            transform_str = f"translate({self.pos.x}, {self.pos.y})"
            if self.angle:
                transform_str += f" rotate({self.angle})"

            parts = [
                 f'<g transform="{transform_str}">',
                    f'  <rect x="0" y="0" width="{self.width}" height="{self.height}" rx="{self.rx}" fill="{self.fill_color}" stroke="{self.stroke_color}" stroke-width="1.5"/>',
                    f'  <image href="{self.icon.url}" x="{icon_offset_x}" y="5" width="{self.icon.width}" height="{self.icon.height}" opacity="0.5"/>'
                ]
            parts.extend(label.to_svg() for label in self.name_labels)
            parts.extend(label.to_svg() for label in self.desc_labels)
            parts.append('</g>')
            return "\n".join(parts)


class Phase(SVGBox):
    def __init__(self, pos, phase_number, title, desc, color, bg, width=100, height=150, canvas_width=1000, canvas_height=1000, rx=6,
                 angle=0, grid=None, register=False, stroke_width=1.5, text_color="#000"):
        self.phase_number = phase_number
        phase_title = "Phase " + str(phase_number) + ": " + title

        super().__init__(pos=pos, width=width, height=height,
                         title_text=phase_title, desc=desc,
                         fill_color=bg, stroke_color=color, rx=4, canvas_width=canvas_width, canvas_height=canvas_height,
                         angle=angle, grid=grid, register=register, stroke_width=stroke_width, text_color=text_color)

        self.color = color
        self.bg = bg
        self.steps = []
        # Absolute Y where the next phase begins (set by diagram_creator once
        # this phase's real height is known). Kept as a plain number, not a
        # Position, since it's a single coordinate, not a point.
        self.next_phase_y = None

        # Built once here (rather than inside to_svg()) since render_text_lines
        # now creates real Label objects and appends them to self.contents -
        # doing that on every to_svg() call would duplicate them. Phase draws
        # its rect at absolute coordinates (no <g transform> wrapper like
        # Actor/generic SVGBox), so label positions are absolute too.
        half_width = self.width / 2
        title_start_y = self.pos.y + self.height // 4
        self.title_labels, next_y = self.render_text_lines(
            x=self.pos.x + half_width, start_y=title_start_y, lines=self.title_lines, text_class="node-title")
        self.desc_labels, _ = self.render_text_lines(
            x=self.pos.x + half_width, start_y=next_y + 4, lines=self.desc_lines, text_class="info-title")

    def badge(self, center, number, color=None):
        return Badge(center, number, color or self.color, grid=self.grid)

    def lifeline(self):
        mid_y = self.pos.y + self.height // 2
        return Lifeline(start_x=self.pos.x + self.width, end_x=self.canvas_width, start_y=mid_y, end_y=mid_y, color=self.stroke_color)

    def arrow(self, start=None, end=None, path=None,
              dashed=None, width=1.5, color=None):
        return Arrow(start, end, color=color or self.color,
                     width=width, dashed=dashed, path=path, grid=self.grid)

    def note(self, pos, width, height, lines, shape="rect", rx=5,
             fold=10, corner="top-right", fill="#ffffff", stroke=None,
             stroke_width=1):
        return NoteBox(pos, width, height, lines, shape=shape, rx=rx,
                       fold=fold, corner=corner, fill=fill,
                       stroke=stroke or self.color, stroke_width=stroke_width, grid=self.grid)

    def add_step(self, step):
        self.steps.append(step)
        return self

    def add(self, *items):
        self.contents.extend(items)
        return self

    def to_svg(self):
        parts = [
            f'  <rect x="{self.pos.x}" y="{self.pos.y}" width="{self.width}" height="{self.height}" rx="12" fill="{self.fill_color}" stroke="{self.stroke_color}" stroke-width="{self.stroke_width}" stroke-dasharray="4,4"/>',
        ]

        parts.extend(label.to_svg() for label in self.title_labels)
        parts.extend(label.to_svg() for label in self.desc_labels)
        parts.extend(s.to_svg() for s in self.steps)
        return "\n".join(parts)


class Step(SVGObject):
    """
    Note on coordinates: from_pos/to_pos (and therefore `center`) are
    phase-relative, not absolute diagram coordinates (see diagram_creator,
    which passes `actor.pos - phase.pos`). Step still registers its bounding
    box on a Collision_Grid so overlapping steps within the same local
    coordinate space can be detected, but by default that's a *different*
    grid than the one Actors/Phases share (pass `grid=` explicitly to share
    one).
    """
    def __init__(self, from_pos, to_pos, number, badge=None, arrows=None, labels=None, noteboxes=None, icons=None,
                 is_loop=False, loop_width=40, loop_height=30, angle=0, color="#000",
                 grid=None, register=False):
        self.from_pos = from_pos
        self.to_pos = to_pos
        self.number = number
        self.center = Position((from_pos.x + to_pos.x) / 2, (from_pos.y + to_pos.y) / 2)
        self.color = color
        
        is_loop = (from_pos == to_pos)
        direction = Arrow.RIGHT if to_pos.x > from_pos.x else Arrow.LEFT
        badge_pos = Position(from_pos.x - (9 * direction), from_pos.y)
        if is_loop:
            badge_pos.y -= 10

        # Badge/arrows/labels are positioned relative to `center`, not in
        # grid coordinates, so they don't register themselves individually -
        # only the Step as a whole Steps space below.
        self.badge = badge or Badge(badge_pos, number, color, grid=grid, register=False)

        self.is_loop = is_loop
        self.loop_width = loop_width
        self.loop_height = loop_height
        self.noteboxes = noteboxes or []
        self.icons = icons or []

        # Needed early so _loop_arrow() (called below, before
        # SVGObject.__init__ runs) can register on the right grid too.
        self.grid = grid if grid is not None else DEFAULT_GRID

        if arrows is not None:
            self.arrows = arrows
        elif self.is_loop:
            self.arrows = [self._loop_arrow()]
        else:
            self.arrows = [Arrow(start=from_pos, end=to_pos, color=color, width="2.5", grid=grid, register=register)]
        self.labels = labels or []
        self.noteboxes = noteboxes or []
        self.icons = icons or []
        for label in self.labels:
            label.step = self
            label.pos_relative = label.pos - from_pos
            bbox_w, bbox_h = self.loop_width + 20, self.loop_height + 30
            box_pos = Position(self.center.x - 10, self.center.y - bbox_h / 2)
        else:
            bx = min(from_pos.x, to_pos.x) - 10
            by = min(from_pos.y, to_pos.y) - 25
            bbox_w = max(from_pos.x, to_pos.x) + 10 - bx
            bbox_h = max(from_pos.y, to_pos.y) + 25 - by
            box_pos = Position(bx, by)

        super().__init__(pos=box_pos, width=bbox_w, height=bbox_h,
                          angle=angle, grid=grid, register=False)

        self.contents = [self.badge] + self.arrows + self.labels + self.noteboxes + self.icons
    def _loop_arrow(self):
        # A small rounded bulge that leaves the lifeline, arcs out to the
        # right, and curves back to end (with the arrowhead) right where it
        # started - the conventional "self message" shape in sequence
        # diagrams. Step.to_svg() renders everything (badge, straight
        # arrows, labels) in absolute canvas coordinates with no wrapping
        # translate, so the loop's path is built in absolute coordinates
        # too, anchored at the step's own `center` - the point on the
        # lifeline the message starts/ends at.
        w, h = self.loop_width, self.loop_height
        half_h = h / 2
        c = self.center
        path = f"M {c.x},{c.y - half_h} C {c.x + w},{c.y - half_h} {c.x + w},{c.y + half_h} {c.x},{c.y + half_h}"
        return Arrow(path=path, color=self.color, width="2.5", grid=self.grid, register=False)

    def to_svg(self):

        parts = []
        parts.append(f'<!-- Step {self.number} -->')
        if self.angle:
            parts.append(f'  <g transform="rotate({self.angle}, {self.center.x}, {self.center.y})">')
        if self.badge:
            parts.append(self.badge.to_svg())
        parts.extend(a.to_svg() for a in self.arrows)
        if self.is_loop:
            # Center the label(s) over the bulge instead of over the lifeline,
            # and lift them clear of the top of the loop.
            for l in self.labels:
                l.pos.x += self.loop_width / 2
                l.pos.y -= (self.loop_height / 2)
        parts.extend(l.to_svg() for l in self.labels)
        parts.extend(nb.to_svg() for nb in self.noteboxes)
        parts.extend(icon.to_svg() for icon in self.icons)
        if self.angle:
            parts.append(f'  </g>')

        return "\n      ".join(parts)

    def set_angle(self, angle):
        self.angle = angle

    def add_arrow(self, arrow):
        self.arrows.append(arrow)
        self.contents.append(arrow)
    def add_label(self, label):
        label.step = self
        label.pos_relative = label.pos - self.from_pos
        self.labels.append(label)
        self.contents.append(label)

    def add_icon(self, name, pos=None, width=30, height=30, angle=0, grid=None, register=False, pos_relative=None):
        if pos_relative is not None:
            pos = self.from_pos + pos_relative
        icon = Icon(name, pos=pos, width=width, height=height, angle=angle, grid=grid, register=register)
        icon.step = self
        icon.pos_relative = pos_relative if pos_relative is not None else (icon.pos - self.from_pos)
        self.contents.append(icon)
        self.icons.append(icon)

    def add_notebox(self, pos=None, width=100, height=100, lines=[], shape="rect", rx=5,
                 fold=10, corner="top-right", fill="#ffffff", stroke="#000",
                 stroke_width=1, angle=0, grid=None, register=False, pos_relative=None):
        if pos is None:
            pos = Position(1000, 1000)
        if pos_relative is not None:
            pos = self.from_pos + pos_relative
        notebox = NoteBox(pos, width, height, lines, shape=shape, rx=rx,
                          fold=fold, corner=corner, fill=fill, grid=grid, register=register)
        notebox.step = self
        notebox.pos_relative = pos_relative if pos_relative is not None else (notebox.pos - self.from_pos)
        self.contents.append(notebox)
        self.noteboxes.append(notebox)


class StyleRule:
    def __init__(self, selector, **props):
        self.selector = selector
        self.props = props

    def to_css(self):
        decls = "; ".join(f"{k.replace('_', '-')}: {v}" for k, v in self.props.items())
        return f".{self.selector} {{ {decls}; }}"


class StyleSheet:
    def __init__(self, rules):
        self.rules = rules

    def to_svg(self):
        body = "\n    ".join(rule.to_css() for rule in self.rules)
        return f"  <style>\n    {body}\n  </style>"


DEFAULT_STYLESHEET = StyleSheet([
    StyleRule("title", font_family="'Segoe UI', Helvetica, Arial, sans-serif",
              font_size="18px", font_weight="bold", fill="#1a1a1a"),
    StyleRule("phase-text", font_family="'Segoe UI', Helvetica, Arial, sans-serif",
              font_size="13px", font_weight="bold", fill="#ffffff"),
    StyleRule("node-title", font_family="'Segoe UI', Helvetica, Arial, sans-serif",
              font_size="12px", font_weight="bold", fill="#1a1a1a"),
    StyleRule("node-sub", font_family="'Segoe UI', Helvetica, Arial, sans-serif",
              font_size="10px", fill="#555555"),
    StyleRule("pkt-text", font_family="'Segoe UI', Helvetica, Arial, sans-serif",
              font_size="11px", font_weight="600"),
    StyleRule("info-title", font_family="'Segoe UI', Helvetica, Arial, sans-serif",
              font_size="11px", fill="#222222"),
    StyleRule("info-body", font_family="'Segoe UI', Helvetica, Arial, sans-serif",
              font_size="10px", fill="#444444"),
])


class AttackDiagram:
    def __init__(self, width, height, title, desc, stylesheet=DEFAULT_STYLESHEET, grid=None, show_grid=True):
        self.width = width
        self.height = height
        self.title = title
        self.desc = desc
        self.stylesheet = stylesheet
        self.actors = []
        self.phases = []
        self.footer = None
        # Shared collision grid: pass the same `grid` into Actor/Phase/etc.
        # constructors so everything registers on this one instance.
        self.grid = grid if grid is not None else Collision_Grid(width, height)
        self.show_grid = show_grid
        self.contents = []

    def add_actor(self, actor):
        self.actors.append(actor)
        self.contents.append(actor)
        return self

    def add_phase(self, phase):
        self.phases.append(phase)
        self.contents.append(phase)
        for step in phase.steps:
            self.contents.append(step)
            self.contents.extend(step.contents)
        return self

    def set_footer(self, notebox):
        self.footer = notebox
        return self

    def actor_boxes_svg(self):
        return "\n".join(a.to_svg() for a in self.actors)

    def lifelines_svg(self, list_of_objects=None):
        return "\n  ".join(a.lifeline().to_svg() for a in list_of_objects)

    def phases_svg(self):
        return "\n\n".join(p.to_svg() for p in self.phases)

    def load_header(self, header_text):
        self.title = header_text
        return

    def build_svg(self):
        # title_label = Label(Position(self.width // 2, 0), self.title, cls="title", anchor="middle", grid=self.grid)
        parts = [
            f'<svg width="100%" height="100%" viewBox="0 0 {self.width} {self.height}" '
            f'role="img" xmlns="http://www.w3.org/2000/svg">',
            f'  <title>{xml_escape(str(self.title))}</title>',
            f'  <desc>{xml_escape(str(self.desc))}</desc>',
            '',
            '  <defs>',
            '    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" '
            'markerHeight="6" orient="auto-start-reverse">',
            '      <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" '
            'stroke-linecap="round" stroke-linejoin="round"/>',
            '    </marker>',
            '  </defs>',
            '',
            self.stylesheet.to_svg(),
            '',
            self.actor_boxes_svg(),
            '',
            f'  {self.lifelines_svg(self.actors)}',
            '',
            self.phases_svg(),
            f' {self.lifelines_svg(self.phases)}',
            '',
        ]
        if self.footer:
            parts.append(self.footer.to_svg())
        if self.show_grid:
            parts.append(self.grid.visualize_grid())
        parts.append('')
        parts.append('</svg>')
        content = "\n".join(parts)
        return content
    
    # 2. Map the calculated mathematical values back to your objects
    def update_positions_from_solver(self, variables):
        for obj in self.contents:
            if obj.is_dynamic:
                # Retrieve the Kiwi variables we created for this object
                vx, vy = variables.get(obj, (None, None))
                
                if vx is not None and vy is not None:
                    # Fetch the calculated position from the solver
                    new_x = vx.value()
                    new_y = vy.value()
                    #print(f"Updating position for {obj.__class__.__name__} (ID: {id(obj)}): New Position = ({new_x}, {new_y})")
                    # Update the real object's coordinates/bounds so the renderer uses them
                    # (Adjust this line to match how your framework sets position, e.g., obj.x = new_x)
                    obj.update_position(new_x = new_x, new_y = new_y)  # Assuming your object has an update_position method
    
    def resolve_layout(self, iterations=8, margin=20):
        dynamic_objs = [o for o in self.contents if o.is_dynamic]
        if not dynamic_objs:
            return

        # 1. חישוב bounds ראשוני לכל האובייקטים הדינמיים
        for obj in dynamic_objs:
            obj.bounds = obj.get_bounds()

        # חישוב Offsets בין המיקום הפיזי (pos) לבין ה-Top-Left של ה-Bounds
        offsets = {
            obj: (obj.pos.x - obj.bounds[0].x, obj.pos.y - obj.bounds[0].y)
            for obj in dynamic_objs
        }

        # 2. הרצת לולאות התיקון (Iterations)
        for iteration in range(iterations):
            solver = kiwi.Solver()
            variables = {}

            # יצירת משתני Kiwi לכל אובייקט דינמי
            for obj in dynamic_objs:
                vx = kiwi.Variable(f"x_{id(obj)}")
                vy = kiwi.Variable(f"y_{id(obj)}")
                variables[obj] = (vx, vy)

            # -------------------------------------------------------------
            # אילוץ 1 (Weak): משיכה אל המיקום המבוקש המקורי (Anchor / Ideal)
            # -------------------------------------------------------------
            for obj in dynamic_objs:
                vx, vy = variables[obj]
                if getattr(obj, 'step', None) is not None and getattr(obj, 'pos_relative', None) is not None:
                    ideal = obj.step.from_pos + obj.pos_relative
                    solver.addConstraint((vx == ideal.x) | kiwi.strength.weak)
                    solver.addConstraint((vy == ideal.y) | kiwi.strength.weak)
                else:
                    # אם אין Step אב, שמור על pos הנוכחי כעוגן
                    solver.addConstraint((vx == obj.pos.x) | kiwi.strength.weak)
                    solver.addConstraint((vy == obj.pos.y) | kiwi.strength.weak)

                # סחף עדין מאוד (Tie-Breaker Bias) למניעת תנודות שוות
                solver.addConstraint((vx == self.width) | (kiwi.strength.weak - 1))
                solver.addConstraint((vy == self.height) | (kiwi.strength.weak - 1))

            # -------------------------------------------------------------
            # אילוץ 2 (Medium): גבולות הקנבס (Canvas Bounds)
            # -------------------------------------------------------------
            for obj in dynamic_objs:
                vx, vy = variables[obj]
                off_x, off_y = offsets[obj]
                _, obj_w, obj_h = obj.bounds

                solver.addConstraint(((vx - off_x) >= 0) | kiwi.strength.medium)
                solver.addConstraint(((vy - off_y) >= 0) | kiwi.strength.medium)
                solver.addConstraint(((vx - off_x + obj_w) <= self.width) | kiwi.strength.medium)
                solver.addConstraint(((vy - off_y + obj_h) <= self.height) | kiwi.strength.medium)

            # -------------------------------------------------------------
            # אילוץ 3 (Strong): מניעת חפיפות והתנגשויות (Non-Overlapping)
            # -------------------------------------------------------------
            SEPARATION = kiwi.strength.strong

            for i, obj in enumerate(self.contents):
                obj_pos, obj_w, obj_h = obj.bounds
                off1x, off1y = offsets.get(obj, (0, 0))

                for other in self.contents[i + 1:]:
                    # אם שניהם סטטיים, אין מה להזיז
                    if not obj.is_dynamic and not other.is_dynamic:
                        continue
                    
                    # אם אין חפיפה פיזית ברגע זה, אין צורך באילוץ
                    if not obj.intersects(other):
                        continue

                    oth_pos, oth_w, oth_h = other.bounds
                    off2x, off2y = offsets.get(other, (0, 0))

                    vx1, vy1 = variables.get(obj, (None, None))
                    vx2, vy2 = variables.get(other, (None, None))

                    dx = (obj_pos.x + obj_w / 2) - (oth_pos.x + oth_w / 2)
                    dy = (obj_pos.y + obj_h / 2) - (oth_pos.y + oth_h / 2)

                    if dx == 0 and dy == 0:
                        dx = 1  # שבירת שוויון דטרמיניסטית

                    # החלטה על ציר ההפרדה הראשי
                    if abs(dx) >= abs(dy):
                        # --- הפרדה אופקית (X) ---
                        if dx > 0:
                            # obj נמצא מימין ל-other
                            if obj.is_dynamic:
                                left_bound = (vx2 - off2x) + oth_w if other.is_dynamic else (oth_pos.x + oth_w)
                                solver.addConstraint(((vx1 - off1x) >= left_bound + margin) | SEPARATION)
                            elif other.is_dynamic:
                                solver.addConstraint(((vx2 - off2x) + oth_w + margin <= obj_pos.x) | SEPARATION)
                        else:
                            # other נמצא מימין ל-obj
                            if other.is_dynamic:
                                left_bound = (vx1 - off1x) + obj_w if obj.is_dynamic else (obj_pos.x + obj_w)
                                solver.addConstraint(((vx2 - off2x) >= left_bound + margin) | SEPARATION)
                            elif obj.is_dynamic:
                                solver.addConstraint(((vx1 - off1x) + obj_w + margin <= oth_pos.x) | SEPARATION)
                    else:
                        # --- הפרדה אנכית (Y) ---
                        if dy > 0:
                            # obj נמצא מתחת ל-other
                            if obj.is_dynamic:
                                top_bound = (vy2 - off2y) + oth_h if other.is_dynamic else (oth_pos.y + oth_h)
                                solver.addConstraint(((vy1 - off1y) >= top_bound + margin) | SEPARATION)
                            elif other.is_dynamic:
                                solver.addConstraint(((vy2 - off2y) + oth_h + margin <= obj_pos.y) | SEPARATION)
                        else:
                            # other נמצא מתחת ל-obj
                            if other.is_dynamic:
                                top_bound = (vy1 - off1y) + obj_h if obj.is_dynamic else (obj_pos.y + obj_h)
                                solver.addConstraint(((vy2 - off2y) >= top_bound + margin) | SEPARATION)
                            elif obj.is_dynamic:
                                solver.addConstraint(((vy1 - off1x) + obj_h + margin <= oth_pos.y) | SEPARATION)

            # 4. פתרון המערכת ועדכון משתנים בסוף הלולאה בלבד
            solver.updateVariables()
            
            # עדכון המיקומים בפועל
            self.update_positions_from_solver(variables)

            # עדכון ה-bounds מחדש לקראת ה-iteration הבא (אם נדרש)
            for obj in dynamic_objs:
                obj.bounds = obj.get_bounds()
def diagram_creator(actors_dict, phases_dict, title, desc):
    starting_phase_x = 0
    max_phase_width = 0

    phase_width = 100
    phase_height = 150          # minimum/default phase height (used when a phase has no steps)

    # All actors must render at the same size, so instead of letting each
    # Actor's SVGBox auto-fit to its own name/desc independently (which would
    # give every actor a different box size), find the max size any single
    # actor's text needs and use that as a uniform floor for all of them.
    actor_width, actor_height = 100, 60
    for actor_data in actors_dict.values():
        actor_width, actor_height = SVGBox.estimate_text_box_size(
            actor_data["name"], actor_data["desc"],
            min_width=actor_width, min_height=actor_height,
        )
    starting_actor_y = 0

    starting_phase_y = actor_height + 20   # was hardcoded to 80, which only
                                            # happened to clear the old fixed
                                            # actor_height=60; now derived so
                                            # phases never start above the
                                            # actual bottom of the actor boxes

    step_height = 70            # vertical gap between consecutive steps inside a phase
    step_top_padding = 40       # space at top of a phase before the first step
    step_bottom_padding = 20    # space left after the last step before the phase's bottom edge
    space_between_actors = 400
    space_between_phases = 20
    num_actors = len(actors_dict)
    num_phases = len(phases_dict)

    diagram_width = phase_width + ((num_actors - 1) * (space_between_actors + actor_width)) + actor_width + 100
    diagram_height = actor_height + phase_height + (num_phases * space_between_phases) + 100
    actors_stroke_colors = palettes.select_random_colors(num_actors, palette=palettes.Bold_6)
    phases_stroke_colors = palettes.select_random_colors(num_phases, palette=palettes.Bold_6)
    actors_box_colors = palettes.lighten_color_list(actors_stroke_colors)
    phases_box_colors = palettes.lighten_color_list(phases_stroke_colors)
    # One grid shared by every Actor/Phase in this diagram, so they're all
    # checked for collisions against each other (see AttackDiagram below,
    # which reuses this same grid for its show_grid overlay).
    diagram_grid = Collision_Grid(width=diagram_width, height=1000)

    processed_phases = []

    current_phase_y = starting_phase_y
    for i, (phase_key, phase_data) in enumerate(phases_dict.items()):
        num_steps = len(phase_data.get("steps", []))
        # However many steps this phase has, make sure the box is tall enough
        # to fit all of them (plus top/bottom padding) before falling back to
        # the default minimum height. This is what keeps steps from overlapping
        # the next phase no matter how many get added.
        content_height = (step_top_padding + (num_steps * step_height) + step_bottom_padding
                           if num_steps else phase_height)
        required_height = max(phase_height, content_height)

        phase_obj = Phase(
            pos=Position(starting_phase_x, current_phase_y),
            phase_number=int(phase_key),
            title=phase_data["title"],
            desc=phase_data["desc"],
            color=phases_stroke_colors[i],
            bg=phases_box_colors[i],
            height=required_height,
            width=phase_width,
            canvas_width=diagram_width,
            canvas_height=0,  # filled in below, once the True total height is known
            grid=diagram_grid,
        )
        if (phase_obj.width > max_phase_width):
            max_phase_width = phase_obj.width

        phase_obj.next_phase_y = current_phase_y + phase_obj.height + space_between_phases
        processed_phases.append(phase_obj)
        current_phase_y = phase_obj.next_phase_y

    # Total canvas height = however far down the last phase actually extends
    # (now that every phase's real height has been taken into account) plus a
    # bottom margin for the actor lifelines to terminate in.
    calculated_height = current_phase_y - space_between_phases + 50
    for phase_obj in processed_phases:
        phase_obj.canvas_height = calculated_height

    # Now that the true height is known, sync it onto the shared grid so its
    # debug overlay (visualize_grid) covers the full diagram instead of the
    # width=diagram_width/height=1000 placeholder it was created with.
    diagram_grid.width = diagram_width
    diagram_grid.height = calculated_height

    logger.info("Calculated canvas dimensions: width=%s, height=%s", diagram_width, calculated_height)

    starting_actor_x = starting_phase_x + max_phase_width
    runtime_actors_map = {}
    for i, (actor_key, actor_data) in enumerate(actors_dict.items()):
        current_actor_x = starting_actor_x + (i * space_between_actors)
        actor_obj = Actor(
            pos=Position(current_actor_x, starting_actor_y),
            desc=actor_data["desc"],
            name=actor_data["name"],
            width=actor_width,
            height=actor_height,
            box_color=actors_box_colors[i],
            stroke_color=actors_stroke_colors[i],
            icon_name=actor_data.get("icon", "laptop"),
            lifeline_color=actors_stroke_colors[i],
            canvas_width=diagram_width,
            canvas_height=calculated_height,
            grid=diagram_grid,
        )
        runtime_actors_map[actor_key] = actor_obj

    for phase_obj, phase_data in zip(processed_phases, phases_dict.values()):
        step_y_inside_phase = step_top_padding
        for step_data in phase_data["steps"]:

            actor_a = runtime_actors_map[step_data["from"]]
            actor_b = runtime_actors_map[step_data["to"]]

            # Actor.lifeline() runs down the center of the actor's box
            # (pos.x + width/2), not its left edge, so arrows must connect to
            # that same center point or they land offset from the lifeline.
            actor_a_center_x = actor_a.pos.x + actor_a.width / 2
            actor_b_center_x = actor_b.pos.x + actor_b.width / 2

            # step_y_inside_phase is phase-relative; Phase.to_svg() renders its
            # steps in absolute canvas coordinates (no wrapping <g transform>),
            # so it needs phase_obj.pos.y added to land inside this phase's box.
            step_y_absolute = phase_obj.pos.y + step_y_inside_phase
            step_from = Position(actor_a_center_x, step_y_absolute)
            step_to = Position(actor_b_center_x, step_y_absolute)

            # Midpoint of the arrow (same x used for Step.center), so the
            # title/text labels sit centered above/below the arrow itself
            # rather than off to one side.
            step_cx = (actor_a_center_x + actor_b_center_x) / 2

            labels = [
                Label(Position(step_cx, step_y_absolute - 11), step_data["title"], anchor="middle", cls="info-title", fill=phase_obj.stroke_color, grid=diagram_grid, register=False),
                Label(Position(step_cx, step_y_absolute + 20), step_data["text"], anchor="middle", cls="pkt-text", grid=diagram_grid, register=False)
            ]

            # If the step has a notebox, create it and add it to the list of noteboxes for this step
            notebox_data = step_data.get("notebox")
            icon_data = step_data.get("icon")
            step_obj = Step(
                from_pos=step_from,
                to_pos=step_to,
                number=step_data.get("number", 0),
                labels=labels,
                angle=step_data.get("angle", 0),
                color=phase_obj.stroke_color,
                grid=diagram_grid,

            )
            if notebox_data:
                step_obj.add_notebox(
                    pos_relative=Position(notebox_data.get("x", 20), notebox_data.get("y", 35)),
                    width=notebox_data.get("width", 100),
                    height=notebox_data.get("height", 100),
                    lines=notebox_data.get("lines", []),
                    shape=notebox_data.get("shape", "fold"),
                    corner=notebox_data.get("corner", "top-right"),
                    fill=notebox_data.get("fill", "#fffbe6"),
                    grid=diagram_grid,
                    stroke=notebox_data.get("stroke", phase_obj.stroke_color),

                )

            if icon_data:
                step_obj.add_icon(
                    name=icon_data.get("name", "laptop"),
                    pos_relative=Position(icon_data.get("x", 800), icon_data.get("y", 400)),
                    width=icon_data.get("width", 60),
                    height=icon_data.get("height", 60),
                    grid=diagram_grid,
                )

            phase_obj.add_step(step_obj)
            step_y_inside_phase += step_height

    diagram = AttackDiagram(width=diagram_width, height=calculated_height, title=title, desc=desc,
                             grid=diagram_grid, show_grid=True)

    for actor_obj in runtime_actors_map.values():
        diagram.add_actor(actor_obj)

    for phase_obj in processed_phases:
        diagram.add_phase(phase_obj)

   #diagram.resolve_layout()

    return diagram.build_svg()


if __name__ == "__main__":
    
    # ==============================================================================
    # TEST DATA: Dictionaries representing the LLM's structured JSON output
    # ==============================================================================

    # 1. Dictionary containing network actors/nodes with their respective metadata

    actors_dict={
    "victim": {
        "name": "Victim Client",
        "desc": "10.0.2.30",
        "icon": "laptop"
    },
    "c2": {
        "name": "Attacker C2 (Rogue DNS)",
        "desc": "10.0.2.20 authoritative for pirate.sea",
        "icon": "evil"
    }
    }
    phases_dict= {
    "1": {
        "title": "Handshake & Capability Negotiation",
        "desc": "Victim establishes a DNS-based C2 tunnel and negotiates virtual network and codecs using DNS NULL (Type 10) queries.",
        "steps": [
        {
            "from": "victim",
            "to": "c2",
            "title": "DNS NULL Query: Initial check-in (vaaaakardli.pirate.sea)",
            "text": "Beacon to rogue DNS; response contains magic token \"VACKD\" confirming C2 readiness.",
            "number": 1.1,
            "is_malicious": True,
            "notebox": {
            "lines": [
                "Record type: NULL (Type 10)",
                "Session duration ~24.5s; total 434 DNS packets"
            ]
            }
        },
        {
            "from": "victim",
            "to": "c2",
            "title": "Network parameter retrieval",
            "text": "Query for tunnel config; response string: 10.20.30.1-10.20.30.3-1130-24 (nameserver, client tunnel IP, port 1130, /24).",
            "number": 1.2,
            "is_malicious": True,

        },
        {
            "from": "victim",
            "to": "c2",
            "title": "Encoding capability probe (yrbi02.pirate.sea)",
            "text": "C2 returns 48-byte binary capability structure enumerating supported encoding/compression.",
            "number": 1.3,
            "is_malicious": True
        },
        {
            "from": "victim",
            "to": "c2",
            "title": "Character encoding negotiation (zi03..zi1b, 5 queries)",
            "text": "Test strings across ASCII printable, extended Latin, and byte range 0xBC–0xFD; C2 echoes back to derive safe alphabet through DNS transport.",
            "number": 1.4,
            "is_malicious": True
        },
        {
            "from": "victim",
            "to": "c2",
            "title": "Codec selection (sbhi1c, obsi1d, obli1e)",
            "text": "Finalize codecs for tunnel directions and fallback.",
            "number": 1.5,
            "is_malicious": True,

        }
        ]
    },
    "2": {
        "title": "Tunnel Establishment & Bidirectional Data Transfer",
        "desc": "The tunnel carries upstream chunks and sustained downlink via polling, disguised as DNS traffic.",
        "steps": [
        {
            "from": "victim",
            "to": "c2",
            "title": "Upstream data via rc/rd-prefixed queries (13 queries)",
            "text": "Large Base128-encoded payloads embedded in query labels (≤62 bytes per label; multiple labels per FQDN).",
            "number": 2.1,
            "is_malicious": True,

        },
        {
            "from": "c2",
            "to": "victim",
            "title": "Downlink blobs in responses to rc/rd",
            "text": "C2 returns large binary payloads per response (≈768–1,188 bytes each).",
            "number": 2.15,
            "is_malicious": True
        },
        {
            "from": "victim",
            "to": "c2",
            "title": "Keepalive/polling via na/pa-prefixed queries (174 queries)",
            "text": "Short query names (e.g., paeacg2y, pafqcg3a) maintain heartbeat and request pending data.",
            "number": 2.2,
            "is_malicious": True
        },
        {
            "from": "c2",
            "to": "victim",
            "title": "Zlib-compressed downlink during polling",
            "text": "Responses carry zlib data (magic bytes 0x78 0xDA), totaling ≈14,725 bytes of compressed C2 data.",
            "number": 2.25,
            "is_malicious": True,
           
        }
        ]
    },
    "3": {
        "title": "Large-Scale Data Exfiltration",
        "desc": "Victim sends bulk binary data to C2 using maximum-length DNS query names; C2 acks receipt.",
        "steps": [
        {
            "from": "victim",
            "to": "c2",
            "title": "Bulk exfil via numeric-prefixed queries (24 queries)",
            "text": "Queries starting with 1/1e/1i/1m/1q/1u/12… carry ~250-byte names packed with binary data; begins ~13s into session.",
            "number": 3.1,
            "is_malicious": True,

        },
        {
            "from": "c2",
            "to": "victim",
            "title": "Per-chunk acknowledgements",
            "text": "C2 responds with 2-byte sequence ACKs (e.g., 0xA0 0x20, 0xB0 0x20) confirming each exfil chunk.",
            "number": 3.15,
            "is_malicious": True,

        }
        ]
    }
    }
    test_title = "Man-in-the-Middle Incident Report"
    test_desc = "test"

    svg = diagram_creator(actors_dict, phases_dict, test_title, test_desc)

    out_path = "arp_spoofing_mitm.svg"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(svg)
    print(f"Wrote {out_path}")
    import webbrowser
    webbrowser.open(out_path)