"""
Rendering: shells out to the `d2` CLI (https://d2lang.com) to turn a
`.d2` source file into an image. Kept isolated from `d2_builder.py` so the
D2 *source* can always be produced and written to disk even in
environments where the `d2` binary isn't installed -- rendering is treated
as best-effort, not a hard dependency of the pipeline.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_SUPPORTED_FORMATS = ("svg", "png")


def is_d2_available() -> bool:
    """True if the `d2` CLI is on PATH."""
    return shutil.which("d2") is not None


def render(d2_path: str | Path, output_path: str | Path, layout: str = "dagre", timeout_s: int = 60) -> bool:
    """
    Renders `d2_path` to `output_path`. The output format is inferred by
    the `d2` CLI itself from `output_path`'s extension (.svg or .png).

    Returns True on success, False on any failure (missing binary,
    non-zero exit, timeout) -- never raises, so a rendering failure can't
    take down the rest of the pipeline. Failures are logged with enough
    detail (stderr) to debug separately.
    """
    output_path = Path(output_path)
    suffix = output_path.suffix.lstrip(".").lower()
    if suffix not in _SUPPORTED_FORMATS:
        logger.error("Visualizer: unsupported render format %r (supported: %s)", suffix, _SUPPORTED_FORMATS)
        return False

    if not is_d2_available():
        logger.warning(
            "Visualizer: `d2` CLI not found on PATH -- skipping render of %s. "
            "The .d2 source was still written; install d2 "
            "(https://d2lang.com/tour/install) to render it, or run "
            "`d2 %s %s` manually later.",
            output_path, d2_path, output_path,
        )
        return False

    output_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["d2", f"--layout={layout}", str(d2_path), str(output_path)]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("Visualizer: `d2` render timed out after %ds (%s)", timeout_s, output_path)
        return False
    except OSError as e:
        logger.error("Visualizer: failed to invoke `d2`: %s", e)
        return False

    if result.returncode != 0:
        logger.error(
            "Visualizer: `d2` exited %d rendering %s\n  cmd: %s\n  stderr: %s",
            result.returncode, output_path, " ".join(cmd), result.stderr.strip(),
        )
        return False

    logger.info("Visualizer: rendered %s", output_path)
    return True
