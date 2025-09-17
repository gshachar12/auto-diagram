import base64
import pcap
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---- Shared config ----
TEXT_EXTS = {".txt", ".md", ".csv", ".json", ".log", ".yaml", ".yml"}
CODE_EXTS = {".py", ".sh", ".conf", ".ini"}
IMG_EXTS = {".png", ".jpg", ".jpeg", ".webp"}
PCAP_EXTS = {".pcap"}


def create_message_from_path(path: Path, pcap_mode: str = "full") -> Optional[Dict]:
    ext = path.suffix.lower()

    if ext in TEXT_EXTS or ext in CODE_EXTS:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            print(f"failed to parse text: {e}")
            return None

        return {
            "role": "user",
            "content": f"Supporting file: {path.name}\n\n{text}",
        }

    if ext in IMG_EXTS:
        try:
            data = path.read_bytes()
        except Exception as e:
            print(f"failed to parse image: {e}")
            return None
        b64 = base64.b64encode(data).decode("utf-8")
        fmt = ext.lstrip(".")
        data_url = f"data:image/{fmt};base64,{b64}"
        return {
            "role": "user",
            "content": [
                {
                    "type": "input_text",
                    "text": f"Supporting image ({path.name}). Use only if relevant to the network flow.",
                },
                {
                    "type": "input_image",
                    "image_url": data_url,
                    "detail": "auto",
                },
            ],
        }

    if ext in PCAP_EXTS:
        try:
            with path.open(mode="rb") as r:
                text = pcap.prompt(path.name, r, mode=pcap_mode)
        except Exception as e:
            print(f"failed to parse pcap: {e}")
            return None

        return {
            "role": "user",
            "content": text,
        }

    return None


def create_message_from_bytes(
    name: str, data: bytes, pcap_mode: str = "full"
) -> Optional[Dict]:
    lower = name.lower()
    ext = lower[lower.rfind(".") :] if "." in lower else ""

    if ext in TEXT_EXTS or ext in CODE_EXTS:
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return None

        return {"role": "user", "content": f"Supporting file: {name}\n\n{text}"}

    if ext in IMG_EXTS:
        b64 = base64.b64encode(data).decode("utf-8")
        fmt = ext.lstrip(".")
        data_url = f"data:image/{fmt};base64,{b64}"
        return {
            "role": "user",
            "content": [
                {
                    "type": "input_text",
                    "text": f"Supporting image ({name}). Use only if relevant to the network flow.",
                },
                {
                    "type": "input_image",
                    "image_url": data_url,
                    "detail": "auto",
                },
            ],
        }

    if ext in PCAP_EXTS:
        try:
            text = pcap.prompt(name, BytesIO(data), mode=pcap_mode)
        except Exception as e:
            print(f"failed to parse pcap: {e}")
            return None

        return {
            "role": "user",
            "content": text,
        }

    return None


def build_messages_from_dir(directory: Optional[str]) -> List[Dict]:
    if not directory:
        return []
    p = Path(directory)
    if not p.exists() or not p.is_dir():
        return []

    messages: List[Dict] = []
    for file_path in sorted(p.glob("*")):
        if not file_path.is_file():
            continue
        msg = create_message_from_path(file_path)
        if msg:
            messages.append(msg)
    return messages


def build_messages_from_named_bytes(files: List[Tuple[str, bytes]]) -> List[Dict]:
    messages: List[Dict] = []
    for name, data in files:
        msg = create_message_from_bytes(name, data)
        if msg:
            messages.append(msg)
    return messages
