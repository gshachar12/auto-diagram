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

    # 1. Handle Text and Code files
    if ext in TEXT_EXTS or ext in CODE_EXTS:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            # : Returning standardized structure with msg and metadata
            return {
                "msg": {
                    "role": "user",
                    "content": f"Supporting file: {path.name}\n\n{text}",
                },
                "metadata": {"type": "chat_attachment", "name": path.name, "content": text}
            }
        except Exception as e:
            print(f"failed to parse text: {e}")
            return None

    # 2. Handle Image files
    if ext in IMG_EXTS:
        try:
            data = path.read_bytes()
            b64 = base64.b64encode(data).decode("utf-8")
            fmt = ext.lstrip(".")
            data_url = f"data:image/{fmt};base64,{b64}"
            return {
                "msg": {
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
                },
                "metadata": {"type": "chat_attachment", "name": path.name}
            }
        except Exception as e:
            print(f"failed to parse image: {e}")
            return None

    # 3. Handle PCAP files
    if ext in PCAP_EXTS:
        try:
            with path.open(mode="rb") as r:
                # IMPORTANT: Unpacking the tuple (text, packet_data)
                text, packet_data = pcap.prompt(path.name, r, mode=pcap_mode)
                
            return {
                "msg": {
                    "role": "user",
                    "content": text,
                },
                "metadata": {
                    "type": "chat_attachment", 
                    "name": path.name,
                    "packets_list": packet_data # Crucial for the Analysis tab
                }
            }
        except Exception as e:
            print(f"failed to parse pcap: {e}")
            return None

    return None

def create_message_from_bytes(
    name: str, data: bytes, pcap_mode: str = "full"
) -> Optional[Dict]:
    # : Ensure all return types follow the {msg: ..., metadata: ...} structure
    lower = name.lower()
    ext = lower[lower.rfind(".") :] if "." in lower else ""

    # 1. Handle Text and Code files
    if ext in TEXT_EXTS or ext in CODE_EXTS:
        try:
            text = data.decode("utf-8", errors="ignore")
            return {
                "msg": {
                    "role": "user", 
                    "content": f"Supporting file: {name}\n\n{text}"
                },
                "metadata": {"type": "chat_attachment", "name": name, "content": text}
            }
        except Exception:
            return None

    # 2. Handle Image files
    if ext in IMG_EXTS:
        try:
            b64 = base64.b64encode(data).decode("utf-8")
            fmt = ext.lstrip(".")
            data_url = f"data:image/{fmt};base64,{b64}"
            return {
                "msg": {
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
                },
                "metadata": {"type": "chat_attachment", "name": name}
            }
        except Exception:
            return None

    # 3. Handle PCAP files
    if ext in PCAP_EXTS:
        try:
            # Unpack the tuple from pcap.prompt
            text, packet_data = pcap.prompt(name, BytesIO(data), mode=pcap_mode)
            return {
                "msg": {
                    "role": "user",
                    "content": text
                },
                "metadata": {
                    "type": "chat_attachment",
                    "name": name,
                    "packets_list": packet_data  # Structured data for UI
                }
            }
        except Exception as e:
            print(f"failed to parse pcap: {e}")
            return None

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
