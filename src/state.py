import platformdirs
import os
import json
from datetime import datetime
from pydantic import BaseModel, Field
from typing import List, Dict, Iterable

APP_NAME = "auto_diagram"
STATE_FILE_NAME = "state.json"

work_dir = platformdirs.user_data_dir(
    APP_NAME, appauthor=False, version="0.1", ensure_exists=True
)
state_file = os.path.join(work_dir, STATE_FILE_NAME)
print(f"Work dir: {work_dir}")
print(f"State file: {state_file}")


class ChatSession(BaseModel):
    title: str = Field(
        default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    id: float = Field(default_factory=lambda: datetime.now().timestamp())
    updated: float = Field(default_factory=lambda: datetime.now().timestamp())
    messages: List[Dict] = Field(default_factory=list)
    diagram_text: str = ""


def _sorted_sessions(sessions: Iterable[ChatSession]) -> List[ChatSession]:
    return sorted(sessions, key=lambda s: s.updated, reverse=True)


def sorted_state(sessions: Dict[float, ChatSession]) -> List[ChatSession]:
    return _sorted_sessions(sessions.values())


def load():
    if not os.path.exists(state_file):
        return {}
    with open(state_file, "r+") as r:
        raw = json.load(r)
        sessions = [ChatSession.model_validate(item) for item in raw]
        mappings = {}
        for s in sessions:
            mappings[s.id] = s
        return mappings


def write(sessions: Dict[float, ChatSession]):
    payload = sorted_state(sessions)
    payload = [x.model_dump() for x in payload]
    with open(state_file, "w+") as w:
        json.dump(payload, w, ensure_ascii=False, indent=2)
