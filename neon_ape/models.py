from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ChecklistStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    SKIPPED = "skipped"


@dataclass(slots=True)
class ChecklistItem:
    step_order: int
    section_name: str
    title: str
    guide_text: str
    example_command: str
    status: ChecklistStatus = ChecklistStatus.PENDING


@dataclass(slots=True)
class ScanRequest:
    tool_name: str
    target: str
    profile: str
