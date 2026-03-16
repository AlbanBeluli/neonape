from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class SensitivePath(BaseModel):
    """Normalized web-exposure finding with deterministic local scoring.

    Scoring rules:
    - Base category score:
      - Secrets: 80
      - Repo Metadata: 70
      - Server Config: 60
      - Logs: 55
    - Status adjustment:
      - 200/201/202/204/206: +15
      - 401/403: +5
      - 300-399: +0
      - 404/410: -25
      - 500-599: -15
    - Source adjustment:
      - nuclei: +10
      - httpx: +5
      - gobuster/katana: +0
    - Evidence adjustment:
      - known response length > 0: +5
      - each extra confirming source after the first: +10, capped at +20
    Final score is clamped to 0-100.
    """

    CATEGORY_BASE: ClassVar[dict[str, int]] = {
        "Secrets": 80,
        "Repo Metadata": 70,
        "Server Config": 60,
        "Logs": 55,
    }
    SOURCE_BONUS: ClassVar[dict[str, int]] = {
        "nuclei": 10,
        "httpx": 5,
        "gobuster": 0,
        "katana": 0,
    }

    path: str = Field(min_length=1)
    normalized_path: str = Field(min_length=1)
    category: str = Field(min_length=1)
    risk_score: int = Field(ge=0, le=100)
    source_tool: str = Field(min_length=1)
    host: str = ""
    url: str = ""
    status: int | None = None
    length: int | None = None
    severity: str | None = None

    @classmethod
    def categorize(cls, raw_path: str) -> str | None:
        lowered = raw_path.lower()
        basename = lowered.rsplit("/", 1)[-1]
        if any(token in lowered for token in (".env", ".htpasswd", "config.", ".bak", ".backup", ".old", ".sql.gz", ".zip", ".tar.gz")):
            return "Secrets"
        if basename.endswith(".log") or basename in {"production.log", "development.log", "spamlog.log", "error.log", "access.log"}:
            return "Logs"
        if any(token in lowered for token in ("/.git", "/.svn", ".ds_store", "/.hg")):
            return "Repo Metadata"
        if basename in {"php.ini", "web.config", ".htaccess", ".user.ini", "httpd.conf", "nginx.conf"}:
            return "Server Config"
        return None

    @classmethod
    def score(
        cls,
        *,
        category: str,
        status: int | None,
        source_tool: str,
        length: int | None,
        source_count: int = 1,
    ) -> int:
        score = cls.CATEGORY_BASE.get(category, 40)
        if status in {200, 201, 202, 204, 206}:
            score += 15
        elif status in {401, 403}:
            score += 5
        elif status in {404, 410}:
            score -= 25
        elif status is not None and 500 <= status <= 599:
            score -= 15
        score += cls.SOURCE_BONUS.get(source_tool.lower(), 0)
        if length and length > 0:
            score += 5
        if source_count > 1:
            score += min((source_count - 1) * 10, 20)
        return max(0, min(score, 100))

    @classmethod
    def from_observation(
        cls,
        *,
        raw_path: str,
        source_tool: str,
        host: str = "",
        url: str = "",
        status: int | None = None,
        length: int | None = None,
        severity: str | None = None,
        source_count: int = 1,
    ) -> "SensitivePath" | None:
        normalized_path = normalize_web_path(raw_path)
        category = cls.categorize(normalized_path)
        if not category:
            return None
        return cls(
            path=raw_path,
            normalized_path=normalized_path,
            category=category,
            risk_score=cls.score(
                category=category,
                status=status,
                source_tool=source_tool,
                length=length,
                source_count=source_count,
            ),
            source_tool=source_tool,
            host=host,
            url=url,
            status=status,
            length=length,
            severity=severity,
        )


def normalize_web_path(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return "/"
    parsed = urlparse(stripped)
    candidate = parsed.path if parsed.scheme or parsed.netloc else stripped
    if not candidate.startswith("/"):
        candidate = "/" + candidate.lstrip("./")
    while "//" in candidate:
        candidate = candidate.replace("//", "/")
    return candidate or "/"
